"""
HTTP client — pure stdlib.

Why not requests? Two reasons:
  1. We're shipping a single-file tool. The fewer deps, the better.
  2. requests is great. This is a deliberate "what do we actually need" exercise.

What's missing vs. requests:
  - HTTP/2 (we don't need it for fetching JS bundles)
  - Connection pooling (we use one connection per fetch; the OS keeps idle ones warm)
  - Cookie jar (we don't authenticate; cookies would be a feature, not a bug)
"""
import ssl
import socket
import urllib.parse
import time
import gzip
import zlib
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class HTTPResponse:
    status_code: int = 0
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    url: str = ""
    latency_ms: int = 0
    error: Optional[str] = None
    redirected_from: Optional[str] = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400 and not self.error

    def text(self, encoding: Optional[str] = None) -> str:
        # Try to figure out the encoding from the header
        if encoding is None:
            ct = self.headers.get("content-type", "")
            if "charset=" in ct:
                encoding = ct.split("charset=", 1)[1].split(";")[0].strip()
            else:
                encoding = "utf-8"
        try:
            return self.body.decode(encoding, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


class HTTPClient:
    """A minimal HTTP/1.1 client. Doesn't try to be clever."""

    DEFAULT_PORTS = {"http": 80, "https": 443}
    DEFAULT_UA = "js-pulse/0.1.0 (+https://github.com/yourname/js-pulse)"

    def __init__(
        self,
        timeout: int = 15,
        verify_ssl: bool = False,  # Default off — we're a recon tool, not a browser
        user_agent: Optional[str] = None,
        max_retries: int = 2,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or self.DEFAULT_UA
        self.max_retries = max_retries

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> HTTPResponse:
        return self.request(url, "GET", headers=headers)

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
    ) -> HTTPResponse:
        last_error = None
        for attempt in range(self.max_retries + 1):
            start = time.time()
            try:
                resp = self._do_request(url, method, headers, follow_redirects)
                if resp.ok or resp.status_code > 0:
                    return resp
                last_error = resp.error or f"status {resp.status_code}"
            except (socket.timeout, TimeoutError) as e:
                last_error = f"timeout: {e}"
            except (ConnectionError, OSError) as e:
                last_error = f"network: {e}"
            except Exception as e:
                # Don't retry on unknown errors — likely a bug
                return HTTPResponse(url=url, error=str(e), latency_ms=int((time.time() - start) * 1000))

            if attempt < self.max_retries:
                time.sleep(0.5 * (attempt + 1))  # backoff

        return HTTPResponse(url=url, error=last_error or "max retries exceeded")

    def _do_request(
        self,
        url: str,
        method: str,
        headers: Optional[Dict[str, str]],
        follow_redirects: bool,
    ) -> HTTPResponse:
        start = time.time()
        parsed = urllib.parse.urlparse(url)
        scheme = (parsed.scheme or "http").lower()
        host = parsed.hostname
        port = parsed.port or self.DEFAULT_PORTS.get(scheme, 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        req_headers = {
            "Host": host,
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        if headers:
            req_headers.update(headers)

        req = f"{method} {path} HTTP/1.1\r\n"
        req += "\r\n".join(f"{k}: {v}" for k, v in req_headers.items())
        req_bytes = (req + "\r\n\r\n").encode("ascii")

        sock = socket.create_connection((host, port), timeout=self.timeout)
        try:
            if scheme == "https":
                # Default to a modern context; verify_ssl=False only when explicitly set
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.sendall(req_bytes)

            chunks = []
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            try:
                sock.close()
            except Exception:
                pass

        raw = b"".join(chunks)
        latency = int((time.time() - start) * 1000)
        resp = self._parse(raw, url, latency)

        if follow_redirects and resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if location:
                new_url = urllib.parse.urljoin(url, location)
                resp.redirected_from = url
                followed = self._do_request(new_url, "GET", headers, follow_redirects)
                followed.redirected_from = url
                return followed

        return resp

    @staticmethod
    def _parse(raw: bytes, url: str, latency_ms: int) -> HTTPResponse:
        sep = b"\r\n\r\n"
        if sep in raw:
            head_bytes, body = raw.split(sep, 1)
        else:
            head_bytes, body = raw, b""

        try:
            head = head_bytes.decode("iso-8859-1")
        except Exception:
            head = head_bytes.decode("utf-8", errors="replace")

        lines = head.split("\r\n")
        if len(lines) == 1:
            lines = head.split("\n")

        status_line = lines[0] if lines else ""
        parts = status_line.split(" ", 2)
        status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        reason = parts[2] if len(parts) >= 3 else ""

        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        # Decompress if needed. Note: we keep the raw bytes if decompression fails,
        # so the caller can decide what to do.
        if body:
            enc = headers.get("content-encoding", "").lower()
            try:
                if enc == "gzip":
                    body = gzip.decompress(body)
                elif enc == "deflate":
                    body = zlib.decompress(body)
            except Exception:
                pass  # caller will get the original body, which is also useful for debugging

        return HTTPResponse(
            status_code=status_code,
            reason=reason,
            headers=headers,
            body=body,
            url=url,
            latency_ms=latency_ms,
        )