"""URL analyzer — classify URLs found in JS: internal, external, suspicious."""
import re
import ipaddress
from urllib.parse import urlparse
from typing import List
from ..finding import Finding, Category, Severity


class URLAnalyzer:
    """
    Looks at full URLs (http/https/ws) in the JS and pulls out the interesting ones.

    What we surface:
      - Internal IPs (RFC1918, loopback, link-local) — possible SSRF / internal infra leak
      - Internal-looking hostnames (kubernetes.default, *.internal, *.local, *.corp, *.lan)
      - Subdomains you didn't know about
      - Suspicious TLDs or ports (e.g. databases exposed on 3306)
    """

    NAME = "url_analyzer"

    # Match either a domain (with TLD) or an IPv4 address.
    URL_RE = re.compile(
        r"""(?:https?://|wss?://)                              # scheme
            (
                (?:[a-zA-Z0-9\-_]+\.)+[a-zA-Z]{2,}            # domain with TLD
                |
                \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}            # IPv4 address
            )
            (?::[0-9]{1,5})?                                   # port
            (?:[/?#][^\s'"<>)]*)?
        """,
        re.X | re.I,
    )

    INTERNAL_TLDS = (".local", ".internal", ".corp", ".lan", ".intranet", ".private", ".test")
    SUSPICIOUS_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
    }

    def analyze(self, content: str, file_label: str, source_url: str = "") -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()

        for m in self.URL_RE.finditer(content):
            url = m.group(0)
            if url in seen:
                continue
            seen.add(url)

            try:
                parsed = urlparse(url)
            except Exception:
                continue
            host = (parsed.hostname or "").lower()
            port = parsed.port
            if not host:
                continue
            # 1. Internal IPs
            try:
                ip = ipaddress.ip_address(host)
                is_internal = (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                )
                if is_internal:
                    findings.append(Finding(
                        category=Category.INFRA,
                        severity=Severity.HIGH,
                        detector="url_analyzer:internal_ip",
                        title=f"Internal IP exposed: {host}",
                        description=f"Internal/private IP {host} found in JS. Could indicate hardcoded internal service URL.",
                        file=file_label,
                        line=_line_of(content, m.start()),
                        match=url,
                        context=_ctx(content, m.start(), m.end() - m.start()),
                        source_url=source_url,
                    ))
                    continue
            except ValueError:
                pass  # not an IP

            # 2. Internal-looking hostnames
            if any(host.endswith(tld) for tld in self.INTERNAL_TLDS):
                findings.append(Finding(
                    category=Category.INFRA,
                    severity=Severity.HIGH,
                    detector="url_analyzer:internal_hostname",
                    title=f"Internal hostname: {host}",
                    description=f"Hostname {host} uses an internal TLD pattern (.local/.internal/.corp/.lan).",
                    file=file_label,
                    line=_line_of(content, m.start()),
                    match=url,
                    context=_ctx(content, m.start(), m.end() - m.start()),
                    source_url=source_url,
                ))
                continue

            # 3. Suspicious ports
            if port and port in self.SUSPICIOUS_PORTS:
                findings.append(Finding(
                    category=Category.INFRA,
                    severity=Severity.HIGH,
                    detector="url_analyzer:suspicious_port",
                    title=f"{self.SUSPICIOUS_PORTS[port]} on public URL: {host}:{port}",
                    description=f"Database or admin service ({self.SUSPICIOUS_PORTS[port]}) on a non-standard port. May indicate misconfigured infrastructure.",
                    file=file_label,
                    line=_line_of(content, m.start()),
                    match=url,
                    context=_ctx(content, m.start(), m.end() - m.start()),
                    source_url=source_url,
                ))

        return findings


def _line_of(content: str, offset: int) -> int:
    if offset < 0 or offset >= len(content):
        return 0
    return content.count("\n", 0, offset) + 1


def _ctx(content: str, offset: int, length: int, window: int = 60) -> str:
    start = max(0, offset - window)
    end = min(len(content), offset + length + window)
    raw = content[start:end]
    if start > 0:
        raw = "..." + raw
    if end < len(content):
        raw = raw + "..."
    return raw.replace("\n", " ")[:200]


def extract_subdomains(content: str) -> List[str]:
    """Helper: pull all unique subdomains referenced in the JS."""
    subs: set = set()
    for m in re.finditer(
        r"https?://((?:[a-zA-Z0-9\-_]+\.)+[a-zA-Z]{2,})",
        content,
    ):
        host = m.group(1).lower()
        parts = host.split(".")
        if len(parts) >= 2:
            subs.add(host)
    return sorted(subs)