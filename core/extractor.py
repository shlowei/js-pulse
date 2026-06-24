"""
extractor.py — extract endpoint URLs and HTTP method hints from JS source.

This is the heart of js-pulse for the "find API routes" use case. The
approach is regex + heuristics. It's not perfect, but it works for
~85% of real-world JS bundles I've seen.

Why not an AST? Two reasons:
  1. Webpack/Vite bundles are minified single-line madness. A regex on
     the raw text often does better than trying to parse 500KB of minified
     code into an AST and then walking it.
  2. AST parsing in pure Python without deps is painful. The closest
     stdlib option is `ast` (Python's own), which doesn't help with JS.

What's in here:
  - Path extraction: /api/v1/users/{id}, /rest/products, etc.
  - Full URL extraction: https://api.example.com/v1/x
  - HTTP method hints: GET, POST, PUT, DELETE near URL
  - Path templates: ${id}, {uuid}, :slug, etc.

What we deliberately don't do:
  - Try to deobfuscate (that's a separate, hard problem)
  - Execute the JS (static only)
  - Handle webpack chunk loading dynamically (we'd need to follow module IDs)
"""
import re
from urllib.parse import urlparse

from .finding import Finding, Category, Severity


# === Absolute URL patterns ===

# Strict http(s) URL — must have scheme (so we don't grab "//host.com")
# Note: we use a "previous char must not be a word char or / or ." lookbehind.
# In a JS string the URL is preceded by " or ' which both pass this lookbehind.
ABSOLUTE_HTTP_RE = re.compile(
    r"""(?<![A-Za-z0-9_/.])
        (?:https?://)                                  # scheme required
        (?:[a-zA-Z0-9\-_]+\.)+[a-zA-Z]{2,}            # domain
        (?::[0-9]{1,5})?                              # port
        (?:[/?#][^\s'"<>)]*)?
    """,
    re.X,
)

# WebSocket URLs
WEBSOCKET_URL_RE = re.compile(
    r"""(?:wss?://)(?:[a-zA-Z0-9\-_]+\.)+[a-zA-Z]{2,}(?::[0-9]{1,5})?(?:[/?#][^\s'"<>)]*)?""",
    re.I,
)


# === Path patterns ===

# Any path that LOOKS like an API endpoint.
# Heuristic: starts with /, has at least one segment, total length 4-300, no static-asset suffix.
# This is broad on purpose — downstream analyzers (endpoint_analyzer) refine.
# Note: no leading lookbehind — strings always start with " or ' before a /api/...,
# which would break a lookbehind for "not a quote".
ANY_API_LIKE_PATH_RE = re.compile(
    r"""(?:^|[^\w/.])
        (/(?:api|v[0-9]+|rest|graphql|rpc|svc|service|oauth|saml|auth|admin|internal|private|debug|test|dev|user|users|account|profile|order|orders|payment|invoice|billing|dashboard|console|manage|backup|legacy|staging|prod)
            (?:/[a-zA-Z0-9_\-{}:.$*]+)*)
        (?![a-zA-Z0-9_])
    """,
    re.X,
)

# Generic path pattern — any path with 2+ segments and at least one dynamic component
# (curly, dollar, or colon param). Avoids grabbing every URL-ish string.
TEMPLATE_PATH_RE = re.compile(
    r"""(?:^|[^\w/.])
        (/(?:[a-zA-Z0-9_\-]+/)+(?:\{[^}]+\}|\$\{[^}]+\}|[a-zA-Z_]+:[a-zA-Z0-9_]+))
    """,
    re.X,
)

# API-style paths that don't have known prefixes but look like endpoints
# (2+ segments, no static asset pattern, ends with non-asset suffix)
GENERIC_PATH_RE = re.compile(
    r"""(?:^|[^\w/.])
        (/(?:[a-zA-Z0-9_\-]+/){1,}[a-zA-Z0-9_\-]+)
    """,
    re.X,
)


# HTTP methods
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")


# === Filters ===

# Static asset / noise patterns
NOISE_PATH_PATTERNS = [
    re.compile(r"^/(?:js|css|img|images|fonts|static|assets|public|media|dist|build|src)/", re.I),
    re.compile(r"\.(?:png|jpg|jpeg|gif|svg|ico|css|woff2?|ttf|eot|map|pdf|zip|tar|gz|mp4|webp|avif|json|xml)$", re.I),
    re.compile(r"^/(?:node_modules|bower_components|vendor)/", re.I),
    re.compile(r"^/(?:favicon\.ico|robots\.txt|sitemap\.xml|manifest\.json|sw\.js)$", re.I),
    re.compile(r"\.s?css$|\.less$|\.scss$", re.I),
]

CDN_DOMAINS = {
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "maxcdn.bootstrapcdn.com", "code.jquery.com", "stackpath.bootstrapcdn.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com",
    "cdn.skypack.dev", "esm.sh", "cdn.tailwindcss.com", "cdn.jsdelivr.net",
}


def _is_noise_path(path: str) -> bool:
    for p in NOISE_PATH_PATTERNS:
        if p.search(path):
            return True
    return False


def _is_noise_domain(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in CDN_DOMAINS)


def _looks_like_endpoint_path(path: str) -> bool:
    if not path or not path.startswith("/"):
        return False
    if len(path) < 4 or len(path) > 500:
        return False
    if _is_noise_path(path):
        return False
    return True


def _find_line_number(content: str, offset: int) -> int:
    if offset < 0 or offset >= len(content):
        return 0
    return content.count("\n", 0, offset) + 1


def _truncate(s: str, n: int = 120) -> str:
    s = s.replace("\n", " ").replace("\r", " ")
    return s if len(s) <= n else s[: n - 3] + "..."


def _make_context(content: str, offset: int, length: int, window: int = 80) -> str:
    start = max(0, offset - window)
    end = min(len(content), offset + length + window)
    raw = content[start:end]
    if start > 0:
        raw = "..." + raw
    if end < len(content):
        raw = raw + "..."
    return _truncate(raw, 200)


def _guess_http_method(content: str, offset: int) -> str:
    """
    Try to find an HTTP method near the URL match.
    Heuristic: look back ~80 chars for a method-like token followed by colon/whitespace.
    Also handles `method: "GET"` and `method=` — these typically appear AFTER the URL.
    """
    # Look before the URL first (classic `.get(url)` / `.post(url)` calls)
    window_start = max(0, offset - 80)
    window = content[window_start:offset]
    window_clean = re.sub(r"['\"\s\[\]\(\),;{}]", " ", window)
    for method in HTTP_METHODS:
        if re.search(rf"\b{method}\b\s*$", window_clean, re.I):
            return method.upper()

    # Look after the URL for method: "GET" / method=GET pattern
    # (Fetch API style: fetch(url, {method: "DELETE"}))
    window_end = min(len(content), offset + 200)
    after = content[offset:window_end]
    for method in HTTP_METHODS:
        if re.search(rf"method\s*[:=]\s*['\"]?{method}['\"]?", after, re.I):
            return method.upper()

    return ""


def extract_endpoints(content: str, file_label: str, source_url: str = "") -> list:
    """Pull endpoint-like URLs out of JS content."""
    findings = []
    seen = set()

    def _add(match_text: str, offset: int, length: int, is_absolute: bool):
        if match_text in seen:
            return
        seen.add(match_text)

        if is_absolute:
            if _is_noise_domain(match_text):
                return
            kind = "WebSocket" if match_text.startswith(("ws://", "wss://")) else "External URL"
            sev = Severity.MEDIUM if kind == "WebSocket" else Severity.LOW
        else:
            if not _looks_like_endpoint_path(match_text):
                return
            pl = match_text.lower()
            if "/graphql" in pl:
                kind = "GraphQL endpoint"
                sev = Severity.HIGH
            elif pl.startswith(("/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/rpc/", "/api", "/v1", "/v2", "/v3", "/rest", "/rpc")):
                kind = "REST API path"
                sev = Severity.MEDIUM
            elif re.search(r"[{:$]", match_text):
                kind = "REST API path (templated)"
                sev = Severity.MEDIUM
            else:
                kind = "Path"
                sev = Severity.LOW

            # Boost internal-looking paths
            if any(seg in pl for seg in ("/admin", "/internal", "/debug", "/private", "/api/v1/internal", "/_private", "/_internal")):
                sev = Severity.HIGH
            # BOLA/IDOR signal
            if re.search(r"/(?:users?|accounts?|profiles?|orders?|transactions?|invoices?)/(?:\{|\$|:)", pl):
                sev = Severity.HIGH

        method = _guess_http_method(content, offset)
        title = f"{kind}: {match_text}"
        if method:
            title = f"{method} {title}"

        ctx = _make_context(content, offset, length)
        findings.append(Finding(
            category=Category.ENDPOINT,
            severity=sev,
            detector="extractor:endpoint",
            title=title,
            description=f"Extracted {kind.lower()} from JavaScript",
            file=file_label,
            line=_find_line_number(content, offset),
            match=match_text,
            context=ctx,
            source_url=source_url,
        ))

    # 1. Absolute URLs
    for m in ABSOLUTE_HTTP_RE.finditer(content):
        _add(m.group(0), m.start(), m.end() - m.start(), is_absolute=True)
    for m in WEBSOCKET_URL_RE.finditer(content):
        if m.group(0) not in seen:
            _add(m.group(0), m.start(), m.end() - m.start(), is_absolute=True)

    # 2. API-like paths (with known prefixes)
    # group(1) is the actual path; group(0) may include leading non-word char.
    for m in ANY_API_LIKE_PATH_RE.finditer(content):
        path = m.group(1)
        # Offset is the position of the path start, not the prefix char
        path_start = m.start(1)
        _add(path, path_start, m.end(1) - path_start, is_absolute=False)

    # 3. Templated paths (any 2+ segment path with a {param} or :param)
    for m in TEMPLATE_PATH_RE.finditer(content):
        path = m.group(1)
        path_start = m.start(1)
        _add(path, path_start, m.end(1) - path_start, is_absolute=False)

    # 4. Generic multi-segment paths
    for m in GENERIC_PATH_RE.finditer(content):
        path = m.group(1)
        path_start = m.start(1)
        _add(path, path_start, m.end(1) - path_start, is_absolute=False)

    return findings
