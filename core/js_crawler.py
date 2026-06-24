"""
JS crawler — given a URL, find all the JS files.

This is intentionally simple. We're not trying to be a real crawler
(headless browser, JS execution, etc.). We're just doing what curl + grep would do,
but packaged nicely.

What we handle:
  - <script src="..."> in the HTML
  - Inline <script>...</script> blocks
  - Relative URLs (./js/app.js, /static/main.js, etc.)
  - Source map references at the bottom of JS files (//# sourceMappingURL=...)

What we don't handle (yet):
  - Dynamically-loaded JS (script injection, webpack chunk loading)
  - Service workers
  - Cross-origin scripts loaded from iframes
"""
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional, Set
from html.parser import HTMLParser

from .http_client import HTTPClient, HTTPResponse


@dataclass
class JSBundle:
    """A piece of JS to analyze. Either an external URL or inline content."""
    source_url: str                       # Where we got it from (page URL for inline, full URL for external)
    bundle_url: Optional[str] = None       # External URL, if applicable
    content: str = ""
    size: int = 0
    is_inline: bool = False
    source_map_url: Optional[str] = None
    error: Optional[str] = None


@dataclass
class CrawlResult:
    base_url: str
    bundles: List[JSBundle] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    redirected_from: Optional[str] = None


class _ScriptExtractor(HTMLParser):
    """Pulls <script src=...> and inline <script> from HTML."""

    def __init__(self):
        super().__init__()
        self.scripts: List[tuple] = []  # (src_or_None, content_or_None)
        self._in_script = False
        self._current_script = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            attrs_dict = dict(attrs)
            src = attrs_dict.get("src")
            if src is not None:
                # External script — empty content for now
                self.scripts.append((src, None))
            else:
                self._in_script = True
                self._current_script = []

    def handle_data(self, data):
        if self._in_script:
            self._current_script.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._in_script:
            self._in_script = False
            content = "".join(self._current_script)
            if content.strip():
                self.scripts.append((None, content))


class JSCrawler:
    """
    Walks a page, finds JS files, downloads them.

    Usage:
        crawler = JSCrawler()
        result = crawler.crawl("https://example.com")
        for bundle in result.bundles:
            print(bundle.bundle_url, len(bundle.content))
    """

    # Common inline-script patterns we always want to inspect
    # (vs. e.g. a giant JSON blob for hydration that's mostly noise)
    MIN_INLINE_JS_LENGTH = 30

    # Source map reference at end of bundle
    SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s'\"\n]+)", re.I)

    def __init__(self, http_client: Optional[HTTPClient] = None, max_bundles: int = 50):
        self.client = http_client or HTTPClient()
        self.max_bundles = max_bundles
        # Track visited URLs to avoid loops
        self._visited: Set[str] = set()

    def crawl(self, url: str) -> CrawlResult:
        result = CrawlResult(base_url=url)

        if "://" not in url:
            url = "https://" + url

        # Fetch the page itself
        page_resp = self.client.get(url)
        if not page_resp.ok:
            result.errors.append(f"page fetch failed: {page_resp.error or page_resp.status_code}")
            return result
        result.redirected_from = page_resp.redirected_from
        final_url = page_resp.url

        # Extract scripts
        parser = _ScriptExtractor()
        try:
            parser.feed(page_resp.text())
        except Exception as e:
            result.errors.append(f"html parse error: {e}")

        # Resolve URLs against the final URL (after redirects)
        base = urllib.parse.urlparse(final_url)
        for src, inline in parser.scripts:
            if len(result.bundles) >= self.max_bundles:
                result.errors.append(f"hit max_bundles={self.max_bundles}, stopping")
                break

            if src is not None:
                # External script
                bundle_url = urllib.parse.urljoin(final_url, src)
                if bundle_url in self._visited:
                    continue
                self._visited.add(bundle_url)

                bundle = self._fetch_bundle(bundle_url, final_url)
                result.bundles.append(bundle)
            else:
                # Inline script
                if len(inline) < self.MIN_INLINE_JS_LENGTH:
                    continue
                bundle = JSBundle(
                    source_url=final_url,
                    bundle_url=None,
                    content=inline,
                    size=len(inline),
                    is_inline=True,
                )
                result.bundles.append(bundle)

        return result

    def _fetch_bundle(self, bundle_url: str, page_url: str) -> JSBundle:
        """Fetch one external JS bundle."""
        bundle = JSBundle(source_url=page_url, bundle_url=bundle_url)
        try:
            resp = self.client.get(bundle_url)
            if not resp.ok:
                bundle.error = resp.error or f"status {resp.status_code}"
                return bundle
            bundle.content = resp.text()
            bundle.size = len(bundle.content)
            # Look for sourcemap reference
            m = self.SOURCEMAP_RE.search(bundle.content)
            if m:
                sm_url = m.group(1)
                if not sm_url.startswith(("http://", "https://", "data:")):
                    sm_url = urllib.parse.urljoin(bundle_url, sm_url)
                bundle.source_map_url = sm_url
        except Exception as e:
            bundle.error = str(e)
        return bundle

    @staticmethod
    def is_javascript_url(url: str) -> bool:
        """Check whether a URL points to a JS file (by extension or path)."""
        path = urllib.parse.urlparse(url).path.lower()
        return (
            path.endswith(".js")
            or path.endswith(".mjs")
            or path.endswith(".jsx")
            or ".js?" in path
            or path.endswith(".ts")
            or path.endswith(".tsx")
        )