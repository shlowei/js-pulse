#!/usr/bin/env python3
"""
Example 01 — Basic end-to-end scan.

The most common use case: point js-pulse at a target URL, get a report.

This example:
  1. Fetches the start page
  2. Discovers all referenced JS bundles
  3. Fetches each bundle
  4. Runs all 5 analyzers
  5. Prints findings as a table

Target here is a public React app with predictable JS bundles. Swap in
your own target (with permission!) for real bug-hunting work.
"""
import sys
import os

# Allow running from repo root without installing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import (
    HTTPClient,
    JSCrawler,
    AnalysisResult,
    get_all_analyzers,
    Reporter,
)


def main():
    target = "https://example.com"
    print(f"[*] Scanning {target}")

    # Step 1+2: fetch the page and discover JS
    http = HTTPClient(timeout=15, max_concurrent=5)
    crawler = JSCrawler(http, max_bundles=20)
    crawl = crawler.crawl(target)

    print(f"[+] Discovered {len(crawl.bundles)} JS bundle(s)")

    # Step 3+4: run analyzers on each bundle
    analyzers = get_all_analyzers()
    result = AnalysisResult(target=target)

    for bundle in crawl.bundles:
        print(f"  - {bundle.url}  ({len(bundle.content):,} bytes)")
        for analyzer in analyzers:
            try:
                findings = analyzer.analyze(bundle.content, source=bundle.url)
                result.findings.extend(findings)
            except Exception as e:
                result.errors.append(f"{analyzer.name}: {e}")

    # Step 5: render
    reporter = Reporter(format="text", no_color=True)
    print()
    print(reporter.render(result))


if __name__ == "__main__":
    main()
