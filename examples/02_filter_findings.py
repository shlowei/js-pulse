#!/usr/bin/env python3
"""
Example 02 — Filter findings by severity / category.

When you scan a real app, you get 200+ findings. You don't want to read
all of them. Filter aggressively:

  - Severity >= HIGH for the "go verify right now" queue
  - Category 'secret' for the "is this a real leak" queue
  - Min score for CI gating

This example shows all three filtering modes using the Reporter's
min_score, plus a manual filter pass.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import (
    HTTPClient,
    JSCrawler,
    AnalysisResult,
    SecretScanner,
    VulnPatternAnalyzer,
    EndpointAnalyzer,
    Reporter,
    Severity,
    Category,
)


def main():
    target = "https://example.com"

    http = HTTPClient(timeout=15, max_concurrent=5)
    crawler = JSCrawler(http, max_bundles=20)
    crawl = crawler.crawl(target)

    result = AnalysisResult(target=target)

    # Only run the analyzers we care about for a high-signal pass
    high_signal = [SecretScanner(), VulnPatternAnalyzer(), EndpointAnalyzer()]
    for bundle in crawl.bundles:
        for analyzer in high_signal:
            try:
                result.findings.extend(
                    analyzer.analyze(bundle.content, source=bundle.url)
                )
            except Exception as e:
                result.errors.append(f"{analyzer.name}: {e}")

    # Manual pass: only CRITICAL and HIGH
    critical_and_high = [
        f for f in result.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]

    # Manual pass: only secrets
    secrets_only = [f for f in result.findings if f.category == Category.SECRET]

    print(f"[*] Total findings:           {len(result.findings)}")
    print(f"[*] CRITICAL + HIGH:          {len(critical_and_high)}")
    print(f"[*] Secret-category only:     {len(secrets_only)}")
    print()

    # Reporter-side filter (alt approach): min_score=80 catches CRITICAL + HIGH
    reporter = Reporter(format="markdown", min_score=80, no_color=True)
    md = reporter.render(result)

    out_path = os.path.join(os.path.dirname(__file__), "high_signal_report.md")
    with open(out_path, "w") as f:
        f.write(md)
    print(f"[+] Wrote {out_path}")


if __name__ == "__main__":
    main()
