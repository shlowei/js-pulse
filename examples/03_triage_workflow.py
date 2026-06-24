#!/usr/bin/env python3
"""
Example 03 — Programmatic triage: extract endpoints, dedupe, sort by risk.

This is the workflow I'd actually use during a recon phase:

  1. Crawl the target
  2. Extract endpoints (raw regex)
  3. Run secret + vuln pattern analyzers
  4. Group findings by URL path
  5. For each path, show: did we see a secret near it? a vuln signal?
  6. Output a "risk-ranked" endpoint list

The output is what I'd feed into my next tool: manually probe the
top-N paths, look for IDOR / auth-bypass / etc.
"""
import sys
import os
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import (
    HTTPClient,
    JSCrawler,
    AnalysisResult,
    extract_endpoints,
    SecretScanner,
    VulnPatternAnalyzer,
    InfoDisclosureAnalyzer,
    Severity,
)


def main():
    target = "https://example.com"

    http = HTTPClient(timeout=15, max_concurrent=5)
    crawler = JSCrawler(http, max_bundles=20)
    crawl = crawler.crawl(target)

    # 1) Raw endpoint extraction
    all_endpoints = []
    for bundle in crawl.bundles:
        all_endpoints.extend(extract_endpoints(bundle.content))

    # Dedupe
    seen = set()
    unique_endpoints = []
    for ep in all_endpoints:
        key = (ep.path, ep.method)
        if key in seen:
            continue
        seen.add(key)
        unique_endpoints.append(ep)

    # 2) Run analyzers
    result = AnalysisResult(target=target)
    for bundle in crawl.bundles:
        for analyzer in (SecretScanner(), VulnPatternAnalyzer(), InfoDisclosureAnalyzer()):
            try:
                result.findings.extend(analyzer.analyze(bundle.content, source=bundle.url))
            except Exception as e:
                result.errors.append(f"{analyzer.name}: {e}")

    # 3) Group findings by source bundle
    findings_by_source = defaultdict(list)
    for f in result.findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
            findings_by_source[f.source].append(f)

    # 4) Risk score: count CRITICAL=3, HIGH=2, MEDIUM=1 per bundle, attach to endpoints
    bundle_score = {}
    for src, fs in findings_by_source.items():
        s = 0
        for f in fs:
            s += {Severity.CRITICAL: 3, Severity.HIGH: 2, Severity.MEDIUM: 1}[f.severity]
        bundle_score[src] = s

    # 5) Rank endpoints by their bundle's risk score
    ranked = sorted(
        unique_endpoints,
        key=lambda ep: bundle_score.get(ep.source or "", 0),
        reverse=True,
    )

    # 6) Print
    print(f"[*] {len(unique_endpoints)} unique endpoints across {len(crawl.bundles)} bundle(s)")
    print(f"[*] Top risk-ranked paths:\n")
    print(f"  {'SCORE':<6} {'METHOD':<8} PATH")
    print(f"  {'-'*6} {'-'*8} {'-'*40}")
    for ep in ranked[:30]:
        src = ep.source or ""
        score = bundle_score.get(src, 0)
        marker = "🔥" if score >= 3 else "  "
        print(f"  {marker}{score:<4} {ep.method or '-':<8} {ep.path}")


if __name__ == "__main__":
    main()
