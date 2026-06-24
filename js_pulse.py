#!/usr/bin/env python3
"""
js-pulse — Hunt API endpoints, secrets, and bug bounty gold buried in JS.

Usage:
  js_pulse.py scan <url>                # fetch a page, find all JS, analyze
  js_pulse.py analyze <file_or_url>...  # analyze specific JS files
  js_pulse.py patterns                  # list detection patterns
  js_pulse.py version
"""
import sys
import os
import argparse
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.http_client import HTTPClient
from core.js_crawler import JSCrawler, JSCrawler as _JC  # type: ignore
from core.extractor import extract_endpoints
from core.finding import AnalysisResult
from core.analyzers import get_all_analyzers
from core.reporter import Reporter


VERSION = "0.1.0"


# ============== Commands ==============

def cmd_scan(args):
    """Fetch a page, find all its JS, analyze it all."""
    url = args.url
    if "://" not in url:
        url = "https://" + url

    client = HTTPClient(timeout=args.timeout, verify_ssl=False)
    crawler = JSCrawler(http_client=client, max_bundles=args.max_bundles)
    analyzers = get_all_analyzers()

    if args.verbose:
        print(f"[i] Fetching {url} ...", file=sys.stderr)

    crawl = crawler.crawl(url)
    if crawl.errors and not crawl.bundles:
        for e in crawl.errors:
            print(f"[!] {e}", file=sys.stderr)
        sys.exit(2)

    if args.verbose:
        external = sum(1 for b in crawl.bundles if b.bundle_url)
        inline = sum(1 for b in crawl.bundles if b.is_inline)
        print(f"[i] Found {external} external + {inline} inline script(s)", file=sys.stderr)

    # Save JS bundles if requested
    if args.save_js:
        save_dir = Path(args.save_js)
        save_dir.mkdir(parents=True, exist_ok=True)
        for b in crawl.bundles:
            if b.is_inline:
                continue
            if not b.bundle_url:
                continue
            # Derive a filename
            name = b.bundle_url.split("/")[-1].split("?")[0] or "bundle.js"
            name = "".join(c for c in name if c.isalnum() or c in "._-") or "bundle.js"
            out = save_dir / name
            try:
                out.write_text(b.content, encoding="utf-8", errors="replace")
            except Exception as e:
                print(f"[!] Failed to save {out}: {e}", file=sys.stderr)

    # Run the analysis pipeline
    result = AnalysisResult(source=f"scan:{url}")
    result.total_files = len(crawl.bundles)

    for bundle in crawl.bundles:
        if not bundle.content:
            continue
        result.total_chars += len(bundle.content)

        # Save errors but don't bail
        if bundle.error:
            result.errors.append(f"{bundle.bundle_url or 'inline'}: {bundle.error}")
            continue

        # 1. Extract endpoints (first pass)
        endpoints = extract_endpoints(
            content=bundle.content,
            file_label=bundle.bundle_url or f"inline:{bundle.source_url}",
            source_url=bundle.bundle_url or bundle.source_url,
        )
        result.extend(endpoints)

        # 2. Run all analyzers
        for analyzer in analyzers:
            try:
                findings = analyzer.analyze(
                    content=bundle.content,
                    file_label=bundle.bundle_url or f"inline:{bundle.source_url}",
                    source_url=bundle.bundle_url or bundle.source_url,
                )
                result.extend(findings)
            except Exception as e:
                if args.verbose:
                    print(f"[!] analyzer {analyzer.NAME} failed: {e}", file=sys.stderr)

    # Dedup
    result.dedup()

    # Render output
    reporter = Reporter(format=args.format, no_color=args.no_color, min_score=args.min_score)
    output = reporter.render(result)
    print(output)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        if args.verbose:
            print(f"[+] Saved to {args.output}", file=sys.stderr)

    sys.exit(0)


def cmd_analyze(args):
    """Analyze specific files (local or URLs) without crawling."""
    analyzers = get_all_analyzers()
    client = HTTPClient(timeout=args.timeout, verify_ssl=False)

    result = AnalysisResult(source=f"analyze:{','.join(args.targets)}")
    result.total_files = len(args.targets)

    for target in args.targets:
        # Decide local vs remote
        if target.startswith(("http://", "https://")):
            if args.verbose:
                print(f"[i] Fetching {target} ...", file=sys.stderr)
            resp = client.get(target)
            if not resp.ok:
                result.errors.append(f"{target}: {resp.error or resp.status_code}")
                continue
            content = resp.text()
            file_label = target
            source_url = target
        else:
            if not os.path.isfile(target):
                result.errors.append(f"{target}: file not found")
                continue
            try:
                with open(target, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception as e:
                result.errors.append(f"{target}: {e}")
                continue
            file_label = target
            source_url = ""

        result.total_chars += len(content)

        # Endpoints
        endpoints = extract_endpoints(content=content, file_label=file_label, source_url=source_url)
        result.extend(endpoints)

        # Analyzers
        for analyzer in analyzers:
            try:
                findings = analyzer.analyze(content=content, file_label=file_label, source_url=source_url)
                result.extend(findings)
            except Exception as e:
                if args.verbose:
                    print(f"[!] {analyzer.NAME} failed on {target}: {e}", file=sys.stderr)

    result.dedup()

    reporter = Reporter(format=args.format, no_color=args.no_color, min_score=args.min_score)
    output = reporter.render(result)
    print(output)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        if args.verbose:
            print(f"[+] Saved to {args.output}", file=sys.stderr)

    sys.exit(0)


def cmd_patterns(args):
    """List all detection patterns."""
    print(f"\n{'=' * 70}")
    print(" js-pulse detection patterns")
    print(f"{'=' * 70}\n")

    from core.analyzers import get_all_analyzers
    analyzers = get_all_analyzers()

    # Endpoint extractor
    print("[Extractor] endpoint extraction")
    print("  - Absolute URLs (http/https/ws/wss)")
    print("  - API paths (/api/*, /v1/*, /rest/*, /graphql)")
    print("  - Generic multi-segment paths")
    print("  - HTTP method association (heuristic)\n")

    for analyzer in analyzers:
        print(f"[{analyzer.NAME}]")
        if hasattr(analyzer, "PATTERNS"):
            for p in analyzer.PATTERNS:
                if isinstance(p, tuple) and len(p) >= 3:
                    if len(p) == 3:
                        pat, name, sev = p
                    else:
                        pat, name, sev = p[0], p[1], p[3]
                    print(f"  - {name:<40} ({sev.value})")
        elif analyzer.NAME == "endpoint_analyzer":
            print("  - Re-scores endpoints by category (auth/admin/user-data/financial/etc.)")
        print()

    print(f"{'=' * 70}")
    print(" All patterns can be tuned in core/analyzers/*.py")
    print(f"{'=' * 70}\n")


def cmd_version(args):
    print(f"js-pulse {VERSION}")


# ============== Main ==============

def main():
    # Global options (shared with subcommands via parents=)
    global_opts = argparse.ArgumentParser(add_help=False)
    global_opts.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    global_opts.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds (default: 15)")
    global_opts.add_argument("--format", choices=["console", "text", "json", "csv", "markdown"], default="console")
    global_opts.add_argument("--min-score", type=int, default=0, help="Only show findings with score >= N (default: 0)")
    global_opts.add_argument("-o", "--output", help="Output file")
    global_opts.add_argument("--no-color", action="store_true", help="Disable ANSI colors")

    parser = argparse.ArgumentParser(
        prog="js-pulse",
        parents=[global_opts],
        description="js-pulse — Hunt API endpoints, secrets, and bug bounty gold in JS bundles.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  js_pulse.py scan https://example.com
  js_pulse.py scan https://example.com --min-score 60 -o report.md
  js_pulse.py analyze main.chunk.js
  js_pulse.py analyze https://target.com/static/app.js --format json
  js_pulse.py patterns
""",
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit")

    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", parents=[global_opts], help="Fetch a page, find all JS, analyze")
    p_scan.add_argument("url", help="Page URL to start from")
    p_scan.add_argument("--max-bundles", type=int, default=50, help="Max JS bundles to fetch (default: 50)")
    p_scan.add_argument("--save-js", help="Directory to save raw JS bundles")

    # analyze
    p_an = sub.add_parser("analyze", parents=[global_opts], help="Analyze specific files (local or URLs)")
    p_an.add_argument("targets", nargs="+", help="Files or URLs to analyze")

    # patterns
    sub.add_parser("patterns", parents=[global_opts], help="List detection patterns")

    args = parser.parse_args()

    if args.version or args.command == "version":
        cmd_version(args)
        return

    if not args.command:
        parser.print_help()
        sys.exit(0)

    cmds = {
        "scan": cmd_scan,
        "analyze": cmd_analyze,
        "patterns": cmd_patterns,
    }
    cmds[args.command](args)


if __name__ == "__main__":
    main()