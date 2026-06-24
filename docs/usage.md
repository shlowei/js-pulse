# js-pulse — Usage Guide

## CLI quick start

```bash
# Scan a target URL — fetch the page, find all JS, analyze
python3 js_pulse.py scan https://example.com

# Scan + filter to HIGH+ and write a markdown report
python3 js_pulse.py scan https://example.com --min-score 60 -o report.md

# Analyze a local JS file you already downloaded
python3 js_pulse.py analyze main.chunk.js

# Analyze a remote JS file directly (skip the crawl)
python3 js_pulse.py analyze https://target.com/static/app.js --format json

# Dump raw JSON for piping into jq / SIEM
python3 js_pulse.py analyze app.js --format json | jq '.findings[] | select(.severity=="CRITICAL")'

# List all detection patterns
python3 js_pulse.py patterns
```

## CLI reference

```
js_pulse.py scan <url>       [options]
js_pulse.py analyze <files…> [options]
js_pulse.py patterns

Options:
  -v, --verbose         Verbose output
  --timeout N           HTTP timeout in seconds (default: 15)
  --format FMT          console | text | json | csv | markdown  (default: console)
  --min-score N         Only show findings with score >= N  (default: 0)
  -o, --output FILE     Write report to file
  --no-color            Disable ANSI colors

  scan only:
    --max-bundles N     Max JS bundles to fetch  (default: 50)
    --save-js DIR       Save raw JS bundles to directory
```

## Output formats

### `console` (default)
Colored table, ANSI codes. Human eyes only.

### `text`
Pipe-friendly, one finding per line:
```
CRITICAL 95  secret       secret_scanner:AWS Access Key ID  https://t.com/app.js:142  Possible AWS Access Key ID  AKIA...
HIGH     80  endpoint     extractor:endpoint                  https://t.com/app.js:88   Path: /admin/dashboard       /admin/dashboard
```

### `json`
Structured. Use this for CI, SIEM, jq:
```json
{
  "target": "https://example.com",
  "scanned_at": "2026-06-23T10:00:00",
  "summary": {"total": 42, "by_severity": {...}, "by_category": {...}},
  "findings": [
    {"severity": "CRITICAL", "score": 95, "category": "secret", "type": "...", "source": "...", "location": "...", "description": "...", "evidence": "..."}
  ]
}
```

### `csv`
Excel-friendly. Columns: `severity, score, category, type, source, location, description, evidence`.

### `markdown`
Drop into a report:
```markdown
# js-pulse Report — https://example.com
**Scanned:** 2026-06-23T10:00:00  **Findings:** 42

## Summary
| Severity | Count |
|---|---|
| CRITICAL | 2 |
...
```

## Python API

```python
import sys; sys.path.insert(0, ".")
from core import (
    HTTPClient, JSCrawler,
    AnalysisResult, get_all_analyzers, Reporter,
    extract_endpoints,                       # low-level regex
    Severity, Category,                      # enums
    SecretScanner, VulnPatternAnalyzer,      # individual analyzers
)

# Full crawl + analyze
http = HTTPClient(timeout=15, max_concurrent=5)
crawler = JSCrawler(http, max_bundles=50)
crawl = crawler.crawl("https://example.com")

result = AnalysisResult(target="https://example.com")
for bundle in crawl.bundles:
    for analyzer in get_all_analyzers():
        result.findings.extend(analyzer.analyze(bundle.content, source=bundle.url))

# Filter and render
reporter = Reporter(format="markdown", min_score=80)
print(reporter.render(result))
```

See `examples/` for 3 worked examples:
- `01_basic_scan.py` — minimal end-to-end
- `02_filter_findings.py` — severity / category filtering
- `03_triage_workflow.py` — risk-ranked endpoint triage

## Common workflows

### "I just want to know if there are real secrets"
```bash
python3 js_pulse.py analyze app.js --format text --no-color --min-score 80 | grep -i secret
```

### "Give me a JSON dump for my SIEM"
```bash
python3 js_pulse.py scan https://target.com --format json -o findings.json
```

### "I already have the JS file, don't crawl"
```bash
python3 js_pulse.py analyze ./downloads/app.chunk.js --format markdown -o report.md
```

### "I want to add my own analyzer"
1. Create `core/analyzers/my_analyzer.py` with an `analyze(content, source)` method
2. Add it to `get_all_analyzers()` in `core/analyzers/__init__.py`
3. Run `python3 js_pulse.py scan …` — your analyzer runs alongside the built-ins

## Caveats

- **False positives are expected.** A finding is a "look here", not a "this is a bug". Verify before reporting.
- **Detection is regex-based.** Heavily obfuscated code (e.g. `String.fromCharCode(...)` chains) will be missed. That's accepted.
- **No authentication.** If a target requires login, fetch the JS with cookies out-of-band and pass it to `analyze`.
- **Be polite.** Default 5 concurrent connections. Add `--max-bundles N` to limit scope. Don't hammer prod.
