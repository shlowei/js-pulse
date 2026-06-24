# js-pulse — Architecture

## Design goals

1. **Zero external dependencies.** Pure Python 3.8+ stdlib. Drop it on a box with `python3` and it works. No `pip install`, no venv drama.
2. **Static analysis only.** We never execute JS, never spin up a headless browser. Just regex on raw text.
3. **Attacker's mindset.** Every analyzer is built from "what would I look for during a recon phase of a pentest?"
4. **Composable.** The 5 analyzers are independent. Use one, use all, swap in your own.

## Pipeline

```
                   ┌──────────────┐
   target URL ───▶ │  HTTPClient  │  (concurrent fetches, rate-limited)
                   └──────┬───────┘
                          │ raw HTML
                          ▼
                   ┌──────────────┐
                   │  JSCrawler   │  (regex out <script src=...>)
                   └──────┬───────┘
                          │ list of JSBundle{url, content}
                          ▼
              ┌───────────────────────┐
              │      Analyzers        │
              │ ┌──────────────────┐  │
              │ │ EndpointAnalyzer │  │──▶ Finding
              │ ├──────────────────┤  │
              │ │ SecretScanner    │  │──▶ Finding
              │ ├──────────────────┤  │
              │ │ URLAnalyzer      │  │──▶ Finding
              │ ├──────────────────┤  │
              │ │ VulnPattern      │  │──▶ Finding
              │ ├──────────────────┤  │
              │ │ InfoDisclosure   │  │──▶ Finding
              │ └──────────────────┘  │
              └───────────┬───────────┘
                          │ List[Finding]
                          ▼
                   ┌──────────────┐
                   │   Reporter   │  (text / json / csv / markdown)
                   └──────────────┘
```

## Module layout

```
js_pulse.py           CLI entry — argparse, subcommand dispatch
core/
  __init__.py         Public API re-exports
  http_client.py      HTTPClient, HTTPResponse — concurrent stdlib fetcher
  js_crawler.py       JSCrawler, JSBundle — finds and fetches all JS
  extractor.py        extract_endpoints() — regex-based endpoint extraction
  finding.py          Finding, Severity, Category, AnalysisResult — the data model
  reporter.py         Reporter — multi-format output

  analyzers/
    endpoint_analyzer.py    Runs extractor, scores endpoints by risk
    secret_scanner.py       AWS / GCP / Stripe / GitHub / generic API key regex
    url_analyzer.py         External URLs, subdomains, sourcemap refs
    vuln_pattern.py         eval(), innerHTML, document.write, weak crypto, localStorage secrets
    info_disclosure.py      Debug endpoints, stack traces, internal paths
```

## Why regex, not AST?

JS bundles from webpack/Vite/Rollup are minified single-line nightmares. A `babel.parse` on a 500KB minified bundle will:
- Take seconds
- Produce a tree with 100k+ nodes, most of which are noise
- Miss string-literal URLs (which is where 80% of endpoints live)

Regex on the raw text catches the same things faster, with smaller code, zero deps. Trade-off: we miss some obfuscated cases. That's accepted — we surface 85% of what a human would grep for, in 0.3s.

## Severity model

Not CVSS. A "how likely is this to be a real bug, and how bad if so" heuristic:

| Level    | Score | When I assign it                                |
|----------|-------|-------------------------------------------------|
| CRITICAL | 95    | Real-looking secret (not a placeholder/example) |
| HIGH     | 80    | Strong signal: admin path, eval(), AK in code  |
| MEDIUM   | 60    | Worth a look: suspicious path, weak crypto      |
| LOW      | 40    | Informational: external URL, sourcemap ref      |
| INFO     | 20    | FYI: dev comments, version strings              |

The score is what `--min-score` filters on.

## Concurrency model

`HTTPClient` uses a `ThreadPoolExecutor` (stdlib) for concurrent fetches. Default 5 workers, configurable. Rate-limit is a simple per-host token bucket — no deps, no surprises. Each fetch has its own timeout (default 15s) and retries once on connection error.

## Extending

Drop a new file in `core/analyzers/`:

```python
from ..finding import Finding, Category, Severity

class MyAnalyzer:
    name = "my_analyzer"
    description = "What it does"

    def analyze(self, content: str, source: str = None) -> list[Finding]:
        findings = []
        # ... your logic ...
        return findings
```

Add it to `core/analyzers/__init__.py::get_all_analyzers()`. Done.

## What js-pulse deliberately doesn't do

- **Deobfuscate JS.** That's a separate, hard problem (and a separate tool).
- **Follow webpack chunk loading dynamically.** We catch the entry bundle and any statically referenced URLs. Runtime-loaded chunks (`__webpack_require__.u(chunkId)`) are out of scope.
- **Execute the JS.** Pure static. No headless browser.
- **Auth-aware scanning.** Pass us a JS bundle URL with a session cookie and we'll fetch it. We don't handle auth flows.
