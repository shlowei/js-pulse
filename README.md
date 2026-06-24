# js-pulse

> Hunt API endpoints, secrets, and bug bounty gold buried in frontend JavaScript. Pure static analysis. Zero dependencies.

![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)
![Status](https://img.shields.io/badge/status-WIP-yellow)

---

You know that feeling when you pop open `main.chunk.js` in your target's web app, hit `Ctrl+F` and search for `/api`, and you see a waterfall of endpoints you never knew existed? Routes the docs never mentioned. Internal admin paths. Debug toggles still wired up to live servers. Half the time, somebody left an AWS key in there too.

`js-pulse` is the tool I built because I got tired of doing that by hand.

It's not magic. It doesn't fire payloads at your target. It just reads JavaScript like a tired, paranoid bug bounty hunter would — and writes down what it finds.

**What it pulls out of a JS bundle:**

- API endpoints (REST, GraphQL, WebSocket) with HTTP methods attached
- Secrets & API keys (AWS, Stripe, Slack, GitHub, JWTs with `alg: none`, etc.)
- Internal infrastructure (private IPs, internal domains, subdomains you didn't know about)
- Bug surface — SSRF-prone parameters, hardcoded SQL, `eval()` calls, hidden admin paths
- Anything that looks like it shouldn't be in a public JS file

**What it does NOT do:**

- Doesn't send a single HTTP request unless you ask it to (it just analyzes the JS you give it)
- Doesn't exploit anything — it surfaces signals, you do the verification
- Doesn't pretend a finding is a vulnerability. A high score means "worth a closer look", not "pwned"

---

## Install

It's a single Python file with no dependencies.

```bash
git clone https://github.com/yourname/js-pulse.git
cd js-pulse
chmod +x js_pulse.py
./js_pulse.py --help
```

Or grab the single file:

```bash
wget https://raw.githubusercontent.com/yourname/js-pulse/main/js_pulse.py
chmod +x js_pulse.py
```

Python 3.8+. That's it.

---

## Quick start

Point it at a page, get a report:

```bash
./js_pulse.py scan https://target.com --format markdown -o report.md
```

Or feed it a local JS file you already grabbed:

```bash
./js_pulse.py analyze app.bundle.js -o findings.json
```

Want to pull a single JS file by URL and analyze it? Same command, the URL form works for both HTML pages and direct .js links.

A few useful flags:

```bash
# Only show high-confidence findings
./js_pulse.py scan https://target.com --min-score 60

# Pipe-friendly text output (one finding per line, great for grep/awk)
./js_pulse.py scan https://target.com --format text

# Save the raw JS bundles alongside the report (useful for archival)
./js_pulse.py scan https://target.com --save-js ./bundles/

# Skip the crawler — analyze only the URLs you give it
./js_pulse.py analyze https://target.com/app.js https://target.com/vendor.js
```

---

## What the output looks like

```text
$ ./js_pulse.py scan https://example.com

[i] Fetching https://example.com ... (1.2 KB)
[i] Found 3 <script> tags
[i] Downloading 2 external scripts ...
    [+] /static/js/main.chunk.js   (142 KB)
    [+] /static/js/vendor.chunk.js (387 KB)
[i] Analyzing 2 bundles (529 KB total) ...

═══════════════════════════════════════════════════════════════
 js-pulse findings — example.com
═══════════════════════════════════════════════════════════════

[HIGH] AWS Access Key (AKIA...)
  ├─ file:    main.chunk.js
  ├─ match:   AKIA[0-9A-Z]{16} in line 4291
  └─ context: const AWS_KEY = "AKIA...";  // legacy, see ops

[HIGH] Internal API endpoint with IDOR potential
  ├─ file:    main.chunk.js
  ├─ match:   /api/v1/internal/users/{id}
  └─ context: api.get(`/api/v1/internal/users/${uid}`)

[MED]  Debug code still shipped to production
  ├─ file:    vendor.chunk.js
  └─ match:   console.log("DEBUG: cart state =", state)

[MED]  WebSocket endpoint (potential real-time attack surface)
  ├─ file:    main.chunk.js
  └─ match:   wss://realtime.example.com/socket

[LOW]  Email address in JS source
  ├─ file:    main.chunk.js
  └─ match:   support@example.com

═══════════════════════════════════════════════════════════════
 Summary: 2 high · 3 medium · 4 low · 7 informational
═══════════════════════════════════════════════════════════════
```

The `--format json` output is structured for piping into other tools (see the schema at the bottom of this README).

---

## Commands

| Command | What it does |
|---------|--------------|
| `scan <url>` | Fetch a page, discover its JS files, crawl and analyze them all |
| `analyze <files...>` | Skip the crawl — analyze JS files you already have (local paths or URLs) |
| `patterns` | List every detection pattern the tool knows about (useful for tuning) |
| `version` | Print the version and exit |

Global flags: `--format`, `--min-score`, `--save-js`, `--no-color`, `--verbose`.

---

## How it works (short version)

1. **Crawl** — given a URL, fetch the HTML, extract every `<script src=...>` (and inline scripts).
2. **Fetch** — download each external script. Handle sourcemaps too, if `--sourcemaps` is on.
3. **Extract** — for each bundle, run a battery of regex + heuristic extractors:
   - URL-like patterns (paths, full URLs, templated paths)
   - HTTP method names near URLs (rough association, we don't claim 100% accuracy)
   - Known secret formats (prefixed keys, JWTs, base64 blobs that decode to JSON, etc.)
   - Suspicious calls (`eval`, `Function`, `document.write`, `innerHTML =`)
   - Hardcoded emails, IPs (with private range detection), internal-looking hostnames
4. **Score** — every finding gets a 0-100 score. Things that look like real keys score high. Things that look like `example.com` in a comment score low.
5. **Report** — format the findings as text/JSON/CSV/Markdown and either print or save.

The full architecture is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). It's not deep, but it's honest about the tradeoffs.

---

## Detection patterns

Run `./js_pulse.py patterns` to see the live list. At last count, js-pulse recognizes:

- **20+ secret formats** — AWS, Stripe (live + restricted keys), GitHub PATs, Slack tokens, Google API keys, JWTs, SendGrid, Mailgun, Twilio, npm, Discord, Telegram bots, etc.
- **8+ endpoint shapes** — REST paths, GraphQL queries, WebSocket URLs, RPC-style method names, static asset paths (filtered out by default)
- **6+ vuln surface signals** — SSRF-prone parameter names, hardcoded SQL fragments, dangerous sinks, internal-only hostnames, debug leftovers
- **PII extractors** — emails, phone numbers, internal IPs, private hostnames

To add your own pattern, see [docs/ADD_PATTERN.md](docs/ADD_PATTERN.md). The pattern format is deliberately simple — it's just Python regex with metadata, not a DSL.

---

## Why not just use LinkFinder / getjs / subjs?

| | js-pulse | LinkFinder | getjs | subjs |
|---|---|---|---|---|
| Endpoint extraction | ✅ | ✅ (URLs only) | ❌ | ❌ |
| HTTP method association | ✅ (heuristic) | ❌ | ❌ | ❌ |
| Secret scanning | ✅ (20+ formats) | ❌ | ❌ | ❌ |
| Vuln surface signals | ✅ | ❌ | ❌ | ❌ |
| Internal infra extraction | ✅ | ❌ | ❌ | ❌ |
| Zero deps, single file | ✅ | ❌ (Python 2) | ❌ (Go) | ❌ (Go) |
| Pipe-friendly output | ✅ | partial | ❌ | ❌ |

LinkFinder is the closest comparison. It's been unmaintained for years and doesn't do anything beyond URL extraction. I still love the idea of it, just not the current state.

---

## When js-pulse is the wrong tool

- **You need to fuzz and exploit.** This tool only reads. Use Burp, Caido, or nuclei.
- **You need authenticated crawling.** js-pulse is unauthenticated. Use a headless browser if you need to log in.
- **You need to bypass CSP / find XSS via reflection.** js-pulse doesn't execute anything.

It's a recon tool. It's the thing you run at the start of an engagement, not the thing that gets you the bounty.

---

## Roadmap

In roughly the order I'm planning to do them:

- [ ] AST-based endpoint extraction (currently regex — works for ~85% of cases, the rest is dynamic construction)
- [ ] Built-in sourcemap-aware deobfuscation for bundles like Webpack/Burble/Vite
- [ ] Confidence-weighted false-positive reduction (track patterns that have historically been false positives)
- [ ] Webhook-friendly output (post findings to Slack/Discord on demand)
- [ ] Plugin system for custom detectors (see [docs/ADD_PATTERN.md](docs/ADD_PATTERN.md) for the current "drop a regex in a folder" approach)

Things I will probably never do because they'd violate the "static only" rule: dynamic JS execution, headless rendering, anything that requires a browser.

---

## Contributing

Two ways to contribute, in order of how much I appreciate them:

1. **Open a PR with a new detection pattern.** This is the highest-leverage contribution. Every bug bounty hunter has a pattern in their notes app that the rest of us would benefit from.
2. **Open an issue with a false positive** you hit. Include the JS snippet (sanitized) and what made it a false positive. I tune the score weights from these.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the boring details.

---

## Disclaimer

Run this on systems you're authorized to test. The author isn't responsible for what you do with it, and "I was just reading the JavaScript" is not a great defense if you weren't supposed to be.

The license is MIT. Do what you want, just don't sue me.

---

## 中文版

中文版 README 在 [README.zh-CN.md](README.zh-CN.md)。