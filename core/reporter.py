"""
Reporter — format findings in text / JSON / CSV / Markdown.

I tried to make each format actually useful for the stated use case:
  - text:    pipe-friendly, one finding per line
  - json:    structured for CI / SIEM / jq
  - csv:     Excel-friendly
  - markdown: human-readable, drop into a report

If you find yourself wishing a format had a different shape, open an issue
with a sample line and I'll iterate.
"""
import json
import csv
import io
from typing import List, Dict, Any
from collections import Counter

from .finding import Finding, Severity, AnalysisResult


class Reporter:
    """Format AnalysisResult in multiple output modes."""

    SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    SEVERITY_BADGE = {
        Severity.CRITICAL: "🔴 CRIT",
        Severity.HIGH: "🔴 HIGH",
        Severity.MEDIUM: "🟡 MED ",
        Severity.LOW: "🟢 LOW ",
        Severity.INFO: "⚪ INFO",
    }

    def __init__(self, format: str = "console", no_color: bool = False, min_score: int = 0):
        self.format = format
        self.no_color = no_color
        self.min_score = min_score

    def render(self, result: AnalysisResult) -> str:
        # Filter by min_score
        filtered = [f for f in result.findings if f.severity.score >= self.min_score]
        result.findings = filtered
        result.dedup()

        if self.format == "json":
            return self._render_json(result)
        elif self.format == "csv":
            return self._render_csv(result)
        elif self.format == "markdown":
            return self._render_markdown(result)
        elif self.format == "text":
            return self._render_text(result)
        else:  # console
            return self._render_console(result)

    # ============ Console (default) ============

    def _render_console(self, result: AnalysisResult) -> str:
        # ANSI colors
        R = G = Y = B = DIM = BOLD = RST = ""
        if not self.no_color:
            R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
            DIM = "\033[2m"; BOLD = "\033[1m"; RST = "\033[0m"

        out: List[str] = []
        out.append("")
        out.append(f"{BOLD}═══════════════════════════════════════════════════════════════{RST}")
        out.append(f"{BOLD} js-pulse findings{RST}  {DIM}— {result.source}{RST}")
        out.append(f"{BOLD}═══════════════════════════════════════════════════════════════{RST}")
        out.append("")

        if not result.findings:
            out.append(f"  {DIM}No findings above score {self.min_score}.{RST}")
            out.append("")
            return "\n".join(out)

        # Group by severity
        by_sev = result.by_severity()
        for sev in self.SEVERITY_ORDER:
            findings = by_sev.get(sev, [])
            if not findings:
                continue
            for f in sorted(findings, key=lambda x: (x.file, x.line)):
                sev_color = {"CRITICAL": R, "HIGH": R, "MEDIUM": Y, "LOW": G, "INFO": DIM}[sev.value]
                out.append(f"{sev_color}[{sev.value:<8}]{RST} {B}{f.title}{RST}")
                if f.file:
                    out.append(f"  {DIM}├─ file:{RST}    {f.file}:{f.line}")
                if f.match:
                    out.append(f"  {DIM}├─ match:{RST}  {B}{f.match[:80]}{RST}")
                if f.context:
                    out.append(f"  {DIM}└─ context:{RST} {DIM}{f.context}{RST}")
                out.append("")

        # Summary
        out.append(f"{BOLD}───────────────────────────────────────────────────────────────{RST}")
        counts = Counter(f.severity for f in result.findings)
        parts = []
        for sev in self.SEVERITY_ORDER:
            if counts.get(sev):
                parts.append(f"{counts[sev]} {sev.value.lower()}")
        out.append(f" {BOLD}Summary:{RST} " + " · ".join(parts) if parts else " no findings")
        out.append(f"{BOLD}───────────────────────────────────────────────────────────────{RST}")
        out.append("")
        return "\n".join(out)

    # ============ Text (pipe-friendly) ============

    def _render_text(self, result: AnalysisResult) -> str:
        out: List[str] = []
        for f in sorted(result.findings, key=lambda x: (-x.severity.score, x.file, x.line)):
            out.append(f"{f.severity.value}\t{f.severity.score}\t{f.category.value}\t{f.detector}\t{f.file}:{f.line}\t{f.title}\t{f.match}")
        return "\n".join(out) + ("\n" if out else "")

    # ============ JSON ============

    def _render_json(self, result: AnalysisResult) -> str:
        return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)

    # ============ CSV ============

    def _render_csv(self, result: AnalysisResult) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["severity", "score", "category", "detector", "file", "line", "title", "match", "source_url"])
        for f in sorted(result.findings, key=lambda x: (-x.severity.score, x.file, x.line)):
            w.writerow([
                f.severity.value, f.severity.score, f.category.value, f.detector,
                f.file, f.line, f.title, f.match[:200], f.source_url,
            ])
        return buf.getvalue()

    # ============ Markdown ============

    def _render_markdown(self, result: AnalysisResult) -> str:
        out: List[str] = []
        out.append(f"# js-pulse report — `{result.source}`")
        out.append("")
        if result.total_files:
            out.append(f"- **Files analyzed**: {result.total_files}")
        if result.total_chars:
            out.append(f"- **Total JS**: {result.total_chars:,} bytes")
        out.append("")

        if not result.findings:
            out.append("_No findings above the minimum score._")
            out.append("")
            return "\n".join(out)

        # Summary table
        counts = Counter(f.severity for f in result.findings)
        out.append("## Summary")
        out.append("")
        out.append("| Severity | Count |")
        out.append("|----------|-------|")
        for sev in self.SEVERITY_ORDER:
            if counts.get(sev):
                out.append(f"| {self.SEVERITY_BADGE[sev]} | {counts[sev]} |")
        out.append("")

        # Detail by category
        by_cat: Dict[str, List[Finding]] = {}
        for f in result.findings:
            by_cat.setdefault(f.category.value, []).append(f)

        cat_titles = {
            "secret": "🔑 Secrets & API Keys",
            "endpoint": "🌐 Endpoints",
            "infra": "🏗️ Infrastructure",
            "vuln_signal": "⚠️ Vulnerability Signals",
            "info_leak": "📢 Information Disclosure",
            "debug": "🐛 Debug / Leftovers",
        }

        for cat_key, items in by_cat.items():
            out.append(f"## {cat_titles.get(cat_key, cat_key)}")
            out.append("")
            for f in sorted(items, key=lambda x: (-x.severity.score, x.file, x.line)):
                badge = self.SEVERITY_BADGE[f.severity]
                out.append(f"### {badge} {f.title}")
                out.append("")
                if f.description:
                    out.append(f"{f.description}")
                    out.append("")
                if f.file:
                    out.append(f"- **File**: `{f.file}:{f.line}`")
                if f.match:
                    out.append(f"- **Match**: `{f.match[:120]}`")
                if f.context:
                    out.append(f"- **Context**:")
                    out.append("  ```js")
                    out.append(f"  {f.context}")
                    out.append("  ```")
                out.append("")

        # Errors
        if result.errors:
            out.append("## Errors")
            out.append("")
            for e in result.errors:
                out.append(f"- {e}")
            out.append("")

        out.append("---")
        out.append(f"*Generated by js-pulse v0.1.0 — https://github.com/yourname/js-pulse*")
        out.append("")
        return "\n".join(out)