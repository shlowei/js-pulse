"""
The Finding — every analyzer produces one of these.
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any, List, Optional


class Severity(Enum):
    """Confidence-weighted severity. Not CVSS, just how much I'd poke at it."""
    CRITICAL = "CRITICAL"  # Real secret, real risk — go verify right now
    HIGH = "HIGH"          # Strong signal, very likely a real issue
    MEDIUM = "MEDIUM"      # Worth a look
    LOW = "LOW"            # Informational; check if it's in scope
    INFO = "INFO"          # FYI, probably noise

    def __str__(self):
        return self.name

    @property
    def score(self) -> int:
        return {
            Severity.CRITICAL: 95,
            Severity.HIGH: 80,
            Severity.MEDIUM: 60,
            Severity.LOW: 40,
            Severity.INFO: 20,
        }[self]


class Category(Enum):
    SECRET = "secret"
    ENDPOINT = "endpoint"
    INFRA = "infra"
    VULN_SIGNAL = "vuln_signal"
    INFO_LEAK = "info_leak"
    DEBUG = "debug"


@dataclass
class Finding:
    """A single piece of intel extracted from a JS bundle."""
    category: Category
    severity: Severity
    detector: str           # Which analyzer produced this (e.g. "secret_scanner:aws")
    title: str              # Short human-readable label
    description: str = ""   # Longer explanation
    file: str = ""          # Where we found it
    line: int = 0           # Best-effort line number
    match: str = ""         # The actual matched text (may be truncated)
    context: str = ""       # Surrounding code (truncated)
    source_url: str = ""    # Origin URL (for inline scripts, the page URL)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["score"] = self.severity.score
        return d

    def fingerprint(self) -> str:
        """Stable identifier for dedup across multiple bundles."""
        # We dedup on (file, detector, match) — same finding in same file = same finding
        return f"{self.file}::{self.detector}::{self.match[:200]}"


@dataclass
class AnalysisResult:
    """Aggregate of all findings from a single bundle (or a whole crawl)."""
    source: str  # "scan:https://..." or "analyze:/path/to/file.js"
    findings: List[Finding] = field(default_factory=list)
    total_chars: int = 0
    total_files: int = 0
    errors: List[str] = field(default_factory=list)

    def add(self, finding: Finding):
        self.findings.append(finding)

    def extend(self, findings: List[Finding]):
        self.findings.extend(findings)

    def dedup(self):
        """Remove duplicate findings (same fingerprint)."""
        seen: set = set()
        unique: List[Finding] = []
        for f in self.findings:
            fp = f.fingerprint()
            if fp in seen:
                continue
            seen.add(fp)
            unique.append(f)
        self.findings = unique

    def by_severity(self) -> Dict[Severity, List[Finding]]:
        result: Dict[Severity, List[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "total_chars": self.total_chars,
            "total_files": self.total_files,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }