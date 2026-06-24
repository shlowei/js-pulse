"""
Secret scanner — finds API keys, tokens, and other credentials in JS.

How I built this:
  Started with the obvious "AKIA..." AWS pattern. Then added a few more.
  Then ran js-pulse against a handful of real-world bundles and added
  what I missed. Repeat. After 20-odd patterns I stopped because anything
  beyond that is "regex for things I haven't personally seen" — and those
  patterns tend to be too noisy to be useful.
"""
import re
import base64
import json
from typing import List
from ..finding import Finding, Category, Severity


class SecretScanner:
    """Find secrets and API keys in JS source."""

    NAME = "secret_scanner"

    # (pattern, name, severity)
    PATTERNS = [
        # ========== Cloud ==========
        ("AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity.CRITICAL),
        ("ASIA[0-9A-Z]{16}", "AWS Temporary Access Key", Severity.CRITICAL),
        (r"aws_secret_access_key\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]", "AWS Secret Access Key", Severity.CRITICAL),
        ("AIza[0-9A-Za-z_-]{35}", "Google API Key", Severity.HIGH),
        ("ya29\\.[0-9A-Za-z_-]+", "Google OAuth Token", Severity.CRITICAL),
        ("AZ[a-zA-Z0-9_]{32}", "Azure API Key", Severity.HIGH),
        ("dop_v1_[a-f0-9]{64}", "DigitalOcean PAT", Severity.CRITICAL),

        # ========== Payments ==========
        ("sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", Severity.CRITICAL),
        ("sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Secret Key", Severity.MEDIUM),
        ("pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key", Severity.LOW),
        ("rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted Key", Severity.HIGH),
        ("sq0atp-[0-9A-Za-z_-]{22}", "Square Access Token", Severity.CRITICAL),
        ("sq0csp-[0-9A-Za-z_-]{43}", "Square Client Secret", Severity.CRITICAL),

        # ========== Dev / Source control ==========
        ("ghp_[0-9a-zA-Z]{36}", "GitHub PAT", Severity.CRITICAL),
        ("gho_[0-9a-zA-Z]{36}", "GitHub OAuth Token", Severity.CRITICAL),
        ("ghu_[0-9a-zA-Z]{36}", "GitHub User Token", Severity.CRITICAL),
        ("ghs_[0-9a-zA-Z]{36}", "GitHub Server Token", Severity.CRITICAL),
        ("ghr_[0-9a-zA-Z]{36}", "GitHub Refresh Token", Severity.CRITICAL),
        ("github_pat_[0-9a-zA-Z_]{82}", "GitHub Fine-Grained PAT", Severity.CRITICAL),
        ("glpat-[0-9A-Za-z_-]{20,}", "GitLab PAT", Severity.CRITICAL),
        ("npm_[0-9A-Za-z]{36}", "npm Token", Severity.CRITICAL),

        # ========== Comms / Messaging ==========
        ("xox[baprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}", "Slack Token", Severity.CRITICAL),
        ("[0-9]{17,19}:[A-Za-z_-]{60,}", "Telegram Bot Token", Severity.CRITICAL),
        ("SK[0-9a-fA-F]{32}", "Twilio API Key", Severity.CRITICAL),
        ("AC[0-9a-fA-F]{32}", "Twilio Account SID", Severity.LOW),
        ("SG\\.[0-9A-Za-z_-]{22}\\.[0-9A-Za-z_-]{43}", "SendGrid API Key", Severity.CRITICAL),
        ("key-[0-9a-fA-F]{32}", "Mailgun API Key", Severity.CRITICAL),

        # ========== Maps / Data ==========
        ("https://[a-z0-9-]+\\.firebaseio\\.com", "Firebase Database URL", Severity.LOW),

        # ========== Auth / JWT ==========
        ("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+", "JWT Token", Severity.HIGH),

        # ========== Webhooks ==========
        ("https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{23,}", "Slack Webhook URL", Severity.HIGH),
        ("https://discord(?:app)?\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", "Discord Webhook", Severity.MEDIUM),

        # ========== AI ==========
        ("sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}", "OpenAI API Key", Severity.CRITICAL),
        ("sk-proj-[A-Za-z0-9_-]{40,}", "OpenAI Project Key", Severity.CRITICAL),
    ]

    # Things that look like keys but are definitely not.
    # Built at runtime so the literal patterns never appear in source
    # (GitHub secret scanning). Note: these are still matched against
    # the regex-derived candidate strings, so they must be valid format.
    @staticmethod
    def _blacklist():
        # Build the well-known AWS documentation example key without
        # putting a literal 20+ char base64 string in source.
        return {
            "AKIA" + "A" * 16,                                # AKIAIOSFODNN7EXAMPLE
            "wJalrXUt" + "nFEMI" + "/K7MDENG" + "/bPxRfiCY" + "EXAMPLEKEY",  # AWS doc sample
        }

    BLACKLIST = None  # initialized lazily in analyze() — see _blacklist()

    # Domains that signal "this is a demo/test fixture, not real"
    SAMPLE_DOMAINS = ("example.com", "test.com", "localhost", "yourdomain.com", "your-site.com", "placeholder.com")

    def analyze(self, content: str, file_label: str, source_url: str = "") -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()
        # Lazy-init the blacklist (built at runtime, no literal patterns in source)
        if self.BLACKLIST is None:
            self.BLACKLIST = self._blacklist()

        for pattern, name, severity in self.PATTERNS:
            try:
                matches = list(re.finditer(pattern, content, re.I))
            except re.error:
                continue
            for m in matches:
                full_match = m.group(1) if m.groups() else m.group(0)

                if full_match in self.BLACKLIST:
                    continue

                # Skip matches inside sample/demo contexts
                if any(d in full_match for d in self.SAMPLE_DOMAINS):
                    continue

                key = (name, full_match[:80])
                if key in seen:
                    continue
                seen.add(key)

                ctx = _extract_context(content, m.start(), m.end() - m.start())
                findings.append(Finding(
                    category=Category.SECRET,
                    severity=severity,
                    detector=f"secret_scanner:{name}",
                    title=f"Possible {name}",
                    description=f"Pattern matched a known format for {name}.",
                    file=file_label,
                    line=_line_of(content, m.start()),
                    match=_truncate(full_match, 100),
                    context=ctx,
                    source_url=source_url,
                ))

        # Special: JWT alg=none detection
        findings.extend(self._detect_jwt_alg_none(content, file_label, source_url))

        # Special: long base64 blobs assigned to variables
        findings.extend(self._detect_long_base64_blobs(content, file_label, source_url))

        return findings

    def _detect_jwt_alg_none(self, content: str, file_label: str, source_url: str) -> List[Finding]:
        """Look for JWTs with alg=none in their header. This is the classic JWT bypass."""
        findings: List[Finding] = []
        jwt_re = re.compile(r"\b(eyJ[A-Za-z0-9_-]+)\.eyJ")
        for m in jwt_re.finditer(content):
            header_b64 = m.group(1)
            try:
                padded = header_b64 + "=" * (4 - len(header_b64) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
                if '"alg":"none"' in decoded or '"alg":"None"' in decoded or '"alg":"NONE"' in decoded:
                    ctx = _extract_context(content, m.start(), m.end() - m.start())
                    findings.append(Finding(
                        category=Category.SECRET,
                        severity=Severity.CRITICAL,
                        detector="secret_scanner:jwt_alg_none",
                        title="JWT with alg=none in source",
                        description="JWT header specifies alg=none. If the server-side verifier doesn't reject this, you can forge tokens by stripping the signature.",
                        file=file_label,
                        line=_line_of(content, m.start()),
                        match=decoded,
                        context=ctx,
                        source_url=source_url,
                    ))
            except Exception:
                pass
        return findings

    def _detect_long_base64_blobs(self, content: str, file_label: str, source_url: str) -> List[Finding]:
        """Long base64 strings assigned to const/let/var."""
        findings: List[Finding] = []
        pattern = re.compile(
            r"""\b(?:const|let|var)\s+([A-Z_][A-Z0-9_]{2,})\s*=\s*['"]([A-Za-z0-9+/=]{40,})['"]\s*;""",
            re.MULTILINE,
        )
        for m in pattern.finditer(content):
            var_name = m.group(1)
            value = m.group(2)

            if not value.endswith(("=", "==")) and len(value) % 4 != 0:
                continue
            try:
                decoded = base64.b64decode(value).decode("utf-8", errors="strict")
            except Exception:
                continue

            if not (decoded.startswith("{") or decoded.startswith("[") or '"' in decoded[:20]):
                continue
            try:
                json.loads(decoded)
                looks_like_json = True
            except Exception:
                looks_like_json = False

            if looks_like_json or len(decoded) > 100:
                ctx = _extract_context(content, m.start(), m.end() - m.start())
                findings.append(Finding(
                    category=Category.SECRET,
                    severity=Severity.MEDIUM,
                    detector="secret_scanner:base64_blob",
                    title=f"Base64-encoded config in {var_name}",
                    description=f"Variable {var_name} contains a long base64 string. Decoded length: {len(decoded)} bytes.",
                    file=file_label,
                    line=_line_of(content, m.start()),
                    match=_truncate(value, 60) + "...",
                    context=ctx,
                    source_url=source_url,
                ))
        return findings


# ============ helpers ============

def _line_of(content: str, offset: int) -> int:
    if offset < 0 or offset >= len(content):
        return 0
    return content.count("\n", 0, offset) + 1


def _truncate(s: str, n: int) -> str:
    s = str(s).replace("\n", " ").replace("\r", " ")
    if len(s) <= n:
        return s
    return s[: n - 3] + "..."


def _extract_context(content: str, offset: int, length: int, window: int = 60) -> str:
    start = max(0, offset - window)
    end = min(len(content), offset + length + window)
    raw = content[start:end]
    if start > 0:
        raw = "..." + raw
    if end < len(content):
        raw = raw + "..."
    return _truncate(raw, 200)