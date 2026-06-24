"""
Vulnerability pattern analyzer — static detection of likely-vulnerable code patterns.

The big caveat: this is grep-level analysis. We can't tell you for sure that
eval(userInput) is exploitable. We CAN tell you it's worth a 10-minute look.

We do NOT:
  - Execute the code
  - Try to trace data flow (would need a real JS parser/AST)
  - Score severity by exploitation likelihood (we score by "is this interesting?")

We DO:
  - Find things that made our skin crawl during real engagements
  - Find SSRF-prone parameter names
  - Find dangerous sinks (eval, Function, document.write, etc.)
  - Find hardcoded SQL fragments
  - Find dangerous URL protocols (javascript:, data:, vbscript:)
"""
import re
from typing import List
from ..finding import Finding, Category, Severity


class VulnPatternAnalyzer:
    """Surface patterns that have historically been bug-bounty-relevant."""

    NAME = "vuln_pattern"

    # (regex, title, description, severity)
    PATTERNS = [
        # === SSRF-prone parameters ===
        (
            r"\b(?:url|uri|src|href|image|img|imgUrl|imageUrl|avatar|cover|thumbnail|"
            r"callback|webhook|hook|target|dest|destination|redirect|redirectUri|"
            r"redirectUrl|returnUrl|next|callbackUrl|fetch|load|proxy|"
            r"site|host|domain|server|endpoint|api|apiUrl|api_url|"
            r"rss|feed|xmlUrl|xml_url|atom|"
            r"path|file|filepath|filePath|filename|fileName|page|"
            r"downloadUrl|download_url|preview)\s*[:=]\s*['\"]?(https?://|\$\{[^}]*\}|"
            r"`[^`]*\$\{)",
            "Possible SSRF-vulnerable parameter",
            "Parameter name and value pattern suggests server-side URL fetch. Verify the value isn't used unsanitized in a server-side HTTP request.",
            Severity.MEDIUM,
        ),

        # === eval / Function constructor ===
        (
            r"\beval\s*\(",
            "eval() call",
            "Dynamic code execution. If the argument is user-controllable, this is RCE.",
            Severity.HIGH,
        ),
        (
            r"\bnew\s+Function\s*\(",
            "new Function() constructor",
            "Dynamic code execution via Function constructor. Same risk profile as eval().",
            Severity.HIGH,
        ),
        (
            r"setTimeout\s*\(\s*['\"`].*['\"`]",
            "setTimeout with string argument",
            "setTimeout with a string argument is treated like eval(). Modern code shouldn't do this.",
            Severity.MEDIUM,
        ),
        (
            r"setInterval\s*\(\s*['\"`].*['\"`]",
            "setInterval with string argument",
            "setInterval with a string argument is treated like eval().",
            Severity.MEDIUM,
        ),

        # === DOM XSS sinks ===
        (
            r"\b(?:document\.write|document\.writeln)\s*\(",
            "document.write call",
            "Direct DOM XSS sink if the argument contains user input.",
            Severity.MEDIUM,
        ),
        (
            r"\.innerHTML\s*=",
            ".innerHTML assignment",
            "innerHTML writes raw HTML. If the right-hand side is user-controllable, that's XSS.",
            Severity.MEDIUM,
        ),
        (
            r"\.outerHTML\s*=",
            ".outerHTML assignment",
            "outerHTML writes raw HTML. Same risk as innerHTML.",
            Severity.MEDIUM,
        ),
        (
            r"\b(?:insertAdjacentHTML|insertAdjacentElement)\s*\(",
            "insertAdjacentHTML/Element call",
            "DOM XSS sink. Common in older code that pre-dates safer patterns.",
            Severity.MEDIUM,
        ),
        (
            r"jQuery\s*\(\s*['\"`].*['\"`]\s*\)\.html\s*\(",
            "jQuery .html() with selector",
            "Classic DOM XSS via jQuery .html() with user-controlled selector.",
            Severity.MEDIUM,
        ),

        # === Dangerous protocols in URLs ===
        (
            r"['\"]javascript:[^'\"]+['\"]",
            "javascript: URL in source",
            "javascript: URLs in source code. If constructed from user input, this is XSS.",
            Severity.MEDIUM,
        ),
        (
            r"['\"]data:text/html[^'\"]+['\"]",
            "data:text/html URL in source",
            "data:text/html URLs. Can be used to bypass CSP or in phishing.",
            Severity.LOW,
        ),

        # === localStorage / sessionStorage with sensitive data ===
        (
            r"localStorage\s*\.\s*setItem\s*\(\s*['\"](?:token|access_token|refresh_token|password|secret|api_key|apikey|auth)",
            "Sensitive data in localStorage",
            "Storing tokens/passwords in localStorage exposes them to XSS. Should use httpOnly cookies or in-memory storage.",
            Severity.MEDIUM,
        ),

        # === SQL fragments (rare in JS, but seen in template literals) ===
        (
            r"['\"`].*(?:\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b).*(?:FROM|INTO|SET|WHERE).*['\"`]",
            "SQL fragment in JS",
            "Hardcoded SQL fragment. If concatenated with user input, this is SQLi.",
            Severity.LOW,
        ),

        # === Cookie not httpOnly / secure / samesite ===
        (
            r"document\.cookie\s*=\s*[^;]+",
            "document.cookie write",
            "JavaScript-set cookie. Check that Secure, HttpOnly, and SameSite are set where they should be.",
            Severity.LOW,
        ),

        # === postMessage without origin check ===
        (
            r"addEventListener\s*\(\s*['\"]message['\"]",
            "postMessage listener",
            "postMessage listener. Verify the event.origin check is strict.",
            Severity.LOW,
        ),

        # === dangerouslySetInnerHTML in JSX ===
        (
            r"dangerouslySetInnerHTML",
            "dangerouslySetInnerHTML in JSX",
            "React's bypass of HTML sanitization. Make sure the input is sanitized.",
            Severity.MEDIUM,
        ),

        # === Math.random for security ===
        (
            r"Math\.random\s*\(",
            "Math.random() in source",
            "Math.random() is not cryptographically secure. If used for tokens, IDs, or nonces, replace with crypto.getRandomValues() or crypto.randomUUID().",
            Severity.LOW,
        ),

        # === Direct fetch with user-controlled URL (insecure-direct-object-reference precursor) ===
        (
            r"fetch\s*\(\s*[`'\"][^'\"`]*\$\{",
            "fetch() with template literal URL",
            "fetch() URL is a template literal. If the interpolated value is user-controllable, this might allow SSRF or unauthorized access.",
            Severity.MEDIUM,
        ),

        # === CORS misconfiguration ===
        (
            r"['\"]Access-Control-Allow-Origin['\"]\s*[:=]\s*['\"]\\*['\"]",
            "CORS wildcard config",
            "Access-Control-Allow-Origin: *. The browser will refuse this if credentials are also sent, but some servers allow it via reflection. Check.",
            Severity.MEDIUM,
        ),
        (
            r"withCredentials\s*[:=]\s*true",
            "withCredentials=true",
            "Sends cookies on cross-origin requests. Combined with a permissive CORS policy, this can be exploited.",
            Severity.LOW,
        ),

        # === CSRF / auth tokens in URL ===
        (
            r"[?&](?:token|access_token|api_key|apikey|session|sid|auth|password)=[^&'\"]+",
            "Sensitive parameter in URL",
            "Token or password in URL. URLs land in logs, referrers, browser history. Use headers or POST body.",
            Severity.MEDIUM,
        ),

        # === weak crypto ===
        (
            r"\b(?:md5|sha1)\s*\(",
            "MD5 or SHA1 use",
            "MD5 and SHA1 are cryptographically broken. Use SHA-256+ for integrity, bcrypt/argon2 for passwords.",
            Severity.LOW,
        ),
    ]

    def analyze(self, content: str, file_label: str, source_url: str = "") -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()  # (title, line) for dedup

        for pattern, title, desc, severity in self.PATTERNS:
            try:
                matches = list(re.finditer(pattern, content, re.I | re.S))
            except re.error:
                continue
            for m in matches:
                line = _line_of(content, m.start())
                key = (title, line)
                if key in seen:
                    continue
                seen.add(key)

                findings.append(Finding(
                    category=Category.VULN_SIGNAL,
                    severity=severity,
                    detector=f"vuln_pattern:{title}",
                    title=title,
                    description=desc,
                    file=file_label,
                    line=line,
                    match=_truncate(m.group(0), 120),
                    context=_ctx(content, m.start(), m.end() - m.start()),
                    source_url=source_url,
                ))

        return findings


def _line_of(content: str, offset: int) -> int:
    if offset < 0 or offset >= len(content):
        return 0
    return content.count("\n", 0, offset) + 1


def _truncate(s: str, n: int) -> str:
    s = str(s).replace("\n", " ").replace("\r", " ")
    if len(s) <= n:
        return s
    return s[: n - 3] + "..."


def _ctx(content: str, offset: int, length: int, window: int = 50) -> str:
    start = max(0, offset - window)
    end = min(len(content), offset + length + window)
    raw = content[start:end]
    if start > 0:
        raw = "..." + raw
    if end < len(content):
        raw = raw + "..."
    return _truncate(raw, 200)