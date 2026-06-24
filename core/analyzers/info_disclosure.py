"""
Info disclosure analyzer — finds emails, internal paths, debug code, and other stuff
that probably shouldn't be in a public JS bundle.
"""
import re
import ipaddress
from typing import List
from ..finding import Finding, Category, Severity


class InfoDisclosureAnalyzer:
    """Surface the small stuff that adds up during a real assessment."""

    NAME = "info_disclosure"

    EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

    PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?[2-9][0-9]{2}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}(?!\d)")

    # Suspicious paths often used internally
    INTERNAL_PATH_RE = re.compile(
        r"""['"`](
            /(?:admin|administrator|backstage|console|manage|manager|panel|internal|
               private|debug|test|dev|staging|stage|qa|uat|sandbox|poc|demo|
               _private|_internal|_debug|_admin|
               config|conf|cfg|settings|
               backup|backups|bak|old|archive|legacy|
               swagger|api-docs|openapi|redoc|
               health|healthz|ready|readyz|metrics|prometheus|
               grafana|kibana|elastic|elasticsearch|
               phpmyadmin|pma|adminer|pgadmin|
               actuator/env|actuator/beans|actuator/configprops|
               trace|logs|log|
               debug\.log|error\.log|access\.log
            )(?:[/'"\s`])?
        )""",
        re.X | re.I,
    )

    # Common debug code left in
    DEBUG_CODE_PATTERNS = [
        (r"\bconsole\.(log|debug|info|warn|error)\s*\(\s*['\"`].*(?:DEBUG|TODO|FIXME|HACK|XXX).*['\"`]", "Debug log with marker", "Production code with debug markers like DEBUG/TODO/FIXME.", Severity.LOW),
        (r"\bdebugger\s*;", "debugger statement", "Production code with debugger statement. Halts execution if devtools are open.", Severity.LOW),
        (r"\balert\s*\(", "alert() call", "Production code with alert(). Real product doesn't alert().", Severity.INFO),
        (r"\bconfirm\s*\(", "confirm() call", "Production code with confirm().", Severity.INFO),
        (r"\bTODO\b|\bFIXME\b|\bHACK\b|\bXXX\b", "TODO/FIXME marker", "Unresolved TODO/FIXME. May indicate unfinished security work.", Severity.INFO),
        (r"\bconsole\.(log|debug)\s*\(\s*['\"`]\[DEBUG\]", "[DEBUG] log", "Production debug logging. May leak data to console.", Severity.LOW),
    ]

    # Stack trace fragments
    STACK_TRACE_RE = re.compile(
        r"\b(?:TypeError|ReferenceError|SyntaxError|RangeError|EvalError|URIError)\b:",
    )

    def analyze(self, content: str, file_label: str, source_url: str = "") -> List[Finding]:
        findings: List[Finding] = []
        seen_lines: set = set()

        # 1. Emails
        for m in self.EMAIL_RE.finditer(content):
            email = m.group(0)
            if _is_obvious_dummy(email):
                continue
            line = _line_of(content, m.start())
            key = ("email", line)
            if key in seen_lines:
                continue
            seen_lines.add(key)
            sev = Severity.LOW if _is_personal_email(email) else Severity.MEDIUM
            findings.append(Finding(
                category=Category.INFO_LEAK,
                severity=sev,
                detector="info_disclosure:email",
                title=f"Email address in JS: {email}",
                description="Email address hardcoded in JS source.",
                file=file_label,
                line=line,
                match=email,
                context=_ctx(content, m.start(), m.end() - m.start()),
                source_url=source_url,
            ))

        # 2. Phone numbers (US format, heuristic)
        for m in self.PHONE_RE.finditer(content):
            phone = m.group(0)
            line = _line_of(content, m.start())
            key = ("phone", line)
            if key in seen_lines:
                continue
            seen_lines.add(key)
            findings.append(Finding(
                category=Category.INFO_LEAK,
                severity=Severity.LOW,
                detector="info_disclosure:phone",
                title=f"Phone number in JS: {phone}",
                description="Phone number hardcoded in JS source.",
                file=file_label,
                line=line,
                match=phone,
                context=_ctx(content, m.start(), m.end() - m.start()),
                source_url=source_url,
            ))

        # 3. Internal paths
        for m in self.INTERNAL_PATH_RE.finditer(content):
            path = m.group(1)
            line = _line_of(content, m.start())
            key = ("path", line, path)
            if key in seen_lines:
                continue
            seen_lines.add(key)

            # Bump severity for actually dangerous paths
            sev = Severity.LOW
            if any(p in path.lower() for p in ("admin", "internal", "private", "debug", "phpmyadmin", "adminer", "actuator", "config", "backup")):
                sev = Severity.MEDIUM
            if any(p in path.lower() for p in ("swagger", "api-docs", "openapi", "actuator/env", "actuator/configprops", ".log")):
                sev = Severity.HIGH

            findings.append(Finding(
                category=Category.INFO_LEAK,
                severity=sev,
                detector="info_disclosure:suspicious_path",
                title=f"Suspicious internal path: {path}",
                description="Path that looks like an internal endpoint, admin route, or debug surface.",
                file=file_label,
                line=line,
                match=path,
                context=_ctx(content, m.start(), m.end() - m.start()),
                source_url=source_url,
            ))

        # 4. Debug code
        for pattern, title, desc, severity in self.DEBUG_CODE_PATTERNS:
            for m in re.finditer(pattern, content, re.I):
                line = _line_of(content, m.start())
                key = ("debug", line, title)
                if key in seen_lines:
                    continue
                seen_lines.add(key)
                findings.append(Finding(
                    category=Category.DEBUG,
                    severity=severity,
                    detector=f"info_disclosure:debug:{title}",
                    title=title,
                    description=desc,
                    file=file_label,
                    line=line,
                    match=_truncate(m.group(0), 100),
                    context=_ctx(content, m.start(), m.end() - m.start()),
                    source_url=source_url,
                ))

        # 5. Stack traces in source (often shipped by error reporters)
        for m in self.STACK_TRACE_RE.finditer(content):
            line = _line_of(content, m.start())
            key = ("stack", line)
            if key in seen_lines:
                continue
            seen_lines.add(key)
            findings.append(Finding(
                category=Category.INFO_LEAK,
                severity=Severity.LOW,
                detector="info_disclosure:stack_trace",
                title="Stack trace fragment in JS",
                description="Looks like a real stack trace made it into the bundle. Usually harmless, occasionally leaks internal module names.",
                file=file_label,
                line=line,
                match=m.group(0),
                context=_ctx(content, m.start(), m.end() - m.start(), window=100),
                source_url=source_url,
            ))

        return findings


def _is_obvious_dummy(email: str) -> bool:
    el = email.lower()
    return any(p in el for p in ("example.com", "test.com", "yourdomain", "placeholder", "user@", "name@"))


def _is_personal_email(email: str) -> bool:
    """Gmail/Yahoo/Outlook are personal, corporate domains are not."""
    el = email.lower()
    return any(el.endswith("@" + d) for d in ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "qq.com", "163.com", "126.com"))


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