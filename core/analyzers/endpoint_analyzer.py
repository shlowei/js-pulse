"""Endpoint analyzer — second pass over extracted endpoints, classifies and prioritizes."""
import re
from typing import List
from ..finding import Finding, Category, Severity


class EndpointAnalyzer:
    """
    Re-scores the endpoints from the extractor based on what they look like.

    The extractor's first pass is intentionally broad. This pass:
      - Demotes static asset paths
      - Boosts internal-looking paths
      - Tags endpoints with their likely purpose (auth, admin, user data, etc.)
    """

    NAME = "endpoint_analyzer"

    # Path segment → category tag
    AUTH_SEGMENTS = {"login", "logout", "signup", "register", "auth", "oauth", "token", "session", "sso", "callback", "verify", "reset-password", "forgot", "2fa", "mfa"}
    ADMIN_SEGMENTS = {"admin", "administrator", "manage", "manager", "console", "backstage", "internal", "private", "panel", "dashboard"}
    USER_DATA_SEGMENTS = {"user", "users", "account", "accounts", "profile", "profiles", "member", "members", "customer", "customers"}
    FINANCIAL_SEGMENTS = {"order", "orders", "payment", "payments", "invoice", "invoices", "billing", "checkout", "transaction", "transactions", "wallet", "balance", "charge", "refund", "subscription"}
    SENSITIVE_SEGMENTS = {"password", "secret", "credential", "credentials", "key", "token", "apikey", "private"}
    DEBUG_SEGMENTS = {"debug", "test", "dev", "stage", "staging", "internal", "ping", "health", "metrics", "status", "_debug", "_private", "_internal"}

    def analyze(self, findings: List[Finding]) -> List[Finding]:
        """Augment existing endpoint findings with category tags and severity adjustments."""
        for f in findings:
            if f.category != Category.ENDPOINT:
                continue

            path = f.match.lower() if not f.match.startswith(("http://", "https://", "ws://", "wss://")) else ""
            if not path:
                continue

            segments = set(re.split(r"[/._-]", path))
            segments.discard("")

            tags = []

            # Auth-related
            if segments & self.AUTH_SEGMENTS:
                tags.append("auth")
                if f.severity == Severity.LOW:
                    f.severity = Severity.MEDIUM

            # Admin/internal
            if segments & self.ADMIN_SEGMENTS:
                tags.append("admin")
                f.severity = Severity.HIGH
                if "auth" not in tags:
                    tags.append("auth")

            # User data (potential BOLA/IDOR)
            if segments & self.USER_DATA_SEGMENTS and re.search(r"[{:$]", f.match):
                tags.append("user-data-idor")
                f.severity = Severity.HIGH

            # Financial (extra scrutiny)
            if segments & self.FINANCIAL_SEGMENTS:
                tags.append("financial")
                if f.severity in (Severity.LOW, Severity.MEDIUM):
                    f.severity = Severity.HIGH

            # Sensitive in path
            if segments & self.SENSITIVE_SEGMENTS:
                tags.append("sensitive")

            # Debug/dev/staging (often not properly secured)
            if segments & self.DEBUG_SEGMENTS:
                tags.append("debug")
                f.severity = Severity.MEDIUM

            # GraphQL
            if "graphql" in path:
                tags.append("graphql")
                f.severity = Severity.HIGH

            # WebSocket
            if f.match.startswith(("ws://", "wss://")):
                tags.append("websocket")
                f.severity = Severity.MEDIUM

            if tags:
                f.title = f"[{', '.join(tags)}] {f.title}"

        return findings