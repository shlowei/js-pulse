"""Analyzers — each one produces a list of Findings from a JS bundle."""
from .endpoint_analyzer import EndpointAnalyzer
from .secret_scanner import SecretScanner
from .url_analyzer import URLAnalyzer
from .vuln_pattern import VulnPatternAnalyzer
from .info_disclosure import InfoDisclosureAnalyzer


__all__ = [
    "EndpointAnalyzer",
    "SecretScanner",
    "URLAnalyzer",
    "VulnPatternAnalyzer",
    "InfoDisclosureAnalyzer",
]


def get_all_analyzers():
    return [
        EndpointAnalyzer(),
        SecretScanner(),
        URLAnalyzer(),
        VulnPatternAnalyzer(),
        InfoDisclosureAnalyzer(),
    ]