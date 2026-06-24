"""Unit tests for js-pulse core modules."""
import sys
import os
import unittest
import json
import base64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.http_client import HTTPClient
from core.extractor import extract_endpoints
from core.finding import Finding, Category, Severity, AnalysisResult
from core.analyzers.endpoint_analyzer import EndpointAnalyzer
from core.analyzers.secret_scanner import SecretScanner
from core.analyzers.url_analyzer import URLAnalyzer
from core.analyzers.vuln_pattern import VulnPatternAnalyzer
from core.analyzers.info_disclosure import InfoDisclosureAnalyzer
from core.reporter import Reporter


# ============== HTTPClient ==============

class TestHTTPClientParsing(unittest.TestCase):
    def setUp(self):
        self.client = HTTPClient(timeout=5)

    def test_parse_basic_response(self):
        raw = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nhello"
        resp = self.client._parse(raw, "http://x.com", 50)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["server"], "nginx")
        self.assertEqual(resp.body, b"hello")

    def test_parse_404(self):
        raw = b"HTTP/1.1 404 Not Found\r\n\r\n"
        resp = self.client._parse(raw, "http://x.com", 10)
        self.assertEqual(resp.status_code, 404)
        self.assertFalse(resp.ok)

    def test_parse_gzip(self):
        import gzip
        body = b"<html>gzipped</html>"
        gz = gzip.compress(body)
        raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n" + gz
        resp = self.client._parse(raw, "http://x.com", 10)
        self.assertEqual(resp.body, body)

    def test_text_decoding(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html>test</html>"
        resp = self.client._parse(raw, "http://x.com", 10)
        self.assertIn("test", resp.text())


# ============== Endpoint Extractor ==============

class TestEndpointExtractor(unittest.TestCase):
    def test_api_path_extraction(self):
        content = 'fetch("/api/v1/users/123")'
        findings = extract_endpoints(content, "test.js")
        self.assertTrue(any("/api/v1/users/123" in f.match for f in findings))

    def test_absolute_url(self):
        content = 'const api = "https://api.example.com/v1/products";'
        findings = extract_endpoints(content, "test.js")
        urls = [f.match for f in findings]
        self.assertIn("https://api.example.com/v1/products", urls)

    def test_websocket_url(self):
        content = 'const ws = new WebSocket("wss://realtime.example.com/socket");'
        findings = extract_endpoints(content, "test.js")
        self.assertTrue(any(f.match.startswith("wss://") for f in findings))

    def test_graphql_boosted_severity(self):
        content = 'fetch("/graphql", {method: "POST"})'
        findings = extract_endpoints(content, "test.js")
        graphql_findings = [f for f in findings if "/graphql" in f.match]
        self.assertTrue(graphql_findings)
        self.assertEqual(graphql_findings[0].severity, Severity.HIGH)

    def test_static_asset_filtered(self):
        content = 'const url = "/static/js/main.js"; const img = "/images/logo.png";'
        findings = extract_endpoints(content, "test.js")
        for f in findings:
            self.assertNotIn("/static/js/main.js", f.match)
            self.assertNotIn(".png", f.match)

    def test_cdn_domains_filtered(self):
        content = 'const lib = "https://cdn.jsdelivr.net/npm/react";'
        findings = extract_endpoints(content, "test.js")
        # Should not include the CDN URL as a finding
        for f in findings:
            self.assertNotIn("jsdelivr.net", f.match)

    def test_method_association(self):
        content = 'const res = await fetch("/api/users", {method: "DELETE"});'
        findings = extract_endpoints(content, "test.js")
        # Method should be in the title
        delete_findings = [f for f in findings if "DELETE" in f.title]
        self.assertTrue(delete_findings)


# ============== Secret Scanner ==============

class TestSecretScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SecretScanner()

    def test_aws_access_key(self):
        # AKIA + 16 [0-9A-Z] = full AWS key format.
        # Build at runtime so the literal "AKIA"+16chars never appears
        # in source (keeps GitHub secret scanning happy).
        akia = "AKIA" + "A" * 16
        content = f'const AWS_KEY = "{akia}";'
        findings = self.scanner.analyze(content, "test.js")
        aws = [f for f in findings if "AWS" in f.title]
        # AKIA pattern is in BLACKLIST, so it should be filtered out
        self.assertEqual(len(aws), 0)

    def test_aws_access_key_real(self):
        # Real-looking key (not the BLACKLIST one) — same construction.
        akia = "AKIA" + "1" * 16
        content = f'const AWS_KEY = "{akia}";'
        findings = self.scanner.analyze(content, "test.js")
        aws = [f for f in findings if "AWS" in f.title]
        self.assertTrue(len(aws) > 0, f"expected AWS finding, got: {findings}")
        self.assertEqual(aws[0].severity, Severity.CRITICAL)

    def test_stripe_live(self):
        # GitHub secret scanning blocks any literal matching
        # "sk_live_<24+ alphanum>" — even with placeholder content.
        # We build the test string at runtime from parts so the literal
        # pattern never appears in source, while the assembled value
        # still exercises the scanner's regex.
        prefix = "sk_l" + "ive_"
        body = "a" * 24
        content = f'const stripe = "{prefix}{body}";'
        findings = self.scanner.analyze(content, "test.js")
        stripe = [f for f in findings if "Stripe" in f.title]
        self.assertTrue(len(stripe) > 0, f"expected Stripe finding, got: {findings}")
        self.assertEqual(stripe[0].severity, Severity.CRITICAL)

    def test_github_pat(self):
        # ghp_ + 36 alphanumeric chars (real format).
        # Build at runtime so the literal pattern never appears in source.
        pat = "ghp_" + "a" * 36
        content = f'const token = "{pat}";'
        findings = self.scanner.analyze(content, "test.js")
        gh = [f for f in findings if "GitHub" in f.title]
        self.assertTrue(len(gh) > 0, f"expected GitHub PAT finding, got: {findings}")
        self.assertEqual(gh[0].severity, Severity.CRITICAL)

    def test_jwt_alg_none(self):
        # alg=none in JWT header
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        content = f'const token = "{header}.eyJzdWIiOiIxMjM0In0.";'
        findings = self.scanner.analyze(content, "test.js")
        alg_none = [f for f in findings if "alg=none" in f.title]
        self.assertTrue(len(alg_none) > 0)
        self.assertEqual(alg_none[0].severity, Severity.CRITICAL)

    def test_slack_webhook(self):
        content = 'const hook = "https://hooks.slack.com/services/T12345/B67890/abcdefghijklmnopqrstuvw";'
        findings = self.scanner.analyze(content, "test.js")
        slk = [f for f in findings if "Slack" in f.title]
        self.assertTrue(len(slk) > 0)

    def test_dummy_domain_filtered(self):
        # Build AKIA + example email at runtime to keep the source clean
        # of full secret patterns (GitHub secret scanning).
        akia = "AKIA" + "A" * 16
        content = (
            f'const x = "{akia}"; '
            f'const y = "admin@example.com";'
        )
        # Test that example.com emails are filtered
        findings = self.scanner.analyze(content, "test.js")
        # Both should not be flagged (AKIA is in blacklist, example.com is in sample domains)
        self.assertEqual(len(findings), 0)


# ============== URL Analyzer ==============

class TestURLAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = URLAnalyzer()

    def test_internal_ip_detected(self):
        content = 'const api = "http://192.168.1.100:8080/api";'
        findings = self.analyzer.analyze(content, "test.js")
        ip_findings = [f for f in findings if "192.168" in f.match]
        self.assertTrue(len(ip_findings) > 0)
        self.assertEqual(ip_findings[0].severity, Severity.HIGH)

    def test_loopback_detected(self):
        content = 'const api = "http://127.0.0.1:3000";'
        findings = self.analyzer.analyze(content, "test.js")
        self.assertTrue(any("127.0.0.1" in f.match for f in findings))

    def test_internal_hostname(self):
        content = 'const api = "https://api.internal.company.local/v1";'
        findings = self.analyzer.analyze(content, "test.js")
        self.assertTrue(any("internal" in f.match for f in findings))

    def test_suspicious_port(self):
        content = 'const db = "http://prod.example.com:3306/mydb";'
        findings = self.analyzer.analyze(content, "test.js")
        port_findings = [f for f in findings if "3306" in f.match]
        self.assertTrue(len(port_findings) > 0)
        self.assertIn("MySQL", port_findings[0].title)

    def test_public_url_not_flagged(self):
        content = 'const api = "https://api.example.com/v1";'
        findings = self.analyzer.analyze(content, "test.js")
        # No internal signals
        self.assertEqual(len(findings), 0)


# ============== Vuln Pattern ==============

class TestVulnPattern(unittest.TestCase):
    def setUp(self):
        self.analyzer = VulnPatternAnalyzer()

    def test_eval_detected(self):
        content = 'const result = eval(userInput);'
        findings = self.analyzer.analyze(content, "test.js")
        eval_findings = [f for f in findings if "eval" in f.title.lower()]
        self.assertTrue(len(eval_findings) > 0)
        self.assertEqual(eval_findings[0].severity, Severity.HIGH)

    def test_innerHTML_detected(self):
        content = 'element.innerHTML = userInput;'
        findings = self.analyzer.analyze(content, "test.js")
        self.assertTrue(any("innerHTML" in f.title for f in findings))

    def test_javascript_url(self):
        content = 'const href = "javascript:alert(1)";'
        findings = self.analyzer.analyze(content, "test.js")
        self.assertTrue(any("javascript" in f.title for f in findings))

    def test_localstorage_token(self):
        content = 'localStorage.setItem("token", "secret-value");'
        findings = self.analyzer.analyze(content, "test.js")
        self.assertTrue(any("localStorage" in f.title for f in findings))

    def test_math_random_for_security(self):
        content = 'const sessionId = Math.random().toString(36);'
        findings = self.analyzer.analyze(content, "test.js")
        self.assertTrue(any("Math.random" in f.title for f in findings))

    def test_md5_use(self):
        content = 'const hash = md5(password);'
        findings = self.analyzer.analyze(content, "test.js")
        self.assertTrue(any("MD5" in f.title for f in findings))


# ============== Info Disclosure ==============

class TestInfoDisclosure(unittest.TestCase):
    def setUp(self):
        self.analyzer = InfoDisclosureAnalyzer()

    def test_email_detected(self):
        content = 'const support = "support@company.com";'
        findings = self.analyzer.analyze(content, "test.js")
        self.assertTrue(any("@company.com" in f.match for f in findings))

    def test_admin_path_detected(self):
        content = 'fetch("/admin/users");'
        findings = self.analyzer.analyze(content, "test.js")
        self.assertTrue(any("admin" in f.title for f in findings))

    def test_swagger_path_high_severity(self):
        content = 'const url = "/swagger/v1/swagger.json";'
        findings = self.analyzer.analyze(content, "test.js")
        swagger = [f for f in findings if "swagger" in f.match]
        self.assertTrue(len(swagger) > 0)
        self.assertEqual(swagger[0].severity, Severity.HIGH)

    def test_console_log_debug(self):
        content = 'console.log("[DEBUG] user state =", state);'
        findings = self.analyzer.analyze(content, "test.js")
        self.assertTrue(any("DEBUG" in f.title for f in findings))

    def test_debugger_statement(self):
        content = 'function foo() { debugger; return x; }'
        findings = self.analyzer.analyze(content, "test.js")
        self.assertTrue(any("debugger" in f.title for f in findings))

    def test_dummy_email_filtered(self):
        content = 'const x = "user@example.com";'
        findings = self.analyzer.analyze(content, "test.js")
        # example.com should be filtered
        self.assertEqual(len(findings), 0)


# ============== Endpoint Analyzer (second pass) ==============

class TestEndpointAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = EndpointAnalyzer()

    def test_admin_endpoint_promoted(self):
        finding = Finding(
            category=Category.ENDPOINT,
            severity=Severity.LOW,
            detector="test",
            title="/admin/dashboard",
            match="/admin/dashboard",
        )
        result = self.analyzer.analyze([finding])
        self.assertEqual(result[0].severity, Severity.HIGH)
        self.assertIn("admin", result[0].title)

    def test_auth_endpoint_promoted(self):
        finding = Finding(
            category=Category.ENDPOINT,
            severity=Severity.LOW,
            detector="test",
            title="/api/login",
            match="/api/login",
        )
        result = self.analyzer.analyze([finding])
        self.assertEqual(result[0].severity, Severity.MEDIUM)
        self.assertIn("auth", result[0].title)

    def test_user_data_idor(self):
        finding = Finding(
            category=Category.ENDPOINT,
            severity=Severity.LOW,
            detector="test",
            title="/api/users/{id}",
            match="/api/users/{id}",
        )
        result = self.analyzer.analyze([finding])
        self.assertIn("user-data-idor", result[0].title)
        self.assertEqual(result[0].severity, Severity.HIGH)

    def test_graphql_tagged(self):
        finding = Finding(
            category=Category.ENDPOINT,
            severity=Severity.MEDIUM,
            detector="test",
            title="/graphql",
            match="/graphql",
        )
        result = self.analyzer.analyze([finding])
        self.assertIn("graphql", result[0].title)


# ============== Reporter ==============

class TestReporter(unittest.TestCase):
    def setUp(self):
        self.reporter = Reporter(format="console", no_color=True)
        self.reporter_json = Reporter(format="json", no_color=True)
        self.reporter_md = Reporter(format="markdown", no_color=True)
        self.reporter_csv = Reporter(format="csv", no_color=True)
        self.reporter_text = Reporter(format="text", no_color=True)

    def _make_result(self, findings):
        result = AnalysisResult(source="test")
        result.extend(findings)
        return result

    def test_console_output(self):
        f = Finding(category=Category.SECRET, severity=Severity.CRITICAL,
                    detector="test", title="AWS Key", match="AKIA...")
        result = self._make_result([f])
        out = self.reporter.render(result)
        self.assertIn("AWS Key", out)
        self.assertIn("CRITICAL", out)
        self.assertIn("Summary", out)

    def test_json_output(self):
        f = Finding(category=Category.SECRET, severity=Severity.HIGH,
                    detector="test", title="GitHub PAT", match="ghp_...")
        result = self._make_result([f])
        out = self.reporter_json.render(result)
        data = json.loads(out)
        self.assertIn("findings", data)
        self.assertEqual(len(data["findings"]), 1)

    def test_markdown_output(self):
        f = Finding(category=Category.ENDPOINT, severity=Severity.MEDIUM,
                    detector="test", title="/api/users", match="/api/users")
        result = self._make_result([f])
        out = self.reporter_md.render(result)
        self.assertIn("# js-pulse report", out)
        self.assertIn("Summary", out)
        self.assertIn("Endpoints", out)

    def test_csv_output(self):
        f = Finding(category=Category.SECRET, severity=Severity.HIGH,
                    detector="test", title="Slack", match="xoxb-...")
        result = self._make_result([f])
        out = self.reporter_csv.render(result)
        self.assertIn("severity,score,category", out)
        self.assertIn("Slack", out)

    def test_text_output_pipe_friendly(self):
        f = Finding(category=Category.ENDPOINT, severity=Severity.MEDIUM,
                    detector="test", title="/api/x", match="/api/x", file="a.js", line=10)
        result = self._make_result([f])
        out = self.reporter_text.render(result)
        # Should be tab-separated
        self.assertIn("\t", out)
        self.assertIn("a.js:10", out)

    def test_min_score_filter(self):
        f_low = Finding(category=Category.INFO_LEAK, severity=Severity.LOW,
                        detector="test", title="Email", match="a@b.com")
        f_high = Finding(category=Category.SECRET, severity=Severity.CRITICAL,
                         detector="test", title="Key", match="AKIA...")
        result = self._make_result([f_low, f_high])
        # With min_score=60, only HIGH+ pass
        reporter = Reporter(format="console", no_color=True, min_score=60)
        out = reporter.render(result)
        self.assertIn("Key", out)
        self.assertNotIn("Email", out)


# ============== Deduplication ==============

class TestAnalysisResultDedup(unittest.TestCase):
    def test_dedup_removes_duplicates(self):
        result = AnalysisResult(source="test")
        f1 = Finding(category=Category.SECRET, severity=Severity.HIGH,
                     detector="x", title="t", file="a.js", match="X")
        f2 = Finding(category=Category.SECRET, severity=Severity.HIGH,
                     detector="x", title="t", file="a.js", match="X")
        result.add(f1)
        result.add(f2)
        result.dedup()
        self.assertEqual(len(result.findings), 1)


# ============== End-to-end smoke ==============

class TestEndToEnd(unittest.TestCase):
    def test_analyze_local_file(self):
        import tempfile
        # Build the JS content at runtime so no literal "AKIA"+16-char
        # pattern appears in source (GitHub secret scanning).
        akia = "AKIA" + "1" * 16
        body = f'''
                const AWS_KEY = "{akia}";
                const API = "https://api.example.com/v1";
                fetch("/admin/dashboard");
                eval(userInput);
            '''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(body)
            f.write('localStorage.setItem("token", x);')
            tmp = f.name
        try:
            # Use subprocess to call CLI
            import subprocess
            result = subprocess.run(
                [sys.executable, "js_pulse.py", "analyze", tmp, "--format", "text", "--no-color"],
                capture_output=True, text=True, cwd="/tmp/js-pulse",
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("AWS", result.stdout)
            self.assertIn("admin", result.stdout)
        finally:
            os.unlink(tmp)


if __name__ == "__main__":
    unittest.main(verbosity=2)