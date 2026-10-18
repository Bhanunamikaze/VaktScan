import csv
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules import domain_scan, web_checks
import reporter


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8")
        self.headers = headers or {}


class RouteClient:
    def __init__(self, routes=None, default=None):
        self.routes = routes or {}
        self.default = default or FakeResponse(404, "Not found")

    async def get(self, url, **_kwargs):
        return self.routes.get(urlparse(url).path, self.default)


class ContextClient(RouteClient):
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def head(self, url, **_kwargs):
        return self.routes.get(("HEAD", urlparse(url).path), self.default)


class ReportAccuracyTests(unittest.TestCase):
    def test_origin_url_is_promoted_to_exact_payload_path(self):
        finding = {
            "url": "https://example.com/",
            "payload_url": "https://example.com/secrets.yml",
            "target": "example.com",
            "port": 443,
            "vulnerability": "Confirmed test",
            "status": "VULNERABLE",
            "details": "Evidence present",
        }
        normalized = reporter.normalize_finding_for_report(finding)
        self.assertEqual(normalized["url"], "https://example.com/secrets.yml")

    def test_two_distinct_full_urls_remain_distinct(self):
        finding = {
            "url": "https://example.com/api",
            "payload_url": "https://example.com/payload",
        }
        normalized = reporter.normalize_finding_for_report(finding)
        self.assertEqual(normalized["url"], "https://example.com/api")

    def test_legacy_noise_is_removed_but_evidenced_finding_remains(self):
        findings = [
            {
                "module": "domain_scan", "vulnerability": "Potential Open Redirect (url)",
                "status": "POTENTIAL", "details": "Redirected to same-site query",
            },
            {
                "module": "WebChecks", "vulnerability": "Secrets File Exposed",
                "status": "CRITICAL", "details": "HTTP 200 only",
            },
            {
                "module": "WebChecks", "vulnerability": "Secrets File Exposed",
                "status": "CRITICAL", "details": "Evidence: YAML credential assignment.",
            },
        ]
        accepted, rejected = reporter.prepare_findings_for_report(
            findings, include_rejections=True
        )
        self.assertEqual(len(accepted), 1)
        self.assertEqual(len(rejected), 2)

    def test_csv_uses_exact_payload_for_origin_only_url(self):
        finding = {
            "module": "test", "vulnerability": "Confirmed test", "status": "VULNERABLE",
            "severity": "HIGH", "target": "example.com", "port": 443,
            "url": "https://example.com/", "payload_url": "https://example.com/admin/login",
            "details": "Evidence present",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "result.csv")
            reporter.save_results_to_csv([finding], path)
            with open(path, newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
        self.assertEqual(rows[0]["URL"], "https://example.com/admin/login")

    def test_legacy_cors_redirect_is_rejected(self):
        finding = {
            "module": "domain_scan",
            "vulnerability": "CORS: Arbitrary Origin Reflection with Credentials",
            "status": "VULNERABLE",
            "http_status": "302",
            "details": "Confirmed arbitrary origin reflection with credentials.",
        }
        self.assertIn("redirect/error", reporter.finding_rejection_reason(finding))

    def test_invalid_internal_ip_is_rejected(self):
        finding = {
            "module": "js_paths",
            "vulnerability": "Internal IP Disclosure",
            "status": "POTENTIAL",
            "details": "RFC-1918 address '10.934.661.508' found in app.js",
        }
        self.assertIn("not a valid IP", reporter.finding_rejection_reason(finding))

    def test_dependency_cve_without_exploit_path_is_rejected(self):
        finding = {
            "module": "js_cve",
            "vulnerability": "CVE-2020-11023 - jquery 3.3.1",
            "status": "VULNERABLE",
            "service_version": "jquery 3.3.1",
            "details": "Vulnerable client-side library detected via filename.",
        }
        self.assertIn("reachable vulnerable-code", reporter.finding_rejection_reason(finding))


class WebCheckAccuracyTests(unittest.IsolatedAsyncioTestCase):
    async def test_sensitive_file_catchall_is_suppressed(self):
        catchall = FakeResponse(
            200,
            "<html><title>Marketing</title><body>Welcome to our site</body></html>",
            {"content-type": "text/html"},
        )
        findings = await web_checks.check_sensitive_files(
            "https://example.com/", RouteClient(default=catchall)
        )
        self.assertEqual(findings, [])

    async def test_real_environment_file_requires_and_records_oracle(self):
        routes = {
            "/.env": FakeResponse(200, "DB_PASSWORD=secret\nAPP_ENV=prod\n"),
        }
        findings = await web_checks.check_sensitive_files(
            "https://example.com/", RouteClient(routes=routes)
        )
        env = [f for f in findings if "Environment File Exposed" in f["vulnerability"]]
        self.assertEqual(len(env), 1)
        self.assertIn("Evidence:", env[0]["details"])
        self.assertEqual(env[0]["payload_url"], "https://example.com:443/.env")

    async def test_header_policy_is_not_inferred_from_404(self):
        findings = await web_checks.check_security_headers(
            "https://example.com/", RouteClient(default=FakeResponse(404, "Not found"))
        )
        self.assertEqual(findings, [])

    async def test_admin_catchall_is_suppressed(self):
        catchall = FakeResponse(
            200,
            '<html><title>Portal</title><form><input type="password"></form></html>',
            {"content-type": "text/html"},
        )
        findings = await web_checks.check_admin_panels(
            "https://example.com/", RouteClient(default=catchall)
        )
        self.assertEqual(findings, [])

    async def test_admin_login_form_is_inventory_not_high_severity(self):
        routes = {
            "/admin": FakeResponse(
                200,
                '<html><title>Admin Login</title><form><input type="password"></form></html>',
                {"content-type": "text/html"},
            ),
        }
        findings = await web_checks.check_admin_panels(
            "https://example.com/", RouteClient(routes=routes)
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "INFO")
        self.assertEqual(findings[0]["status"], "INFO")


class DomainScanAccuracyTests(unittest.IsolatedAsyncioTestCase):
    async def test_cors_headers_on_redirect_are_not_a_finding(self):
        redirect = FakeResponse(
            302,
            "",
            {
                "access-control-allow-origin": "https://cors-test.invalid",
                "access-control-allow-credentials": "true",
                "location": "https://access.example/login",
            },
        )
        scanner = domain_scan.DomainScanner(tempfile.gettempdir())
        with patch("modules.domain_scan.httpx.AsyncClient", return_value=ContextClient(default=redirect)):
            findings = await scanner.run_anomaly_checks(
                ["https://example.com"],
                [{"url": "https://example.com", "input": "example.com"}],
                concurrency=2,
            )
        self.assertFalse(any(f["vulnerability"].startswith("CORS:") for f in findings))


class BrokenResourceAccuracyTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_confirmed_same_origin_resource_is_diagnostic(self):
        parent = "https://example.com/"
        routes = {
            "/": FakeResponse(
                200,
                '<html><script src="/missing.js"></script>'
                '<script src="/cdn-cgi/scripts/email-decode.min.js"></script>'
                '<script src="https://third.example/lib.js"></script></html>',
                {"content-type": "text/html"},
            ),
            ("HEAD", "/missing.js"): FakeResponse(404, ""),
            "/missing.js": FakeResponse(404, "missing"),
        }
        scanner = domain_scan.DomainScanner(tempfile.gettempdir())
        with patch("modules.domain_scan.httpx.AsyncClient", return_value=ContextClient(routes)):
            diagnostics = await scanner.check_broken_components(
                [{"url": parent, "status_code": 200, "port": 443}], concurrency=5
            )
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0]["url"], "https://example.com/missing.js")
        self.assertEqual(diagnostics[0]["severity"], "INFO")


if __name__ == "__main__":
    unittest.main()
