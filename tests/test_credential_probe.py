"""
Tests for modules/credential_probe.py — identity endpoint probing.

Covers: credential exposure detection, identity-only detection, catch-all
suppression, 404 no-findings, non-JSON ignored, schema validation, and
multiple-endpoint scenarios.
"""

import unittest
from urllib.parse import urlparse

from modules import credential_probe
from modules.schema import validate_finding


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8", errors="replace")
        self.headers = headers or {}


class FakeClient:
    def __init__(self, routes=None, default_status=404, default_text=""):
        self.routes = routes or {}
        self.default_status = default_status
        self.default_text = default_text

    async def get(self, url, **kwargs):
        path = urlparse(url).path or "/"
        if path in self.routes:
            return self.routes[path]
        return FakeResponse(self.default_status, self.default_text)


URL = "http://target.test"


class CredentialExposureTests(unittest.IsolatedAsyncioTestCase):
    async def test_credential_exposure_detected(self):
        routes = {
            "/api/me": FakeResponse(200, (
                '{"email":"admin@corp.com",'
                '"username":"admin",'
                '"authentication_token":"aBcDeFgHiJkLmNoP123456",'
                '"api_key":"sk-prod-XXXXXXXXXXXXXXXXXXXX"}'
            )),
        }
        client = FakeClient(routes=routes)
        findings = await credential_probe.check_identity_endpoints(URL, client)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["status"], "CRITICAL")
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertIn("Credential Exposure", f["vulnerability"])
        self.assertIn("/api/me", f["vulnerability"])
        self.assertIn("authentication_token", f["details"])
        self.assertIn("api_key", f["details"])
        self.assertEqual(f["module"], credential_probe.MODULE_NAME)

    async def test_identity_without_creds(self):
        routes = {
            "/api/me": FakeResponse(200, (
                '{"email":"user@corp.com","name":"Some User","role":"viewer"}'
            )),
        }
        client = FakeClient(routes=routes)
        findings = await credential_probe.check_identity_endpoints(URL, client)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["status"], "VULNERABLE")
        self.assertEqual(f["severity"], "HIGH")
        self.assertIn("Identity Endpoint", f["vulnerability"])
        self.assertIn("/api/me", f["vulnerability"])

    async def test_catchall_suppressed(self):
        catchall = '{"email":"x@x.com","username":"x","authentication_token":"longvalue1234"}'
        client = FakeClient(default_status=200, default_text=catchall)
        findings = await credential_probe.check_identity_endpoints(URL, client)
        self.assertEqual(findings, [])

    async def test_404_no_findings(self):
        client = FakeClient(default_status=404, default_text="Not Found")
        findings = await credential_probe.check_identity_endpoints(URL, client)
        self.assertEqual(findings, [])

    async def test_non_json_ignored(self):
        routes = {
            "/api/me": FakeResponse(200, "<html><body>Login page</body></html>"),
        }
        client = FakeClient(routes=routes)
        findings = await credential_probe.check_identity_endpoints(URL, client)
        self.assertEqual(findings, [])

    async def test_schema_validation(self):
        routes = {
            "/api/me": FakeResponse(200, (
                '{"email":"a@b.com","authentication_token":"abcdefghijklmnop"}'
            )),
            "/whoami": FakeResponse(200, (
                '{"username":"admin","role":"superuser"}'
            )),
        }
        client = FakeClient(routes=routes)
        findings = await credential_probe.check_identity_endpoints(URL, client)
        self.assertGreater(len(findings), 0)

        for f in findings:
            violations = validate_finding(f)
            self.assertEqual(violations, [], f"Schema violations: {violations}")

    async def test_multiple_endpoints(self):
        routes = {
            "/api/me": FakeResponse(200, (
                '{"email":"a@b.com","authentication_token":"secretvalue1234567"}'
            )),
            "/whoami": FakeResponse(200, (
                '{"username":"admin","role":"superuser"}'
            )),
            "/api/profile": FakeResponse(200, (
                '{"email":"c@d.com","refresh_token":"refresh_XXXXXXXXXXX"}'
            )),
        }
        client = FakeClient(routes=routes)
        findings = await credential_probe.check_identity_endpoints(URL, client)

        vulns = {f["vulnerability"] for f in findings}
        self.assertIn("Unauthenticated Credential Exposure (/api/me)", vulns)
        self.assertIn("Unauthenticated Identity Endpoint (/whoami)", vulns)
        self.assertIn("Unauthenticated Credential Exposure (/api/profile)", vulns)
        self.assertEqual(len(findings), 3)

    async def test_short_credential_value_ignored(self):
        """Credential field with a value shorter than 8 chars is not flagged as CRITICAL."""
        routes = {
            "/api/me": FakeResponse(200, (
                '{"email":"a@b.com","api_key":"short"}'
            )),
        }
        client = FakeClient(routes=routes)
        findings = await credential_probe.check_identity_endpoints(URL, client)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "VULNERABLE")
        self.assertEqual(findings[0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
