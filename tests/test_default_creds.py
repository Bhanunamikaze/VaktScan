"""
Tests for modules/default_creds.py — the default-credential confirmation
module. All HTTP is mocked; nothing touches the network.

The suite enforces the false-positive discipline required of this module:

* a CONFIRMED default-credential response (positive oracle satisfied) yields a
  CRITICAL finding,
* rejected credentials (401 / login page that does not accept the creds) yield
  NO finding,
* a catch-all server that "succeeds" for a deliberately-wrong credential (the
  negative control) yields NO finding,
* empty input yields [].
"""
import asyncio
import os
import sys
import unittest
from unittest.mock import patch
from urllib.parse import urlparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules import default_creds  # noqa: E402


_UNSET = object()


class FakeResponse:
    """Minimal stand-in for an httpx.Response."""

    def __init__(self, status_code=200, text="", headers=None,
                 json_data=_UNSET, cookies=None):
        self.status_code = status_code
        self.text = text
        # httpx headers are case-insensitive; store lowercase keys so the
        # module's lowercase .get() lookups resolve.
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._json = json_data
        self.cookies = cookies if cookies is not None else {}

    def json(self):
        if self._json is _UNSET:
            raise ValueError("no json body")
        return self._json


class FakeClient:
    """Async client whose responses come from a handler(method, url, kwargs)."""

    def __init__(self, handler):
        self.handler = handler

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **kw):
        return self.handler("GET", url, kw)

    async def post(self, url, **kw):
        return self.handler("POST", url, kw)


class _DummyProgress:
    """No-op DashboardProgress replacement for the entry-point test."""

    def __init__(self, *a, **k):
        pass

    async def wrap(self, coro):
        return await coro


def _path(url):
    return urlparse(url).path or "/"


def _run(coro):
    return asyncio.run(coro)


TOMCAT_MANAGER_BODY = (
    "<html><head><title>/manager</title></head><body>"
    "Tomcat Web Application Manager - list applications - undeploy"
    "</body></html>"
)
TOMCAT_CHALLENGE = {"www-authenticate": 'Basic realm="Tomcat Manager Application"'}


# ─── Apache Tomcat Manager ────────────────────────────────────────────────────

class TomcatManagerTests(unittest.TestCase):

    def test_confirmed_default_creds_yield_critical(self):
        def handler(method, url, kw):
            if _path(url) == "/manager/html":
                auth = kw.get("auth")
                if auth and auth[0] == "tomcat" and auth[1] == "tomcat":
                    return FakeResponse(200, text=TOMCAT_MANAGER_BODY)
                # bogus + admin/admin → Basic-Auth challenge
                return FakeResponse(401, headers=TOMCAT_CHALLENGE)
            return FakeResponse(404)

        findings = _run(default_creds.check_tomcat_manager(
            "http://tomcat.example:8080", FakeClient(handler)))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "CRITICAL")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("tomcat:tomcat", findings[0]["details"])
        self.assertEqual(findings[0]["module"], default_creds.MODULE_NAME)

    def test_rejected_creds_yield_no_finding(self):
        """Present (401 challenge) but every credential is rejected → nothing."""
        def handler(method, url, kw):
            if _path(url) == "/manager/html":
                return FakeResponse(401, headers=TOMCAT_CHALLENGE)
            return FakeResponse(404)

        findings = _run(default_creds.check_tomcat_manager(
            "http://tomcat.example:8080", FakeClient(handler)))
        self.assertEqual(findings, [])

    def test_catch_all_manager_body_suppressed(self):
        """Manager UI returned for ANY credential (incl. bogus) → suppressed."""
        def handler(method, url, kw):
            if _path(url) == "/manager/html":
                # even the random baseline credential gets the manager body
                return FakeResponse(200, text=TOMCAT_MANAGER_BODY,
                                    headers=TOMCAT_CHALLENGE)
            return FakeResponse(404)

        findings = _run(default_creds.check_tomcat_manager(
            "http://tomcat.example:8080", FakeClient(handler)))
        self.assertEqual(findings, [])

    def test_not_tomcat_yields_no_finding(self):
        def handler(method, url, kw):
            return FakeResponse(404)

        findings = _run(default_creds.check_tomcat_manager(
            "http://nope.example", FakeClient(handler)))
        self.assertEqual(findings, [])


# ─── Grafana ──────────────────────────────────────────────────────────────────

class GrafanaTests(unittest.TestCase):

    def test_confirmed_default_admin_yields_critical(self):
        def handler(method, url, kw):
            p = _path(url)
            if p == "/login" and method == "GET":
                return FakeResponse(200, text="<html>grafana window.grafanaBootData</html>")
            if p == "/login" and method == "POST":
                body = kw.get("json") or {}
                if body.get("user") == "admin" and body.get("password") == "admin":
                    return FakeResponse(200, json_data={"message": "Logged in"},
                                        cookies={"grafana_session": "valid"})
                return FakeResponse(401, json_data={"message": "invalid"}, cookies={})
            if p == "/api/user":
                cookies = kw.get("cookies") or {}
                if cookies.get("grafana_session") == "valid":
                    return FakeResponse(200, json_data={
                        "id": 1, "login": "admin",
                        "email": "admin@localhost", "isGrafanaAdmin": True})
                return FakeResponse(401, text="")
            return FakeResponse(404)

        findings = _run(default_creds.check_grafana(
            "http://grafana.example:3000", FakeClient(handler)))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "CRITICAL")
        self.assertIn("admin:admin", findings[0]["details"])

    def test_rejected_creds_yield_no_finding(self):
        """admin/admin returns 401 (rejected) → /api/user stays 401 → nothing."""
        def handler(method, url, kw):
            p = _path(url)
            if p == "/login" and method == "GET":
                return FakeResponse(200, text="<html>grafana</html>")
            if p == "/login" and method == "POST":
                return FakeResponse(401, json_data={"message": "invalid"}, cookies={})
            if p == "/api/user":
                return FakeResponse(401, text="")
            return FakeResponse(404)

        findings = _run(default_creds.check_grafana(
            "http://grafana.example:3000", FakeClient(handler)))
        self.assertEqual(findings, [])

    def test_anonymous_api_user_suppressed(self):
        """/api/user authenticated without login → anonymous access, not a
        default-cred finding."""
        def handler(method, url, kw):
            p = _path(url)
            if p == "/login" and method == "GET":
                return FakeResponse(200, text="<html>grafana</html>")
            if p == "/api/user":
                return FakeResponse(200, json_data={
                    "id": 1, "login": "admin", "email": "a@b", "isGrafanaAdmin": True})
            return FakeResponse(404)

        findings = _run(default_creds.check_grafana(
            "http://grafana.example:3000", FakeClient(handler)))
        self.assertEqual(findings, [])

    def test_catch_all_any_cookie_suppressed(self):
        """Wrong-credential login also yields an authenticated /api/user (any
        cookie works) → negative control suppresses the finding."""
        def handler(method, url, kw):
            p = _path(url)
            if p == "/login" and method == "GET":
                return FakeResponse(200, text="<html>grafana</html>")
            if p == "/login" and method == "POST":
                # ANY login hands back a session cookie
                return FakeResponse(200, json_data={"message": "Logged in"},
                                    cookies={"grafana_session": "whatever"})
            if p == "/api/user":
                cookies = kw.get("cookies") or {}
                if cookies:  # any cookie authenticates → catch-all
                    return FakeResponse(200, json_data={
                        "id": 1, "login": "admin",
                        "email": "a@b", "isGrafanaAdmin": True})
                return FakeResponse(401, text="")
            return FakeResponse(404)

        findings = _run(default_creds.check_grafana(
            "http://grafana.example:3000", FakeClient(handler)))
        self.assertEqual(findings, [])


# ─── Jenkins ──────────────────────────────────────────────────────────────────

JENKINS_HEADERS = {"x-jenkins": "2.400"}


class JenkinsTests(unittest.TestCase):

    def test_anonymous_script_console_yields_critical(self):
        def handler(method, url, kw):
            p = _path(url)
            if p == "/":
                return FakeResponse(200, text="<html>Jenkins dashboard</html>",
                                    headers=JENKINS_HEADERS)
            if p == "/script":
                return FakeResponse(
                    200, text="Script Console - groovy - System.getProperty")
            if p == "/whoAmI/api/json":
                return FakeResponse(200, json_data={
                    "authenticated": False, "name": "anonymous"})
            if p == "/j_spring_security_check":
                return FakeResponse(401, cookies={})
            return FakeResponse(404)

        findings = _run(default_creds.check_jenkins(
            "http://jenkins.example:8080", FakeClient(handler)))
        vulns = [f["vulnerability"] for f in findings]
        self.assertIn("Jenkins Script Console Accessible (Anonymous)", vulns)
        self.assertTrue(all(f["status"] == "CRITICAL" for f in findings))

    def test_weak_admin_login_yields_critical(self):
        def handler(method, url, kw):
            p = _path(url)
            if p == "/":
                return FakeResponse(200, text="Jenkins", headers=JENKINS_HEADERS)
            if p == "/script":
                return FakeResponse(403, text="forbidden")  # secured
            if p == "/whoAmI/api/json":
                cookies = kw.get("cookies") or {}
                if cookies.get("JSESSIONID") == "valid":
                    return FakeResponse(200, json_data={
                        "authenticated": True, "name": "admin"})
                return FakeResponse(200, json_data={
                    "authenticated": False, "name": "anonymous"})
            if p == "/j_spring_security_check":
                data = kw.get("data") or {}
                if data.get("j_username") == "admin" and data.get("j_password") == "admin":
                    return FakeResponse(302, cookies={"JSESSIONID": "valid"})
                return FakeResponse(401, cookies={})
            return FakeResponse(404)

        findings = _run(default_creds.check_jenkins(
            "http://jenkins.example:8080", FakeClient(handler)))
        vulns = [f["vulnerability"] for f in findings]
        self.assertIn("Jenkins Weak Admin Credentials", vulns)
        crit = [f for f in findings if f["vulnerability"] == "Jenkins Weak Admin Credentials"][0]
        self.assertEqual(crit["status"], "CRITICAL")

    def test_secured_jenkins_yields_no_finding(self):
        """Secured console (403) and login rejected → nothing."""
        def handler(method, url, kw):
            p = _path(url)
            if p == "/":
                return FakeResponse(200, text="Jenkins", headers=JENKINS_HEADERS)
            if p == "/script":
                return FakeResponse(403, text="forbidden")
            if p == "/whoAmI/api/json":
                return FakeResponse(200, json_data={
                    "authenticated": False, "name": "anonymous"})
            if p == "/j_spring_security_check":
                return FakeResponse(401, cookies={})  # all logins rejected
            return FakeResponse(404)

        findings = _run(default_creds.check_jenkins(
            "http://jenkins.example:8080", FakeClient(handler)))
        self.assertEqual(findings, [])

    def test_catch_all_whoami_suppressed(self):
        """/whoAmI always reports an authenticated admin → anonymous baseline
        guard suppresses the weak-login claim."""
        def handler(method, url, kw):
            p = _path(url)
            if p == "/":
                return FakeResponse(200, text="Jenkins", headers=JENKINS_HEADERS)
            if p == "/script":
                return FakeResponse(403, text="forbidden")
            if p == "/whoAmI/api/json":
                return FakeResponse(200, json_data={
                    "authenticated": True, "name": "admin"})  # always authed
            if p == "/j_spring_security_check":
                return FakeResponse(302, cookies={"JSESSIONID": "x"})
            return FakeResponse(404)

        findings = _run(default_creds.check_jenkins(
            "http://jenkins.example:8080", FakeClient(handler)))
        self.assertEqual(findings, [])


# ─── Generic HTTP Basic-Auth ──────────────────────────────────────────────────

BASIC_CHALLENGE = {"www-authenticate": 'Basic realm="Admin Area"'}
CHALLENGE_BODY = "401 Unauthorized"


class BasicAuthTests(unittest.TestCase):

    def test_confirmed_weak_creds_yield_finding(self):
        def handler(method, url, kw):
            auth = kw.get("auth")
            if auth and auth[0] == "admin" and auth[1] == "admin":
                return FakeResponse(200, text="<html>Secret Admin Dashboard</html>")
            # no creds, bogus, admin/password → 401 challenge
            return FakeResponse(401, headers=BASIC_CHALLENGE, text=CHALLENGE_BODY)

        findings = _run(default_creds.check_basic_auth(
            "http://basic.example", FakeClient(handler)))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "VULNERABLE")
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("admin:admin", findings[0]["details"])

    def test_rejected_creds_yield_no_finding(self):
        def handler(method, url, kw):
            return FakeResponse(401, headers=BASIC_CHALLENGE, text=CHALLENGE_BODY)

        findings = _run(default_creds.check_basic_auth(
            "http://basic.example", FakeClient(handler)))
        self.assertEqual(findings, [])

    def test_catch_all_200_to_everything_suppressed(self):
        """No-cred is 401 but a bogus credential returns 200 → the gate is not
        real → suppressed."""
        def handler(method, url, kw):
            auth = kw.get("auth")
            if auth is None:
                return FakeResponse(401, headers=BASIC_CHALLENGE, text=CHALLENGE_BODY)
            # ANY credential (including the random control) → 200
            return FakeResponse(200, text="<html>anything</html>")

        findings = _run(default_creds.check_basic_auth(
            "http://basic.example", FakeClient(handler)))
        self.assertEqual(findings, [])

    def test_unchanged_body_suppressed(self):
        """A 200 whose body equals the 401 challenge is not real content."""
        def handler(method, url, kw):
            auth = kw.get("auth")
            if auth and auth[0] == "admin" and auth[1] == "admin":
                return FakeResponse(200, text=CHALLENGE_BODY)  # same as challenge
            return FakeResponse(401, headers=BASIC_CHALLENGE, text=CHALLENGE_BODY)

        findings = _run(default_creds.check_basic_auth(
            "http://basic.example", FakeClient(handler)))
        self.assertEqual(findings, [])

    def test_no_basic_challenge_yields_no_finding(self):
        def handler(method, url, kw):
            return FakeResponse(200, text="<html>public</html>")

        findings = _run(default_creds.check_basic_auth(
            "http://basic.example", FakeClient(handler)))
        self.assertEqual(findings, [])


# ─── Entry point ──────────────────────────────────────────────────────────────

class EntryPointTests(unittest.TestCase):

    def test_empty_input_returns_empty_list(self):
        findings = _run(default_creds.check_default_credentials([], "/tmp/out"))
        self.assertEqual(findings, [])

    def test_all_none_input_returns_empty_list(self):
        findings = _run(default_creds.check_default_credentials([None, ""], "/tmp/out"))
        self.assertEqual(findings, [])

    def test_confirmed_grafana_via_entry_point_yields_critical(self):
        def handler(method, url, kw):
            p = _path(url)
            # Grafana confirmed path
            if p == "/login" and method == "GET":
                return FakeResponse(200, text="<html>grafana</html>")
            if p == "/login" and method == "POST":
                body = kw.get("json") or {}
                if body.get("user") == "admin" and body.get("password") == "admin":
                    return FakeResponse(200, json_data={"message": "Logged in"},
                                        cookies={"grafana_session": "valid"})
                return FakeResponse(401, json_data={"message": "invalid"}, cookies={})
            if p == "/api/user":
                cookies = kw.get("cookies") or {}
                if cookies.get("grafana_session") == "valid":
                    return FakeResponse(200, json_data={
                        "id": 1, "login": "admin", "email": "a@b",
                        "isGrafanaAdmin": True})
                return FakeResponse(401, text="")
            # Everything else (root, /manager/html, /script, ...) is benign:
            # a non-401 root so the other checks all short-circuit cleanly.
            if p == "/":
                return FakeResponse(200, text="grafana app")
            return FakeResponse(404)

        fake_client = FakeClient(handler)
        with patch("modules.default_creds.httpx.AsyncClient", return_value=fake_client), \
             patch("modules.default_creds.DashboardProgress", _DummyProgress):
            findings = _run(default_creds.check_default_credentials(
                ["http://grafana.example:3000"], "/tmp/out", concurrency=4))

        crit = [f for f in findings if f["status"] == "CRITICAL"]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]["vulnerability"], "Grafana Default Admin Credentials")
        # canonical schema: all 15 keys present
        from modules.schema import CANONICAL_KEYS
        for key in CANONICAL_KEYS:
            self.assertIn(key, crit[0])

    def test_per_host_error_is_caught_and_skipped(self):
        """A client that raises on every request must not crash the run."""
        def handler(method, url, kw):
            raise RuntimeError("network down")

        fake_client = FakeClient(handler)
        with patch("modules.default_creds.httpx.AsyncClient", return_value=fake_client), \
             patch("modules.default_creds.DashboardProgress", _DummyProgress):
            findings = _run(default_creds.check_default_credentials(
                ["http://boom.example"], "/tmp/out"))
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
