"""
Tests for modules/tech_fingerprint.py.

Everything is mocked so the suite runs with NO external tools (webanalyze) and NO
network (endoflife.date / target hosts):

* webanalyze  -> mocked ``asyncio.create_subprocess_exec`` + patched binary resolver
* endoflife.date and target-host HTTP -> a fake ``httpx.AsyncClient``

Coverage:
  - version parsing (built-in header detector + webanalyze JSON parser)
  - EOL flagging: a clearly-EOL version yields a finding; a supported one does not
  - EOL date is surfaced in the finding, severity is MEDIUM/HIGH
  - graceful behaviour: empty input, endoflife network failure, webanalyze->builtin fallback
  - every finding validates against the canonical schema
"""

import unittest
from unittest.mock import patch

from modules import tech_fingerprint
from modules.schema import validate_finding


# ─── Fakes for httpx.AsyncClient ───────────────────────────────────────────────

class FakeResponse:
    def __init__(self, status_code=200, headers=None, text="", json_data=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self._json = json_data

    def json(self):
        if self._json is None:
            raise ValueError("no json body")
        return self._json


class FakeAsyncClient:
    """Minimal stand-in for httpx.AsyncClient driven by a ``route`` callable."""

    def __init__(self, route):
        self._route = route

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, **kwargs):
        return self._route(url)


def _client_factory(route):
    """Return a callable that mimics ``httpx.AsyncClient(...)`` construction."""
    def factory(*args, **kwargs):
        return FakeAsyncClient(route)
    return factory


# ─── Fake webanalyze subprocess ────────────────────────────────────────────────

class FakeProc:
    def __init__(self, stdout=b"", stderr=b""):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = 0

    async def communicate(self):
        return (self._stdout, self._stderr)


def _fake_exec(stdout_bytes):
    async def _exec(*args, **kwargs):
        return FakeProc(stdout=stdout_bytes)
    return _exec


# ─── Sample endoflife.date cycle tables ────────────────────────────────────────

PHP_CYCLES = [
    {"cycle": "8.3", "eol": "2099-12-31"},
    {"cycle": "5.6", "eol": "2018-12-31"},   # clearly EOL (long past)
]
APACHE_CYCLES = [
    {"cycle": "2.4", "eol": False},          # still supported
    {"cycle": "2.2", "eol": "2018-01-01"},
]
NGINX_CYCLES = [
    {"cycle": "1.10", "eol": "2017-04-01"},  # clearly EOL
    {"cycle": "1.24", "eol": "2099-01-01"},
]
WORDPRESS_CYCLES = [
    {"cycle": "4.9", "eol": False},          # supported (per this fixture)
    {"cycle": "6.4", "eol": "2099-01-01"},
]


def _endoflife_route(url):
    if "endoflife.date/api/php.json" in url:
        return FakeResponse(200, json_data=PHP_CYCLES)
    if "endoflife.date/api/apache.json" in url:
        return FakeResponse(200, json_data=APACHE_CYCLES)
    if "endoflife.date/api/nginx.json" in url:
        return FakeResponse(200, json_data=NGINX_CYCLES)
    if "endoflife.date/api/wordpress.json" in url:
        return FakeResponse(200, json_data=WORDPRESS_CYCLES)
    if "endoflife.date" in url:
        return FakeResponse(404)
    return None


def _eol_findings(findings):
    return [f for f in findings if f["vulnerability"].startswith("Software End-of-Life")]


def _info_findings(findings):
    return [f for f in findings if f["vulnerability"].startswith("Technology Detected")]


def _by_version(findings, version):
    return [f for f in findings if f.get("service_version") == version]


class TechFingerprintTests(unittest.IsolatedAsyncioTestCase):

    # ── built-in detector + EOL cross-reference ────────────────────────────────
    async def test_builtin_detection_and_eol_flagging(self):
        def route(url):
            eol = _endoflife_route(url)
            if eol is not None:
                return eol
            # target host: Apache 2.4.7 (supported) + PHP 5.6.40 (EOL)
            return FakeResponse(
                200,
                headers={"Server": "Apache/2.4.7 (Ubuntu)",
                         "X-Powered-By": "PHP/5.6.40"},
                text="<html><head><title>hi</title></head><body>ok</body></html>",
            )

        with patch.object(tech_fingerprint, "_webanalyze_binary", return_value=None), \
             patch("modules.tech_fingerprint.httpx.AsyncClient",
                   _client_factory(route)):
            findings = await tech_fingerprint.fingerprint_tech(
                ["https://eol.example.com"], "reports_test"
            )

        infos = _info_findings(findings)
        # Version parsing: both Apache 2.4.7 and PHP 5.6.40 detected.
        self.assertTrue(_by_version(infos, "2.4.7"), "apache version not parsed")
        self.assertTrue(_by_version(infos, "5.6.40"), "php version not parsed")

        # EOL flagging: exactly one EOL finding — PHP 5.6.40 — NOT Apache 2.4.7.
        eols = _eol_findings(findings)
        self.assertEqual(len(eols), 1, f"expected 1 EOL finding, got {eols}")
        php_eol = eols[0]
        self.assertIn("PHP", php_eol["vulnerability"])
        self.assertEqual(php_eol["service_version"], "5.6.40")
        self.assertIn("2018-12-31", php_eol["details"])   # EOL date surfaced
        self.assertIn(php_eol["severity"], ("MEDIUM", "HIGH"))
        self.assertEqual(php_eol["status"], "VULNERABLE")

        # Supported product (Apache 2.4.7) produced NO EOL finding.
        self.assertFalse(
            [f for f in eols if "Apache" in f["vulnerability"]],
            "supported Apache 2.4 should not be flagged EOL",
        )

        for f in findings:
            self.assertEqual(validate_finding(f), [], f"schema violation: {f}")

    # ── webanalyze JSON parsing path ───────────────────────────────────────────
    async def test_webanalyze_parsing_and_eol(self):
        webanalyze_json = (
            '{"hostname":"https://tech.example.com","matches":['
            '{"app_name":"Nginx","version":"1.10.0","categories":["Web servers"]},'
            '{"app_name":"WordPress","version":"4.9","categories":["CMS"]}'
            ']}'
        )

        def route(url):
            eol = _endoflife_route(url)
            if eol is not None:
                return eol
            # If the built-in detector were (wrongly) used, this would add nothing.
            return FakeResponse(200, headers={}, text="")

        with patch.object(tech_fingerprint, "_webanalyze_binary",
                          return_value="/usr/bin/webanalyze"), \
             patch("asyncio.create_subprocess_exec",
                   side_effect=_fake_exec(webanalyze_json.encode())), \
             patch("modules.tech_fingerprint.httpx.AsyncClient",
                   _client_factory(route)):
            findings = await tech_fingerprint.fingerprint_tech(
                ["https://tech.example.com"], "reports_test"
            )

        infos = _info_findings(findings)
        # webanalyze versions parsed correctly.
        self.assertTrue(_by_version(infos, "1.10.0"), "nginx version not parsed")
        self.assertTrue(_by_version(infos, "4.9"), "wordpress version not parsed")

        eols = _eol_findings(findings)
        # Only Nginx 1.10 is EOL; WordPress 4.9 is supported in the fixture.
        self.assertEqual(len(eols), 1, f"expected 1 EOL finding, got {eols}")
        self.assertIn("Nginx", eols[0]["vulnerability"])
        self.assertIn("2017-04-01", eols[0]["details"])
        self.assertIn(eols[0]["severity"], ("MEDIUM", "HIGH"))

        for f in findings:
            self.assertEqual(validate_finding(f), [], f"schema violation: {f}")

    # ── empty input ────────────────────────────────────────────────────────────
    async def test_empty_input_returns_empty(self):
        self.assertEqual(await tech_fingerprint.fingerprint_tech([], "reports_test"), [])
        self.assertEqual(
            await tech_fingerprint.fingerprint_tech(["", "   "], "reports_test"), []
        )

    # ── endoflife.date network failure → keep fingerprint, skip EOL ────────────
    async def test_endoflife_network_failure_keeps_fingerprint(self):
        def route(url):
            if "endoflife.date" in url:
                raise RuntimeError("simulated network failure")
            return FakeResponse(200, headers={"X-Powered-By": "PHP/5.6.40"}, text="")

        with patch.object(tech_fingerprint, "_webanalyze_binary", return_value=None), \
             patch("modules.tech_fingerprint.httpx.AsyncClient",
                   _client_factory(route)):
            findings = await tech_fingerprint.fingerprint_tech(
                ["https://down.example.com"], "reports_test"
            )

        # Fingerprint (INFO) survives; EOL step is skipped, not crashed.
        self.assertTrue(_by_version(_info_findings(findings), "5.6.40"))
        self.assertEqual(_eol_findings(findings), [])
        for f in findings:
            self.assertEqual(validate_finding(f), [], f"schema violation: {f}")

    # ── webanalyze present but empty output → built-in fallback ────────────────
    async def test_webanalyze_empty_falls_back_to_builtin(self):
        def route(url):
            eol = _endoflife_route(url)
            if eol is not None:
                return eol
            return FakeResponse(200, headers={"Server": "nginx/1.10.0"}, text="")

        with patch.object(tech_fingerprint, "_webanalyze_binary",
                          return_value="/usr/bin/webanalyze"), \
             patch("asyncio.create_subprocess_exec",
                   side_effect=_fake_exec(b"")), \
             patch("modules.tech_fingerprint.httpx.AsyncClient",
                   _client_factory(route)):
            findings = await tech_fingerprint.fingerprint_tech(
                ["https://fallback.example.com"], "reports_test"
            )

        # Built-in detector picked nginx up from the Server header ...
        self.assertTrue(_by_version(_info_findings(findings), "1.10.0"))
        # ... and the EOL cross-reference still fired.
        eols = _eol_findings(findings)
        self.assertEqual(len(eols), 1)
        self.assertIn("nginx", eols[0]["vulnerability"].lower())
        for f in findings:
            self.assertEqual(validate_finding(f), [], f"schema violation: {f}")

    # ── unknown product (not on endoflife.date) → INFO only, no EOL ────────────
    async def test_unknown_product_no_eol_finding(self):
        # Sanity: the detected product must genuinely be off the EOL map.
        self.assertIsNone(tech_fingerprint._product_slug("CoolServer"))

        queried = []

        def route(url):
            if "endoflife.date" in url:
                queried.append(url)
                return FakeResponse(404)
            return FakeResponse(200, headers={"Server": "CoolServer/1.2.3"}, text="")

        with patch.object(tech_fingerprint, "_webanalyze_binary", return_value=None), \
             patch("modules.tech_fingerprint.httpx.AsyncClient",
                   _client_factory(route)):
            findings = await tech_fingerprint.fingerprint_tech(
                ["https://unknown.example.com"], "reports_test"
            )

        # Version was parsed and reported as INFO ...
        self.assertTrue(_by_version(_info_findings(findings), "1.2.3"))
        # ... but no EOL finding, and endoflife.date was never even queried.
        self.assertEqual(_eol_findings(findings), [])
        self.assertEqual(queried, [], "should not query EOL for unknown products")
        for f in findings:
            self.assertEqual(validate_finding(f), [], f"schema violation: {f}")

    # ── version-less detection → INFO only, no EOL ─────────────────────────────
    async def test_versionless_detection_no_eol_finding(self):
        queried = []

        def route(url):
            if "endoflife.date" in url:
                queried.append(url)
                return FakeResponse(200, json_data=WORDPRESS_CYCLES)
            # WordPress detected via marker only — NO version available.
            return FakeResponse(
                200, headers={},
                text="<html><body><img src='/wp-content/x.png'></body></html>",
            )

        with patch.object(tech_fingerprint, "_webanalyze_binary", return_value=None), \
             patch("modules.tech_fingerprint.httpx.AsyncClient",
                   _client_factory(route)):
            findings = await tech_fingerprint.fingerprint_tech(
                ["https://cms.example.com"], "reports_test"
            )

        infos = _info_findings(findings)
        # WordPress detected (INFO), but with no version ...
        self.assertTrue(any("WordPress" in f["vulnerability"] for f in infos))
        # ... so no EOL finding and no EOL lookup (version required first).
        self.assertEqual(_eol_findings(findings), [])
        self.assertEqual(queried, [], "should not query EOL without a version")
        for f in findings:
            self.assertEqual(validate_finding(f), [], f"schema violation: {f}")

    # ── unit: a boolean/undated eol is NOT treated as EOL (needs concrete date)─
    def test_eol_status_requires_concrete_past_date(self):
        import datetime as _dt
        today = _dt.date(2026, 7, 27)
        self.assertEqual(
            tech_fingerprint._eol_status({"cycle": "1", "eol": True}, today),
            (False, None),
        )
        self.assertEqual(
            tech_fingerprint._eol_status({"cycle": "1", "eol": "2099-01-01"}, today),
            (False, None),
        )
        self.assertEqual(
            tech_fingerprint._eol_status({"cycle": "1", "eol": "2018-12-31"}, today),
            (True, "2018-12-31"),
        )

    # ── unit: cycle matching does not confuse 8.1 with 8.10 ────────────────────
    def test_match_cycle_prefix_precision(self):
        cycles = [{"cycle": "8.1", "eol": "2024-01-01"},
                  {"cycle": "8.10", "eol": "2099-01-01"}]
        self.assertEqual(tech_fingerprint._match_cycle("8.1.7", cycles)["cycle"], "8.1")
        self.assertEqual(tech_fingerprint._match_cycle("8.10.2", cycles)["cycle"], "8.10")
        # OpenSSL-style trailing letter.
        oc = [{"cycle": "1.0.2", "eol": "2019-12-31"}]
        self.assertEqual(tech_fingerprint._match_cycle("1.0.2k", oc)["cycle"], "1.0.2")


if __name__ == "__main__":
    unittest.main()
