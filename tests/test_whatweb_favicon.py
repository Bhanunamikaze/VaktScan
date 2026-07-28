"""
Tests for the whatweb (modules/tech_fingerprint.py) and favicon-product-ID
(modules/favicon_jarm.py) additions.

Everything is mocked - NO external tools (webanalyze / whatweb) and NO network
(endoflife.date / target hosts / favicon fetch):

* whatweb / webanalyze -> mocked ``asyncio.create_subprocess_exec`` + patched
  binary resolvers (which=None simulates "tool absent").
* endoflife.date and target-host HTTP -> a fake ``httpx.AsyncClient``.
* favicon fetch -> a mocked httpx client.

Coverage:
  - whatweb JSON with product+version -> a canonical "Technology Detected:
    nginx 1.18.0" finding (the contract that feeds web_tech_cve's --tech funnel)
  - whatweb absent (which=None) -> graceful skip / no crash (built-in fallback)
  - whatweb EOL cross-reference still fires for whatweb-sourced detections
  - dedupe: webanalyze + whatweb both reporting the same (name, version) yields a
    single Technology Detected finding
  - whatweb meta plugins are skipped; HTTPServer string tokens are parsed
  - favicon known-hash -> INFO product-identification finding with NO fabricated
    version; favicon unknown-hash -> no product claim
"""

import asyncio
import base64
import os
import sys
import unittest
from unittest import mock
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import mmh3  # noqa: E402  (available in the test env; used to build a known vector)

from modules import favicon_jarm  # noqa: E402
from modules import tech_fingerprint  # noqa: E402
from modules.schema import CANONICAL_KEYS, validate_finding  # noqa: E402


# ─── Fakes for httpx.AsyncClient (tech_fingerprint) ────────────────────────────

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
    def __init__(self, route):
        self._route = route

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, **kwargs):
        return self._route(url)


def _client_factory(route):
    def factory(*args, **kwargs):
        return FakeAsyncClient(route)
    return factory


# ─── Fake subprocess (webanalyze / whatweb differentiated by argv) ─────────────

class FakeProc:
    def __init__(self, stdout=b"", stderr=b""):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = 0

    async def communicate(self, input=None):
        return (self._stdout, self._stderr)


def _fake_exec(stdout_bytes):
    async def _exec(*args, **kwargs):
        return FakeProc(stdout=stdout_bytes)
    return _exec


def _fake_exec_by_tool(webanalyze_out=b"", whatweb_out=b""):
    """Return webanalyze or whatweb output depending on the invoked binary."""
    async def _exec(*args, **kwargs):
        argv = " ".join(str(a) for a in args)
        if "whatweb" in argv:
            return FakeProc(stdout=whatweb_out)
        return FakeProc(stdout=webanalyze_out)
    return _exec


NGINX_CYCLES = [
    {"cycle": "1.10", "eol": "2017-04-01"},  # clearly EOL
    {"cycle": "1.24", "eol": "2099-01-01"},
]


def _endoflife_404(url):
    if "endoflife.date" in url:
        return FakeResponse(404)
    return None


def _info_findings(findings):
    return [f for f in findings
            if f["vulnerability"].startswith("Technology Detected")]


def _eol_findings(findings):
    return [f for f in findings
            if f["vulnerability"].startswith("Software End-of-Life")]


def _by_version(findings, version):
    return [f for f in findings if f.get("service_version") == version]


# ─── whatweb: JSON parsing (pure) ──────────────────────────────────────────────

class WhatwebParseTests(unittest.TestCase):
    def test_plugins_product_and_version(self):
        text = (
            '[{"target":"https://x","plugins":{'
            '"nginx":{"version":["1.18.0"]},'
            '"PHP":{"version":["7.4.3"]},'
            '"WordPress":{}}}]'
        )
        dets = tech_fingerprint._parse_whatweb_output(text)
        by = {(d["name"].lower(), d["version"]) for d in dets}
        self.assertIn(("nginx", "1.18.0"), by)
        self.assertIn(("php", "7.4.3"), by)
        self.assertIn(("wordpress", ""), by)  # versionless still detected
        self.assertTrue(all(d["source"] == "whatweb" for d in dets))

    def test_meta_plugins_skipped(self):
        text = (
            '[{"plugins":{'
            '"Title":{"string":["Home"]},'
            '"Country":{"string":["UNITED STATES"]},'
            '"HTML5":{},'
            '"nginx":{"version":["1.18.0"]}}}]'
        )
        dets = tech_fingerprint._parse_whatweb_output(text)
        names = {d["name"].lower() for d in dets}
        self.assertEqual(names, {"nginx"})

    def test_httpserver_string_token_parsed(self):
        text = '[{"plugins":{"HTTPServer":{"string":["nginx/1.18.0"]}}}]'
        dets = tech_fingerprint._parse_whatweb_output(text)
        by = {(d["name"].lower(), d["version"]) for d in dets}
        self.assertIn(("nginx", "1.18.0"), by)

    def test_empty_and_garbage(self):
        self.assertEqual(tech_fingerprint._parse_whatweb_output(""), [])
        self.assertEqual(tech_fingerprint._parse_whatweb_output("not json"), [])


# ─── whatweb: end-to-end via fingerprint_tech ──────────────────────────────────

class WhatwebFingerprintTests(unittest.IsolatedAsyncioTestCase):
    async def test_whatweb_emits_technology_detected(self):
        whatweb_json = (
            '[{"target":"https://ww.example.com","plugins":{'
            '"nginx":{"version":["1.18.0"]},'
            '"WordPress":{}}}]'
        )
        with patch.object(tech_fingerprint, "_webanalyze_binary", return_value=None), \
             patch.object(tech_fingerprint, "_whatweb_binary",
                          return_value="/usr/bin/whatweb"), \
             patch("asyncio.create_subprocess_exec",
                   side_effect=_fake_exec(whatweb_json.encode())), \
             patch("modules.tech_fingerprint.httpx.AsyncClient",
                   _client_factory(_endoflife_404)):
            findings = await tech_fingerprint.fingerprint_tech(
                ["https://ww.example.com"], "reports_test")

        infos = _info_findings(findings)
        # The canonical contract that feeds web_tech_cve's --tech funnel.
        nginx = _by_version(infos, "1.18.0")
        self.assertTrue(nginx, "whatweb nginx version not surfaced")
        self.assertEqual(nginx[0]["vulnerability"], "Technology Detected: nginx 1.18.0")
        self.assertEqual(nginx[0]["module"], tech_fingerprint.MODULE_NAME)
        # Versionless WordPress detection is INFO-only (no version).
        self.assertTrue(any("WordPress" in f["vulnerability"] for f in infos))
        for f in findings:
            self.assertEqual(validate_finding(f), [], f"schema violation: {f}")

    async def test_whatweb_eol_still_flags(self):
        whatweb_json = (
            '[{"plugins":{"nginx":{"version":["1.10.0"]}}}]'
        )

        def route(url):
            if "endoflife.date/api/nginx.json" in url:
                return FakeResponse(200, json_data=NGINX_CYCLES)
            if "endoflife.date" in url:
                return FakeResponse(404)
            return FakeResponse(200, headers={}, text="")

        with patch.object(tech_fingerprint, "_webanalyze_binary", return_value=None), \
             patch.object(tech_fingerprint, "_whatweb_binary",
                          return_value="/usr/bin/whatweb"), \
             patch("asyncio.create_subprocess_exec",
                   side_effect=_fake_exec(whatweb_json.encode())), \
             patch("modules.tech_fingerprint.httpx.AsyncClient",
                   _client_factory(route)):
            findings = await tech_fingerprint.fingerprint_tech(
                ["https://eol.example.com"], "reports_test")

        eols = _eol_findings(findings)
        self.assertEqual(len(eols), 1, f"expected 1 EOL finding, got {eols}")
        self.assertIn("nginx", eols[0]["vulnerability"].lower())
        self.assertIn("2017-04-01", eols[0]["details"])
        for f in findings:
            self.assertEqual(validate_finding(f), [], f"schema violation: {f}")

    async def test_whatweb_absent_graceful_skip(self):
        # Both tools absent (which=None) -> built-in fallback, no crash.
        def route(url):
            eol = _endoflife_404(url)
            if eol is not None:
                return eol
            return FakeResponse(200, headers={"Server": "nginx/1.18.0"}, text="")

        with patch.object(tech_fingerprint, "_webanalyze_binary", return_value=None), \
             patch.object(tech_fingerprint, "_whatweb_binary", return_value=None), \
             patch("modules.tech_fingerprint.httpx.AsyncClient",
                   _client_factory(route)):
            findings = await tech_fingerprint.fingerprint_tech(
                ["https://noww.example.com"], "reports_test")

        # No crash; the built-in detector still yields a signal from the header.
        self.assertTrue(_by_version(_info_findings(findings), "1.18.0"))

    async def test_dedupe_webanalyze_and_whatweb(self):
        # webanalyze reports "Nginx 1.18.0"; whatweb reports "nginx 1.18.0".
        webanalyze_json = (
            '{"hostname":"https://dup.example.com","matches":['
            '{"app_name":"Nginx","version":"1.18.0","categories":["Web servers"]}'
            ']}'
        )
        whatweb_json = (
            '[{"plugins":{"nginx":{"version":["1.18.0"]}}}]'
        )
        with patch.object(tech_fingerprint, "_webanalyze_binary",
                          return_value="/usr/bin/webanalyze"), \
             patch.object(tech_fingerprint, "_whatweb_binary",
                          return_value="/usr/bin/whatweb"), \
             patch("asyncio.create_subprocess_exec",
                   side_effect=_fake_exec_by_tool(
                       webanalyze_out=webanalyze_json.encode(),
                       whatweb_out=whatweb_json.encode())), \
             patch("modules.tech_fingerprint.httpx.AsyncClient",
                   _client_factory(_endoflife_404)):
            findings = await tech_fingerprint.fingerprint_tech(
                ["https://dup.example.com"], "reports_test")

        # Same (name, version) from two sources -> exactly ONE info finding.
        infos_1180 = _by_version(_info_findings(findings), "1.18.0")
        self.assertEqual(len(infos_1180), 1,
                         f"expected dedupe to a single finding, got {infos_1180}")
        for f in findings:
            self.assertEqual(validate_finding(f), [], f"schema violation: {f}")


# ─── favicon -> product identification ─────────────────────────────────────────

def _mock_response(status_code=200, content=b""):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.content = content
    return resp


def _mock_client(get_return=None):
    client = mock.AsyncMock()
    client.__aenter__ = mock.AsyncMock(return_value=client)
    client.__aexit__ = mock.AsyncMock(return_value=None)
    client.get = mock.AsyncMock(return_value=get_return)
    return client


class FaviconProductLookupTests(unittest.TestCase):
    def test_known_hash_maps_to_product(self):
        # Pick any real entry from the curated map.
        known_hash, product = next(iter(favicon_jarm.FAVICON_PRODUCT_MAP.items()))
        self.assertEqual(favicon_jarm.favicon_product(known_hash), product)

    def test_unknown_hash_returns_none(self):
        # A hash guaranteed not to be in the curated map.
        self.assertIsNone(favicon_jarm.favicon_product(0))

    def test_bad_input_returns_none(self):
        self.assertIsNone(favicon_jarm.favicon_product("not-an-int"))
        self.assertIsNone(favicon_jarm.favicon_product(None))


class FaviconIdentificationTests(unittest.IsolatedAsyncioTestCase):
    async def test_known_favicon_identifies_product_without_version(self):
        raw = b"fake-favicon-bytes"
        fhash = favicon_jarm._shodan_favicon_hash(raw)
        client = _mock_client(get_return=_mock_response(200, raw))
        sem = asyncio.Semaphore(5)

        with mock.patch.dict(favicon_jarm.FAVICON_PRODUCT_MAP,
                             {fhash: "AcmeAdminPanel"}, clear=False), \
             mock.patch.object(favicon_jarm, "_compute_jarm",
                               new=mock.AsyncMock(return_value=None)):
            findings = await favicon_jarm._fingerprint_one(
                client, sem, "https://example.com:443")

        id_findings = [f for f in findings
                       if f["vulnerability"] == "Product Identified via Favicon"]
        self.assertEqual(len(id_findings), 1)
        idf = id_findings[0]
        self.assertEqual(idf["status"], "INFO")
        self.assertEqual(idf["severity"], "INFO")
        self.assertIn("AcmeAdminPanel", idf["details"])
        # HONESTY: identifies product only - NO version fabricated.
        self.assertEqual(idf["service_version"], "N/A")
        self.assertIn("NO version", idf["details"])
        # The pivot favicon finding is still emitted alongside.
        self.assertTrue(any(f["vulnerability"].startswith("Favicon Hash")
                            for f in findings))
        for f in findings:
            for key in CANONICAL_KEYS:
                self.assertIn(key, f)
            hard = [v for v in validate_finding(f)
                    if v.startswith(("MISSING", "INVALID", "FORBIDDEN"))]
            self.assertEqual(hard, [], f"schema violations: {hard}")

    async def test_unknown_favicon_makes_no_product_claim(self):
        raw = b"some-unrecognised-favicon"
        fhash = favicon_jarm._shodan_favicon_hash(raw)
        client = _mock_client(get_return=_mock_response(200, raw))
        sem = asyncio.Semaphore(5)

        # Ensure the computed hash is NOT in the map.
        clean_map = {k: v for k, v in favicon_jarm.FAVICON_PRODUCT_MAP.items()
                     if k != fhash}
        with mock.patch.object(favicon_jarm, "FAVICON_PRODUCT_MAP", clean_map), \
             mock.patch.object(favicon_jarm, "_compute_jarm",
                               new=mock.AsyncMock(return_value=None)):
            findings = await favicon_jarm._fingerprint_one(
                client, sem, "https://example.com:443")

        # Favicon pivot finding present, but NO product-identification claim.
        self.assertTrue(any(f["vulnerability"].startswith("Favicon Hash")
                            for f in findings))
        self.assertFalse(any(f["vulnerability"] == "Product Identified via Favicon"
                             for f in findings))


if __name__ == "__main__":
    unittest.main()
