"""Tests for modules/favicon_jarm.py — favicon-hash + JARM pivot fingerprinting.

All network I/O (the httpx favicon fetch) and all JARM computation are mocked, so
these tests run WITHOUT any network access or external tools installed.
"""

import asyncio
import base64
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import mmh3  # noqa: E402  (available in the test env; used to build the known vector)

from modules import favicon_jarm  # noqa: E402
from modules.schema import CANONICAL_KEYS, validate_finding  # noqa: E402


# ── helpers ─────────────────────────────────────────────────────────────────────

def _mock_response(status_code=200, content=b""):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.content = content
    return resp


def _mock_client(get_return=None, get_side_effect=None):
    """An httpx.AsyncClient-like mock usable both directly and as `async with`."""
    client = mock.AsyncMock()
    client.__aenter__ = mock.AsyncMock(return_value=client)
    client.__aexit__ = mock.AsyncMock(return_value=None)
    if get_side_effect is not None:
        client.get = mock.AsyncMock(side_effect=get_side_effect)
    else:
        client.get = mock.AsyncMock(return_value=get_return)
    return client


# ── favicon mmh3 pipeline ────────────────────────────────────────────────────────

class FaviconHashPipelineTest(unittest.TestCase):
    def test_known_vector(self):
        # Known vector: base64.encodebytes(b"hello world") == b"aGVsbG8gd29ybGQ=\n"
        # and mmh3.hash(that) == -1787112514 (seed 0, signed 32-bit).
        self.assertEqual(favicon_jarm._shodan_favicon_hash(b"hello world"), -1787112514)

    def test_pipeline_matches_base64_encodebytes_then_mmh3(self):
        raw = b"\x89PNG\r\n\x1a\n some binary favicon bytes \x00\x01\x02"
        expected = mmh3.hash(base64.encodebytes(raw))
        self.assertEqual(favicon_jarm._shodan_favicon_hash(raw), expected)

    def test_newlines_every_76_chars(self):
        # 76-char line wrapping (MIME base64) is what Shodan expects; encodebytes
        # yields a trailing newline and wraps long payloads.
        raw = b"A" * 200
        b64 = base64.encodebytes(raw)
        self.assertTrue(b64.endswith(b"\n"))
        # Every non-final chunk line is at most 76 chars.
        lines = b64.split(b"\n")
        self.assertTrue(any(len(l) == 76 for l in lines))


# ── target parsing ───────────────────────────────────────────────────────────────

class ParseTargetTest(unittest.TestCase):
    def test_full_https_url_with_port(self):
        self.assertEqual(favicon_jarm._parse_target("https://a.example.com:8443"),
                         ("https", "a.example.com", 8443))

    def test_https_default_port(self):
        self.assertEqual(favicon_jarm._parse_target("https://example.com"),
                         ("https", "example.com", 443))

    def test_http_default_port(self):
        self.assertEqual(favicon_jarm._parse_target("http://example.com"),
                         ("http", "example.com", 80))

    def test_bare_host_assumes_https(self):
        self.assertEqual(favicon_jarm._parse_target("example.com"),
                         ("https", "example.com", 443))

    def test_empty_returns_none(self):
        self.assertIsNone(favicon_jarm._parse_target(""))
        self.assertIsNone(favicon_jarm._parse_target(None))


# ── JARM output parsing / graceful skip ──────────────────────────────────────────

class JarmParsingTest(unittest.TestCase):
    def test_extracts_62_char_hash(self):
        h = "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c"
        out = f"Domain: example.com\nResolved IP: 1.2.3.4\nJARM: {h}\n"
        self.assertEqual(favicon_jarm._parse_jarm_output(out), h)

    def test_all_zero_hash_is_skipped(self):
        out = "JARM: " + ("0" * 62)
        self.assertIsNone(favicon_jarm._parse_jarm_output(out))

    def test_no_hash_returns_none(self):
        self.assertIsNone(favicon_jarm._parse_jarm_output("no fingerprint here"))


class JarmAvailabilityTest(unittest.IsolatedAsyncioTestCase):
    async def test_compute_jarm_skips_when_unavailable(self):
        with mock.patch.object(favicon_jarm, "_jarm_cli_path", return_value=None), \
             mock.patch.object(favicon_jarm, "_jarm_py_module", return_value=None):
            self.assertFalse(favicon_jarm.jarm_available())
            self.assertIsNone(await favicon_jarm._compute_jarm("example.com", 443))

    async def test_compute_jarm_uses_cli_when_present(self):
        h = "1" + "0" * 60 + "a"  # 62-char, not all-zero
        cli_out = f"JARM: {h}\n".encode()

        async def fake_cli(binary, host, port):
            return favicon_jarm._parse_jarm_output(cli_out.decode())

        with mock.patch.object(favicon_jarm, "_jarm_cli_path", return_value="/fake/jarm"), \
             mock.patch.object(favicon_jarm, "_jarm_via_cli", side_effect=fake_cli):
            result = await favicon_jarm._compute_jarm("example.com", 443)
        self.assertEqual(result, h)


# ── per-host worker: findings ────────────────────────────────────────────────────

class FingerprintOneTest(unittest.IsolatedAsyncioTestCase):
    async def test_favicon_finding_from_mocked_fetch(self):
        raw = b"fake-favicon-bytes"
        expected_hash = favicon_jarm._shodan_favicon_hash(raw)
        client = _mock_client(get_return=_mock_response(200, raw))
        sem = asyncio.Semaphore(5)

        # JARM unavailable → only the favicon finding.
        with mock.patch.object(favicon_jarm, "_compute_jarm",
                               new=mock.AsyncMock(return_value=None)):
            findings = await favicon_jarm._fingerprint_one(
                client, sem, "https://example.com:443")

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["module"], "favicon_jarm")
        self.assertEqual(f["status"], "INFO")
        self.assertEqual(f["severity"], "INFO")
        self.assertIn("Favicon", f["vulnerability"])
        self.assertIn(str(expected_hash), f["details"])
        self.assertIn("pivot", f["details"].lower())
        self.assertIn("http.favicon.hash", f["details"])
        self.assertTrue(f["url"].endswith("/favicon.ico"))

    async def test_jarm_finding_when_available(self):
        raw = b"favicon"
        client = _mock_client(get_return=_mock_response(200, raw))
        sem = asyncio.Semaphore(5)
        jarm_hash = "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c"

        with mock.patch.object(favicon_jarm, "_compute_jarm",
                               new=mock.AsyncMock(return_value=jarm_hash)):
            findings = await favicon_jarm._fingerprint_one(
                client, sem, "https://example.com:443")

        jarm_findings = [f for f in findings if "JARM" in f["vulnerability"]]
        self.assertEqual(len(jarm_findings), 1)
        jf = jarm_findings[0]
        self.assertIn(jarm_hash, jf["details"])
        self.assertIn("ssl.jarm", jf["details"])
        self.assertIn("pivot", jf["details"].lower())

    async def test_jarm_graceful_skip_produces_no_jarm_finding(self):
        raw = b"favicon"
        client = _mock_client(get_return=_mock_response(200, raw))
        sem = asyncio.Semaphore(5)

        # do_jarm=False simulates "no jarm tool available".
        findings = await favicon_jarm._fingerprint_one(
            client, sem, "https://example.com:443", do_jarm=False)

        self.assertTrue(all("JARM" not in f["vulnerability"] for f in findings))
        self.assertTrue(any("Favicon" in f["vulnerability"] for f in findings))

    async def test_non_200_favicon_yields_no_favicon_finding(self):
        client = _mock_client(get_return=_mock_response(404, b""))
        sem = asyncio.Semaphore(5)
        with mock.patch.object(favicon_jarm, "_compute_jarm",
                               new=mock.AsyncMock(return_value=None)):
            findings = await favicon_jarm._fingerprint_one(
                client, sem, "https://example.com")
        self.assertEqual(findings, [])

    async def test_fetch_exception_is_swallowed(self):
        client = _mock_client(get_side_effect=RuntimeError("connection reset"))
        sem = asyncio.Semaphore(5)
        with mock.patch.object(favicon_jarm, "_compute_jarm",
                               new=mock.AsyncMock(return_value=None)):
            findings = await favicon_jarm._fingerprint_one(
                client, sem, "https://example.com")
        self.assertEqual(findings, [])

    async def test_findings_are_schema_canonical(self):
        raw = b"favicon"
        client = _mock_client(get_return=_mock_response(200, raw))
        sem = asyncio.Semaphore(5)
        jarm_hash = "a" * 62
        with mock.patch.object(favicon_jarm, "_compute_jarm",
                               new=mock.AsyncMock(return_value=jarm_hash)):
            findings = await favicon_jarm._fingerprint_one(
                client, sem, "https://example.com:443")

        self.assertEqual(len(findings), 2)
        for f in findings:
            # All 15 canonical keys present.
            for key in CANONICAL_KEYS:
                self.assertIn(key, f)
            # No MISSING/INVALID/FORBIDDEN violations (WARN-only is acceptable).
            violations = validate_finding(f)
            hard = [v for v in violations
                    if v.startswith(("MISSING", "INVALID", "FORBIDDEN"))]
            self.assertEqual(hard, [], f"schema violations: {hard}")


# ── public entry point ───────────────────────────────────────────────────────────

class EntryPointTest(unittest.IsolatedAsyncioTestCase):
    async def test_empty_input_returns_empty(self):
        self.assertEqual(
            await favicon_jarm.fingerprint_favicon_jarm([], "reports"), [])

    async def test_all_deps_missing_returns_empty(self):
        # mmh3 absent AND no jarm → return [] gracefully (never crash).
        with mock.patch.object(favicon_jarm, "_HAVE_MMH3", False), \
             mock.patch.object(favicon_jarm, "jarm_available", return_value=False):
            result = await favicon_jarm.fingerprint_favicon_jarm(
                ["https://example.com"], "reports")
        self.assertEqual(result, [])

    async def test_full_run_with_mocked_httpx_and_jarm(self):
        raw = b"fake-favicon"
        expected_hash = favicon_jarm._shodan_favicon_hash(raw)
        jarm_hash = "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c"

        client = _mock_client(get_return=_mock_response(200, raw))

        with mock.patch.object(favicon_jarm.httpx, "AsyncClient", return_value=client), \
             mock.patch.object(favicon_jarm, "jarm_available", return_value=True), \
             mock.patch.object(favicon_jarm, "_compute_jarm",
                               new=mock.AsyncMock(return_value=jarm_hash)):
            findings = await favicon_jarm.fingerprint_favicon_jarm(
                ["https://a.example.com:443", "https://b.example.com:443",
                 "https://a.example.com:443"],  # duplicate is deduped
                "reports", concurrency=4)

        # 2 unique hosts × (favicon + JARM) = 4 findings.
        self.assertEqual(len(findings), 4)
        favicon_findings = [f for f in findings if "Favicon" in f["vulnerability"]]
        jarm_findings = [f for f in findings if "JARM" in f["vulnerability"]]
        self.assertEqual(len(favicon_findings), 2)
        self.assertEqual(len(jarm_findings), 2)
        self.assertTrue(all(str(expected_hash) in f["details"] for f in favicon_findings))
        self.assertTrue(all(jarm_hash in f["details"] for f in jarm_findings))

    async def test_mmh3_missing_degrades_to_jarm_only(self):
        jarm_hash = "b" * 62
        client = _mock_client(get_return=_mock_response(200, b"favicon"))

        with mock.patch.object(favicon_jarm, "_HAVE_MMH3", False), \
             mock.patch.object(favicon_jarm.httpx, "AsyncClient", return_value=client), \
             mock.patch.object(favicon_jarm, "jarm_available", return_value=True), \
             mock.patch.object(favicon_jarm, "_compute_jarm",
                               new=mock.AsyncMock(return_value=jarm_hash)):
            findings = await favicon_jarm.fingerprint_favicon_jarm(
                ["https://example.com"], "reports")

        # No favicon findings (mmh3 missing), JARM still computed. Never crashes.
        self.assertTrue(all("Favicon" not in f["vulnerability"] for f in findings))
        self.assertEqual(len(findings), 1)
        self.assertIn("JARM", findings[0]["vulnerability"])


if __name__ == "__main__":
    unittest.main()
