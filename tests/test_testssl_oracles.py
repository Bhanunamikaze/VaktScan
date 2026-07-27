"""
Tests for testssl_runner oracle logic:

* nested ``--jsonfile-pretty`` parsing (per-host category arrays) in addition to
  the flat ``--jsonfile`` layout,
* correct vulnerable-vs-safe determination (OK/INFO severities skipped - the
  "not vulnerable" / "not offered" / "PFS is offered (OK)" safe-signals that
  runcommand.py greps for),
* the expanded VULN_MAP id -> title mappings (real testssl ids incl. Obsolete
  CBC, missing PFS, LOGJAM, BEAST, POODLE_SSL, client-initiated renegotiation),
* no bogus "SSL/TLS Issue: None" finding from a host-metadata object.

All subprocess/filesystem interaction is mocked; the suite runs fully offline.
"""

import json
import unittest
from unittest.mock import AsyncMock, patch

from modules import testssl_runner
from modules.testssl_runner import VULN_MAP, _iter_scan_findings
from modules.schema import validate_finding


# ── Real testssl.sh --jsonfile-pretty shape: scanResult = [ host_object ] ───────
NESTED_PRETTY = {
    "Invocation": "testssl --jsonfile-pretty out.json localhost:443",
    "at": "host",
    "version": "3.0.6",
    "scanResult": [
        {
            "targetHost": "localhost",
            "ip": "127.0.0.1/443",
            "port": "443",
            "service": "HTTP",
            "protocols": [
                {"id": "SSLv2", "severity": "OK", "finding": "not offered"},
                {"id": "SSLv3", "severity": "HIGH", "finding": "offered (NOT ok)"},
                {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
                {"id": "TLS1_2", "severity": "OK", "finding": "offered"},
            ],
            "ciphers": [
                {"id": "cipherlist_OBSOLETED", "severity": "LOW", "finding": "offered"},
                {"id": "cipherlist_STRONG_FS", "severity": "OK", "finding": "offered"},
            ],
            "fs": [
                {"id": "FS", "severity": "MEDIUM",
                 "finding": "Not OK: No ciphers supporting Forward Secrecy offered"},
            ],
            "vulnerabilities": [
                {"id": "heartbleed", "severity": "OK", "cve": "CVE-2014-0160",
                 "finding": "not vulnerable, no heartbeat extension"},
                {"id": "ROBOT", "severity": "MEDIUM", "finding": "VULNERABLE (NOT ok)"},
                {"id": "POODLE_SSL", "severity": "HIGH", "cve": "CVE-2014-3566",
                 "finding": "VULNERABLE (NOT ok)"},
                {"id": "BEAST", "severity": "LOW", "cve": "CVE-2011-3389",
                 "finding": "VULNERABLE -- but also supports higher protocols"},
                {"id": "LOGJAM", "severity": "HIGH", "cve": "CVE-2015-4000",
                 "finding": "VULNERABLE, common prime detected"},
                {"id": "SWEET32", "severity": "OK", "finding": "not vulnerable"},
                {"id": "secure_client_renego", "severity": "MEDIUM",
                 "finding": "VULNERABLE (NOT ok)"},
                {"id": "RC4", "severity": "OK", "finding": "no RC4 ciphers detected"},
            ],
            "serverDefaults": [
                {"id": "cert_expirationStatus", "severity": "HIGH", "finding": "expired"},
            ],
        }
    ],
}


def _mock_subprocess_writing(json_data):
    async def _factory(*args, **kwargs):
        temp_path = args[2]  # cmd = [binary, "--jsonfile-pretty", temp_path, ...]
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f)
        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(b"", b""))
        proc.returncode = 0
        return proc
    return _factory


class IterScanFindingsTests(unittest.TestCase):
    def test_flat_toplevel_list(self):
        data = [
            {"id": "SSLv2", "severity": "HIGH", "finding": "offered"},
            {"id": "heartbleed", "severity": "OK", "finding": "not vulnerable"},
            {"noise": True},
        ]
        got = list(_iter_scan_findings(data))
        self.assertEqual([f["id"] for f in got], ["SSLv2", "heartbleed"])

    def test_flat_scanresult_entries(self):
        # Legacy shape the original parser/test rely on: entries ARE findings.
        data = {"scanResult": [
            {"id": "SSLv2", "severity": "HIGH", "finding": "offered"},
            {"id": "cert_trust", "severity": "MEDIUM", "finding": "untrusted"},
        ]}
        got = list(_iter_scan_findings(data))
        self.assertEqual([f["id"] for f in got], ["SSLv2", "cert_trust"])

    def test_nested_pretty_yields_only_category_findings(self):
        got = list(_iter_scan_findings(NESTED_PRETTY))
        # 4 protocols + 2 ciphers + 1 fs + 8 vulns + 1 serverDefaults = 16
        self.assertEqual(len(got), 16)
        # Host metadata object itself must never be yielded as a finding.
        self.assertFalse(any("targetHost" in f for f in got))
        self.assertTrue(all("id" in f and "severity" in f for f in got))


class VulnMapTests(unittest.TestCase):
    def test_real_testssl_ids_have_friendly_titles(self):
        cases = {
            "ROBOT": "SSL/TLS Vulnerability: ROBOT Attack (CVE-2017-13098)",
            "POODLE_SSL": "SSL/TLS Vulnerability: POODLE (CVE-2014-3566)",
            "BEAST": "SSL/TLS Vulnerability: BEAST (CVE-2011-3389)",
            "CRIME_TLS": "SSL/TLS Vulnerability: CRIME (CVE-2012-4929)",
            "cipherlist_OBSOLETED": "Obsolete CBC Cipher Suites Offered",
            "FS": "Missing Forward Secrecy (PFS) Support",
            "secure_client_renego": "Insecure Client-Initiated SSL/TLS Renegotiation Allowed",
            "cert_expirationStatus": "SSL/TLS Certificate Expired or Nearing Expiry",
        }
        for vuln_id, title in cases.items():
            self.assertEqual(VULN_MAP.get(vuln_id), title, vuln_id)

    def test_legacy_lowercase_ids_preserved(self):
        # The existing unit test relies on these exact mappings.
        self.assertEqual(VULN_MAP.get("SSLv2"), "SSLv2 Protocol Support Enabled")
        self.assertEqual(VULN_MAP.get("cert_trust"), "Untrusted SSL/TLS Certificate Chain")


class RunScansNestedTests(unittest.IsolatedAsyncioTestCase):
    async def test_nested_pretty_json_parsed(self):
        with patch("shutil.which", return_value="/usr/bin/testssl"), \
             patch("asyncio.create_subprocess_exec",
                   side_effect=_mock_subprocess_writing(NESTED_PRETTY)):
            findings = await testssl_runner.run_scans(
                {"scan_address": "127.0.0.1", "resolved_ip": "127.0.0.1",
                 "display_target": "localhost"},
                443,
            )

        by_title = {f["vulnerability"]: f for f in findings}

        # Safe (OK) entries must NOT produce findings.
        self.assertNotIn("SSL/TLS Vulnerability: Heartbleed (CVE-2014-0160)", by_title)
        self.assertNotIn("SSL/TLS Vulnerability: SWEET32 (CVE-2016-2183)", by_title)
        self.assertFalse(any(t.startswith("SSL/TLS Vulnerability: Weak RC4") for t in by_title))

        # Never emit a bogus finding from the host-metadata object.
        self.assertNotIn("SSL/TLS Issue: None", by_title)

        # Vulnerable entries must be present with correct titles + severity mapping.
        expected = {
            "SSLv3 Protocol Support Enabled": ("HIGH", "VULNERABLE"),
            "TLSv1.0 Protocol Support Enabled": ("LOW", "POTENTIAL"),
            "Obsolete CBC Cipher Suites Offered": ("LOW", "POTENTIAL"),
            "Missing Forward Secrecy (PFS) Support": ("MEDIUM", "VULNERABLE"),
            "SSL/TLS Vulnerability: ROBOT Attack (CVE-2017-13098)": ("MEDIUM", "VULNERABLE"),
            "SSL/TLS Vulnerability: POODLE (CVE-2014-3566)": ("HIGH", "VULNERABLE"),
            "SSL/TLS Vulnerability: BEAST (CVE-2011-3389)": ("LOW", "POTENTIAL"),
            "SSL/TLS Vulnerability: LOGJAM (CVE-2015-4000)": ("HIGH", "VULNERABLE"),
            "Insecure Client-Initiated SSL/TLS Renegotiation Allowed": ("MEDIUM", "VULNERABLE"),
            "SSL/TLS Certificate Expired or Nearing Expiry": ("HIGH", "VULNERABLE"),
        }
        for title, (sev, status) in expected.items():
            self.assertIn(title, by_title, title)
            self.assertEqual(by_title[title]["severity"], sev, title)
            self.assertEqual(by_title[title]["status"], status, title)

        self.assertEqual(len(findings), len(expected))

        for f in findings:
            self.assertEqual(validate_finding(f), [])

    async def test_all_safe_nested_json_yields_nothing(self):
        safe = {"scanResult": [{
            "targetHost": "localhost", "ip": "127.0.0.1/443", "port": "443",
            "vulnerabilities": [
                {"id": "heartbleed", "severity": "OK", "finding": "not vulnerable"},
                {"id": "ROBOT", "severity": "OK", "finding": "not vulnerable"},
                {"id": "SWEET32", "severity": "OK", "finding": "not vulnerable"},
            ],
            "fs": [{"id": "FS", "severity": "OK", "finding": "PFS is offered (OK)"}],
        }]}
        with patch("shutil.which", return_value="/usr/bin/testssl"), \
             patch("asyncio.create_subprocess_exec",
                   side_effect=_mock_subprocess_writing(safe)):
            findings = await testssl_runner.run_scans(
                {"scan_address": "127.0.0.1", "resolved_ip": "127.0.0.1",
                 "display_target": "localhost"},
                443,
            )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
