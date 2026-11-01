import unittest
from unittest.mock import AsyncMock, patch
import json
import os
import shutil

from modules import testssl_runner
from modules.schema import validate_finding

class TestSSLRunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_scans_binary_missing(self):
        # Verify that run_scans returns an empty list if testssl binary is not found
        with patch("shutil.which", return_value=None):
            findings = await testssl_runner.run_scans(
                {"scan_address": "127.0.0.1", "resolved_ip": "127.0.0.1", "display_target": "localhost"},
                443
            )
            self.assertEqual(findings, [])

    async def test_run_scans_parses_json_results(self):
        # Mock JSON data representing testssl.sh pretty-json output
        mock_json_data = {
            "scanResult": [
                {
                    "id": "SSLv2",
                    "ip": "127.0.0.1/443",
                    "port": "443",
                    "severity": "HIGH",
                    "finding": "offered"
                },
                {
                    "id": "heartbleed",
                    "ip": "127.0.0.1/443",
                    "port": "443",
                    "severity": "CRITICAL",
                    "finding": "vulnerable"
                },
                {
                    "id": "cert_trust",
                    "ip": "127.0.0.1/443",
                    "port": "443",
                    "severity": "MEDIUM",
                    "finding": "untrusted"
                },
                {
                    "id": "HSTS",
                    "ip": "127.0.0.1/443",
                    "port": "443",
                    "severity": "WARN",
                    "finding": "not offered"
                },
                {
                    "id": "some_unknown_id",
                    "ip": "127.0.0.1/443",
                    "port": "443",
                    "severity": "LOW",
                    "finding": "unknown finding"
                },
                {
                    "id": "overall_grade",
                    "ip": "127.0.0.1/443",
                    "port": "443",
                    "severity": "CRITICAL",
                    "finding": "M"
                },
                {
                    "id": "cipher-tls1_2_xc027",
                    "ip": "127.0.0.1/443",
                    "port": "443",
                    "severity": "LOW",
                    "finding": "TLSv1.2 xc027 ECDHE-RSA-AES128-SHA256"
                },
                {
                    "id": "SSLv3",
                    "ip": "127.0.0.1/443",
                    "port": "443",
                    "severity": "OK",
                    "finding": "not offered"
                },
                {
                    "id": "TLS1_2",
                    "ip": "127.0.0.1/443",
                    "port": "443",
                    "severity": "INFO",
                    "finding": "offered"
                }
            ]
        }

        async def mock_create_subprocess_exec(*args, **kwargs):
            # args[2] is the temp_path since cmd is:
            # [binary, "--jsonfile-pretty", temp_path, ...]
            temp_path = args[2]
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(mock_json_data, f)
            
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"stdout", b"stderr"))
            mock_proc.returncode = 0
            return mock_proc

        with patch("shutil.which", return_value="/usr/bin/testssl"), \
             patch("asyncio.create_subprocess_exec", side_effect=mock_create_subprocess_exec):
            
            findings = await testssl_runner.run_scans(
                {"scan_address": "127.0.0.1", "resolved_ip": "127.0.0.1", "display_target": "localhost"},
                443
            )

            # We expect 3 findings: SSLv2, heartbleed, HSTS.
            #   - OK (SSLv3) and INFO (TLS1_2) are safe-signals, filtered out.
            #   - some_unknown_id is LOW and unmapped -> dropped (informational
            #     long tail, not a real issue).
            #   - overall_grade is a letter-grade summary -> always dropped, even
            #     though testssl labels it CRITICAL.
            #   - cipher-tls1_2_xc027 is a per-cipher enumeration line -> dropped.
            #   - cert_trust is an IP-pinned-scan artifact (SNI mismatch) -> dropped.
            by_title = {f["vulnerability"]: f for f in findings}
            self.assertEqual(len(findings), 3)

            # Mapped real issues are present with correct severity/status.
            self.assertEqual(by_title["SSLv2 Protocol Support Enabled"]["severity"], "HIGH")
            self.assertEqual(by_title["SSLv2 Protocol Support Enabled"]["status"], "VULNERABLE")
            self.assertEqual(by_title["SSLv2 Protocol Support Enabled"]["port"], "443")

            self.assertEqual(
                by_title["SSL/TLS Vulnerability: Heartbleed (CVE-2014-0160)"]["severity"], "CRITICAL")
            self.assertEqual(
                by_title["SSL/TLS Vulnerability: Heartbleed (CVE-2014-0160)"]["status"], "CRITICAL")

            self.assertEqual(
                by_title["Missing or Misconfigured Strict-Transport-Security (HSTS) Header"]["severity"], "LOW")

            # Noise ids must NOT appear in any form.
            self.assertNotIn("SSL/TLS Issue: some_unknown_id", by_title)
            self.assertNotIn("SSL/TLS Issue: overall_grade", by_title)
            self.assertNotIn("Untrusted SSL/TLS Certificate Chain", by_title)
            self.assertFalse(any("cipher-tls" in t for t in by_title))
            self.assertFalse(any(f["severity"] == "CRITICAL" and "Heartbleed" not in f["vulnerability"]
                                 for f in findings))

            # Verify that all findings comply with the canonical schema keys
            for f in findings:
                violations = validate_finding(f)
                self.assertEqual(violations, [], f"Schema violations found: {violations}")

    async def test_noise_filtering_normalisation_and_dedup(self):
        # Reproduces the real-world flood: per-cipher dumps, the letter-grade
        # summary, informational serverDefaults, and real certificate findings
        # emitted once per leaf certificate with a <hostCert#N> suffix.
        mock_json_data = {
            "scanResult": [{
                "targetHost": "example.com", "ip": "127.0.0.1/443", "port": "443",
                "ciphers": [
                    {"id": "cipher-tls1_2_xc027", "severity": "LOW", "finding": "ECDHE-RSA-AES128-SHA256"},
                    {"id": "cipher-tls1_2_xc028", "severity": "LOW", "finding": "ECDHE-RSA-AES256-SHA384"},
                    {"id": "cipherlist_OBSOLETED", "severity": "LOW", "finding": "offered"},
                ],
                "serverDefaults": [
                    # IP-pinned-scan cert-trust artifacts -> always dropped.
                    {"id": "cert_chain_of_trust <hostCert#1>", "severity": "CRITICAL", "finding": "failed (self signed)."},
                    {"id": "cert_chain_of_trust <hostCert#2>", "severity": "CRITICAL", "finding": "failed (self signed)."},
                    {"id": "cert_trust <hostCert#1>", "severity": "HIGH", "finding": "does not match URI"},
                    # Real cert issue, one entry per leaf cert -> normalise + dedup.
                    {"id": "cert_expirationStatus <hostCert#1>", "severity": "MEDIUM", "finding": "expires < 60 days (56)"},
                    {"id": "cert_notAfter <hostCert#1>", "severity": "MEDIUM", "finding": "2026-12-28"},
                    {"id": "OCSP_stapling", "severity": "LOW", "finding": "not offered"},
                    {"id": "security_headers", "severity": "MEDIUM", "finding": "--"},
                ],
                "misc": [
                    {"id": "overall_grade", "severity": "CRITICAL", "finding": "M"},
                    {"id": "optimal_proto", "severity": "WARN", "finding": "doesn't seem to be a TLS/SSL enabled server"},
                    # Unknown id, but HIGH -> kept by the safety net.
                    {"id": "brand_new_vuln", "severity": "HIGH", "finding": "VULNERABLE"},
                ],
            }]
        }

        async def mock_create_subprocess_exec(*args, **kwargs):
            with open(args[2], "w", encoding="utf-8") as f:
                json.dump(mock_json_data, f)
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_proc.returncode = 0
            return mock_proc

        with patch("shutil.which", return_value="/usr/bin/testssl"), \
             patch("asyncio.create_subprocess_exec", side_effect=mock_create_subprocess_exec):
            findings = await testssl_runner.run_scans(
                {"scan_address": "example.com", "resolved_ip": "127.0.0.1", "display_target": "example.com"},
                443,
            )

        titles = [f["vulnerability"] for f in findings]
        pairs = sorted((f["vulnerability"], f["severity"]) for f in findings)

        # Kept, after <hostCert#N> normalisation + per-host dedup:
        #   - obsolete CBC (mapped LOW)
        #   - cert_expirationStatus MEDIUM
        #   - the unknown HIGH vuln via the safety net
        # Dropped: cert_chain_of_trust (CRITICAL) and cert_trust (HIGH) are
        # IP-pinned-scan artifacts, not real weaknesses.
        self.assertEqual(pairs, sorted([
            ("Obsolete CBC Cipher Suites Offered", "LOW"),
            ("SSL/TLS Certificate Expired or Nearing Expiry", "MEDIUM"),
            ("SSL/TLS Issue: brand_new_vuln", "HIGH"),
        ]))

        # cert trust/chain artifacts are suppressed regardless of severity.
        self.assertFalse(any(f["severity"] == "CRITICAL" for f in findings))
        self.assertNotIn("Untrusted SSL/TLS Certificate Chain", titles)

        # No per-cipher dumps, grades, or informational lines leaked through.
        self.assertFalse(any("cipher-tls" in t for t in titles))
        self.assertNotIn("SSL/TLS Issue: overall_grade", titles)
        self.assertNotIn("SSL/TLS Issue: optimal_proto", titles)
        self.assertNotIn("SSL/TLS Issue: security_headers", titles)
        self.assertNotIn("SSL/TLS Issue: OCSP_stapling", titles)
        self.assertNotIn("SSL/TLS Issue: cert_notAfter", titles)
        # The <hostCert#N> suffix never survives into a title.
        self.assertFalse(any("<hostCert" in t for t in titles))

        for f in findings:
            self.assertEqual(validate_finding(f), [])


if __name__ == "__main__":
    unittest.main()
