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

            # We expect 5 findings: SSLv2, heartbleed, cert_trust, HSTS, some_unknown_id.
            # OK (SSLv3) and INFO (TLS1_2) should be filtered out.
            self.assertEqual(len(findings), 5)

            # Verify finding 1: SSLv2 (HIGH / VULNERABLE)
            self.assertEqual(findings[0]["vulnerability"], "SSLv2 Protocol Support Enabled")
            self.assertEqual(findings[0]["severity"], "HIGH")
            self.assertEqual(findings[0]["status"], "VULNERABLE")
            self.assertEqual(findings[0]["port"], "443")

            # Verify finding 2: heartbleed (CRITICAL / CRITICAL)
            self.assertEqual(findings[1]["vulnerability"], "SSL/TLS Vulnerability: Heartbleed (CVE-2014-0160)")
            self.assertEqual(findings[1]["severity"], "CRITICAL")
            self.assertEqual(findings[1]["status"], "CRITICAL")

            # Verify finding 3: cert_trust (MEDIUM / VULNERABLE)
            self.assertEqual(findings[2]["vulnerability"], "Untrusted SSL/TLS Certificate Chain")
            self.assertEqual(findings[2]["severity"], "MEDIUM")
            self.assertEqual(findings[2]["status"], "VULNERABLE")

            # Verify finding 4: HSTS (LOW / POTENTIAL - mapped from WARN)
            self.assertEqual(findings[3]["vulnerability"], "Missing or Misconfigured Strict-Transport-Security (HSTS) Header")
            self.assertEqual(findings[3]["severity"], "LOW")
            self.assertEqual(findings[3]["status"], "POTENTIAL")

            # Verify finding 5: unknown id fallback
            self.assertEqual(findings[4]["vulnerability"], "SSL/TLS Issue: some_unknown_id")
            self.assertEqual(findings[4]["severity"], "LOW")
            self.assertEqual(findings[4]["status"], "POTENTIAL")

            # Verify that all 5 findings comply with the canonical schema keys
            for f in findings:
                violations = validate_finding(f)
                self.assertEqual(violations, [], f"Schema violations found: {violations}")

if __name__ == "__main__":
    unittest.main()
