"""
Tests for the weak SSH MAC detection added to service_recon.check_ssh
(nmap --script ssh2-enum-algos, oracle: hmac-md5 / hmac-sha1 in mac_algorithms).

Subprocess + socket interaction is mocked; the suite runs fully offline.
"""

import unittest
from unittest.mock import AsyncMock, patch

from modules import service_recon
from modules.schema import validate_finding


NMAP_WEAK = """\
Starting Nmap
PORT   STATE SERVICE
22/tcp open  ssh
| ssh2-enum-algos:
|   kex_algorithms: (2)
|       curve25519-sha256
|       diffie-hellman-group14-sha1
|   server_host_key_algorithms: (1)
|       ssh-rsa
|   encryption_algorithms: (1)
|       aes128-ctr
|   mac_algorithms: (6)
|       hmac-sha2-256
|       hmac-sha2-512
|       hmac-sha1
|       hmac-sha1-etm@openssh.com
|       hmac-md5
|       umac-64@openssh.com
|_  compression_algorithms: (1)
|       none
"""

NMAP_SAFE = """\
Starting Nmap
PORT   STATE SERVICE
22/tcp open  ssh
| ssh2-enum-algos:
|   mac_algorithms: (3)
|       hmac-sha2-256
|       hmac-sha2-512
|       umac-128-etm@openssh.com
|_  compression_algorithms: (1)
|       none
"""


def _bin_only(name_present):
    return lambda n: f"/usr/bin/{n}" if n == name_present else None


class SSHWeakMacTests(unittest.IsolatedAsyncioTestCase):
    async def test_weak_macs_flagged(self):
        with patch.object(service_recon, "_bin", side_effect=_bin_only("nmap")), \
             patch.object(service_recon, "_run",
                          new=AsyncMock(return_value=(NMAP_WEAK, "", 0))), \
             patch.object(service_recon.asyncio, "open_connection",
                          new=AsyncMock(side_effect=OSError)):
            findings = await service_recon.check_ssh("h", 22, "target", "1.2.3.4")

        mac = [f for f in findings
               if f["vulnerability"] == "SSH Weak MAC Algorithms Supported"]
        self.assertEqual(len(mac), 1)
        details = mac[0]["details"].lower()
        self.assertIn("hmac-md5", details)
        self.assertIn("hmac-sha1", details)
        # diffie-hellman-group14-sha1 must NOT be misread as an hmac.
        self.assertNotIn("group14", details)
        self.assertEqual(mac[0]["severity"], "MEDIUM")
        self.assertEqual(mac[0]["status"], "VULNERABLE")
        self.assertEqual(validate_finding(mac[0]), [])

    async def test_strong_macs_not_flagged(self):
        with patch.object(service_recon, "_bin", side_effect=_bin_only("nmap")), \
             patch.object(service_recon, "_run",
                          new=AsyncMock(return_value=(NMAP_SAFE, "", 0))), \
             patch.object(service_recon.asyncio, "open_connection",
                          new=AsyncMock(side_effect=OSError)):
            findings = await service_recon.check_ssh("h", 22, "target", "1.2.3.4")

        self.assertFalse(any(
            f["vulnerability"] == "SSH Weak MAC Algorithms Supported" for f in findings))

    async def test_nmap_absent_skips_gracefully(self):
        # No external binaries at all -> no crash, no MAC finding.
        with patch.object(service_recon, "_bin", return_value=None), \
             patch.object(service_recon.asyncio, "open_connection",
                          new=AsyncMock(side_effect=OSError)):
            findings = await service_recon.check_ssh("h", 22, "target", "1.2.3.4")

        self.assertFalse(any(
            f["vulnerability"] == "SSH Weak MAC Algorithms Supported" for f in findings))


if __name__ == "__main__":
    unittest.main()
