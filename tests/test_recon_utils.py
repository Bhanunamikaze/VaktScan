import unittest
from unittest.mock import patch

import utils


class ReconUtilsTests(unittest.IsolatedAsyncioTestCase):
    async def test_resolve_hostnames_returns_bidirectional_mappings(self):
        async def fake_resolve(hostname):
            mapping = {
                "a.example.com": "203.0.113.10",
                "b.example.com": "203.0.113.10",
                "c.example.com": "203.0.113.11",
            }
            return mapping.get(hostname)

        with patch("utils.resolve_hostname", side_effect=fake_resolve):
            host_to_ip, ip_to_hosts, unresolved = await utils.resolve_hostnames(
                ["a.example.com", "b.example.com", "c.example.com", "missing.example.com"]
            )

        self.assertEqual(host_to_ip["a.example.com"], "203.0.113.10")
        self.assertEqual(host_to_ip["b.example.com"], "203.0.113.10")
        self.assertEqual(ip_to_hosts["203.0.113.10"], ["a.example.com", "b.example.com"])
        self.assertEqual(ip_to_hosts["203.0.113.11"], ["c.example.com"])
        self.assertEqual(unresolved, ["missing.example.com"])

    def test_build_recon_probe_urls_expands_shared_ip_hosts(self):
        port_scan_results = [
            (
                {
                    "scan_address": "a.example.com",
                    "display_target": "a.example.com",
                    "resolved_ip": "203.0.113.10",
                },
                {"open_ports": [80, 8080]},
            )
        ]
        ip_to_hosts = {"203.0.113.10": ["a.example.com", "b.example.com"]}

        probe_urls = set(
            utils.build_recon_probe_urls(
                ["a.example.com", "b.example.com"],
                port_scan_results,
                ip_to_hosts,
            )
        )

        self.assertIn("http://a.example.com", probe_urls)
        self.assertIn("https://b.example.com", probe_urls)
        self.assertIn("http://b.example.com:8080", probe_urls)
        self.assertIn("https://203.0.113.10:8080", probe_urls)

    def test_build_scan_targets_from_mappings_keeps_hostname_to_ip_context(self):
        targets = utils.build_scan_targets_from_mappings(
            ["a.example.com", "b.example.com", "203.0.113.11"],
            {
                "a.example.com": "203.0.113.10",
                "b.example.com": "203.0.113.10",
            },
        )

        self.assertEqual(
            targets,
            [
                {
                    "scan_address": "a.example.com",
                    "display_target": "a.example.com",
                    "resolved_ip": "203.0.113.10",
                },
                {
                    "scan_address": "203.0.113.10",
                    "display_target": "a.example.com",
                    "resolved_ip": "203.0.113.10",
                },
                {
                    "scan_address": "203.0.113.11",
                    "display_target": "203.0.113.11",
                    "resolved_ip": "203.0.113.11",
                },
            ],
        )


if __name__ == "__main__":
    unittest.main()
