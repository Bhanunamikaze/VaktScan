"""Tests for modules/asset_classifier.py (shared-hosting customer/company split).

All DNS resolution is mocked - no network. Validates the core behavior that made
the theory hold on homestead.com: hosts crowding one shared IP are customers,
distinct-IP and functional-named hosts are company assets.
"""

import asyncio
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules import asset_classifier, dns_recon  # noqa: E402


def _fake_query_for(ip_map):
    async def fake(server, name, qtype, **kw):
        ip = ip_map.get(name.rstrip("."))
        if ip:
            return {"rcode": 0, "answers": [{"type": dns_recon.RR_A, "data": ip}]}
        return {"rcode": 0, "answers": []}   # no A record
    return fake


class ApexChildTests(unittest.TestCase):
    def test_direct_child_label(self):
        self.assertEqual(asset_classifier._apex_child_label("mail.homestead.com", "homestead.com"), "mail")
        # not a direct child (two labels before apex)
        self.assertIsNone(asset_classifier._apex_child_label("www.cust.homestead.com", "homestead.com"))
        # not under the apex
        self.assertIsNone(asset_classifier._apex_child_label("mail.other.com", "homestead.com"))

    def test_is_functional(self):
        self.assertTrue(asset_classifier._is_functional("www.homestead.com", "homestead.com"))
        self.assertTrue(asset_classifier._is_functional("api.homestead.com", "homestead.com"))
        self.assertFalse(asset_classifier._is_functional("randomcustomer.homestead.com", "homestead.com"))
        # www.<customer> must NOT be treated as functional (it's a customer site)
        self.assertFalse(asset_classifier._is_functional("www.randomcustomer.homestead.com", "homestead.com"))


class ClassifyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="vakt_cls_")

    def _make(self, n_customers=12):
        apex = "example.com"
        ip_map = {}
        customers = [f"cust{i}.example.com" for i in range(n_customers)]
        for c in customers:
            ip_map[c] = "1.1.1.1"                    # all on the shared IP
        ip_map["www.example.com"] = "1.1.1.1"        # functional, but on shared IP
        ip_map["blog.example.com"] = "1.1.1.1"       # functional, on shared IP
        ip_map["mail.example.com"] = "2.2.2.2"       # distinct IP -> company
        # 'gone.example.com' intentionally absent -> does not resolve -> company
        hosts = customers + ["www.example.com", "blog.example.com",
                             "mail.example.com", "gone.example.com"]
        return apex, hosts, ip_map, customers

    async def test_shared_ip_hosts_are_customers_functional_rescued(self):
        apex, hosts, ip_map, customers = self._make()
        with mock.patch("modules.dns_recon._query", side_effect=_fake_query_for(ip_map)):
            res = await asset_classifier.classify_by_shared_ip(
                hosts, apex, self.dir, shared_ip_threshold=10)

        self.assertEqual(sorted(res["customer"]), sorted(customers))
        # functional names on the shared IP + distinct-IP + non-resolving are company.
        for h in ("www.example.com", "blog.example.com", "mail.example.com", "gone.example.com"):
            self.assertIn(h, res["company"])
        self.assertEqual(res["shared_ips"], ["1.1.1.1"])
        # transparency files written
        self.assertTrue(os.path.exists(os.path.join(self.dir, "customer_sites.txt")))
        self.assertTrue(os.path.exists(os.path.join(self.dir, "company_assets.txt")))
        # a single INFO summary finding
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["severity"], "INFO")

    async def test_threshold_above_cluster_keeps_everything(self):
        apex, hosts, ip_map, _ = self._make(n_customers=12)   # 14 hosts on 1.1.1.1
        with mock.patch("modules.dns_recon._query", side_effect=_fake_query_for(ip_map)):
            res = await asset_classifier.classify_by_shared_ip(
                hosts, apex, self.dir, shared_ip_threshold=50)   # nothing reaches 50
        self.assertEqual(res["customer"], [])
        self.assertEqual(sorted(res["company"]), sorted(hosts))
        self.assertEqual(res["shared_ips"], [])

    async def test_empty_input(self):
        res = await asset_classifier.classify_by_shared_ip([], "example.com")
        self.assertEqual(res["company"], [])
        self.assertEqual(res["customer"], [])

    async def test_fail_open_on_error(self):
        # If resolution blows up, scan everything (never silently drop targets).
        def boom(*a, **k):
            raise RuntimeError("dns exploded")
        with mock.patch("modules.dns_recon._query", side_effect=boom):
            res = await asset_classifier.classify_by_shared_ip(
                ["a.example.com", "b.example.com"], "example.com", shared_ip_threshold=1)
        # every host resolves to None -> no shared IPs -> all company (fail-open).
        self.assertEqual(res["customer"], [])
        self.assertEqual(sorted(res["company"]), ["a.example.com", "b.example.com"])


if __name__ == "__main__":
    unittest.main()
