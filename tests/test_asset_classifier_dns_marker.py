"""Tests for the DNS-marker signal in modules/asset_classifier.py.

All DNS resolution is mocked (A / CNAME / PTR) - no network. Validates that a
host whose CNAME target or reverse-DNS (PTR) hostname matches a shared-hosting
marker is classified as a CUSTOMER site, that this complements (does not replace)
the shared-IP rule, and that the functional-name rescue still wins.

Uses steinzsecurity.com as the example apex throughout.
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules import asset_classifier, dns_recon  # noqa: E402

APEX = "steinzsecurity.com"


def _fake_query(a_map=None, cname_map=None, ptr_map=None):
    """Build a fake ``dns_recon._query`` covering A, CNAME and PTR lookups.

      * A/CNAME: keyed by host name -> ip (a_map) and host name -> cname (cname_map).
      * PTR: an ``*.in-addr.arpa`` query is mapped back to its IP and looked up in
        ptr_map -> PTR hostname.
    """
    a_map = a_map or {}
    cname_map = cname_map or {}
    ptr_map = ptr_map or {}

    async def fake(server, name, qtype, **kw):
        n = name.rstrip(".")
        if n.endswith(".in-addr.arpa"):
            octets = n[: -len(".in-addr.arpa")].split(".")
            ip = ".".join(reversed(octets))
            host = ptr_map.get(ip)
            if host:
                return {"rcode": 0, "answers": [{"type": asset_classifier.RR_PTR, "data": host}]}
            return {"rcode": 0, "answers": []}
        answers = []
        cn = cname_map.get(n)
        if cn:
            answers.append({"type": dns_recon.RR_CNAME, "data": cn})
        ip = a_map.get(n)
        if ip:
            answers.append({"type": dns_recon.RR_A, "data": ip})
        return {"rcode": 0, "answers": answers}

    return fake


async def _classify(hosts, a_map=None, cname_map=None, ptr_map=None,
                    threshold=10, extra_markers=None, output_dir=None):
    fake = _fake_query(a_map, cname_map, ptr_map)
    with mock.patch("modules.dns_recon._query", side_effect=fake):
        return await asset_classifier.classify_by_shared_ip(
            hosts, APEX, output_dir,
            shared_ip_threshold=threshold, extra_markers=extra_markers)


class DnsMarkerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="vakt_marker_")

    async def test_ptr_marker_on_distinct_ip_is_customer(self):
        # A single host on its own IP (below the shared-IP threshold) whose PTR
        # matches a default marker -> CUSTOMER via the DNS-marker signal.
        host = "clientsite.steinzsecurity.com"
        res = await _classify(
            [host],
            a_map={host: "203.0.113.10"},
            ptr_map={"203.0.113.10": "box512.unifiedlayer.com"},
            threshold=10, output_dir=self.dir)
        self.assertIn(host, res["customer"])
        self.assertNotIn(host, res["company"])
        self.assertEqual(res["shared_ips"], [])          # not caught by shared IP
        # summary finding notes the marker split
        self.assertEqual(len(res["findings"]), 1)
        self.assertIn("via DNS marker", res["findings"][0]["details"])

    async def test_functional_child_rescued_from_marker_and_shared_ip(self):
        # beta.<apex> matches a marker on a distinct IP; www.<apex> sits on a
        # shared IP with 10 customers. Both functional children stay COMPANY.
        customers = [f"c{i}.steinzsecurity.com" for i in range(10)]
        beta = "beta.steinzsecurity.com"
        www = "www.steinzsecurity.com"
        a_map = {beta: "203.0.113.20", www: "203.0.113.30"}
        for c in customers:
            a_map[c] = "203.0.113.30"                    # shared IP (11 hosts w/ www)
        ptr_map = {
            "203.0.113.20": "srv.hostgator.com",         # marker for beta
            "203.0.113.30": "shared.bluehost.com",       # marker + shared
        }
        res = await _classify([beta, www] + customers, a_map=a_map, ptr_map=ptr_map,
                              threshold=10, output_dir=self.dir)
        # functional children rescued despite marker (beta) and shared IP (www)
        self.assertIn(beta, res["company"])
        self.assertIn(www, res["company"])
        # the 10 customers on the shared IP are customer sites
        self.assertEqual(sorted(res["customer"]), sorted(customers))
        self.assertEqual(res["shared_ips"], ["203.0.113.30"])

    async def test_no_marker_distinct_ip_is_company(self):
        host = "host1.steinzsecurity.com"
        res = await _classify(
            [host],
            a_map={host: "203.0.113.40"},
            ptr_map={"203.0.113.40": "no-match-here.example.net"},
            threshold=10)
        self.assertIn(host, res["company"])
        self.assertEqual(res["customer"], [])

    async def test_extra_marker_string_matches_is_customer(self):
        host = "widget.steinzsecurity.com"
        a_map = {host: "203.0.113.50"}
        ptr_map = {"203.0.113.50": "node7.acmehosting.net"}   # not a default marker
        # Without the extra marker -> company.
        base = await _classify([host], a_map=a_map, ptr_map=ptr_map, threshold=10)
        self.assertIn(host, base["company"])
        # With a user-supplied marker -> customer.
        res = await _classify([host], a_map=a_map, ptr_map=ptr_map, threshold=10,
                              extra_markers=["AcmeHosting"])   # mixed-case -> lowercased
        self.assertIn(host, res["customer"])
        self.assertNotIn(host, res["company"])

    async def test_cname_marker_match_is_customer(self):
        # The CNAME target carries the marker; the PTR does NOT -> still CUSTOMER.
        host = "acmeclient.steinzsecurity.com"
        res = await _classify(
            [host],
            a_map={host: "203.0.113.60"},
            cname_map={host: "acmeclient.websitewelcome.com"},   # marker via CNAME
            ptr_map={"203.0.113.60": "plain.example.net"},       # no marker via PTR
            threshold=10)
        self.assertIn(host, res["customer"])
        self.assertNotIn(host, res["company"])

    async def test_resolution_error_fails_open_keeps_host(self):
        # A resolver blow-up must not drop the host: it stays COMPANY (fail-open).
        def boom(*a, **k):
            raise RuntimeError("dns exploded")
        hosts = ["a.steinzsecurity.com", "b.steinzsecurity.com"]
        with mock.patch("modules.dns_recon._query", side_effect=boom):
            res = await asset_classifier.classify_by_shared_ip(
                hosts, APEX, shared_ip_threshold=2, extra_markers=["unifiedlayer"])
        self.assertEqual(res["customer"], [])
        self.assertEqual(sorted(res["company"]), sorted(hosts))


if __name__ == "__main__":
    unittest.main()
