"""Tests for modules/horizontal_expand.py.

subprocess for asnmap / dnsx / amass is mocked, so the suite runs with none of
those tools installed.  Coverage:
  * parsing of representative asnmap (JSON + plain), amass intel, and dnsx output
  * the reverse-DNS sweep bounds - the /20 range skip and the total-IP cap
  * graceful empty returns (no seeds / no tools) and canonical-schema findings
"""

import os
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from modules import horizontal_expand as hx
from modules.schema import CANONICAL_KEYS, validate_finding


# --- representative sample tool outputs -------------------------------------
ASNMAP_JSON = (
    '{"input":"example.com","as_number":"AS13335","as_name":"CLOUDFLARENET",'
    '"as_country":"US","as_range":["104.16.0.0/20","104.17.0.0/24"]}\n'
    '{"input":"example.com","as_number":"AS15169","as_name":"GOOGLE",'
    '"as_range":["8.8.8.0/24"]}\n'
)

ASNMAP_SILENT_PLAIN = "104.16.0.0/20\n104.17.0.0/24\n104.16.0.0/20\n"

AMASS_INTEL_OUT = (
    "example.com\n"
    "example.org\n"
    "example-corp.net\n"
    "example.org\n"          # duplicate - must be collapsed
    "\n"
)

DNSX_PTR_OUT = (
    "mail.example.com\n"
    "vpn.example.com\n"
    "192.0.2.5 [gw.example.com]\n"   # IP [host] form
    "203.0.113.9\n"                  # bare IP with no PTR - ignored
    "\n"
)


def _fake_proc(stdout_bytes):
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout_bytes, b""))
    proc.returncode = 0
    return proc


def _which_map(mapping):
    """Return a shutil.which side-effect honoring ``mapping`` (name -> path/None)."""
    def _which(name):
        return mapping.get(name)
    return _which


class ParsingTests(unittest.TestCase):
    def test_parse_asnmap_json_extracts_asns_and_cidrs(self):
        asns, cidrs = hx._parse_asnmap_output(ASNMAP_JSON)
        self.assertEqual(asns, ["AS13335", "AS15169"])
        self.assertEqual(cidrs, ["104.16.0.0/20", "104.17.0.0/24", "8.8.8.0/24"])

    def test_parse_asnmap_plain_silent_cidrs_only(self):
        # -silent output has no ASN column; CIDRs still parse and dedupe.
        asns, cidrs = hx._parse_asnmap_output(ASNMAP_SILENT_PLAIN)
        self.assertEqual(asns, [])
        self.assertEqual(cidrs, ["104.16.0.0/20", "104.17.0.0/24"])

    def test_parse_amass_intel_dedupes_domains(self):
        domains = hx._parse_amass_intel_output(AMASS_INTEL_OUT)
        self.assertEqual(domains, ["example.com", "example.org", "example-corp.net"])

    def test_parse_dnsx_output_extracts_hostnames_and_ignores_ips(self):
        hosts = hx._parse_dnsx_output(DNSX_PTR_OUT)
        self.assertEqual(hosts, ["mail.example.com", "vpn.example.com", "gw.example.com"])

    def test_norm_asn_accepts_multiple_forms(self):
        self.assertEqual(hx._norm_asn("AS13335"), "AS13335")
        self.assertEqual(hx._norm_asn("13335"), "AS13335")
        self.assertEqual(hx._norm_asn("as13335"), "AS13335")
        self.assertIsNone(hx._norm_asn("not-an-asn"))


class BoundsTests(unittest.TestCase):
    def test_skips_ranges_larger_than_slash_20(self):
        # /13 is larger than /20 (prefixlen 13 < 20) -> skipped wholesale.
        # /24 is kept and expands to 254 usable hosts.
        ips, skipped_large, capped = hx._expand_cidrs_to_ips(
            ["10.0.0.0/13", "192.168.1.0/24"]
        )
        self.assertEqual(skipped_large, ["10.0.0.0/13"])
        self.assertEqual(len(ips), 254)
        self.assertFalse(capped)
        self.assertNotIn("10.0.0.0", ips)

    def test_slash_20_is_kept(self):
        # /20 itself is the boundary and must NOT be skipped (4094 usable hosts).
        ips, skipped_large, capped = hx._expand_cidrs_to_ips(["100.64.0.0/20"])
        self.assertEqual(skipped_large, [])
        self.assertEqual(len(ips), 4094)
        self.assertFalse(capped)

    def test_total_ip_cap_is_enforced(self):
        # Three /20 ranges = 3 * 4094 = 12282 hosts, above the 8192 cap.
        ips, skipped_large, capped = hx._expand_cidrs_to_ips(
            ["10.0.0.0/20", "10.1.0.0/20", "10.2.0.0/20"]
        )
        self.assertTrue(capped)
        self.assertEqual(len(ips), hx.DEFAULT_MAX_TOTAL_IPS)
        self.assertEqual(len(ips), 8192)

    def test_ipv6_ranges_are_not_swept(self):
        ips, skipped_large, capped = hx._expand_cidrs_to_ips(["2606:4700::/32"])
        self.assertEqual(ips, [])
        self.assertEqual(skipped_large, ["2606:4700::/32"])
        self.assertFalse(capped)


class EntryPointTests(unittest.IsolatedAsyncioTestCase):
    async def test_empty_seed_domains_returns_empty_shape(self):
        result = await hx.expand_horizontal([], "/tmp/vakt_hx_empty")
        self.assertEqual(
            result,
            {"asns": [], "cidrs": [], "related_domains": [], "reverse_hosts": [], "findings": []},
        )

    async def test_all_tools_missing_returns_empty_shape(self):
        with patch("shutil.which", return_value=None):
            result = await hx.expand_horizontal(["example.com"], "/tmp/vakt_hx_notools")
        self.assertEqual(
            result,
            {"asns": [], "cidrs": [], "related_domains": [], "reverse_hosts": [], "findings": []},
        )

    async def test_asnmap_only_populates_asns_and_cidrs(self):
        tmp = tempfile.mkdtemp(prefix="vakt_hx_asnmap_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        which = _which_map({"asnmap": "/usr/bin/asnmap"})  # dnsx / amass absent

        async def fake_exec(*args, **kwargs):
            return _fake_proc(ASNMAP_JSON.encode())

        with patch("shutil.which", side_effect=which), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await hx.expand_horizontal(["example.com"], tmp)

        self.assertEqual(result["asns"], ["AS13335", "AS15169"])
        self.assertEqual(result["cidrs"], ["8.8.8.0/24", "104.16.0.0/20", "104.17.0.0/24"])
        # No dnsx -> no reverse hosts; no amass -> no related domains.
        self.assertEqual(result["reverse_hosts"], [])
        self.assertEqual(result["related_domains"], [])
        # A single ASN/CIDR summary INFO finding is emitted.
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["status"], "INFO")

    async def test_amass_only_populates_related_domains(self):
        which = _which_map({"amass": "/usr/bin/amass"})

        async def fake_exec(*args, **kwargs):
            return _fake_proc(AMASS_INTEL_OUT.encode())

        with patch("shutil.which", side_effect=which), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await hx.expand_horizontal(["example.com"], "/tmp/vakt_hx_amass")

        self.assertEqual(
            result["related_domains"],
            ["example-corp.net", "example.com", "example.org"],
        )
        self.assertEqual(result["asns"], [])
        self.assertEqual(result["cidrs"], [])

    async def test_reverse_dns_sweep_end_to_end(self):
        # asnmap returns a small /24, so the sweep stays in-bounds and dnsx runs.
        which = _which_map({"asnmap": "/usr/bin/asnmap", "dnsx": "/usr/bin/dnsx"})

        async def fake_exec(*args, **kwargs):
            program = args[0]
            if program.endswith("asnmap"):
                return _fake_proc(b'{"as_number":"AS64500","as_range":["192.0.2.0/24"]}\n')
            if program.endswith("dnsx"):
                return _fake_proc(DNSX_PTR_OUT.encode())
            return _fake_proc(b"")

        with patch("shutil.which", side_effect=which), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await hx.expand_horizontal(["example.com"], "/tmp/vakt_hx_ptr")

        self.assertEqual(result["cidrs"], ["192.0.2.0/24"])
        self.assertEqual(
            result["reverse_hosts"],
            ["gw.example.com", "mail.example.com", "vpn.example.com"],
        )

    async def test_large_range_is_not_swept_even_when_dnsx_present(self):
        # asnmap returns a /12 (larger than /20). dnsx is present but the range
        # must be skipped by the bound, so no reverse hosts appear and dnsx is
        # never actually invoked with any IPs.
        which = _which_map({"asnmap": "/usr/bin/asnmap", "dnsx": "/usr/bin/dnsx"})
        dnsx_calls = []

        async def fake_exec(*args, **kwargs):
            program = args[0]
            if program.endswith("asnmap"):
                return _fake_proc(b"10.0.0.0/12\n")
            if program.endswith("dnsx"):
                dnsx_calls.append(args)
                return _fake_proc(DNSX_PTR_OUT.encode())
            return _fake_proc(b"")

        with patch("shutil.which", side_effect=which), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await hx.expand_horizontal(["example.com"], "/tmp/vakt_hx_large")

        self.assertEqual(result["cidrs"], ["10.0.0.0/12"])
        self.assertEqual(result["reverse_hosts"], [])
        self.assertEqual(dnsx_calls, [], "dnsx must not be invoked for an out-of-bounds range")

    async def test_findings_conform_to_canonical_schema(self):
        which = _which_map({
            "asnmap": "/usr/bin/asnmap",
            "dnsx": "/usr/bin/dnsx",
            "amass": "/usr/bin/amass",
        })

        async def fake_exec(*args, **kwargs):
            program = args[0]
            if program.endswith("asnmap"):
                return _fake_proc(ASNMAP_JSON.encode())
            if program.endswith("dnsx"):
                return _fake_proc(DNSX_PTR_OUT.encode())
            if program.endswith("amass"):
                return _fake_proc(AMASS_INTEL_OUT.encode())
            return _fake_proc(b"")

        tmp = tempfile.mkdtemp(prefix="vakt_hx_schema_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        with patch("shutil.which", side_effect=which), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await hx.expand_horizontal(["example.com"], tmp)

        # All three summary findings present.
        self.assertEqual(len(result["findings"]), 3)
        for finding in result["findings"]:
            self.assertEqual(sorted(finding.keys()), sorted(CANONICAL_KEYS))
            self.assertEqual(validate_finding(finding), [], f"schema violations: {finding}")
            self.assertEqual(finding["status"], "INFO")
            self.assertEqual(finding["severity"], "INFO")
            self.assertEqual(finding["module"], "horizontal_expand")

        # Artifacts were written to <output_dir>/horizontal_expand/.
        art_dir = os.path.join(tmp, "horizontal_expand")
        for name in ("asns.txt", "cidrs.txt", "related_domains.txt", "reverse_hosts.txt"):
            self.assertTrue(os.path.exists(os.path.join(art_dir, name)))

    async def test_asn_seed_is_routed_through_dash_a(self):
        captured = {}
        which = _which_map({"asnmap": "/usr/bin/asnmap"})

        async def fake_exec(*args, **kwargs):
            captured["cmd"] = list(args)
            return _fake_proc(ASNMAP_JSON.encode())

        with patch("shutil.which", side_effect=which), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            await hx.expand_horizontal(["AS13335"], "/tmp/vakt_hx_asn")

        self.assertIn("-a", captured["cmd"])
        self.assertIn("AS13335", captured["cmd"])
        self.assertNotIn("-d", captured["cmd"])


if __name__ == "__main__":
    unittest.main()
