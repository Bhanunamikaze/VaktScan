"""Tests for modules/dns_resolve.py.

subprocess for puredns / massdns / alterx / dnsgen is mocked, so the suite runs
with none of those tools installed.  Coverage:
  * pure parsers (puredns/fallback stdout, massdns simple output)
  * wildcard-filter parsing (puredns diff + massdns catch-all IP filter)
  * the permutation candidate cap and de-duplication
  * dedup of the merged resolved/permutation sets
  * graceful empty return, the no-tools built-in-resolver fallback, and
    canonical-schema findings
"""

import os
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from modules import dns_resolve as dr
from modules.schema import CANONICAL_KEYS, validate_finding


# --- representative sample tool outputs -------------------------------------
PUREDNS_RESOLVED_OUT = (
    "www.example.com\n"
    "api.example.com\n"
    "MAIL.example.com\n"      # mixed case — must normalize
    "www.example.com\n"       # duplicate — must collapse
    "\n"
)

MASSDNS_SIMPLE_OUT = (
    "www.example.com. A 93.184.216.34\n"
    "api.example.com. A 93.184.216.34\n"
    "junk.example.com. A 10.10.10.10\n"     # only the wildcard IP -> filtered
    "cname.example.com. CNAME edge.example.net.\n"   # no A -> kept
)

ALTERX_OUT = (
    "api-dev.example.com\n"
    "api-staging.example.com\n"
    "www.example.com\n"        # already-known host — dedup vs resolved
    "\n"
)

DNSGEN_OUT = (
    "api-prod.example.com\n"
    "api-dev.example.com\n"    # duplicate across generators
)


def _fake_proc(stdout_bytes):
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout_bytes, b""))
    proc.returncode = 0
    return proc


def _which_map(mapping):
    """shutil.which side-effect honoring ``mapping`` (name -> path/None)."""
    def _which(name):
        return mapping.get(name)
    return _which


# --- pure parsing / helper tests --------------------------------------------
class ParsingTests(unittest.TestCase):
    def test_parse_resolved_lines_normalizes_and_dedupes(self):
        hosts = dr._parse_resolved_lines(PUREDNS_RESOLVED_OUT)
        self.assertEqual(hosts, ["www.example.com", "api.example.com", "mail.example.com"])

    def test_parse_massdns_simple_builds_ip_map(self):
        resolved = dr._parse_massdns_simple(MASSDNS_SIMPLE_OUT)
        self.assertEqual(resolved["www.example.com"], {"93.184.216.34"})
        self.assertEqual(resolved["junk.example.com"], {"10.10.10.10"})
        # CNAME-only host is present but carries no address.
        self.assertEqual(resolved["cname.example.com"], set())

    def test_clean_hosts_drops_non_domain_shaped(self):
        cleaned = dr._clean_hosts(["good.example.com", "not a host", "", "UP.example.com"])
        self.assertEqual(cleaned, ["good.example.com", "up.example.com"])

    def test_apex_of_prefers_supplied_apex(self):
        self.assertEqual(dr._apex_of("a.b.example.com", ["example.com"]), "example.com")
        # No apex list -> 2-label guess.
        self.assertEqual(dr._apex_of("a.b.example.com", []), "example.com")


class WildcardFilterTests(unittest.TestCase):
    def test_massdns_wildcard_filter_drops_catch_all_only_hosts(self):
        resolved_map = dr._parse_massdns_simple(MASSDNS_SIMPLE_OUT)
        # 10.10.10.10 is the apex's wildcard/catch-all address.
        wildcard_ips = {"example.com": {"10.10.10.10"}}
        kept, filtered = dr._filter_wildcards(resolved_map, wildcard_ips, ["example.com"])
        self.assertIn("junk.example.com", filtered)
        self.assertNotIn("junk.example.com", kept)
        # Real hosts and the CNAME-only host survive.
        self.assertIn("www.example.com", kept)
        self.assertIn("api.example.com", kept)
        self.assertIn("cname.example.com", kept)

    def test_no_wildcard_ips_keeps_everything(self):
        resolved_map = dr._parse_massdns_simple(MASSDNS_SIMPLE_OUT)
        kept, filtered = dr._filter_wildcards(resolved_map, {}, ["example.com"])
        self.assertEqual(filtered, set())
        self.assertEqual(set(kept), set(resolved_map))


class CapAndDedupTests(unittest.TestCase):
    def test_permutation_cap_enforced(self):
        # 60k distinct candidates -> capped to exactly PERMUTATION_CAP.
        candidates = [f"h{i}.example.com" for i in range(60_000)]
        capped_list, was_capped = dr._cap_candidates(candidates, dr.PERMUTATION_CAP)
        self.assertTrue(was_capped)
        self.assertEqual(len(capped_list), dr.PERMUTATION_CAP)
        self.assertEqual(len(capped_list), 50_000)

    def test_cap_dedupes_before_capping(self):
        # Duplicates collapse first; a small distinct set is not flagged capped.
        candidates = ["a.example.com", "a.example.com", "b.example.com"]
        capped_list, was_capped = dr._cap_candidates(candidates, dr.PERMUTATION_CAP)
        self.assertFalse(was_capped)
        self.assertEqual(capped_list, ["a.example.com", "b.example.com"])

    def test_cap_boundary_not_capped(self):
        candidates = [f"h{i}.example.com" for i in range(dr.PERMUTATION_CAP)]
        _, was_capped = dr._cap_candidates(candidates, dr.PERMUTATION_CAP)
        self.assertFalse(was_capped)


# --- entry-point tests ------------------------------------------------------
class EntryPointTests(unittest.IsolatedAsyncioTestCase):
    async def test_empty_input_returns_empty_shape(self):
        result = await dr.resolve_and_permute([], ["example.com"], "/tmp/vakt_dr_empty")
        self.assertEqual(
            result,
            {"resolved": [], "wildcard_filtered": [], "permutations_found": [], "findings": []},
        )

    async def test_no_tools_falls_back_to_builtin_resolver(self):
        tmp = tempfile.mkdtemp(prefix="vakt_dr_fallback_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        subs = ["www.example.com", "api.example.com"]

        # No external tools; built-in resolver reports every host live.
        with patch("shutil.which", return_value=None), \
             patch.object(dr, "_resolve_one", AsyncMock(return_value=True)):
            result = await dr.resolve_and_permute(subs, ["example.com"], tmp)

        self.assertEqual(result["resolved"], sorted(subs))
        self.assertEqual(result["wildcard_filtered"], [])
        self.assertEqual(result["permutations_found"], [])
        # A resolution summary finding is still emitted.
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["module"], "dns_resolve")

    async def test_fallback_returns_input_when_nothing_resolves(self):
        subs = ["www.example.com", "api.example.com"]
        # getaddrinfo reports nothing live -> best-effort returns the full input.
        with patch.object(dr, "_resolve_one", AsyncMock(return_value=False)):
            live = await dr._fallback_resolve(subs, concurrency=10)
        self.assertEqual(live, set(subs))

    async def test_puredns_resolution_and_wildcard_diff(self):
        tmp = tempfile.mkdtemp(prefix="vakt_dr_puredns_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        # Input has a bogus host that puredns will NOT return -> wildcard_filtered.
        subs = ["www.example.com", "api.example.com", "mail.example.com", "bogus.example.com"]
        which = _which_map({"puredns": "/usr/bin/puredns"})  # no permutation tools

        async def fake_exec(*args, **kwargs):
            return _fake_proc(PUREDNS_RESOLVED_OUT.encode())

        with patch("shutil.which", side_effect=which), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await dr.resolve_and_permute(subs, ["example.com"], tmp)

        self.assertEqual(result["resolved"], ["api.example.com", "mail.example.com", "www.example.com"])
        # The host puredns dropped is reported as wildcard/dead.
        self.assertIn("bogus.example.com", result["wildcard_filtered"])
        self.assertEqual(result["permutations_found"], [])
        # Artifacts written under <output_dir>/dns_resolve/.
        self.assertTrue(os.path.exists(os.path.join(tmp, "dns_resolve", "resolved.txt")))

    async def test_permutation_end_to_end_with_dedup(self):
        tmp = tempfile.mkdtemp(prefix="vakt_dr_perm_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        subs = ["www.example.com"]
        which = _which_map({"puredns": "/usr/bin/puredns", "alterx": "/usr/bin/alterx"})

        # Track what puredns is asked to resolve on the permutation pass.
        perm_inputs = {}

        async def fake_exec(*args, **kwargs):
            program = os.path.basename(args[0])
            if program == "alterx":
                return _fake_proc(ALTERX_OUT.encode())
            if program == "puredns":
                # args: puredns resolve <infile> -r <resolvers> --quiet
                infile = args[2]
                with open(infile, encoding="utf-8") as handle:
                    lines = [ln.strip() for ln in handle if ln.strip()]
                if os.path.basename(infile) == "permute_input.txt":
                    perm_inputs["hosts"] = lines
                    # api-dev resolves; api-staging does not.
                    return _fake_proc(b"api-dev.example.com\n")
                # Initial resolution pass: www resolves.
                return _fake_proc(b"www.example.com\n")
            return _fake_proc(b"")

        with patch("shutil.which", side_effect=which), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await dr.resolve_and_permute(subs, ["example.com"], tmp)

        # www (already known) must be excluded from the permutation resolve set.
        self.assertNotIn("www.example.com", perm_inputs.get("hosts", []))
        self.assertIn("api-dev.example.com", perm_inputs.get("hosts", []))

        # New live host surfaced only via permutation.
        self.assertEqual(result["permutations_found"], ["api-dev.example.com"])
        # Merged resolved set is deduped + sorted and contains both.
        self.assertEqual(result["resolved"], ["api-dev.example.com", "www.example.com"])
        # No accidental double-count of www.
        self.assertEqual(len(result["resolved"]), len(set(result["resolved"])))

    async def test_permute_false_skips_permutation_even_with_tools(self):
        """Default (--dns-hygiene without --dns-permute): wildcard-filter only —
        permutation generation must be skipped even though alterx is installed."""
        tmp = tempfile.mkdtemp(prefix="vakt_dr_noperm_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        which = _which_map({"puredns": "/usr/bin/puredns", "alterx": "/usr/bin/alterx"})
        called = {"programs": []}

        async def fake_exec(*args, **kwargs):
            program = os.path.basename(args[0])
            called["programs"].append(program)
            if program == "puredns":
                return _fake_proc(b"www.example.com\n")
            return _fake_proc(b"")

        with patch("shutil.which", side_effect=which), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await dr.resolve_and_permute(
                ["www.example.com"], ["example.com"], tmp, permute=False
            )

        self.assertEqual(result["permutations_found"], [])
        self.assertEqual(result["resolved"], ["www.example.com"])
        self.assertNotIn("alterx", called["programs"], "alterx must not run when permute=False")

    async def test_findings_conform_to_canonical_schema(self):
        tmp = tempfile.mkdtemp(prefix="vakt_dr_schema_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        which = _which_map({"puredns": "/usr/bin/puredns", "dnsgen": "/usr/bin/dnsgen"})

        async def fake_exec(*args, **kwargs):
            program = os.path.basename(args[0])
            if program == "dnsgen":
                return _fake_proc(DNSGEN_OUT.encode())
            if program == "puredns":
                infile = args[2]
                if os.path.basename(infile) == "permute_input.txt":
                    return _fake_proc(b"api-prod.example.com\n")
                return _fake_proc(b"www.example.com\napi.example.com\n")
            return _fake_proc(b"")

        with patch("shutil.which", side_effect=which), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await dr.resolve_and_permute(
                ["www.example.com", "api.example.com"], ["example.com"], tmp
            )

        # Resolution summary + permutation summary.
        self.assertEqual(len(result["findings"]), 2)
        for finding in result["findings"]:
            self.assertEqual(sorted(finding.keys()), sorted(CANONICAL_KEYS))
            self.assertEqual(validate_finding(finding), [], f"schema violations: {finding}")
            self.assertEqual(finding["status"], "INFO")
            self.assertEqual(finding["severity"], "INFO")
            self.assertEqual(finding["module"], "dns_resolve")


if __name__ == "__main__":
    unittest.main()
