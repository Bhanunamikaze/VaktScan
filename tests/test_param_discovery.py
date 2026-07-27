"""Tests for modules/param_discovery.py.

All tests run WITHOUT the real tools: paramspider / arjun / gf subprocesses are
mocked (routed by binary name), and ``shutil.which`` is patched so nothing on
the host is required. They assert parsing, URL building, dedup, graceful skip
when tools are absent, and canonical-finding emission.
"""

import glob
import json
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from modules import param_discovery
from modules.param_discovery import (
    _build_fuzz_url,
    _dedup_param_urls,
    _hosts_from_urls,
    _parse_arjun_json,
    _parse_url_lines,
    discover_parameters,
)
from modules.schema import CANONICAL_KEYS


def _is_canonical(finding):
    """A finding must carry all 15 canonical keys (normalize_finding contract)."""
    return set(CANONICAL_KEYS).issubset(finding.keys())


# ---------------------------------------------------------------------------
# Fake subprocess plumbing
# ---------------------------------------------------------------------------

class _FakeProc:
    def __init__(self, stdout=b"", stderr=b""):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = 0

    async def communicate(self, input=None):
        return self._stdout, self._stderr


def _make_fake_exec(paramspider_urls=None, arjun_output=None, gf_map=None):
    """Build an async side_effect for asyncio.create_subprocess_exec that routes
    on the binary name and mimics each tool's real I/O contract."""
    paramspider_urls = paramspider_urls or []
    arjun_output = arjun_output or {}
    gf_map = gf_map or {}

    async def fake_exec(*args, **kwargs):
        argv = list(args)
        binary = str(argv[0])

        if "paramspider" in binary:
            # paramspider writes its results to the -o path (and/or results/<d>.txt).
            outfile = argv[argv.index("-o") + 1]
            with open(outfile, "w", encoding="utf-8") as handle:
                handle.write("\n".join(paramspider_urls))
            return _FakeProc(stdout=b"", stderr=b"")

        if "arjun" in binary:
            outjson = argv[argv.index("-oJ") + 1]
            with open(outjson, "w", encoding="utf-8") as handle:
                json.dump(arjun_output, handle)
            return _FakeProc(stdout=b"", stderr=b"")

        if "gf" in binary:
            pattern = argv[1]
            matches = gf_map.get(pattern, [])
            payload = ("\n".join(matches) + "\n").encode() if matches else b""
            return _FakeProc(stdout=payload, stderr=b"")

        return _FakeProc(b"", b"")

    return fake_exec


# ---------------------------------------------------------------------------
# Pure parsing / helper tests
# ---------------------------------------------------------------------------

class ParsingTests(unittest.TestCase):
    def test_parse_url_lines_extracts_and_dedups(self):
        text = (
            "[*] paramspider banner\n"
            "https://ex.com/a.php?id=FUZZ\n"
            "  https://ex.com/b.php?x=FUZZ  \n"
            "https://ex.com/a.php?id=FUZZ\n"     # duplicate -> dropped
            "not a url line\n"
        )
        out = _parse_url_lines(text)
        self.assertEqual(out, [
            "https://ex.com/a.php?id=FUZZ",
            "https://ex.com/b.php?x=FUZZ",
        ])

    def test_parse_url_lines_empty(self):
        self.assertEqual(_parse_url_lines(""), [])
        self.assertEqual(_parse_url_lines(None), [])

    def test_parse_arjun_json_newer_dict_shape(self):
        data = {"http://ex.com/api": {"method": "GET", "params": ["id", "token", "id"]}}
        self.assertEqual(_parse_arjun_json(data), {"http://ex.com/api": ["id", "token"]})

    def test_parse_arjun_json_older_list_shape(self):
        data = {"http://ex.com/api": ["a", "b"]}
        self.assertEqual(_parse_arjun_json(data), {"http://ex.com/api": ["a", "b"]})

    def test_parse_arjun_json_bad_input(self):
        self.assertEqual(_parse_arjun_json(None), {})
        self.assertEqual(_parse_arjun_json([1, 2, 3]), {})

    def test_hosts_from_urls(self):
        self.assertEqual(
            _hosts_from_urls([
                "https://A.com/x", "http://a.com/y?p=1", "https://b.com", "", None,
            ]),
            ["a.com", "b.com"],
        )

    def test_build_fuzz_url_appends_params(self):
        url = _build_fuzz_url("https://ex.com/api/user", ["token", "debug"])
        self.assertEqual(url, "https://ex.com/api/user?token=FUZZ&debug=FUZZ")

    def test_build_fuzz_url_merges_existing_query(self):
        url = _build_fuzz_url("https://ex.com/p?a=1", ["b"])
        # Existing keys are preserved (value normalized), new key added.
        self.assertIn("a=1", url)
        self.assertIn("b=FUZZ", url)

    def test_dedup_param_urls_collapses_by_param_keys(self):
        urls = [
            "https://ex.com/p?id=1",
            "https://ex.com/p?id=99",       # same path + {id} -> duplicate
            "https://ex.com/p?id=1&x=2",    # different key set -> kept
            "https://ex.com/other?id=1",    # different path -> kept
            "https://ex.com/nofilter",      # no params -> dropped entirely
        ]
        out = _dedup_param_urls(urls)
        self.assertEqual(len(out), 3)
        self.assertIn("https://ex.com/p?id=1", out)
        self.assertIn("https://ex.com/p?id=1&x=2", out)
        self.assertIn("https://ex.com/other?id=1", out)
        self.assertNotIn("https://ex.com/nofilter", out)


# ---------------------------------------------------------------------------
# Entry-point behaviour tests
# ---------------------------------------------------------------------------

class DiscoverParametersTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.output_dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _feed_contents(self):
        params_dir = os.path.join(self.output_dir, "params")
        matches = glob.glob(os.path.join(params_dir, "param_urls_*.txt"))
        self.assertTrue(matches, "expected a param_urls feed file to be written")
        with open(matches[0], "r", encoding="utf-8") as handle:
            return handle.read()

    async def test_empty_input_returns_empty(self):
        self.assertEqual(await discover_parameters([], self.output_dir), [])
        self.assertEqual(await discover_parameters(["   ", None], self.output_dir), [])

    async def test_all_tools_missing_graceful_skip(self):
        exec_mock = AsyncMock()
        with patch("modules.param_discovery.shutil.which", return_value=None), \
             patch("asyncio.create_subprocess_exec", exec_mock):
            out = await discover_parameters(["https://ex.com/x?id=1"], self.output_dir)
        self.assertEqual(out, [])
        exec_mock.assert_not_called()  # never spawns a subprocess when nothing is installed

    async def test_full_pipeline_produces_canonical_findings(self):
        alive = [
            "https://ex.com/index.html",              # no params -> ignored in feed
            "https://ex.com/page?id=1",               # seeded param URL
            "https://ex.com/page?id=99",              # dup of above (same {id}) -> collapsed
            "https://ex.com/search.php?q=1&cat=2",    # seeded, gf-xss target
        ]
        # paramspider (passive) contributes an archived parameterized URL.
        paramspider_urls = ["https://ex.com/prod.php?pid=FUZZ"]
        # arjun (active) reports two params on an endpoint with no prior query.
        arjun_output = {"https://ex.com/api/user": {"method": "GET", "params": ["token", "debug"]}}
        # gf tags one URL for xss only.
        gf_map = {"xss": ["https://ex.com/search.php?q=1&cat=2"]}

        which_map = {
            "paramspider": "/usr/bin/paramspider",
            "arjun": "/usr/bin/arjun",
            "gf": "/usr/bin/gf",
        }
        fake_exec = _make_fake_exec(paramspider_urls, arjun_output, gf_map)

        with patch("modules.param_discovery.shutil.which", side_effect=lambda n: which_map.get(n)), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            findings = await discover_parameters(alive, self.output_dir, concurrency=5)

        # --- Findings are canonical and attributed to this module ---
        self.assertTrue(findings, "expected findings from discovered parameters")
        for f in findings:
            self.assertTrue(_is_canonical(f), f"non-canonical finding: {f}")
            self.assertEqual(f["module"], "param_discovery")

        # --- LOW-NOISE contract: this module NEVER claims a vulnerability. ---
        # Every finding is a pure INFO summary; no VULNERABLE/POTENTIAL/CRITICAL
        # status and no HIGH/MEDIUM/CRITICAL severity may ever be emitted.
        self.assertTrue(all(f["status"] == "INFO" for f in findings))
        self.assertTrue(all(f["severity"] == "INFO" for f in findings))

        # --- Exactly ONE aggregated summary per host (no per-URL row spam). ---
        summary = [f for f in findings if f["vulnerability"] == "Parameterized Endpoints Discovered"]
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["target"], "ex.com")

        # --- gf hits fold into ONE aggregated INFO "candidate" finding per host,
        #     NOT a VULNERABLE xss/sqli/etc. finding. ---
        gf_findings = [f for f in findings if f["vulnerability"] == "Parameter Injection Test Candidates (gf)"]
        self.assertEqual(len(gf_findings), 1, "gf hits must aggregate to one candidate finding per host")
        gf_f = gf_findings[0]
        self.assertEqual(gf_f["target"], "ex.com")
        self.assertEqual(gf_f["status"], "INFO")
        self.assertEqual(gf_f["severity"], "INFO")
        # Wording must read as a candidate/lead, never a confirmation.
        self.assertIn("xss", gf_f["details"])
        self.assertIn("NOT confirmed", gf_f["details"])
        # A gf tag must NOT mint a standalone XSS/SQLi vuln finding.
        self.assertFalse(
            [f for f in findings if "XSS" in f["vulnerability"] or "SQL" in f["vulnerability"].upper()]
        )
        # Only xss matched -> sqli/ssrf/redirect are absent from the candidate detail.
        self.assertNotIn("sqli", gf_f["details"])

        # At most two findings per host (surface summary + gf candidate).
        self.assertEqual(len(findings), 2)

        # --- Feed file aggregates all sources and is deduped ---
        feed = self._feed_contents()
        self.assertIn("https://ex.com/page?id=1", feed)                     # seeded
        self.assertIn("https://ex.com/search.php?q=1&cat=2", feed)          # seeded
        self.assertIn("https://ex.com/prod.php?pid=FUZZ", feed)             # paramspider
        # arjun params are normalized (sorted) by _parse_arjun_json -> debug,token.
        self.assertIn("https://ex.com/api/user?debug=FUZZ&token=FUZZ", feed)  # arjun
        self.assertNotIn("https://ex.com/index.html", feed)                # no params -> excluded
        # id=99 collapsed into id=1 (same param-key set) -> only one /page line.
        self.assertEqual(feed.count("/page?"), 1)

        # --- Param-name wordlist written with the union of discovered keys ---
        names_files = glob.glob(os.path.join(self.output_dir, "params", "param_names_*.txt"))
        self.assertTrue(names_files)
        with open(names_files[0], "r", encoding="utf-8") as handle:
            names = set(handle.read().split())
        self.assertTrue({"id", "q", "cat", "pid", "token", "debug"}.issubset(names))

    async def test_only_gf_available_still_tags_seeded_urls(self):
        # paramspider + arjun absent; gf present. Seeded param URLs still flow to
        # the feed and gf can tag them -> graceful partial operation, no crash.
        which_map = {"gf": "/usr/bin/gf"}
        gf_map = {"sqli": ["https://ex.com/item?id=1"]}
        fake_exec = _make_fake_exec(gf_map=gf_map)

        with patch("modules.param_discovery.shutil.which", side_effect=lambda n: which_map.get(n)), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            findings = await discover_parameters(
                ["https://ex.com/item?id=1", "https://ex.com/static"], self.output_dir
            )

        # Summary finding for the seeded param URL + an aggregated gf candidate
        # finding whose detail names the sqli category — but still only INFO.
        self.assertTrue([f for f in findings if f["vulnerability"] == "Parameterized Endpoints Discovered"])
        gf_findings = [f for f in findings if f["vulnerability"] == "Parameter Injection Test Candidates (gf)"]
        self.assertEqual(len(gf_findings), 1)
        self.assertIn("sqli", gf_findings[0]["details"])
        for f in findings:
            self.assertTrue(_is_canonical(f))
            self.assertEqual(f["status"], "INFO")
            self.assertEqual(f["severity"], "INFO")

    async def test_dedup_collapses_near_duplicates_to_one_finding(self):
        # 50 URLs that differ only in param VALUES (same host/path/{id}) must
        # collapse to a single feed line and a single aggregated host finding,
        # so a large archive can't spawn hundreds of near-duplicate rows.
        alive = [f"https://ex.com/item.php?id={n}" for n in range(50)]
        which_map = {"paramspider": "/usr/bin/paramspider"}
        fake_exec = _make_fake_exec(paramspider_urls=[])
        with patch("modules.param_discovery.shutil.which", side_effect=lambda n: which_map.get(n)), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            findings = await discover_parameters(alive, self.output_dir)

        # Exactly one aggregated summary finding for the host.
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Parameterized Endpoints Discovered")
        # Feed collapsed 50 value-variants to a single canonical line.
        feed = self._feed_contents()
        self.assertEqual(feed.strip().count("\n"), 0)
        self.assertIn("https://ex.com/item.php?id=0", feed)

    async def test_no_parameterized_endpoints_returns_empty(self):
        # Tools present, but nothing has params and no tool discovers any.
        which_map = {"arjun": "/usr/bin/arjun", "gf": "/usr/bin/gf"}
        fake_exec = _make_fake_exec(arjun_output={}, gf_map={})
        with patch("modules.param_discovery.shutil.which", side_effect=lambda n: which_map.get(n)), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            findings = await discover_parameters(
                ["https://ex.com/", "https://ex.com/about"], self.output_dir
            )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
