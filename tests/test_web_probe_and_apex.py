"""Tests for the opt-in streaming web probe (B2) and per-apex cloud enum (B6)."""

import asyncio
import os
import sys
import unittest
from contextlib import ExitStack
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main  # noqa: E402


class RegistrableDomainTest(unittest.TestCase):
    def test_apex_extraction(self):
        cases = {
            "a.b.example.com": "example.com",
            "example.com": "example.com",
            "richardrodermond.steinzsecurity.com": "steinzsecurity.com",
            "deep.sub.domain.example.co.uk": "example.co.uk",
            "shop.example.com.au": "example.com.au",
            "localhost": "localhost",
            "": "",
            "Example.COM": "example.com",
        }
        for host, expected in cases.items():
            with self.subTest(host=host):
                self.assertEqual(main._registrable_domain(host), expected)


class WebPortSetTest(unittest.TestCase):
    def test_includes_custom_ports(self):
        base = {"web": [80, 443]}
        self.assertEqual(main._web_port_set(base, None), {80, 443})
        self.assertEqual(main._web_port_set(base, "8080,9000"), {80, 443, 8080, 9000})

    def test_bad_custom_ports_ignored(self):
        self.assertEqual(main._web_port_set({"web": [80]}, "notaport"), {80})


class ProbeWebUrlsTest(unittest.TestCase):
    def test_collects_nuclei_webchecks_js_findings(self):
        nuc = {"vulnerability": "nuclei-hit"}
        wc = {"vulnerability": "webcheck-hit"}
        js = {"vulnerability": "js-secret"}

        class FakeHttpx:
            def __init__(self, output_dir=None):
                pass

            async def run_httpx(self, urls, concurrency):
                return [{"url": "http://a"}]

            def save_csv(self, data, label):
                pass

        class FakeNuclei:
            def __init__(self, output_dir=None):
                pass

            async def run_nuclei(self, urls):
                return [nuc]

        class FakeDir:
            def __init__(self, label, output_dir=None):
                pass

            async def run_dirsearch(self, urls):
                return "reports"

        class FakeJS:
            def __init__(self, urls, output_dir=None):
                pass

            async def run(self):
                return {"findings": [js]}

        async def fake_wc(urls, concurrency):
            return [wc]

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main.httpx_runner, "HTTPXRunner", FakeHttpx))
            es.enter_context(mock.patch.object(main.nuclei_runner, "NucleiRunner", FakeNuclei))
            es.enter_context(mock.patch.object(main.web_checks, "run_checks", fake_wc))
            es.enter_context(mock.patch.object(main.dir_enum, "DirEnumerator", FakeDir))
            es.enter_context(mock.patch.object(main.js_paths, "JSPathsScanner", FakeJS))
            findings = asyncio.run(main._probe_web_urls(["http://a:80"], "reports", "lbl", 10))

        self.assertIn(nuc, findings)
        self.assertIn(wc, findings)
        self.assertIn(js, findings)

    def test_no_urls_returns_empty(self):
        self.assertEqual(asyncio.run(main._probe_web_urls([], "reports", "lbl", 10)), [])

    def test_js_cve_runs_in_direct_target_path(self):
        # Regression: js_cve previously only ran in recon mode. The direct-target
        # web-probe path must feed its discovered JS to js_cve too.
        js_cve_finding = {"vulnerability": "CVE-2011-4969 - jquery 1.6.2"}

        class FakeHttpx:
            def __init__(self, output_dir=None):
                pass

            async def run_httpx(self, urls, concurrency):
                return [{"url": "http://a/app.js"}]

            def save_csv(self, data, label):
                pass

        class FakeNuclei:
            def __init__(self, output_dir=None):
                pass

            async def run_nuclei(self, urls):
                return []

        class FakeDir:
            def __init__(self, label, output_dir=None):
                pass

            async def run_dirsearch(self, urls):
                return "reports"

        class FakeJS:
            def __init__(self, urls, output_dir=None):
                pass

            async def run(self):
                return {"findings": [], "js_urls": ["http://a/jquery-1.6.2.min.js"],
                        "absolute_urls": []}

        async def fake_wc(urls, concurrency):
            return []

        captured = {}

        async def fake_scan(corpus, output_dir=None, concurrency=20):
            captured["corpus"] = list(corpus)
            return [js_cve_finding]

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main.httpx_runner, "HTTPXRunner", FakeHttpx))
            es.enter_context(mock.patch.object(main.nuclei_runner, "NucleiRunner", FakeNuclei))
            es.enter_context(mock.patch.object(main.web_checks, "run_checks", fake_wc))
            es.enter_context(mock.patch.object(main.dir_enum, "DirEnumerator", FakeDir))
            es.enter_context(mock.patch.object(main.js_paths, "JSPathsScanner", FakeJS))
            es.enter_context(mock.patch.object(main.js_cve, "scan_js_cves", fake_scan))
            findings = asyncio.run(main._probe_web_urls(["http://a:80"], "reports", "lbl", 10))

        self.assertIn(js_cve_finding, findings)
        # Both the js_paths-discovered JS URL and the alive .js URL are in the corpus.
        self.assertIn("http://a/jquery-1.6.2.min.js", captured["corpus"])
        self.assertIn("http://a/app.js", captured["corpus"])

    def test_js_cve_skipped_when_disabled(self):
        class FakeHttpx:
            def __init__(self, output_dir=None):
                pass

            async def run_httpx(self, urls, concurrency):
                return [{"url": "http://a/app.js"}]

            def save_csv(self, data, label):
                pass

        class FakeNuclei:
            def __init__(self, output_dir=None):
                pass

            async def run_nuclei(self, urls):
                return []

        class FakeDir:
            def __init__(self, label, output_dir=None):
                pass

            async def run_dirsearch(self, urls):
                return "reports"

        class FakeJS:
            def __init__(self, urls, output_dir=None):
                pass

            async def run(self):
                return {"findings": [], "js_urls": ["http://a/jquery-1.6.2.min.js"]}

        async def fake_wc(urls, concurrency):
            return []

        scan = mock.AsyncMock(return_value=[{"vulnerability": "should-not-appear"}])

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main.httpx_runner, "HTTPXRunner", FakeHttpx))
            es.enter_context(mock.patch.object(main.nuclei_runner, "NucleiRunner", FakeNuclei))
            es.enter_context(mock.patch.object(main.web_checks, "run_checks", fake_wc))
            es.enter_context(mock.patch.object(main.dir_enum, "DirEnumerator", FakeDir))
            es.enter_context(mock.patch.object(main.js_paths, "JSPathsScanner", FakeJS))
            es.enter_context(mock.patch.object(main.js_cve, "scan_js_cves", scan))
            findings = asyncio.run(
                main._probe_web_urls(["http://a:80"], "reports", "lbl", 10, enable_js_cve=False)
            )

        scan.assert_not_called()
        self.assertEqual(findings, [])


class StreamingWebProbeOptInTest(unittest.TestCase):
    def _run(self, web_probe):
        calls = {"n": 0, "urls": None}

        async def fake_stream(raw_targets, chunk_size):
            yield [{"scan_address": "a", "resolved_ip": "1.1.1.1", "open_ports": [80]}]

        async def fake_scan_ports(*args, **kwargs):
            return [({"scan_address": "a", "resolved_ip": "1.1.1.1", "display_target": "a"}, {"open_ports": [80]})]

        async def fake_chunk_services(*args, **kwargs):
            return []

        async def fake_probe(urls, output_dir, label, concurrency, enable_js_cve=True):
            calls["n"] += 1
            calls["urls"] = urls
            calls["enable_js_cve"] = enable_js_cve
            return []

        async def fake_enrich(findings, run_id, output_dir, sarif_output, output_format=None):
            return findings

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main, "process_targets_streaming", fake_stream))
            es.enter_context(mock.patch.object(main, "scan_ports", fake_scan_ports))
            es.enter_context(mock.patch.object(main, "process_chunk_services", fake_chunk_services))
            es.enter_context(mock.patch.object(main, "save_port_scan_csv", mock.MagicMock()))
            es.enter_context(mock.patch.object(main, "_probe_web_urls", fake_probe))
            es.enter_context(mock.patch.object(main, "_enrich_and_report", fake_enrich))
            asyncio.run(
                main.process_streaming_scan(
                    ["1.1.1.1"], 1, state_manager=mock.MagicMock(), run_id=1, web_probe=web_probe,
                )
            )
        return calls

    def test_opt_in_probes_open_web_ports(self):
        calls = self._run(web_probe=True)
        self.assertEqual(calls["n"], 1, "web probe must run on the chunk's open web port")
        self.assertTrue(any(":80" in u for u in calls["urls"]))

    def test_off_by_default(self):
        calls = self._run(web_probe=False)
        self.assertEqual(calls["n"], 0, "web probe must NOT run unless opted in")


if __name__ == "__main__":
    unittest.main()
