"""Tests for the lightweight `scan --tech-only` mode.

`--tech-only` runs ONLY the minimal web-technology pipeline:

    resolve/expand -> web-port scan -> httpx alive-probe ->
    tech_fingerprint.fingerprint_tech -> web_tech_cve (+ NVD/KEV/EPSS/CVSS) -> report

It must NOT touch the heavy pipeline: subdomain enum (recon), nuclei, dirsearch,
web_checks, js_paths, the service-scan path, domain_scan, archived_urls, or nmap.

The orchestration test drives `main.main(module_mode='tech-only', ...)` with every
heavy/networked collaborator mocked, asserting (via spies) that tech_fingerprint
IS invoked, the heavy modules are NOT, and a CSV report is written. The CLI-smoke
tests confirm the `--tech-only` flag parses on the `scan` subcommand.
"""

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main  # noqa: E402

WORKTREE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class _FakeDashboard:
    """Stand-in for modules.dashboard.LiveDashboard (no terminal control)."""
    active = False

    def __getattr__(self, _name):
        return lambda *a, **k: None


class _FakeHTTPXRunner:
    """Minimal httpx runner: returns one alive URL, writes nothing."""

    def __init__(self, output_dir=None):
        self.output_dir = output_dir

    async def run_httpx(self, urls, concurrency):
        return [{"url": "https://example.com"}]

    def save_csv(self, httpx_data, domain_label):
        return None


class _TechOnlyTempCwd(unittest.TestCase):
    """Base class: run each test in a disposable working directory so any
    reports/ writes land in a temp dir that is cleaned up."""

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="vaktscan_techonly_")
        os.chdir(self._tmp)

    def tearDown(self):
        os.chdir(self._cwd)
        shutil.rmtree(self._tmp, ignore_errors=True)


class TechOnlyPipelineTest(_TechOnlyTempCwd):
    """--tech-only runs tech_fingerprint + web_tech_cve, skips the heavy modules,
    and writes a report."""

    def test_runs_tech_fingerprint_and_skips_heavy_modules(self):
        tech_finding = {
            "module": main.tech_fingerprint.MODULE_NAME,
            "vulnerability": "Technology Detected: nginx 1.18.0",
            "service_version": "1.18.0",
            "target": "example.com",
            "resolved_ip": "93.184.216.34",
            "port": 443,
            "url": "https://example.com",
            "status": "INFO",
            "severity": "INFO",
            "details": "webanalyze",
        }

        async def fake_process_targets(raw_targets):
            return [{
                "scan_address": "example.com",
                "display_target": "example.com",
                "resolved_ip": "93.184.216.34",
            }]

        async def fake_scan_ports(*args, **kwargs):
            return []

        async def passthru(findings):
            return findings

        async def no_additions(findings):
            return []

        # tech_fingerprint MUST run.
        fingerprint = mock.AsyncMock(return_value=[tech_finding])

        # Heavy modules that MUST NOT run in tech-only mode.
        nuclei_cls = mock.MagicMock()
        dirsearch_cls = mock.MagicMock()
        recon_cls = mock.MagicMock()
        jspaths_cls = mock.MagicMock()
        web_checks_run = mock.AsyncMock(return_value=[])
        service_scan = mock.AsyncMock(return_value=[])
        nmap_mod = mock.MagicMock()
        domain_scan_mod = mock.MagicMock()
        archived_mod = mock.MagicMock()

        saved_csv = mock.MagicMock(return_value="tech_only.csv")

        with ExitStack() as es:
            es.enter_context(mock.patch("modules.dashboard.LiveDashboard", return_value=_FakeDashboard()))
            es.enter_context(mock.patch.object(main.nuclei_runner, "sync_nuclei_templates", return_value=None))
            es.enter_context(mock.patch.object(main, "load_subdomains_file", return_value=["example.com"]))
            es.enter_context(mock.patch.object(main, "process_targets", fake_process_targets))
            es.enter_context(mock.patch.object(main, "scan_ports", fake_scan_ports))
            es.enter_context(mock.patch.object(main.httpx_runner, "HTTPXRunner", _FakeHTTPXRunner))

            # tech_fingerprint spy (must be called).
            es.enter_context(mock.patch.object(main.tech_fingerprint, "fingerprint_tech", fingerprint))

            # web_tech_cve header + tech CVE paths run (mocked to avoid NVD network).
            es.enter_context(mock.patch.object(main.web_tech_cve, "collect_existing_cve_keys", return_value=set()))
            es.enter_context(mock.patch.object(main.web_tech_cve, "cves_from_headers", mock.AsyncMock(return_value=[])))
            es.enter_context(mock.patch.object(main.web_tech_cve, "cves_from_tech_detections", mock.AsyncMock(return_value=[])))

            # NVD / KEV / EPSS / passive enrichment (no network).
            es.enter_context(mock.patch.object(main.nvd, "extract_product_and_version", lambda f: ("", "")))
            es.enter_context(mock.patch.object(main.cisa_kev, "enrich_findings_with_kev", passthru))
            es.enter_context(mock.patch.object(main.epss, "enrich_findings_with_epss", passthru))
            es.enter_context(mock.patch.object(main.passive_intel, "enrich_findings_with_passive_intel", no_additions))

            # Report writers (spy on CSV, no-op HTML).
            es.enter_context(mock.patch.object(main, "save_results_to_csv", saved_csv))
            es.enter_context(mock.patch.object(main, "save_results_to_html", mock.MagicMock()))

            # Heavy modules that must NEVER be reached in tech-only mode.
            es.enter_context(mock.patch.object(main.nuclei_runner, "NucleiRunner", nuclei_cls))
            es.enter_context(mock.patch.object(main.dir_enum, "DirEnumerator", dirsearch_cls))
            es.enter_context(mock.patch.object(main.recon, "ReconScanner", recon_cls))
            es.enter_context(mock.patch.object(main.js_paths, "JSPathsScanner", jspaths_cls))
            es.enter_context(mock.patch.object(main.web_checks, "run_checks", web_checks_run))
            es.enter_context(mock.patch.object(main, "process_chunk_services", service_scan))
            es.enter_context(mock.patch.object(main, "nmap_runner", nmap_mod))
            es.enter_context(mock.patch.object(main, "domain_scan", domain_scan_mod))
            es.enter_context(mock.patch.object(main, "archived_urls", archived_mod))

            asyncio.run(
                main.main(
                    None,               # targets_file
                    1,                  # concurrency
                    module_mode="tech-only",
                    domain_scan_file="example.com",
                )
            )

        # tech_fingerprint ran, over the httpx-discovered alive URL.
        self.assertTrue(fingerprint.called, "tech_fingerprint.fingerprint_tech must run in tech-only mode")
        self.assertIn("https://example.com", fingerprint.call_args.args[0])

        # A CSV report was written via the shared finalization tail.
        self.assertTrue(saved_csv.called, "tech-only must write a CSV report")
        self.assertIn(tech_finding, saved_csv.call_args.args[0])

        # The heavy pipeline was skipped entirely.
        nuclei_cls.assert_not_called()
        dirsearch_cls.assert_not_called()
        recon_cls.assert_not_called()          # no subdomain enum
        jspaths_cls.assert_not_called()
        web_checks_run.assert_not_called()
        service_scan.assert_not_called()        # no service scans
        self.assertEqual(nmap_mod.mock_calls, [], "nmap must not run in tech-only mode")
        self.assertEqual(domain_scan_mod.mock_calls, [], "domain_scan must not run in tech-only mode")
        self.assertEqual(archived_mod.mock_calls, [], "archived_urls must not run in tech-only mode")


class TechOnlyCLISmokeTest(unittest.TestCase):
    """The --tech-only flag is registered on the scan subparser and parses."""

    def test_tech_only_in_scan_help(self):
        result = subprocess.run(
            [sys.executable, "main.py", "scan", "--help"],
            capture_output=True, text=True, cwd=WORKTREE,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--tech-only", result.stdout)

    def test_scan_tech_only_parses(self):
        # `scan --tech-only` (no target) must PARSE (argparse accepts the flag)
        # and reach the handler's target check - it exits 1 with the target
        # message, NOT argparse's exit-2 "unrecognized arguments". This proves
        # `scan --tech-only <target>` is a valid, parseable invocation.
        result = subprocess.run(
            [sys.executable, "main.py", "scan", "--tech-only"],
            capture_output=True, text=True, cwd=WORKTREE,
        )
        combined = result.stdout + result.stderr
        self.assertNotIn("unrecognized arguments", combined)
        self.assertIn("scan requires a target", combined)


if __name__ == "__main__":
    unittest.main()
