"""Integration tests for main.py orchestration control flow.

These drive `main()` and `process_streaming_scan()` with the heavy/networked
collaborators mocked, exercising the code paths that previously had latent
bugs:

* B#1 — the standalone ``--sub-domains`` branch must PERSIST its findings
  (it returns before a state_manager exists, so it writes CSV directly).
* B#2 — passive-recon findings buffered before a subdomain is discovered must
  NOT be dropped on the "no usable targets" early return.
* B#3 — the streaming (>1000 targets) path must reach inventory persistence and
  SARIF output, at parity with the non-streaming path. This also exercises the
  ``ipaddress.ip_network`` target-count loop that used to raise ``NameError``.
* A1 — a programming bug (NameError/UnboundLocalError) raised inside recon must
  PROPAGATE, not be masked by ``gather(return_exceptions=True)`` as
  "Recon finished with no usable targets".

Each test runs inside a throwaway working directory so any real report/CSV
writes land in a temp dir that is cleaned up.
"""

import asyncio
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import ExitStack
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main  # noqa: E402


async def _noop_async(*args, **kwargs):
    return None


class _FakeDashboard:
    """Stand-in for modules.dashboard.LiveDashboard (no terminal control)."""
    active = False

    def __getattr__(self, _name):
        return lambda *a, **k: None


class _MainTempCwd(unittest.TestCase):
    """Base class: run each test in a disposable working directory."""

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="vaktscan_test_")
        os.chdir(self._tmp)

    def tearDown(self):
        os.chdir(self._cwd)
        shutil.rmtree(self._tmp, ignore_errors=True)


class StandaloneSubdomainsPersistenceTest(_MainTempCwd):
    """B#1: standalone --sub-domains findings must be written to CSV."""

    def test_findings_persisted_to_csv(self):
        finding = {"vulnerability": "nuclei-hit", "target": "a.example.com", "severity": "HIGH"}

        async def fake_followups(*args, **kwargs):
            return [finding]

        saved = mock.MagicMock(return_value="recon_findings.csv")

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main.nuclei_runner, "sync_nuclei_templates", return_value=None))
            es.enter_context(mock.patch.object(main, "load_subdomains_file", return_value=["a.example.com"]))
            es.enter_context(mock.patch.object(main, "run_recon_followups", fake_followups))
            es.enter_context(mock.patch.object(main, "save_results_to_csv", saved))

            asyncio.run(
                main.main(
                    None,               # targets_file
                    1,                  # concurrency
                    subdomains_file="mylist.txt",
                    recon_domains=None,
                )
            )

        self.assertTrue(saved.called, "standalone --sub-domains path must persist findings")
        persisted = saved.call_args.args[0]
        self.assertIn(finding, persisted)


class OrphanPassiveFindingsTest(_MainTempCwd):
    """B#2: passive findings must survive the 'no subdomains discovered' path."""

    def test_passive_findings_persisted_when_no_subdomains(self):
        dns_finding = {"vulnerability": "subdomain-takeover", "target": "example.com", "severity": "HIGH"}

        class _FakeScanner:
            def __init__(self, domain, wordlist=None, detailed_dashboard=True):
                self.domain = domain

            async def run_all(self):
                # results_file, subdomains — NO subdomains discovered.
                return (os.path.join("reports", "example.com", "subs.txt"), [])

        async def fake_passive(domain, concurrency, detailed_dashboard=True):
            return ([dns_finding], [], [])

        saved = mock.MagicMock(return_value="passive.csv")

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main.nuclei_runner, "sync_nuclei_templates", return_value=None))
            es.enter_context(mock.patch("modules.dashboard.LiveDashboard", return_value=_FakeDashboard()))
            es.enter_context(mock.patch.object(main.recon, "ReconScanner", _FakeScanner))
            es.enter_context(mock.patch.object(main, "_run_parallel_passive", fake_passive))
            es.enter_context(mock.patch.object(main, "save_results_to_csv", saved))

            # No subdomains anywhere -> "no usable targets" early return.
            asyncio.run(
                main.main(
                    None,
                    1,
                    recon_domains=["example.com"],
                    scan_found=False,
                    no_dork=True,
                )
            )

        self.assertTrue(saved.called, "buffered passive findings must be persisted, not dropped")
        persisted = saved.call_args.args[0]
        self.assertIn(dns_finding, persisted)


class ProgrammingErrorPropagatesTest(_MainTempCwd):
    """A1: a NameError inside recon must propagate, not become 'no usable targets'."""

    def test_name_error_in_recon_is_not_swallowed(self):
        class _FakeScanner:
            def __init__(self, domain, wordlist=None, detailed_dashboard=True):
                self.domain = domain

            async def run_all(self):
                return (os.path.join("reports", "example.com", "subs.txt"), ["a.example.com"])

        async def boom(*args, **kwargs):
            raise NameError("simulated bug: name 'state_manager' is not defined")

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main.nuclei_runner, "sync_nuclei_templates", return_value=None))
            es.enter_context(mock.patch("modules.dashboard.LiveDashboard", return_value=_FakeDashboard()))
            es.enter_context(mock.patch.object(main.recon, "ReconScanner", _FakeScanner))
            es.enter_context(mock.patch.object(main, "_run_parallel_passive", boom))

            with self.assertRaises(NameError):
                asyncio.run(
                    main.main(
                        None,
                        1,
                        recon_domains=["example.com"],
                        scan_found=False,
                        no_dork=True,
                    )
                )


class StreamingPersistenceTest(_MainTempCwd):
    """B#3: streaming path must persist to inventory + SARIF (and not NameError
    on the ipaddress-based target count)."""

    def test_streaming_persists_inventory_and_sarif(self):
        async def fake_stream(raw_targets, chunk_size):
            yield [{"scan_address": "192.0.2.1", "resolved_ip": "192.0.2.1", "open_ports": []}]

        async def fake_scan_ports(*args, **kwargs):
            return []  # no open ports -> trivial downstream

        inv = mock.MagicMock()
        inv.save_findings.return_value = {}
        sarif = mock.MagicMock()
        state_mgr = mock.MagicMock()

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main, "process_targets_streaming", fake_stream))
            es.enter_context(mock.patch.object(main, "scan_ports", fake_scan_ports))
            es.enter_context(mock.patch.object(main, "print_final_results", _noop_async))
            es.enter_context(mock.patch.object(main, "save_port_scan_csv", mock.MagicMock()))
            es.enter_context(mock.patch.object(main, "inventory", inv))
            es.enter_context(mock.patch.object(main, "write_sarif_output", sarif))

            result = asyncio.run(
                main.process_streaming_scan(
                    ["192.0.2.0/30"],   # CIDR -> exercises ipaddress.ip_network count loop
                    1,
                    state_manager=state_mgr,
                    run_id=99,
                    sarif_output="out.sarif",
                )
            )

        self.assertEqual(result, [])
        self.assertTrue(inv.save_findings.called, "streaming scan must write findings to inventory")
        self.assertEqual(inv.save_findings.call_args.args[0], 99)
        self.assertTrue(inv.complete_scan_run.called, "streaming scan must close out the run")
        self.assertTrue(sarif.called, "streaming scan must honor --sarif")
        self.assertEqual(sarif.call_args.args[1], "out.sarif")

    def test_streaming_without_run_id_skips_inventory(self):
        async def fake_stream(raw_targets, chunk_size):
            yield []

        async def fake_scan_ports(*args, **kwargs):
            return []

        inv = mock.MagicMock()
        with ExitStack() as es:
            es.enter_context(mock.patch.object(main, "process_targets_streaming", fake_stream))
            es.enter_context(mock.patch.object(main, "scan_ports", fake_scan_ports))
            es.enter_context(mock.patch.object(main, "print_final_results", _noop_async))
            es.enter_context(mock.patch.object(main, "inventory", inv))

            asyncio.run(
                main.process_streaming_scan(
                    ["10.0.0.1"],
                    1,
                    state_manager=mock.MagicMock(),
                    run_id=None,
                )
            )
        self.assertFalse(inv.save_findings.called)


class EnrichAndReportTest(_MainTempCwd):
    """B2: the shared finalization tail enriches, persists, and writes outputs."""

    def test_enriches_persists_and_writes_outputs(self):
        finding = {"vulnerability": "X", "target": "a.com", "status": "VULNERABLE", "url": "http://a.com"}
        inv = mock.MagicMock()
        inv.save_findings.return_value = {}
        sarif = mock.MagicMock()

        async def passthru(f):
            return f

        async def no_additions(f):
            return []

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main.cisa_kev, "enrich_findings_with_kev", passthru))
            es.enter_context(mock.patch.object(main.epss, "enrich_findings_with_epss", passthru))
            es.enter_context(mock.patch.object(main.passive_intel, "enrich_findings_with_passive_intel", no_additions))
            es.enter_context(mock.patch.object(main.nvd, "extract_product_and_version", lambda f: ("", "")))
            es.enter_context(mock.patch.object(main, "inventory", inv))
            es.enter_context(mock.patch.object(main, "write_sarif_output", sarif))

            result = asyncio.run(
                main._enrich_and_report([dict(finding)], run_id=5, output_dir=None, sarif_output="out.sarif")
            )

        self.assertTrue(inv.save_findings.called, "must persist to inventory")
        self.assertEqual(inv.save_findings.call_args.args[0], 5)
        self.assertTrue(inv.complete_scan_run.called)
        self.assertTrue(sarif.called, "must write SARIF when requested")
        self.assertEqual([f["vulnerability"] for f in result], ["X"])


class StreamingParityTest(_MainTempCwd):
    """B2: streaming must dedup findings and route them through _enrich_and_report."""

    def test_streaming_dedups_and_finalizes(self):
        finding = {"vulnerability": "X", "target": "a", "status": "INFO", "url": "http://a", "port": 80}

        async def fake_stream(raw_targets, chunk_size):
            yield [{"scan_address": "a", "resolved_ip": "1.1.1.1", "open_ports": [80]}]

        async def fake_scan_ports(*args, **kwargs):
            return [({"scan_address": "a", "resolved_ip": "1.1.1.1"}, {"open_ports": [80]})]

        async def fake_chunk_services(*args, **kwargs):
            return [dict(finding), dict(finding)]  # duplicate → dedup should collapse to 1

        captured = {}

        async def fake_enrich(findings, run_id, output_dir, sarif_output):
            captured["findings"] = findings
            captured["run_id"] = run_id
            return findings

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main, "process_targets_streaming", fake_stream))
            es.enter_context(mock.patch.object(main, "scan_ports", fake_scan_ports))
            es.enter_context(mock.patch.object(main, "process_chunk_services", fake_chunk_services))
            es.enter_context(mock.patch.object(main, "save_port_scan_csv", mock.MagicMock()))
            es.enter_context(mock.patch.object(main, "_enrich_and_report", fake_enrich))

            asyncio.run(
                main.process_streaming_scan(
                    ["1.1.1.1"], 1, state_manager=mock.MagicMock(), run_id=42,
                )
            )

        self.assertEqual(captured.get("run_id"), 42)
        self.assertEqual(len(captured.get("findings", [])), 1, "duplicate findings must be deduped before finalize")


if __name__ == "__main__":
    unittest.main()
