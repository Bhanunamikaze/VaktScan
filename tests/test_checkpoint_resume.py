"""Phase 6 checkpoint-coverage tests (design doc T4 + T5).

These cover the durable-checkpoint story end to end, fully offline (no network,
no subprocesses, resolver monkeypatched to loopback):

* **T4** - an interrupt *mid-phase* must leave a resumable checkpoint on disk:
  the phase, the per-host ``scanned_ips`` set, and ``open_ports`` all reflect
  the progress made before the cancel.
* **T5** - re-running the identical command resumes and does NOT redo completed
  units, asserted per target type / mechanism via spies:
    - already-port-scanned hosts are skipped (``scan_ports`` unit skip),
    - completed ``{ip}:{port}:{service}`` triples are skipped
      (``scan_with_state_saving`` path, observed through the service scanners),
    - completed web URLs are skipped (``_probe_web_urls`` receives them),
    - the stable ``scan_id`` recomputes identically for ip / domain / file.

Style mirrors tests/test_resume.py (isolated VAKT_STATE_DIR + temp CWD).
"""

import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import ExitStack
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main  # noqa: E402
import port_scanner  # noqa: E402
import state_key  # noqa: E402
from scan_state import ScanStateManager  # noqa: E402


def _quiet_manager(*args, **kwargs):
    """A real ScanStateManager with its background save timer disabled (tests
    must not leave a lingering daemon thread that later writes into a torn-down
    temp dir). Saving/loading still hit disk for real."""
    mgr = ScanStateManager(*args, **kwargs)
    mgr._shutdown = True
    if mgr._save_timer:
        mgr._save_timer.cancel()
    return mgr


class _StateDirMixin:
    """Point state storage at an isolated temp dir via VAKT_STATE_DIR."""

    def _init_state_dir(self):
        self._prev_env = os.environ.get("VAKT_STATE_DIR")
        self._state_dir = tempfile.mkdtemp(prefix="vaktscan_state_")
        os.environ["VAKT_STATE_DIR"] = self._state_dir

    def _restore_state_dir(self):
        if self._prev_env is None:
            os.environ.pop("VAKT_STATE_DIR", None)
        else:
            os.environ["VAKT_STATE_DIR"] = self._prev_env
        shutil.rmtree(self._state_dir, ignore_errors=True)

    def _state_path(self, scan_id):
        return os.path.join(self._state_dir, f"{scan_id}.json")

    def _read_state(self, scan_id):
        with open(self._state_path(scan_id)) as f:
            return json.load(f)


class _MainTempCwd(_StateDirMixin, unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="vaktscan_ckpt_")
        os.chdir(self._tmp)
        self._init_state_dir()

    def tearDown(self):
        os.chdir(self._cwd)
        self._restore_state_dir()
        shutil.rmtree(self._tmp, ignore_errors=True)


async def _noop_async(*a, **k):
    return None


# ---------------------------------------------------------------------------
# T4 - state written on interrupt mid-phase.
# ---------------------------------------------------------------------------
class CheckpointOnInterruptTest(_MainTempCwd):
    def test_state_written_on_interrupt_mid_port_scan(self):
        """A Ctrl+C (CancelledError) during the port-scan phase must leave a
        state file whose phase == port_scanning and whose scanned_ips /
        open_ports reflect the host that finished before the interrupt."""
        targets_file, concurrency = "targets.txt", 100
        open(targets_file, "w").write("192.0.2.10\n")
        scan_id, canon, scope = "ip-4a4a4a4a4a4a4a4a", ["192.0.2.10"], "scope-sig-A"

        async def fake_process_targets(raw):
            return [{"scan_address": "192.0.2.10", "display_target": "192.0.2.10",
                     "resolved_ip": "192.0.2.10"}]

        async def fake_scan_ports(*a, **k):
            # state_manager is the 4th positional arg. Record real progress for
            # one host, then simulate the interrupt landing mid-phase.
            sm = a[3]
            sm.add_open_port("192.0.2.10", 80)
            sm.mark_ip_scanned("192.0.2.10")
            raise asyncio.CancelledError()

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main.nuclei_runner, "sync_nuclei_templates", return_value=None))
            es.enter_context(mock.patch.object(main, "inventory", mock.MagicMock()))
            es.enter_context(mock.patch.object(main, "ScanStateManager", _quiet_manager))
            es.enter_context(mock.patch.object(main, "process_targets", fake_process_targets))
            es.enter_context(mock.patch.object(main, "scan_ports", fake_scan_ports))
            with self.assertRaises((asyncio.CancelledError, KeyboardInterrupt)):
                asyncio.run(main.main(targets_file, concurrency,
                                      scan_id=scan_id, canonical_targets=canon, scope=scope))

        # The checkpoint must be on disk and reflect the interrupted phase.
        self.assertTrue(os.path.exists(self._state_path(scan_id)),
                        "no state file written on interrupt")
        state = self._read_state(scan_id)
        self.assertEqual(state["phase"], "port_scanning")
        self.assertIn("192.0.2.10", state.get("scanned_ips", []))
        self.assertIn("192.0.2.10", state.get("open_ports", {}))
        self.assertIn(80, state["open_ports"]["192.0.2.10"])
        self.assertFalse(state.get("completed"))


# ---------------------------------------------------------------------------
# T5a - resume skips hosts whose port sweep already completed (scan_ports unit).
# Exercises the real port_scanner.scan_ports; asyncio.open_connection is stubbed
# so no packets leave the box.
# ---------------------------------------------------------------------------
class PortScanResumeSkipTest(_StateDirMixin, unittest.TestCase):
    def setUp(self):
        self._init_state_dir()

    def tearDown(self):
        self._restore_state_dir()

    def test_scan_ports_skips_already_scanned_hosts(self):
        mgr = _quiet_manager("ip-5b5b5b5b5b5b5b5b", ["10.0.0.1", "10.0.0.2"], "scope-sig-A")
        # Host A already fully swept last run (with one open port); B is new.
        mgr.state["scanned_ips"] = ["10.0.0.1"]
        mgr.state["open_ports"] = {"10.0.0.1": [80]}

        target_a = {"scan_address": "10.0.0.1", "display_target": "10.0.0.1", "resolved_ip": "10.0.0.1"}
        target_b = {"scan_address": "10.0.0.2", "display_target": "10.0.0.2", "resolved_ip": "10.0.0.2"}

        attempted = []

        async def fake_open_connection(host, port):
            attempted.append(host)
            writer = mock.MagicMock()

            async def _wait_closed():
                return None

            writer.wait_closed = _wait_closed
            return mock.MagicMock(), writer

        with mock.patch("asyncio.open_connection", fake_open_connection):
            results = asyncio.run(port_scanner.scan_ports(
                [target_a, target_b], [80], 10, mgr))

        # Only the not-yet-scanned host got probed.
        self.assertEqual(set(attempted), {"10.0.0.2"},
                         "resume must not re-probe an already-scanned host")
        # B is now recorded as scanned; A remains scanned.
        scanned = set(mgr.get_scanned_ips())
        self.assertIn("10.0.0.2", scanned)
        self.assertIn("10.0.0.1", scanned)
        # Both hosts appear in the results; A keeps its persisted open ports.
        by_ip = {t["resolved_ip"]: data["open_ports"] for t, data in results}
        self.assertEqual(by_ip.get("10.0.0.1"), [80])
        self.assertEqual(by_ip.get("10.0.0.2"), [80])


# ---------------------------------------------------------------------------
# T5b - resume of an interrupted vulnerability_scanning phase skips the
# {ip}:{port}:{service} triples that already completed, and checkpoints the
# ones that newly finish. Drives main() end to end for an IP target.
# ---------------------------------------------------------------------------
class ServiceScanResumeSkipTest(_MainTempCwd):
    def test_resume_skips_completed_service_triples(self):
        targets_file, concurrency = "targets.txt", 100
        open(targets_file, "w").write("192.0.2.20\n")
        scan_id, canon, scope = "ip-6c6c6c6c6c6c6c6c", ["192.0.2.20"], "scope-sig-A"
        ip = "192.0.2.20"

        # Interrupted mid vuln-scan: elasticsearch@9200 already ran; grafana@3000
        # had not. Both ports are open in the persisted state.
        with open(self._state_path(scan_id), "w") as f:
            json.dump({
                "scan_id": scan_id, "canonical_targets": canon, "scope": scope,
                "phase": "vulnerability_scanning",
                "total_ips": 1, "total_combinations": 2,
                "port_scan_progress": {"completed_combinations": 2, "scanned_ips": [ip]},
                "scanned_ips": [ip],
                "open_ports": {ip: [9200, 3000]},
                "validated_services": {}, "vulnerabilities": [],
                "completed_service_scans": [f"{ip}:9200:elasticsearch"],
                "completed_recon_domains": [],
                "completed_web_urls": [], "completed": False,
            }, f)

        async def fake_process_targets(raw):
            return [{"scan_address": ip, "display_target": ip, "resolved_ip": ip}]

        async def fake_validate(service, target_obj, port):
            return True  # every candidate service validates

        # Record every per-service scanner that actually runs, keyed by the
        # service name, so we can prove the completed triple never re-runs.
        calls = []

        def _make_spy(name):
            async def _spy(target_obj, port, **k):
                calls.append((name, port))
                return []
            return _spy

        # Capture the ScanStateManager main() builds - the state file is cleaned
        # up when the scan completes, so assert the checkpoint in memory instead.
        managers = []

        def _capture_manager(*a, **k):
            mgr = _quiet_manager(*a, **k)
            managers.append(mgr)
            return mgr

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main.nuclei_runner, "sync_nuclei_templates", return_value=None))
            es.enter_context(mock.patch.object(main, "inventory", mock.MagicMock()))
            es.enter_context(mock.patch.object(main, "ScanStateManager", _capture_manager))
            es.enter_context(mock.patch.object(main, "process_targets", fake_process_targets))
            es.enter_context(mock.patch.object(main, "validate_service", fake_validate))
            es.enter_context(mock.patch.object(main, "_enrich_and_report", _noop_async))
            # Stub every service scanner so nothing touches the network.
            for _svc, _mod in main.SERVICE_TO_MODULE.items():
                es.enter_context(mock.patch.object(_mod, "run_scans", _make_spy(_svc)))
            asyncio.run(main.main(targets_file, concurrency, resume=True,
                                  scan_id=scan_id, canonical_targets=canon, scope=scope))

        # The completed elasticsearch:9200 triple was skipped; grafana:3000 ran.
        self.assertNotIn(("elasticsearch", 9200), calls,
                         "completed elasticsearch:9200 scan must not re-run on resume")
        self.assertIn(("grafana", 3000), calls,
                      "the not-yet-completed grafana:3000 scan must run on resume")

        # Both triples are checkpointed after the run (seeded + newly finished).
        self.assertEqual(len(managers), 1)
        done = managers[0].get_completed_service_scans()
        self.assertIn(f"{ip}:9200:elasticsearch", done)
        self.assertIn(f"{ip}:3000:grafana", done)


# ---------------------------------------------------------------------------
# T5c - resume of an interrupted web-probe phase passes the persisted
# completed_web_urls through to _probe_web_urls so they are skipped (domain
# target; resolver monkeypatched to loopback via a stubbed process_targets).
# ---------------------------------------------------------------------------
class WebProbeResumeSkipTest(_MainTempCwd):
    def test_resume_passes_completed_urls_to_probe(self):
        targets_file, concurrency = "targets.txt", 100
        open(targets_file, "w").write("host.example.com\n")
        scan_id, canon, scope = "host-7d7d7d7d7d7d7d7d", ["host.example.com"], "scope-sig-A"
        already = "http://host.example.com:80"
        with open(self._state_path(scan_id), "w") as f:
            json.dump({
                "scan_id": scan_id, "canonical_targets": canon, "scope": scope,
                "phase": "web_probing",
                "total_ips": 1, "total_combinations": 2,
                "port_scan_progress": {"completed_combinations": 2, "scanned_ips": ["127.0.0.1"]},
                "scanned_ips": ["127.0.0.1"],
                "open_ports": {"127.0.0.1": [80, 443]},
                "validated_services": {}, "vulnerabilities": [],
                "completed_service_scans": [],
                "completed_web_urls": [already], "completed": False,
            }, f)

        async def fake_process_targets(raw):
            # Resolver -> loopback (offline stand-in).
            return [{"scan_address": "host.example.com",
                     "display_target": "host.example.com",
                     "resolved_ip": "127.0.0.1"}]

        async def fake_scan_ports(*a, **k):
            raise AssertionError("port scan must not run when resuming the web-probe phase")

        async def fake_validate(*a, **k):
            return False

        capture = {}

        async def fake_probe(urls, output_dir, label, concurrency,
                             completed_urls=None, record_completed=None, batch_size=None,
                             enable_js_cve=True, record_findings=None):
            capture["urls"] = urls
            capture["completed_urls"] = completed_urls
            capture["record_completed"] = record_completed
            capture["record_findings"] = record_findings
            return []

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main.nuclei_runner, "sync_nuclei_templates", return_value=None))
            es.enter_context(mock.patch.object(main, "inventory", mock.MagicMock()))
            es.enter_context(mock.patch.object(main, "ScanStateManager", _quiet_manager))
            es.enter_context(mock.patch.object(main, "process_targets", fake_process_targets))
            es.enter_context(mock.patch.object(main, "scan_ports", fake_scan_ports))
            es.enter_context(mock.patch.object(main, "validate_service", fake_validate))
            es.enter_context(mock.patch.object(main, "_probe_web_urls", fake_probe))
            es.enter_context(mock.patch.object(main, "_enrich_and_report", _noop_async))
            asyncio.run(main.main(targets_file, concurrency, resume=True,
                                  scan_id=scan_id, canonical_targets=canon, scope=scope))

        self.assertIn("urls", capture)
        # The persisted completed URL is handed through so the probe can skip it.
        self.assertEqual(capture["completed_urls"], {already})
        self.assertTrue(callable(capture["record_completed"]))
        # Hostname attribution preserved (URLs use the hostname, not the IP).
        self.assertTrue(all("host.example.com" in u for u in capture["urls"]))


# ---------------------------------------------------------------------------
# T5d - the stable scan_id recomputes identically across runs for every target
# type (ip / domain / file), which is what lets an identical command re-resume.
# ---------------------------------------------------------------------------
class PortScanCancelDoesNotOvermarkTest(_StateDirMixin, unittest.TestCase):
    """Cancel-path over-marking regression (issue #2).

    ``check_port_with_progress`` runs its host-completion bookkeeping in a
    ``finally`` that fires on cancellation too. If it decremented the per-host
    counter unconditionally, an in-flight host whose probes are cancelled could
    reach 0 and be ``mark_ip_scanned``'d - so a resume would SKIP its un-probed
    ports (and could lose an entire host whose probes were all in-flight). This
    drives the REAL scan_ports/check_port_with_progress with one host completing
    and one host stuck in-flight when the cancel lands, and asserts only the
    completed host is checkpointed.
    """

    def setUp(self):
        self._init_state_dir()

    def tearDown(self):
        self._restore_state_dir()

    def test_inflight_host_not_marked_scanned_on_cancel(self):
        mgr = _quiet_manager("ip-cancel00000000", ["10.0.0.1", "10.0.0.2"], "scope-sig-A")
        target_a = {"scan_address": "10.0.0.1", "display_target": "10.0.0.1", "resolved_ip": "10.0.0.1"}
        target_b = {"scan_address": "10.0.0.2", "display_target": "10.0.0.2", "resolved_ip": "10.0.0.2"}

        async def run():
            hang = asyncio.Event()  # never set -> host B probes stay in-flight

            async def fake_open_connection(host, port):
                if host == "10.0.0.2":
                    await hang.wait()  # block until cancelled
                writer = mock.MagicMock()

                async def _wait_closed():
                    return None

                writer.wait_closed = _wait_closed
                return mock.MagicMock(), writer

            with mock.patch("asyncio.open_connection", fake_open_connection):
                # Large connect_timeout so host B truly stays in-flight (no
                # timeout completion) until we cancel; retries=0 for determinism.
                task = asyncio.create_task(port_scanner.scan_ports(
                    [target_a, target_b], [80, 81], 50, mgr,
                    connect_timeout=60, retries=0))
                # Wait until host A's full sweep is checkpointed (both its ports
                # completed), while host B is still blocked in-flight.
                for _ in range(1000):
                    await asyncio.sleep(0.005)
                    if "10.0.0.1" in mgr.state.get("scanned_ips", []):
                        break
                self.assertIn("10.0.0.1", mgr.state.get("scanned_ips", []),
                              "host A never completed - test setup issue")
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task

        asyncio.run(run())

        # The completed host is checkpointed; the in-flight (cancelled) host is
        # NOT - so a resume re-scans it rather than skipping its un-probed ports.
        self.assertIn("10.0.0.1", mgr.state.get("scanned_ips", []))
        self.assertNotIn("10.0.0.2", mgr.state.get("scanned_ips", []),
                         "an in-flight host whose probes were cancelled must not be "
                         "marked fully scanned")


class WebProbeBatchFindingsAtomicTest(unittest.TestCase):
    """Completed-batch findings must not be lost on a later-batch interrupt
    (issue #3).

    ``_probe_web_urls`` marks a batch's URLs completed (checkpointed + skipped
    on resume). If a batch's findings are only returned for a bulk add *after*
    the whole call, an interrupt during a later batch discards the earlier
    batch's findings while their URLs stay checkpointed - losing them forever.
    With ``record_findings`` supplied, each batch's findings are persisted
    before its URLs are marked done (no await between the two), so they survive.
    """

    def test_completed_batch_findings_persisted_before_later_batch_cancel(self):
        urls = [f"http://h{i}.example:80" for i in range(120)]  # 3 batches of 50/50/20
        recorded_findings = []
        completed_urls = []
        calls = {"n": 0}

        async def fake_batch(batch, output_dir, label, concurrency, enable_js_cve=True):
            calls["n"] += 1
            if calls["n"] == 1:
                return [{"vulnerability": "batch1-finding"}]
            # Interrupt lands during batch 2 (e.g. a Ctrl+C).
            raise asyncio.CancelledError()

        async def run():
            with mock.patch.object(main, "_run_web_probe_batch", fake_batch):
                await main._probe_web_urls(
                    urls, "/tmp", "lbl", 10,
                    completed_urls=None,
                    record_completed=lambda b: completed_urls.extend(b),
                    batch_size=50,
                    record_findings=lambda f: recorded_findings.append(f),
                )

        with self.assertRaises(asyncio.CancelledError):
            asyncio.run(run())

        # Batch 1's finding was persisted despite the batch-2 cancel...
        self.assertIn({"vulnerability": "batch1-finding"}, recorded_findings,
                      "a completed batch's findings must be persisted before a later "
                      "batch's interrupt can discard them")
        # ...and its 50 URLs were checkpointed (only after the findings), so a
        # resume that skips them still has the findings recorded.
        self.assertEqual(len(completed_urls), 50)


class ReconResumeSkipTest(_MainTempCwd):
    """Recon must not re-run (and re-add findings) on resume (issue #1).

    ``add_vulnerability`` does not dedup, so re-running a completed domain's
    recon pipeline on resume duplicates every recon finding. Drives main() in
    ``-m recon`` mode against a state whose domain already completed, and
    asserts the enumeration / passive / followups pipeline is skipped and no
    finding is duplicated.
    """

    def test_resume_skips_completed_recon_domain_no_duplicate_findings(self):
        scan_id, canon, scope = "example.com-recon00000000", ["example.com"], "scope-sig-A"
        subs = ["a.example.com", "b.example.com"]
        with open(self._state_path(scan_id), "w") as f:
            json.dump({
                "scan_id": scan_id, "canonical_targets": canon, "scope": scope,
                "phase": "recon",
                "total_ips": 0, "total_combinations": 0,
                "port_scan_progress": {"completed_combinations": 0, "scanned_ips": []},
                "scanned_ips": [], "open_ports": {}, "validated_services": {},
                "vulnerabilities": [{"vulnerability": "recon-F1"}],
                "completed_service_scans": [],
                "completed_recon_domains": ["example.com"],
                "recon_results": {"example.com": subs},
                "completed_web_urls": [], "completed": False,
            }, f)

        ran = {"scanner": 0, "passive": 0, "followups": 0}

        class _SpyScanner:
            def __init__(self, domain, wordlist=None, detailed_dashboard=True):
                ran["scanner"] += 1

            async def run_all(self):
                return (os.path.join("reports", "subs.txt"), ["should-not-run"])

        async def spy_passive(*a, **k):
            ran["passive"] += 1
            return ([], [], [])

        async def spy_followups(*a, **k):
            ran["followups"] += 1
            return [{"vulnerability": "dup"}]

        async def empty_targets(raw):
            return []  # halt cleanly right after the recon block ("no targets")

        fake_dashboard = mock.MagicMock()
        fake_dashboard.active = False
        managers = []

        def _capture(*a, **k):
            m = _quiet_manager(*a, **k)
            managers.append(m)
            return m

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main.nuclei_runner, "sync_nuclei_templates", return_value=None))
            es.enter_context(mock.patch.object(main, "inventory", mock.MagicMock()))
            es.enter_context(mock.patch("modules.dashboard.LiveDashboard", return_value=fake_dashboard))
            es.enter_context(mock.patch.object(main, "ScanStateManager", _capture))
            es.enter_context(mock.patch.object(main.recon, "ReconScanner", _SpyScanner))
            es.enter_context(mock.patch.object(main, "_run_parallel_passive", spy_passive))
            es.enter_context(mock.patch.object(main, "run_recon_followups", spy_followups))
            es.enter_context(mock.patch.object(main, "process_targets", empty_targets))
            asyncio.run(main.main(None, 1, recon_domains=["example.com"],
                                  scan_found=True, no_dork=True, resume=True,
                                  scan_id=scan_id, canonical_targets=canon, scope=scope))

        self.assertEqual(ran["scanner"], 0, "subdomain enumeration must be skipped on resume")
        self.assertEqual(ran["passive"], 0, "passive recon must be skipped on resume")
        self.assertEqual(ran["followups"], 0, "run_recon_followups must be skipped on resume")
        self.assertEqual(len(managers), 1)
        self.assertEqual(managers[0].get_vulnerabilities(), [{"vulnerability": "recon-F1"}],
                         "resuming a completed recon domain must not re-add its findings")


class ScanIdStabilityPerTargetTypeTest(unittest.TestCase):
    def _id(self, target_type, raw, label):
        canon = state_key.canonical_targets(target_type, raw, self._parse)
        scope = state_key.scope_signature({"ports": None, "module_filter": None})
        return state_key.compute_scan_id(label, canon, scope), canon

    @staticmethod
    def _parse(path):
        with open(path) as f:
            return [ln.strip() for ln in f if ln.strip()]

    def test_ip_domain_file_ids_are_stable(self):
        # ip
        id1, c1 = self._id("ip", "192.0.2.10", "192.0.2.10")
        id2, c2 = self._id("ip", "192.0.2.10", "192.0.2.10")
        self.assertEqual(id1, id2)
        self.assertEqual(c1, ["192.0.2.10"])

        # domain (case / trailing dot normalized to the same canonical form)
        idd1, cd1 = self._id("domain", "Example.COM.", "Example.COM.")
        idd2, cd2 = self._id("domain", "example.com", "example.com")
        self.assertEqual(cd1, cd2, "domain canonicalization must be stable")
        self.assertEqual(idd1.split("-")[-1], idd2.split("-")[-1],
                         "the digest (identity) must match regardless of label casing")

        # file (rename with identical contents -> same id)
        with tempfile.TemporaryDirectory() as d:
            p1 = os.path.join(d, "targets.txt")
            p2 = os.path.join(d, "renamed.txt")
            for p in (p1, p2):
                with open(p, "w") as f:
                    f.write("192.0.2.10\nexample.com\n")
            idf1, cf1 = self._id("file", p1, "targets")
            idf2, cf2 = self._id("file", p2, "renamed")
            self.assertEqual(cf1, cf2)
            self.assertEqual(idf1.split("-")[-1], idf2.split("-")[-1],
                             "a renamed file with identical contents must resume")


if __name__ == "__main__":
    unittest.main()
