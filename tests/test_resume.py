"""Tests for scan resume (B8).

Covers the two things the resume story hinges on:

* **Root-cause bug** — ``--resume`` must actually LOAD the persisted state.
  The old ``resume or state_manager.load_existing_state()`` short-circuited when
  the flag was set, so ``--resume`` silently skipped the load and restarted the
  scan from scratch. ``main._decide_resume`` must load state unconditionally.
* **Resumable web-probe phase** — an interrupted httpx/web-probe must resume from
  the URLs it had not reached yet (persisted ``completed_web_urls``), keep its
  hostname attribution, and be a first-class phase rather than being skipped.

Everything here is fully offline: network/subprocess collaborators are mocked.
"""

import asyncio
import hashlib
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
from scan_state import ScanStateManager  # noqa: E402


def _quiet_manager(targets_file, concurrency):
    """A ScanStateManager with its background save timer disabled (tests don't
    want a lingering 2-minute daemon thread)."""
    mgr = ScanStateManager(targets_file, concurrency)
    mgr._shutdown = True
    if mgr._save_timer:
        mgr._save_timer.cancel()
    return mgr


def _state_file_for(targets_file, concurrency):
    h = hashlib.md5(f"{targets_file}_{concurrency}".encode()).hexdigest()[:8]
    return f"scan_state_{h}.json"


class _TempCwd(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="vaktscan_resume_")
        os.chdir(self._tmp)

    def tearDown(self):
        os.chdir(self._cwd)
        shutil.rmtree(self._tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Root cause: --resume must load persisted state
# ---------------------------------------------------------------------------
class DecideResumeTest(_TempCwd):
    def _seed(self, targets_file="targets.txt", concurrency=100):
        open(targets_file, "w").write("192.0.2.10\n")
        seed = _quiet_manager(targets_file, concurrency)
        seed.state["phase"] = "vulnerability_scanning_complete"
        seed.state["open_ports"] = {"192.0.2.10": [80, 443]}
        seed.state["vulnerabilities"] = [{"vulnerability": "seeded", "target": "192.0.2.10"}]
        seed.save_state(force=True)
        return targets_file, concurrency

    def test_resume_flag_still_loads_saved_state(self):
        """The regression: --resume (flag=True) must restore the saved phase/ports,
        not short-circuit past the load and start fresh."""
        targets_file, concurrency = self._seed()
        mgr = _quiet_manager(targets_file, concurrency)
        self.assertEqual(mgr.state["phase"], "initializing")  # fresh before load

        is_resume = main._decide_resume(mgr, resume_flag=True)

        self.assertTrue(is_resume)
        self.assertEqual(mgr.state["phase"], "vulnerability_scanning_complete")
        self.assertEqual(mgr.state["open_ports"], {"192.0.2.10": [80, 443]})
        self.assertEqual(len(mgr.state["vulnerabilities"]), 1)

    def test_auto_detect_without_flag_also_resumes(self):
        targets_file, concurrency = self._seed()
        mgr = _quiet_manager(targets_file, concurrency)
        is_resume = main._decide_resume(mgr, resume_flag=False)
        self.assertTrue(is_resume)
        self.assertEqual(mgr.state["phase"], "vulnerability_scanning_complete")

    def test_no_state_file_starts_fresh(self):
        open("targets.txt", "w").write("192.0.2.10\n")
        mgr = _quiet_manager("targets.txt", 100)
        self.assertFalse(main._decide_resume(mgr, resume_flag=False))
        # A --resume with nothing to resume from is treated as resume-mode but
        # simply has no saved state to restore (phase stays fresh).
        self.assertTrue(main._decide_resume(mgr, resume_flag=True))
        self.assertEqual(mgr.state["phase"], "initializing")


# ---------------------------------------------------------------------------
# Fail-safe: a corrupt / mismatched state file must not crash and must not
# silently masquerade as a valid resume.
# ---------------------------------------------------------------------------
class CorruptStateFailSafeTest(_TempCwd):
    def test_corrupt_json_starts_fresh(self):
        open("targets.txt", "w").write("192.0.2.10\n")
        with open(_state_file_for("targets.txt", 100), "w") as f:
            f.write("{ this is not valid json ")
        mgr = _quiet_manager("targets.txt", 100)
        # Must not raise, must report "fresh", must keep default state intact.
        self.assertFalse(mgr.load_existing_state())
        self.assertEqual(mgr.state["phase"], "initializing")
        self.assertEqual(mgr.state["open_ports"], {})

    def test_state_for_different_targets_is_ignored(self):
        open("targets.txt", "w").write("192.0.2.10\n")
        with open(_state_file_for("targets.txt", 100), "w") as f:
            json.dump({"targets_file": "someone_elses.txt", "concurrency": 100,
                       "phase": "port_scanning_complete"}, f)
        mgr = _quiet_manager("targets.txt", 100)
        self.assertFalse(mgr.load_existing_state())
        self.assertEqual(mgr.state["phase"], "initializing")

    def test_old_state_without_web_urls_key_loads(self):
        """State files written before the web-probe checkpoint existed must still
        load (backward compatibility)."""
        open("targets.txt", "w").write("192.0.2.10\n")
        with open(_state_file_for("targets.txt", 100), "w") as f:
            json.dump({"targets_file": "targets.txt", "concurrency": 100,
                       "phase": "port_scanning_complete",
                       "open_ports": {"192.0.2.10": [80]}}, f)
        mgr = _quiet_manager("targets.txt", 100)
        self.assertTrue(mgr.load_existing_state())
        self.assertEqual(mgr.get_completed_web_urls(), set())


# ---------------------------------------------------------------------------
# State manager: web-probe checkpoint round-trips through disk.
# ---------------------------------------------------------------------------
class WebUrlCheckpointStateTest(_TempCwd):
    def test_add_and_reload_completed_web_urls(self):
        open("targets.txt", "w").write("192.0.2.10\n")
        mgr = _quiet_manager("targets.txt", 100)
        mgr.add_completed_web_urls(["http://a:80", "https://a:443"])
        mgr.add_completed_web_urls(["http://a:80", "http://b:80"])  # dedup
        self.assertEqual(mgr.get_completed_web_urls(),
                         {"http://a:80", "https://a:443", "http://b:80"})
        # Reload from disk in a fresh manager.
        mgr2 = _quiet_manager("targets.txt", 100)
        self.assertTrue(mgr2.load_existing_state())
        self.assertEqual(mgr2.get_completed_web_urls(),
                         {"http://a:80", "https://a:443", "http://b:80"})


# ---------------------------------------------------------------------------
# _probe_web_urls: skips completed URLs and checkpoints per batch.
# ---------------------------------------------------------------------------
class ProbeWebUrlsCheckpointTest(unittest.TestCase):
    def _mock_runners(self, es, probed_capture):
        class FakeHttpx:
            def __init__(self, output_dir=None):
                pass

            async def run_httpx(self, urls, concurrency):
                probed_capture.extend(urls)
                return [{"url": u} for u in urls]

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
                return {"findings": []}

        async def fake_wc(urls, concurrency):
            return []

        es.enter_context(mock.patch.object(main.httpx_runner, "HTTPXRunner", FakeHttpx))
        es.enter_context(mock.patch.object(main.nuclei_runner, "NucleiRunner", FakeNuclei))
        es.enter_context(mock.patch.object(main.web_checks, "run_checks", fake_wc))
        es.enter_context(mock.patch.object(main.dir_enum, "DirEnumerator", FakeDir))
        es.enter_context(mock.patch.object(main.js_paths, "JSPathsScanner", FakeJS))

    def test_skips_completed_and_records(self):
        probed = []
        recorded = []
        with ExitStack() as es:
            self._mock_runners(es, probed)
            asyncio.run(main._probe_web_urls(
                ["http://a:80", "http://b:80", "http://c:80"],
                "reports", "lbl", 10,
                completed_urls={"http://b:80"},
                record_completed=lambda urls: recorded.extend(urls),
                batch_size=50,
            ))
        # b was already done -> never probed; a and c are.
        self.assertNotIn("http://b:80", probed)
        self.assertEqual(set(probed), {"http://a:80", "http://c:80"})
        self.assertEqual(set(recorded), {"http://a:80", "http://c:80"})

    def test_batches_checkpoint_incrementally(self):
        probed = []
        recorded_batches = []
        with ExitStack() as es:
            self._mock_runners(es, probed)
            urls = [f"http://h{i}:80" for i in range(5)]
            asyncio.run(main._probe_web_urls(
                urls, "reports", "lbl", 10,
                completed_urls=set(),
                record_completed=lambda b: recorded_batches.append(list(b)),
                batch_size=2,
            ))
        # 5 URLs / batch 2 -> 3 checkpoint calls (2, 2, 1).
        self.assertEqual([len(b) for b in recorded_batches], [2, 2, 1])
        self.assertEqual(len(probed), 5)

    def test_no_recorder_runs_single_batch(self):
        """Default (no checkpoint hooks) behavior is unchanged: one batch."""
        probed = []
        with ExitStack() as es:
            self._mock_runners(es, probed)
            urls = [f"http://h{i}:80" for i in range(5)]
            findings = asyncio.run(main._probe_web_urls(urls, "reports", "lbl", 10))
        self.assertEqual(len(probed), 5)
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# Integration: main() honors saved state on --resume instead of re-scanning.
# ---------------------------------------------------------------------------
async def _noop_async(*a, **k):
    return None


class _MainTempCwd(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="vaktscan_resume_main_")
        os.chdir(self._tmp)

    def tearDown(self):
        os.chdir(self._cwd)
        shutil.rmtree(self._tmp, ignore_errors=True)


class ResumeDoesNotRescanTest(_MainTempCwd):
    def test_resume_skips_portscan_and_keeps_findings(self):
        targets_file, concurrency = "targets.txt", 100
        open(targets_file, "w").write("192.0.2.10\n")
        seeded = {"status": "VULNERABLE", "vulnerability": "seeded-cve",
                  "target": "192.0.2.10", "details": "d", "url": "http://192.0.2.10"}
        with open(_state_file_for(targets_file, concurrency), "w") as f:
            json.dump({
                "targets_file": targets_file, "concurrency": concurrency,
                "phase": "vulnerability_scanning_complete",
                "total_ips": 1, "total_combinations": 1,
                "port_scan_progress": {"completed_combinations": 1, "scanned_ips": []},
                "open_ports": {"192.0.2.10": [80]},
                "validated_services": {}, "vulnerabilities": [seeded],
                "completed_web_urls": [], "completed": False,
            }, f)

        scan_ports_spy = mock.MagicMock()

        async def fake_scan_ports(*a, **k):
            scan_ports_spy(*a, **k)
            return []

        async def fake_process_targets(raw):
            return [{"scan_address": "192.0.2.10", "display_target": "192.0.2.10",
                     "resolved_ip": "192.0.2.10"}]

        captured = {}

        async def fake_enrich(findings, run_id, output_dir, sarif_output, output_format=None):
            captured["findings"] = findings
            return findings

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main.nuclei_runner, "sync_nuclei_templates", return_value=None))
            es.enter_context(mock.patch.object(main, "inventory", mock.MagicMock()))
            es.enter_context(mock.patch.object(main, "process_targets", fake_process_targets))
            es.enter_context(mock.patch.object(main, "scan_ports", fake_scan_ports))
            es.enter_context(mock.patch.object(main, "_enrich_and_report", fake_enrich))
            asyncio.run(main.main(targets_file, concurrency, resume=True))

        self.assertFalse(scan_ports_spy.called,
                         "resume must NOT re-run the port scan for an already-scanned state")
        self.assertIn("findings", captured)
        self.assertIn("seeded-cve", [f.get("vulnerability") for f in captured["findings"]])


class ResumeWebProbePhaseTest(_MainTempCwd):
    def test_resume_web_probe_skips_completed_and_keeps_hostname(self):
        targets_file, concurrency = "targets.txt", 100
        open(targets_file, "w").write("host.example.com\n")
        already_done = "http://host.example.com:80"
        with open(_state_file_for(targets_file, concurrency), "w") as f:
            json.dump({
                "targets_file": targets_file, "concurrency": concurrency,
                "phase": "web_probing",
                "total_ips": 1, "total_combinations": 1,
                "port_scan_progress": {"completed_combinations": 1, "scanned_ips": []},
                "open_ports": {"192.0.2.10": [80, 443]},
                "validated_services": {}, "vulnerabilities": [],
                "completed_web_urls": [already_done], "completed": False,
            }, f)

        async def fake_process_targets(raw):
            # Hostname-bearing object resolving to the saved IP.
            return [{"scan_address": "host.example.com",
                     "display_target": "host.example.com",
                     "resolved_ip": "192.0.2.10"}]

        async def fake_scan_ports(*a, **k):
            raise AssertionError("port scan must not run when resuming the web-probe phase")

        capture = {}

        async def fake_probe(urls, output_dir, label, concurrency,
                             completed_urls=None, record_completed=None, batch_size=None):
            capture["urls"] = urls
            capture["completed_urls"] = completed_urls
            capture["record_completed"] = record_completed
            return []

        async def fake_validate(*a, **k):
            return False

        with ExitStack() as es:
            es.enter_context(mock.patch.object(main.nuclei_runner, "sync_nuclei_templates", return_value=None))
            es.enter_context(mock.patch.object(main, "inventory", mock.MagicMock()))
            es.enter_context(mock.patch.object(main, "process_targets", fake_process_targets))
            es.enter_context(mock.patch.object(main, "scan_ports", fake_scan_ports))
            es.enter_context(mock.patch.object(main, "validate_service", fake_validate))
            es.enter_context(mock.patch.object(main, "_probe_web_urls", fake_probe))
            es.enter_context(mock.patch.object(main, "_enrich_and_report", _noop_async))
            asyncio.run(main.main(targets_file, concurrency, resume=True))

        # Hostname attribution preserved on resume: URLs use the hostname, not the IP.
        self.assertIn("urls", capture)
        self.assertTrue(all("host.example.com" in u for u in capture["urls"]))
        self.assertFalse(any("192.0.2.10" in u for u in capture["urls"]))
        # The persisted completed-URL set is passed through so it can be skipped.
        self.assertEqual(capture["completed_urls"], {already_done})
        # And a recorder is wired so further progress checkpoints.
        self.assertTrue(callable(capture["record_completed"]))


if __name__ == "__main__":
    unittest.main()
