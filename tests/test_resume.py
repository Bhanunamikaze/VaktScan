"""Tests for scan resume (B8).

Covers the two things the resume story hinges on:

* **Root-cause bug** - ``--resume`` must actually LOAD the persisted state.
  The old ``resume or state_manager.load_existing_state()`` short-circuited when
  the flag was set, so ``--resume`` silently skipped the load and restarted the
  scan from scratch. ``main._decide_resume`` must load state unconditionally.
* **Resumable web-probe phase** - an interrupted httpx/web-probe must resume from
  the URLs it had not reached yet (persisted ``completed_web_urls``), keep its
  hostname attribution, and be a first-class phase rather than being skipped.

Post-Phase-4 the state identity is a stable ``scan_id`` derived from the
normalized target set + scope config (see ``state_key.py``), and state files
live under ``VAKT_STATE_DIR`` (``./.vaktscan/state`` by default) instead of a
CWD ``scan_state_<hash>.json``. These tests seed against that scheme.

Everything here is fully offline: network/subprocess collaborators are mocked.
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
from scan_state import ScanStateManager  # noqa: E402


def _quiet_manager(scan_id, canonical_targets, scope):
    """A ScanStateManager with its background save timer disabled (tests don't
    want a lingering 2-minute daemon thread)."""
    mgr = ScanStateManager(scan_id, canonical_targets, scope)
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


class _TempCwd(_StateDirMixin, unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="vaktscan_resume_")
        os.chdir(self._tmp)
        self._init_state_dir()

    def tearDown(self):
        os.chdir(self._cwd)
        self._restore_state_dir()
        shutil.rmtree(self._tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Root cause: --resume must load persisted state
# ---------------------------------------------------------------------------
class DecideResumeTest(_TempCwd):
    SCAN_ID = "targets-deadbeefcafed00d"
    CANON = ["192.0.2.10"]
    SCOPE = "scope-sig-A"

    def _seed(self):
        seed = _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE)
        seed.state["phase"] = "vulnerability_scanning_complete"
        seed.state["open_ports"] = {"192.0.2.10": [80, 443]}
        seed.state["vulnerabilities"] = [{"vulnerability": "seeded", "target": "192.0.2.10"}]
        seed.save_state(force=True)

    def test_resume_flag_still_loads_saved_state(self):
        """The regression: --resume ("require" mode) must restore the saved
        phase/ports, not short-circuit past the load and start fresh."""
        self._seed()
        mgr = _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE)
        self.assertEqual(mgr.state["phase"], "initializing")  # fresh before load

        is_resume = main._decide_resume(mgr, "require")

        self.assertTrue(is_resume)
        self.assertEqual(mgr.state["phase"], "vulnerability_scanning_complete")
        self.assertEqual(mgr.state["open_ports"], {"192.0.2.10": [80, 443]})
        self.assertEqual(len(mgr.state["vulnerabilities"]), 1)

    def test_auto_detect_without_flag_also_resumes(self):
        self._seed()
        mgr = _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE)
        is_resume = main._decide_resume(mgr, "auto")
        self.assertTrue(is_resume)
        self.assertEqual(mgr.state["phase"], "vulnerability_scanning_complete")

    def test_no_state_file_starts_fresh(self):
        mgr = _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE)
        # Auto-resume with nothing to resume from just starts fresh.
        self.assertFalse(main._decide_resume(mgr, "auto"))
        # --resume ("require") with nothing to resume MUST error out (Phase 5).
        with self.assertRaises(SystemExit):
            main._decide_resume(mgr, "require")
        self.assertEqual(mgr.state["phase"], "initializing")


# ---------------------------------------------------------------------------
# Fail-safe: a corrupt / mismatched state file must not crash and must not
# silently masquerade as a valid resume.
# ---------------------------------------------------------------------------
class CorruptStateFailSafeTest(_TempCwd):
    SCAN_ID = "targets-0011223344556677"
    CANON = ["192.0.2.10"]
    SCOPE = "scope-sig-A"

    def test_corrupt_json_starts_fresh(self):
        with open(self._state_path(self.SCAN_ID), "w") as f:
            f.write("{ this is not valid json ")
        mgr = _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE)
        # Must not raise, must report "fresh", must keep default state intact.
        self.assertFalse(mgr.load_existing_state())
        self.assertEqual(mgr.state["phase"], "initializing")
        self.assertEqual(mgr.state["open_ports"], {})

    def test_state_for_different_targets_is_ignored(self):
        # Same scan_id on disk but DIFFERENT canonical targets => collision:
        # must NOT resume and must NOT clobber the stored state.
        with open(self._state_path(self.SCAN_ID), "w") as f:
            json.dump({"canonical_targets": ["203.0.113.9"], "scope": self.SCOPE,
                       "phase": "port_scanning_complete"}, f)
        mgr = _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE)
        self.assertFalse(mgr.load_existing_state())
        self.assertEqual(mgr.state["phase"], "initializing")
        # Writes were relocated to <id>-1.json so the old state is preserved.
        self.assertTrue(mgr.state_file.endswith(f"{self.SCAN_ID}-1.json"))

    def test_state_for_different_scope_is_ignored(self):
        with open(self._state_path(self.SCAN_ID), "w") as f:
            json.dump({"canonical_targets": self.CANON, "scope": "scope-sig-B",
                       "phase": "port_scanning_complete"}, f)
        mgr = _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE)
        self.assertFalse(mgr.load_existing_state())
        self.assertEqual(mgr.state["phase"], "initializing")

    def test_old_state_without_web_urls_key_loads(self):
        """A state written before the web-probe checkpoint existed must still load
        (backward compatibility) as long as its identity matches."""
        with open(self._state_path(self.SCAN_ID), "w") as f:
            json.dump({"canonical_targets": self.CANON, "scope": self.SCOPE,
                       "phase": "port_scanning_complete",
                       "open_ports": {"192.0.2.10": [80]}}, f)
        mgr = _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE)
        self.assertTrue(mgr.load_existing_state())
        self.assertEqual(mgr.get_completed_web_urls(), set())


# ---------------------------------------------------------------------------
# Legacy migration shim: a lone pre-Phase-4 CWD scan_state_*.json is adopted.
# ---------------------------------------------------------------------------
class LegacyMigrationShimTest(_TempCwd):
    def test_single_legacy_cwd_state_is_migrated(self):
        # Pre-Phase-4 file in the CWD, keyed off the old md5 scheme.
        with open("scan_state_deadbeef.json", "w") as f:
            json.dump({"targets_file": "targets.txt", "concurrency": 100,
                       "phase": "port_scanning_complete",
                       "open_ports": {"192.0.2.10": [80]},
                       "port_scan_progress": {"completed_combinations": 1},
                       "total_combinations": 1, "vulnerabilities": []}, f)
        mgr = _quiet_manager("targets-cafebabe0000ffff", ["192.0.2.10"], "scope-sig-A")
        self.assertTrue(mgr.load_existing_state())
        self.assertEqual(mgr.state["phase"], "port_scanning_complete")
        self.assertEqual(mgr.state["open_ports"], {"192.0.2.10": [80]})

    def test_ambiguous_legacy_states_not_guessed(self):
        for h in ("aaaa", "bbbb"):
            with open(f"scan_state_{h}.json", "w") as f:
                json.dump({"phase": "port_scanning", "open_ports": {}}, f)
        mgr = _quiet_manager("targets-cafebabe0000ffff", ["192.0.2.10"], "scope-sig-A")
        self.assertFalse(mgr.load_existing_state())


# ---------------------------------------------------------------------------
# State manager: web-probe checkpoint round-trips through disk.
# ---------------------------------------------------------------------------
class WebUrlCheckpointStateTest(_TempCwd):
    SCAN_ID = "targets-1234567890abcdef"
    CANON = ["192.0.2.10"]
    SCOPE = "scope-sig-A"

    def test_add_and_reload_completed_web_urls(self):
        mgr = _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE)
        mgr.add_completed_web_urls(["http://a:80", "https://a:443"])
        mgr.add_completed_web_urls(["http://a:80", "http://b:80"])  # dedup
        self.assertEqual(mgr.get_completed_web_urls(),
                         {"http://a:80", "https://a:443", "http://b:80"})
        # Reload from disk in a fresh manager.
        mgr2 = _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE)
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


class _MainTempCwd(_StateDirMixin, unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="vaktscan_resume_main_")
        os.chdir(self._tmp)
        self._init_state_dir()

    def tearDown(self):
        os.chdir(self._cwd)
        self._restore_state_dir()
        shutil.rmtree(self._tmp, ignore_errors=True)


class ResumeDoesNotRescanTest(_MainTempCwd):
    def test_resume_skips_portscan_and_keeps_findings(self):
        targets_file, concurrency = "targets.txt", 100
        open(targets_file, "w").write("192.0.2.10\n")
        scan_id, canon, scope = "targets-a1b2c3d4e5f60718", ["192.0.2.10"], "scope-sig-A"
        seeded = {"status": "VULNERABLE", "vulnerability": "seeded-cve",
                  "target": "192.0.2.10", "details": "d", "url": "http://192.0.2.10"}
        with open(self._state_path(scan_id), "w") as f:
            json.dump({
                "scan_id": scan_id, "canonical_targets": canon, "scope": scope,
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
            asyncio.run(main.main(targets_file, concurrency, resume=True,
                                  scan_id=scan_id, canonical_targets=canon, scope=scope))

        self.assertFalse(scan_ports_spy.called,
                         "resume must NOT re-run the port scan for an already-scanned state")
        self.assertIn("findings", captured)
        self.assertIn("seeded-cve", [f.get("vulnerability") for f in captured["findings"]])


class ResumeWebProbePhaseTest(_MainTempCwd):
    def test_resume_web_probe_skips_completed_and_keeps_hostname(self):
        targets_file, concurrency = "targets.txt", 100
        open(targets_file, "w").write("host.example.com\n")
        scan_id, canon, scope = "targets-b2c3d4e5f6071829", ["host.example.com"], "scope-sig-A"
        already_done = "http://host.example.com:80"
        with open(self._state_path(scan_id), "w") as f:
            json.dump({
                "scan_id": scan_id, "canonical_targets": canon, "scope": scope,
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
                             completed_urls=None, record_completed=None, batch_size=None,
                             enable_js_cve=True, record_findings=None):
            capture["urls"] = urls
            capture["completed_urls"] = completed_urls
            capture["record_completed"] = record_completed
            capture["record_findings"] = record_findings
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
            asyncio.run(main.main(targets_file, concurrency, resume=True,
                                  scan_id=scan_id, canonical_targets=canon, scope=scope))

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
