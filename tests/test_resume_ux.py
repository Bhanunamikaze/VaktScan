"""Phase-5 resume UX tests.

Covers the CLI resume surface added in Phase 5:

* ``--fresh`` / ``--no-resume``  - ignore & overwrite existing state.
* ``--resume`` (redefined)       - REQUIRE a resumable state; error if none.
* ``--resume-id <scan_id>``      - resume a specific saved scan; refuse on a
                                   stored targets/scope mismatch.
* ``--list-resumable``           - print the index rows and exit.
* default AUTO-RESUME            - recompute the id and resume a matching,
                                   non-completed state; a finished scan starts
                                   fresh.
* the ``.vaktscan/state/index.json`` maintained on every save.
* the non-scope config-diff warning.

Everything is offline: state storage is redirected to an isolated temp dir via
``VAKT_STATE_DIR`` and network/subprocess collaborators are mocked.
"""

import asyncio
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from contextlib import ExitStack
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main  # noqa: E402
import scan_state  # noqa: E402
from scan_state import ScanStateManager  # noqa: E402

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _quiet_manager(scan_id, canonical_targets, scope, **kw):
    """A ScanStateManager with its 2-minute background save timer disabled."""
    mgr = ScanStateManager(scan_id, canonical_targets, scope, **kw)
    mgr._shutdown = True
    if mgr._save_timer:
        mgr._save_timer.cancel()
    return mgr


class _StateDirMixin:
    """Point state storage at an isolated temp dir via VAKT_STATE_DIR and run in
    an isolated CWD (so the legacy ``scan_state_*.json`` shim never adopts a
    stray file from the repo root)."""

    def setUp(self):
        self._prev_env = os.environ.get("VAKT_STATE_DIR")
        self._state_dir = tempfile.mkdtemp(prefix="vaktscan_ux_state_")
        os.environ["VAKT_STATE_DIR"] = self._state_dir  # absolute -> survives chdir
        self._cwd = os.getcwd()
        self._work_dir = tempfile.mkdtemp(prefix="vaktscan_ux_cwd_")
        os.chdir(self._work_dir)

    def tearDown(self):
        os.chdir(self._cwd)
        if self._prev_env is None:
            os.environ.pop("VAKT_STATE_DIR", None)
        else:
            os.environ["VAKT_STATE_DIR"] = self._prev_env
        shutil.rmtree(self._state_dir, ignore_errors=True)
        shutil.rmtree(self._work_dir, ignore_errors=True)

    def _state_path(self, scan_id):
        return os.path.join(self._state_dir, f"{scan_id}.json")

    def _seed_state(self, scan_id, canon, scope, phase="port_scanning_complete",
                    completed=False, non_scope_config=None):
        with open(self._state_path(scan_id), "w") as f:
            json.dump({
                "scan_id": scan_id, "canonical_targets": canon, "scope": scope,
                "non_scope_config": non_scope_config or {},
                "phase": phase,
                "total_ips": 1, "total_combinations": 10,
                "port_scan_progress": {"completed_combinations": 4, "scanned_ips": []},
                "open_ports": {"192.0.2.10": [80]},
                "validated_services": {}, "vulnerabilities": [],
                "completed_web_urls": [], "completed": completed,
            }, f)


# ---------------------------------------------------------------------------
# _decide_resume: the four modes.
# ---------------------------------------------------------------------------
class DecideResumeModesTest(_StateDirMixin, unittest.TestCase):
    SCAN_ID = "t-1111222233334444"
    CANON = ["192.0.2.10"]
    SCOPE = "scope-A"

    def _mgr(self, **kw):
        return _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE, **kw)

    # --- default AUTO-RESUME ---
    def test_auto_resumes_matching_noncompleted_state(self):
        self._seed_state(self.SCAN_ID, self.CANON, self.SCOPE, phase="web_probing")
        mgr = self._mgr()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(main._decide_resume(mgr, "auto"))
        self.assertEqual(mgr.state["phase"], "web_probing")

    def test_auto_starts_fresh_when_no_state(self):
        mgr = self._mgr()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(main._decide_resume(mgr, "auto"))
        self.assertEqual(mgr.state["phase"], "initializing")

    def test_auto_resets_completed_state_to_fresh(self):
        # A finished scan is NOT resumable - auto must start over cleanly.
        self._seed_state(self.SCAN_ID, self.CANON, self.SCOPE,
                         phase="completed", completed=True)
        mgr = self._mgr()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(main._decide_resume(mgr, "auto"))
        self.assertEqual(mgr.state["phase"], "initializing")
        self.assertEqual(mgr.state["open_ports"], {})

    # --- --fresh / --no-resume ---
    def test_fresh_ignores_existing_state(self):
        self._seed_state(self.SCAN_ID, self.CANON, self.SCOPE, phase="web_probing")
        mgr = self._mgr()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(main._decide_resume(mgr, "fresh"))
        # Existing state must NOT be loaded.
        self.assertEqual(mgr.state["phase"], "initializing")
        self.assertEqual(mgr.state["open_ports"], {})

    # --- --resume (require) ---
    def test_require_errors_when_no_state(self):
        mgr = self._mgr()
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                main._decide_resume(mgr, "require")

    def test_require_resumes_when_state_exists(self):
        self._seed_state(self.SCAN_ID, self.CANON, self.SCOPE)
        mgr = self._mgr()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(main._decide_resume(mgr, "require"))

    # --- --resume-id ---
    def test_resume_id_resumes_matching(self):
        self._seed_state(self.SCAN_ID, self.CANON, self.SCOPE)
        mgr = self._mgr()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(main._decide_resume(mgr, "id"))

    def test_resume_id_errors_when_no_state(self):
        mgr = self._mgr()
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                main._decide_resume(mgr, "id")

    def test_resume_id_refuses_scope_mismatch(self):
        # Same id on disk but a DIFFERENT scope: a forced --resume-id must refuse
        # (not silently fork to <id>-1) and set identity_mismatch.
        self._seed_state(self.SCAN_ID, self.CANON, "scope-DIFFERENT")
        mgr = self._mgr()  # current scope is self.SCOPE == "scope-A"
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                main._decide_resume(mgr, "id")
        self.assertTrue(mgr.identity_mismatch)


# ---------------------------------------------------------------------------
# Non-scope config diff: warns and adopts new values, keeps identity.
# ---------------------------------------------------------------------------
class NonScopeConfigDiffTest(_StateDirMixin, unittest.TestCase):
    SCAN_ID = "t-55556666aaaabbbb"
    CANON = ["192.0.2.10"]
    SCOPE = "scope-A"

    def test_config_change_warns_and_adopts(self):
        self._seed_state(self.SCAN_ID, self.CANON, self.SCOPE,
                         non_scope_config={"concurrency": 100})
        mgr = _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE,
                             non_scope_config={"concurrency": 250})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertTrue(mgr.load_existing_state())
        out = buf.getvalue()
        self.assertIn("concurrency", out)
        self.assertIn("changed settings", out)
        # New value adopted; identity untouched.
        self.assertEqual(mgr.state["non_scope_config"]["concurrency"], 250)


# ---------------------------------------------------------------------------
# index.json maintenance on save / complete / cleanup.
# ---------------------------------------------------------------------------
class StateIndexTest(_StateDirMixin, unittest.TestCase):
    SCAN_ID = "t-77778888ccccdddd"
    CANON = ["example.com"]
    SCOPE = "scope-A"

    def _index(self):
        return scan_state.read_index()

    def test_save_writes_index_entry(self):
        mgr = _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE,
                             primary_target="example.com")
        mgr.update_phase("port_scanning")  # triggers a save
        mgr.save_state(force=True)
        idx = self._index()
        self.assertIn(self.SCAN_ID, idx)
        self.assertEqual(idx[self.SCAN_ID]["primary_target"], "example.com")
        self.assertEqual(idx[self.SCAN_ID]["phase"], "port_scanning")
        self.assertFalse(idx[self.SCAN_ID]["completed"])

    def test_mark_completed_flags_and_cleanup_removes(self):
        mgr = _quiet_manager(self.SCAN_ID, self.CANON, self.SCOPE)
        mgr.save_state(force=True)
        mgr.mark_completed()
        self.assertTrue(self._index()[self.SCAN_ID]["completed"])
        mgr.cleanup_state_file()
        self.assertNotIn(self.SCAN_ID, self._index())


# ---------------------------------------------------------------------------
# list_resumable / format_resumable_table filtering.
# ---------------------------------------------------------------------------
class ListResumableTest(_StateDirMixin, unittest.TestCase):
    def _seed_index_row(self, key, **over):
        # Also create the referenced state file so the existence check passes,
        # unless the caller wants a "stale" (missing-file) row.
        state_file = over.pop("state_file", self._state_path(key))
        row = {
            "scan_id": key, "primary_target": key, "phase": "port_scanning",
            "completed": False, "completed_combinations": 3, "total_combinations": 9,
            "updated": time.time(), "start_time": time.time(),
            "state_file": state_file,
        }
        row.update(over)
        if row.get("_make_file", True) and not over.get("_stale"):
            with open(state_file, "w") as f:
                f.write("{}")
        idx_path = os.path.join(self._state_dir, "index.json")
        idx = scan_state.read_index()
        idx[key] = {k: v for k, v in row.items() if not k.startswith("_")}
        with open(idx_path, "w") as f:
            json.dump(idx, f)

    def test_lists_only_resumable(self):
        self._seed_index_row("live-1")
        self._seed_index_row("done-1", completed=True)
        # Stale row: index entry present but state file removed.
        self._seed_index_row("stale-1", _stale=True,
                             state_file=os.path.join(self._state_dir, "gone.json"))
        rows = scan_state.list_resumable()
        ids = {r["scan_id"] for r in rows}
        self.assertEqual(ids, {"live-1"})

    def test_format_table_has_headers_and_row(self):
        self._seed_index_row("live-xyz", primary_target="example.com", phase="web_probing")
        table = scan_state.format_resumable_table()
        for col in ("SCAN_ID", "TARGET", "PHASE", "PROGRESS", "AGE"):
            self.assertIn(col, table)
        self.assertIn("live-xyz", table)
        self.assertIn("example.com", table)
        self.assertIn("3/9", table)

    def test_format_table_empty(self):
        self.assertIn("No resumable scans", scan_state.format_resumable_table())


# ---------------------------------------------------------------------------
# cmd_scan CLI glue: --list-resumable prints & exits; missing target errors.
# ---------------------------------------------------------------------------
def _scan_args(**over):
    ns = types.SimpleNamespace(
        target=None, list_resumable=False, fresh=False, resume=False,
        resume_id=None, no_dashboard=True,
    )
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


class CmdScanGlueTest(_StateDirMixin, unittest.TestCase):
    def test_list_resumable_prints_and_returns(self):
        # Seed one resumable scan in the index.
        key = "cli-1"
        with open(self._state_path(key), "w") as f:
            f.write("{}")
        with open(os.path.join(self._state_dir, "index.json"), "w") as f:
            json.dump({key: {
                "scan_id": key, "primary_target": "example.com", "phase": "web_probing",
                "completed": False, "completed_combinations": 1, "total_combinations": 2,
                "updated": time.time(), "state_file": self._state_path(key),
            }}, f)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            asyncio.run(main.cmd_scan(_scan_args(list_resumable=True)))
        out = buf.getvalue()
        self.assertIn("cli-1", out)
        self.assertIn("example.com", out)

    def test_missing_target_errors(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                asyncio.run(main.cmd_scan(_scan_args(target=None, list_resumable=False)))


# ---------------------------------------------------------------------------
# Full-CLI smoke: the flags parse and --list-resumable exits 0 through the real
# entrypoint (proves argparse wiring + no-network path).
# ---------------------------------------------------------------------------
class CliSubprocessTest(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="vaktscan_ux_cli_")

    def tearDown(self):
        shutil.rmtree(self._dir, ignore_errors=True)

    def _run(self, *cli):
        env = dict(os.environ, VAKT_STATE_DIR=self._dir)
        return subprocess.run(
            [sys.executable, "main.py", "scan", *cli],
            cwd=_REPO_ROOT, env=env, capture_output=True, text=True, timeout=120,
        )

    def test_list_resumable_exits_zero_and_lists(self):
        key = "cli-sub-1"
        with open(os.path.join(self._dir, f"{key}.json"), "w") as f:
            f.write("{}")
        with open(os.path.join(self._dir, "index.json"), "w") as f:
            json.dump({key: {
                "scan_id": key, "primary_target": "sub.example.com",
                "phase": "port_scanning", "completed": False,
                "completed_combinations": 5, "total_combinations": 20,
                "updated": time.time(), "state_file": os.path.join(self._dir, f"{key}.json"),
            }}, f)
        r = self._run("--list-resumable")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("cli-sub-1", r.stdout)
        self.assertIn("sub.example.com", r.stdout)

    def test_missing_target_exits_nonzero(self):
        r = self._run()  # no target, no --list-resumable
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("target", (r.stdout + r.stderr).lower())


# ---------------------------------------------------------------------------
# Integration: default (no flag) AUTO-RESUME through main() skips the port scan.
# ---------------------------------------------------------------------------
class AutoResumeIntegrationTest(_StateDirMixin, unittest.TestCase):
    # The mixin already provides an isolated CWD + VAKT_STATE_DIR.
    def test_default_auto_resume_skips_portscan(self):
        targets_file = "targets.txt"
        open(targets_file, "w").write("192.0.2.10\n")
        scan_id, canon, scope = "t-auto12345678abcd", ["192.0.2.10"], "scope-A"
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
            # No resume flag at all -> default AUTO-RESUME must find the state.
            asyncio.run(main.main(targets_file, 100,
                                  scan_id=scan_id, canonical_targets=canon, scope=scope))

        self.assertFalse(scan_ports_spy.called,
                         "default auto-resume must NOT re-run the port scan")
        self.assertIn("seeded-cve", [f.get("vulnerability") for f in captured["findings"]])


if __name__ == "__main__":
    unittest.main()
