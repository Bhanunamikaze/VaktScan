"""Offline, deterministic tests for modules/proc.py.

Prove:
  * children run in their own process group (getpgid differs from parent);
  * cancelling the awaiting run_tool task SIGKILLs the whole group within the
    grace window, even for a child that traps and ignores SIGTERM/SIGINT;
  * the timeout path kills the group;
  * input=/env=/DEVNULL parity for run_tool.

No network. External tools are replaced by ``sleep`` and tiny python stubs.
"""

import asyncio
import os
import signal
import sys
import time
import unittest

from modules import proc


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# A stub that traps and *ignores* SIGTERM/SIGINT, spawns a grandchild in the
# same process group, announces both pids on stderr, then sleeps forever.
STUB_IGNORE = (
    "import signal, time, subprocess, os, sys\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
    "child = subprocess.Popen(['sleep', '300'])\n"
    "sys.stderr.write('READY %d %d\\n' % (os.getpid(), child.pid))\n"
    "sys.stderr.flush()\n"
    "time.sleep(300)\n"
)


def _proc_state(pid):
    """Return the single-char state from /proc/<pid>/stat, or None if gone."""
    try:
        with open("/proc/%d/stat" % pid) as fh:
            data = fh.read()
        # comm may contain ')'; state is the field after the last ')'
        return data.rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError, IndexError):
        return None


def _dead_or_zombie(pid):
    """True if the pid no longer exists or is a reaped-pending zombie."""
    state = _proc_state(pid)
    return state is None or state == "Z"


async def _await_dead(pid, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _dead_or_zombie(pid):
            return True
        await asyncio.sleep(0.02)
    return _dead_or_zombie(pid)


@unittest.skipIf(sys.platform == "win32", "POSIX process-group semantics")
class ProcPosixTests(unittest.IsolatedAsyncioTestCase):

    async def asyncTearDown(self):
        # Clean up any child left registered by a failing assertion.
        proc.kill_all_process_groups()

    async def test_child_runs_in_own_process_group(self):
        child = await proc._spawn(["sleep", "30"])
        try:
            self.assertIsNone(child.returncode)
            child_pgid = os.getpgid(child.pid)
            parent_pgid = os.getpgid(0)
            # start_new_session -> the child leads its own session/group.
            self.assertNotEqual(child_pgid, parent_pgid)
            self.assertEqual(child_pgid, child.pid)
        finally:
            await proc._terminate_group(child, grace=1.0)
        self.assertNotIn(child, proc._LIVE)

    async def test_terminate_group_sigkill_escalation_kills_whole_group(self):
        # Child ignores SIGTERM; _terminate_group must escalate to SIGKILL of
        # the whole group after the grace window, taking down the grandchild.
        child = await proc._spawn(
            [sys.executable, "-c", STUB_IGNORE],
            stderr=asyncio.subprocess.PIPE,
        )
        line = await asyncio.wait_for(child.stderr.readline(), timeout=5.0)
        parts = line.decode().split()
        self.assertEqual(parts[0], "READY")
        child_pid = int(parts[1])
        grand_pid = int(parts[2])

        grace = 0.5
        start = time.monotonic()
        await proc._terminate_group(child, grace=grace)
        elapsed = time.monotonic() - start

        # It had to wait out the grace before SIGKILL (SIGTERM was ignored).
        self.assertGreaterEqual(elapsed, grace)
        self.assertTrue(await _await_dead(child_pid), "child survived SIGKILL")
        self.assertTrue(await _await_dead(grand_pid), "grandchild survived group SIGKILL")
        self.assertNotIn(child, proc._LIVE)

    async def test_cancel_run_tool_kills_group_within_grace(self):
        # Cancelling the awaiting run_tool task must tear the group down within
        # the grace window even when the child ignores SIGTERM/SIGINT.
        self.assertEqual(len(proc._LIVE), 0)
        task = asyncio.create_task(
            proc.run_tool([sys.executable, "-c", STUB_IGNORE])
        )
        # Wait until the child is spawned and registered.
        for _ in range(100):
            await asyncio.sleep(0.02)
            if proc._LIVE:
                break
        self.assertEqual(len(proc._LIVE), 1)
        child = next(iter(proc._LIVE))
        child_pid = child.pid

        task.cancel()
        start = time.monotonic()
        with self.assertRaises(asyncio.CancelledError):
            await task
        elapsed = time.monotonic() - start

        # run_tool uses the default 5.0s grace; allow a small margin.
        self.assertLessEqual(elapsed, 5.0 + 3.0)
        self.assertTrue(await _await_dead(child_pid), "child survived cancel")
        self.assertEqual(len(proc._LIVE), 0)

    async def test_timeout_path_kills_group(self):
        self.assertEqual(len(proc._LIVE), 0)
        task = asyncio.create_task(
            proc.run_tool(["sleep", "30"], timeout=0.3)
        )
        for _ in range(100):
            await asyncio.sleep(0.02)
            if proc._LIVE:
                break
        child = next(iter(proc._LIVE))
        child_pid = child.pid

        with self.assertRaises(asyncio.TimeoutError):
            await task

        self.assertTrue(await _await_dead(child_pid), "child survived timeout")
        self.assertEqual(len(proc._LIVE), 0)

    async def test_input_parity(self):
        res = await proc.run_tool(["cat"], input=b"hello world")
        self.assertIsInstance(res, proc.ToolResult)
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout, b"hello world")
        self.assertEqual(res.stderr, b"")
        self.assertEqual(len(proc._LIVE), 0)

    async def test_env_parity(self):
        res = await proc.run_tool(
            ["env"],
            env={"VAKT_TEST_TOKEN": "sentinel-123", "PATH": os.environ.get("PATH", "")},
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn(b"VAKT_TEST_TOKEN=sentinel-123", res.stdout)

    async def test_devnull_parity(self):
        res = await proc.run_tool(
            ["sh", "-c", "echo to-stdout; echo to-stderr 1>&2"],
            stdout=asyncio.subprocess.DEVNULL,
        )
        self.assertEqual(res.returncode, 0)
        # stdout was discarded; stderr still captured.
        self.assertEqual(res.stdout, b"")
        self.assertIn(b"to-stderr", res.stderr)

    async def test_shell_command_parity(self):
        # str command -> shell execution path.
        res = await proc.run_tool("printf '%s' ok", stdout=asyncio.subprocess.PIPE)
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout, b"ok")

    async def test_spawn_tool_streaming_teardown(self):
        child_pid = None
        async with proc.spawn_tool(["sleep", "30"]) as child:
            child_pid = child.pid
            self.assertIn(child, proc._LIVE)
        # Context exit tears the group down.
        self.assertTrue(await _await_dead(child_pid))
        self.assertNotIn(child, proc._LIVE)


if __name__ == "__main__":
    unittest.main()
