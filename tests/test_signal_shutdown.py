"""Offline, deterministic tests for the top-level signal/cancellation model.

Covers the Phase-1 test plan (design doc section 4):

  * T1 - one SIGINT to the runner terminates the spawned child, even a child
    that traps and *ignores* SIGINT/SIGTERM (proves the SIGKILL escalation in
    proc._terminate_group runs when the main task is cancelled).
  * T2 - cancelling the task awaiting proc.run_tool propagates
    asyncio.CancelledError and tears the child group down; a companion test
    wraps the await in `except Exception` and asserts the cancel STILL
    propagates (guards the bare-except -> except Exception audit).
  * T3 - a second SIGINT force-quits with exit code 130 and leaves no orphans.

No network. The external tool is replaced by a tiny python stub; the T1/T3
harness is a throwaway python process launched with start_new_session=True so
it lives in its own process group, isolated from the test runner.
"""

import asyncio
import os
import select
import signal
import subprocess
import sys
import time
import unittest

from modules import proc

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Stub tool that ignores SIGINT/SIGTERM and sleeps -> forces the SIGKILL
# escalation path (a cooperative `sleep` would die on the first SIGTERM and
# never exercise the group-kill grace window).
STUB_IGNORE = (
    "import signal, time\n"
    "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "time.sleep(300)\n"
)

# Harness: reuse main.run_command (the real top-level runner) to await
# proc.run_tool on the ignoring stub. Announces the spawned child's pid on
# stdout so the parent test can assert the child dies.
HARNESS = (
    "import asyncio, sys\n"
    "sys.path.insert(0, %r)\n" % REPO_ROOT +
    "import main\n"
    "from modules import proc\n"
    "STUB = %r\n" % STUB_IGNORE +
    "async def _announce():\n"
    "    for _ in range(2000):\n"
    "        if proc._LIVE:\n"
    "            child = next(iter(proc._LIVE))\n"
    "            sys.stdout.write('SPAWNED %d\\n' % child.pid)\n"
    "            sys.stdout.flush()\n"
    "            return\n"
    "        await asyncio.sleep(0.01)\n"
    "async def _work():\n"
    "    asyncio.ensure_future(_announce())\n"
    "    await proc.run_tool([sys.executable, '-c', STUB])\n"
    "main.run_command(_work())\n"
    "sys.stdout.write('EXITED\\n')\n"
    "sys.stdout.flush()\n"
)

# T3 harness: a STUCK graceful shutdown. `_work` keeps a real child alive (for the
# no-orphan assertion) but swallows the first cancellation, so a single Ctrl+C can
# never end the process -- only the SECOND signal's force-quit (os._exit(130)) can.
# (The default HARNESS shuts down cleanly in ~0.1s, so a second signal would never
# land during it; the force-quit path only matters when graceful cancel is stuck.)
HARNESS_STUCK = (
    "import asyncio, sys\n"
    "sys.path.insert(0, %r)\n" % REPO_ROOT +
    "import main\n"
    "from modules import proc\n"
    "STUB = %r\n" % STUB_IGNORE +
    "async def _announce():\n"
    "    for _ in range(2000):\n"
    "        if proc._LIVE:\n"
    "            child = next(iter(proc._LIVE))\n"
    "            sys.stdout.write('SPAWNED %d\\n' % child.pid)\n"
    "            sys.stdout.flush()\n"
    "            return\n"
    "        await asyncio.sleep(0.01)\n"
    "async def _work():\n"
    "    asyncio.ensure_future(_announce())\n"
    "    asyncio.ensure_future(proc.run_tool([sys.executable, '-c', STUB]))\n"
    "    while True:\n"
    "        try:\n"
    "            await asyncio.sleep(3600)\n"
    "        except asyncio.CancelledError:\n"
    "            pass\n"   # stuck: absorb the graceful cancel; force-quit is required
    "main.run_command(_work())\n"
    "sys.stdout.write('EXITED\\n')\n"
    "sys.stdout.flush()\n"
)


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _await_pid_dead(pid, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.02)
    return not _pid_alive(pid)


def _readline_timeout(fh, timeout):
    """Read one line from a pipe file object with a wall-clock deadline."""
    deadline = time.monotonic() + timeout
    buf = b""
    while time.monotonic() < deadline:
        r, _, _ = select.select([fh], [], [], deadline - time.monotonic())
        if not r:
            continue
        ch = os.read(fh.fileno(), 1)
        if not ch:
            break
        buf += ch
        if ch == b"\n":
            break
    return buf.decode(errors="replace")


def _spawn_harness(src=HARNESS):
    return subprocess.Popen(
        [sys.executable, "-c", src],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=REPO_ROOT,
        start_new_session=True,   # isolate harness in its own process group
    )


@unittest.skipIf(sys.platform == "win32", "POSIX signal/process-group semantics")
class SignalShutdownHarnessTests(unittest.TestCase):
    """T1 / T3 - real subprocess runner driven by os.kill."""

    def _read_spawned_pid(self, harness):
        line = _readline_timeout(harness.stdout, timeout=15.0)
        self.assertTrue(line.startswith("SPAWNED "),
                        "harness never announced a spawned child (got %r)" % line)
        return int(line.split()[1])

    def _cleanup(self, harness, child_pid):
        # Best-effort teardown so a failed assertion never leaks processes.
        for pid in (child_pid, harness.pid):
            if pid and _pid_alive(pid):
                try:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        try:
            harness.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            harness.kill()

    def test_t1_single_sigint_terminates_ignoring_child(self):
        harness = _spawn_harness()
        child_pid = None
        try:
            child_pid = self._read_spawned_pid(harness)
            self.assertTrue(_pid_alive(child_pid))

            # One SIGINT to the runner -> graceful cancel -> group SIGKILL.
            os.kill(harness.pid, signal.SIGINT)

            harness.wait(timeout=15.0)   # 5s grace + margin
            # A single interrupt is a graceful cancel, not a force-quit.
            self.assertNotEqual(harness.returncode, 130)
            self.assertTrue(_await_pid_dead(child_pid),
                            "child survived the single-SIGINT graceful cancel")
        finally:
            self._cleanup(harness, child_pid)

    def test_t3_second_sigint_force_quits_exit_130_no_orphans(self):
        harness = _spawn_harness(HARNESS_STUCK)
        child_pid = None
        try:
            child_pid = self._read_spawned_pid(harness)
            self.assertTrue(_pid_alive(child_pid))

            # First SIGINT requests a graceful cancel, but this harness's _work
            # absorbs it (a stuck shutdown), so the process stays alive. The
            # second SIGINT force-quits with os._exit(130) and kills the child.
            os.kill(harness.pid, signal.SIGINT)
            time.sleep(0.5)
            os.kill(harness.pid, signal.SIGINT)

            harness.wait(timeout=15.0)
            self.assertEqual(harness.returncode, 130,
                             "second SIGINT did not force-quit with exit code 130")
            self.assertTrue(_await_pid_dead(child_pid),
                            "force-quit left an orphaned child")
        finally:
            self._cleanup(harness, child_pid)


@unittest.skipIf(sys.platform == "win32", "POSIX signal/process-group semantics")
class CancelPropagationTests(unittest.IsolatedAsyncioTestCase):
    """T2 - pure-asyncio cancel propagation through proc.run_tool."""

    async def asyncTearDown(self):
        proc.kill_all_process_groups()

    async def _spawn_and_get_child_pid(self, coro_task):
        for _ in range(500):
            await asyncio.sleep(0.01)
            if proc._LIVE:
                return next(iter(proc._LIVE)).pid
        self.fail("run_tool never spawned/registered a child")

    async def test_t2_cancel_propagates_and_kills_group(self):
        self.assertEqual(len(proc._LIVE), 0)
        task = asyncio.create_task(
            proc.run_tool([sys.executable, "-c", STUB_IGNORE])
        )
        child_pid = await self._spawn_and_get_child_pid(task)

        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertTrue(await _await_dead_async(child_pid),
                        "child survived cancel")
        self.assertEqual(len(proc._LIVE), 0)

    async def test_t2_cancel_propagates_through_except_exception(self):
        # A wrapper that swallows `Exception` must NOT swallow the cancel:
        # asyncio.CancelledError is a BaseException, not an Exception, so it
        # propagates past the handler. This guards the Phase-3 bare-except audit.
        self.assertEqual(len(proc._LIVE), 0)

        async def _worker():
            try:
                await proc.run_tool([sys.executable, "-c", STUB_IGNORE])
            except Exception:
                return "swallowed"

        task = asyncio.create_task(_worker())
        child_pid = await self._spawn_and_get_child_pid(task)

        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertTrue(await _await_dead_async(child_pid),
                        "child survived cancel through except-Exception wrapper")
        self.assertEqual(len(proc._LIVE), 0)


async def _await_dead_async(pid, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        await asyncio.sleep(0.02)
    return not _pid_alive(pid)


if __name__ == "__main__":
    unittest.main()
