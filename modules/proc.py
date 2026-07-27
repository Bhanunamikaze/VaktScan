"""Shared subprocess helper with process-group isolation and teardown.

Every spawn site in VaktScan adopts this module so that:
  * children run in their own session/process group (POSIX),
  * every live child is registered for global force-quit teardown, and
  * cancellation / exception / timeout escalates ``SIGTERM -> grace -> SIGKILL``
    against the whole process *group* (not just the direct child).

Both ``list`` argv (exec) and ``str`` (shell) commands are supported. Callers
that buffer output use :func:`run_tool`; streaming callers use the
:func:`spawn_tool` async context manager.
"""

import asyncio
import contextlib
import os
import signal
import sys
from dataclasses import dataclass

_LIVE: "set[asyncio.subprocess.Process]" = set()  # for force-quit teardown
_POSIX = sys.platform != "win32"


@dataclass
class ToolResult:
    returncode: "int | None"
    stdout: bytes
    stderr: bytes


async def _spawn(cmd, *, env=None, cwd=None,
                 stdout=asyncio.subprocess.PIPE,
                 stderr=asyncio.subprocess.PIPE, stdin=None):
    kw = dict(stdout=stdout, stderr=stderr, env=env, cwd=cwd)
    if stdin is not None:
        kw["stdin"] = stdin
    if _POSIX:
        kw["start_new_session"] = True  # own process group
    if isinstance(cmd, str):
        proc = await asyncio.create_subprocess_shell(cmd, **kw)
    else:
        proc = await asyncio.create_subprocess_exec(*cmd, **kw)
    _LIVE.add(proc)
    return proc


async def _terminate_group(proc, grace=5.0):
    if proc.returncode is not None:
        _LIVE.discard(proc)
        return
    if _POSIX:
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            _LIVE.discard(proc)
            return
        try:
            # shield so an in-flight cancel doesn't abort the grace wait
            await asyncio.shield(asyncio.wait_for(proc.wait(), timeout=grace))
        except (asyncio.TimeoutError, asyncio.CancelledError):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(pgid, signal.SIGKILL)
            with contextlib.suppress(Exception):
                await asyncio.shield(proc.wait())
    else:
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        with contextlib.suppress(Exception):
            await asyncio.shield(asyncio.wait_for(proc.wait(), timeout=grace))
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
    _LIVE.discard(proc)


def kill_all_process_groups():
    """Synchronous, best-effort SIGKILL of every live child group (force-quit)."""
    for proc in list(_LIVE):
        try:
            if _POSIX:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, Exception):
            pass
        _LIVE.discard(proc)


async def run_tool(cmd, *, timeout=None, input=None, env=None, cwd=None,
                   stdout=asyncio.subprocess.PIPE,
                   stderr=asyncio.subprocess.PIPE) -> ToolResult:
    """Buffered spawn+communicate. Kills the whole group on cancel/timeout."""
    proc = await _spawn(cmd, env=env, cwd=cwd, stdout=stdout, stderr=stderr,
                        stdin=(asyncio.subprocess.PIPE if input is not None else None))
    try:
        fut = proc.communicate(input=input)
        out, err = await (asyncio.wait_for(fut, timeout) if timeout else fut)
        return ToolResult(proc.returncode, out or b"", err or b"")
    except (asyncio.CancelledError, asyncio.TimeoutError):
        await _terminate_group(proc)
        raise
    finally:
        _LIVE.discard(proc)


@contextlib.asynccontextmanager
async def spawn_tool(cmd, *, env=None, cwd=None,
                     stdout=asyncio.subprocess.PIPE,
                     stderr=asyncio.subprocess.PIPE):
    """For streaming callers (httpx/nuclei): yields the Process; guarantees
    group teardown on normal exit, exception, or cancellation."""
    proc = await _spawn(cmd, env=env, cwd=cwd, stdout=stdout, stderr=stderr)
    try:
        yield proc
    finally:
        await _terminate_group(proc)
