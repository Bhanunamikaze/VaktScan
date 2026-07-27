"""Live-progress helpers for long-running scans shown on the LiveDashboard.

Several scans previously showed a frozen ``Running... | Starting`` status because
their dashboard task received no updates while the (long) work ran — an animated
spinner but no count, percentage, or elapsed time, so the scan looked hung.

Two helpers make liveness trivial to add without restructuring a runner:

* :class:`DashboardProgress` — increments a task's ``completed`` count as
  concurrent items finish (for ``asyncio.gather``-style fan-out over a countable
  list, e.g. one dirsearch/gau/waybackurls run per host/URL).
* :func:`heartbeat` — an async context manager that ticks ``<label> · <n>s
  elapsed`` on a task at a fixed interval, for an opaque single long operation
  (one subprocess / blocking call) where item-level counting is not possible.

Both are safe when the dashboard is inactive (they simply no-op) and never raise
out of the progress path — reporting progress must not be able to break a scan.
The dashboard is a singleton, so ``LiveDashboard()`` returns the active instance.
"""

import asyncio
import contextlib
import time


def _get_dashboard():
    # Imported lazily to avoid an import cycle at module load time.
    try:
        from modules.dashboard import LiveDashboard
        return LiveDashboard()
    except Exception:
        return None


def _active(dashboard):
    return dashboard is not None and getattr(dashboard, "active", False)


class DashboardProgress:
    """Track completion of concurrent items on a single dashboard task.

    Example::

        prog = DashboardProgress("gau", total=len(hosts), noun="hosts")
        results = await asyncio.gather(
            *(prog.wrap(_run_single(h)) for h in hosts),
            return_exceptions=True,
        )

    ``wrap`` bumps ``completed`` (and the status text) each time an item's
    coroutine finishes, whether it succeeded or raised.
    """

    def __init__(self, task_id, total, noun="done", dashboard=None):
        self.task_id = task_id
        self.total = max(0, int(total))
        self.noun = noun
        self.dashboard = dashboard if dashboard is not None else _get_dashboard()
        self.done = 0
        self._lock = asyncio.Lock()
        # Seed the task with a real total so the renderer draws a bar/percentage
        # instead of the bare spinner + "Starting".
        if _active(self.dashboard):
            self.dashboard.update_task(
                task_id, total=self.total, completed=0,
                status=f"0/{self.total} {noun}",
            )

    async def wrap(self, coro):
        try:
            return await coro
        finally:
            async with self._lock:
                self.done += 1
                if _active(self.dashboard):
                    self.dashboard.update_task(
                        self.task_id, completed=self.done,
                        status=f"{self.done}/{self.total} {self.noun}",
                    )


@contextlib.asynccontextmanager
async def heartbeat(task_id, label, interval=2.0, dashboard=None):
    """Tick ``<label> · <elapsed>s`` on ``task_id`` every ``interval`` seconds
    while the wrapped block runs. No-ops when the dashboard is inactive.

    Example::

        async with heartbeat("cloud_enum", "Enumerating cloud assets"):
            await enumerate_cloud_assets(domain)
    """
    dash = dashboard if dashboard is not None else _get_dashboard()
    start = time.monotonic()

    async def _beat():
        try:
            while True:
                await asyncio.sleep(interval)
                if _active(dash):
                    elapsed = int(time.monotonic() - start)
                    dash.update_task(task_id, status=f"{label} · {elapsed}s elapsed")
        except asyncio.CancelledError:
            pass

    task = asyncio.create_task(_beat())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
