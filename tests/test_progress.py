"""Unit tests for the live-progress helpers (modules/progress.py)."""

import asyncio
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules import progress  # noqa: E402


def _fake_dashboard(active=True):
    d = mock.MagicMock()
    d.active = active
    return d


class DashboardProgressTest(unittest.IsolatedAsyncioTestCase):
    async def test_counts_up_as_items_complete(self):
        dash = _fake_dashboard(active=True)

        async def item(n):
            await asyncio.sleep(0)
            return n

        prog = progress.DashboardProgress("gau", total=3, noun="hosts", dashboard=dash)
        results = await asyncio.gather(*(prog.wrap(item(i)) for i in range(3)))

        self.assertEqual(sorted(results), [0, 1, 2])
        # total was seeded once, and completed reached 3.
        seeded = [c for c in dash.update_task.call_args_list if c.kwargs.get("total") == 3]
        self.assertTrue(seeded)
        completions = [c.kwargs.get("completed") for c in dash.update_task.call_args_list
                       if c.kwargs.get("completed") is not None]
        self.assertEqual(max(completions), 3)

    async def test_counts_even_when_item_raises(self):
        dash = _fake_dashboard(active=True)

        async def boom():
            raise ValueError("tool failed")

        prog = progress.DashboardProgress("dirsearch", total=1, dashboard=dash)
        with self.assertRaises(ValueError):
            await prog.wrap(boom())
        # Completion must still be recorded despite the failure.
        self.assertTrue(any(c.kwargs.get("completed") == 1 for c in dash.update_task.call_args_list))

    async def test_inactive_dashboard_is_noop(self):
        dash = _fake_dashboard(active=False)
        prog = progress.DashboardProgress("x", total=2, dashboard=dash)

        async def item():
            return 1

        await asyncio.gather(prog.wrap(item()), prog.wrap(item()))
        dash.update_task.assert_not_called()


class HeartbeatTest(unittest.IsolatedAsyncioTestCase):
    async def test_ticks_elapsed_status_while_running(self):
        dash = _fake_dashboard(active=True)
        async with progress.heartbeat("cloud_enum", "Enumerating", interval=0.01, dashboard=dash):
            await asyncio.sleep(0.05)
        self.assertTrue(dash.update_task.called)
        # Status text carries the label.
        statuses = [c.kwargs.get("status", "") for c in dash.update_task.call_args_list]
        self.assertTrue(any("Enumerating" in s for s in statuses))

    async def test_heartbeat_inactive_is_noop(self):
        dash = _fake_dashboard(active=False)
        async with progress.heartbeat("x", "y", interval=0.01, dashboard=dash):
            await asyncio.sleep(0.03)
        dash.update_task.assert_not_called()


if __name__ == "__main__":
    unittest.main()
