"""Large scans must not make dashboard output fatal or unbounded."""

import os

from modules.dashboard import LiveDashboard


def _dashboard():
    dashboard = object.__new__(LiveDashboard)
    dashboard._initialized = False
    dashboard.__init__()
    dashboard.active = True
    return dashboard


def test_dashboard_limits_visible_tasks(monkeypatch):
    monkeypatch.setattr("shutil.get_terminal_size", lambda fallback: os.terminal_size((80, 24)))
    dashboard = _dashboard()
    output = []
    dashboard.original_stdout_write = output.append
    for index in range(100):
        dashboard.add_task(f"task{index}", f"Task {index}")

    dashboard._draw_dashboard()

    assert dashboard.drawn_lines <= 23
    assert "80 more task(s) hidden" in output[-1]


def test_dashboard_suspends_rendering_when_stdout_would_block():
    dashboard = _dashboard()
    dashboard.add_task("task", "Task")

    def blocked_write(_):
        raise BlockingIOError(11, "write could not complete without blocking")

    dashboard.original_stdout_write = blocked_write
    dashboard._draw_dashboard()
    dashboard.log_message("progress\n")

    assert dashboard.render_suspended
