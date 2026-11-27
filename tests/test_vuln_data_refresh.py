import asyncio
import argparse
from unittest.mock import AsyncMock

import main
from modules import vuln_data_refresh


def test_refreshes_only_due_sources_and_rechecks_status(monkeypatch):
    before = [
        {"name": "nvd", "status": "stale", "age_days": 20},
        {"name": "retirejs", "status": "unknown", "age_days": None},
        {"name": "bundled_components", "status": "fresh", "age_days": 1},
        {"name": "cisa_kev", "status": "fresh", "age_days": 2},
    ]
    after = [{"name": row["name"], "status": "fresh", "age_days": 0} for row in before]
    states = iter((before, after))
    monkeypatch.setattr(vuln_data_refresh.cve_freshness, "inspect_default_databases", lambda: next(states))
    updater = AsyncMock(return_value=True)
    kev = AsyncMock(return_value={"vulnerabilities": []})
    monkeypatch.setattr(vuln_data_refresh, "_run_updater", updater)
    monkeypatch.setattr(vuln_data_refresh.cisa_kev, "fetch_kev_catalog", kev)

    result = asyncio.run(vuln_data_refresh.refresh_outdated_sources())

    assert result == after
    assert [call.args[0] for call in updater.await_args_list] == ["nvd", "retirejs"]
    kev.assert_awaited_once_with(force=True)


def test_fresh_sources_do_not_download(monkeypatch):
    fresh = [{"name": name, "status": "fresh", "age_days": 0}
             for name in vuln_data_refresh.REFRESH_AFTER_DAYS]
    monkeypatch.setattr(vuln_data_refresh.cve_freshness, "inspect_default_databases", lambda: fresh)
    updater = AsyncMock()
    monkeypatch.setattr(vuln_data_refresh, "_run_updater", updater)
    result = asyncio.run(vuln_data_refresh.refresh_outdated_sources())
    assert result == fresh
    updater.assert_not_awaited()


def test_scan_lightweight_mode_refreshes_before_scanning(monkeypatch):
    events = []

    async def refresh():
        events.append("refresh")

    async def scan(**kwargs):
        events.append("scan")

    monkeypatch.setattr(main.vuln_data_refresh, "refresh_outdated_sources", refresh)
    monkeypatch.setattr(main, "main", scan)
    args = argparse.Namespace(
        target="example.com", no_dashboard=True, tech_only=True, posture=False,
        concurrency=1, ports=None, connect_timeout=1.0, port_retries=0,
        sarif=None, format=None,
    )
    asyncio.run(main.cmd_scan(args))
    assert events == ["refresh", "scan"]
