"""Refresh local vulnerability feeds when a scan starts and their checks expire."""

from __future__ import annotations

import asyncio
import socket
import sys
import urllib.request
from pathlib import Path

from modules import cisa_kev, cpanel, cve_freshness, nvd


ROOT = Path(__file__).resolve().parents[1]
REFRESH_AFTER_DAYS = {
    "nvd": 1,
    "retirejs": 7,
    "bundled_components": 30,
    "cisa_kev": 1,
}
UPDATERS = {
    "nvd": ("update_cve_db.py", "services.nvd.nist.gov", 1800, ("--force",)),
    "retirejs": ("update_js_cve_db.py", "raw.githubusercontent.com", 120, ("--force",)),
    "bundled_components": ("build_bundled_cves.py", "services.nvd.nist.gov", 900, ()),
}


def _needs_refresh(record: dict) -> bool:
    return record["status"] != "fresh" or (
        record["age_days"] is not None and
        record["age_days"] >= REFRESH_AFTER_DAYS[record["name"]]
    )


async def _reachable(host: str) -> bool:
    if urllib.request.getproxies().get("https"):
        # The updater's urllib client will use the configured proxy.
        return True
    def check() -> bool:
        try:
            with socket.create_connection((host, 443), timeout=5):
                return True
        except OSError:
            return False
    return await asyncio.to_thread(check)


async def _run_updater(name: str) -> bool:
    script, host, timeout, args = UPDATERS[name]
    if not await _reachable(host):
        print(f"[!] {name}: cannot connect to {host}; keeping cached vulnerability data.")
        return False
    print(f"[*] {name}: vulnerability data is due for refresh; downloading now.", flush=True)
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-u", str(ROOT / "scripts" / script), *args,
        cwd=str(ROOT),
    )
    try:
        result = await asyncio.wait_for(proc.wait(), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        proc.kill()
        await proc.wait()
        raise
    if result != 0:
        print(f"[!] {name}: updater exited {result}; keeping available cached data.")
        return False
    return True


async def refresh_outdated_sources() -> list[dict]:
    """Attempt every due source, then return the actual post-refresh status."""
    records = cve_freshness.inspect_default_databases()
    due = {row["name"] for row in records if _needs_refresh(row)}
    for name in ("nvd", "retirejs", "bundled_components"):
        if name not in due:
            continue
        try:
            await _run_updater(name)
        except (OSError, asyncio.TimeoutError) as exc:
            print(f"[!] {name}: refresh failed ({exc}); keeping cached vulnerability data.")
        if name == "nvd":
            nvd._LOCAL_DB_CACHE.clear()
        if name == "bundled_components":
            cpanel.reload_bundled_cves()
    if "cisa_kev" in due:
        print("[*] cisa_kev: vulnerability data is due for refresh; downloading now.", flush=True)
        cache_path = Path(cisa_kev._CACHE_FILE)
        before = cache_path.stat().st_mtime_ns if cache_path.exists() else None
        await cisa_kev.fetch_kev_catalog(force=True)
        after = cache_path.stat().st_mtime_ns if cache_path.exists() else None
        if after is None or after == before:
            print("[!] cisa_kev: refresh failed; keeping available cached data.")
    return cve_freshness.inspect_default_databases()
