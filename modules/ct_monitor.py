"""
Certificate Transparency change detection.

Queries crt.sh, diffs against a persisted SQLite baseline, and returns
findings only for subdomains that are NEW since the last scan.

First scan for a domain: establishes baseline, emits INFO findings.
Subsequent scans: emits HIGH findings for each newly observed subdomain.
"""

import os
import sqlite3
from datetime import datetime

import httpx

_DEFAULT_DB = os.path.join("reports", "ct_baseline.sqlite")


def _conn(db_path):
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ct_baseline (
            domain    TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            PRIMARY KEY (domain, subdomain)
        )
    """)
    conn.commit()
    return conn


def get_baseline(domain: str, db_path: str = _DEFAULT_DB) -> set:
    """Return the set of subdomains already seen for *domain*."""
    conn = _conn(db_path)
    rows = conn.execute(
        "SELECT subdomain FROM ct_baseline WHERE domain = ?", (domain,)
    ).fetchall()
    conn.close()
    return {r[0] for r in rows}


def update_baseline(domain: str, subdomains: set, db_path: str = _DEFAULT_DB) -> None:
    """Upsert *subdomains* into the baseline (never removes)."""
    conn = _conn(db_path)
    ts = datetime.utcnow().isoformat() + "Z"
    conn.executemany(
        "INSERT OR IGNORE INTO ct_baseline (domain, subdomain, first_seen) VALUES (?, ?, ?)",
        [(domain, sub, ts) for sub in subdomains],
    )
    conn.commit()
    conn.close()


async def _fetch_raw(domain: str) -> set:
    """Query crt.sh and return a clean set of subdomain strings."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return set()
            data = resp.json()
    except Exception:
        return set()

    subs: set = set()
    for entry in data:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower()
            if not name or name.startswith("*."):
                continue
            if name.endswith(f".{domain}") or name == domain:
                subs.add(name)
    return subs


async def check_new_certificates(domain: str, db_path: str = _DEFAULT_DB) -> list:
    """
    Fetch CT subdomains for *domain*, diff against baseline, return findings.

    Returns [] when nothing new is found.
    Severity is INFO on first scan (baseline establishment) and HIGH on
    subsequent scans where new subdomains appear.
    """
    current = await _fetch_raw(domain)
    if not current:
        return []

    baseline = get_baseline(domain, db_path)
    is_first_scan = not baseline
    new_subs = sorted(current - baseline)

    update_baseline(domain, current, db_path)

    if not new_subs:
        return []

    severity = "INFO" if is_first_scan else "HIGH"
    status = "INFO" if is_first_scan else "VULNERABLE"
    display = new_subs[:20]
    truncated = f" (showing first 20 of {len(new_subs)})" if len(new_subs) > 20 else ""
    label = "CT baseline established" if is_first_scan else "New CT certificates detected"

    return [{
        "status": status,
        "severity": severity,
        "vulnerability": f"{label} for {domain}",
        "target": domain,
        "resolved_ip": "N/A",
        "port": "N/A",
        "url": f"https://crt.sh/?q=%.{domain}",
        "payload_url": "N/A",
        "module": "ct_monitor",
        "service_version": "N/A",
        "details": (
            f"{len(new_subs)} new subdomain(s) in CT logs{truncated}: "
            f"{', '.join(display)}"
        ),
        "http_status": "N/A",
        "page_title": "N/A",
        "content_length": "N/A",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }]
