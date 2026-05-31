"""
modules/inventory.py — SQLite-backed persistent asset inventory.

Enables delta reports (new vs resolved findings) across scan runs.
Uses only Python stdlib: sqlite3, json, os, time, hashlib.
DB file: vaktscan_inventory.db in the current working directory.
"""

import sqlite3
import json
import os
import time
import hashlib

DB_PATH = 'vaktscan_inventory.db'


def _connect() -> sqlite3.Connection:
    """Get a SQLite connection with WAL mode for concurrency safety."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at  TEXT    NOT NULL,
                targets_file TEXT,
                total_findings INTEGER DEFAULT 0,
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS assets (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT    NOT NULL,
                hostname    TEXT,
                first_seen  TEXT    NOT NULL,
                last_seen   TEXT    NOT NULL,
                open_ports  TEXT,
                UNIQUE(ip)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id       INTEGER NOT NULL,
                finding_hash TEXT    NOT NULL,
                status       TEXT,
                vulnerability TEXT,
                target       TEXT,
                resolved_ip  TEXT,
                port         TEXT,
                url          TEXT,
                module       TEXT,
                severity     TEXT,
                details      TEXT,
                first_seen   TEXT    NOT NULL,
                last_seen    TEXT    NOT NULL,
                resolved_at  TEXT,
                UNIQUE(finding_hash)
            );
        """)


def _finding_hash(finding: dict) -> str:
    """Stable hash for deduplication across runs: sha1(vulnerability+resolved_ip+port+module)."""
    key = '|'.join([
        str(finding.get('vulnerability', '')),
        str(finding.get('resolved_ip', '')),
        str(finding.get('port', '')),
        str(finding.get('module', '')),
    ])
    return hashlib.sha1(key.encode()).hexdigest()


def start_scan_run(targets_file: str) -> int:
    """Insert a new scan_run row and return its ID."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO scan_runs (started_at, targets_file) VALUES (?, ?)",
            (now, targets_file),
        )
        return cur.lastrowid


def complete_scan_run(run_id: int, total_findings: int):
    """Mark scan run complete with finding count."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _connect() as conn:
        conn.execute(
            "UPDATE scan_runs SET completed_at = ?, total_findings = ? WHERE id = ?",
            (now, total_findings, run_id),
        )


def upsert_asset(ip: str, hostname: str, open_ports: list):
    """Insert or update asset. Updates last_seen and open_ports on conflict."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    ports_json = json.dumps(sorted(set(int(p) for p in open_ports if p)))
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO assets (ip, hostname, first_seen, last_seen, open_ports)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen  = excluded.last_seen,
                open_ports = excluded.open_ports,
                hostname   = COALESCE(excluded.hostname, hostname)
            """,
            (ip, hostname or '', now, now, ports_json),
        )


def save_findings(run_id: int, findings: list) -> dict:
    """
    Persist findings for this run. Returns delta report dict:
    {
        'new':       [findings new since last run],
        'resolved':  [findings from last run not seen this run],
        'recurring': [findings seen in previous runs too],
        'total':     int
    }
    """
    now = time.strftime("%Y-%m-%d %H:%M:%S")

    # 1. Get all finding_hashes from the PREVIOUS run (run_id - 1)
    prev_hashes: set[str] = set()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT DISTINCT finding_hash FROM findings WHERE run_id = ?",
            (run_id - 1,),
        ).fetchall()
        prev_hashes = {r["finding_hash"] for r in rows}

    # 2. Insert/update all current findings (upsert on finding_hash)
    current_hashes: set[str] = set()
    new_findings: list[dict] = []
    recurring_findings: list[dict] = []

    with _connect() as conn:
        for finding in findings:
            fhash = _finding_hash(finding)
            current_hashes.add(fhash)

            existing = conn.execute(
                "SELECT id, first_seen FROM findings WHERE finding_hash = ?",
                (fhash,),
            ).fetchone()

            if existing is None:
                # Brand-new finding
                conn.execute(
                    """
                    INSERT INTO findings
                        (run_id, finding_hash, status, vulnerability, target,
                         resolved_ip, port, url, module, severity, details,
                         first_seen, last_seen, resolved_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        run_id,
                        fhash,
                        finding.get('status', ''),
                        finding.get('vulnerability', ''),
                        finding.get('target', ''),
                        finding.get('resolved_ip', ''),
                        str(finding.get('port', '')),
                        finding.get('url', ''),
                        finding.get('module', ''),
                        finding.get('severity', ''),
                        finding.get('details', ''),
                        now,
                        now,
                    ),
                )
                new_findings.append(finding)
            else:
                # Seen before — update run_id, last_seen, clear resolved_at
                conn.execute(
                    """
                    UPDATE findings
                    SET run_id = ?, last_seen = ?, resolved_at = NULL,
                        status = ?, severity = ?, details = ?
                    WHERE finding_hash = ?
                    """,
                    (
                        run_id,
                        now,
                        finding.get('status', ''),
                        finding.get('severity', ''),
                        finding.get('details', ''),
                        fhash,
                    ),
                )
                if fhash in prev_hashes:
                    recurring_findings.append(finding)
                else:
                    # Was seen before the previous run (came back after a gap)
                    new_findings.append(finding)

    # 3. Mark findings from previous run NOT in current run as resolved
    resolved_findings: list[dict] = []
    stale_hashes = prev_hashes - current_hashes
    if stale_hashes:
        with _connect() as conn:
            for fhash in stale_hashes:
                conn.execute(
                    "UPDATE findings SET resolved_at = ? WHERE finding_hash = ?",
                    (now, fhash),
                )
            # Fetch resolved finding records for the report
            placeholders = ','.join('?' * len(stale_hashes))
            rows = conn.execute(
                f"SELECT * FROM findings WHERE finding_hash IN ({placeholders})",
                list(stale_hashes),
            ).fetchall()
            resolved_findings = [dict(r) for r in rows]

    return {
        'new':       new_findings,
        'resolved':  resolved_findings,
        'recurring': recurring_findings,
        'total':     len(findings),
    }


def get_delta_report(run_id: int) -> dict:
    """Get new/resolved/recurring counts for a specific run."""
    with _connect() as conn:
        # Findings first seen in this run = new
        new_rows = conn.execute(
            "SELECT * FROM findings WHERE run_id = ? AND first_seen = last_seen",
            (run_id,),
        ).fetchall()

        # Findings resolved after this run's previous run_id
        resolved_rows = conn.execute(
            "SELECT * FROM findings WHERE resolved_at IS NOT NULL AND run_id < ?",
            (run_id,),
        ).fetchall()

        # Findings seen before and still active in this run = recurring
        recurring_rows = conn.execute(
            "SELECT * FROM findings WHERE run_id = ? AND first_seen != last_seen",
            (run_id,),
        ).fetchall()

    new       = [dict(r) for r in new_rows]
    resolved  = [dict(r) for r in resolved_rows]
    recurring = [dict(r) for r in recurring_rows]

    return {
        'new':       new,
        'resolved':  resolved,
        'recurring': recurring,
        'total':     len(new) + len(recurring),
    }


def print_delta_report(delta: dict):
    """Print a formatted delta report to stdout."""
    new       = delta.get('new', [])
    resolved  = delta.get('resolved', [])
    recurring = delta.get('recurring', [])

    print(f"\n{'='*50}")
    print(f"  Delta Report vs Previous Scan")
    print(f"{'='*50}")
    print(f"  NEW findings:       {len(new)}")
    print(f"  RESOLVED findings:  {len(resolved)}")
    print(f"  RECURRING findings: {len(recurring)}")

    if new:
        print(f"\n  New Findings:")
        for f in new[:10]:
            sev = (f.get('severity') or 'N/A').ljust(8)[:8]
            vuln = (f.get('vulnerability') or 'N/A')[:60]
            tgt  = f.get('target') or f.get('resolved_ip') or 'N/A'
            print(f"    [+] {sev} | {vuln} | {tgt}")
        if len(new) > 10:
            print(f"    ... and {len(new)-10} more")

    if resolved:
        print(f"\n  Resolved Since Last Scan:")
        for f in resolved[:5]:
            vuln = (f.get('vulnerability') or 'N/A')[:60]
            tgt  = f.get('target') or f.get('resolved_ip') or 'N/A'
            print(f"    [-] {vuln} | {tgt}")

    print(f"{'='*50}\n")
