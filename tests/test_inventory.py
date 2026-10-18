import os
import tempfile
import unittest
from unittest import mock

from modules import inventory


def _finding(target, url, details="evidence"):
    return {
        "status": "VULNERABLE",
        "vulnerability": "Missing Content-Security-Policy Header",
        "target": target,
        "resolved_ip": "104.18.6.249",
        "port": "443",
        "url": url,
        "module": "WebChecks",
        "severity": "MEDIUM",
        "details": details,
    }


class InventoryIsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "inventory.db")
        self.db_patch = mock.patch.object(inventory, "DB_PATH", self.db_path)
        self.db_patch.start()
        inventory.init_db()

    def tearDown(self):
        self.db_patch.stop()
        self.tmp.cleanup()

    def test_finding_hash_is_scoped_by_target_and_endpoint(self):
        onit = _finding("trust.onit.com", "https://trust.onit.com/")
        axdraft = _finding("trust.axdraft.com", "https://trust.axdraft.com/")
        other_path = _finding("trust.axdraft.com", "https://trust.axdraft.com/admin")

        self.assertNotEqual(inventory._finding_hash(onit), inventory._finding_hash(axdraft))
        self.assertNotEqual(inventory._finding_hash(axdraft), inventory._finding_hash(other_path))

    def test_shared_cdn_ip_does_not_contaminate_later_run(self):
        onit_run = inventory.start_scan_run("onit.txt", scope_key="onit-scope")
        inventory.save_findings(
            onit_run, [_finding("trust.onit.com", "https://trust.onit.com/")]
        )

        axdraft_run = inventory.start_scan_run("axdraft.txt", scope_key="axdraft-scope")
        delta = inventory.save_findings(
            axdraft_run, [_finding("trust.axdraft.com", "https://trust.axdraft.com/")]
        )

        self.assertEqual([f["target"] for f in delta["new"]], ["trust.axdraft.com"])
        self.assertEqual(delta["resolved"], [])
        scores = inventory.get_risk_scores(axdraft_run)
        self.assertEqual([row["asset"] for row in scores], ["trust.axdraft.com"])

        with inventory._connect() as conn:
            rows = conn.execute(
                "SELECT run_id, target FROM findings ORDER BY run_id, target"
            ).fetchall()
        self.assertEqual(
            [(row["run_id"], row["target"]) for row in rows],
            [(onit_run, "trust.onit.com"), (axdraft_run, "trust.axdraft.com")],
        )

    def test_delta_uses_previous_run_for_same_scope(self):
        first_a = inventory.start_scan_run("a-1.txt", scope_key="scope-a")
        inventory.save_findings(
            first_a, [_finding("a.example", "https://a.example/path?a=one")]
        )

        run_b = inventory.start_scan_run("b.txt", scope_key="scope-b")
        inventory.save_findings(
            run_b, [_finding("b.example", "https://b.example/path")]
        )

        second_a = inventory.start_scan_run("a-2.txt", scope_key="scope-a")
        delta = inventory.save_findings(
            second_a,
            [_finding("a.example", "https://a.example/path?a=two", details="updated")],
        )

        self.assertEqual(delta["new"], [])
        self.assertEqual(delta["resolved"], [])
        self.assertEqual(len(delta["recurring"]), 1)
        self.assertEqual(delta["recurring"][0]["target"], "a.example")

    def test_init_db_migrates_legacy_scan_runs_table(self):
        os.unlink(self.db_path)
        import sqlite3

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    targets_file TEXT,
                    total_findings INTEGER DEFAULT 0,
                    completed_at TEXT
                )
                """
            )

        inventory.init_db()
        with inventory._connect() as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(scan_runs)")}
        self.assertIn("scope_key", columns)


if __name__ == "__main__":
    unittest.main()
