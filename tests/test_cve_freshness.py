import json
import hashlib
from datetime import datetime, timezone

from modules.cve_freshness import inspect_database


def test_cve_freshness_reports_age_and_coverage(tmp_path):
    path = tmp_path / "db.json"
    path.write_text(json.dumps({
        "_meta": {"refreshed_at": "2026-01-01T00:00:00Z", "products": {"a:b": {}}},
        "index": {"CVE-1": {}, "CVE-2": {}},
    }), encoding="utf-8")
    row = inspect_database(path, now=datetime(2026, 1, 20, tzinfo=timezone.utc), stale_after_days=14)
    assert row["status"] == "stale"
    assert row["age_days"] == 19.0
    assert row["coverage"]["products"] == 1
    assert row["coverage"]["advisories"] == 2


def test_cve_freshness_does_not_claim_mtime_is_feed_freshness(tmp_path):
    path = tmp_path / "db.json"
    path.write_text('{"library": {"vulnerabilities": []}}', encoding="utf-8")
    row = inspect_database(path)
    assert row["status"] == "unknown"
    assert "authoritative refresh timestamp" in row["warning"]


def test_retirejs_successful_check_metadata_is_bound_to_db_contents(tmp_path):
    path = tmp_path / "retirejs_db.json"
    path.write_text('{"jquery": {"vulnerabilities": []}}', encoding="utf-8")
    sidecar = tmp_path / "retirejs_db.meta.json"
    sidecar.write_text(json.dumps({
        "refreshed_at": "2026-01-19T00:00:00Z",
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }), encoding="utf-8")
    now = datetime(2026, 1, 20, tzinfo=timezone.utc)
    row = inspect_database(path, name="retirejs", now=now, stale_after_days=7)
    assert row["status"] == "fresh"
    assert row["freshness_basis"] == "verified_sidecar"
    path.write_text('{"jquery": {"vulnerabilities": [{}]}}', encoding="utf-8")
    row = inspect_database(path, name="retirejs", now=now, stale_after_days=7)
    assert row["status"] == "unknown"
