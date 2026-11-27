"""A failed upstream refresh must never make preserved CVE rows look current."""

import json
import io
import sys
import urllib.error

from scripts import build_bundled_cves, update_cve_db


def test_nvd_failed_refresh_preserves_old_timestamp(tmp_path, monkeypatch):
    path = tmp_path / "nvd.json"
    old = "2025-01-01T00:00:00Z"
    path.write_text(json.dumps({
        "_meta": {"refreshed_at": old, "products": {}},
        "index": {"nginx:nginx": [{"cve": "CVE-2020-0001"}]},
    }), encoding="utf-8")
    monkeypatch.setattr(update_cve_db, "OUT_PATH", str(path))
    monkeypatch.setattr(update_cve_db, "PRODUCT_CPES", {"nginx": ["cpe:2.3:a:nginx:nginx"]})
    monkeypatch.setattr(update_cve_db, "fetch", lambda *args: (_ for _ in ()).throw(urllib.error.URLError("offline")))
    monkeypatch.setattr(update_cve_db.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(sys, "argv", ["update_cve_db.py", "--force"])

    assert update_cve_db.main() == 1
    assert json.loads(path.read_text(encoding="utf-8"))["_meta"]["refreshed_at"] == old
    assert update_cve_db.is_fresh(14)[0] is False


def test_bundled_failed_refresh_preserves_old_timestamp(tmp_path, monkeypatch):
    path = tmp_path / "bundled.json"
    curated_path = tmp_path / "curated.json"
    curated_path.write_text('{"components": {}}', encoding="utf-8")
    old = "2025-01-01T00:00:00Z"
    path.write_text(json.dumps({
        "_meta": {"refreshed_at": old},
        "components": {"apache_httpd": [{"cve": "CVE-2020-0001"}]},
    }), encoding="utf-8")
    monkeypatch.setattr(build_bundled_cves, "OUT_PATH", str(path))
    monkeypatch.setattr(build_bundled_cves, "CURATED_PATH", str(curated_path))
    monkeypatch.setattr(build_bundled_cves, "fetch_nvd", lambda *args: (_ for _ in ()).throw(urllib.error.URLError("offline")))
    monkeypatch.setattr(sys, "argv", ["build_bundled_cves.py", "--components", "apache_httpd"])

    assert build_bundled_cves.main() == 1
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["_meta"]["refreshed_at"] == old
    assert data["components"]["apache_httpd"] == [{"cve": "CVE-2020-0001"}]


def test_bundled_queries_partial_cpe_and_ignores_other_product_ranges(monkeypatch):
    seen = []
    payload = {"totalResults": 1, "vulnerabilities": [{"cve": {
        "id": "CVE-2026-0001", "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
             "versionEndExcluding": "2.4.60"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:other:product:*:*:*:*:*:*:*:*",
             "versionEndExcluding": "9.0"},
        ]}]}],
    }}]}

    def fake_open(request, timeout):
        seen.append(request.full_url)
        return io.BytesIO(json.dumps(payload).encode())

    monkeypatch.setattr(build_bundled_cves.urllib.request, "urlopen", fake_open)
    result = build_bundled_cves.fetch_nvd("cpe:2.3:a:apache:http_server")
    entries = build_bundled_cves.extract_entries(result, "cpe:2.3:a:apache:http_server")
    assert "virtualMatchString=" in seen[0]
    assert "cpeName=" not in seen[0]
    assert entries[0]["affected_versions"] == ["<2.4.60"]


def test_bundled_merge_preserves_curated_cve_omitted_by_nvd():
    curated = [{"cve": "CVE-2024-25602", "affected_versions": ["<8.0"]}]
    fetched = [{"cve": "CVE-2026-0001", "affected_versions": ["<9.0"]}]
    merged = build_bundled_cves.merge_curated_entries(curated, fetched)
    assert {row["cve"] for row in merged} == {"CVE-2024-25602", "CVE-2026-0001"}
