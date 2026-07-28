"""
Offline tests for the local-first NVD CVE lookup (modules/nvd.py).

Every test controls the DB via a temp file and clears the module-level cache, so
none of them touch the real modules/data/nvd_cve_db.json. Network is asserted
absent on the local-hit paths (httpx.AsyncClient must never be constructed) and
mocked on the fallback paths.
"""
import json
import os
import tempfile

import pytest
from unittest.mock import patch, MagicMock

from modules import nvd


# ── Fixtures / helpers ──────────────────────────────────────────────────────────

SAMPLE_DB = {
    "_meta": {"schema_version": 1, "min_cvss": 7.0},
    "index": {
        "nginx:nginx": [
            {
                "cve": "CVE-2021-23017",
                "cvss": 9.8,
                "severity": "CRITICAL",
                "affected_versions": [">=0.6.18,<1.20.1"],
                "summary": "nginx resolver off-by-one heap write.",
            },
            {
                "cve": "CVE-2019-20372",
                "cvss": 7.5,
                "severity": "HIGH",
                "affected_versions": [">=0.7.12,<1.17.7"],
                "summary": "nginx error_page request smuggling.",
            },
            {
                # Below the default CVSS>=7 cutoff: must never be emitted.
                "cve": "CVE-2000-0000",
                "cvss": 5.3,
                "severity": "MEDIUM",
                "affected_versions": [">=0.0.0,<99.0.0"],
                "summary": "low-severity noise.",
            },
        ],
        # A product present in the DB but with NO qualifying entries. A lookup
        # for it must still answer offline (empty), not hit the network.
        "openssl:openssl": [
            {
                "cve": "CVE-2014-0160",
                "cvss": 7.5,
                "severity": "HIGH",
                "affected_versions": [">=1.0.1,<1.0.1g"],
                "summary": "Heartbleed.",
            },
        ],
    },
}


@pytest.fixture
def local_db(tmp_path):
    """Write SAMPLE_DB to a temp file, point nvd at it, clear the cache."""
    db_path = tmp_path / "nvd_cve_db.json"
    db_path.write_text(json.dumps(SAMPLE_DB), encoding="utf-8")
    old = nvd.NVD_CVE_DB_PATH
    nvd.NVD_CVE_DB_PATH = str(db_path)
    nvd._LOCAL_DB_CACHE.clear()
    try:
        yield str(db_path)
    finally:
        nvd.NVD_CVE_DB_PATH = old
        nvd._LOCAL_DB_CACHE.clear()


def _no_network():
    """Patch httpx.AsyncClient so any network construction fails the test."""
    return patch.object(nvd.httpx, "AsyncClient",
                        side_effect=AssertionError("network used on a local hit"))


class _MockResponse:
    def __init__(self, json_data, status_code):
        self._json = json_data
        self.status_code = status_code

    def json(self):
        return self._json


# ── Local-hit paths (no network) ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_local_hit_returns_cves_without_network(local_db):
    with _no_network():
        findings = await nvd.lookup_cves(
            "nginx", "1.16.0", target="example.com",
            resolved_ip="1.2.3.4", port="80")
    ids = sorted(f["vulnerability"].split(" - ")[0] for f in findings)
    # Both HIGH/CRITICAL entries match 1.16.0; the MEDIUM one is filtered out.
    assert ids == ["CVE-2019-20372", "CVE-2021-23017"]
    crit = next(f for f in findings if "CVE-2021-23017" in f["vulnerability"])
    assert crit["status"] == "CRITICAL"
    assert crit["severity"] == "CRITICAL"
    assert crit["module"] == "nvd"
    assert crit["target"] == "example.com"
    assert crit["resolved_ip"] == "1.2.3.4"
    assert crit["port"] == "80"
    assert crit["service_version"] == "1.16.0"
    # Finding shape is the canonical NVD shape callers already consume.
    for key in ("status", "severity", "vulnerability", "url", "payload_url",
                "details", "http_status", "page_title", "content_length",
                "timestamp"):
        assert key in crit


@pytest.mark.asyncio
async def test_local_non_vulnerable_version_returns_empty_no_network(local_db):
    # 1.99.0 is above every stored upper bound -> no CVE, and no live call.
    with _no_network():
        findings = await nvd.lookup_cves("nginx", "1.99.0", target="t")
    assert findings == []


@pytest.mark.asyncio
async def test_local_boundary_is_exclusive(local_db):
    # 1.20.1 is the exclusive upper bound of CVE-2021-23017 -> not affected;
    # it is also >= 1.17.7 so CVE-2019-20372 does not apply either.
    with _no_network():
        findings = await nvd.lookup_cves("nginx", "1.20.1", target="t")
    assert findings == []


@pytest.mark.asyncio
async def test_local_min_cvss_filter(local_db):
    # Raise the bar above 9.8 -> only nothing qualifies, still offline.
    with _no_network():
        findings = await nvd.lookup_cves("nginx", "1.16.0", target="t",
                                         min_cvss=10.0)
    assert findings == []


@pytest.mark.asyncio
async def test_covered_product_nonvuln_version_no_network(local_db):
    # openssl is in the DB; 1.0.1h is past Heartbleed's exclusive <1.0.1g bound.
    with _no_network():
        findings = await nvd.lookup_cves("openssl", "1.0.1h", target="t")
    assert findings == []
    # ...but a vulnerable openssl version is caught offline.
    with _no_network():
        findings = await nvd.lookup_cves("openssl", "1.0.1f", target="t")
    assert len(findings) == 1
    assert "CVE-2014-0160" in findings[0]["vulnerability"]


# ── Fallback paths (live API, mocked) ───────────────────────────────────────────

LIVE_PAYLOAD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-99999",
                "metrics": {"cvssMetricV31": [
                    {"cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}]},
                "descriptions": [{"lang": "en", "value": "Live-API CVE."}],
            }
        }
    ]
}


@pytest.mark.asyncio
async def test_unknown_product_falls_back_to_live_api(local_db):
    # "someappliance" is not in the local DB -> live API path (mocked).
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = _MockResponse(LIVE_PAYLOAD, 200)
        findings = await nvd.lookup_cves("someappliance", "1.0", target="t",
                                         port="8443")
    assert mock_get.called
    assert len(findings) == 1
    assert "CVE-2023-99999" in findings[0]["vulnerability"]
    assert findings[0]["status"] == "CRITICAL"
    assert findings[0]["module"] == "nvd"


@pytest.mark.asyncio
async def test_missing_db_falls_back_to_live_api(tmp_path):
    missing = tmp_path / "does_not_exist.json"
    old = nvd.NVD_CVE_DB_PATH
    nvd.NVD_CVE_DB_PATH = str(missing)
    nvd._LOCAL_DB_CACHE.clear()
    try:
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value = _MockResponse(LIVE_PAYLOAD, 200)
            findings = await nvd.lookup_cves("nginx", "1.16.0", target="t")
        assert mock_get.called  # no local DB -> live path even for nginx
        assert len(findings) == 1
        assert "CVE-2023-99999" in findings[0]["vulnerability"]
    finally:
        nvd.NVD_CVE_DB_PATH = old
        nvd._LOCAL_DB_CACHE.clear()


@pytest.mark.asyncio
async def test_corrupt_db_falls_back_to_live_api(tmp_path):
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{ this is not valid json ]]", encoding="utf-8")
    old = nvd.NVD_CVE_DB_PATH
    nvd.NVD_CVE_DB_PATH = str(corrupt)
    nvd._LOCAL_DB_CACHE.clear()
    try:
        # Must not raise; a corrupt DB behaves exactly like today (live API).
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value = _MockResponse(LIVE_PAYLOAD, 200)
            findings = await nvd.lookup_cves("nginx", "1.16.0", target="t")
        assert mock_get.called
        assert len(findings) == 1
    finally:
        nvd.NVD_CVE_DB_PATH = old
        nvd._LOCAL_DB_CACHE.clear()


@pytest.mark.asyncio
async def test_unknown_version_short_circuits(local_db):
    # Unknown/N/A version returns [] before any DB or network work.
    with _no_network():
        assert await nvd.lookup_cves("nginx", "Unknown") == []
        assert await nvd.lookup_cves("nginx", "N/A") == []
        assert await nvd.lookup_cves("nginx", "") == []


# ── Version-range comparator unit tests ─────────────────────────────────────────

def test_version_affected_ranges():
    assert nvd._version_affected("1.16.0", [">=0.6.18,<1.20.1"]) is True
    assert nvd._version_affected("1.20.1", [">=0.6.18,<1.20.1"]) is False  # exclusive
    assert nvd._version_affected("1.20.0", [">=0.6.18,<=1.20.0"]) is True  # inclusive
    assert nvd._version_affected("0.5.0", [">=0.6.18,<1.20.1"]) is False   # below start
    assert nvd._version_affected("9.0.37", ["==9.0.37"]) is True
    assert nvd._version_affected("9.0.38", ["==9.0.37"]) is False
    # Any-of semantics across expressions.
    assert nvd._version_affected("2.5", ["<1.0", ">=2.0,<3.0"]) is True
    # Conservative: no version bound / empty version -> never matches.
    assert nvd._version_affected("1.0", []) is False
    assert nvd._version_affected("", ["<9.9"]) is False


def test_version_suffix_ordering():
    # A bare release sorts before the same release with a letter suffix.
    assert nvd._compare_versions("1.0.2", "1.0.2k") < 0
    assert nvd._compare_versions("1.0.2k", "1.0.2m") < 0
    assert nvd._compare_versions("8.2p1", "8.2") > 0
    # Suffix range boundary (openssl-style).
    assert nvd._version_affected("1.0.2h", [">=1.0.2,<1.0.2m"]) is True
    assert nvd._version_affected("1.0.2n", [">=1.0.2,<1.0.2m"]) is False
