"""Tests for modules/ct_monitor.py — CT change detection."""

import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from modules import ct_monitor


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_crt_response(names: list[str]):
    """Build a crt.sh-style JSON response for the given name_value strings."""
    return [{"name_value": name} for name in names]


def _run(coro):
    return asyncio.run(coro)


# ── baseline persistence ───────────────────────────────────────────────────────

class TestBaseline:
    def test_empty_baseline_on_new_domain(self, tmp_path):
        db = str(tmp_path / "ct.sqlite")
        assert ct_monitor.get_baseline("example.com", db) == set()

    def test_update_and_read_baseline(self, tmp_path):
        db = str(tmp_path / "ct.sqlite")
        ct_monitor.update_baseline("example.com", {"a.example.com", "b.example.com"}, db)
        result = ct_monitor.get_baseline("example.com", db)
        assert result == {"a.example.com", "b.example.com"}

    def test_update_is_additive(self, tmp_path):
        db = str(tmp_path / "ct.sqlite")
        ct_monitor.update_baseline("example.com", {"a.example.com"}, db)
        ct_monitor.update_baseline("example.com", {"b.example.com"}, db)
        assert ct_monitor.get_baseline("example.com", db) == {"a.example.com", "b.example.com"}

    def test_baseline_isolated_by_domain(self, tmp_path):
        db = str(tmp_path / "ct.sqlite")
        ct_monitor.update_baseline("example.com", {"sub.example.com"}, db)
        assert ct_monitor.get_baseline("other.com", db) == set()


# ── fetch_raw ─────────────────────────────────────────────────────────────────

def _mock_client(resp_or_exc):
    """Return a context manager mock that yields an AsyncClient mock."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    if isinstance(resp_or_exc, Exception):
        mock_client.get = AsyncMock(side_effect=resp_or_exc)
    else:
        mock_client.get = AsyncMock(return_value=resp_or_exc)
    return patch("modules.ct_monitor.httpx.AsyncClient", return_value=mock_client)


class TestFetchRaw:
    def test_filters_wildcards(self):
        data = _make_crt_response(["*.example.com", "sub.example.com"])
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = data
        with _mock_client(mock_resp):
            result = _run(ct_monitor._fetch_raw("example.com"))
        assert "*.example.com" not in result
        assert "sub.example.com" in result

    def test_splits_multiline_name_value(self):
        data = [{"name_value": "a.example.com\nb.example.com"}]
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = data
        with _mock_client(mock_resp):
            result = _run(ct_monitor._fetch_raw("example.com"))
        assert result == {"a.example.com", "b.example.com"}

    def test_returns_empty_on_non_200(self):
        mock_resp = MagicMock(status_code=503)
        with _mock_client(mock_resp):
            result = _run(ct_monitor._fetch_raw("example.com"))
        assert result == set()

    def test_returns_empty_on_exception(self):
        with _mock_client(Exception("network error")):
            result = _run(ct_monitor._fetch_raw("example.com"))
        assert result == set()


# ── check_new_certificates ────────────────────────────────────────────────────

class TestCheckNewCertificates:
    def _mock_fetch(self, subs):
        return patch.object(ct_monitor, "_fetch_raw", new=AsyncMock(return_value=subs))

    def test_first_scan_returns_info_finding(self, tmp_path):
        db = str(tmp_path / "ct.sqlite")
        subs = {"sub.example.com", "api.example.com"}
        with self._mock_fetch(subs):
            findings = _run(ct_monitor.check_new_certificates("example.com", db))
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "INFO"
        assert f["module"] == "ct_monitor"
        assert "sub.example.com" in f["details"] or "api.example.com" in f["details"]

    def test_first_scan_establishes_baseline(self, tmp_path):
        db = str(tmp_path / "ct.sqlite")
        subs = {"sub.example.com"}
        with self._mock_fetch(subs):
            _run(ct_monitor.check_new_certificates("example.com", db))
        assert ct_monitor.get_baseline("example.com", db) == subs

    def test_second_scan_no_new_subs_returns_empty(self, tmp_path):
        db = str(tmp_path / "ct.sqlite")
        subs = {"sub.example.com"}
        with self._mock_fetch(subs):
            _run(ct_monitor.check_new_certificates("example.com", db))
            findings = _run(ct_monitor.check_new_certificates("example.com", db))
        assert findings == []

    def test_second_scan_new_sub_returns_high_finding(self, tmp_path):
        db = str(tmp_path / "ct.sqlite")
        with self._mock_fetch({"sub.example.com"}):
            _run(ct_monitor.check_new_certificates("example.com", db))
        with self._mock_fetch({"sub.example.com", "new.example.com"}):
            findings = _run(ct_monitor.check_new_certificates("example.com", db))
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "HIGH"
        assert f["status"] == "VULNERABLE"
        assert "new.example.com" in f["details"]

    def test_no_crt_data_returns_empty(self, tmp_path):
        db = str(tmp_path / "ct.sqlite")
        with self._mock_fetch(set()):
            findings = _run(ct_monitor.check_new_certificates("example.com", db))
        assert findings == []

    def test_new_sub_is_added_to_baseline(self, tmp_path):
        db = str(tmp_path / "ct.sqlite")
        with self._mock_fetch({"sub.example.com"}):
            _run(ct_monitor.check_new_certificates("example.com", db))
        with self._mock_fetch({"sub.example.com", "new.example.com"}):
            _run(ct_monitor.check_new_certificates("example.com", db))
        assert "new.example.com" in ct_monitor.get_baseline("example.com", db)
