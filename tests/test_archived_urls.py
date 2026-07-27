"""Tests for modules/archived_urls.py.

All tests run WITHOUT real tools or network access: the ``uro`` subprocess and
the httpx re-probe are mocked, and JS fetching is patched.
"""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from modules import archived_urls
from modules.archived_urls import (
    _classify,
    _dedup_internal,
    _filter_high_signal,
    scan_archived_urls,
)
from modules.schema import CANONICAL_KEYS


def _is_canonical(finding):
    """A finding must carry all 15 canonical keys (normalize_finding contract)."""
    return set(CANONICAL_KEYS).issubset(finding.keys())


class DedupTests(unittest.TestCase):
    def test_internal_dedup_collapses_by_path_and_param_keys(self):
        urls = [
            "https://ex.com/search?q=a&page=1",
            "https://ex.com/search?q=b&page=2",   # same path + param KEYS -> duplicate
            "https://ex.com/search?q=c&sort=x",   # different param key set -> kept
            "https://ex.com/other?q=a",           # different path -> kept
            "https://ex.com/search?q=a&page=1",   # exact dup -> dropped
        ]
        out = _dedup_internal(urls)
        self.assertEqual(len(out), 3)
        # First occurrence of the (path, {q,page}) key is kept.
        self.assertIn("https://ex.com/search?q=a&page=1", out)
        self.assertIn("https://ex.com/search?q=c&sort=x", out)
        self.assertIn("https://ex.com/other?q=a", out)

    def test_internal_dedup_skips_blanks(self):
        self.assertEqual(_dedup_internal(["", "  ", None]), [])


class FilterTests(unittest.TestCase):
    def test_filter_selects_extensions_and_keywords_only(self):
        urls = [
            "https://ex.com/index.html",          # dropped
            "https://ex.com/img/logo.png",         # dropped
            "https://ex.com/config/.env",          # sensitive ext .env
            "https://ex.com/db/backup.sql",        # sensitive ext .sql (+ keyword)
            "https://ex.com/app.old",              # sensitive ext .old
            "https://ex.com/admin/panel",          # keyword admin
            "https://ex.com/api/v1/users",         # keyword api
            "https://ex.com/assets/app.js",        # JS bucket
            "https://ex.com/module.mjs",           # JS bucket
        ]
        sensitive, js = _filter_high_signal(urls)

        self.assertIn("https://ex.com/config/.env", sensitive)
        self.assertIn("https://ex.com/db/backup.sql", sensitive)
        self.assertIn("https://ex.com/app.old", sensitive)
        self.assertIn("https://ex.com/admin/panel", sensitive)
        self.assertIn("https://ex.com/api/v1/users", sensitive)

        # Plain page/asset are excluded.
        self.assertNotIn("https://ex.com/index.html", sensitive)
        self.assertNotIn("https://ex.com/img/logo.png", sensitive)

        # JS routed to its own bucket, not the sensitive bucket.
        self.assertEqual(set(js), {"https://ex.com/assets/app.js", "https://ex.com/module.mjs"})
        self.assertNotIn("https://ex.com/assets/app.js", sensitive)

    def test_git_directory_form_is_matched(self):
        sensitive, _ = _filter_high_signal(["https://ex.com/.git/config"])
        self.assertEqual(sensitive, ["https://ex.com/.git/config"])

    def test_classify_severity_tiers(self):
        self.assertEqual(_classify("https://ex.com/a/.env")[2], "HIGH")
        self.assertEqual(_classify("https://ex.com/db.sql")[2], "HIGH")
        self.assertEqual(_classify("https://ex.com/.git/config")[2], "HIGH")
        self.assertEqual(_classify("https://ex.com/db-backup.tar.gz")[2], "HIGH")
        self.assertEqual(_classify("https://ex.com/settings.ini")[2], "MEDIUM")
        self.assertEqual(_classify("https://ex.com/admin/panel")[2], "INFO")


class NormalizeDedupUroTests(unittest.IsolatedAsyncioTestCase):
    async def test_uro_subprocess_is_used_when_available(self):
        class _FakeUroProc:
            async def communicate(self, input=None):
                # uro collapses the two near-duplicate URLs into one.
                return b"https://ex.com/search?q=FUZZ\n", b""

        async def fake_exec(*args, **kwargs):
            return _FakeUroProc()

        with patch("modules.archived_urls.shutil.which", return_value="/fake/uro"), \
             patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            out = await archived_urls._normalize_and_dedup(
                ["https://ex.com/search?q=a", "https://ex.com/search?q=b"]
            )

        self.assertEqual(out, ["https://ex.com/search?q=FUZZ"])

    async def test_falls_back_to_internal_dedup_when_uro_absent(self):
        with patch("modules.archived_urls.shutil.which", return_value=None):
            out = await archived_urls._normalize_and_dedup(
                ["https://ex.com/p?a=1", "https://ex.com/p?a=2"]
            )
        # Internal dedup collapses same path + same param-key set.
        self.assertEqual(out, ["https://ex.com/p?a=1"])


class ScanArchivedUrlsTests(unittest.IsolatedAsyncioTestCase):
    async def test_empty_input_returns_empty(self):
        self.assertEqual(await scan_archived_urls([], "/tmp/vaktscan_archived_test"), [])

    async def test_no_high_signal_urls_returns_empty(self):
        # Only plain pages/assets -> nothing to probe.
        with patch("modules.archived_urls.shutil.which", return_value=None), \
             patch("modules.archived_urls.HTTPXRunner") as HR:
            out = await scan_archived_urls(
                ["https://ex.com/index.html", "https://ex.com/logo.png"],
                "/tmp/vaktscan_archived_test",
            )
        self.assertEqual(out, [])
        HR.assert_not_called()  # never even constructs the prober

    async def test_full_scan_produces_canonical_findings(self):
        urls = [
            "https://ex.com/index.html",       # ignored
            "https://ex.com/config/.env",       # HIGH, live 200
            "https://ex.com/db/backup.sql",     # HIGH, live 403 (auth-required)
            "https://ex.com/assets/app.js",     # JS, live 200, has a secret
            "https://ex.com/admin/panel",       # keyword, but 404 -> not live
        ]

        alive = [
            {"input": "https://ex.com/config/.env", "url": "https://ex.com/config/.env", "status_code": 200},
            {"input": "https://ex.com/db/backup.sql", "url": "https://ex.com/db/backup.sql", "status_code": 403},
            {"input": "https://ex.com/assets/app.js", "url": "https://ex.com/assets/app.js", "status_code": 200},
            {"input": "https://ex.com/admin/panel", "url": "https://ex.com/admin/panel", "status_code": 404},
        ]

        fake_runner = MagicMock()
        fake_runner.run_httpx = AsyncMock(return_value=alive)

        # A live JS file containing a classic AWS access key -> js_paths secret hit.
        js_body = 'const c={key:"AKIAIOSFODNN7EXAMPLE"};'

        with patch("modules.archived_urls.shutil.which", return_value=None), \
             patch("modules.archived_urls.HTTPXRunner", return_value=fake_runner), \
             patch("modules.archived_urls._fetch_text", AsyncMock(return_value=js_body)):
            findings = await scan_archived_urls(urls, "/tmp/vaktscan_archived_test", concurrency=10)

        # httpx was invoked with the union of sensitive + JS URLs.
        fake_runner.run_httpx.assert_awaited_once()
        probed = fake_runner.run_httpx.await_args.args[0]
        self.assertIn("https://ex.com/config/.env", probed)
        self.assertIn("https://ex.com/assets/app.js", probed)
        self.assertNotIn("https://ex.com/index.html", probed)

        self.assertTrue(findings, "expected findings from live archived URLs")

        # Every finding is canonical.
        for f in findings:
            self.assertTrue(_is_canonical(f), f"non-canonical finding: {f}")
            self.assertEqual(f["module"], "archived_urls")

        # .env exposure -> HIGH / VULNERABLE.
        env_findings = [f for f in findings if ".env" in f["payload_url"]]
        self.assertTrue(env_findings)
        self.assertEqual(env_findings[0]["severity"], "HIGH")
        self.assertEqual(env_findings[0]["status"], "VULNERABLE")

        # backup.sql served with 403 still counts as live -> HIGH exposure.
        sql_findings = [f for f in findings if "backup.sql" in f["url"]]
        self.assertTrue(sql_findings)
        self.assertEqual(sql_findings[0]["severity"], "HIGH")

        # Secret hit reuses js_paths severity (CRITICAL).
        secret_findings = [f for f in findings if "Hardcoded Secret" in f["vulnerability"]]
        self.assertTrue(secret_findings, "expected a reused js_paths secret finding")
        self.assertEqual(secret_findings[0]["severity"], "CRITICAL")

        # 404 admin/panel is NOT live -> no finding references it.
        self.assertFalse(any("admin/panel" in (f.get("url") or "") for f in findings))

    async def test_dead_urls_yield_no_findings(self):
        fake_runner = MagicMock()
        fake_runner.run_httpx = AsyncMock(return_value=[
            {"input": "https://ex.com/x.sql", "url": "https://ex.com/x.sql", "status_code": 404},
        ])
        with patch("modules.archived_urls.shutil.which", return_value=None), \
             patch("modules.archived_urls.HTTPXRunner", return_value=fake_runner):
            findings = await scan_archived_urls(["https://ex.com/x.sql"], "/tmp/vaktscan_archived_test")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
