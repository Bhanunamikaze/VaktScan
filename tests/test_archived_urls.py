"""Tests for modules/archived_urls.py.

All tests run WITHOUT real tools or network access: the ``uro`` subprocess, the
httpx re-probe, and the content/JS fetches are mocked.

The emphasis is the FALSE-POSITIVE discipline: a live 200 alone must NEVER
produce an "exposed sensitive file" finding — the response CONTENT must be
validated (a catch-all/SPA that 200s every path must yield nothing), and a
401/403 (protected) must not be reported as exposed.
"""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from modules import archived_urls
from modules.archived_urls import (
    _classify_ext,
    _dedup_internal,
    _filter_high_signal,
    _validate_exposure,
    scan_archived_urls,
)
from modules.schema import CANONICAL_KEYS


def _is_canonical(finding):
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

    def test_internal_dedup_skips_blanks(self):
        self.assertEqual(_dedup_internal(["", "  ", None]), [])


class FilterTests(unittest.TestCase):
    def test_filter_selects_extensions_and_keywords_only(self):
        urls = [
            "https://ex.com/index.html",
            "https://ex.com/img/logo.png",
            "https://ex.com/config/.env",
            "https://ex.com/db/backup.sql",
            "https://ex.com/admin/panel",
            "https://ex.com/assets/app.js",
        ]
        sensitive, js = _filter_high_signal(urls)
        self.assertIn("https://ex.com/config/.env", sensitive)
        self.assertIn("https://ex.com/admin/panel", sensitive)
        self.assertNotIn("https://ex.com/index.html", sensitive)
        self.assertEqual(set(js), {"https://ex.com/assets/app.js"})

    def test_classify_ext_tiers(self):
        self.assertEqual(_classify_ext(".env")[2], "HIGH")
        self.assertEqual(_classify_ext(".sql")[2], "HIGH")
        self.assertEqual(_classify_ext(".ini")[2], "MEDIUM")


class ValidateExposureOracleTests(unittest.TestCase):
    """The content oracle is what prevents catch-all false positives."""

    def test_env_requires_key_value_lines(self):
        self.assertTrue(_validate_exposure(".env", "SECRET_KEY=abc\nDB_HOST=db\n", "text/plain", 24))
        # KEY=VALUE absent -> reject
        self.assertFalse(_validate_exposure(".env", "just some prose", "text/plain", 15))

    def test_env_html_catchall_rejected(self):
        # The classic false positive: a SPA/catch-all returns HTML 200 for /.env
        self.assertFalse(_validate_exposure(".env", "<!DOCTYPE html><html>app</html>", "text/html", 500))

    def test_git_requires_ref(self):
        self.assertTrue(_validate_exposure(".git", "ref: refs/heads/main\n", "text/plain", 20))
        self.assertFalse(_validate_exposure(".git", "<html>404</html>", "text/html", 16))

    def test_sql_requires_sql_markers(self):
        self.assertTrue(_validate_exposure(".sql", "CREATE TABLE users (id int);", "text/plain", 28))
        self.assertFalse(_validate_exposure(".sql", "welcome to my site", "text/plain", 18))

    def test_zip_requires_binary_or_size(self):
        self.assertTrue(_validate_exposure(".zip", "PKblob", "application/zip", 4096))
        self.assertTrue(_validate_exposure(".zip", "x" * 4096, "", 4096))   # large, no ct
        self.assertFalse(_validate_exposure(".zip", "<html>page</html>", "text/html", 500))


class ScanArchivedUrlsTests(unittest.IsolatedAsyncioTestCase):
    async def test_empty_input_returns_empty(self):
        self.assertEqual(await scan_archived_urls([], "/tmp/vaktscan_archived_test"), [])

    async def test_no_high_signal_urls_returns_empty(self):
        with patch("modules.archived_urls.shutil.which", return_value=None), \
             patch("modules.archived_urls.HTTPXRunner") as HR:
            out = await scan_archived_urls(
                ["https://ex.com/index.html", "https://ex.com/logo.png"],
                "/tmp/vaktscan_archived_test",
            )
        self.assertEqual(out, [])
        HR.assert_not_called()

    async def test_content_validated_exposure_only(self):
        """The core anti-FP test: only the .env with REAL content becomes a finding;
        the catch-all-HTML .env and the 403-protected .sql do NOT."""
        urls = [
            "https://ex.com/real/.env",      # 200 + real KEY=VALUE  -> HIGH
            "https://ex.com/fake/.env",      # 200 + HTML catch-all  -> NO finding
            "https://ex.com/db/backup.sql",  # 403 protected         -> NO finding
            "https://ex.com/assets/app.js",  # 200 JS w/ secret      -> CRITICAL
        ]
        alive = [
            {"input": "https://ex.com/real/.env", "url": "https://ex.com/real/.env", "status_code": 200},
            {"input": "https://ex.com/fake/.env", "url": "https://ex.com/fake/.env", "status_code": 200},
            {"input": "https://ex.com/db/backup.sql", "url": "https://ex.com/db/backup.sql", "status_code": 403},
            {"input": "https://ex.com/assets/app.js", "url": "https://ex.com/assets/app.js", "status_code": 200},
        ]
        fake_runner = MagicMock()
        fake_runner.run_httpx = AsyncMock(return_value=alive)

        async def fake_meta(url, timeout=10.0):
            if url.endswith("_probe_zx9q83.bak"):
                return 404, "not found", "text/html", 9   # host is NOT a catch-all
            if url == "https://ex.com/real/.env":
                return 200, "SECRET_KEY=abc123\nDB_HOST=db\n", "text/plain", 30
            if url == "https://ex.com/fake/.env":
                return 200, "<!DOCTYPE html><html><body>SPA</body></html>", "text/html", 200
            return None, None, "", 0

        js_body = 'const c={key:"AKIAIOSFODNN7EXAMPLE"};'

        with patch("modules.archived_urls.shutil.which", return_value=None), \
             patch("modules.archived_urls.HTTPXRunner", return_value=fake_runner), \
             patch("modules.archived_urls._fetch_meta", side_effect=fake_meta), \
             patch("modules.archived_urls._fetch_text", AsyncMock(return_value=js_body)):
            findings = await scan_archived_urls(urls, "/tmp/vaktscan_archived_test", concurrency=10)

        for f in findings:
            self.assertTrue(_is_canonical(f))
            self.assertEqual(f["module"], "archived_urls")

        # Real .env content -> HIGH / VULNERABLE.
        real_env = [f for f in findings if f["url"] == "https://ex.com/real/.env"]
        self.assertTrue(real_env, "content-validated .env must produce a finding")
        self.assertEqual(real_env[0]["severity"], "HIGH")
        self.assertEqual(real_env[0]["status"], "VULNERABLE")

        # Catch-all HTML .env -> NO finding (the false positive we're preventing).
        self.assertFalse(
            any(f["url"] == "https://ex.com/fake/.env" for f in findings),
            "an HTML catch-all .env must NOT be reported as exposed",
        )

        # 403-protected .sql -> NOT exposed.
        self.assertFalse(
            any("backup.sql" in (f.get("url") or "") for f in findings),
            "a 401/403 sensitive path is protected, not exposed",
        )

        # JS secret still fires (regex-validated, so no FP risk).
        secret = [f for f in findings if "Hardcoded Secret" in f["vulnerability"]]
        self.assertTrue(secret)
        self.assertEqual(secret[0]["severity"], "CRITICAL")

    async def test_keyword_only_endpoint_is_info_not_vulnerable(self):
        alive = [{"input": "https://ex.com/admin/panel", "url": "https://ex.com/admin/panel", "status_code": 200}]
        fake_runner = MagicMock()
        fake_runner.run_httpx = AsyncMock(return_value=alive)

        async def fake_meta(url, timeout=10.0):
            # soft-404 probe -> 404, so ex.com is NOT a catch-all.
            return 404, "nf", "text/html", 2

        with patch("modules.archived_urls.shutil.which", return_value=None), \
             patch("modules.archived_urls.HTTPXRunner", return_value=fake_runner), \
             patch("modules.archived_urls._fetch_meta", side_effect=fake_meta):
            findings = await scan_archived_urls(["https://ex.com/admin/panel"], "/tmp/vaktscan_archived_test")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["severity"], "INFO")
        self.assertNotEqual(findings[0]["status"], "VULNERABLE")

    async def test_query_param_keyword_is_not_a_candidate(self):
        # ?config= / ?secret= are benign query params, not path segments — they must
        # NOT be selected as sensitive candidates (the catch-all INFO-noise source).
        sensitive, js = _filter_high_signal([
            "https://ex.com/page?config=1",
            "https://ex.com/home?secret=x",
            "https://ex.com/administrator",   # substring, not a segment
        ])
        self.assertEqual(sensitive, [])

    async def test_non_html_always_200_catchall_suppressed(self):
        """The exact FP the audit found: a host that 200s EVERY path with a
        non-HTML body (JSON error envelope) must NOT yield a false 'exposed .bak',
        while a genuinely different sensitive file on the same host still fires."""
        soft = '{"error":"not found","status":404,"detail":"no such path on this host"}'
        urls = ["https://catch.com/x/app.bak", "https://catch.com/real/.env"]
        alive = [
            {"input": "https://catch.com/x/app.bak", "url": "https://catch.com/x/app.bak", "status_code": 200},
            {"input": "https://catch.com/real/.env", "url": "https://catch.com/real/.env", "status_code": 200},
        ]
        fake_runner = MagicMock()
        fake_runner.run_httpx = AsyncMock(return_value=alive)

        async def fake_meta(url, timeout=10.0):
            if url.endswith("_probe_zx9q83.bak"):
                return 200, soft, "application/json", len(soft)   # catch-all: 200 to bogus path
            if url == "https://catch.com/x/app.bak":
                return 200, soft, "application/json", len(soft)   # echoes soft-404 -> suppressed
            if url == "https://catch.com/real/.env":
                return 200, "AWS_KEY=AKIAABC\nDB_HOST=prod\n", "text/plain", 26  # DIFFERS -> real
            return None, None, "", 0

        with patch("modules.archived_urls.shutil.which", return_value=None), \
             patch("modules.archived_urls.HTTPXRunner", return_value=fake_runner), \
             patch("modules.archived_urls._fetch_meta", side_effect=fake_meta):
            findings = await scan_archived_urls(urls, "/tmp/vaktscan_archived_test")

        # The .bak that just echoes the catch-all baseline -> NO finding (the FP).
        self.assertFalse(
            any("app.bak" in (f.get("url") or "") for f in findings),
            "a non-HTML always-200 catch-all must not produce a false exposed-file finding",
        )
        # A real .env whose content DIFFERS from the baseline still fires.
        env = [f for f in findings if f["url"] == "https://catch.com/real/.env"]
        self.assertTrue(env, "a genuinely different sensitive file must still be reported")
        self.assertEqual(env[0]["severity"], "HIGH")

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
