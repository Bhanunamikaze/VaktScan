"""Offline tests for modules/js_cve.py (VaktScan client-side JS CVE detector).

Everything here runs WITHOUT network or real subprocesses:

* Positive/negative detection assertions use a small, controlled fixture DB
  written to a temp file and loaded through the real ``load_db``/matcher path,
  so assertions never depend on the exact (mutable) vendored upstream DB.
* The single ``scan_js_cves`` fetch test mocks ``_fetch_js`` with an ``AsyncMock``
  so no HTTP ever happens.
* One smoke test uses the vendored DB but only asserts shape/robustness plus the
  long-lived CVE-2011-4969 (jQuery 1.6.2), which is stable in the Retire.js DB.

Async entrypoints are driven with ``asyncio.run`` to match the repo's test
convention (no pytest-asyncio mode is configured).
"""

import asyncio
import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from modules import js_cve
from modules.js_cve import (
    detect_in_artifact,
    is_at_or_above,
    load_db,
    scan_js_cves,
    _applies,
    _strip_min,
)
from modules.schema import CANONICAL_KEYS, validate_finding

# Captured before any test mutates it, so tearDown can always restore the real DB.
ORIG_DB_PATH = js_cve.DB_PATH


def _run(coro):
    return asyncio.run(coro)


def _is_canonical(finding):
    return validate_finding(finding) == [] and "server" not in finding


# ---------------------------------------------------------------------------
# A small, fully controlled fixture DB (raw / on-disk Retire.js shape).
# ---------------------------------------------------------------------------

def _base_fixture_db():
    return {
        "jquery": {
            "extractors": {
                "filename": ["jquery-(§§version§§)(\\.min)?\\.js"],
                "uri": ["/(§§version§§)/jquery(\\.min)?\\.js"],
                "filecontent": ["/\\*!? jQuery v(§§version§§)"],
            },
            "vulnerabilities": [
                {
                    "below": "1.6.3",
                    "severity": "medium",
                    "cwe": ["CWE-79"],
                    "identifiers": {
                        "summary": "XSS with location.hash",
                        "CVE": ["CVE-2011-4969"],
                        "githubID": "GHSA-579v-mp3v-rrw5",
                    },
                    "info": ["https://nvd.nist.gov/vuln/detail/CVE-2011-4969"],
                },
                {
                    "atOrAbove": "1.0.0",
                    "below": "3.5.0",
                    "severity": "medium",
                    "identifiers": {
                        "summary": "htmlPrefilter regex XSS",
                        "CVE": ["CVE-2020-11022"],
                    },
                },
            ],
        },
    }


class _FixtureDBMixin:
    """Install a controlled DB by pointing DB_PATH at a temp file and reloading."""

    def install_db(self, raw):
        fd, path = tempfile.mkstemp(suffix=".json", prefix="retirejs_fixture_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(raw, f)
        self._tmp_db_path = path
        js_cve.DB_PATH = path
        load_db(force=True)  # also clears the matcher cache

    def install_missing_db(self):
        # A path that does not exist -> load_db hits FileNotFoundError -> {}.
        js_cve.DB_PATH = os.path.join(
            tempfile.gettempdir(), "definitely_missing_retirejs_db_xyz.json"
        )
        load_db(force=True)

    def install_corrupt_db(self):
        fd, path = tempfile.mkstemp(suffix=".json", prefix="retirejs_corrupt_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("{ this is : not valid json ,,,")
        self._tmp_db_path = path
        js_cve.DB_PATH = path
        load_db(force=True)

    def tearDown(self):
        # Restore the real DB path and drop caches so later tests reload cleanly.
        path = getattr(self, "_tmp_db_path", None)
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass
        self._tmp_db_path = None
        js_cve.DB_PATH = ORIG_DB_PATH
        js_cve._DB_LOADED = False
        js_cve._DB_CACHE = None
        js_cve._MATCHERS_CACHE = None


# ---------------------------------------------------------------------------
# Version comparator: is_at_or_above / _strip_min
# ---------------------------------------------------------------------------

class VersionComparatorTests(unittest.TestCase):
    def test_numeric_segment_ranking(self):
        # 1.10.0 > 1.9.9 (segment 2 compared as ints: 10 > 9, not "10" < "9").
        self.assertTrue(is_at_or_above("1.10.0", "1.9.9"))
        self.assertFalse(is_at_or_above("1.9.9", "1.10.0"))

    def test_equal_versions_are_at_or_above(self):
        self.assertTrue(is_at_or_above("1.2.3", "1.2.3"))
        self.assertTrue(is_at_or_above("2.0", "2.0.0"))  # missing trailing seg == 0

    def test_prerelease_ranks_below_release(self):
        # A plain release outranks a same-base pre-release (numeric > string).
        self.assertTrue(is_at_or_above("1.0.0", "1.0.0-rc"))
        self.assertFalse(is_at_or_above("1.0.0-rc", "1.0.0"))
        self.assertTrue(is_at_or_above("2.0.0", "2.0.0-beta"))
        self.assertFalse(is_at_or_above("2.0.0-beta", "2.0.0"))

    def test_greater_and_lesser_across_segments(self):
        self.assertTrue(is_at_or_above("2.0.0", "1.9.9"))
        self.assertFalse(is_at_or_above("1.0.0", "1.0.1"))

    def test_strip_min_trailing_marker(self):
        self.assertEqual(_strip_min("1.2.3.min"), "1.2.3")
        self.assertEqual(_strip_min("1.2.3-min"), "1.2.3")
        self.assertEqual(_strip_min("1.2.3"), "1.2.3")
        # Only a trailing marker is stripped, not an interior "min".
        self.assertEqual(_strip_min("1.min.2"), "1.min.2")


# ---------------------------------------------------------------------------
# Range matching: _applies (below exclusive, atOrAbove inclusive, excludes)
# ---------------------------------------------------------------------------

class RangeMatchingTests(unittest.TestCase):
    def test_below_is_exclusive_upper_bound(self):
        self.assertTrue(_applies("1.6.2", {"below": "1.6.3"}))   # strictly below
        self.assertFalse(_applies("1.6.3", {"below": "1.6.3"}))  # boundary excluded
        self.assertFalse(_applies("1.7.0", {"below": "1.6.3"}))  # above

    def test_at_or_above_is_inclusive_lower_bound(self):
        vuln = {"atOrAbove": "1.0.0", "below": "2.0.0"}
        self.assertTrue(_applies("1.0.0", vuln))   # boundary included
        self.assertTrue(_applies("1.5.0", vuln))   # inside
        self.assertFalse(_applies("0.9.9", vuln))  # below lower bound
        self.assertFalse(_applies("2.0.0", vuln))  # at upper bound (excluded)

    def test_excludes_exact_string_membership(self):
        vuln = {"below": "2.0.0", "excludes": ["1.5.0"]}
        self.assertFalse(_applies("1.5.0", vuln))  # exact excluded version
        self.assertTrue(_applies("1.5.1", vuln))   # not excluded

    def test_no_bounds_matches_all_versions(self):
        self.assertTrue(_applies("9.9.9", {"severity": "high"}))

    def test_unsupported_range_keys_are_noops(self):
        # retire.js (and this port) only honor below/atOrAbove/excludes; unknown
        # keys such as above/atOrBelow are not filters and must not restrict.
        self.assertTrue(_applies("5.0.0", {"atOrBelow": "1.0.0"}))
        self.assertTrue(_applies("0.0.1", {"above": "9.0.0"}))


# ---------------------------------------------------------------------------
# Detection precedence + extractor coverage via detect_in_artifact
# ---------------------------------------------------------------------------

class DetectionExtractorTests(_FixtureDBMixin, unittest.TestCase):
    def setUp(self):
        self.install_db(_base_fixture_db())
        self.matchers = js_cve._get_matchers()

    def test_filename_extractor(self):
        det = detect_in_artifact(
            self.matchers, "https://ex.com/js/jquery-1.6.2.js", None
        )
        self.assertIn(("jquery", "1.6.2", "filename"), det)

    def test_uri_extractor(self):
        det = detect_in_artifact(
            self.matchers, "https://cdn.ex.com/1.6.2/jquery.min.js", None
        )
        self.assertEqual(len(det), 1)
        lib, ver, how = det[0]
        self.assertEqual((lib, ver), ("jquery", "1.6.2"))
        self.assertEqual(how, "uri")

    def test_filecontent_extractor_when_url_has_no_signal(self):
        det = detect_in_artifact(
            self.matchers, "https://ex.com/app.js", "/*! jQuery v1.6.2 | (c) foo */"
        )
        self.assertEqual(det, [("jquery", "1.6.2", "filecontent")])

    def test_hash_extractor_with_controlled_fixture(self):
        content = "console.log('tinylib bootstrap');"
        digest = hashlib.sha1(content.encode("utf-8", "ignore")).hexdigest()
        raw = _base_fixture_db()
        raw["tinylib"] = {
            "extractors": {"hashes": {digest: "0.0.1"}},
            "vulnerabilities": [
                {
                    "below": "1.0.0",
                    "severity": "high",
                    "identifiers": {"CVE": ["CVE-9999-0001"]},
                }
            ],
        }
        self.install_db(raw)
        matchers = js_cve._get_matchers()
        det = detect_in_artifact(matchers, "https://ex.com/x.js", content)
        self.assertEqual(det, [("tinylib", "0.0.1", "hash")])

    def test_url_signal_takes_precedence_over_content(self):
        # Filename gives a version; content is never consulted (precedence).
        det = detect_in_artifact(
            self.matchers,
            "https://ex.com/jquery-1.6.2.js",
            "/*! jQuery v3.7.1 */",  # would be a different (patched) version
        )
        versions = {v for _, v, _ in det}
        self.assertEqual(versions, {"1.6.2"})

    def test_content_matches_collapse_to_one_detection(self):
        # Same banner appearing twice -> _uniq collapses to a single detection.
        content = "/*! jQuery v1.6.2 */\n/*! jQuery v1.6.2 */"
        det = detect_in_artifact(self.matchers, "https://ex.com/app.js", content)
        self.assertEqual(det, [("jquery", "1.6.2", "filecontent")])

    def test_no_recognizable_library_yields_nothing(self):
        det = detect_in_artifact(
            self.matchers, "https://ex.com/app.js", "var x = 1; function y(){}"
        )
        self.assertEqual(det, [])

    def test_name_without_extractable_version_yields_nothing(self):
        # The library banner is present but the version token cannot be captured
        # (non-numeric) -> oracle discipline: no version, no detection.
        det = detect_in_artifact(
            self.matchers, "https://ex.com/app.js", "/*! jQuery vFOO custom build */"
        )
        self.assertEqual(det, [])

    def test_versionless_url_yields_nothing(self):
        det = detect_in_artifact(self.matchers, "https://ex.com/jquery.min.js", None)
        self.assertEqual(det, [])

    def test_leading_slash_filename_pattern_matches_basename(self):
        # Regression: a filename extractor carrying a leading path separator
        # (e.g. ExtJS's "/ext-all-(§§version§§).js") must still match the bare
        # basename - the leading "/" is stripped before anchoring, else the
        # library could never be detected.
        raw = _base_fixture_db()
        raw["extjs"] = {
            "extractors": {
                "filename": ["/ext-all-(§§version§§)(\\.min)?\\.js"],
            },
            "vulnerabilities": [
                {"below": "9.9.9", "severity": "high",
                 "identifiers": {"CVE": ["CVE-9999-1234"]}},
            ],
        }
        self.install_db(raw)
        matchers = js_cve._get_matchers()
        det = detect_in_artifact(matchers, "https://host/js/ext-all-4.2.1.js", None)
        self.assertIn(("extjs", "4.2.1", "filename"), det)


# ---------------------------------------------------------------------------
# _fetch_js response gating (_looks_like_js_body): soft-404 / HTML must be skipped
# ---------------------------------------------------------------------------

class FetchGatingTests(unittest.TestCase):
    def test_real_js_body_passes(self):
        self.assertTrue(js_cve._looks_like_js_body(
            200, "application/javascript", "/*! jQuery v1.6.2 */ var x=1;"))

    def test_missing_content_type_but_js_body_passes(self):
        # Many static hosts/CDNs omit content-type for .js; a non-HTML body is OK.
        self.assertTrue(js_cve._looks_like_js_body(
            200, "", "/*! jQuery v1.6.2 */"))

    def test_non_200_rejected(self):
        self.assertFalse(js_cve._looks_like_js_body(
            404, "application/javascript", "/*! jQuery v1.6.2 */"))

    def test_html_content_type_rejected(self):
        # The adversarial soft-404 repro: an HTML error/SPA page embedding a
        # library banner must NOT be scanned as JS.
        body = "<html>...<script>/*! jQuery v1.6.2 */</script>...404 Not Found</html>"
        self.assertFalse(js_cve._looks_like_js_body(200, "text/html; charset=utf-8", body))

    def test_html_body_without_content_type_rejected(self):
        body = "<!DOCTYPE html>\n<html><script>/*! jQuery v1.6.2 */</script></html>"
        self.assertFalse(js_cve._looks_like_js_body(200, "", body))

    def test_xml_rejected(self):
        self.assertFalse(js_cve._looks_like_js_body(200, "application/xml", "<?xml version='1.0'?>"))


# ---------------------------------------------------------------------------
# End-to-end scan_js_cves against the fixture DB (positives, negatives, schema)
# ---------------------------------------------------------------------------

class ScanFixtureTests(_FixtureDBMixin, unittest.TestCase):
    def setUp(self):
        self.install_db(_base_fixture_db())

    def test_vulnerable_jquery_emits_expected_cve_and_schema(self):
        corpus = [
            {"url": "https://site.tld/js/app.js", "content": "/*! jQuery v1.6.2 */"}
        ]
        findings = _run(scan_js_cves(corpus))
        self.assertTrue(findings)
        for f in findings:
            self.assertTrue(_is_canonical(f), validate_finding(f))
            self.assertEqual(f["module"], "js_cve")
            self.assertEqual(f["status"], "VULNERABLE")
            self.assertEqual(f["severity"], "MEDIUM")
            self.assertEqual(f["service_version"], "jquery 1.6.2")
            self.assertEqual(f["target"], "site.tld")
            self.assertEqual(f["url"], "https://site.tld/js/app.js")

        vulns = {f["vulnerability"] for f in findings}
        self.assertIn("CVE-2011-4969 - jquery 1.6.2", vulns)
        self.assertIn("CVE-2020-11022 - jquery 1.6.2", vulns)

        cve_finding = next(
            f for f in findings if f["vulnerability"].startswith("CVE-2011-4969")
        )
        # CVE id mirrored into details so downstream KEV/EPSS enrichment fires,
        # and the detection method is recorded.
        self.assertIn("CVE-2011-4969", cve_finding["details"])
        self.assertIn("filecontent", cve_finding["details"])

    def test_patched_jquery_emits_no_finding(self):
        corpus = [{"url": "https://site.tld/js/app.js", "content": "/*! jQuery v3.7.1 */"}]
        self.assertEqual(_run(scan_js_cves(corpus)), [])

    def test_unknown_library_emits_no_finding(self):
        corpus = [{"url": "https://site.tld/app.js", "content": "var a=1;// nothing"}]
        self.assertEqual(_run(scan_js_cves(corpus)), [])

    def test_versionless_input_emits_no_finding(self):
        corpus = [
            "https://site.tld/jquery.min.js",  # bare URL, no version, no content
            {"url": "https://site.tld/lib.js", "content": "/*! jQuery vNOPE */"},
        ]
        self.assertEqual(_run(scan_js_cves(corpus)), [])

    def test_dedupe_same_lib_version_same_url(self):
        # The identical artifact twice must not double the findings.
        art = {"url": "https://site.tld/app.js", "content": "/*! jQuery v1.6.2 */"}
        findings = _run(scan_js_cves([art, dict(art)]))
        vulns = [f["vulnerability"] for f in findings]
        self.assertEqual(len(vulns), len(set(vulns)))
        self.assertEqual(len(findings), 2)  # exactly the 2 distinct CVEs, not 4

    def test_distinct_urls_are_preserved(self):
        corpus = [
            {"url": "https://a.tld/app.js", "content": "/*! jQuery v1.6.2 */"},
            {"url": "https://b.tld/app.js", "content": "/*! jQuery v1.6.2 */"},
        ]
        findings = _run(scan_js_cves(corpus))
        targets = {f["target"] for f in findings}
        self.assertEqual(targets, {"a.tld", "b.tld"})

    def test_empty_corpus_returns_empty_list(self):
        self.assertEqual(_run(scan_js_cves([])), [])
        self.assertEqual(_run(scan_js_cves(None)), [])

    def test_content_present_is_not_refetched(self):
        corpus = [{"url": "https://site.tld/app.js", "content": "/*! jQuery v1.6.2 */"}]
        with patch.object(js_cve, "_fetch_js", new=AsyncMock(return_value="")) as m:
            findings = _run(scan_js_cves(corpus))
        m.assert_not_called()
        self.assertTrue(findings)

    def test_missing_content_is_fetched_via_mock(self):
        corpus = ["https://site.tld/some.js"]  # URL only -> needs a fetch
        fake = AsyncMock(return_value="/*! jQuery v1.6.2 */")
        with patch.object(js_cve, "_fetch_js", new=fake):
            findings = _run(scan_js_cves(corpus))
        fake.assert_awaited()
        self.assertTrue(findings)
        self.assertTrue(all(f["module"] == "js_cve" for f in findings))

    def test_fetch_disabled_skips_download(self):
        corpus = ["https://site.tld/some.js"]
        with patch.object(js_cve, "_fetch_js", new=AsyncMock(return_value="x")) as m:
            findings = _run(scan_js_cves(corpus, fetch_missing=False))
        m.assert_not_called()
        self.assertEqual(findings, [])

    def test_malformed_port_does_not_abort_loop(self):
        # A non-numeric port in a discovered/archived URL must not raise inside the
        # detection loop (urllib .port raises ValueError) - the finding for that URL
        # is still emitted and later URLs are not silently dropped.
        corpus = [
            {"url": "https://bad.tld:notaport/app.js", "content": "/*! jQuery v1.6.2 */"},
            {"url": "https://good.tld/app.js", "content": "/*! jQuery v1.6.2 */"},
        ]
        findings = _run(scan_js_cves(corpus))
        targets = {f["target"] for f in findings}
        self.assertIn("bad.tld", targets)   # bad-port URL still produced a finding
        self.assertIn("good.tld", targets)  # subsequent URL not dropped
        bad = next(f for f in findings if f["target"] == "bad.tld")
        self.assertEqual(bad["port"], "443")  # falls back to the scheme default

    def test_tuple_and_alt_key_corpus_shapes(self):
        corpus = [
            ("https://t.tld/app.js", "/*! jQuery v1.6.2 */"),        # (url, content)
            {"js_url": "https://k.tld/x.js", "body": "/*! jQuery v1.6.2 */"},  # alt keys
        ]
        findings = _run(scan_js_cves(corpus))
        targets = {f["target"] for f in findings}
        self.assertEqual(targets, {"t.tld", "k.tld"})


# ---------------------------------------------------------------------------
# Fail-safe: missing / corrupt DB never raises and yields nothing
# ---------------------------------------------------------------------------

class FailSafeTests(_FixtureDBMixin, unittest.TestCase):
    def test_missing_db_returns_empty_without_raising(self):
        self.install_missing_db()
        self.assertEqual(load_db(force=True), {})
        corpus = [{"url": "https://site.tld/app.js", "content": "/*! jQuery v1.6.2 */"}]
        self.assertEqual(_run(scan_js_cves(corpus)), [])

    def test_corrupt_db_returns_empty_without_raising(self):
        self.install_corrupt_db()
        self.assertEqual(load_db(force=True), {})
        corpus = [{"url": "https://site.tld/app.js", "content": "/*! jQuery v1.6.2 */"}]
        self.assertEqual(_run(scan_js_cves(corpus)), [])

    def test_garbage_corpus_items_are_ignored(self):
        self.install_db(_base_fixture_db())
        corpus = [None, 123, {"no_url_no_content": True}, object()]
        self.assertEqual(_run(scan_js_cves(corpus)), [])


# ---------------------------------------------------------------------------
# Smoke test against the real vendored DB (shape + robustness only).
# ---------------------------------------------------------------------------

class VendoredDBSmokeTests(unittest.TestCase):
    def tearDown(self):
        js_cve.DB_PATH = ORIG_DB_PATH
        js_cve._DB_LOADED = False
        js_cve._DB_CACHE = None
        js_cve._MATCHERS_CACHE = None

    def test_vendored_db_loads(self):
        db = load_db(force=True)
        self.assertIsInstance(db, dict)
        self.assertTrue(db)  # vendored DB ships with content

    def test_real_jquery_1_6_2_detected_and_canonical(self):
        load_db(force=True)
        corpus = [
            {"url": "https://site.tld/js/jquery.js", "content": "/*! jQuery v1.6.2 */"}
        ]
        findings = _run(scan_js_cves(corpus))
        self.assertIsInstance(findings, list)
        for f in findings:
            self.assertTrue(_is_canonical(f), validate_finding(f))
        vulns = " ".join(f["vulnerability"] for f in findings)
        self.assertIn("CVE-2011-4969", vulns)


if __name__ == "__main__":
    unittest.main()
