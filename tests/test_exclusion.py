"""Tests for scan-exclusion patterns (utils.build_exclusion_matcher / load_exclusion_patterns)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils import build_exclusion_matcher, load_exclusion_patterns  # noqa: E402


class ExclusionMatcherTests(unittest.TestCase):
    def test_glob_match(self):
        m = build_exclusion_matcher(["customer1*.steinzsecurity.com"])
        self.assertTrue(m("customer123.steinzsecurity.com"))
        self.assertTrue(m("customer1.steinzsecurity.com"))
        self.assertFalse(m("customer2.steinzsecurity.com"))
        self.assertFalse(m("www.steinzsecurity.com"))

    def test_case_insensitive(self):
        m = build_exclusion_matcher(["*.Internal.example.com"])
        self.assertTrue(m("HOST.internal.EXAMPLE.com"))

    def test_wildcard_question_mark(self):
        m = build_exclusion_matcher(["customer?.example.com"])
        self.assertTrue(m("customer5.example.com"))
        self.assertFalse(m("customer50.example.com"))

    def test_regex_prefix(self):
        m = build_exclusion_matcher([r"re:^(dev|stg)\.-?"])
        self.assertTrue(m("dev.example.com"))
        self.assertFalse(m("prod.example.com"))

    def test_multiple_patterns(self):
        m = build_exclusion_matcher(["*.customers.example.com", "re:^internal\\."])
        self.assertTrue(m("a.customers.example.com"))
        self.assertTrue(m("internal.example.com"))
        self.assertFalse(m("app.example.com"))

    def test_empty_never_excludes(self):
        self.assertFalse(build_exclusion_matcher([])("anything.com"))
        self.assertFalse(build_exclusion_matcher(None)("anything.com"))
        self.assertFalse(build_exclusion_matcher(["  ", ""])("anything.com"))

    def test_invalid_regex_ignored(self):
        # A broken regex must not raise; it's simply dropped.
        m = build_exclusion_matcher(["re:[unterminated", "*.bad.com"])
        self.assertTrue(m("x.bad.com"))
        self.assertFalse(m("ok.com"))


class LoadPatternsTests(unittest.TestCase):
    def test_items_and_file_combined(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "ex.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# a comment\n\n*.customers.example.com\nre:^stg\\.\n")
        pats = load_exclusion_patterns(["extra*.example.com"], path)
        self.assertIn("extra*.example.com", pats)
        self.assertIn("*.customers.example.com", pats)
        self.assertIn("re:^stg\\.", pats)
        self.assertNotIn("# a comment", pats)
        self.assertNotIn("", pats)

    def test_missing_file_is_ignored(self):
        self.assertEqual(load_exclusion_patterns(["a*"], "/no/such/file.txt"), ["a*"])

    def test_none_inputs(self):
        self.assertEqual(load_exclusion_patterns(None, None), [])


if __name__ == "__main__":
    unittest.main()
