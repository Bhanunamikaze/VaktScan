"""Tests for the self-contained HTML report (reporter.save_results_to_html)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from reporter import save_results_to_html  # noqa: E402


class HtmlReportTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="vaktscan_html_")
        self.path = os.path.join(self.dir, "report.html")

    def _write(self, findings, **kw):
        out = save_results_to_html(findings, filename=self.path, **kw)
        self.assertEqual(out, self.path)
        with open(self.path, encoding="utf-8") as fh:
            return fh.read()

    def test_escapes_untrusted_text(self):
        findings = [{
            "severity": "HIGH", "status": "VULNERABLE",
            "vulnerability": "XSS via <script>alert(1)</script>",
            "target": "a.com", "resolved_ip": "1.2.3.4", "port": "443",
            "url": "https://a.com/x", "module": "web_checks",
            "details": "payload a & b <img src=x>",
        }]
        html = self._write(findings)
        # Raw injection must not survive; escaped form must be present.
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&amp;", html)

    def test_severity_counts_and_ordering(self):
        findings = [
            {"severity": "INFO", "vulnerability": "i", "target": "t"},
            {"severity": "CRITICAL", "vulnerability": "c", "target": "t"},
            {"severity": "HIGH", "vulnerability": "h", "target": "t"},
        ]
        html = self._write(findings, scan_label="run1")
        self.assertIn("run1", html)
        self.assertIn("3 finding(s)", html)
        # CRITICAL row should appear before the INFO row (severity-ordered table).
        self.assertLess(html.index(">c<"), html.index(">i<"))

    def test_empty_is_valid_report(self):
        html = self._write([])
        self.assertIn("No findings.", html)
        self.assertIn("0 finding(s)", html)

    def test_self_contained_no_external_assets(self):
        html = self._write([{"severity": "LOW", "vulnerability": "x", "target": "t"}])
        # Inlined CSS/JS only - no external stylesheet/script references.
        self.assertNotIn("http://", html.split("</head>")[0].replace("initial-scale", ""))
        self.assertIn("<style>", html)


if __name__ == "__main__":
    unittest.main()
