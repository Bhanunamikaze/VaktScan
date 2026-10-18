"""Tests for the self-contained HTML report (reporter.save_results_to_html)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from reporter import save_results_to_html, save_unified_html_report  # noqa: E402


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

    def test_unified_report_combines_state_and_tool_artifacts(self):
        artifact_dir = os.path.join(self.dir, "artifacts")
        os.makedirs(os.path.join(artifact_dir, "dirsearch_reports"))
        with open(os.path.join(artifact_dir, "subfinder_example.txt"), "w", encoding="utf-8") as fh:
            fh.write("api.example.com\n")
        with open(os.path.join(artifact_dir, "dirsearch_reports", "dirsearch_report_api.txt"), "w", encoding="utf-8") as fh:
            fh.write("https://api.example.com/admin 200\n")
        state = {
            "phase": "vulnerability_scanning",
            "primary_target": "example.com",
            "recon_enumeration_results": {
                "example.com": {"subdomains": ["api.example.com", "www.example.com"]}
            },
            "recon_http_results": {
                "example.com": {"httpx_data": [{
                    "url": "https://api.example.com", "status-code": 200,
                    "title": "API", "tech": ["nginx"], "host": "192.0.2.5",
                }]}
            },
            "open_ports": {"192.0.2.5": [80, 443]},
        }
        finding = [{
            "severity": "HIGH", "status": "VULNERABLE", "vulnerability": "Example issue",
            "target": "api.example.com", "resolved_ip": "192.0.2.5", "port": 443,
            "url": "https://api.example.com", "module": "nuclei", "details": "evidence",
        }]
        out = save_unified_html_report(
            finding, self.path, "example.com", state=state, artifact_root=artifact_dir
        )
        self.assertEqual(out, self.path)
        with open(self.path, encoding="utf-8") as fh:
            html = fh.read()
        for expected in (
            "Asset inventory", "Live web services", "Vulnerabilities and observations",
            "Directory discoveries", "All tool outputs", "api.example.com", "Example issue",
            "dirsearch_report_api.txt", "https://api.example.com/admin 200", "subfinder_example.txt",
        ):
            self.assertIn(expected, html)
        self.assertIn('id="global-search"', html)

    def test_unified_report_escapes_artifact_content(self):
        artifact_dir = os.path.join(self.dir, "artifacts")
        os.makedirs(artifact_dir)
        with open(os.path.join(artifact_dir, "raw.txt"), "w", encoding="utf-8") as fh:
            fh.write("<script>alert(1)</script>")
        save_unified_html_report([], self.path, artifact_root=artifact_dir)
        with open(self.path, encoding="utf-8") as fh:
            html = fh.read()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)


if __name__ == "__main__":
    unittest.main()
