"""
Tests for subdomain-takeover detection inside modules/domain_scan.py.

Exercises detect_takeover_from_response against synthetic responses that
match every signature class and confirms the canonical reporting schema
is preserved.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules import domain_scan  # noqa: E402


def _entry(url='https://orphan.example.com/'):
    return {
        'url': url,
        'input': url,
        'host': '203.0.113.10',
        'port': 443,
        'status_code': 404,
        'title': '',
        'webserver': 'cloudfront',
        'content_length': 0,
    }


class TakeoverDetectionTests(unittest.TestCase):

    def setUp(self):
        self.scanner = domain_scan.DomainScanner('example.com')

    def test_signature_table_populated(self):
        self.assertGreater(len(domain_scan.TAKEOVER_SIGNATURES), 30)
        # Every signature row must have 4 fields and a valid severity.
        for vendor, marker, codes, severity in domain_scan.TAKEOVER_SIGNATURES:
            self.assertTrue(vendor)
            self.assertTrue(marker)
            self.assertTrue(codes)
            self.assertIn(severity, {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'})

    def test_github_pages_takeover_detected(self):
        body = "<html>There isn't a GitHub Pages site here.</html>"
        finding = self.scanner.detect_takeover_from_response(_entry(), 404, body)
        self.assertIsNotNone(finding)
        self.assertIn('GitHub Pages', finding['vulnerability'])
        self.assertEqual(finding['status'], 'CRITICAL')
        # Schema fields present.
        for key in ('module', 'target', 'url', 'details', 'severity', 'http_status'):
            self.assertIn(key, finding)

    def test_cpanel_orphan_takeover_detected(self):
        body = '<title>Default Web Site Page</title><body>nothing here</body>'
        finding = self.scanner.detect_takeover_from_response(_entry(), 200, body)
        self.assertIsNotNone(finding)
        self.assertIn('cPanel orphan', finding['vulnerability'])

    def test_aws_s3_takeover_detected(self):
        body = "<Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>"
        finding = self.scanner.detect_takeover_from_response(_entry(), 404, body)
        self.assertIsNotNone(finding)
        self.assertIn('AWS S3', finding['vulnerability'])
        self.assertEqual(finding['status'], 'CRITICAL')

    def test_no_false_positive_on_clean_404(self):
        body = '<html><h1>Not Found</h1>Sorry.</html>'
        finding = self.scanner.detect_takeover_from_response(_entry(), 404, body)
        # No vendor marker → must not fire.
        self.assertIsNone(finding)

    def test_status_code_gate_holds(self):
        body = "There isn't a GitHub Pages site here."
        # GitHub Pages signature is valid for 200/404; 500 must NOT fire.
        self.assertIsNone(self.scanner.detect_takeover_from_response(_entry(), 500, body))


if __name__ == '__main__':
    unittest.main()
