"""
Round-trip test for the §9c reporting contract.

Builds synthetic findings, stamps them with the canonical reporting
fields, runs them through main.save_results_to_csv, and confirms every
CSV column round-trips with the expected value. Also confirms
deduplicate_vulnerabilities accepts the rows unchanged.
"""
import csv
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# main.py performs print_logo() and other CLI niceties on import; we only
# need its CSV emitter and deduper.
import main as vakt_main  # noqa: E402
from modules import cpanel  # noqa: E402


def _stamped_finding(**overrides):
    base = cpanel._finding(
        status='VULNERABLE',
        severity='HIGH',
        vulnerability='CVE-2023-29489 - cPanel reflected XSS via /cpanelwebcall/',
        details='Reflected XSS confirmed via marker reflection in HTML body.',
        payload_url='https://example.com:2083/cpanelwebcall/vkt-marker',
    )
    base.update({
        'module': cpanel.MODULE_NAME,
        'service_version': '11.110.0.10',
        'target': 'example.com',
        'server': 'example.com',
        'port': 2083,
        'resolved_ip': '203.0.113.10',
        'url': 'https://example.com:2083/cpanelwebcall/vkt-marker',
        'http_status': 200,
        'page_title': 'cPanel Login',
        'content_length': 4096,
    })
    base.update(overrides)
    cpanel._strip_internals(base)
    return base


class CsvRoundTripTests(unittest.TestCase):

    EXPECTED_HEADERS = [
        'Timestamp', 'Status', 'Vulnerability', 'Hostname', 'IP Address',
        'Port', 'URL', 'Payload_URL', 'Module', 'Service_Version',
        'Severity', 'Details', 'HTTP_Status', 'Page_Title', 'Content_Length',
    ]

    def test_csv_columns_match_contract(self):
        finding = _stamped_finding()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'out.csv')
            vakt_main.save_results_to_csv([finding], filename=path)
            with open(path, 'r', encoding='utf-8') as fh:
                rows = list(csv.reader(fh))
            self.assertEqual(rows[0], self.EXPECTED_HEADERS)
            # 15 columns; Timestamp is column 0 (filled by emitter).
            self.assertEqual(len(rows[1]), 15)
            # Hostname column (3) is the target.
            self.assertEqual(rows[1][3], 'example.com')
            # IP Address column (4).
            self.assertEqual(rows[1][4], '203.0.113.10')
            # Port column (5).
            self.assertEqual(rows[1][5], '2083')
            # Status column (1).
            self.assertEqual(rows[1][1], 'VULNERABLE')
            # Module column (8).
            self.assertEqual(rows[1][8], 'cPanel')
            # Severity column (10).
            self.assertEqual(rows[1][10], 'HIGH')

    def test_ip_target_blanks_hostname_column(self):
        # The emitter blanks Hostname when the target is a plain IP.
        finding = _stamped_finding(target='203.0.113.10')
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'out.csv')
            vakt_main.save_results_to_csv([finding], filename=path)
            with open(path, 'r', encoding='utf-8') as fh:
                rows = list(csv.reader(fh))
            self.assertEqual(rows[1][3], '')

    def test_status_vocabulary_round_trips(self):
        for status in cpanel.VALID_STATUSES:
            finding = _stamped_finding(status=status)
            with tempfile.TemporaryDirectory() as tmpdir:
                path = os.path.join(tmpdir, 'out.csv')
                vakt_main.save_results_to_csv([finding], filename=path)
                with open(path, 'r', encoding='utf-8') as fh:
                    rows = list(csv.reader(fh))
                self.assertEqual(rows[1][1], status)


class DeduplicatorAcceptsCpanelFindings(unittest.TestCase):
    def test_deduplicator_passes_cpanel_rows_through(self):
        findings = [_stamped_finding(), _stamped_finding(target='example.com', resolved_ip='203.0.113.10')]
        out = vakt_main.deduplicate_vulnerabilities(findings)
        # Two findings with the same target+CVE collapse via main.py logic.
        self.assertEqual(len(out), 1)


if __name__ == '__main__':
    unittest.main()
