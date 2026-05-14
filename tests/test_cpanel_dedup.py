"""
Tests for _dedup_and_validate (cpanel_plan.md §11) and the §9c reporting
schema. Synthetic finding lists exercise each collapsing rule.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules import cpanel  # noqa: E402


def _f(**kwargs):
    base = {
        'status': 'VULNERABLE',
        'severity': 'MEDIUM',
        'vulnerability': 'Test finding',
        'details': 'Details body',
        'payload_url': 'https://example.com/x',
        '_evidence_hash': 'abc',
        '_surface': 'cPanel',
        '_cve_id': None,
    }
    base.update(kwargs)
    return base


class DedupAndValidateTests(unittest.TestCase):

    def test_vague_row_dropped(self):
        # Missing details — vague → dropped (§11 rule 7).
        findings = [_f(details='')]
        self.assertEqual(cpanel._dedup_and_validate(findings), [])

    def test_status_normalised_to_info(self):
        # Unknown status falls through to INFO.
        findings = [_f(status='WEIRD')]
        out = cpanel._dedup_and_validate(findings)
        self.assertEqual(out[0]['status'], 'INFO')

    def test_within_check_dedup_merges_payload_url(self):
        # Two identical findings with different payload_urls → one row, pipe-joined urls.
        findings = [
            _f(payload_url='https://a/1'),
            _f(payload_url='https://a/2'),
        ]
        out = cpanel._dedup_and_validate(findings)
        self.assertEqual(len(out), 1)
        self.assertIn('https://a/1', out[0]['payload_url'])
        self.assertIn('https://a/2', out[0]['payload_url'])

    def test_tsr_observable_collapse(self):
        # TSR row whose details references the same CVE as an observable
        # row → TSR row dropped (§11 rule 4).
        findings = [
            _f(vulnerability='CVE-2023-29489 - cPanel reflected XSS', _cve_id='CVE-2023-29489', payload_url='https://x/cpanelwebcall/marker'),
            _f(vulnerability='TSR-2023-0005 - cPanel & WHM Security Advisory',
               details='Covers: CVE-2023-29489. Fix in 11.110.0.32.',
               payload_url='https://x/'),
        ]
        out = cpanel._dedup_and_validate(findings)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0]['vulnerability'].startswith('CVE-2023-29489'))

    def test_distinct_findings_kept(self):
        findings = [
            _f(vulnerability='XSS A', _evidence_hash='h1'),
            _f(vulnerability='XSS B', _evidence_hash='h2'),
        ]
        out = cpanel._dedup_and_validate(findings)
        self.assertEqual(len(out), 2)


class ReportingSchemaTests(unittest.TestCase):
    """§9c.2 contract: every finding must have the canonical keys after run_scans."""

    REQUIRED_KEYS = ('status', 'severity', 'vulnerability', 'details', 'payload_url')

    def test_finding_factory_includes_required_keys(self):
        f = cpanel._finding(
            status='VULNERABLE',
            severity='HIGH',
            vulnerability='X',
            details='Y',
            payload_url='https://example/x',
        )
        for k in self.REQUIRED_KEYS:
            self.assertIn(k, f)

    def test_strip_internals_removes_underscore_keys(self):
        f = cpanel._finding(status='INFO', severity='LOW', vulnerability='X', details='Y', payload_url='https://e/x', evidence_hash='h', surface='cPanel', cve_id='CVE-X')
        cpanel._strip_internals(f)
        self.assertNotIn('_evidence_hash', f)
        self.assertNotIn('_surface', f)
        self.assertNotIn('_cve_id', f)
        for k in self.REQUIRED_KEYS:
            self.assertIn(k, f)


class VersionMatchingTests(unittest.TestCase):
    def test_is_version_affected_range(self):
        self.assertTrue(cpanel.is_version_affected('11.110.0.10', ['>=11.110.0.0,<11.110.0.32']))
        self.assertFalse(cpanel.is_version_affected('11.110.0.40', ['>=11.110.0.0,<11.110.0.32']))

    def test_is_version_affected_lt(self):
        self.assertTrue(cpanel.is_version_affected('11.65.0.0', ['<11.66.0.0']))
        self.assertFalse(cpanel.is_version_affected('11.67.0.0', ['<11.66.0.0']))

    def test_compare_versions(self):
        self.assertEqual(cpanel.compare_versions('1.2.3', '1.2.4'), -1)
        self.assertEqual(cpanel.compare_versions('2.0', '1.99'), 1)
        self.assertEqual(cpanel.compare_versions('1.0.0', '1.0'), 0)


if __name__ == '__main__':
    unittest.main()
