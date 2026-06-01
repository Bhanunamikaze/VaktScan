import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import unittest
from modules.schema import CANONICAL_KEYS, validate_finding, normalize_finding


def _valid_finding(**overrides):
    base = {k: 'test_value' for k in CANONICAL_KEYS}
    base['status'] = 'INFO'
    base['severity'] = 'INFO'
    base['timestamp'] = '2026-06-01T12:00:00Z'
    base.update(overrides)
    return base


class TestValidateFinding(unittest.TestCase):
    def test_valid_finding_no_violations(self):
        self.assertEqual(validate_finding(_valid_finding()), [])

    def test_missing_key_reported(self):
        f = _valid_finding()
        del f['timestamp']
        violations = validate_finding(f)
        self.assertTrue(any('timestamp' in v for v in violations))

    def test_server_key_forbidden(self):
        f = _valid_finding()
        f['server'] = 'internal'
        violations = validate_finding(f)
        self.assertTrue(any('server' in v for v in violations))

    def test_invalid_status(self):
        f = _valid_finding(status='VULN')
        violations = validate_finding(f)
        self.assertTrue(any('status' in v.lower() for v in violations))

    def test_invalid_severity(self):
        f = _valid_finding(severity='EXTREME')
        violations = validate_finding(f)
        self.assertTrue(any('severity' in v.lower() for v in violations))


class TestNormalizeFinding(unittest.TestCase):
    def test_fills_missing_keys(self):
        f = {'status': 'INFO', 'vulnerability': 'test'}
        n = normalize_finding(f)
        self.assertTrue(all(k in n for k in CANONICAL_KEYS))

    def test_strips_server_promotes_resolved_ip(self):
        f = {'server': '10.0.0.1', 'resolved_ip': 'N/A'}
        n = normalize_finding(f)
        self.assertNotIn('server', n)
        self.assertEqual(n['resolved_ip'], '10.0.0.1')

    def test_strips_server_keeps_resolved_ip_when_set(self):
        f = {'server': '10.0.0.1', 'resolved_ip': '1.2.3.4'}
        n = normalize_finding(f)
        self.assertNotIn('server', n)
        self.assertEqual(n['resolved_ip'], '1.2.3.4')

    def test_timestamp_auto_set(self):
        f = {}
        n = normalize_finding(f)
        self.assertIn('timestamp', n)
        self.assertTrue(n['timestamp'].endswith('Z'))


if __name__ == '__main__':
    unittest.main()
