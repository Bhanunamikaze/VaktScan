import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import unittest
from main import target_classifier
from utils import is_valid_domain


class TestTargetClassifier(unittest.TestCase):
    def test_domain(self):
        self.assertEqual(target_classifier('example.com'), 'domain')
        self.assertEqual(target_classifier('sub.example.com'), 'domain')
        self.assertEqual(target_classifier('api.internal.corp'), 'domain')

    def test_ip(self):
        self.assertEqual(target_classifier('192.168.1.1'), 'ip')
        self.assertEqual(target_classifier('10.0.0.1'), 'ip')
        self.assertEqual(target_classifier('::1'), 'ip')

    def test_cidr(self):
        self.assertEqual(target_classifier('192.168.1.0/24'), 'cidr')
        self.assertEqual(target_classifier('10.0.0.0/8'), 'cidr')

    def test_file(self):
        # Use __file__ itself as a real file path
        self.assertEqual(target_classifier(__file__), 'file')

    def test_domain_not_confused_with_ip(self):
        # Make sure dotted names that aren't IPs are classified as domain
        self.assertEqual(target_classifier('localhost'), 'domain')  # no dot → domain fallback


class TestIsValidDomain(unittest.TestCase):
    def test_valid_domains(self):
        self.assertTrue(is_valid_domain('example.com'))
        self.assertTrue(is_valid_domain('sub.example.com'))
        self.assertTrue(is_valid_domain('my-domain.co.uk'))
        self.assertTrue(is_valid_domain('api.corp.local-ish'))

    def test_invalid_domains(self):
        self.assertFalse(is_valid_domain('endpoint'))
        self.assertFalse(is_valid_domain('prod'))
        self.assertFalse(is_valid_domain('localhost'))
        self.assertFalse(is_valid_domain('192.168.1.1'))
        self.assertFalse(is_valid_domain('example..com'))
        self.assertFalse(is_valid_domain('.example.com'))
        self.assertFalse(is_valid_domain('example.com.'))
        self.assertFalse(is_valid_domain('example.local'))
        self.assertFalse(is_valid_domain('example.internal'))


if __name__ == '__main__':
    unittest.main()
