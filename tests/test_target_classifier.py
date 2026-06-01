import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import unittest
from main import target_classifier


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


if __name__ == '__main__':
    unittest.main()
