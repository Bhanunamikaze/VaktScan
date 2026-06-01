import subprocess
import sys
import os
import unittest

WORKTREE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


class TestCLISmoke(unittest.TestCase):
    def _help_exit_code(self, subcommand):
        result = subprocess.run(
            [sys.executable, 'main.py', subcommand, '--help'],
            capture_output=True, text=True, cwd=WORKTREE
        )
        return result.returncode, result.stdout

    def test_root_help(self):
        result = subprocess.run(
            [sys.executable, 'main.py', '--help'],
            capture_output=True, text=True, cwd=WORKTREE
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn('scan', result.stdout)

    def test_scan_help(self):
        code, out = self._help_exit_code('scan')
        self.assertEqual(code, 0)
        self.assertIn('target', out)

    def test_enum_help(self):
        code, _ = self._help_exit_code('enum')
        self.assertEqual(code, 0)

    def test_dns_help(self):
        code, _ = self._help_exit_code('dns')
        self.assertEqual(code, 0)

    def test_cloud_help(self):
        code, _ = self._help_exit_code('cloud')
        self.assertEqual(code, 0)

    def test_js_paths_help(self):
        code, _ = self._help_exit_code('js-paths')
        self.assertEqual(code, 0)

    def test_domain_scan_help(self):
        code, _ = self._help_exit_code('domain-scan')
        self.assertEqual(code, 0)

    def test_google_dork_help(self):
        code, _ = self._help_exit_code('google-dork')
        self.assertEqual(code, 0)

    def test_probe_help(self):
        code, _ = self._help_exit_code('probe')
        self.assertEqual(code, 0)


if __name__ == '__main__':
    unittest.main()
