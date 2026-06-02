"""
Integration test: mixed targets file (1 domain + 1 IP) correctly routes
domain lines to the recon pipeline and IP lines to the port-scan pipeline.

Verified behaviours:
- parse_targets_file() extracts both entries from a mixed file
- target_classifier() labels domain vs IP correctly
- cmd_scan() sets recon_domains=[domain] and passes the original file as
  targets_file so the IP is still port-scanned
- With --no-subdomain-enum, recon_domains is None but file is still passed
- Info messages report the correct domain/IP counts
"""

import argparse
import asyncio
import os
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

# Ensure project root is on the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import main as vakt_main
from utils import parse_targets_file
from main import target_classifier as _tc


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_args(**overrides):
    defaults = dict(
        concurrency=50,
        resume=False,
        module=None,
        ports=None,
        chunk_size=30000,
        no_subdomain_enum=False,
        wordlist=None,
        nmap=False,
        sub_domains_file=None,
        sarif=None,
        recon_concurrency=1,
        connect_timeout=3.0,
        port_retries=1,
        proxy=None,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _mixed_file(domain='example.com', ip='1.2.3.4'):
    f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    f.write(f"{domain}\n{ip}\n")
    f.close()
    return f.name


# ── parse / classify unit tests ───────────────────────────────────────────────

class TestMixedFileParsing(unittest.TestCase):
    def test_parse_extracts_both_entries(self):
        path = _mixed_file('example.com', '10.0.0.1')
        try:
            entries = parse_targets_file(path)
            self.assertIn('example.com', entries)
            self.assertIn('10.0.0.1', entries)
            self.assertEqual(len(entries), 2)
        finally:
            os.unlink(path)

    def test_classifier_labels_domain(self):
        self.assertEqual(_tc('example.com'), 'domain')
        self.assertEqual(_tc('sub.example.co.uk'), 'domain')

    def test_classifier_labels_ip(self):
        self.assertEqual(_tc('192.168.1.1'), 'ip')
        self.assertEqual(_tc('10.0.0.0/24'), 'cidr')

    def test_classifier_labels_file(self):
        path = _mixed_file()
        try:
            self.assertEqual(_tc(path), 'file')
        finally:
            os.unlink(path)

    def test_blank_lines_and_comments_are_skipped(self):
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        f.write("# comment\n\nexample.com\n\n# another comment\n10.0.0.1\n")
        f.close()
        try:
            entries = parse_targets_file(f.name)
            self.assertEqual(entries, ['example.com', '10.0.0.1'])
        finally:
            os.unlink(f.name)


# ── cmd_scan routing integration tests ───────────────────────────────────────

class TestCmdScanMixedRouting(unittest.TestCase):
    """
    Patches the module-level main() to a no-op async mock and verifies that
    cmd_scan() passes the correct arguments for mixed-file targets.
    """

    def _run(self, coro):
        return asyncio.run(coro)

    def test_domain_routed_to_recon_domains(self):
        """Domain lines must appear in recon_domains so subdomain enum runs."""
        path = _mixed_file('example.com', '1.2.3.4')
        captured = {}

        async def fake_main(**kwargs):
            captured.update(kwargs)

        try:
            with patch.object(vakt_main, 'main', new=AsyncMock(side_effect=fake_main)):
                self._run(vakt_main.cmd_scan(_make_args(target=path)))

            self.assertIsNotNone(captured.get('recon_domains'))
            self.assertIn('example.com', captured['recon_domains'])
        finally:
            os.unlink(path)

    def test_file_passed_as_targets_file_for_ip_scanning(self):
        """The original file must be passed as targets_file so IPs are port-scanned."""
        path = _mixed_file('example.com', '1.2.3.4')
        captured = {}

        async def fake_main(**kwargs):
            captured.update(kwargs)

        try:
            with patch.object(vakt_main, 'main', new=AsyncMock(side_effect=fake_main)):
                self._run(vakt_main.cmd_scan(_make_args(target=path)))

            self.assertEqual(captured.get('targets_file'), path)
        finally:
            os.unlink(path)

    def test_no_subdomain_enum_clears_recon_domains(self):
        """--no-subdomain-enum must set recon_domains=None even for domain lines."""
        path = _mixed_file('example.com', '1.2.3.4')
        captured = {}

        async def fake_main(**kwargs):
            captured.update(kwargs)

        try:
            with patch.object(vakt_main, 'main', new=AsyncMock(side_effect=fake_main)):
                self._run(vakt_main.cmd_scan(_make_args(target=path, no_subdomain_enum=True)))

            self.assertIsNone(captured.get('recon_domains'))
            self.assertEqual(captured.get('targets_file'), path)
        finally:
            os.unlink(path)

    def test_ip_only_file_has_no_recon_domains(self):
        """A file with only IPs must not trigger subdomain enum."""
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        f.write("10.0.0.1\n192.168.1.100\n")
        f.close()
        captured = {}

        async def fake_main(**kwargs):
            captured.update(kwargs)

        try:
            with patch.object(vakt_main, 'main', new=AsyncMock(side_effect=fake_main)):
                self._run(vakt_main.cmd_scan(_make_args(target=f.name)))

            self.assertIsNone(captured.get('recon_domains'))
        finally:
            os.unlink(f.name)

    def test_mixed_file_info_message_printed(self):
        """cmd_scan must print the domain/IP count message for mixed files."""
        path = _mixed_file('example.com', '1.2.3.4')

        async def fake_main(**kwargs):
            pass

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()

        try:
            with patch.object(vakt_main, 'main', new=AsyncMock(side_effect=fake_main)):
                with redirect_stdout(buf):
                    self._run(vakt_main.cmd_scan(_make_args(target=path)))

            output = buf.getvalue()
            # Should mention both domain and IP counts
            self.assertRegex(output, r'1 domain')
            self.assertRegex(output, r'1 IP')
        finally:
            os.unlink(path)

    def test_no_subdomain_enum_message_variant(self):
        """With --no-subdomain-enum the message should say enum is skipped."""
        path = _mixed_file('example.com', '1.2.3.4')

        async def fake_main(**kwargs):
            pass

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()

        try:
            with patch.object(vakt_main, 'main', new=AsyncMock(side_effect=fake_main)):
                with redirect_stdout(buf):
                    self._run(vakt_main.cmd_scan(_make_args(target=path, no_subdomain_enum=True)))

            self.assertIn('skipped', buf.getvalue())
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
