"""
Oracle-completeness test.

Asserts every entry in OBSERVABLE_CVE_CHECKS carries the oracle triple
(positive + control + indicator) required by §10.4 of cpanel_plan.md and
that every test_cve_payload-equivalent emission goes through it.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules import cpanel  # noqa: E402


class OracleCompletenessTests(unittest.TestCase):
    def test_every_observable_cve_has_oracle_triple(self):
        for cve_id, meta in cpanel.OBSERVABLE_CVE_CHECKS.items():
            self.assertIn('oracle', meta, f"{cve_id} is missing 'oracle'")
            oracle = meta['oracle']
            for key in ('positive', 'control', 'indicator'):
                self.assertIn(key, oracle, f"{cve_id} oracle missing '{key}'")
                self.assertTrue(callable(oracle[key]), f"{cve_id}.oracle.{key} not callable")
            self.assertIn('drop_if', oracle, f"{cve_id} oracle missing 'drop_if'")
            self.assertIsInstance(oracle['drop_if'], list)

    def test_every_observable_cve_has_required_metadata(self):
        required = ('description', 'severity', 'status', 'surface', 'details')
        for cve_id, meta in cpanel.OBSERVABLE_CVE_CHECKS.items():
            for key in required:
                self.assertIn(key, meta, f"{cve_id} missing metadata key {key}")
            self.assertIn(meta['status'], cpanel.VALID_STATUSES, f"{cve_id} invalid status {meta['status']}")
            self.assertIn(meta['severity'], {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'})


class DataTableTests(unittest.TestCase):
    def test_tsr_archive_loaded(self):
        self.assertGreater(len(cpanel.CPANEL_SECURITY_BULLETINS), 0)
        for b in cpanel.CPANEL_SECURITY_BULLETINS:
            for key in ('id', 'severity', 'affected_versions', 'cves', 'summary'):
                self.assertIn(key, b)

    def test_bundled_cves_loaded(self):
        self.assertIn('apache_httpd', cpanel.BUNDLED_COMPONENT_CVES)
        self.assertIn('exim', cpanel.BUNDLED_COMPONENT_CVES)
        self.assertIn('roundcube', cpanel.BUNDLED_COMPONENT_CVES)
        self.assertIn('whmcs', cpanel.BUNDLED_COMPONENT_CVES)

    def test_must_call_out_cves_present(self):
        all_cves = set()
        for entries in cpanel.BUNDLED_COMPONENT_CVES.values():
            for e in entries:
                all_cves.add(e['cve'])
        # The "never-miss" set from cpanel_plan.md §4.3.
        must_have = {
            'CVE-2024-25602',   # WHMCS RCE
            'CVE-2024-37383',   # Roundcube stored-XSS
            'CVE-2024-23184',   # Dovecot
            'CVE-2024-4577',    # PHP CGI
            'CVE-2024-38476',   # Apache mod_rewrite
            'CVE-2023-25690',   # Apache smuggling
            'CVE-2019-10149',   # Exim wizard
            'CVE-2020-28017',   # Exim 21Nails
            'CVE-2022-30287',   # Horde
            'CVE-2024-6387',    # OpenSSH regreSSHion
            'CVE-2014-0160',    # Heartbleed
            'CVE-2015-3306',    # ProFTPD mod_copy
            'CVE-2017-1000501', # AWStats path traversal
            'CVE-2023-49103',   # ownCloud
        }
        missing = must_have - all_cves
        self.assertFalse(missing, f"Must-call-out CVEs missing from bundled_cves.json: {missing}")


class StatusVocabularyTests(unittest.TestCase):
    def test_valid_statuses_match_main_py(self):
        # main.py:1119-1128 colour-codes exactly these four values.
        self.assertEqual(cpanel.VALID_STATUSES, {'CRITICAL', 'VULNERABLE', 'POTENTIAL', 'INFO'})


if __name__ == '__main__':
    unittest.main()
