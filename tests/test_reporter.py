"""
Unit tests for reporter.py reporting layer.

Tests the CSV, JSON, and SARIF output helpers, ensuring:
- CSV has exactly 15 columns with proper schema
- Timestamp handling (from finding vs. injected)
- JSON structure and keys
- SARIF 2.1.0 validity
- Port scan CSV structure
"""
import csv
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import reporter


class TestSaveResultsToCsvColumns(unittest.TestCase):
    """Test CSV output structure and column count."""

    EXPECTED_HEADERS = [
        'Timestamp', 'Status', 'Vulnerability', 'Hostname', 'IP Address',
        'Port', 'URL', 'Payload_URL', 'Module', 'Service_Version',
        'Severity', 'Details', 'HTTP_Status', 'Page_Title', 'Content_Length',
    ]

    def test_csv_has_15_columns(self):
        """Verify CSV has exactly 15 columns with all canonical keys."""
        finding = {
            'status': 'VULNERABLE',
            'vulnerability': 'CVE-2023-29489 - Test',
            'target': 'example.com',
            'resolved_ip': '203.0.113.10',
            'port': 2083,
            'url': 'https://example.com:2083/test',
            'payload_url': 'https://example.com:2083/payload',
            'module': 'test_module',
            'service_version': '1.0.0',
            'severity': 'HIGH',
            'details': 'Test details',
            'http_status': 200,
            'page_title': 'Test Page',
            'content_length': 4096,
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            temp_file = f.name

        try:
            reporter.save_results_to_csv([finding], filename=temp_file)
            with open(temp_file, 'r', encoding='utf-8') as fh:
                rows = list(csv.reader(fh))

            # Check header
            self.assertEqual(rows[0], self.EXPECTED_HEADERS)
            # Check that data row has exactly 15 columns
            self.assertEqual(len(rows[1]), 15, f"Expected 15 columns, got {len(rows[1])}")
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_csv_values_mapped_correctly(self):
        """Verify CSV column values match expected mappings."""
        finding = {
            'status': 'VULNERABLE',
            'vulnerability': 'CVE-2023-TEST',
            'target': 'example.com',
            'resolved_ip': '203.0.113.10',
            'port': 8080,
            'url': 'https://example.com:8080/api',
            'payload_url': 'https://example.com:8080/payload',
            'module': 'test_mod',
            'service_version': '2.0.0',
            'severity': 'CRITICAL',
            'details': 'Critical vulnerability found',
            'http_status': 200,
            'page_title': 'Admin Panel',
            'content_length': 5000,
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            temp_file = f.name

        try:
            reporter.save_results_to_csv([finding], filename=temp_file)
            with open(temp_file, 'r', encoding='utf-8') as fh:
                rows = list(csv.reader(fh))

            data_row = rows[1]
            # Column indices from EXPECTED_HEADERS:
            # Status=1, Vulnerability=2, Hostname=3, IP Address=4, Port=5,
            # URL=6, Payload_URL=7, Module=8, Service_Version=9, Severity=10,
            # Details=11, HTTP_Status=12, Page_Title=13, Content_Length=14
            self.assertEqual(data_row[1], 'VULNERABLE')  # Status
            self.assertEqual(data_row[2], 'CVE-2023-TEST')  # Vulnerability
            self.assertEqual(data_row[3], 'example.com')  # Hostname
            self.assertEqual(data_row[4], '203.0.113.10')  # IP Address
            self.assertEqual(data_row[5], '8080')  # Port
            self.assertEqual(data_row[6], 'https://example.com:8080/api')  # URL
            self.assertEqual(data_row[7], 'https://example.com:8080/payload')  # Payload_URL
            self.assertEqual(data_row[8], 'test_mod')  # Module
            self.assertEqual(data_row[9], '2.0.0')  # Service_Version
            self.assertEqual(data_row[10], 'CRITICAL')  # Severity
            self.assertEqual(data_row[11], 'Critical vulnerability found')  # Details
            self.assertEqual(data_row[12], '200')  # HTTP_Status
            self.assertEqual(data_row[13], 'Admin Panel')  # Page_Title
            self.assertEqual(data_row[14], '5000')  # Content_Length
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)


class TestTimestampHandling(unittest.TestCase):
    """Test timestamp field handling in CSV output."""

    def test_timestamp_injected_when_not_present(self):
        """Verify Timestamp column is filled even when finding has no timestamp."""
        finding = {
            'status': 'VULNERABLE',
            'vulnerability': 'CVE-2023-TEST',
            'target': 'example.com',
            'resolved_ip': '203.0.113.10',
            'port': 443,
            'url': 'https://example.com',
            'payload_url': 'N/A',
            'module': 'test',
            'service_version': 'N/A',
            'severity': 'HIGH',
            'details': 'Test',
            'http_status': 200,
            'page_title': 'N/A',
            'content_length': 0,
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            temp_file = f.name

        try:
            reporter.save_results_to_csv([finding], filename=temp_file)
            with open(temp_file, 'r', encoding='utf-8') as fh:
                rows = list(csv.reader(fh))

            data_row = rows[1]
            # Timestamp is column 0
            timestamp_col = data_row[0]
            # Should be populated (not empty)
            self.assertNotEqual(timestamp_col, '', 'Timestamp column should be filled')
            # Should look like a timestamp (contains dashes and colons)
            self.assertIn('-', timestamp_col, 'Timestamp should contain date separators')
            self.assertIn(':', timestamp_col, 'Timestamp should contain time separators')
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_ip_target_blanks_hostname(self):
        """Verify IP addresses in target field result in blank Hostname column."""
        finding = {
            'status': 'VULNERABLE',
            'vulnerability': 'CVE-2023-TEST',
            'target': '203.0.113.10',  # IP as target, not hostname
            'resolved_ip': '203.0.113.10',
            'port': 443,
            'url': 'https://203.0.113.10',
            'payload_url': 'N/A',
            'module': 'test',
            'service_version': 'N/A',
            'severity': 'HIGH',
            'details': 'Test',
            'http_status': 200,
            'page_title': 'N/A',
            'content_length': 0,
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            temp_file = f.name

        try:
            reporter.save_results_to_csv([finding], filename=temp_file)
            with open(temp_file, 'r', encoding='utf-8') as fh:
                rows = list(csv.reader(fh))

            data_row = rows[1]
            # Hostname is column 3
            self.assertEqual(data_row[3], '', 'Hostname should be blank when target is an IP')
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)


class TestSaveResultsToJsonStructure(unittest.TestCase):
    """Test JSON output structure and content."""

    def test_json_output_structure(self):
        """Verify JSON output is a list of dicts with expected keys."""
        findings = [
            {
                'status': 'VULNERABLE',
                'vulnerability': 'CVE-2023-TEST-1',
                'target': 'example.com',
                'resolved_ip': '203.0.113.10',
                'port': 443,
                'url': 'https://example.com',
                'payload_url': 'N/A',
                'module': 'test_mod',
                'service_version': '1.0.0',
                'severity': 'HIGH',
                'details': 'Test vulnerability',
                'http_status': 200,
                'page_title': 'Test Page',
                'content_length': 1024,
            },
            {
                'status': 'VULNERABLE',
                'vulnerability': 'CVE-2023-TEST-2',
                'target': 'example2.com',
                'resolved_ip': '203.0.113.11',
                'port': 8080,
                'url': 'https://example2.com:8080',
                'payload_url': 'N/A',
                'module': 'test_mod2',
                'service_version': '2.0.0',
                'severity': 'CRITICAL',
                'details': 'Another test',
                'http_status': 201,
                'page_title': 'Admin',
                'content_length': 2048,
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_file = f.name

        try:
            reporter.save_results_to_json(findings, filename=temp_file)
            with open(temp_file, 'r', encoding='utf-8') as fh:
                data = json.load(fh)

            # Should be a list
            self.assertIsInstance(data, list, 'JSON output should be a list')
            # Should have 2 records
            self.assertEqual(len(data), 2, 'Should have 2 records')

            # Check first record structure
            first = data[0]
            self.assertIsInstance(first, dict, 'Each record should be a dict')
            expected_keys = {
                'Timestamp', 'Status', 'Vulnerability', 'Hostname', 'IP Address',
                'Port', 'URL', 'Payload_URL', 'Module', 'Service_Version',
                'Severity', 'Details', 'HTTP_Status', 'Page_Title', 'Content_Length'
            }
            self.assertEqual(set(first.keys()), expected_keys, 'Record should have expected keys')

            # Verify values from first record
            self.assertEqual(first['Status'], 'VULNERABLE')
            self.assertEqual(first['Vulnerability'], 'CVE-2023-TEST-1')
            self.assertEqual(first['Hostname'], 'example.com')
            self.assertEqual(first['IP Address'], '203.0.113.10')
            self.assertEqual(first['Port'], 443)
            self.assertEqual(first['Severity'], 'HIGH')

            # Verify second record
            second = data[1]
            self.assertEqual(second['Vulnerability'], 'CVE-2023-TEST-2')
            self.assertEqual(second['IP Address'], '203.0.113.11')
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_json_ip_target_blanks_hostname(self):
        """Verify IP addresses in target field result in blank Hostname in JSON."""
        finding = {
            'status': 'VULNERABLE',
            'vulnerability': 'CVE-2023-TEST',
            'target': '203.0.113.10',  # IP as target
            'resolved_ip': '203.0.113.10',
            'port': 443,
            'url': 'https://203.0.113.10',
            'payload_url': 'N/A',
            'module': 'test',
            'service_version': 'N/A',
            'severity': 'HIGH',
            'details': 'Test',
            'http_status': 200,
            'page_title': 'N/A',
            'content_length': 0,
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_file = f.name

        try:
            reporter.save_results_to_json([finding], filename=temp_file)
            with open(temp_file, 'r', encoding='utf-8') as fh:
                data = json.load(fh)

            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]['Hostname'], '', 'Hostname should be blank when target is an IP')
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)


class TestSarifOutputValidity(unittest.TestCase):
    """Test SARIF 2.1.0 output structure."""

    def test_sarif_output_valid(self):
        """Verify SARIF output has required structure (runs, results, rules)."""
        findings = [
            {
                'status': 'VULNERABLE',
                'vulnerability': 'CVE-2023-TEST-1',
                'target': 'example.com',
                'resolved_ip': '203.0.113.10',
                'port': 443,
                'url': 'https://example.com',
                'payload_url': 'N/A',
                'module': 'test_mod',
                'service_version': '1.0.0',
                'severity': 'HIGH',
                'details': 'High severity vulnerability',
                'http_status': 200,
                'page_title': 'Test',
                'content_length': 1024,
            },
            {
                'status': 'VULNERABLE',
                'vulnerability': 'CVE-2023-TEST-2',
                'target': 'example.com',
                'resolved_ip': '203.0.113.10',
                'port': 8080,
                'url': 'https://example.com:8080',
                'payload_url': 'N/A',
                'module': 'test_mod',
                'service_version': '1.0.0',
                'severity': 'CRITICAL',
                'details': 'Critical severity vulnerability',
                'http_status': 200,
                'page_title': 'Test',
                'content_length': 1024,
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sarif') as f:
            temp_file = f.name

        try:
            reporter.write_sarif_output(findings, temp_file)
            with open(temp_file, 'r', encoding='utf-8') as fh:
                data = json.load(fh)

            # Check version
            self.assertEqual(data['version'], '2.1.0', 'SARIF version should be 2.1.0')

            # Check schema
            self.assertIn('$schema', data)
            self.assertIn('2.1.0', data['$schema'])

            # Check runs array
            self.assertIn('runs', data)
            self.assertIsInstance(data['runs'], list)
            self.assertEqual(len(data['runs']), 1, 'Should have one run')

            run = data['runs'][0]

            # Check tool and driver
            self.assertIn('tool', run)
            self.assertIn('driver', run['tool'])
            driver = run['tool']['driver']
            self.assertEqual(driver['name'], 'VaktScan')

            # Check rules exist
            self.assertIn('rules', driver)
            self.assertIsInstance(driver['rules'], list)
            self.assertGreater(len(driver['rules']), 0, 'Should have at least one rule')

            # Check rule structure
            rule = driver['rules'][0]
            self.assertIn('id', rule)
            self.assertIn('shortDescription', rule)
            self.assertIn('defaultConfiguration', rule)

            # Check results
            self.assertIn('results', run)
            self.assertIsInstance(run['results'], list)
            self.assertEqual(len(run['results']), 2, 'Should have 2 results (one per finding)')

            # Check result structure
            result = run['results'][0]
            self.assertIn('ruleId', result)
            self.assertIn('level', result)
            self.assertIn('message', result)
            self.assertIn('locations', result)

            # Check location structure
            location = result['locations'][0]
            self.assertIn('physicalLocation', location)
            self.assertIn('artifactLocation', location['physicalLocation'])
            self.assertIn('uri', location['physicalLocation']['artifactLocation'])
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_sarif_severity_mapping(self):
        """Verify SARIF severity levels are correctly mapped."""
        test_cases = [
            ('CRITICAL', 'error'),
            ('HIGH', 'error'),
            ('MEDIUM', 'warning'),
            ('LOW', 'note'),
            ('INFO', 'none'),
        ]

        for severity, expected_level in test_cases:
            finding = {
                'status': 'VULNERABLE',
                'vulnerability': f'CVE-2023-SEVERITY-{severity}',
                'target': 'example.com',
                'resolved_ip': '203.0.113.10',
                'port': 443,
                'url': 'https://example.com',
                'payload_url': 'N/A',
                'module': 'test',
                'service_version': '1.0.0',
                'severity': severity,
                'details': f'Test {severity}',
                'http_status': 200,
                'page_title': 'Test',
                'content_length': 1024,
            }

            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sarif') as f:
                temp_file = f.name

            try:
                reporter.write_sarif_output([finding], temp_file)
                with open(temp_file, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)

                rule = data['runs'][0]['tool']['driver']['rules'][0]
                level = rule['defaultConfiguration']['level']
                self.assertEqual(level, expected_level,
                                f'Severity {severity} should map to {expected_level}, got {level}')
            finally:
                if os.path.exists(temp_file):
                    os.remove(temp_file)


class TestPortScanCsvStructure(unittest.TestCase):
    """Test port scan CSV output structure."""

    def test_port_scan_csv_structure(self):
        """Verify port scan CSV has expected headers and structure."""
        # Mock scan results structure: list of tuples (target_obj, result_dict)
        scan_results = [
            (
                {
                    'display_target': 'example.com',
                    'resolved_ip': '203.0.113.10',
                },
                {
                    'open_ports': [80, 443, 8080, 8443],
                }
            ),
            (
                {
                    'display_target': 'example2.com',
                    'resolved_ip': '203.0.113.11',
                },
                {
                    'open_ports': [22, 443],
                }
            ),
            (
                {
                    'display_target': 'example3.com',
                    'resolved_ip': '203.0.113.12',
                },
                {
                    'open_ports': [],  # No open ports - should be skipped
                }
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            # Temporarily change to tmpdir to avoid creating files in working directory
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                filename = reporter.save_port_scan_csv(scan_results, 'test.com')

                # Verify file was created
                self.assertIsNotNone(filename)
                self.assertTrue(os.path.exists(filename))

                # Read and verify CSV structure
                with open(filename, 'r', encoding='utf-8') as fh:
                    rows = list(csv.reader(fh))

                # Check headers
                expected_headers = ['Timestamp', 'Hostname', 'IP Address', 'Open Ports', 'Count']
                self.assertEqual(rows[0], expected_headers)

                # Check that we have 2 data rows (skip the one with no open ports)
                self.assertEqual(len(rows), 3, 'Should have header + 2 data rows')

                # Check first data row
                row1 = rows[1]
                self.assertEqual(row1[1], 'example.com')  # Hostname
                self.assertEqual(row1[2], '203.0.113.10')  # IP Address
                self.assertIn('80', row1[3])  # Open Ports should contain 80
                self.assertIn('443', row1[3])  # Open Ports should contain 443
                self.assertEqual(row1[4], '4')  # Count should be 4

                # Check second data row
                row2 = rows[2]
                self.assertEqual(row2[1], 'example2.com')
                self.assertEqual(row2[2], '203.0.113.11')
                self.assertIn('22', row2[3])
                self.assertIn('443', row2[3])
                self.assertEqual(row2[4], '2')
            finally:
                os.chdir(original_cwd)

    def test_port_scan_csv_empty_results(self):
        """Verify port scan CSV handles empty results gracefully."""
        scan_results = [
            (
                {
                    'display_target': 'example.com',
                    'resolved_ip': '203.0.113.10',
                },
                {
                    'open_ports': [],  # No open ports
                }
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                filename = reporter.save_port_scan_csv(scan_results, 'test.com')

                self.assertIsNotNone(filename)
                self.assertTrue(os.path.exists(filename))

                with open(filename, 'r', encoding='utf-8') as fh:
                    rows = list(csv.reader(fh))

                # Should only have header row (no data rows)
                self.assertEqual(len(rows), 1, 'Should only have header when no ports are open')
            finally:
                os.chdir(original_cwd)


class TestDeduplicateVulnerabilities(unittest.TestCase):
    """Test deduplication logic."""

    def test_deduplicates_same_target_port_cve(self):
        """Verify vulnerabilities with same target, port, and CVE are deduplicated."""
        findings = [
            {
                'target': 'example.com',
                'resolved_ip': '203.0.113.10',
                'port': 443,
                'vulnerability': 'CVE-2023-TEST',
                'severity': 'HIGH',
                'status': 'VULNERABLE',
            },
            {
                'target': 'example.com',
                'resolved_ip': '203.0.113.10',
                'port': 443,
                'vulnerability': 'CVE-2023-TEST',
                'severity': 'HIGH',
                'status': 'VULNERABLE',
            },
        ]

        result = reporter.deduplicate_vulnerabilities(findings)
        self.assertEqual(len(result), 1, 'Duplicate findings should be deduplicated')
        self.assertEqual(result[0]['vulnerability'], 'CVE-2023-TEST')

    def test_keeps_different_vulnerabilities(self):
        """Verify different vulnerabilities are not deduplicated."""
        findings = [
            {
                'target': 'example.com',
                'resolved_ip': '203.0.113.10',
                'port': 443,
                'vulnerability': 'CVE-2023-TEST-1',
                'severity': 'HIGH',
                'status': 'VULNERABLE',
            },
            {
                'target': 'example.com',
                'resolved_ip': '203.0.113.10',
                'port': 443,
                'vulnerability': 'CVE-2023-TEST-2',
                'severity': 'HIGH',
                'status': 'VULNERABLE',
            },
        ]

        result = reporter.deduplicate_vulnerabilities(findings)
        self.assertEqual(len(result), 2, 'Different vulnerabilities should not be deduplicated')

    def test_prefers_hostname_over_ip_in_target(self):
        """Verify deduplicator prefers hostname when both IP and hostname versions exist."""
        findings = [
            {
                'target': '203.0.113.10',  # IP target
                'resolved_ip': '203.0.113.10',
                'port': 443,
                'vulnerability': 'CVE-2023-TEST',
                'severity': 'HIGH',
                'status': 'VULNERABLE',
            },
            {
                'target': 'example.com',  # Hostname target
                'resolved_ip': '203.0.113.10',
                'port': 443,
                'vulnerability': 'CVE-2023-TEST',
                'severity': 'HIGH',
                'status': 'VULNERABLE',
            },
        ]

        result = reporter.deduplicate_vulnerabilities(findings)
        self.assertEqual(len(result), 1, 'Should deduplicate to one result')
        # Should prefer hostname over IP
        self.assertEqual(result[0]['target'], 'example.com')


if __name__ == '__main__':
    unittest.main()
