"""
Tests for the new DNS recon module (modules/dns_recon.py).

Covers:
  - DNS wire-format encode/decode helpers (offline, deterministic).
  - SPF policy classification.
  - Finding schema parity with main.save_results_to_csv.

No live network is required.
"""
import os
import struct
import sys
import unittest
import unittest.mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules import dns_recon  # noqa: E402


class WireFormatTests(unittest.TestCase):

    def test_encode_name_roundtrip(self):
        encoded = dns_recon._encode_name('www.example.com')
        # Length-prefixed labels: 3www 7example 3com 0.
        self.assertTrue(encoded.startswith(b'\x03www'))
        self.assertTrue(encoded.endswith(b'\x00'))
        # Decode it back.
        decoded, offset = dns_recon._decode_name(encoded, 0)
        self.assertEqual(decoded, 'www.example.com')
        self.assertEqual(offset, len(encoded))

    def test_build_query_header_shape(self):
        payload, tx_id = dns_recon._build_query('example.com', dns_recon.RR_A)
        self.assertEqual(len(payload) >= 12 + len('example.com') + 2 + 4, True)
        # Flags byte should contain RD=1 (0x01 in low byte of flags word).
        flags = struct.unpack('>H', payload[2:4])[0]
        self.assertEqual(flags & 0x0100, 0x0100)

    def test_parse_response_handles_no_answers(self):
        # Construct a minimal response: same id, flags=0x8180 (response, RD/RA, no error), QDCOUNT=1, ANCOUNT=0.
        question = dns_recon._encode_name('example.com') + struct.pack('>HH', dns_recon.RR_A, 1)
        header = struct.pack('>HHHHHH', 0x1234, 0x8180, 1, 0, 0, 0)
        parsed = dns_recon._parse_response(header + question)
        self.assertEqual(parsed['rcode'], 0)
        self.assertEqual(parsed['answers'], [])


class SpfClassificationTests(unittest.TestCase):

    def test_missing_spf_emits_vulnerable_finding(self):
        out = dns_recon._spf_findings('example.com', txt_records=[])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['status'], 'VULNERABLE')
        self.assertIn('SPF record missing', out[0]['vulnerability'])

    def test_plus_all_spf_flagged_high(self):
        out = dns_recon._spf_findings('example.com', txt_records=['v=spf1 +all'])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['severity'], 'HIGH')

    def test_proper_spf_emits_info_only(self):
        out = dns_recon._spf_findings('example.com', txt_records=['v=spf1 mx -all'])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['status'], 'INFO')


class FindingSchemaTests(unittest.TestCase):

    REQUIRED = ('status', 'severity', 'vulnerability', 'details', 'target',
                'module', 'url', 'payload_url', 'http_status', 'page_title',
                'content_length')

    def test_finding_factory_keys_complete(self):
        f = dns_recon._finding('example.com', 'INFO', 'LOW', 'X', 'Y')
        for k in self.REQUIRED:
            self.assertIn(k, f, f"missing key {k}")
        self.assertEqual(f['module'], 'DNS')


class DanglingCnameTests(unittest.IsolatedAsyncioTestCase):
    """DNS-level subdomain-takeover detection (dangling CNAME -> NXDOMAIN)."""

    def _fake_query(self, cname_map, nxdomain_targets):
        async def fake(server, name, qtype, **kw):
            name = name.rstrip('.')
            if qtype == dns_recon.RR_CNAME:
                tgt = cname_map.get(name)
                if tgt:
                    return {'rcode': 0, 'answers': [{'type': dns_recon.RR_CNAME, 'data': tgt}]}
                return {'rcode': 0, 'answers': []}
            # A / AAAA lookup on a target
            if name in nxdomain_targets:
                return {'rcode': 3, 'answers': []}   # NXDOMAIN
            return {'rcode': 0, 'answers': [{'type': qtype, 'data': '1.2.3.4'}]}
        return fake

    async def test_known_service_nxdomain_is_takeover(self):
        cname_map = {'app.example.com': 'unclaimed.s3.amazonaws.com'}
        nx = {'unclaimed.s3.amazonaws.com'}
        with unittest.mock.patch.object(dns_recon, '_query', side_effect=self._fake_query(cname_map, nx)):
            findings = await dns_recon.check_dangling_cnames(['app.example.com'])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['status'], 'VULNERABLE')
        self.assertIn('AWS S3', findings[0]['vulnerability'])

    async def test_unknown_target_nxdomain_is_medium(self):
        cname_map = {'old.example.com': 'gone.internal.example.net'}
        nx = {'gone.internal.example.net'}
        with unittest.mock.patch.object(dns_recon, '_query', side_effect=self._fake_query(cname_map, nx)):
            findings = await dns_recon.check_dangling_cnames(['old.example.com'])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'MEDIUM')

    async def test_resolving_cname_is_not_flagged(self):
        # CNAME target resolves fine -> NOT dangling -> no finding (false-positive guard).
        cname_map = {'live.example.com': 'live.cdn.example.com'}
        with unittest.mock.patch.object(dns_recon, '_query', side_effect=self._fake_query(cname_map, set())):
            findings = await dns_recon.check_dangling_cnames(['live.example.com'])
        self.assertEqual(findings, [])

    async def test_no_cname_is_not_flagged(self):
        with unittest.mock.patch.object(dns_recon, '_query', side_effect=self._fake_query({}, set())):
            findings = await dns_recon.check_dangling_cnames(['plain.example.com'])
        self.assertEqual(findings, [])

    async def test_empty_input(self):
        self.assertEqual(await dns_recon.check_dangling_cnames([]), [])


if __name__ == '__main__':
    unittest.main()
