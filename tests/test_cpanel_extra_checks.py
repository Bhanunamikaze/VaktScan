"""
Tests for the seven additional cPanel checks added on top of the initial
oracle-validated set: PROXY-protocol, HTTP/2 ALPN, SSI execution, request
smuggling, branding upload, license-server banner, default credentials.

These checks are network-dependent at runtime, so the tests assert they
exist, are wired into run_scans, and behave correctly against
deterministic input where possible.
"""
import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules import cpanel  # noqa: E402


class ExtraChecksRegisteredTests(unittest.TestCase):

    EXPECTED = (
        'check_proxy_protocol',
        'check_http2_support',
        'check_ssi_execution',
        'check_request_smuggling',
        'check_branding_upload',
        'check_license_server',
        'check_default_credentials',
    )

    def test_every_extra_check_exists(self):
        for name in self.EXPECTED:
            self.assertTrue(hasattr(cpanel, name), f"missing check function: {name}")
            self.assertTrue(callable(getattr(cpanel, name)))

    def test_default_credentials_gated_off_by_default(self):
        """Without VAKTSCAN_AGGRESSIVE_CPANEL=1 the check must short-circuit."""
        os.environ.pop('VAKTSCAN_AGGRESSIVE_CPANEL', None)

        async def run():
            ctx = {
                'origin_url': 'https://example.com:2087',
                'scan_address': 'example.com',
                'port': 2087,
                'is_tls': True,
                'surface': 'WHM',
            }

            class _FakeClient:
                async def post(self, *a, **kw):
                    raise AssertionError("default credential check fired without env opt-in")

            findings = await cpanel.check_default_credentials(_FakeClient(), ctx)
            self.assertEqual(findings, [])

        asyncio.run(run())

    def test_default_credentials_only_runs_on_whm_ports(self):
        os.environ['VAKTSCAN_AGGRESSIVE_CPANEL'] = '1'
        try:
            async def run():
                ctx = {
                    'origin_url': 'https://example.com:2083',
                    'scan_address': 'example.com',
                    'port': 2083,
                    'is_tls': True,
                    'surface': 'cPanel',
                }

                class _FakeClient:
                    async def post(self, *a, **kw):
                        raise AssertionError("default credential check fired on non-WHM port")

                findings = await cpanel.check_default_credentials(_FakeClient(), ctx)
                self.assertEqual(findings, [])
            asyncio.run(run())
        finally:
            os.environ.pop('VAKTSCAN_AGGRESSIVE_CPANEL', None)


class RunScansWiringTests(unittest.TestCase):

    def test_run_scans_invokes_every_extra_check(self):
        import ast
        src = open(os.path.join(os.path.dirname(__file__), '..', 'modules', 'cpanel.py'), 'r', encoding='utf-8').read()
        tree = ast.parse(src)
        invoked = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == 'run_scans':
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                        invoked.add(sub.func.id)
        for fn in ExtraChecksRegisteredTests.EXPECTED:
            self.assertIn(fn, invoked, f"{fn} not invoked from run_scans()")


if __name__ == '__main__':
    unittest.main()
