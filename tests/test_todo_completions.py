import asyncio
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import main
from modules import artifact_findings, cloud_enum, domain_scan, web_checks
from modules.schema import validate_finding


class _Response:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.content = text.encode()
        self.headers = headers or {}


class _Client:
    def __init__(self, response):
        self.response = response

    async def get(self, *_args, **_kwargs):
        return self.response


class CSPTests(unittest.IsolatedAsyncioTestCase):
    async def test_weak_csp_and_missing_frame_ancestors_are_reported(self):
        client = _Client(_Response(headers={
            "content-security-policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' *"
        }))
        findings = await web_checks.check_security_headers("https://example.com", client)
        titles = {finding["vulnerability"] for finding in findings}
        self.assertIn("Weak Content-Security-Policy Directives", titles)
        self.assertIn("Missing Clickjacking Protection (X-Frame-Options / CSP)", titles)

    async def test_frame_ancestors_is_valid_clickjacking_protection(self):
        client = _Client(_Response(headers={
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'"
        }))
        findings = await web_checks.check_security_headers("https://example.com", client)
        titles = {finding["vulnerability"] for finding in findings}
        self.assertNotIn("Missing Clickjacking Protection (X-Frame-Options / CSP)", titles)
        self.assertNotIn("Weak Content-Security-Policy Directives", titles)

    async def test_web_check_client_pool_follows_concurrency(self):
        captured = {}

        class Client:
            def __init__(self, **kwargs):
                captured.update(kwargs)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        with patch("modules.web_checks.httpx.AsyncClient", Client), \
             patch("modules.web_checks._run_checks_for_url", AsyncMock(return_value=[])):
            await web_checks.run_checks(["https://example.com"], concurrency=37)

        limits = captured["limits"]
        self.assertEqual(limits.max_connections, 37)
        self.assertEqual(limits.max_keepalive_connections, 37)


class HorizontalPipelineTests(unittest.TestCase):
    def test_reverse_and_related_hosts_feed_pipeline_deduplicated(self):
        expansion = {
            "reverse_hosts": ["VPN.Example.com", "vpn.example.com"],
            "related_domains": ["example.org", "not a host"],
        }
        self.assertEqual(
            main._horizontal_targets(expansion),
            ["example.org", "vpn.example.com"],
        )


class DomainConcurrencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_broken_component_fetches_honor_requested_concurrency(self):
        tracker = {"active": 0, "maximum": 0}

        class Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def get(self, _url):
                tracker["active"] += 1
                tracker["maximum"] = max(tracker["maximum"], tracker["active"])
                await asyncio.sleep(0.01)
                tracker["active"] -= 1
                return _Response(200, "<html></html>")

            async def head(self, _url):
                return _Response(200, "")

        entries = [{"url": f"https://host{i}.example.com"} for i in range(20)]
        scanner = domain_scan.DomainScanner(output_dir=tempfile.gettempdir())
        with patch("modules.domain_scan.httpx.AsyncClient", return_value=Client()):
            await scanner.check_broken_components(entries, concurrency=20)
        self.assertEqual(tracker["maximum"], 20)


class ArtifactFindingTests(unittest.TestCase):
    def test_archive_results_become_canonical_summary_findings(self):
        findings = artifact_findings.archive_findings(
            "GAU", {"example.com": ["https://example.com/a", "https://example.com/a"]}
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("1 unique URL", findings[0]["details"])
        self.assertEqual(validate_finding(findings[0]), [])

    def test_dirsearch_report_becomes_canonical_summary_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "dirsearch_report_example.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("https://example.com/admin\nhttps://example.com/login\n")
            findings = artifact_findings.dirsearch_findings(directory)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["target"], "example.com")
        self.assertEqual(validate_finding(findings[0]), [])


class CloudBreadthTests(unittest.IsolatedAsyncioTestCase):
    async def test_digitalocean_private_space_is_recorded(self):
        findings = await cloud_enum._probe_object_endpoint(
            _Client(_Response(403, "<Code>AccessDenied</Code>")),
            asyncio.Semaphore(1), "example.com", "example",
            "https://example.nyc3.digitaloceanspaces.com/", "DigitalOcean Spaces",
        )
        self.assertEqual(findings[0]["vulnerability"], "DigitalOcean Spaces Bucket Exists (Access Denied)")

    async def test_alibaba_missing_bucket_is_ignored(self):
        findings = await cloud_enum._probe_object_endpoint(
            _Client(_Response(403, "<Code>NoSuchBucket</Code>")),
            asyncio.Semaphore(1), "example.com", "missing",
            "https://missing.oss-us-east-1.aliyuncs.com/", "Alibaba OSS",
        )
        self.assertEqual(findings, [])

    async def test_non_blob_azure_endpoint_is_recorded(self):
        findings = await cloud_enum._probe_azure_service(
            _Client(_Response(403, "<Code>AuthenticationFailed</Code>", {"x-ms-request-id": "abc"})),
            asyncio.Semaphore(1), "example.com", "example", "queue", "Queues",
        )
        self.assertEqual(findings[0]["vulnerability"], "Azure Queues Endpoint Exists (Restricted)")


if __name__ == "__main__":
    unittest.main()
