"""
Tests for the content-oracle endpoint checks added to web_checks:

* check_status_endpoints - /server-status, /jkstatus, Graylog /config.js,
  Elasticsearch /_nodes/stats, S3 /@ (AWS_SECRET_ACCESS_KEY),
* check_http_trace - TRACE method / Cross-Site Tracing.

Every check must fire on a positive body oracle and must NOT fire on a
soft-404 / catch-all server that returns HTTP 200 for every path. Fully offline:
a fake httpx-like client feeds canned bodies keyed by path.
"""

import unittest
from urllib.parse import urlparse

from modules import web_checks
from modules.schema import validate_finding


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8", errors="replace")
        self.headers = headers or {}


class FakeClient:
    """Routes GET by URL path; TRACE returns a preset response."""

    def __init__(self, routes=None, default_status=404, default_text="",
                 default_headers=None, trace_response=None):
        self.routes = routes or {}
        self.default_status = default_status
        self.default_text = default_text
        self.default_headers = default_headers or {}
        self.trace_response = trace_response

    async def get(self, url, **kwargs):
        path = urlparse(url).path or "/"
        if path in self.routes:
            return self.routes[path]
        return FakeResponse(self.default_status, self.default_text, dict(self.default_headers))

    async def request(self, method, url, **kwargs):
        if method == "TRACE" and self.trace_response is not None:
            return self.trace_response
        return FakeResponse(405, "")


URL = "http://target.test"


def _titles(findings):
    return {f["vulnerability"] for f in findings}


class StatusEndpointPositiveTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_endpoints_fire_on_oracle(self):
        routes = {
            "/server-status": FakeResponse(200, (
                "<html><head><title>Apache Status</title></head><body>"
                "Apache Server Status for target.test<br>Server Version: Apache/2.4.7"
                "</body></html>")),
            "/jkstatus": FakeResponse(200,
                "JK Status Manager for target.test\nLoad Balancer Manager\nworker1 OK"),
            "/config.js": FakeResponse(200,
                'window.appConfig={gl2ServerUrl:"http://target.test/api",'
                'api_key:"SECRET-ABC123",rootTimeZone:"UTC"};',
                headers={"content-type": "application/javascript"}),
            "/_nodes/stats": FakeResponse(200,
                '{"cluster_name":"prod-es","nodes":{"a1":{"name":"n1"}},"indices":{}}',
                headers={"content-type": "application/json"}),
            "/@": FakeResponse(200,
                "AWS_ACCESS_KEY_ID=AKIAEXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/EXAMPLEKEY"),
        }
        # default 404 -> catch-all negative control is a clean 404 miss.
        client = FakeClient(routes=routes, default_status=404)
        findings = await web_checks.check_status_endpoints(URL, client)
        titles = _titles(findings)

        self.assertIn("Apache mod_status Page Exposed (/server-status)", titles)
        self.assertIn("Apache mod_jk Status Manager Exposed (/jkstatus)", titles)
        self.assertIn("Graylog config.js Exposes Embedded API Key", titles)
        self.assertIn("Elasticsearch Unauthenticated Access (/_nodes/stats)", titles)
        self.assertIn("AWS Credential Disclosure via Environment Dump (/@)", titles)
        self.assertEqual(len(findings), 5)

        # S3 disclosure must be CRITICAL/CRITICAL.
        s3 = next(f for f in findings
                  if f["vulnerability"].startswith("AWS Credential Disclosure"))
        self.assertEqual(s3["status"], "CRITICAL")
        self.assertEqual(s3["severity"], "CRITICAL")

        for f in findings:
            self.assertEqual(validate_finding(f), [])
            self.assertEqual(f["module"], web_checks.MODULE_NAME)


class StatusEndpointNegativeTests(unittest.IsolatedAsyncioTestCase):
    async def test_catchall_server_suppresses_all(self):
        # Server returns 200 for EVERYTHING with a body that echoes every oracle.
        catchall = ('{ "cluster_name":"x", "nodes":{}, "indices":{}, '
                    '"msg":"Apache Server Status Load Balancer Manager '
                    'AWS_SECRET_ACCESS_KEY=Y", api_key:"Z" }')
        client = FakeClient(default_status=200, default_text=catchall)
        findings = await web_checks.check_status_endpoints(URL, client)
        self.assertEqual(findings, [], f"catch-all not suppressed: {_titles(findings)}")

    async def test_generic_200_without_oracle_no_finding(self):
        routes = {
            "/server-status": FakeResponse(200, "<html><body>Welcome home</body></html>"),
            "/jkstatus": FakeResponse(200, "<html><body>Not found here</body></html>"),
            "/config.js": FakeResponse(200, "var config={theme:'dark'};",
                                       headers={"content-type": "application/javascript"}),
            "/_nodes/stats": FakeResponse(200, "<html><body>login</body></html>"),
            "/@": FakeResponse(200, "<html><body>nothing to see</body></html>"),
        }
        client = FakeClient(routes=routes, default_status=404)
        findings = await web_checks.check_status_endpoints(URL, client)
        self.assertEqual(findings, [])

    async def test_404_endpoints_no_finding(self):
        client = FakeClient(routes={}, default_status=404)
        findings = await web_checks.check_status_endpoints(URL, client)
        self.assertEqual(findings, [])

    async def test_config_js_requires_key_assignment(self):
        # 'api_key' appears only as prose, not as an assignment -> no finding.
        routes = {"/config.js": FakeResponse(200,
            "// document your api_key usage in the wiki",
            headers={"content-type": "application/javascript"})}
        client = FakeClient(routes=routes, default_status=404)
        findings = await web_checks.check_status_endpoints(URL, client)
        self.assertEqual(findings, [])


class HttpTraceTests(unittest.IsolatedAsyncioTestCase):
    async def test_trace_enabled_fires(self):
        client = FakeClient(trace_response=FakeResponse(
            200, "TRACE / HTTP/1.1\r\nHost: target.test\r\n",
            headers={"content-type": "message/http"}))
        findings = await web_checks.check_http_trace(URL, client)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"],
                         "HTTP TRACE Method Enabled (Cross-Site Tracing)")
        self.assertEqual(validate_finding(findings[0]), [])

    async def test_trace_disabled_405_no_finding(self):
        client = FakeClient(trace_response=None)  # request() -> 405
        findings = await web_checks.check_http_trace(URL, client)
        self.assertEqual(findings, [])

    async def test_trace_200_without_message_http_no_finding(self):
        # Server returns 200 but does not echo as message/http -> not confirmed.
        client = FakeClient(trace_response=FakeResponse(
            200, "<html>ok</html>", headers={"content-type": "text/html"}))
        findings = await web_checks.check_http_trace(URL, client)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
