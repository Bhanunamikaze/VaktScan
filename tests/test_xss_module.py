"""
Tests for modules/xss_checks.py — reflected XSS surface probing, filter
bypass, stored XSS upload audit, DOM XSS indicators, and postMessage checks.

Fully offline: FakeClient returns canned responses keyed by URL.
"""

import unittest
from urllib.parse import urlparse

from modules import xss_checks
from modules.schema import validate_finding


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8", errors="replace")
        self.headers = headers or {}


class FakeClient:
    """Routes GET by a handler function or returns default."""

    def __init__(self, handler=None, default_status=404, default_text=""):
        self.handler = handler
        self.default_status = default_status
        self.default_text = default_text

    async def get(self, url, **kwargs):
        if self.handler:
            return self.handler(url)
        return FakeResponse(self.default_status, self.default_text)


URL = "http://target.test"
CANARY = xss_checks._CANARY


def _titles(findings):
    return {f["vulnerability"] for f in findings}


# ──────────────────────────────────────────────────────────────────────────────
# Reflected XSS
# ──────────────────────────────────────────────────────────────────────────────

class ReflectedXssTests(unittest.IsolatedAsyncioTestCase):

    async def test_reflected_xss_unescaped_tag(self):
        """Endpoint reflects <canary> unescaped → VULNERABLE/HIGH."""
        def handler(url):
            path = urlparse(url).path
            query = urlparse(url).query
            if "_vaktscan_xss_neg_ctrl" in path:
                return FakeResponse(404, "not found")
            if CANARY in query or CANARY in path:
                # Reflect whatever comes in, unescaped
                param_val = query.split("=", 1)[-1] if "=" in query else path.split("/")[-1]
                body = f"<html><body><p>Error: {param_val}</p></body></html>"
                return FakeResponse(200, body, {"content-type": "text/html"})
            return FakeResponse(404, "not found")

        client = FakeClient(handler=handler)
        findings = await xss_checks.check_reflected_xss(URL, client)
        self.assertTrue(len(findings) > 0)
        vuln = findings[0]
        self.assertIn("Unescaped HTML Tag Injection", vuln["vulnerability"])
        self.assertEqual(vuln["status"], "VULNERABLE")
        self.assertEqual(vuln["severity"], "HIGH")

    async def test_reflected_xss_escaped_tag(self):
        """Endpoint reflects canary but escapes tags → POTENTIAL/MEDIUM."""
        def handler(url):
            path = urlparse(url).path
            query = urlparse(url).query
            if "_vaktscan_xss_neg_ctrl" in path:
                return FakeResponse(404, "not found")
            if CANARY in (query + path):
                param_val = query.split("=", 1)[-1] if "=" in query else ""
                escaped = param_val.replace("<", "&lt;").replace(">", "&gt;")
                body = f"<html><body><p>Error: {escaped}</p></body></html>"
                return FakeResponse(200, body, {"content-type": "text/html"})
            return FakeResponse(404, "not found")

        client = FakeClient(handler=handler)
        findings = await xss_checks.check_reflected_xss(URL, client)
        self.assertTrue(len(findings) > 0)
        vuln = findings[0]
        self.assertIn("Reflected Input Without HTML Encoding", vuln["vulnerability"])
        self.assertEqual(vuln["status"], "POTENTIAL")
        self.assertEqual(vuln["severity"], "MEDIUM")

    async def test_reflected_xss_no_reflection(self):
        """Canary not in response → no finding."""
        def handler(url):
            path = urlparse(url).path
            if "_vaktscan_xss_neg_ctrl" in path:
                return FakeResponse(404, "not found")
            return FakeResponse(200, "<html><body>Welcome</body></html>",
                                {"content-type": "text/html"})

        client = FakeClient(handler=handler)
        findings = await xss_checks.check_reflected_xss(URL, client)
        self.assertEqual(findings, [])

    async def test_reflected_xss_catchall_suppressed(self):
        """Catch-all server echoes canary for all paths including neg ctrl → no finding."""
        def handler(url):
            body = f"<html><body>{CANARY} appears everywhere</body></html>"
            return FakeResponse(200, body, {"content-type": "text/html"})

        client = FakeClient(handler=handler)
        findings = await xss_checks.check_reflected_xss(URL, client)
        self.assertEqual(findings, [])


# ──────────────────────────────────────────────────────────────────────────────
# Filter bypass
# ──────────────────────────────────────────────────────────────────────────────

class FilterBypassTests(unittest.IsolatedAsyncioTestCase):

    async def test_filter_bypass_whitespace(self):
        """Tag escaped but whitespace bypass payload survives → CRITICAL."""
        def handler(url):
            path = urlparse(url).path
            query = urlparse(url).query
            if "_vaktscan_xss_neg_ctrl" in path:
                return FakeResponse(404, "not found")

            param_val = query.split("=", 1)[-1] if "=" in query else path.split("/")[-1]

            if "<" in param_val and "img" not in param_val:
                # Escape simple tags like <canary>
                escaped = param_val.replace("<", "&lt;").replace(">", "&gt;")
                body = f"<html><body>{escaped}</body></html>"
            elif "onerror=" in param_val:
                # Whitespace bypass goes through! WAF missed it
                body = f"<html><body>{param_val}</body></html>"
            elif CANARY in param_val:
                # Plain canary reflects
                body = f"<html><body>{param_val}</body></html>"
            else:
                body = "<html><body>nope</body></html>"

            return FakeResponse(200, body, {"content-type": "text/html"})

        client = FakeClient(handler=handler)
        findings = await xss_checks.check_xss_filter_bypass(URL, client)
        self.assertTrue(len(findings) > 0)
        vuln = findings[0]
        self.assertIn("XSS Filter Bypass", vuln["vulnerability"])
        self.assertEqual(vuln["status"], "CRITICAL")
        self.assertEqual(vuln["severity"], "CRITICAL")

    async def test_filter_bypass_no_reflection(self):
        """No reflection at all → no bypass findings."""
        client = FakeClient(default_status=404)
        findings = await xss_checks.check_xss_filter_bypass(URL, client)
        self.assertEqual(findings, [])


# ──────────────────────────────────────────────────────────────────────────────
# Stored XSS surfaces
# ──────────────────────────────────────────────────────────────────────────────

class StoredXssTests(unittest.IsolatedAsyncioTestCase):

    async def test_upload_directory_inline(self):
        """Upload path with listing, no nosniff → finding."""
        def handler(url):
            path = urlparse(url).path
            if "_vaktscan_upload_neg_ctrl" in path:
                return FakeResponse(404, "not found")
            if path in ("/uploads/", "/upload/", "/files/", "/media/",
                        "/attachments/", "/assets/uploads/", "/content/uploads/",
                        "/wp-content/uploads/", "/sites/default/files/",
                        "/storage/", "/public/uploads/", "/user-content/",
                        "/static/uploads/", "/data/uploads/"):
                body = '<html><body><h1>Index of /uploads/</h1><pre><a href="file.html">file.html</a></pre></body></html>'
                return FakeResponse(200, body, {"content-type": "text/html"})
            return FakeResponse(404, "not found")

        client = FakeClient(handler=handler)
        findings = await xss_checks.check_stored_xss_surfaces(URL, client)
        self.assertTrue(len(findings) > 0)
        vuln = findings[0]
        self.assertIn("Upload Directory Serves Inline Content", vuln["vulnerability"])
        self.assertEqual(vuln["status"], "POTENTIAL")

    async def test_upload_path_404(self):
        """Upload paths all 404 → no findings."""
        client = FakeClient(default_status=404)
        findings = await xss_checks.check_stored_xss_surfaces(URL, client)
        self.assertEqual(findings, [])


# ──────────────────────────────────────────────────────────────────────────────
# DOM XSS indicators
# ──────────────────────────────────────────────────────────────────────────────

class DomXssTests(unittest.IsolatedAsyncioTestCase):

    async def test_dom_xss_innerHTML_location(self):
        """Page contains innerHTML = location.hash → finding."""
        body = '''<html><body><script>
            var x = location.hash.substring(1);
            document.getElementById("out").innerHTML = location.hash;
        </script></body></html>'''

        client = FakeClient(handler=lambda url: FakeResponse(200, body, {"content-type": "text/html"}))
        findings = await xss_checks.check_dom_xss_indicators(URL, client)
        self.assertTrue(len(findings) > 0)
        self.assertIn("DOM XSS Indicator", findings[0]["vulnerability"])

    async def test_dom_xss_no_source(self):
        """Page has innerHTML but no URL source → no finding."""
        body = '<html><body><script>document.getElementById("x").innerHTML = "safe";</script></body></html>'
        client = FakeClient(handler=lambda url: FakeResponse(200, body, {"content-type": "text/html"}))
        findings = await xss_checks.check_dom_xss_indicators(URL, client)
        self.assertEqual(findings, [])

    async def test_dom_xss_eval_referrer(self):
        """eval() with document.referrer → finding."""
        body = '<html><body><script>eval(document.referrer)</script></body></html>'
        client = FakeClient(handler=lambda url: FakeResponse(200, body, {"content-type": "text/html"}))
        findings = await xss_checks.check_dom_xss_indicators(URL, client)
        self.assertTrue(len(findings) > 0)
        self.assertTrue(any("eval()" in f["vulnerability"] for f in findings))

    async def test_dom_xss_dangerously_set(self):
        """React dangerouslySetInnerHTML → finding."""
        body = '<html><body><script>return <div dangerouslySetInnerHTML={ {__html: data} } /></script></body></html>'
        client = FakeClient(handler=lambda url: FakeResponse(200, body, {"content-type": "text/html"}))
        findings = await xss_checks.check_dom_xss_indicators(URL, client)
        self.assertTrue(len(findings) > 0)
        self.assertTrue(any("dangerouslySetInnerHTML" in f["vulnerability"] for f in findings))


# ──────────────────────────────────────────────────────────────────────────────
# postMessage
# ──────────────────────────────────────────────────────────────────────────────

class PostMessageTests(unittest.IsolatedAsyncioTestCase):

    async def test_postmessage_no_origin(self):
        """addEventListener('message') with no origin check → VULNERABLE."""
        body = '''<html><body><script>
            window.addEventListener('message', function(event) {
                document.getElementById("x").innerHTML = event.data;
            });
        </script></body></html>'''

        client = FakeClient(handler=lambda url: FakeResponse(200, body, {"content-type": "text/html"}))
        findings = await xss_checks.check_postmessage_handlers(URL, client)
        self.assertTrue(len(findings) > 0)
        vuln = next(f for f in findings if "Origin Validation" in f["vulnerability"])
        self.assertEqual(vuln["status"], "VULNERABLE")
        self.assertEqual(vuln["severity"], "HIGH")

    async def test_postmessage_with_origin_check(self):
        """addEventListener('message') with event.origin === check → no origin finding."""
        body = '''<html><body><script>
            window.addEventListener('message', function(event) {
                if (event.origin !== 'https://safe.com') return;
                document.getElementById("x").innerHTML = event.data;
            });
        </script></body></html>'''

        client = FakeClient(handler=lambda url: FakeResponse(200, body, {"content-type": "text/html"}))
        findings = await xss_checks.check_postmessage_handlers(URL, client)
        origin_findings = [f for f in findings if "Origin Validation" in f["vulnerability"]]
        self.assertEqual(origin_findings, [])

    async def test_postmessage_wildcard(self):
        """postMessage(data, '*') → POTENTIAL finding."""
        body = '''<html><body><script>
            parent.postMessage({token: "abc"}, '*');
        </script></body></html>'''

        client = FakeClient(handler=lambda url: FakeResponse(200, body, {"content-type": "text/html"}))
        findings = await xss_checks.check_postmessage_handlers(URL, client)
        self.assertTrue(len(findings) > 0)
        vuln = next(f for f in findings if "Wildcard Origin" in f["vulnerability"])
        self.assertEqual(vuln["status"], "POTENTIAL")
        self.assertEqual(vuln["severity"], "MEDIUM")


# ──────────────────────────────────────────────────────────────────────────────
# Schema validation
# ──────────────────────────────────────────────────────────────────────────────

class SchemaValidationTests(unittest.IsolatedAsyncioTestCase):

    async def test_all_findings_pass_schema(self):
        """Every finding across all checks must pass validate_finding()."""
        # Build a handler that triggers every check type
        body_with_sinks = '''<html><body>
            <script>
                window.addEventListener('message', function(e) {
                    document.getElementById("x").innerHTML = e.data;
                });
                parent.postMessage({tok: "x"}, '*');
                document.getElementById("y").innerHTML = location.hash;
            </script>
        </body></html>'''

        def handler(url):
            path = urlparse(url).path
            query = urlparse(url).query
            if "_vaktscan_xss_neg_ctrl" in path or "_vaktscan_upload_neg_ctrl" in path:
                return FakeResponse(404, "not found")
            if "/uploads/" in path:
                return FakeResponse(200,
                    '<html><pre>Index of /uploads/ <a href="x.html">x.html</a></pre></html>',
                    {"content-type": "text/html"})
            if CANARY in (query + path):
                param_val = query.split("=", 1)[-1] if "=" in query else ""
                return FakeResponse(200,
                    f"<html><body>{param_val}</body></html>",
                    {"content-type": "text/html"})
            return FakeResponse(200, body_with_sinks, {"content-type": "text/html"})

        client = FakeClient(handler=handler)
        all_findings = []
        for check in xss_checks._ALL_CHECKS:
            results = await check(URL, client)
            all_findings.extend(results)

        self.assertTrue(len(all_findings) > 0, "Expected at least one finding for schema test")
        for f in all_findings:
            violations = validate_finding(f)
            errors = [v for v in violations if not v.startswith("WARN:")]
            self.assertEqual(errors, [], f"Schema violation in {f['vulnerability']}: {errors}")
            self.assertEqual(f["module"], xss_checks.MODULE_NAME)


# ──────────────────────────────────────────────────────────────────────────────
# Integration — run_checks
# ──────────────────────────────────────────────────────────────────────────────

class RunChecksIntegrationTests(unittest.IsolatedAsyncioTestCase):

    async def test_run_checks_empty_input(self):
        """Empty URL list → empty findings."""
        results = await xss_checks.run_checks([])
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
