"""
Integration test: verify all new check functions fire correctly against
simulated vulnerable endpoints. Uses FakeClient to simulate a target
with intentional vulnerabilities — no network required.
"""
import json
import unittest
from urllib.parse import urlparse, parse_qs, unquote

from modules import web_checks, credential_probe, graphql_checks, xss_checks
from modules.schema import validate_finding


# ── Fake HTTP layer ──────────────────────────────────────────────────

class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8", errors="replace")
        self.headers = headers or {}


class VulnerableServer:
    """Simulates a server with multiple vulnerabilities for integration testing."""

    def __init__(self):
        self.graphql_introspection = True
        self.graphql_federation = True
        self.graphql_debug = True
        self.graphql_batch = True
        self.identity_exposed = True
        self.reflects_input = True
        self.upload_listing = True

    async def get(self, url, **kwargs):
        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query
        qs = parse_qs(query)

        # Negative control paths → 404
        if "_vaktscan_" in path or "_vaktscan_" in query:
            return FakeResponse(404, "Not Found")

        # Identity endpoints
        if self.identity_exposed and path in ("/api/me", "/api/user", "/whoami"):
            return FakeResponse(200, json.dumps({
                "id": 1, "email": "admin@target.com", "name": "Admin",
                "authentication_token": "tok_live_a1b2c3d4e5f6g7h8i9j0",
                "role": "administrator"
            }), {"content-type": "application/json"})

        # Reflecting search endpoint
        if self.reflects_input and path == "/search":
            q = qs.get("q", [""])[0]
            return FakeResponse(200,
                f'<html><body><h1>Results for: {q}</h1><p>No results found.</p></body></html>',
                {"content-type": "text/html"})

        # Upload directory listing
        if self.upload_listing and path == "/uploads/":
            return FakeResponse(200,
                '<html><body><h2>Index of /uploads/</h2>'
                '<a href="report.pdf">report.pdf</a><br>'
                '<a href="avatar.jpg">avatar.jpg</a></body></html>',
                {"content-type": "text/html"})

        # GraphQL GET introspection
        if path == "/graphql" and "query" in qs:
            gql_query = qs["query"][0]
            if "__schema" in gql_query:
                return FakeResponse(200, json.dumps({
                    "data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}
                }))
            if "mutation" in gql_query:
                return FakeResponse(200, json.dumps({"data": {"__typename": "Mutation"}}))
            return FakeResponse(200, json.dumps({"data": {"__typename": "Query"}}))

        # DOM XSS indicators in main page
        if path == "/" or path == "":
            return FakeResponse(200,
                '<html><script>'
                'var x = location.hash; document.getElementById("out").innerHTML = x;'
                'window.addEventListener("message", function(e) { div.innerHTML = e.data; });'
                '</script><body><div id="out"></div></body></html>',
                {"content-type": "text/html"})

        return FakeResponse(404, "Not Found")

    async def post(self, url, **kwargs):
        parsed = urlparse(url)
        path = parsed.path
        body = kwargs.get("content", "")

        if path != "/graphql":
            return FakeResponse(404)

        # Batch query
        if isinstance(body, str) and body.strip().startswith("["):
            try:
                queries = json.loads(body)
                if self.graphql_batch:
                    return FakeResponse(200, json.dumps(
                        [{"data": {"__typename": "Query"}} for _ in queries]
                    ))
            except json.JSONDecodeError:
                pass

        if isinstance(body, str):
            try:
                parsed_body = json.loads(body)
            except json.JSONDecodeError:
                parsed_body = {}
        else:
            parsed_body = {}

        query = parsed_body.get("query", body if isinstance(body, str) else "")

        # Full introspection
        if "__schema" in query and self.graphql_introspection:
            return FakeResponse(200, json.dumps({
                "data": {"__schema": {"types": [
                    {"name": "Query"}, {"name": "User"}, {"name": "Mutation"},
                    {"name": "String"}, {"name": "Int"}, {"name": "Boolean"}
                ]}}
            }))

        # Partial introspection (__type but NOT __typename)
        if "__type(" in query or ("__type " in query and "__typename" not in query):
            return FakeResponse(200, json.dumps({
                "data": {"__type": {"name": "Query", "fields": [
                    {"name": "user", "type": {"name": "User"}},
                    {"name": "users", "type": {"name": "[User]"}}
                ]}}
            }))

        # Federation _service{sdl}
        if "_service" in query and self.graphql_federation:
            return FakeResponse(200, json.dumps({
                "data": {"_service": {"sdl": "type User @key(fields: \"id\") { id: ID! name: String email: String }"}}
            }))

        # Federation _entities
        if "_entities" in query:
            return FakeResponse(200, json.dumps({
                "data": {"_entities": [{"__typename": "User"}]}
            }))

        # Alias overload — detect many colon-separated aliases like a0:__typename a1:__typename
        colon_count = query.count(":")
        if colon_count >= 5:
            aliases = {}
            for i in range(colon_count):
                aliases[f"a{i}"] = "Query"
            return FakeResponse(200, json.dumps({"data": aliases}))

        # Field suggestion leak
        if "__nonexistent" in query or "xyzzy" in query:
            return FakeResponse(200, json.dumps({
                "errors": [{"message": "Cannot query field '__nonexistent'. Did you mean '__typename'?"}]
            }))

        # Directive overload
        if "@skip" in query:
            return FakeResponse(200, json.dumps({"data": {"__typename": "Query"}}))

        # Default — simple __typename or other queries (also serves debug extensions)
        if self.graphql_debug:
            return FakeResponse(200, json.dumps({
                "data": {"__typename": "Query"},
                "extensions": {"tracing": {"duration": 1234, "execution": {}}}
            }))

        return FakeResponse(200, json.dumps({"data": {"__typename": "Query"}}))

    async def request(self, method, url, **kwargs):
        if method == "TRACE":
            return FakeResponse(405)
        return FakeResponse(404)


URL = "http://vulnerable.test"


# ── Tests ────────────────────────────────────────────────────────────

class GraphQLExpandedTests(unittest.IsolatedAsyncioTestCase):
    """Test expanded check_graphql in web_checks.py fires all sub-checks."""

    async def test_introspection_detected(self):
        client = VulnerableServer()
        findings = await web_checks.check_graphql(URL, client)
        vulns = {f["vulnerability"] for f in findings}
        self.assertIn("GraphQL Introspection Enabled", vulns)

    async def test_debug_extensions_detected(self):
        client = VulnerableServer()
        findings = await web_checks.check_graphql(URL, client)
        vulns = {f["vulnerability"] for f in findings}
        self.assertIn("GraphQL Debug Extensions Exposed", vulns)

    async def test_federation_sdl_detected(self):
        client = VulnerableServer()
        findings = await web_checks.check_graphql(URL, client)
        vulns = {f["vulnerability"] for f in findings}
        self.assertIn("GraphQL Federation Schema Exposed (_service SDL)", vulns)

    async def test_batch_queries_detected(self):
        client = VulnerableServer()
        findings = await web_checks.check_graphql(URL, client)
        vulns = {f["vulnerability"] for f in findings}
        self.assertIn("GraphQL Batch Queries Enabled (Rate-Limit Bypass Risk)", vulns)

    async def test_get_introspection_bypass(self):
        server = VulnerableServer()
        server.graphql_introspection = False  # block POST introspection
        findings = await web_checks.check_graphql(URL, server)
        vulns = {f["vulnerability"] for f in findings}
        self.assertIn("GraphQL GET-Based Introspection Bypass", vulns)

    async def test_all_findings_valid_schema(self):
        client = VulnerableServer()
        findings = await web_checks.check_graphql(URL, client)
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertEqual(validate_finding(f), [], f"Invalid: {f['vulnerability']}")


class CredentialProbeIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Test credential_probe fires against exposed identity endpoints."""

    async def test_credential_exposure(self):
        client = VulnerableServer()
        findings = await credential_probe.check_identity_endpoints(URL, client)
        self.assertGreater(len(findings), 0)
        crit = [f for f in findings if f["status"] == "CRITICAL"]
        self.assertGreater(len(crit), 0, "Should find CRITICAL credential exposure")
        self.assertIn("authentication_token", crit[0]["details"])

    async def test_no_exposure_when_disabled(self):
        server = VulnerableServer()
        server.identity_exposed = False
        findings = await credential_probe.check_identity_endpoints(URL, server)
        self.assertEqual(findings, [])

    async def test_all_findings_valid_schema(self):
        client = VulnerableServer()
        findings = await credential_probe.check_identity_endpoints(URL, client)
        for f in findings:
            self.assertEqual(validate_finding(f), [], f"Invalid: {f['vulnerability']}")


class GraphQLAdvancedIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Test graphql_checks module fires against vulnerable GraphQL endpoint."""

    async def test_alias_overload_detected(self):
        client = VulnerableServer()
        from modules.graphql_checks import check_alias_overload
        findings = await check_alias_overload(URL, URL + "/graphql", client)
        self.assertGreater(len(findings), 0)
        self.assertIn("Alias", findings[0]["vulnerability"])

    async def test_batch_array_detected(self):
        client = VulnerableServer()
        from modules.graphql_checks import check_batch_array
        findings = await check_batch_array(URL, URL + "/graphql", client)
        self.assertGreater(len(findings), 0)

    async def test_federation_sdl_detected(self):
        client = VulnerableServer()
        from modules.graphql_checks import check_federation_sdl
        findings = await check_federation_sdl(URL, URL + "/graphql", client)
        self.assertGreater(len(findings), 0)

    async def test_field_suggestions_detected(self):
        client = VulnerableServer()
        from modules.graphql_checks import check_field_suggestions
        findings = await check_field_suggestions(URL, URL + "/graphql", client)
        self.assertGreater(len(findings), 0)

    async def test_debug_extensions_detected(self):
        client = VulnerableServer()
        from modules.graphql_checks import check_debug_extensions
        findings = await check_debug_extensions(URL, URL + "/graphql", client)
        self.assertGreater(len(findings), 0)

    async def test_all_findings_valid_schema(self):
        client = VulnerableServer()
        findings = await graphql_checks.run_checks(["http://vulnerable.test"], concurrency=5)
        for f in findings:
            self.assertEqual(validate_finding(f), [], f"Invalid: {f['vulnerability']}")


class ReflectedXSSIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Test XSS surface detection in xss_checks fires against reflecting endpoints."""

    async def test_reflected_xss_detected(self):
        client = VulnerableServer()
        findings = await xss_checks.check_reflected_xss(URL, client)
        self.assertGreater(len(findings), 0, "Should detect reflected input in search")
        vulns = {f["vulnerability"] for f in findings}
        has_xss = any("Reflected" in v or "Unescaped" in v or "XSS" in v for v in vulns)
        self.assertTrue(has_xss, f"Expected XSS finding, got: {vulns}")

    async def test_no_reflection_when_disabled(self):
        server = VulnerableServer()
        server.reflects_input = False
        findings = await xss_checks.check_reflected_xss(URL, server)
        self.assertEqual(findings, [])

    async def test_all_findings_valid_schema(self):
        client = VulnerableServer()
        findings = await xss_checks.check_reflected_xss(URL, client)
        for f in findings:
            self.assertEqual(validate_finding(f), [], f"Invalid: {f['vulnerability']}")


class UploadContentTypeIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Test upload directory content-type check in xss_checks."""

    async def test_upload_listing_detected(self):
        client = VulnerableServer()
        findings = await xss_checks.check_stored_xss_surfaces(URL, client)
        self.assertGreater(len(findings), 0, "Should detect upload directory listing")

    async def test_no_listing_when_disabled(self):
        server = VulnerableServer()
        server.upload_listing = False
        findings = await xss_checks.check_stored_xss_surfaces(URL, server)
        self.assertEqual(findings, [])

    async def test_all_findings_valid_schema(self):
        client = VulnerableServer()
        findings = await xss_checks.check_stored_xss_surfaces(URL, client)
        for f in findings:
            self.assertEqual(validate_finding(f), [], f"Invalid: {f['vulnerability']}")


class FullPipelineTest(unittest.IsolatedAsyncioTestCase):
    """End-to-end: all new modules produce valid, non-empty findings against a vulnerable target."""

    async def test_all_modules_produce_findings(self):
        client = VulnerableServer()
        all_findings = []

        # web_checks expanded GraphQL
        gql = await web_checks.check_graphql(URL, client)
        all_findings.extend(gql)

        # xss_checks reflected
        xss = await xss_checks.check_reflected_xss(URL, client)
        all_findings.extend(xss)

        # xss_checks upload
        upload = await xss_checks.check_stored_xss_surfaces(URL, client)
        all_findings.extend(upload)

        # credential_probe
        cred = await credential_probe.check_identity_endpoints(URL, client)
        all_findings.extend(cred)

        self.assertGreaterEqual(len(all_findings), 5,
                               f"Expected 5+ findings across all modules, got {len(all_findings)}")

        # Every finding must pass schema validation
        for f in all_findings:
            violations = validate_finding(f)
            self.assertEqual(violations, [],
                             f"Schema violation in {f['vulnerability']}: {violations}")

        # Verify we got findings from multiple modules
        modules_hit = {f["module"] for f in all_findings}
        self.assertIn("WebChecks", modules_hit)
        self.assertIn("CredentialProbe", modules_hit)

        print(f"\n  Total findings: {len(all_findings)}")
        print(f"  Modules: {modules_hit}")
        for f in all_findings:
            print(f"    [{f['status']:>10}] [{f['severity']:>8}] {f['vulnerability']}")


if __name__ == "__main__":
    unittest.main()
