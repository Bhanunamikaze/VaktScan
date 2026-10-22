"""
Tests for the expanded GraphQL security checks in web_checks.check_graphql.

Covers: full introspection, partial introspection bypass, GET introspection
bypass, field suggestion leak, debug extensions, federation SDL exposure,
GET-mutation CSRF, batch query detection, and negative cases.

Fully offline: a fake httpx-like client feeds canned responses keyed by path.
"""

import unittest
from urllib.parse import urlparse, parse_qs

from modules import web_checks
from modules.schema import validate_finding


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8", errors="replace")
        self.headers = headers or {}


class FakeClient:
    """Routes GET (with query-string matching) and POST by URL path."""

    def __init__(self, routes=None, post_routes=None,
                 default_status=404, default_text=""):
        self.routes = routes or {}
        self.post_routes = post_routes or {}
        self.default_status = default_status
        self.default_text = default_text

    async def get(self, url, **kwargs):
        parsed = urlparse(url)
        path = parsed.path or "/"
        query = parsed.query
        key = f"{path}?{query}" if query else path
        if key in self.routes:
            return self.routes[key]
        if path in self.routes:
            return self.routes[path]
        return FakeResponse(self.default_status, self.default_text)

    async def post(self, url, **kwargs):
        parsed = urlparse(url)
        path = parsed.path or "/"
        if path in self.post_routes:
            handler = self.post_routes[path]
            if callable(handler):
                return handler(kwargs.get("content", ""))
            return handler
        return FakeResponse(self.default_status, self.default_text)


URL = "http://target.test"


def _titles(findings):
    return {f["vulnerability"] for f in findings}


def _gql_post_router(introspection=True, partial=True, suggestions=False,
                      debug_ext=False, federation=False, batch=False):
    """Return a callable that simulates a GraphQL endpoint's POST responses."""
    def handler(content):
        body = content if isinstance(content, str) else content.decode("utf-8", errors="replace")

        # Batch: array payload starts with [
        if body.strip().startswith("["):
            if batch:
                return FakeResponse(200, '[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]')
            return FakeResponse(400, '{"errors":[{"message":"Batch not supported"}]}')

        if "__schema" in body:
            if introspection:
                return FakeResponse(200, '{"data":{"__schema":{"types":[{"name":"Query"}]}}}')
            return FakeResponse(200, '{"errors":[{"message":"Introspection disabled"}]}')

        # __type(name:...) but not __typename — check for the parenthesis
        if "__type(" in body:
            if partial:
                return FakeResponse(200, '{"data":{"__type":{"name":"Query","fields":[{"name":"user","type":{"name":"User"}}]}}}')
            return FakeResponse(200, '{"errors":[{"message":"Not allowed"}]}')

        if "__nonexistent" in body:
            if suggestions:
                return FakeResponse(400, '{"errors":[{"message":"Cannot query field \\"__nonexistent\\". Did you mean \\"user\\" or \\"users\\"?"}]}')
            return FakeResponse(400, '{"errors":[{"message":"Cannot query field \\"__nonexistent\\"."}]}')

        if "_service" in body and "__typename" not in body:
            if federation:
                return FakeResponse(200, '{"data":{"_service":{"sdl":"type Query { user(id: ID!): User }\\nextend type User @key(fields: \\"id\\") { id: ID! }"}}}')
            return FakeResponse(200, '{"errors":[{"message":"Cannot query field \\"_service\\"."}]}')

        if "__typename" in body:
            if debug_ext:
                return FakeResponse(200, '{"data":{"__typename":"Query"},"extensions":{"tracing":{"duration":1234}}}')
            return FakeResponse(200, '{"data":{"__typename":"Query"}}')

        return FakeResponse(200, '{"data":{}}')
    return handler


class GraphQLFullIntrospectionTest(unittest.IsolatedAsyncioTestCase):
    async def test_full_introspection_detected(self):
        client = FakeClient(post_routes={
            "/graphql": _gql_post_router(introspection=True),
        })
        findings = await web_checks.check_graphql(URL, client)
        titles = _titles(findings)
        self.assertIn("GraphQL Introspection Enabled", titles)
        f = next(f for f in findings if f["vulnerability"] == "GraphQL Introspection Enabled")
        self.assertEqual(f["status"], "CRITICAL")
        self.assertEqual(f["severity"], "HIGH")
        for finding in findings:
            self.assertEqual(validate_finding(finding), [])


class GraphQLPartialIntrospectionTest(unittest.IsolatedAsyncioTestCase):
    async def test_partial_introspection_bypass(self):
        client = FakeClient(post_routes={
            "/graphql": _gql_post_router(introspection=False, partial=True),
        })
        findings = await web_checks.check_graphql(URL, client)
        titles = _titles(findings)
        self.assertNotIn("GraphQL Introspection Enabled", titles)
        self.assertIn("GraphQL Partial Introspection Bypass (__type)", titles)
        f = next(f for f in findings if "Partial" in f["vulnerability"])
        self.assertEqual(f["status"], "VULNERABLE")
        self.assertEqual(f["severity"], "MEDIUM")
        for finding in findings:
            self.assertEqual(validate_finding(finding), [])


class GraphQLGetIntrospectionTest(unittest.IsolatedAsyncioTestCase):
    async def test_get_introspection_bypass(self):
        client = FakeClient(
            routes={
                "/graphql?query={__schema{types{name}}}":
                    FakeResponse(200, '{"data":{"__schema":{"types":[{"name":"Query"}]}}}'),
            },
            post_routes={
                "/graphql": _gql_post_router(introspection=False, partial=False),
            },
        )
        findings = await web_checks.check_graphql(URL, client)
        titles = _titles(findings)
        self.assertNotIn("GraphQL Introspection Enabled", titles)
        self.assertIn("GraphQL GET-Based Introspection Bypass", titles)
        f = next(f for f in findings if "GET-Based" in f["vulnerability"])
        self.assertEqual(f["status"], "CRITICAL")
        self.assertEqual(f["severity"], "HIGH")
        for finding in findings:
            self.assertEqual(validate_finding(finding), [])


class GraphQLFieldSuggestionTest(unittest.IsolatedAsyncioTestCase):
    async def test_field_suggestion_leak(self):
        client = FakeClient(post_routes={
            "/graphql": _gql_post_router(introspection=False, suggestions=True),
        })
        findings = await web_checks.check_graphql(URL, client)
        titles = _titles(findings)
        self.assertIn("GraphQL Field Suggestion Leak", titles)
        f = next(f for f in findings if "Suggestion" in f["vulnerability"])
        self.assertEqual(f["status"], "POTENTIAL")
        self.assertEqual(f["severity"], "MEDIUM")
        for finding in findings:
            self.assertEqual(validate_finding(finding), [])


class GraphQLDebugExtensionsTest(unittest.IsolatedAsyncioTestCase):
    async def test_debug_extensions_detected(self):
        client = FakeClient(post_routes={
            "/graphql": _gql_post_router(debug_ext=True),
        })
        findings = await web_checks.check_graphql(URL, client)
        titles = _titles(findings)
        self.assertIn("GraphQL Debug Extensions Exposed", titles)
        f = next(f for f in findings if "Debug" in f["vulnerability"])
        self.assertEqual(f["status"], "VULNERABLE")
        self.assertEqual(f["severity"], "MEDIUM")
        for finding in findings:
            self.assertEqual(validate_finding(finding), [])


class GraphQLFederationSDLTest(unittest.IsolatedAsyncioTestCase):
    async def test_federation_sdl_exposed(self):
        client = FakeClient(post_routes={
            "/graphql": _gql_post_router(federation=True),
        })
        findings = await web_checks.check_graphql(URL, client)
        titles = _titles(findings)
        self.assertIn("GraphQL Federation Schema Exposed (_service SDL)", titles)
        f = next(f for f in findings if "Federation" in f["vulnerability"])
        self.assertEqual(f["status"], "CRITICAL")
        self.assertEqual(f["severity"], "HIGH")
        for finding in findings:
            self.assertEqual(validate_finding(finding), [])


class GraphQLGetMutationCSRFTest(unittest.IsolatedAsyncioTestCase):
    async def test_get_mutation_csrf(self):
        client = FakeClient(
            routes={
                "/graphql?query=mutation{__typename}":
                    FakeResponse(200, '{"data":{"__typename":"Mutation"}}'),
                "/graphql?query={__schema{types{name}}}":
                    FakeResponse(400, '{"errors":[{"message":"not allowed"}]}'),
            },
            post_routes={
                "/graphql": _gql_post_router(),
            },
        )
        findings = await web_checks.check_graphql(URL, client)
        titles = _titles(findings)
        self.assertIn("GraphQL GET-Mutation CSRF Risk", titles)
        f = next(f for f in findings if "CSRF" in f["vulnerability"])
        self.assertEqual(f["status"], "VULNERABLE")
        self.assertEqual(f["severity"], "HIGH")
        for finding in findings:
            self.assertEqual(validate_finding(finding), [])


class GraphQLBatchQueryTest(unittest.IsolatedAsyncioTestCase):
    async def test_batch_queries_detected(self):
        client = FakeClient(post_routes={
            "/graphql": _gql_post_router(batch=True),
        })
        findings = await web_checks.check_graphql(URL, client)
        titles = _titles(findings)
        self.assertIn("GraphQL Batch Queries Enabled (Rate-Limit Bypass Risk)", titles)
        f = next(f for f in findings if "Batch" in f["vulnerability"])
        self.assertEqual(f["status"], "POTENTIAL")
        self.assertEqual(f["severity"], "MEDIUM")
        for finding in findings:
            self.assertEqual(validate_finding(finding), [])


class GraphQLNoEndpointTest(unittest.IsolatedAsyncioTestCase):
    async def test_no_graphql_no_findings(self):
        client = FakeClient(default_status=404)
        findings = await web_checks.check_graphql(URL, client)
        self.assertEqual(findings, [])


class GraphQLAllFindingsSchemaTest(unittest.IsolatedAsyncioTestCase):
    async def test_all_findings_validate(self):
        """Fire every check and verify all findings pass schema validation."""
        client = FakeClient(
            routes={
                "/graphql?query={__schema{types{name}}}":
                    FakeResponse(200, '{"data":{"__schema":{"types":[{"name":"Query"}]}}}'),
                "/graphql?query=mutation{__typename}":
                    FakeResponse(200, '{"data":{"__typename":"Mutation"}}'),
            },
            post_routes={
                "/graphql": _gql_post_router(
                    introspection=True, partial=True, suggestions=True,
                    debug_ext=True, federation=True, batch=True,
                ),
            },
        )
        findings = await web_checks.check_graphql(URL, client)
        self.assertGreaterEqual(len(findings), 5)
        for f in findings:
            violations = validate_finding(f)
            self.assertEqual(violations, [], f"Finding {f['vulnerability']} failed: {violations}")
            self.assertEqual(f["module"], web_checks.MODULE_NAME)


class GraphQLEndpointDiscoveryTest(unittest.IsolatedAsyncioTestCase):
    async def test_finds_endpoint_on_alternate_path(self):
        """Endpoint at /api/v1/graphql is discovered and checked."""
        client = FakeClient(post_routes={
            "/api/v1/graphql": _gql_post_router(introspection=True),
        })
        findings = await web_checks.check_graphql(URL, client)
        titles = _titles(findings)
        self.assertIn("GraphQL Introspection Enabled", titles)
        self.assertIn("/api/v1/graphql", findings[0]["payload_url"])


if __name__ == "__main__":
    unittest.main()
