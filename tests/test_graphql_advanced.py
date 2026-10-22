"""
Tests for modules/graphql_checks.py — advanced GraphQL security checks.

Uses a FakeClient with POST/GET support to simulate GraphQL endpoint responses.
"""

import asyncio
import json
import unittest
from urllib.parse import urlparse

from modules import graphql_checks
from modules.schema import validate_finding


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8", errors="replace")
        self.headers = headers or {}


class FakeClient:
    """Routes POST and GET by URL path via handler callbacks."""

    def __init__(self, post_handler=None, get_handler=None, default_status=404):
        self.post_handler = post_handler
        self.get_handler = get_handler
        self.default_status = default_status

    async def post(self, url, **kwargs):
        if self.post_handler:
            return self.post_handler(url, kwargs.get("content", ""))
        return FakeResponse(self.default_status)

    async def get(self, url, **kwargs):
        if self.get_handler:
            return self.get_handler(url, kwargs)
        return FakeResponse(self.default_status)


URL = "http://target.test"
GQL_URL = "http://target.test:80/graphql"


def _make_typename_response():
    return FakeResponse(200, json.dumps({"data": {"__typename": "Query"}}))


def _make_gql_post_handler(extra_handlers=None):
    """Return a post_handler that recognises the /graphql path and delegates."""
    extra = extra_handlers or {}

    def handler(url, content):
        path = urlparse(url).path
        if path != "/graphql":
            return FakeResponse(404)
        body_str = content if isinstance(content, str) else content.decode()
        # Dispatch by query content.
        for key, fn in extra.items():
            if key in body_str:
                return fn(body_str)
        # Default: accept __typename probes.
        if "__typename" in body_str:
            return _make_typename_response()
        return FakeResponse(200, json.dumps({"errors": [{"message": "unknown"}]}))

    return handler


# ──────────────────────────────────────────────────────────────────────────────
# Alias overload
# ──────────────────────────────────────────────────────────────────────────────

class AliasOverloadTests(unittest.IsolatedAsyncioTestCase):
    async def test_alias_overload_detected(self):
        def alias_handler(body_str):
            data = {f"a{i}": "Query" for i in range(50)}
            return FakeResponse(200, json.dumps({"data": data}))

        handler = _make_gql_post_handler({"a49:": alias_handler})
        client = FakeClient(post_handler=handler)
        findings = await graphql_checks.check_alias_overload(URL, GQL_URL, client)
        self.assertEqual(len(findings), 1)
        self.assertIn("Alias Overload", findings[0]["vulnerability"])
        self.assertEqual(findings[0]["status"], "POTENTIAL")
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    async def test_alias_overload_rejected(self):
        def reject_handler(body_str):
            return FakeResponse(200, json.dumps({
                "errors": [{"message": "Query too complex"}],
            }))

        handler = _make_gql_post_handler({"a49:": reject_handler})
        client = FakeClient(post_handler=handler)
        findings = await graphql_checks.check_alias_overload(URL, GQL_URL, client)
        self.assertEqual(findings, [])


# ──────────────────────────────────────────────────────────────────────────────
# Batch array
# ──────────────────────────────────────────────────────────────────────────────

class BatchArrayTests(unittest.IsolatedAsyncioTestCase):
    async def test_batch_array_detected(self):
        def batch_handler(body_str):
            items = json.loads(body_str)
            results = [{"data": {"__typename": "Query"}} for _ in items]
            return FakeResponse(200, json.dumps(results))

        handler = _make_gql_post_handler({"[{": batch_handler})
        client = FakeClient(post_handler=handler)
        findings = await graphql_checks.check_batch_array(URL, GQL_URL, client)
        self.assertEqual(len(findings), 1)
        self.assertIn("Array Batching", findings[0]["vulnerability"])

    async def test_batch_array_rejected(self):
        def reject_handler(body_str):
            return FakeResponse(200, json.dumps(
                {"errors": [{"message": "Batching not supported"}]}
            ))

        handler = _make_gql_post_handler({"[{": reject_handler})
        client = FakeClient(post_handler=handler)
        findings = await graphql_checks.check_batch_array(URL, GQL_URL, client)
        self.assertEqual(findings, [])


# ──────────────────────────────────────────────────────────────────────────────
# Directive overload
# ──────────────────────────────────────────────────────────────────────────────

class DirectiveOverloadTests(unittest.IsolatedAsyncioTestCase):
    async def test_directive_overload_detected(self):
        handler = _make_gql_post_handler()
        client = FakeClient(post_handler=handler)
        findings = await graphql_checks.check_directive_overload(URL, GQL_URL, client)
        self.assertEqual(len(findings), 1)
        self.assertIn("Directive Overloading", findings[0]["vulnerability"])
        self.assertEqual(findings[0]["status"], "INFO")

    async def test_directive_overload_rejected(self):
        def reject_handler(body_str):
            if "@skip" in body_str:
                return FakeResponse(200, json.dumps({
                    "errors": [{"message": "Too many directives"}],
                }))
            return _make_typename_response()

        handler = _make_gql_post_handler({"@skip": reject_handler})
        client = FakeClient(post_handler=handler)
        findings = await graphql_checks.check_directive_overload(URL, GQL_URL, client)
        self.assertEqual(findings, [])


# ──────────────────────────────────────────────────────────────────────────────
# Field suggestions
# ──────────────────────────────────────────────────────────────────────────────

class FieldSuggestionTests(unittest.IsolatedAsyncioTestCase):
    async def test_field_suggestions_detected(self):
        def suggestion_handler(body_str):
            return FakeResponse(400, json.dumps({
                "errors": [{"message": "Cannot query field 'xyzzy'. Did you mean 'user'?"}],
            }))

        handler = _make_gql_post_handler({"__nonexistent_field": suggestion_handler})
        client = FakeClient(post_handler=handler)
        findings = await graphql_checks.check_field_suggestions(URL, GQL_URL, client)
        self.assertEqual(len(findings), 1)
        self.assertIn("Field Suggestions", findings[0]["vulnerability"])

    async def test_field_suggestions_absent(self):
        def no_suggestion_handler(body_str):
            return FakeResponse(400, json.dumps({
                "errors": [{"message": "Cannot query field '__nonexistent_field_xyzzy_vaktscan'"}],
            }))

        handler = _make_gql_post_handler({"__nonexistent_field": no_suggestion_handler})
        client = FakeClient(post_handler=handler)
        findings = await graphql_checks.check_field_suggestions(URL, GQL_URL, client)
        self.assertEqual(findings, [])


# ──────────────────────────────────────────────────────────────────────────────
# Debug extensions
# ──────────────────────────────────────────────────────────────────────────────

class DebugExtensionTests(unittest.IsolatedAsyncioTestCase):
    async def test_debug_extensions_detected(self):
        def debug_handler(body_str):
            return FakeResponse(200, json.dumps({
                "data": {"__typename": "Query"},
                "extensions": {
                    "tracing": {"duration": 1234},
                    "cacheControl": {"hints": []},
                },
            }))

        handler = _make_gql_post_handler({"__typename": debug_handler})
        client = FakeClient(post_handler=handler)
        findings = await graphql_checks.check_debug_extensions(URL, GQL_URL, client)
        self.assertEqual(len(findings), 1)
        self.assertIn("Debug/Tracing", findings[0]["vulnerability"])
        self.assertIn("cacheControl", findings[0]["details"])
        self.assertIn("tracing", findings[0]["details"])

    async def test_no_debug_extensions(self):
        handler = _make_gql_post_handler()
        client = FakeClient(post_handler=handler)
        findings = await graphql_checks.check_debug_extensions(URL, GQL_URL, client)
        self.assertEqual(findings, [])


# ──────────────────────────────────────────────────────────────────────────────
# Federation SDL
# ──────────────────────────────────────────────────────────────────────────────

class FederationSdlTests(unittest.IsolatedAsyncioTestCase):
    async def test_federation_sdl_detected(self):
        def sdl_handler(body_str):
            return FakeResponse(200, json.dumps({
                "data": {"_service": {"sdl": "type User @key(fields: \"id\") { id: ID! email: String }"}},
            }))

        handler = _make_gql_post_handler({"_service": sdl_handler})
        client = FakeClient(post_handler=handler)
        findings = await graphql_checks.check_federation_sdl(URL, GQL_URL, client)
        self.assertEqual(len(findings), 1)
        self.assertIn("Federation", findings[0]["vulnerability"])
        self.assertEqual(findings[0]["severity"], "HIGH")

    async def test_federation_sdl_not_exposed(self):
        def no_sdl_handler(body_str):
            return FakeResponse(200, json.dumps({
                "errors": [{"message": "Cannot query field '_service'"}],
            }))

        handler = _make_gql_post_handler({"_service": no_sdl_handler})
        client = FakeClient(post_handler=handler)
        findings = await graphql_checks.check_federation_sdl(URL, GQL_URL, client)
        self.assertEqual(findings, [])


# ──────────────────────────────────────────────────────────────────────────────
# GET query (mutation CSRF risk)
# ──────────────────────────────────────────────────────────────────────────────

class GetQueryTests(unittest.IsolatedAsyncioTestCase):
    async def test_get_query_accepted(self):
        def get_handler(url, kwargs):
            params = kwargs.get("params", {})
            if params.get("query") and "__typename" in params["query"]:
                return FakeResponse(200, json.dumps({"data": {"__typename": "Query"}}))
            return FakeResponse(404)

        client = FakeClient(get_handler=get_handler)
        findings = await graphql_checks.check_get_query(URL, GQL_URL, client)
        self.assertEqual(len(findings), 1)
        self.assertIn("GET Queries", findings[0]["vulnerability"])

    async def test_get_query_rejected(self):
        client = FakeClient()
        findings = await graphql_checks.check_get_query(URL, GQL_URL, client)
        self.assertEqual(findings, [])


# ──────────────────────────────────────────────────────────────────────────────
# No GraphQL endpoint → no findings
# ──────────────────────────────────────────────────────────────────────────────

class NoGraphqlTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_graphql_no_findings(self):
        client = FakeClient(default_status=404)
        findings = await graphql_checks._run_checks_for_url(
            URL, client, asyncio.Semaphore(1),
        )
        self.assertEqual(findings, [])


# ──────────────────────────────────────────────────────────────────────────────
# Schema validation — every finding passes validate_finding()
# ──────────────────────────────────────────────────────────────────────────────

class SchemaValidationTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_findings_pass_schema(self):
        data_50 = {f"a{i}": "Query" for i in range(50)}
        batch_10 = [{"data": {"__typename": "Query"}}] * 10

        def omnibus_handler(url, content):
            path = urlparse(url).path
            if path != "/graphql":
                return FakeResponse(404)
            body_str = content if isinstance(content, str) else content.decode()
            if "[{" in body_str:
                return FakeResponse(200, json.dumps(batch_10))
            if "_service" in body_str:
                return FakeResponse(200, json.dumps({
                    "data": {"_service": {"sdl": "type Q { f: Int }"}},
                }))
            if "__nonexistent_field" in body_str:
                return FakeResponse(400, json.dumps({
                    "errors": [{"message": "Did you mean 'user'?"}],
                }))
            if "a49:" in body_str:
                return FakeResponse(200, json.dumps({"data": data_50}))
            return FakeResponse(200, json.dumps({
                "data": {"__typename": "Query"},
                "extensions": {"tracing": {"duration": 1}},
            }))

        def get_handler(url, kwargs):
            params = kwargs.get("params", {})
            if params.get("query"):
                return FakeResponse(200, json.dumps({"data": {"__typename": "Query"}}))
            return FakeResponse(404)

        client = FakeClient(
            post_handler=omnibus_handler,
            get_handler=get_handler,
        )
        findings = await graphql_checks._run_checks_for_url(
            URL, client, asyncio.Semaphore(1),
        )
        self.assertGreater(len(findings), 0, "Expected at least one finding")
        for f in findings:
            violations = validate_finding(f)
            self.assertEqual(violations, [], f"Schema violation in {f['vulnerability']}: {violations}")
            self.assertEqual(f["module"], graphql_checks.MODULE_NAME)


if __name__ == "__main__":
    unittest.main()
