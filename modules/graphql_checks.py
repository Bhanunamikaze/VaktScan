"""
graphql_checks.py - Advanced GraphQL security checks for VaktScan.

Goes beyond basic introspection (handled by web_checks.check_graphql) to test
alias overloading, array batching, directive abuse, federation exposure, field
suggestion leaks, debug extensions, and GET-based mutation CSRF.

Entry point:
    async def run_checks(alive_urls: list[str], concurrency: int = 20) -> list[dict]
"""

from __future__ import annotations

import asyncio
import datetime
import json
import re
from urllib.parse import urlparse

import httpx

from modules.progress import DashboardProgress, heartbeat

MODULE_NAME = "GraphQLChecks"
_DEFAULT_TIMEOUT = 10.0

_GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/playground", "/console",
    "/api/graphql", "/api/v1/graphql", "/api/v2/graphql", "/api/gql",
    "/v1/graphql", "/v2/graphql", "/gql", "/query",
    "/graphql/console", "/graphql/v1", "/graphql/v2",
    "/altair", "/explorer", "/graphql-explorer",
    "/admin/graphql", "/internal/graphql",
]

_GQL_HEADERS = {"Content-Type": "application/json"}

# Probe payload — minimal query that any compliant server accepts.
_TYPENAME_QUERY = json.dumps({"query": "{__typename}"})


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _origin(url: str) -> str:
    p = urlparse(url)
    port = p.port
    if port is None:
        port = 443 if p.scheme == "https" else 80
    return f"{p.scheme}://{p.hostname}:{port}"


def _make_finding(
    *,
    url: str,
    payload_url: str,
    vulnerability: str,
    status: str,
    severity: str,
    details: str,
    http_status: str = "N/A",
    page_title: str = "N/A",
    content_length: str = "N/A",
    service_version: str = "N/A",
) -> dict:
    p = urlparse(url)
    host = p.hostname or url
    port = str(p.port or (443 if p.scheme == "https" else 80))
    return {
        "status":          status,
        "vulnerability":   vulnerability,
        "target":          host,
        "resolved_ip":     "N/A",
        "port":            port,
        "url":             url,
        "payload_url":     payload_url,
        "module":          MODULE_NAME,
        "service_version": service_version,
        "severity":        severity,
        "details":         details,
        "http_status":     http_status,
        "page_title":      page_title,
        "content_length":  content_length,
        "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
    }


async def _post_json(client, url: str, payload: str):
    return await client.post(url, content=payload, headers=_GQL_HEADERS)


def _is_gql_data(text: str) -> bool:
    """Return True when the response looks like a GraphQL data envelope."""
    return '"data"' in text


# ──────────────────────────────────────────────────────────────────────────────
# Endpoint discovery
# ──────────────────────────────────────────────────────────────────────────────

async def _find_graphql_endpoint(
    origin: str, client: httpx.AsyncClient,
) -> str | None:
    for path in _GRAPHQL_PATHS:
        probe_url = origin + path
        try:
            resp = await _post_json(client, probe_url, _TYPENAME_QUERY)
        except Exception:
            continue
        if resp.status_code == 200 and _is_gql_data(resp.text):
            return probe_url
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Individual checks
# ──────────────────────────────────────────────────────────────────────────────

async def check_alias_overload(
    url: str, gql_url: str, client: httpx.AsyncClient,
) -> list[dict]:
    query = "{" + " ".join(f"a{i}:__typename" for i in range(50)) + "}"
    payload = json.dumps({"query": query})
    try:
        resp = await _post_json(client, gql_url, payload)
    except Exception:
        return []
    if resp.status_code != 200 or not _is_gql_data(resp.text):
        return []
    try:
        data = json.loads(resp.text).get("data", {})
    except (json.JSONDecodeError, AttributeError):
        return []
    if not isinstance(data, dict):
        return []
    matched = sum(1 for i in range(50) if f"a{i}" in data)
    if matched < 50:
        return []
    return [_make_finding(
        url=url,
        payload_url=gql_url,
        vulnerability="GraphQL Alias Overload Accepted (Rate-Limit Bypass Risk)",
        status="POTENTIAL",
        severity="MEDIUM",
        details=(
            f"The GraphQL endpoint at '{gql_url}' accepted a query containing "
            "50 aliased fields in a single request without rejection. An attacker "
            "can abuse this to bypass per-query rate limits by packing many "
            "operations into one request (e.g. brute-forcing OTPs or passwords)."
        ),
        http_status=str(resp.status_code),
        content_length=str(len(resp.content)),
    )]


async def check_batch_array(
    url: str, gql_url: str, client: httpx.AsyncClient,
) -> list[dict]:
    batch = json.dumps([{"query": "{__typename}"}] * 10)
    try:
        resp = await _post_json(client, gql_url, batch)
    except Exception:
        return []
    if resp.status_code != 200:
        return []
    try:
        body = json.loads(resp.text)
    except json.JSONDecodeError:
        return []
    if not isinstance(body, list) or len(body) < 10:
        return []
    data_count = sum(1 for item in body if isinstance(item, dict) and "data" in item)
    if data_count < 10:
        return []
    return [_make_finding(
        url=url,
        payload_url=gql_url,
        vulnerability="GraphQL Array Batching Enabled (Rate-Limit Bypass Risk)",
        status="POTENTIAL",
        severity="MEDIUM",
        details=(
            f"The GraphQL endpoint at '{gql_url}' processed an array batch of "
            "10 queries in a single HTTP request and returned all 10 results. "
            "An attacker can use batched queries to bypass rate limits, "
            "brute-force credentials, or enumerate data in bulk."
        ),
        http_status=str(resp.status_code),
        content_length=str(len(resp.content)),
    )]


async def check_directive_overload(
    url: str, gql_url: str, client: httpx.AsyncClient,
) -> list[dict]:
    query = "{__typename" + " @skip(if:false)" * 20 + "}"
    payload = json.dumps({"query": query})
    try:
        resp = await _post_json(client, gql_url, payload)
    except Exception:
        return []
    if resp.status_code != 200 or not _is_gql_data(resp.text):
        return []
    return [_make_finding(
        url=url,
        payload_url=gql_url,
        vulnerability="GraphQL Directive Overloading Accepted",
        status="INFO",
        severity="LOW",
        details=(
            f"The GraphQL endpoint at '{gql_url}' accepted a query with 20 "
            "duplicate @skip directives. This indicates no directive-count limit "
            "is enforced, which can contribute to resource-exhaustion attacks."
        ),
        http_status=str(resp.status_code),
        content_length=str(len(resp.content)),
    )]


async def check_field_suggestions(
    url: str, gql_url: str, client: httpx.AsyncClient,
) -> list[dict]:
    payload = json.dumps({"query": "{__nonexistent_field_xyzzy_vaktscan}"})
    try:
        resp = await _post_json(client, gql_url, payload)
    except Exception:
        return []
    if resp.status_code not in (200, 400):
        return []
    if "did you mean" not in resp.text.lower():
        return []
    return [_make_finding(
        url=url,
        payload_url=gql_url,
        vulnerability="GraphQL Field Suggestions Enabled (Schema Reconstruction Risk)",
        status="POTENTIAL",
        severity="MEDIUM",
        details=(
            f"The GraphQL endpoint at '{gql_url}' responds with 'Did you mean' "
            "field suggestions on invalid queries. Even with introspection disabled, "
            "an attacker can brute-force field names using wordlists and reconstruct "
            "the schema (Clairvoyance-style attack)."
        ),
        http_status=str(resp.status_code),
        content_length=str(len(resp.content)),
    )]


async def check_debug_extensions(
    url: str, gql_url: str, client: httpx.AsyncClient,
) -> list[dict]:
    payload = json.dumps({"query": "{__typename}"})
    try:
        resp = await _post_json(client, gql_url, payload)
    except Exception:
        return []
    if resp.status_code != 200:
        return []
    try:
        body = json.loads(resp.text)
    except json.JSONDecodeError:
        return []
    extensions = body.get("extensions", {})
    if not isinstance(extensions, dict):
        return []
    debug_keys = {"tracing", "debug", "cacheControl", "trace", "metrics"}
    found = debug_keys & set(extensions.keys())
    if not found:
        return []
    return [_make_finding(
        url=url,
        payload_url=gql_url,
        vulnerability="GraphQL Debug/Tracing Extensions Exposed in Production",
        status="VULNERABLE",
        severity="MEDIUM",
        details=(
            f"The GraphQL endpoint at '{gql_url}' returns debug extensions in "
            f"responses: {', '.join(sorted(found))}. These can leak SQL queries, "
            "resolver timing, cache behaviour, and internal service topology."
        ),
        http_status=str(resp.status_code),
        content_length=str(len(resp.content)),
    )]


async def check_federation_sdl(
    url: str, gql_url: str, client: httpx.AsyncClient,
) -> list[dict]:
    payload = json.dumps({"query": "{_service{sdl}}"})
    try:
        resp = await _post_json(client, gql_url, payload)
    except Exception:
        return []
    if resp.status_code != 200 or not _is_gql_data(resp.text):
        return []
    try:
        data = json.loads(resp.text).get("data", {})
    except (json.JSONDecodeError, AttributeError):
        return []
    service = data.get("_service") if isinstance(data, dict) else None
    if not isinstance(service, dict) or not service.get("sdl"):
        return []
    return [_make_finding(
        url=url,
        payload_url=gql_url,
        vulnerability="GraphQL Federation _service SDL Exposed",
        status="VULNERABLE",
        severity="HIGH",
        details=(
            f"The GraphQL subgraph at '{gql_url}' exposes its full SDL schema "
            "via the _service{{sdl}} query. This reveals the complete type "
            "system including internal fields. If the subgraph is directly "
            "accessible (not behind a gateway), _entities queries can bypass "
            "gateway-level authorization."
        ),
        http_status=str(resp.status_code),
        content_length=str(len(resp.content)),
    )]


async def check_get_query(
    url: str, gql_url: str, client: httpx.AsyncClient,
) -> list[dict]:
    try:
        resp = await client.get(
            gql_url, params={"query": "{__typename}"},
        )
    except Exception:
        return []
    if resp.status_code != 200 or not _is_gql_data(resp.text):
        return []
    return [_make_finding(
        url=url,
        payload_url=f"{gql_url}?query={{__typename}}",
        vulnerability="GraphQL Accepts GET Queries (Mutation CSRF Risk)",
        status="POTENTIAL",
        severity="MEDIUM",
        details=(
            f"The GraphQL endpoint at '{gql_url}' accepts queries via HTTP GET. "
            "If mutations are also accepted via GET and no CSRF token is required, "
            "an attacker can craft a URL that performs state-changing operations "
            "when visited by an authenticated user."
        ),
        http_status=str(resp.status_code),
        content_length=str(len(resp.content)),
    )]


# ──────────────────────────────────────────────────────────────────────────────
# Per-URL orchestration
# ──────────────────────────────────────────────────────────────────────────────

_ALL_GQL_CHECKS = [
    check_alias_overload,
    check_batch_array,
    check_directive_overload,
    check_field_suggestions,
    check_debug_extensions,
    check_federation_sdl,
    check_get_query,
]


async def _run_checks_for_url(
    url: str,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> list[dict]:
    async with semaphore:
        origin = _origin(url)
        gql_url = await _find_graphql_endpoint(origin, client)
        if gql_url is None:
            return []
        tasks = [check(url, gql_url, client) for check in _ALL_GQL_CHECKS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: list[dict] = []
        for res in results:
            if isinstance(res, list):
                findings.extend(res)
        return findings


def _dedup_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for f in findings:
        key = (f.get("vulnerability", ""), f.get("payload_url", ""), f.get("target", ""))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


async def run_checks(alive_urls: list[str], concurrency: int = 20) -> list[dict]:
    """
    Run advanced GraphQL security checks against the provided alive URLs.

    Discovers GraphQL endpoints automatically, then tests for alias overloading,
    array batching, directive abuse, field suggestions, debug extensions,
    federation SDL exposure, and GET-based query/mutation CSRF.
    """
    if not alive_urls:
        return []

    request_concurrency = max(1, int(concurrency))
    semaphore = asyncio.Semaphore(max(1, request_concurrency // 50))
    findings: list[dict] = []

    async with httpx.AsyncClient(
        verify=False,
        timeout=_DEFAULT_TIMEOUT,
        follow_redirects=True,
        limits=httpx.Limits(
            max_connections=request_concurrency,
            max_keepalive_connections=request_concurrency,
        ),
    ) as client:
        async with heartbeat("graphql_checks", "Running GraphQL checks"):
            tasks = [
                _run_checks_for_url(url, client, semaphore)
                for url in alive_urls
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if isinstance(res, list):
            findings.extend(res)

    return _dedup_findings(findings)
