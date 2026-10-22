"""
credential_probe.py - Generic identity endpoint prober for VaktScan.

Probes 25+ common current-user / whoami / session endpoints without
authentication.  When a target returns user-identity data (email, username,
role …) to an unauthenticated request, it is flagged.  If the response also
leaks credential fields (tokens, secrets, keys), the finding is escalated to
CRITICAL.

Entry point:
    async def run_checks(alive_urls: list[str], concurrency: int = 20) -> list[dict]

All findings use the canonical VaktScan finding schema (15 keys).
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import re
from urllib.parse import urlparse

import httpx

MODULE_NAME = "CredentialProbe"
_DEFAULT_TIMEOUT = 8.0

# ──────────────────────────────────────────────────────────────────────────────
# Endpoint catalogue
# ──────────────────────────────────────────────────────────────────────────────

_IDENTITY_ENDPOINTS = [
    "/api/me",
    "/api/v1/me",
    "/api/v2/me",
    "/api/user",
    "/api/v1/user",
    "/api/v2/user",
    "/api/users/current",
    "/api/account",
    "/api/v1/account",
    "/api/profile",
    "/api/auth/session",
    "/api/session",
    "/api/identity",
    "/api/self",
    "/api/v1/auth/check",
    "/me",
    "/whoami",
    "/userinfo",
    "/oauth/userinfo",
    "/wp-json/wp/v2/users/me",
    "/.auth/me",
    "/api/v4/user",
    "/_session",
    "/session/token",
    "/_api/v1/session",
    "/users/v1",
    "/users/v1/_debug",
    "/api/users",
    "/api/v1/users",
    "/api/v2/users",
    "/api/v1/users/_debug",
    "/api/admin/users",
    "/admin/api/users",
    "/v1/users",
    "/v2/users",
    "/v1/accounts",
    "/api/v1/accounts",
    "/debug/users",
    "/internal/users",
    "/_debug/users",
    "/actuator/env",
    "/env",
    "/config",
    "/api/config",
]

# ──────────────────────────────────────────────────────────────────────────────
# Detection patterns
# ──────────────────────────────────────────────────────────────────────────────

_IDENTITY_MARKERS = re.compile(
    r'"(email|username|user_name|login|user_id|userId|role|'
    r'display_name|displayName|first_name|firstName|account_id|accountId)"',
    re.IGNORECASE,
)

_CREDENTIAL_FIELDS = re.compile(
    r'"(authentication_token|auth_token|access_token|api_key|api_token|'
    r'bearer_token|secret_key|session_token|refresh_token|private_key|'
    r'client_secret|service_token|machine_token|jwt|password_hash|'
    r'totp_secret|recovery_codes|signing_secret|webhook_secret|bot_token|'
    r'ssn|credit_card|aws_secret_access_key|database_url)'
    r'"\s*:\s*"([^"]{8,})"',
    re.IGNORECASE,
)

_SHORT_CREDENTIAL_FIELDS = re.compile(
    r'"(password|passwd|secret)"'
    r'\s*:\s*"([^"]{3,})"',
    re.IGNORECASE,
)

_NEGATIVE_CONTROL_PATH = "/_vaktscan_negative_control_7f3a"

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _origin(url: str) -> str:
    p = urlparse(url)
    port = p.port
    if port is None:
        port = 443 if p.scheme == "https" else 80
    return f"{p.scheme}://{p.hostname}:{port}"


def _body_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


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


# ──────────────────────────────────────────────────────────────────────────────
# Core check
# ──────────────────────────────────────────────────────────────────────────────

async def check_identity_endpoints(
    url: str,
    client: httpx.AsyncClient,
) -> list[dict]:
    findings: list[dict] = []
    origin = _origin(url)

    # --- negative control ---------------------------------------------------
    try:
        neg = await client.get(origin + _NEGATIVE_CONTROL_PATH)
    except Exception:
        neg = None

    neg_hash = _body_hash(neg.text) if neg else None
    neg_status = neg.status_code if neg else None

    for endpoint in _IDENTITY_ENDPOINTS:
        probe_url = origin + endpoint
        try:
            resp = await client.get(probe_url)
        except Exception:
            continue

        if resp.status_code != 200:
            continue

        body = resp.text

        # Catch-all suppression: same status + same body as negative control
        if neg_status == 200 and neg_hash and _body_hash(body) == neg_hash:
            continue

        if not _IDENTITY_MARKERS.search(body):
            continue

        cred_matches = _CREDENTIAL_FIELDS.findall(body) + _SHORT_CREDENTIAL_FIELDS.findall(body)
        cred_names = sorted({m[0] for m in cred_matches})

        if cred_names:
            findings.append(_make_finding(
                url=url,
                payload_url=probe_url,
                vulnerability=f"Unauthenticated Credential Exposure ({endpoint})",
                status="CRITICAL",
                severity="CRITICAL",
                details=(
                    f"Identity endpoint '{endpoint}' returns user data without "
                    f"authentication. Credential fields exposed: "
                    f"{', '.join(cred_names)}. Negative control confirmed "
                    f"({_NEGATIVE_CONTROL_PATH} returned "
                    f"{neg_status or 'N/A'})."
                ),
                http_status=str(resp.status_code),
                content_length=str(len(resp.content)),
            ))
        else:
            findings.append(_make_finding(
                url=url,
                payload_url=probe_url,
                vulnerability=f"Unauthenticated Identity Endpoint ({endpoint})",
                status="VULNERABLE",
                severity="HIGH",
                details=(
                    f"Identity endpoint '{endpoint}' returns user data "
                    f"(identity markers detected) without authentication, "
                    f"but no credential fields were found in the response body. "
                    f"Negative control confirmed ({_NEGATIVE_CONTROL_PATH} "
                    f"returned {neg_status or 'N/A'})."
                ),
                http_status=str(resp.status_code),
                content_length=str(len(resp.content)),
            ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Runner (mirrors web_checks.run_checks)
# ──────────────────────────────────────────────────────────────────────────────

def _dedup_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for f in findings:
        key = (f.get("vulnerability", ""), f.get("payload_url", ""), f.get("target", ""))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


async def run_checks(
    alive_urls: list[str],
    concurrency: int = 20,
) -> list[dict]:
    if not alive_urls:
        return []

    semaphore = asyncio.Semaphore(max(1, concurrency))
    findings: list[dict] = []

    async with httpx.AsyncClient(
        verify=False,
        timeout=_DEFAULT_TIMEOUT,
        follow_redirects=True,
        limits=httpx.Limits(
            max_connections=concurrency,
            max_keepalive_connections=concurrency,
        ),
    ) as client:

        async def _check(u: str) -> list[dict]:
            async with semaphore:
                return await check_identity_endpoints(u, client)

        results = await asyncio.gather(
            *[_check(u) for u in alive_urls],
            return_exceptions=True,
        )
        for res in results:
            if isinstance(res, list):
                findings.extend(res)

    return _dedup_findings(findings)
