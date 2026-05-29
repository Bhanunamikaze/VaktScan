"""
web_checks.py — Web-layer security checks for VaktScan.

Entry point:
    async def run_checks(alive_urls: list[str], concurrency: int = 20) -> list[dict]

All findings use the canonical VaktScan finding schema:
    status, vulnerability, target, resolved_ip, port, url, payload_url,
    module, service_version, severity, details, http_status, page_title,
    content_length
"""

from __future__ import annotations

import asyncio
import datetime
import re
import socket
import ssl
from urllib.parse import urlparse

import httpx

MODULE_NAME = "WebChecks"
_DEFAULT_TIMEOUT = 8.0

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _origin(url: str) -> str:
    """Return scheme://host:port with no trailing slash."""
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
        "resolved_ip":     "",           # filled in lazily; callers may patch
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
    }


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        return m.group(1).strip()[:200]
    return "N/A"


def _is_error_page(body: str, status: int) -> bool:
    """Heuristic: treat as error/non-content page."""
    if status >= 400:
        return True
    if len(body) < 50:
        return True
    lower = body[:2048].lower()
    for marker in ("not found", "404", "error", "forbidden", "access denied"):
        if marker in lower:
            return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Check 1 — HTTP Security Headers
# ──────────────────────────────────────────────────────────────────────────────

_VERSION_RE = re.compile(r"[\d]+\.[\d]+", re.I)

async def check_security_headers(url: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []
    try:
        resp = await client.get(url)
    except Exception:
        return findings

    h = {k.lower(): v for k, v in resp.headers.items()}
    parsed = urlparse(url)
    is_https = parsed.scheme == "https"
    title = _extract_title(resp.text)
    http_status = str(resp.status_code)
    cl = str(len(resp.content))

    base = dict(url=url, payload_url=url, http_status=http_status,
                page_title=title, content_length=cl)

    # Missing HSTS (HTTPS only)
    if is_https and "strict-transport-security" not in h:
        findings.append(_make_finding(
            **base,
            vulnerability="Missing Strict-Transport-Security Header",
            status="VULNERABLE",
            severity="HIGH",
            details=(
                "The HTTPS response does not include a Strict-Transport-Security (HSTS) header. "
                "Without HSTS, browsers will not enforce HTTPS for subsequent visits, leaving "
                "users vulnerable to SSL-stripping and downgrade attacks."
            ),
        ))

    # Missing X-Frame-Options AND CSP (clickjacking)
    if "x-frame-options" not in h and "content-security-policy" not in h:
        findings.append(_make_finding(
            **base,
            vulnerability="Missing Clickjacking Protection (X-Frame-Options / CSP)",
            status="VULNERABLE",
            severity="MEDIUM",
            details=(
                "Neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive "
                "is present. The page can be embedded in an attacker-controlled iframe, enabling "
                "clickjacking attacks that trick users into performing unintended actions."
            ),
        ))

    # Missing X-Content-Type-Options
    if "x-content-type-options" not in h:
        findings.append(_make_finding(
            **base,
            vulnerability="Missing X-Content-Type-Options Header",
            status="INFO",
            severity="LOW",
            details=(
                "The X-Content-Type-Options: nosniff header is absent. Browsers may MIME-sniff "
                "responses, potentially executing scripts embedded in non-script responses."
            ),
        ))

    # Missing Referrer-Policy
    if "referrer-policy" not in h:
        findings.append(_make_finding(
            **base,
            vulnerability="Missing Referrer-Policy Header",
            status="INFO",
            severity="LOW",
            details=(
                "The Referrer-Policy header is not set. Full Referer URLs (which may contain "
                "sensitive path/query parameters) will be leaked to third-party origins."
            ),
        ))

    # Server header disclosing version
    server = h.get("server", "")
    if server and _VERSION_RE.search(server):
        findings.append(_make_finding(
            **base,
            vulnerability="Server Header Discloses Version",
            status="VULNERABLE",
            severity="LOW",
            details=(
                f"The Server response header discloses software version information: '{server}'. "
                "This assists attackers in targeting known CVEs for the identified version."
            ),
            service_version=server,
        ))

    # X-Powered-By disclosing tech stack
    xpb = h.get("x-powered-by", "")
    if xpb:
        findings.append(_make_finding(
            **base,
            vulnerability="X-Powered-By Header Discloses Technology",
            status="INFO",
            severity="LOW",
            details=(
                f"The X-Powered-By header reveals the server-side technology stack: '{xpb}'. "
                "This information aids fingerprinting and targeted exploit selection."
            ),
            service_version=xpb,
        ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Check 2 — Exposed Sensitive Files
# ──────────────────────────────────────────────────────────────────────────────

# (path, severity_if_found, label)
_SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    ("/.git/HEAD",             "CRITICAL", "Git Repository Exposed (.git/HEAD)"),
    ("/.git/config",           "CRITICAL", "Git Repository Exposed (.git/config)"),
    ("/.env",                  "CRITICAL", "Environment File Exposed (.env)"),
    ("/.env.local",            "CRITICAL", "Environment File Exposed (.env.local)"),
    ("/.env.production",       "CRITICAL", "Environment File Exposed (.env.production)"),
    ("/.env.backup",           "CRITICAL", "Environment File Exposed (.env.backup)"),
    ("/phpinfo.php",           "HIGH",     "PHP Info Page Exposed"),
    ("/info.php",              "HIGH",     "PHP Info Page Exposed"),
    ("/test.php",              "HIGH",     "PHP Test Page Exposed"),
    ("/wp-config.php",         "CRITICAL", "WordPress Config Exposed (wp-config.php)"),
    ("/config.php",            "HIGH",     "Config File Exposed"),
    ("/configuration.php",     "HIGH",     "Config File Exposed"),
    ("/database.yml",          "CRITICAL", "Database Credentials File Exposed"),
    ("/secrets.yml",           "CRITICAL", "Secrets File Exposed"),
    ("/credentials.yml",       "CRITICAL", "Credentials File Exposed"),
    ("/backup.zip",            "HIGH",     "Backup Archive Exposed"),
    ("/backup.tar.gz",         "HIGH",     "Backup Archive Exposed"),
    ("/www.zip",               "HIGH",     "Site Archive Exposed"),
    ("/site.zip",              "HIGH",     "Site Archive Exposed"),
    ("/robots.txt",            "INFO",     "robots.txt Accessible"),
    ("/.well-known/security.txt", "INFO",  "security.txt Accessible"),
    ("/crossdomain.xml",       "MEDIUM",   "crossdomain.xml Accessible"),
    ("/adminer.php",           "CRITICAL", "Adminer Database UI Exposed"),
    ("/adminer",               "CRITICAL", "Adminer Database UI Exposed"),
    ("/phpMyAdmin/",           "HIGH",     "phpMyAdmin Exposed"),
    ("/phpmyadmin/",           "HIGH",     "phpMyAdmin Exposed"),
    ("/admin/",                "INFO",     "Admin Panel Detected"),
    ("/administrator/",        "INFO",     "Admin Panel Detected"),
    ("/wp-admin/",             "INFO",     "WordPress Admin Panel Detected"),
]

_SEVERITY_TO_STATUS = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "VULNERABLE",
    "MEDIUM":   "VULNERABLE",
    "LOW":      "INFO",
    "INFO":     "INFO",
}


async def check_sensitive_files(url: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []
    origin = _origin(url)

    async def probe(path: str, severity: str, label: str):
        probe_url = origin + path
        try:
            resp = await client.get(probe_url)
        except Exception:
            return

        body = resp.text
        status_code = resp.status_code
        title = _extract_title(body)
        cl = str(len(resp.content))
        http_status = str(status_code)

        # robots.txt — INFO regardless, enumerate disallowed
        if path == "/robots.txt":
            if status_code == 200 and len(body) > 10:
                disallowed = re.findall(r"(?im)^disallow:\s*(.+)$", body)
                details = "robots.txt is publicly accessible."
                if disallowed:
                    sample = disallowed[:20]
                    details += f" Disallowed paths ({len(disallowed)} total): {', '.join(sample)}"
                findings.append(_make_finding(
                    url=url,
                    payload_url=probe_url,
                    vulnerability=label,
                    status="INFO",
                    severity="LOW",
                    details=details,
                    http_status=http_status,
                    page_title=title,
                    content_length=cl,
                ))
            return

        # security.txt — INFO, parse contact
        if path == "/.well-known/security.txt":
            if status_code == 200 and len(body) > 10:
                contact = re.findall(r"(?im)^contact:\s*(.+)$", body)
                details = "security.txt is present."
                if contact:
                    details += f" Contact: {', '.join(contact[:5])}"
                findings.append(_make_finding(
                    url=url,
                    payload_url=probe_url,
                    vulnerability=label,
                    status="INFO",
                    severity="LOW",
                    details=details,
                    http_status=http_status,
                    page_title=title,
                    content_length=cl,
                ))
            return

        # crossdomain.xml — check for wildcard
        if path == "/crossdomain.xml":
            if status_code == 200 and len(body) > 10:
                wildcard = 'domain="*"' in body or "domain='*'" in body
                details = "crossdomain.xml is accessible."
                sev = "MEDIUM"
                st = "VULNERABLE"
                if wildcard:
                    details += " WILDCARD allow-access-from detected — any domain can read responses via Flash/legacy cross-domain requests."
                    sev = "HIGH"
                else:
                    details += " No wildcard detected; review allowed domains manually."
                    st = "INFO"
                    sev = "LOW"
                findings.append(_make_finding(
                    url=url,
                    payload_url=probe_url,
                    vulnerability=label,
                    status=st,
                    severity=sev,
                    details=details,
                    http_status=http_status,
                    page_title=title,
                    content_length=cl,
                ))
            return

        # Generic sensitive file — only fire if 200 and not an error page
        if status_code == 200 and not _is_error_page(body, status_code):
            status = _SEVERITY_TO_STATUS.get(severity, "VULNERABLE")
            details_map = {
                "CRITICAL": (
                    f"The file '{path}' is publicly accessible (HTTP 200, {len(resp.content)} bytes). "
                    "This file likely contains credentials, secrets, or full source code, "
                    "enabling account takeover or full compromise."
                ),
                "HIGH": (
                    f"The file '{path}' is publicly accessible (HTTP 200, {len(resp.content)} bytes). "
                    "This exposes server configuration details or backup data that can be leveraged "
                    "for further attacks."
                ),
                "MEDIUM": (
                    f"The file '{path}' is publicly accessible (HTTP 200, {len(resp.content)} bytes). "
                    "Review the content to assess exposure risk."
                ),
                "INFO": (
                    f"The path '{path}' is accessible (HTTP 200, {len(resp.content)} bytes)."
                ),
            }
            details = details_map.get(severity, f"Path '{path}' returned HTTP {status_code}.")
            findings.append(_make_finding(
                url=url,
                payload_url=probe_url,
                vulnerability=label,
                status=status,
                severity=severity,
                details=details,
                http_status=http_status,
                page_title=title,
                content_length=cl,
            ))

    tasks = [probe(path, sev, label) for path, sev, label in _SENSITIVE_PATHS]
    await asyncio.gather(*tasks, return_exceptions=True)
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Check 3 — GraphQL Introspection
# ──────────────────────────────────────────────────────────────────────────────

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql"]
_GRAPHQL_QUERY = '{"query": "{__schema{types{name}}}"}'


async def check_graphql(url: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []
    origin = _origin(url)

    for path in _GRAPHQL_PATHS:
        probe_url = origin + path
        try:
            resp = await client.post(
                probe_url,
                content=_GRAPHQL_QUERY,
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            continue

        if resp.status_code == 200 and "__schema" in resp.text:
            findings.append(_make_finding(
                url=url,
                payload_url=probe_url,
                vulnerability="GraphQL Introspection Enabled",
                status="CRITICAL",
                severity="HIGH",
                details=(
                    f"GraphQL introspection is enabled at '{probe_url}'. An attacker can query "
                    "__schema to enumerate the full API schema — all types, fields, queries, "
                    "and mutations — enabling highly targeted attacks against the API surface."
                ),
                http_status=str(resp.status_code),
                content_length=str(len(resp.content)),
            ))
            break  # one finding per base URL is sufficient

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Check 4 — Swagger / OpenAPI Spec Exposed
# ──────────────────────────────────────────────────────────────────────────────

_SWAGGER_PATHS = [
    "/swagger.json",
    "/swagger/v2/swagger.json",
    "/api-docs",
    "/api-docs/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
]
_SWAGGER_MARKERS = ("swagger", "openapi", '"paths"', "'paths'")


async def check_swagger(url: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []
    origin = _origin(url)

    for path in _SWAGGER_PATHS:
        probe_url = origin + path
        try:
            resp = await client.get(probe_url)
        except Exception:
            continue

        if resp.status_code != 200:
            continue

        body_lower = resp.text[:4096].lower()
        if any(m.lower() in body_lower for m in _SWAGGER_MARKERS):
            findings.append(_make_finding(
                url=url,
                payload_url=probe_url,
                vulnerability="API Documentation Publicly Exposed (Swagger/OpenAPI)",
                status="VULNERABLE",
                severity="HIGH",
                details=(
                    f"An API specification document is publicly accessible at '{probe_url}'. "
                    "This reveals all API endpoints, parameters, authentication methods, and "
                    "data models, providing attackers a complete roadmap for targeted API abuse."
                ),
                http_status=str(resp.status_code),
                content_length=str(len(resp.content)),
            ))
            break  # one finding per base URL

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Check 5 — SSL Certificate Expiry
# ──────────────────────────────────────────────────────────────────────────────

def _get_cert_info(hostname: str, port: int) -> dict | None:
    """Return parsed cert dict or None on failure."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except Exception:
        return None


async def check_ssl_expiry(url: str, client: httpx.AsyncClient) -> list[dict]:  # noqa: ARG001
    findings: list[dict] = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return findings

    hostname = parsed.hostname or ""
    port = parsed.port or 443

    loop = asyncio.get_event_loop()
    cert = await loop.run_in_executor(None, _get_cert_info, hostname, port)
    if not cert:
        return findings

    # Parse notAfter
    not_after_str = cert.get("notAfter", "")
    try:
        not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        not_after = not_after.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        return findings

    now = datetime.datetime.now(datetime.timezone.utc)
    days_left = (not_after - now).days

    base = dict(url=url, payload_url=url, http_status="N/A",
                page_title="N/A", content_length="N/A")

    if days_left < 0:
        findings.append(_make_finding(
            **base,
            vulnerability="SSL Certificate Expired",
            status="CRITICAL",
            severity="CRITICAL",
            details=(
                f"The SSL certificate for '{hostname}' expired on {not_after.date()} "
                f"({abs(days_left)} day(s) ago). Browsers will display hard security errors "
                "and reject connections, making the service effectively unavailable."
            ),
        ))
    elif days_left <= 7:
        findings.append(_make_finding(
            **base,
            vulnerability="SSL Certificate Expiring Within 7 Days",
            status="CRITICAL",
            severity="CRITICAL",
            details=(
                f"The SSL certificate for '{hostname}' expires on {not_after.date()} "
                f"({days_left} day(s) remaining). Immediate renewal is required."
            ),
        ))
    elif days_left <= 30:
        findings.append(_make_finding(
            **base,
            vulnerability="SSL Certificate Expiring Within 30 Days",
            status="VULNERABLE",
            severity="HIGH",
            details=(
                f"The SSL certificate for '{hostname}' expires on {not_after.date()} "
                f"({days_left} day(s) remaining). Plan renewal soon to avoid service disruption."
            ),
        ))

    # Self-signed check
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer",  []))
    if subject == issuer:
        findings.append(_make_finding(
            **base,
            vulnerability="Self-Signed SSL Certificate",
            status="VULNERABLE",
            severity="MEDIUM",
            details=(
                f"The SSL certificate for '{hostname}' is self-signed (issuer == subject). "
                "Self-signed certificates do not provide trusted identity verification and will "
                "trigger browser warnings, undermining user trust and HTTPS security guarantees."
            ),
        ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Check 6 — Admin Panel Detection
# ──────────────────────────────────────────────────────────────────────────────

_ADMIN_PATHS = [
    "/admin", "/administrator", "/admin/login", "/admin.php",
    "/cp", "/controlpanel", "/dashboard", "/manage", "/management",
    "/backend", "/cms", "/portal",
]

_LOGIN_FORM_RE = re.compile(
    r'<form[^>]*>.*?(?:type=["\']password["\']|name=["\']password["\'])',
    re.I | re.S,
)


async def check_admin_panels(url: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []
    origin = _origin(url)

    async def probe(path: str):
        probe_url = origin + path
        try:
            resp = await client.get(probe_url)
        except Exception:
            return

        sc = resp.status_code
        if sc not in (200, 401, 403):
            return

        title = _extract_title(resp.text)
        cl = str(len(resp.content))
        base = dict(url=url, payload_url=probe_url, http_status=str(sc),
                    page_title=title, content_length=cl)

        has_login_form = bool(_LOGIN_FORM_RE.search(resp.text))

        if sc == 200 and has_login_form:
            findings.append(_make_finding(
                **base,
                vulnerability=f"Admin Panel Publicly Accessible: {path}",
                status="VULNERABLE",
                severity="HIGH",
                details=(
                    f"An admin/management login panel is directly accessible at '{probe_url}' "
                    f"(HTTP {sc}). Exposed admin panels are a primary target for credential "
                    "brute-force, credential stuffing, and authentication bypass attacks."
                ),
            ))
        elif sc in (200, 401):
            findings.append(_make_finding(
                **base,
                vulnerability=f"Admin Panel Detected: {path}",
                status="INFO",
                severity="MEDIUM",
                details=(
                    f"An admin or management interface is reachable at '{probe_url}' "
                    f"(HTTP {sc}). Verify that strong authentication is enforced and "
                    "access is restricted to authorised networks."
                ),
            ))

    await asyncio.gather(*[probe(p) for p in _ADMIN_PATHS], return_exceptions=True)
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Check 7 — Directory Listing Enabled
# ──────────────────────────────────────────────────────────────────────────────

_DIR_LISTING_PATHS = [
    "/images/", "/uploads/", "/files/", "/static/",
    "/assets/", "/backup/", "/logs/", "/tmp/",
]
_DIR_LISTING_MARKERS = ("index of", "parent directory")


async def check_directory_listing(url: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []
    origin = _origin(url)

    async def probe(path: str):
        probe_url = origin + path
        try:
            resp = await client.get(probe_url)
        except Exception:
            return

        if resp.status_code != 200:
            return

        body_lower = resp.text[:8192].lower()
        if any(m in body_lower for m in _DIR_LISTING_MARKERS):
            title = _extract_title(resp.text)
            findings.append(_make_finding(
                url=url,
                payload_url=probe_url,
                vulnerability=f"Directory Listing Enabled: {path}",
                status="VULNERABLE",
                severity="HIGH",
                details=(
                    f"Directory listing is enabled at '{probe_url}'. Attackers can enumerate "
                    "all files in the directory, potentially exposing source code, backups, "
                    "configuration files, or user-uploaded data."
                ),
                http_status=str(resp.status_code),
                page_title=title,
                content_length=str(len(resp.content)),
            ))

    await asyncio.gather(*[probe(p) for p in _DIR_LISTING_PATHS], return_exceptions=True)
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Check 8 — Default Credentials
# ──────────────────────────────────────────────────────────────────────────────

_WP_CREDS = [("admin", "admin"), ("admin", "password"), ("admin", "123456")]
_JOOMLA_CREDS = [("admin", "admin"), ("admin", "password")]
_DRUPAL_CREDS = [("admin", "admin"), ("admin", "password")]


async def _try_wp_default_creds(origin: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []
    login_url = origin + "/wp-login.php"
    try:
        # Fetch nonce/login page first
        get_resp = await client.get(login_url)
    except Exception:
        return findings

    if get_resp.status_code not in (200, 302):
        return findings

    for username, password in _WP_CREDS:
        try:
            post_resp = await client.post(
                login_url,
                data={
                    "log": username,
                    "pwd": password,
                    "wp-submit": "Log In",
                    "redirect_to": origin + "/wp-admin/",
                    "testcookie": "1",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except Exception:
            continue

        # Success indicators: redirect to /wp-admin/ or logout link present
        location = post_resp.headers.get("location", "")
        body = post_resp.text.lower()
        if (
            "wp-admin" in location
            or "dashboard" in location
            or "log-out" in body
            or "wp-admin/profile.php" in body
        ):
            findings.append(_make_finding(
                url=origin,
                payload_url=login_url,
                vulnerability="WordPress Default Credentials",
                status="CRITICAL",
                severity="CRITICAL",
                details=(
                    f"WordPress admin panel accepted default credentials "
                    f"'{username}:{password}' at '{login_url}'. "
                    "Full administrative access to the CMS is possible without any brute-force."
                ),
                http_status=str(post_resp.status_code),
            ))
            break  # no need to try more creds

    return findings


async def _try_joomla_default_creds(origin: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []
    login_url = origin + "/administrator/"
    try:
        get_resp = await client.get(login_url)
    except Exception:
        return findings

    if get_resp.status_code not in (200,):
        return findings

    # Extract CSRF token if present
    token_match = re.search(
        r'<input[^>]+name="([a-f0-9]{32})"[^>]+value="1"', get_resp.text
    )

    for username, password in _JOOMLA_CREDS:
        post_data: dict = {
            "username": username,
            "passwd": password,
            "option": "com_login",
            "task": "login",
            "return": "aW5kZXgucGhw",
        }
        if token_match:
            post_data[token_match.group(1)] = "1"

        try:
            post_resp = await client.post(
                login_url,
                data=post_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except Exception:
            continue

        body = post_resp.text.lower()
        location = post_resp.headers.get("location", "")
        if (
            "administrator/index.php" in location
            or "com_cpanel" in body
            or "logout" in body
        ):
            findings.append(_make_finding(
                url=origin,
                payload_url=login_url,
                vulnerability="Joomla Default Credentials",
                status="CRITICAL",
                severity="CRITICAL",
                details=(
                    f"Joomla administrator panel accepted default credentials "
                    f"'{username}:{password}' at '{login_url}'. "
                    "Full CMS administrative access is possible."
                ),
                http_status=str(post_resp.status_code),
            ))
            break

    return findings


async def _try_drupal_default_creds(origin: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []
    login_url = origin + "/user/login"
    try:
        get_resp = await client.get(login_url)
    except Exception:
        return findings

    if get_resp.status_code not in (200,):
        return findings

    # Extract Drupal form_build_id
    form_id_match = re.search(
        r'<input[^>]+name="form_build_id"[^>]+value="([^"]+)"', get_resp.text
    )
    form_build_id = form_id_match.group(1) if form_id_match else ""

    for username, password in _DRUPAL_CREDS:
        post_data: dict = {
            "name": username,
            "pass": password,
            "form_id": "user_login_form",
            "op": "Log in",
        }
        if form_build_id:
            post_data["form_build_id"] = form_build_id

        try:
            post_resp = await client.post(
                login_url,
                data=post_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except Exception:
            continue

        body = post_resp.text.lower()
        location = post_resp.headers.get("location", "")
        if (
            "/user/" in location
            or "admin/dashboard" in location
            or "log out" in body
            or "edit account" in body
        ):
            findings.append(_make_finding(
                url=origin,
                payload_url=login_url,
                vulnerability="Drupal Default Credentials",
                status="CRITICAL",
                severity="CRITICAL",
                details=(
                    f"Drupal login accepted default credentials "
                    f"'{username}:{password}' at '{login_url}'. "
                    "Full site administrative access is possible."
                ),
                http_status=str(post_resp.status_code),
            ))
            break

    return findings


async def check_default_creds(url: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []
    origin = _origin(url)

    # Detect app type from homepage
    try:
        home = await client.get(origin + "/")
        body = home.text.lower()
    except Exception:
        return findings

    tasks = []
    if "wp-content" in body or "wp-includes" in body or "wordpress" in body:
        tasks.append(_try_wp_default_creds(origin, client))
    if "joomla" in body or "/administrator/" in body:
        tasks.append(_try_joomla_default_creds(origin, client))
    if "drupal" in body or "drupal.js" in body or "/sites/default/" in body:
        tasks.append(_try_drupal_default_creds(origin, client))

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, list):
                findings.extend(res)

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────────────

# All check functions, keyed for dedup tracking
_ALL_CHECKS = [
    check_security_headers,
    check_sensitive_files,
    check_graphql,
    check_swagger,
    check_ssl_expiry,
    check_admin_panels,
    check_directory_listing,
    check_default_creds,
]


async def _run_checks_for_url(
    url: str,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> list[dict]:
    async with semaphore:
        tasks = [check(url, client) for check in _ALL_CHECKS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: list[dict] = []
        for res in results:
            if isinstance(res, list):
                findings.extend(res)
        return findings


def _dedup_findings(findings: list[dict]) -> list[dict]:
    """Deduplicate by (vulnerability, payload_url)."""
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
    Run all web-layer security checks against the provided alive HTTP/HTTPS URLs.

    Args:
        alive_urls:   List of URLs confirmed alive by httpx.
        concurrency:  Maximum number of concurrent URL-level tasks.

    Returns:
        Deduplicated list of finding dicts using the VaktScan canonical schema.
    """
    if not alive_urls:
        return []

    semaphore = asyncio.Semaphore(max(1, concurrency))
    findings: list[dict] = []

    async with httpx.AsyncClient(
        verify=False,
        timeout=_DEFAULT_TIMEOUT,
        follow_redirects=True,
    ) as client:
        tasks = [_run_checks_for_url(url, client, semaphore) for url in alive_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if isinstance(res, list):
            findings.extend(res)

    return _dedup_findings(findings)
