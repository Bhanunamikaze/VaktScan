"""
VaktScan default-credential confirmation module.

Turns "admin panel detected" (INFO) into "confirmed default credentials"
(CRITICAL) for a small set of well-known web admin panels. This extends the
default-credential coverage that already lives in other modules
(``modules/cpanel.py`` WHM root probe, ``modules/service_recon.py`` MinIO /
database / ActiveMQ / Tomcat probes) to the common web-admin surface reached
over ``alive_urls``.

Panels covered (bounded - a few creds each, to avoid account lockouts):

* **Apache Tomcat Manager** (``/manager/html`` Basic-Auth) - ``tomcat/tomcat``,
  ``admin/admin``. Confirmed via HTTP 200 + Tomcat Manager HTML.
* **Jenkins** - anonymous Groovy script console (RCE) and a weak
  ``admin/admin`` form login confirmed via ``/whoAmI/api/json``.
* **Grafana** - ``admin/admin`` login confirmed via the ``/api/user`` API
  returning an authenticated session.
* **Generic HTTP Basic-Auth realms** - ``admin/admin``, ``admin/password``,
  confirmed via a ``401 → non-401`` transition where a random credential is
  still rejected.

Design contract (mirrors ``modules/cpanel.py`` + ``modules/service_recon.py``):
a finding is emitted **only when access is CONFIRMED via a response oracle** -
never on a bare 200 to a login page. Every check first establishes that the
service is present *and* that a bogus / random credential is rejected, so a
server that answers 200 (or "authenticated") to everything cannot produce a
false positive. Findings are canonical VaktScan dicts (``modules/schema.py``
``normalize_finding``); the working credential pair is named in ``details`` for
the operator, but is never stored in a dedicated secret field.

Entry point::

    async def check_default_credentials(
        alive_urls: list[str], output_dir: str, concurrency: int = 10,
    ) -> list[dict]
"""

from __future__ import annotations

import asyncio
import secrets
from urllib.parse import urlparse

import httpx

from modules.progress import DashboardProgress
from modules.schema import normalize_finding

MODULE_NAME = "DefaultCreds"

_TIMEOUT = httpx.Timeout(8.0, connect=8.0)

# ─── Bounded default-credential sets (a few per service, to avoid lockouts) ────

TOMCAT_CREDS = (("tomcat", "tomcat"), ("admin", "admin"))
GRAFANA_CREDS = (("admin", "admin"),)
JENKINS_CREDS = (("admin", "admin"),)
BASIC_CREDS = (("admin", "admin"), ("admin", "password"))


# ─── Small HTTP helpers (never raise; mirror cpanel._safe_get) ────────────────

async def _safe_get(client: httpx.AsyncClient, url: str, **kwargs):
    try:
        return await client.get(url, **kwargs)
    except Exception:
        return None


async def _safe_post(client: httpx.AsyncClient, url: str, **kwargs):
    try:
        return await client.post(url, **kwargs)
    except Exception:
        return None


def _origin(url: str) -> str:
    """Return ``scheme://host:port`` with no trailing slash."""
    p = urlparse(url)
    scheme = p.scheme or "http"
    host = p.hostname or url
    port = p.port or (443 if scheme == "https" else 80)
    return f"{scheme}://{host}:{port}"


def _bogus_creds() -> tuple[str, str]:
    """A random credential pair that no real panel should ever accept."""
    return ("vakt_" + secrets.token_hex(6), secrets.token_hex(8))


def _finding(
    *,
    status: str,
    severity: str,
    vulnerability: str,
    details: str,
    url: str,
    payload_url: str | None = None,
    http_status="N/A",
    service_version: str = "N/A",
) -> dict:
    """Build a canonical finding (all 15 keys guaranteed by normalize_finding)."""
    p = urlparse(url)
    host = p.hostname or url
    port = p.port or (443 if p.scheme == "https" else 80)
    return normalize_finding({
        "status": status,
        "severity": severity,
        "vulnerability": vulnerability,
        "target": host,
        "resolved_ip": "N/A",
        "port": port,
        "url": url,
        "payload_url": payload_url or url,
        "module": MODULE_NAME,
        "service_version": service_version,
        "details": details,
        "http_status": str(http_status),
    })


# ─── Body / response oracles ──────────────────────────────────────────────────

def _looks_like_tomcat_manager(resp) -> bool:
    """True only when the body is the actual Tomcat Manager application UI."""
    if resp is None:
        return False
    body = (getattr(resp, "text", "") or "").lower()
    if "tomcat web application manager" in body:
        return True
    if "manager" in body and "tomcat" in body and (
        "list applications" in body or "undeploy" in body or "/manager/html/deploy" in body
    ):
        return True
    return False


def _tomcat_present(resp) -> bool:
    """Detect Tomcat behind /manager/html via the Basic-Auth challenge / banner."""
    if resp is None:
        return False
    www = (resp.headers.get("www-authenticate", "") or "").lower()
    server = (resp.headers.get("server", "") or "").lower()
    if resp.status_code == 401 and "basic" in www and (
        "tomcat" in www or "manager" in www
    ):
        return True
    if "coyote" in server or "apache-tomcat" in server:
        return True
    return False


def _jenkins_present(resp) -> bool:
    if resp is None:
        return False
    # X-Jenkins response header is the strongest, near-unspoofable signal.
    for key in resp.headers:
        if key.lower() in ("x-jenkins", "x-jenkins-session", "x-hudson"):
            return True
    body = (getattr(resp, "text", "") or "").lower()
    return "jenkins" in body and ("dashboard" in body or "/static/" in body or "hudson" in body)


def _looks_like_groovy_console(resp) -> bool:
    if resp is None:
        return False
    body = (getattr(resp, "text", "") or "").lower()
    if "script console" in body and "groovy" in body:
        return True
    if "groovy" in body and ("system.getproperty" in body or "println" in body):
        return True
    return False


def _grafana_present(resp) -> bool:
    if resp is None:
        return False
    if resp.status_code not in (200, 302):
        return False
    body = (getattr(resp, "text", "") or "").lower()
    return "grafana" in body


def _looks_like_grafana_user(resp) -> bool:
    """True when /api/user returns an authenticated Grafana user object."""
    if resp is None or resp.status_code != 200:
        return False
    try:
        data = resp.json()
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    return "login" in data and ("email" in data or "isGrafanaAdmin" in data)


# ─── Check: Apache Tomcat Manager ─────────────────────────────────────────────

async def check_tomcat_manager(url: str, client: httpx.AsyncClient) -> list[dict]:
    """Confirm default Tomcat Manager credentials (tomcat/tomcat, admin/admin)."""
    out: list[dict] = []
    mgr_url = _origin(url) + "/manager/html"

    # Baseline with a random credential. If Tomcat is not here, or if the
    # endpoint hands back the manager UI to *any* credential, we cannot claim
    # a default-credential finding - bail (false-positive guard).
    r_base = await _safe_get(client, mgr_url, auth=_bogus_creds())
    if not _tomcat_present(r_base):
        return out
    if _looks_like_tomcat_manager(r_base):
        return out  # accepts arbitrary creds → not a default-cred confirmation

    for user, pw in TOMCAT_CREDS:
        r = await _safe_get(client, mgr_url, auth=(user, pw))
        if r is None or r.status_code != 200:
            continue
        if _looks_like_tomcat_manager(r):
            out.append(_finding(
                status="CRITICAL",
                severity="CRITICAL",
                vulnerability="Apache Tomcat Manager Default Credentials",
                details=(
                    f"Tomcat Manager at {mgr_url} is accessible with default "
                    f"credentials {user}:{pw} (HTTP 200, Manager UI confirmed). "
                    f"WAR upload / remote code execution is possible."
                ),
                url=url,
                payload_url=mgr_url,
                http_status=r.status_code,
            ))
            break
    return out


# ─── Check: Jenkins ───────────────────────────────────────────────────────────

async def check_jenkins(url: str, client: httpx.AsyncClient) -> list[dict]:
    """Confirm anonymous Jenkins script-console access and weak admin login."""
    out: list[dict] = []
    origin = _origin(url)

    r_root = await _safe_get(client, origin + "/")
    if not _jenkins_present(r_root):
        return out

    # 1) Anonymous Groovy script console → unauthenticated RCE. A secured
    #    Jenkins answers /script with 403 or a login page, not the console.
    script_url = origin + "/script"
    r_script = await _safe_get(client, script_url)
    if r_script is not None and r_script.status_code == 200 and _looks_like_groovy_console(r_script):
        out.append(_finding(
            status="CRITICAL",
            severity="CRITICAL",
            vulnerability="Jenkins Script Console Accessible (Anonymous)",
            details=(
                f"Jenkins Groovy script console at {script_url} is reachable "
                f"without authentication - arbitrary code execution as the "
                f"Jenkins process."
            ),
            url=url,
            payload_url=script_url,
            http_status=r_script.status_code,
        ))

    # 2) Weak admin login, confirmed via /whoAmI/api/json. Establish the
    #    anonymous baseline first: if it already reports an authenticated
    #    admin, the endpoint is not login-gated (false-positive guard).
    whoami_url = origin + "/whoAmI/api/json"
    r_anon = await _safe_get(client, whoami_url)
    if _whoami_authenticated_as(r_anon, None):
        return out  # already "authenticated" without creds → not gated

    login_url = origin + "/j_spring_security_check"

    # NEGATIVE CONTROL: a deliberately-wrong credential must NOT yield an
    # authenticated session via the same oracle. If it does, /whoAmI is a
    # catch-all and the oracle is unreliable → suppress everything.
    bogus_user, bogus_pw = _bogus_creds()
    r_bogus_login = await _safe_post(client, login_url, data={
        "j_username": bogus_user,
        "j_password": bogus_pw,
        "from": "/",
        "Submit": "Sign in",
    })
    if r_bogus_login is not None:
        r_bogus_who = await _safe_get(
            client, whoami_url, cookies=getattr(r_bogus_login, "cookies", None))
        if _whoami_authenticated_as(r_bogus_who, None):
            return out  # wrong creds "authenticate" → oracle unreliable

    for user, pw in JENKINS_CREDS:
        r_login = await _safe_post(client, login_url, data={
            "j_username": user,
            "j_password": pw,
            "from": "/",
            "Submit": "Sign in",
        })
        if r_login is None:
            continue
        cookies = getattr(r_login, "cookies", None)
        r_who = await _safe_get(client, whoami_url, cookies=cookies)
        if _whoami_authenticated_as(r_who, user):
            out.append(_finding(
                status="CRITICAL",
                severity="CRITICAL",
                vulnerability="Jenkins Weak Admin Credentials",
                details=(
                    f"Jenkins form login at {login_url} succeeded with weak "
                    f"credentials {user}:{pw}; /whoAmI confirms an authenticated "
                    f"session. Full Jenkins control (jobs, credentials, RCE)."
                ),
                url=url,
                payload_url=login_url,
                http_status=r_login.status_code,
            ))
            break
    return out


def _whoami_authenticated_as(resp, user) -> bool:
    """
    Interpret /whoAmI/api/json.

    ``user is None`` → return True if the response already looks like a logged-in
    (non-anonymous) session (used for the anonymous-baseline guard).
    ``user`` set → return True only if authenticated as exactly ``user``.
    """
    if resp is None or resp.status_code != 200:
        return False
    try:
        data = resp.json()
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    name = str(data.get("name", "")).lower()
    authenticated = bool(data.get("authenticated"))
    if not authenticated or not name or name == "anonymous":
        return False
    if user is None:
        return True
    return name == user.lower()


# ─── Check: Grafana ───────────────────────────────────────────────────────────

async def check_grafana(url: str, client: httpx.AsyncClient) -> list[dict]:
    """Confirm default Grafana admin/admin via the /api/user oracle."""
    out: list[dict] = []
    origin = _origin(url)

    # Presence: the Grafana login page identifies itself in the body.
    r_login_page = await _safe_get(client, origin + "/login")
    if not _grafana_present(r_login_page):
        return out

    # Negative control 1: /api/user must NOT already return an authenticated
    # user without logging in (that would be anonymous access, not a
    # default-credential confirmation).
    api_user_url = origin + "/api/user"
    r_unauth = await _safe_get(client, api_user_url)
    if _looks_like_grafana_user(r_unauth):
        return out

    # Negative control 2: a deliberately-wrong credential must NOT produce an
    # authenticated /api/user session via the same oracle. If it does, the
    # endpoint accepts any session → oracle unreliable → suppress.
    bogus_user, bogus_pw = _bogus_creds()
    r_bogus_login = await _safe_post(client, origin + "/login", json={
        "user": bogus_user,
        "password": bogus_pw,
    })
    if r_bogus_login is not None:
        r_bogus_user = await _safe_get(
            client, api_user_url, cookies=getattr(r_bogus_login, "cookies", None))
        if _looks_like_grafana_user(r_bogus_user):
            return out

    for user, pw in GRAFANA_CREDS:
        r_login = await _safe_post(client, origin + "/login", json={
            "user": user,
            "password": pw,
        })
        if r_login is None:
            continue
        cookies = getattr(r_login, "cookies", None)
        r_user = await _safe_get(client, api_user_url, cookies=cookies)
        if _looks_like_grafana_user(r_user):
            try:
                login_name = r_user.json().get("login", user)
            except Exception:
                login_name = user
            out.append(_finding(
                status="CRITICAL",
                severity="CRITICAL",
                vulnerability="Grafana Default Admin Credentials",
                details=(
                    f"Grafana admin login at {origin}/login succeeded with "
                    f"default credentials {user}:{pw}; /api/user confirms an "
                    f"authenticated session (login={login_name}). Full Grafana "
                    f"admin access."
                ),
                url=url,
                payload_url=origin + "/login",
                http_status=r_login.status_code,
            ))
            break
    return out


# ─── Check: generic HTTP Basic-Auth realm ─────────────────────────────────────

async def check_basic_auth(url: str, client: httpx.AsyncClient) -> list[dict]:
    """Confirm weak/default creds on a generic HTTP Basic-Auth realm."""
    out: list[dict] = []

    # The resource must actually challenge with Basic auth.
    r_no = await _safe_get(client, url)
    if r_no is None or r_no.status_code != 401:
        return out
    www = (r_no.headers.get("www-authenticate", "") or "")
    if "basic" not in www.lower():
        return out

    # NEGATIVE CONTROL: a random credential must stay 401. If it does not,
    # the server is not gating on credentials (catch-all / always-200) → drop.
    r_bogus = await _safe_get(client, url, auth=_bogus_creds())
    if r_bogus is None or r_bogus.status_code != 401:
        return out

    challenge_body = r_no.text or ""
    realm = _parse_realm(www)
    for user, pw in BASIC_CREDS:
        r = await _safe_get(client, url, auth=(user, pw))
        if r is None:
            continue
        body = r.text or ""
        # POSITIVE ORACLE: authenticated access must return real protected
        # content - a 2xx whose body actually DIFFERS from the 401 challenge
        # (and from the wrong-credential response). A redirect to a login page,
        # an unchanged challenge, or a catch-all 200 cannot satisfy this.
        if not (200 <= r.status_code < 300):
            continue
        if body == challenge_body or body == (r_bogus.text or ""):
            continue
        out.append(_finding(
            status="VULNERABLE",
            severity="HIGH",
            vulnerability="HTTP Basic-Auth Default/Weak Credentials",
            details=(
                f'HTTP Basic authentication realm "{realm}" at {url} accepts '
                f"weak credentials {user}:{pw} (HTTP {r.status_code} with "
                f"protected content that differs from the 401 challenge; "
                f"random credentials still rejected)."
            ),
            url=url,
            payload_url=url,
            http_status=r.status_code,
        ))
        break
    return out


def _parse_realm(www_authenticate: str) -> str:
    import re
    m = re.search(r'realm="?([^"]+)"?', www_authenticate, re.IGNORECASE)
    return m.group(1).strip() if m else "unknown"


# ─── Per-URL fan-out ──────────────────────────────────────────────────────────

_ALL_CHECKS = (
    check_tomcat_manager,
    check_jenkins,
    check_grafana,
    check_basic_auth,
)


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
            # A per-check exception is caught here and skipped - a single bad
            # host can never crash the whole run.
        return findings


def _dedup(findings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for f in findings:
        key = (f.get("vulnerability", ""), f.get("payload_url", ""), f.get("target", ""))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


# ─── Public entry point ───────────────────────────────────────────────────────

async def check_default_credentials(
    alive_urls: list[str],
    output_dir: str,
    concurrency: int = 10,
) -> list[dict]:
    """
    Attempt a small, bounded default-credential set against known web admin
    panels on the provided alive URLs, emitting a finding only when access is
    confirmed by a response oracle.

    Args:
        alive_urls:  URLs confirmed alive by httpx (post panel-detection).
        output_dir:  Reserved for parity with other modules (no files written).
        concurrency: Maximum number of concurrent per-URL tasks.

    Returns:
        Deduplicated list of canonical VaktScan finding dicts. Returns ``[]`` on
        empty input; never raises (per-host errors are caught and skipped).
    """
    if not alive_urls:
        return []

    urls = sorted({u for u in alive_urls if u})
    if not urls:
        return []

    semaphore = asyncio.Semaphore(max(1, concurrency))
    findings: list[dict] = []

    async with httpx.AsyncClient(
        verify=False,
        timeout=_TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": "VaktScan/1.0 default-creds"},
    ) as client:
        prog = DashboardProgress("default_creds", total=len(urls), noun="URLs")
        tasks = [
            prog.wrap(_run_checks_for_url(u, client, semaphore))
            for u in urls
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if isinstance(res, list):
            findings.extend(res)
        # A per-host exception surfaces here as a non-list result → skipped.

    return _dedup(findings)
