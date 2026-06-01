"""
VaktScan Jenkins Module — ported and improved from JenkinsVulnFinder
(https://github.com/Bhanunamikaze/JenkinsVulnFinder)

Checks: anonymous access, script console RCE, stored credentials, plugin enum,
build node enum, auth type fingerprint, unauthenticated endpoint sweep,
CVE-2024-23897 CLI file read, default credential spray, signup enabled,
CSRF protection, job/queue visibility, log/audit access.
"""

import asyncio
from datetime import datetime

import httpx

MODULE_NAME = 'Jenkins'

DEFAULT_CREDS = [
    ('admin', 'admin'),
    ('admin', 'jenkins'),
    ('admin', 'password'),
    ('jenkins', 'jenkins'),
    ('jenkins', 'password'),
    ('admin', '123456'),
    ('root', 'root'),
]

UNAUTH_ENDPOINTS = [
    '/api/json',
    '/computer/api/json',
    '/credentials/api/json',
    '/log/all',
    '/pluginManager/api/json',
    '/queue/api/json',
    '/whoAmI/api/json',
    '/overallLoad/api/json',
    '/updateCenter/api/json',
    '/env-vars.html',
    '/script',
    '/signup',
    '/cli',
    '/me/api/json',
    '/crumbIssuer/api/json',
]


def _finding(status, severity, vulnerability, details, target, resolved_ip, port,
             url='', payload_url='', service_version='',
             http_status='N/A', page_title='N/A', content_length='N/A'):
    return {
        'status': status,
        'vulnerability': vulnerability,
        'target': target,
        'resolved_ip': resolved_ip,
        'port': port,
        'url': url or f'http://{target}:{port}',
        'payload_url': payload_url or url or f'http://{target}:{port}',
        'module': MODULE_NAME,
        'service_version': service_version,
        'severity': severity,
        'details': details,
        'http_status': str(http_status),
        'page_title': page_title,
        'content_length': str(content_length),
        'timestamp': datetime.utcnow().isoformat() + 'Z',
    }


async def _detect_protocol(host, port, timeout=5):
    for scheme in ('https', 'http'):
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as c:
                r = await c.get(f'{scheme}://{host}:{port}/')
                if r.status_code < 600:
                    return scheme
        except Exception:
            continue
    return 'http'


async def get_jenkins_version(client, origin):
    try:
        r = await client.get(f'{origin}/')
        version = r.headers.get('X-Jenkins', '')
        return version or None
    except Exception:
        return None


async def detect_auth_type(client, origin):
    """Fingerprint auth mechanism via redirect behaviour on commenceLogin."""
    try:
        r = await client.get(f'{origin}/securityRealm/commenceLogin?from=%2F',
                             follow_redirects=False)
        if r.status_code == 404:
            return 'Matrix-Based Authorization'
        if r.status_code == 302:
            loc = r.headers.get('location', '').lower()
            if 'microsoft' in loc or 'login.microsoftonline' in loc:
                return 'Microsoft OAuth'
            if 'google' in loc or 'accounts.google' in loc:
                return 'Google OAuth'
            return 'OAuth/SSO'
        if r.status_code == 200:
            return 'RBAC or Form Login'
        return 'Unknown'
    except Exception:
        return 'Unknown'


async def check_anonymous_access(client, origin):
    try:
        r = await client.get(f'{origin}/api/json')
        return r.status_code == 200 and ('jobs' in r.text or 'views' in r.text)
    except Exception:
        return False


async def check_script_console(client, origin):
    try:
        r = await client.get(f'{origin}/script')
        return r.status_code == 200 and ('groovy' in r.text.lower() or 'script console' in r.text.lower())
    except Exception:
        return False


async def check_stored_credentials(client, origin):
    try:
        r = await client.get(f'{origin}/credentials/store/system/domain/_/api/json?depth=1')
        if r.status_code == 200:
            creds = r.json().get('credentials', [])
            return [(c.get('displayName', '?'), c.get('id', '?')) for c in creds]
    except Exception:
        pass
    return []


async def check_plugins(client, origin):
    try:
        r = await client.get(f'{origin}/pluginManager/api/json?depth=1')
        if r.status_code == 200:
            return r.json().get('plugins', [])
    except Exception:
        pass
    return []


async def check_nodes(client, origin):
    try:
        r = await client.get(f'{origin}/computer/api/json')
        if r.status_code == 200:
            return r.json().get('computer', [])
    except Exception:
        pass
    return []


async def check_job_visibility(client, origin):
    try:
        r = await client.get(f'{origin}/api/json?tree=jobs[name,url,color]')
        if r.status_code == 200:
            return r.json().get('jobs', [])
    except Exception:
        pass
    return []


async def check_queue(client, origin):
    try:
        r = await client.get(f'{origin}/queue/api/json')
        if r.status_code == 200:
            return r.json().get('items', [])
    except Exception:
        pass
    return []


async def check_csrf(client, origin):
    try:
        r = await client.get(f'{origin}/crumbIssuer/api/json')
        return r.status_code == 200
    except Exception:
        return False


async def check_signup(client, origin):
    try:
        r = await client.get(f'{origin}/signup')
        return r.status_code == 200 and 'sign' in r.text.lower()
    except Exception:
        return False


async def check_log_access(client, origin):
    try:
        r = await client.get(f'{origin}/log/all')
        return r.status_code == 200 and len(r.text) > 200
    except Exception:
        return False


async def check_unauthenticated_endpoints(client, origin):
    accessible = []
    tasks = []
    for ep in UNAUTH_ENDPOINTS:
        tasks.append(client.get(f'{origin}{ep}'))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for ep, r in zip(UNAUTH_ENDPOINTS, results):
        if isinstance(r, Exception):
            continue
        if r.status_code == 200:
            accessible.append(ep)
    return accessible


async def check_cve_2024_23897(client, origin):
    """
    CVE-2024-23897 — Jenkins CLI arbitrary file read.
    Detects by checking X-Jenkins / X-Instance-Identity headers on /cli endpoint.
    """
    for path in ('/cli', '/jenkins/cli'):
        try:
            r = await client.get(f'{origin}{path}')
            has_jenkins_header = (
                'X-Jenkins' in r.headers or
                'X-Instance-Identity' in r.headers or
                'jenkins' in r.headers.get('X-Hudson', '').lower()
            )
            if has_jenkins_header or (r.status_code == 200 and 'jenkins' in r.text.lower()):
                return True, path
        except Exception:
            continue
    return False, None


async def spray_default_creds(origin):
    """Try common default credentials via HTTP Basic Auth."""
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        for user, password in DEFAULT_CREDS:
            try:
                r = await client.get(f'{origin}/api/json', auth=(user, password))
                if r.status_code == 200 and ('jobs' in r.text or 'views' in r.text):
                    return user, password
            except Exception:
                continue
    return None, None


async def run_scans(target_obj, port, **_):
    host = target_obj['scan_address']
    resolved_ip = target_obj.get('resolved_ip', host)
    display = target_obj.get('display_target', host)
    findings = []

    protocol = await _detect_protocol(host, port)
    origin = f'{protocol}://{host}:{port}'

    async with httpx.AsyncClient(
        timeout=10, verify=False, follow_redirects=True,
        headers={'User-Agent': 'Mozilla/5.0 VaktScan'}
    ) as client:
        # ── Identity check ────────────────────────────────────────────────
        version = await get_jenkins_version(client, origin)
        if not version:
            # Double-check: look for Jenkins in body
            try:
                r = await client.get(f'{origin}/')
                if 'jenkins' not in r.text.lower() and 'hudson' not in r.text.lower():
                    return []
            except Exception:
                return []

        svc_version = f'Jenkins {version}' if version else 'Jenkins (version unknown)'
        auth_type = await detect_auth_type(client, origin)

        findings.append(_finding(
            'INFO', 'INFO', 'Jenkins Instance Detected',
            f'Jenkins identified. Version: {version or "unknown"}. Auth type: {auth_type}.',
            display, resolved_ip, port,
            url=f'{origin}/', service_version=svc_version,
        ))

        # ── Anonymous access ──────────────────────────────────────────────
        anon = await check_anonymous_access(client, origin)
        if anon:
            findings.append(_finding(
                'VULNERABLE', 'HIGH', 'Jenkins Anonymous Access Enabled',
                f'Jenkins API accessible without credentials at {origin}/api/json. '
                f'Exposes job list, build history, and system info to unauthenticated users.',
                display, resolved_ip, port,
                url=f'{origin}/api/json', service_version=svc_version,
            ))

        # ── Script console ────────────────────────────────────────────────
        script = await check_script_console(client, origin)
        if script:
            findings.append(_finding(
                'VULNERABLE', 'CRITICAL', 'Jenkins Script Console Exposed (RCE)',
                f'Groovy script console accessible at {origin}/script without authentication. '
                f'Allows arbitrary code execution on the Jenkins server.',
                display, resolved_ip, port,
                url=f'{origin}/script', service_version=svc_version,
            ))

        # ── CVE-2024-23897 ────────────────────────────────────────────────
        cli_vuln, cli_path = await check_cve_2024_23897(client, origin)
        if cli_vuln:
            findings.append(_finding(
                'VULNERABLE', 'CRITICAL',
                'CVE-2024-23897 — Jenkins CLI Arbitrary File Read',
                f'Jenkins CLI endpoint reachable at {origin}{cli_path}. '
                f'CVE-2024-23897 allows unauthenticated arbitrary file read via the Jenkins CLI '
                f'remoting protocol (affects Jenkins < 2.442, LTS < 2.426.3).',
                display, resolved_ip, port,
                url=f'{origin}{cli_path}', service_version=svc_version,
            ))

        # ── Stored credentials ────────────────────────────────────────────
        creds = await check_stored_credentials(client, origin)
        if creds:
            cred_list = ', '.join(f'{name} (ID: {cid})' for name, cid in creds[:10])
            findings.append(_finding(
                'VULNERABLE', 'CRITICAL', 'Jenkins Credential Store Accessible',
                f'{len(creds)} stored credential(s) readable without auth: {cred_list}',
                display, resolved_ip, port,
                url=f'{origin}/credentials/store/system/domain/_/api/json',
                service_version=svc_version,
            ))

        # ── Log access ────────────────────────────────────────────────────
        if await check_log_access(client, origin):
            findings.append(_finding(
                'VULNERABLE', 'MEDIUM', 'Jenkins System Log Accessible',
                f'System log at {origin}/log/all readable without authentication. '
                f'May expose internal hostnames, credentials, stack traces.',
                display, resolved_ip, port,
                url=f'{origin}/log/all', service_version=svc_version,
            ))

        # ── Job visibility ────────────────────────────────────────────────
        jobs = await check_job_visibility(client, origin)
        if jobs:
            job_names = ', '.join(j.get('name', '?') for j in jobs[:5])
            findings.append(_finding(
                'VULNERABLE', 'MEDIUM', 'Jenkins Job List Exposed',
                f'{len(jobs)} job(s) visible without authentication: {job_names}{"..." if len(jobs) > 5 else ""}. '
                f'Exposes pipeline names, SCM repos, and build history.',
                display, resolved_ip, port,
                url=f'{origin}/api/json', service_version=svc_version,
            ))

        # ── Build nodes ───────────────────────────────────────────────────
        nodes = await check_nodes(client, origin)
        if nodes:
            node_info = ', '.join(
                f'{n.get("displayName","?")} '
                f'({n.get("monitorData",{}).get("hudson.node_monitors.ArchitectureMonitor","?")})'
                for n in nodes[:5]
            )
            findings.append(_finding(
                'VULNERABLE', 'LOW', 'Jenkins Build Nodes Enumerated',
                f'{len(nodes)} build agent(s) visible without auth: {node_info}',
                display, resolved_ip, port,
                url=f'{origin}/computer/api/json', service_version=svc_version,
            ))

        # ── Signup enabled ────────────────────────────────────────────────
        if await check_signup(client, origin):
            findings.append(_finding(
                'VULNERABLE', 'HIGH', 'Jenkins Self-Registration Enabled',
                f'User signup page accessible at {origin}/signup. Anyone can create a Jenkins account.',
                display, resolved_ip, port,
                url=f'{origin}/signup', service_version=svc_version,
            ))

        # ── CSRF check ────────────────────────────────────────────────────
        if not await check_csrf(client, origin):
            findings.append(_finding(
                'POTENTIAL', 'MEDIUM', 'Jenkins CSRF Protection May Be Disabled',
                f'Crumb issuer endpoint {origin}/crumbIssuer/api/json not responding. '
                f'Jenkins may have CSRF protection disabled.',
                display, resolved_ip, port,
                url=f'{origin}/crumbIssuer/api/json', service_version=svc_version,
            ))

        # ── Unauthenticated endpoint sweep ────────────────────────────────
        open_eps = await check_unauthenticated_endpoints(client, origin)
        # Remove endpoints already covered by specific findings above
        already_reported = {'/api/json', '/script', '/log/all', '/signup',
                            '/credentials/api/json', '/cli', '/computer/api/json'}
        new_eps = [ep for ep in open_eps if ep not in already_reported]
        if new_eps:
            findings.append(_finding(
                'VULNERABLE', 'MEDIUM', 'Jenkins Unauthenticated Endpoints Accessible',
                f'{len(new_eps)} additional endpoint(s) accessible without auth: '
                f'{", ".join(new_eps[:10])}',
                display, resolved_ip, port,
                url=f'{origin}/', service_version=svc_version,
            ))

        # ── Plugin enumeration ────────────────────────────────────────────
        plugins = await check_plugins(client, origin)
        if plugins:
            outdated = [p for p in plugins if p.get('hasUpdate')]
            findings.append(_finding(
                'INFO', 'INFO', f'Jenkins Plugins Enumerated ({len(plugins)} installed)',
                f'{len(plugins)} plugin(s) visible without auth. '
                f'{len(outdated)} plugin(s) have available updates: '
                f'{", ".join(p["shortName"] for p in outdated[:10])}',
                display, resolved_ip, port,
                url=f'{origin}/pluginManager/api/json', service_version=svc_version,
            ))

        # ── HTTP (plaintext) ──────────────────────────────────────────────
        if protocol == 'http':
            findings.append(_finding(
                'VULNERABLE', 'MEDIUM', 'Jenkins Served Over Plaintext HTTP',
                f'Jenkins is accessible over unencrypted HTTP at {origin}. '
                f'Credentials and session tokens transmitted in cleartext.',
                display, resolved_ip, port,
                url=origin, service_version=svc_version,
            ))

        # ── Default credential spray ──────────────────────────────────────
        user, password = await spray_default_creds(origin)
        if user:
            findings.append(_finding(
                'VULNERABLE', 'CRITICAL', f'Jenkins Default Credentials Valid ({user}:{password})',
                f'Successfully authenticated to Jenkins with {user}:{password}. '
                f'Full administrative access may be available.',
                display, resolved_ip, port,
                url=f'{origin}/api/json', service_version=svc_version,
            ))

    for f in findings:
        f['module'] = MODULE_NAME
    return findings
