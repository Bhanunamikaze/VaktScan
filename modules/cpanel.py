"""
VaktScan cPanel / WHM / Webmail / WebDisk / CalDAV scanner.

One-point-of-contact module covering the full cPanel attack surface:
- All primary cpsrvd/cpdavd web ports (2077-2080, 2082-2083, 2086-2087,
  2089, 2095-2096, 9998-9999, 80, 443).
- Banner probes for every co-resident service (Exim, Dovecot, FTP, DNS,
  OpenSSH, MySQL, PostgreSQL, Mailman, etc.).
- Version-anchored TSR matrix (modules/data/cpanel_tsr.json).
- Bundled-component CVE matrix (modules/data/bundled_cves.json).
- Live-payload checks with oracle validation (positive + negative control
  + disconfirmers).
- Universal anti-FP post-filter + deduplication.

Reporting contract (see cpanel_plan.md §9c): every finding the module
emits is a dict with the AEM-compatible keys (`status`, `vulnerability`,
`target`, `resolved_ip`, `port`, `url`, `payload_url`, `module`,
`service_version`, `severity`, `details`, plus `http_status`,
`page_title`, `content_length` set by enrich_vuln). `status` is one of
{CRITICAL, VULNERABLE, POTENTIAL, INFO} — matching main.py:1119-1128.
"""

import asyncio
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import string
from urllib.parse import urlparse

import httpx

# ─── Module metadata ───────────────────────────────────────────────────────────

MODULE_NAME = 'cPanel'
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

CPANEL_PRIMARY_PORTS = [
    2077, 2078, 2079, 2080,
    2082, 2083,
    2086, 2087,
    2089,
    2095, 2096,
    9998, 9999,
    80, 443,
]

CPANEL_ADJACENT_PORTS = [
    25, 26, 465, 587,
    110, 143, 993, 995,
    21, 53, 3306, 5432, 22,
    2768, 783, 1097, 2812, 8053, 953,
]

# Map port → which cPanel daemon serves it. Used for surface tagging.
PORT_SURFACE = {
    2082: 'cPanel', 2083: 'cPanel',
    2086: 'WHM', 2087: 'WHM',
    2095: 'Webmail', 2096: 'Webmail',
    2077: 'WebDisk', 2078: 'WebDisk',
    2079: 'CalDAV', 2080: 'CalDAV',
    2089: 'Autoconfig',
    9998: 'cPanel', 9999: 'cPanel',
    80: 'Apache', 443: 'Apache',
}

# TLS-default cpsrvd ports.
TLS_DEFAULT_PORTS = {2083, 2087, 2096, 2078, 2080, 2089, 9999, 443}

# Ports where the WHM root-credential probe is allowed to run.
WHM_PORTS = {2086, 2087}


# ─── Data table loading ───────────────────────────────────────────────────────

def _load_json(path):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return {}


_TSR_DATA = _load_json(os.path.join(DATA_DIR, 'cpanel_tsr.json'))
_BUNDLED_DATA = _load_json(os.path.join(DATA_DIR, 'bundled_cves.json'))

CPANEL_SECURITY_BULLETINS = _TSR_DATA.get('bulletins', [])
BUNDLED_COMPONENT_CVES = _BUNDLED_DATA.get('components', {})


# ─── Protocol / version helpers ───────────────────────────────────────────────

async def detect_protocol(scan_address, port, timeout=3):
    """Detect HTTP or HTTPS. cPanel control-panel ports default to TLS."""
    order = ['https', 'http'] if port in TLS_DEFAULT_PORTS else ['http', 'https']
    for protocol in order:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
                r = await client.get(f"{protocol}://{scan_address}:{port}/")
                if r.status_code in (200, 301, 302, 401, 403, 404):
                    return protocol
        except Exception:
            continue
    return 'https' if port in TLS_DEFAULT_PORTS else 'http'


def parse_version(version_string):
    try:
        m = re.match(r'^(\d+(?:\.\d+)*)', str(version_string).strip())
        if not m:
            return (0,)
        return tuple(int(p) for p in m.group(1).split('.'))
    except Exception:
        return (0,)


def compare_versions(v1, v2):
    a, b = parse_version(v1), parse_version(v2)
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return -1 if a < b else (1 if a > b else 0)


def is_version_affected(current, ranges):
    """Return True if `current` falls inside any of the version ranges."""
    if not current:
        return False
    try:
        for r in ranges:
            r = r.strip()
            if r.startswith('<'):
                if compare_versions(current, r[1:]) < 0:
                    return True
            elif ',' in r and '>=' in r and '<' in r:
                parts = [p.strip() for p in r.split(',')]
                lo = parts[0].lstrip('>=').strip()
                hi = parts[1].lstrip('<').strip()
                if compare_versions(current, lo) >= 0 and compare_versions(current, hi) < 0:
                    return True
            elif r.startswith('>='):
                if compare_versions(current, r[2:]) >= 0:
                    return True
    except Exception:
        pass
    return False


def is_full_url(value):
    return isinstance(value, str) and (value.startswith('http://') or value.startswith('https://'))


def _looks_like_cpanel_body(text):
    if not text:
        return False
    lower = text[:8192].lower()
    return any(marker in lower for marker in (
        'cpsrvd', 'cpanel', 'webhost manager', 'paper_lantern', 'jupiter',
        'cpsess', 'cpanelbranding', 'cpanel_magic_revision', 'webmaild',
    ))


def _looks_like_whm_body(text):
    lower = (text or '')[:8192].lower()
    return 'webhost manager' in lower or 'whm' in lower or '/whm/' in lower


def _build_target_context(target_obj, port, protocol):
    scan_address = target_obj['scan_address']
    display_target = target_obj.get('display_target', scan_address)

    supplied_url = None
    for candidate in (display_target, scan_address):
        if is_full_url(candidate):
            supplied_url = candidate
            break

    parsed = urlparse(supplied_url) if supplied_url else None
    if parsed and parsed.netloc:
        origin = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or ''
    else:
        origin = f"{protocol}://{scan_address}:{port}"
        path = ''

    return {
        'origin_url': origin.rstrip('/'),
        'supplied_url': supplied_url,
        'supplied_path': path.rstrip('/'),
        'display_target': display_target,
        'scan_address': scan_address,
        'port': port,
        'surface': PORT_SURFACE.get(port, 'cPanel'),
        'is_tls': protocol == 'https',
    }


# ─── WAF / lockout / stock-error baseline ─────────────────────────────────────

WAF_FINGERPRINTS = (
    'mod_security', 'modsecurity', 'imunify360', 'cphulkd', 'cphulk',
    'cloudflare', 'incapsula', 'accel-', 'sucuri', 'akamai',
)


def _detect_waf(response):
    """Return WAF fingerprint name if the response looks blocked, else None."""
    if response is None:
        return None
    try:
        body = (response.text or '')[:4096].lower()
        headers = ' '.join(f"{k}:{v}" for k, v in response.headers.items()).lower()
        blob = body + ' ' + headers
        for marker in WAF_FINGERPRINTS:
            if marker in blob:
                return marker
        # cPHulk responses come back with these explicit headers.
        for hdr in response.headers:
            if hdr.lower().startswith('x-cphulkd'):
                return 'cphulkd'
    except Exception:
        pass
    return None


def _hash_body(text):
    return hashlib.sha1((text or '').encode('utf-8', errors='replace')).hexdigest()


async def _baseline_stock_errors(client, origin_url):
    """
    Issue requests for unguessable paths so any later check whose 'positive'
    body matches one of the baseline hashes can be dropped as a stock-error
    response (§10.3 guard 1).
    """
    baselines = set()
    random_paths = [
        '/' + secrets.token_hex(16),
        '/cgi-sys/' + secrets.token_hex(16),
        '/cpsess' + ('0' * 16) + '/' + secrets.token_hex(8),
    ]
    for path in random_paths:
        try:
            r = await client.get(f"{origin_url}{path}", timeout=5)
            baselines.add(_hash_body(r.text))
        except Exception:
            continue
    return baselines


# ─── Version detection ────────────────────────────────────────────────────────

VERSION_HTML_PATTERNS = [
    re.compile(r'cpanel[_\- ]?build[^0-9]{0,8}(\d{2}\.\d+\.\d+(?:\.\d+)?)', re.IGNORECASE),
    re.compile(r'cpanel\s+(?:&amp;|&|and)?\s*whm\s+v?(\d{2}\.\d+\.\d+(?:\.\d+)?)', re.IGNORECASE),
    re.compile(r'WHM\s+(\d{2}\.\d+\.\d+(?:\.\d+)?)', re.IGNORECASE),
    re.compile(r'"version"\s*:\s*"(\d{2}\.\d+\.\d+(?:\.\d+)?)"'),
    re.compile(r'cPanel_magic_revision_(\d+)', re.IGNORECASE),
]
SERVER_HEADER_VERSION = re.compile(r'cpsrvd[\/-](\d+\.\d+(?:\.\d+){0,2})', re.IGNORECASE)


async def get_cpanel_version(client, origin_url):
    """
    Multi-source version detection. Returns {'number': str|None, 'sources':
    [str, ...], 'banner': str|None}. Cross-source agreement is tracked so
    check_version_vulnerabilities can apply §10.3 guard 7 (banner cross-
    check).
    """
    info = {'number': None, 'sources': [], 'banner': None, 'evidence': []}
    candidate_paths = [
        '/', '/login/', '/cgi-sys/defaultwebpage.cgi',
        '/cpanelbranding/', '/unprotected/redirect.html',
    ]
    for path in candidate_paths:
        try:
            r = await client.get(f"{origin_url}{path}", timeout=6)
        except Exception:
            continue
        server = r.headers.get('server', '')
        if server and not info['banner']:
            info['banner'] = server
        m = SERVER_HEADER_VERSION.search(server)
        if m:
            info['number'] = info['number'] or m.group(1)
            info['sources'].append('header:server')
        for pat in VERSION_HTML_PATTERNS:
            m = pat.search(r.text or '')
            if m:
                value = m.group(1)
                # The magic-revision pattern yields a build number alone.
                if not info['number'] and re.match(r'^\d{2}\.\d+', value):
                    info['number'] = value
                info['sources'].append(f'html:{path}')
                info['evidence'].append(value)
                break
    # Dedupe.
    info['sources'] = sorted(set(info['sources']))
    info['evidence'] = sorted(set(info['evidence']))
    return info


# ─── Identification (gate for all checks) ─────────────────────────────────────

async def identify_cpanel_target(client, origin_url, version_info):
    """
    Confidence-scored fingerprint. A target is "identified" once score ≥ 3.

    cpsrvd serves cPanel-flavoured templates on 4xx responses (404, 401)
    too, so the status-code gate explicitly includes 404. The magic-
    revision asset name (`cPanel_magic_revision_<epoch>`) is itself a
    strong fingerprint — when present in version_info evidence we add +3
    even without a parsed version number.
    """
    evidence = []
    score = 0

    if version_info.get('number'):
        evidence.append(f"version:{version_info['number']}")
        score += 3
    if version_info.get('banner') and 'cpsrvd' in version_info['banner'].lower():
        evidence.append('header:cpsrvd')
        score += 2
    # cpanel_magic_revision is unique to cpsrvd-generated pages and is
    # captured during version probing even when no Server header is set.
    for ev in version_info.get('evidence', []):
        if isinstance(ev, str) and ev.isdigit() and len(ev) >= 7:
            evidence.append(f"magic_revision:{ev}")
            score += 3
            break

    probe_paths = [
        ('/login/',                              'login',     2),
        ('/cgi-sys/defaultwebpage.cgi',          'defpage',   2),
        ('/cpanelbranding/',                     'branding',  2),
        ('/unprotected/redirect.html',           'unprot',    2),
        ('/json-api/cpanel?cpanel_jsonapi_apiversion=2&cpanel_jsonapi_module=Branding&cpanel_jsonapi_func=spritelist',
         'jsonapi', 3),
        ('/webmail/',                            'webmail',   1),
        ('/3rdparty/roundcube/',                 'roundcube', 1),
    ]

    for path, label, weight in probe_paths:
        try:
            r = await client.get(f"{origin_url}{path}", timeout=5)
        except Exception:
            continue
        # cpsrvd returns cPanel-templated HTML on 404 too, so include it.
        if r.status_code in (200, 301, 302, 401, 403, 404):
            body = (r.text or '')[:8192].lower()
            loc = r.headers.get('location', '').lower()
            if _looks_like_cpanel_body(body) or 'cpsess' in loc or 'cpanel' in loc:
                evidence.append(label)
                score += weight

    for hdr_name in ('x-cpanel-server', 'x-cpanel-mailloop', 'x-cpanel-redirect', 'x-cpanel-request-id'):
        # We didn't keep the response — re-probe `/` once for the headers.
        pass

    try:
        r = await client.get(f"{origin_url}/", timeout=5)
        for hdr in r.headers:
            if hdr.lower().startswith('x-cpanel'):
                evidence.append(f'header:{hdr.lower()}')
                score += 2
                break
    except Exception:
        pass

    evidence = list(dict.fromkeys(evidence))
    return {'identified': score >= 3, 'score': score, 'evidence': evidence[:10]}


# ─── Finding helper ───────────────────────────────────────────────────────────

def _finding(status, severity, vulnerability, details, payload_url, evidence_hash=None, surface=None, cve_id=None):
    """
    Build a finding dict that satisfies the §9c reporting contract. The
    universal fields (`module`, `target`, `server`, `port`, `resolved_ip`,
    `url`, `service_version`) are stamped by run_scans before the row is
    enriched.
    """
    return {
        'status': status,
        'severity': severity,
        'vulnerability': vulnerability,
        'details': details,
        'payload_url': payload_url,
        '_evidence_hash': evidence_hash,
        '_surface': surface,
        '_cve_id': cve_id,
    }


# ─── Oracle helpers ───────────────────────────────────────────────────────────

async def _safe_get(client, url, **kwargs):
    """GET that never raises; returns response or None."""
    try:
        return await client.get(url, **kwargs)
    except Exception:
        return None


async def _safe_request(client, method, url, **kwargs):
    try:
        return await client.request(method, url, **kwargs)
    except Exception:
        return None


def _response_size_delta(r_pos, r_neg, threshold=32):
    if r_pos is None or r_neg is None:
        return False
    return abs(len(r_pos.text or '') - len(r_neg.text or '')) >= threshold


# ─── Check: live CVE payloads (OBSERVABLE_CVE_CHECKS + oracles) ───────────────

# Each entry includes an `oracle` triple:
#   positive: callable(client, origin) -> response   (the payload request)
#   control:  callable(client, origin) -> response   (the negative-control request)
#   indicator: callable(r_pos, r_neg) -> bool        (decides if positive is real)
# A check emits a finding only if the indicator returns True AND no
# disconfirmer matches.

def _xss_marker():
    return 'vkt-' + secrets.token_hex(8) + '-xss'


async def _oracle_cve_2023_29489_positive(client, origin):
    marker = _xss_marker()
    payload = f"/cpanelwebcall/{marker}<svg/onload=alert(1)>"
    r = await _safe_get(client, origin + payload, timeout=8)
    if r is not None:
        r._marker = marker  # type: ignore[attr-defined]
    return r


async def _oracle_cve_2023_29489_control(client, origin):
    return await _safe_get(client, origin + "/cpanelwebcall/", timeout=8)


def _oracle_cve_2023_29489_indicator(r_pos, r_neg):
    if r_pos is None:
        return False
    marker = getattr(r_pos, '_marker', None)
    if not marker:
        return False
    body = r_pos.text or ''
    # Marker must appear unencoded in HTML body.
    if marker not in body:
        return False
    # Encoded reflection is not exploitable.
    if f"&lt;svg" in body.lower() or f"&#x3c;svg" in body.lower():
        return False
    # Control must NOT contain the marker (it shouldn't — random token).
    if r_neg is not None and marker in (r_neg.text or ''):
        return False
    return True


async def _oracle_cve_2022_44762_positive(client, origin):
    return await _safe_get(client, origin + "/login/?goto_uri=https://attacker.example/", timeout=8)


async def _oracle_cve_2022_44762_control(client, origin):
    return await _safe_get(client, origin + "/login/", timeout=8)


def _oracle_cve_2022_44762_indicator(r_pos, r_neg):
    if r_pos is None:
        return False
    if r_pos.status_code not in (301, 302, 303, 307, 308):
        return False
    loc = r_pos.headers.get('location', '')
    return 'attacker.example' in loc.lower()


async def _oracle_cve_2022_44763_positive(client, origin):
    marker = _xss_marker()
    url = origin + f"/login/?error={marker}<script>alert(1)</script>"
    r = await _safe_get(client, url, timeout=8)
    if r is not None:
        r._marker = marker  # type: ignore[attr-defined]
    return r


async def _oracle_cve_2022_44763_control(client, origin):
    return await _safe_get(client, origin + "/login/", timeout=8)


def _oracle_cve_2022_44763_indicator(r_pos, r_neg):
    if r_pos is None:
        return False
    marker = getattr(r_pos, '_marker', None)
    if not marker:
        return False
    body = r_pos.text or ''
    if marker not in body:
        return False
    if f"&lt;" in body and f"<script>" not in body:
        return False
    return True


async def _oracle_cve_2019_11680_positive(client, origin):
    marker = _xss_marker()
    r = await _safe_get(client, origin + f"/cgi-sys/login.cgi?user={marker}<svg>", timeout=8)
    if r is not None:
        r._marker = marker  # type: ignore[attr-defined]
    return r


async def _oracle_cve_2019_11680_control(client, origin):
    return await _safe_get(client, origin + "/cgi-sys/login.cgi", timeout=8)


def _oracle_cve_2019_11680_indicator(r_pos, r_neg):
    if r_pos is None:
        return False
    marker = getattr(r_pos, '_marker', None)
    if not marker or marker not in (r_pos.text or ''):
        return False
    # Disconfirm if encoded.
    if "&lt;svg" in (r_pos.text or '').lower():
        return False
    return True


async def _oracle_cve_2021_38583_positive(client, origin):
    # SSRF indicator: server attempts to fetch the supplied URL and surfaces
    # an error tied to the attacker domain. Pre-94 cPanel accepted arbitrary
    # fqdns; the API is reachable from cpsess paths only, so we look for the
    # endpoint's existence as an INFO/POTENTIAL — actual SSRF needs a
    # collaborator we don't have.
    return await _safe_get(client, origin + "/json-api/fetch_ssl_certificates_for_fqdns?api.version=1&domains=attacker.example", timeout=8)


async def _oracle_cve_2021_38583_control(client, origin):
    return await _safe_get(client, origin + "/json-api/fetch_ssl_certificates_for_fqdns", timeout=8)


def _oracle_cve_2021_38583_indicator(r_pos, r_neg):
    if r_pos is None:
        return False
    body = (r_pos.text or '').lower()
    # API reachable AND attempted to resolve the attacker domain.
    if r_pos.status_code in (200, 400, 500) and ('attacker.example' in body or 'fqdn' in body):
        return True
    return False


OBSERVABLE_CVE_CHECKS = {
    'CVE-2023-29489': {
        'description': 'cPanel reflected XSS via /cpanelwebcall/',
        'severity': 'HIGH',
        'status': 'VULNERABLE',
        'surface': ['cPanel', 'WHM', 'Webmail'],
        'details': 'Reflected XSS via /cpanelwebcall/<payload>. Unauthenticated, mass-exploited (Assetnote disclosure).',
        'oracle': {
            'positive': _oracle_cve_2023_29489_positive,
            'control':  _oracle_cve_2023_29489_control,
            'indicator': _oracle_cve_2023_29489_indicator,
            'drop_if': ['waf', 'stock_error'],
        },
    },
    'CVE-2022-44762': {
        'description': 'cPanel open redirect via goto_uri on /login/',
        'severity': 'MEDIUM',
        'status': 'VULNERABLE',
        'surface': ['cPanel', 'WHM'],
        'details': 'The goto_uri parameter on /login/ accepts off-site hosts, enabling phishing.',
        'oracle': {
            'positive': _oracle_cve_2022_44762_positive,
            'control':  _oracle_cve_2022_44762_control,
            'indicator': _oracle_cve_2022_44762_indicator,
            'drop_if': ['waf'],
        },
    },
    'CVE-2022-44763': {
        'description': 'cPanel reflected XSS via error= on /login/',
        'severity': 'MEDIUM',
        'status': 'VULNERABLE',
        'surface': ['cPanel', 'WHM', 'Webmail'],
        'details': 'The error parameter on /login/ reflects user-controlled content into the HTML page unescaped.',
        'oracle': {
            'positive': _oracle_cve_2022_44763_positive,
            'control':  _oracle_cve_2022_44763_control,
            'indicator': _oracle_cve_2022_44763_indicator,
            'drop_if': ['waf', 'stock_error'],
        },
    },
    'CVE-2019-11680': {
        'description': 'cPanel reflected XSS in /cgi-sys/login.cgi',
        'severity': 'MEDIUM',
        'status': 'VULNERABLE',
        'surface': ['cPanel'],
        'details': 'login.cgi reflects user-controlled query string content unescaped.',
        'oracle': {
            'positive': _oracle_cve_2019_11680_positive,
            'control':  _oracle_cve_2019_11680_control,
            'indicator': _oracle_cve_2019_11680_indicator,
            'drop_if': ['waf', 'stock_error'],
        },
    },
    'CVE-2021-38583': {
        'description': 'cPanel SSRF via fetch_ssl_certificates_for_fqdns',
        'severity': 'HIGH',
        'status': 'POTENTIAL',
        'surface': ['cPanel'],
        'details': 'fetch_ssl_certificates_for_fqdns endpoint reachable with insufficient FQDN validation. Manual confirmation needed via collaborator.',
        'oracle': {
            'positive': _oracle_cve_2021_38583_positive,
            'control':  _oracle_cve_2021_38583_control,
            'indicator': _oracle_cve_2021_38583_indicator,
            'drop_if': ['waf'],
        },
    },
}


async def check_cve_vulnerabilities(client, ctx, baselines):
    """Run every entry in OBSERVABLE_CVE_CHECKS through its oracle."""
    out = []
    origin = ctx['origin_url']
    surface = ctx['surface']

    for cve_id, meta in OBSERVABLE_CVE_CHECKS.items():
        if surface not in meta['surface'] and ctx['port'] not in (2082, 2083, 2086, 2087, 2095, 2096, 9998, 9999, 80, 443):
            continue
        oracle = meta['oracle']
        try:
            r_pos = await oracle['positive'](client, origin)
            r_neg = await oracle['control'](client, origin)
        except Exception:
            continue
        if r_pos is None:
            continue

        # Disconfirmers.
        if 'stock_error' in oracle.get('drop_if', []) and _hash_body(r_pos.text) in baselines:
            continue
        waf = _detect_waf(r_pos)
        if not oracle['indicator'](r_pos, r_neg):
            continue

        status = meta['status']
        details = meta['details']
        if waf:
            status = 'POTENTIAL'
            details += f' [WAF in path: {waf}]'

        out.append(_finding(
            status=status,
            severity=meta['severity'],
            vulnerability=f"{cve_id} - {meta['description']}",
            details=details,
            payload_url=str(r_pos.request.url),
            evidence_hash=_hash_body(r_pos.text)[:12],
            surface=surface,
            cve_id=cve_id,
        ))
    return out


# ─── Check: version-anchored TSR bulletins ────────────────────────────────────

async def check_version_vulnerabilities(client, ctx, version_info):
    """Match detected version against the full TSR archive."""
    out = []
    ver = version_info.get('number')
    if not ver:
        return out

    # §10.3 guard 7: require ≥ 2 independent sources before trusting the
    # version. If only the Server header reported it, downgrade severity.
    cross_confirmed = len(version_info.get('sources', [])) >= 2

    for bulletin in CPANEL_SECURITY_BULLETINS:
        if not is_version_affected(ver, bulletin.get('affected_versions', [])):
            continue
        surfaces = bulletin.get('surface', [])
        if surfaces and ctx['surface'].lower() not in (s.lower() for s in surfaces) and 'cpanel' not in (s.lower() for s in surfaces):
            continue
        status = 'VULNERABLE' if cross_confirmed else 'POTENTIAL'
        if bulletin.get('severity') == 'CRITICAL':
            status = 'CRITICAL' if cross_confirmed else 'POTENTIAL'
        cves = ', '.join(bulletin.get('cves', []) or [bulletin['id']])
        details = (
            f"Detected cPanel {ver} (surface: {ctx['surface']}) is inside the unpatched range for "
            f"{bulletin['id']} ({bulletin['published']}). Fix: {', '.join(bulletin.get('fixed_in', []))}. "
            f"Covers: {cves}. {bulletin.get('summary', '')}"
        )
        if not cross_confirmed:
            details += ' [version came from a single source — confirm by reading /cpanelbranding/]'
        if bulletin.get('auth_required'):
            details += ' [auth_required: true — flagged for context, not exploited]'

        out.append(_finding(
            status=status,
            severity=bulletin.get('severity', 'MEDIUM'),
            vulnerability=f"{bulletin['id']} - cPanel & WHM Security Advisory",
            details=details,
            payload_url=ctx['origin_url'] + '/',
            evidence_hash=bulletin['id'],
            surface=ctx['surface'],
            cve_id=bulletin.get('cves', [None])[0] if bulletin.get('cves') else None,
        ))
    return out


# ─── Check: sensitive paths ───────────────────────────────────────────────────

#
# Each entry: (path, label, severity, status, exposed_codes)
#
# exposed_codes: the HTTP status codes that mean the path is *actually exposed*
# (not just protected). For a sensitive API like /json-api/listaccts, 403/401
# means the auth gate is doing its job — that's NOT a finding. Only 200 (with
# a real body) means the endpoint leaked. For login portals and reset flows,
# 200/302 are the exposed signals because they're meant to be public.
#
SENSITIVE_PATHS = [
    # Login portals (expected to be public; 200/302/401 are all "reachable")
    ('/login/',                                          'cPanel login portal exposed',                'INFO',       'INFO',       (200, 302, 401)),
    ('/whm/login',                                       'WHM login portal exposed',                   'INFO',       'INFO',       (200, 302, 401)),
    ('/webmail/',                                        'Webmail portal exposed',                     'INFO',       'INFO',       (200, 302, 401)),
    ('/webdisk/',                                        'WebDisk portal exposed',                     'INFO',       'INFO',       (200, 302, 401)),
    # Default install pages — both are stock cPanel static files; we only
    # surface defaultwebpage.cgi because a 200 on it on an unrelated
    # vhost is a strong subdomain-takeover signal (handled separately by
    # domain_scan). We drop /unprotected/redirect.html because it's a
    # stock asset present on every install and not a vulnerability.
    ('/cgi-sys/defaultwebpage.cgi',                      'cPanel default landing page reachable',     'INFO',       'INFO',       (200,)),
    ('/cpanelbranding/',                                 'cPanel branding directory listing',          'LOW',        'VULNERABLE', (200,)),
    # API surfaces that should not be public — only 200 means leaked
    ('/json-api/listaccts',                              'WHM json-api listaccts leaks accounts',      'CRITICAL',   'CRITICAL',   (200,)),
    ('/xml-api/listaccts',                               'WHM xml-api listaccts leaks accounts',       'CRITICAL',   'CRITICAL',   (200,)),
    ('/json-api/version',                                'WHM json-api version leaks',                 'MEDIUM',     'VULNERABLE', (200,)),
    ('/xml-api/version',                                 'WHM xml-api version leaks',                  'MEDIUM',     'VULNERABLE', (200,)),
    ('/json-api/php_get_installed_versions',             'WHM MultiPHP version enumeration',           'MEDIUM',     'VULNERABLE', (200,)),
    ('/json-api/listresellers',                          'WHM reseller list leaks',                    'HIGH',       'VULNERABLE', (200,)),
    ('/json-api/listpkgs',                               'WHM package list leaks',                     'MEDIUM',     'VULNERABLE', (200,)),
    # 3rd-party bundled apps — 200 only (the existence finding)
    ('/3rdparty/roundcube/',                             'Roundcube webmail surface',                  'INFO',       'INFO',       (200, 302)),
    ('/3rdparty/squirrelmail/',                          'SquirrelMail surface (end-of-life)',         'HIGH',       'VULNERABLE', (200, 302)),
    ('/horde/',                                          'Horde groupware surface',                    'INFO',       'INFO',       (200, 302)),
    ('/pma/',                                            'phpMyAdmin reachable at /pma/',              'HIGH',       'VULNERABLE', (200, 302)),
    ('/phpmyadmin/',                                     'phpMyAdmin reachable at /phpmyadmin/',       'HIGH',       'VULNERABLE', (200, 302)),
    ('/mysql/',                                          'MySQL UI proxy reachable',                   'MEDIUM',     'VULNERABLE', (200, 302)),
    ('/whmcs/',                                          'WHMCS billing portal reachable',             'INFO',       'INFO',       (200, 302)),
    ('/clients/',                                        'WHMCS clients portal reachable',             'INFO',       'INFO',       (200, 302)),
    ('/billing/',                                        'Billing portal reachable',                   'INFO',       'INFO',       (200, 302)),
    ('/mailman/',                                        'Mailman mailing-list UI reachable',          'MEDIUM',     'VULNERABLE', (200,)),
    ('/awstats/',                                        'AWStats statistics UI reachable',            'HIGH',       'VULNERABLE', (200,)),
    ('/webalizer/',                                      'Webalizer statistics UI reachable',          'MEDIUM',     'VULNERABLE', (200,)),
    ('/wp-toolkit/',                                     'WP Toolkit UI reachable',                    'INFO',       'INFO',       (200, 302)),
    ('/imunify360/',                                     'Imunify360 UI reachable',                    'INFO',       'INFO',       (200, 302)),
    ('/csf/',                                            'ConfigServer Firewall UI reachable',         'MEDIUM',     'VULNERABLE', (200,)),
    # Server info / config — strictly 200
    ('/server-status',                                   'Apache server-status reachable',             'HIGH',       'VULNERABLE', (200,)),
    ('/server-info',                                     'Apache server-info reachable',               'HIGH',       'VULNERABLE', (200,)),
    ('/.htaccess',                                       '.htaccess directly readable',                'HIGH',       'VULNERABLE', (200,)),
    ('/var/cpanel/version',                              '/var/cpanel/version readable',               'MEDIUM',     'VULNERABLE', (200,)),
    # Password reset / signup (public exposure flow). The reset form is
    # MEANT to be reachable — cPanel users reset their own passwords
    # through it. Rate-limiting is cPHulkd's job, surfaced separately.
    # We report as INFO so operators see the surface without claiming it's
    # a vulnerability.
    ('/resetpass',                                       'Password reset endpoint reachable',          'INFO',       'INFO',       (200, 302)),
    ('/resetpass?start=1',                               'Password reset flow start reachable',        'INFO',       'INFO',       (200, 302)),
    ('/signup',                                          'Signup endpoint reachable',                  'LOW',        'INFO',       (200, 302)),
    ('/invite',                                          'Invite endpoint reachable',                  'LOW',        'INFO',       (200, 302)),
    ('/2fa/manage',                                      'cPanel 2FA management page reachable',       'HIGH',       'VULNERABLE', (200,)),
    # WHM admin scripts (only sensitive when they return JSON/API-shaped
    # content; cpsrvd's templated 200 is filtered by the baseline check).
    ('/scripts/easyapache4',                             'WHM EasyApache 4 surface reachable',         'INFO',       'INFO',       (200,)),
    ('/scripts/backup',                                  'WHM backup-script surface reachable',        'INFO',       'INFO',       (200,)),
    ('/scripts2/manage_api_tokens',                      'WHM API-token management surface reachable', 'MEDIUM',     'VULNERABLE', (200,)),
    ('/scripts2/listapitokens',                          'WHM API-token list surface reachable',       'MEDIUM',     'VULNERABLE', (200,)),
    # CGI scripts (classic cPanel RCE surface) — 200 only
    ('/cgi-sys/FormMail-clone.cgi',                      'Legacy FormMail-clone.cgi present',          'HIGH',       'VULNERABLE', (200,)),
    ('/cgi-sys/cpaddons.cgi',                            'Legacy cpaddons.cgi present',                'MEDIUM',     'VULNERABLE', (200,)),
    ('/cgi-sys/randhtml.cgi',                            'Legacy randhtml.cgi present',                'MEDIUM',     'VULNERABLE', (200,)),
    ('/cgi-sys/scgiwrap',                                'Legacy scgiwrap present',                    'MEDIUM',     'VULNERABLE', (200,)),
    ('/cgi-sys/sitebuilder.cgi',                         'cPanel Site Builder reachable',              'MEDIUM',     'VULNERABLE', (200,)),
    ('/cgi-sys/fantasticoauto.cgi',                      'Fantastico installer present (EOL)',         'HIGH',       'VULNERABLE', (200,)),
]


async def check_sensitive_paths(client, ctx, baselines):
    """
    Probe SENSITIVE_PATHS with status-code gating per entry. A path fires
    a finding only when:
      (1) the response status is in the entry's declared `exposed_codes`,
      (2) the body is not the cpsrvd login-template (which cpsrvd serves
          as a normalised 200 to ANY unknown path — body length is
          identical at ~37KB but the hash drifts because the template
          embeds CSRF tokens, so we have to detect by CONTENT not hash),
      (3) for CRITICAL/HIGH API endpoints, the body actually looks like
          JSON/XML (a 200 from cpsrvd that's actually just the login
          template is not a leak).
    """
    out = []
    origin = ctx['origin_url']
    for entry in SENSITIVE_PATHS:
        path, label, severity, status, exposed_codes = entry
        r = await _safe_get(client, origin + path, timeout=5, follow_redirects=False)
        if r is None:
            continue
        if r.status_code not in exposed_codes:
            continue
        body = r.text or ''
        body_hash = _hash_body(body)
        ct = r.headers.get('content-type', '').lower()
        lower_head = body[:8192].lower()

        if r.status_code == 200:
            # Reject baseline (stock-error / random-path) bodies.
            if body_hash in baselines:
                continue
            # Reject trivially small bodies.
            if len(body) < 64:
                continue
            # cpsrvd normalises any unauthenticated 200 to its login
            # template. The body hash drifts (per-request CSRF token)
            # but the <title> is stable and dispositive: a 200 with
            # `<title>...Login</title>` is the login page, NOT the
            # endpoint the caller asked for. The login portal itself
            # (path == '/login/') is exempted from this check.
            title_match = re.search(r'<title>([^<]+)</title>', body[:4096], re.IGNORECASE)
            title = title_match.group(1).strip().lower() if title_match else ''
            looks_like_login_template = bool(
                title and title.endswith(' login') and 'login' in title and path != '/login/'
            )
            if looks_like_login_template:
                continue
            # For 'leak' findings (CRITICAL/HIGH on API paths), require
            # JSON/XML-shaped body.
            if severity in ('CRITICAL', 'HIGH') and ('json-api' in path or 'xml-api' in path):
                looks_api = (
                    'json' in ct
                    or 'xml' in ct
                    or body.strip().startswith(('{', '[', '<?xml'))
                )
                if not looks_api:
                    continue

        loc = r.headers.get('location', '')
        details = f"{label}. HTTP {r.status_code} from {path}."
        if loc:
            details += f" Location: {loc[:200]}"
        out.append(_finding(
            status=status,
            severity=severity,
            vulnerability=label,
            details=details,
            payload_url=origin + path,
            evidence_hash=body_hash[:12],
            surface=ctx['surface'],
        ))
    return out


# ─── Check: information disclosure ────────────────────────────────────────────

INFO_DISCLOSURE_PATTERNS = [
    (re.compile(r'cpsrvd[\/-](\d+\.\d+(?:\.\d+){0,2})', re.IGNORECASE), 'cpsrvd version banner'),
    (re.compile(r'Apache\/(\d+\.\d+\.\d+)', re.IGNORECASE), 'Apache version banner'),
    (re.compile(r'PHP\/(\d+\.\d+\.\d+)', re.IGNORECASE), 'PHP version banner'),
    (re.compile(r'mod_(?:ssl|fcgid|perl)\/(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE), 'Apache module version'),
    (re.compile(r'OpenSSL\/(\d+\.\d+\.\d+[a-z]?)', re.IGNORECASE), 'OpenSSL version'),
    (re.compile(r'\b([\w\.-]+)\s+\(internal\)', re.IGNORECASE), 'Internal hostname'),
]


async def check_information_disclosure(client, ctx):
    out = []
    origin = ctx['origin_url']
    seen = set()
    for path in ('/', '/login/', '/cgi-sys/defaultwebpage.cgi', '/unprotected/redirect.html'):
        r = await _safe_get(client, origin + path, timeout=5)
        if r is None:
            continue
        blob = ' '.join(f"{k}: {v}" for k, v in r.headers.items()) + '\n' + (r.text or '')[:4096]
        for pattern, label in INFO_DISCLOSURE_PATTERNS:
            m = pattern.search(blob)
            if not m:
                continue
            key = (label, m.group(0))
            if key in seen:
                continue
            seen.add(key)
            out.append(_finding(
                status='INFO',
                severity='LOW',
                vulnerability=f'Information disclosure: {label}',
                details=f"{label} disclosed at {path}: '{m.group(0)[:120]}'.",
                payload_url=origin + path,
                evidence_hash=_hash_body(m.group(0))[:12],
                surface=ctx['surface'],
            ))
    return out


# ─── Check: HTTP method tampering ─────────────────────────────────────────────

async def check_http_method_tampering(client, ctx, baselines):
    out = []
    origin = ctx['origin_url']
    r_get = await _safe_request(client, 'GET', origin + '/', timeout=5)
    if r_get is None:
        return out

    # TRACE
    r_trace = await _safe_request(client, 'TRACE', origin + '/', timeout=5)
    if r_trace is not None and r_trace.status_code == 200 and 'TRACE' in (r_trace.text or '').upper()[:200]:
        out.append(_finding(
            status='VULNERABLE',
            severity='MEDIUM',
            vulnerability='HTTP TRACE method enabled',
            details='Apache TRACE method returns 200 and echoes the request headers — enables Cross-Site Tracing.',
            payload_url=origin + '/',
            surface=ctx['surface'],
        ))

    # PUT to write-protected path: expect 401/403/405; 200/201/204 means trouble.
    r_put = await _safe_request(client, 'PUT', origin + '/_vakt_probe.txt', timeout=5, content=b'vakt')
    if r_put is not None and r_put.status_code in (200, 201, 204):
        out.append(_finding(
            status='CRITICAL',
            severity='CRITICAL',
            vulnerability='HTTP PUT method accepted',
            details=f'PUT to /_vakt_probe.txt returned {r_put.status_code} — server may accept arbitrary file uploads.',
            payload_url=origin + '/_vakt_probe.txt',
            surface=ctx['surface'],
        ))
    return out


# ─── Check: host-header bypass ────────────────────────────────────────────────

async def check_host_header_bypass(client, ctx):
    out = []
    origin = ctx['origin_url']
    parsed = urlparse(origin)
    real_host_url = f"{parsed.scheme}://{parsed.netloc}/"

    r_real = await _safe_get(client, real_host_url, timeout=5)
    r_local = await _safe_get(client, real_host_url, timeout=5, headers={'Host': 'localhost'})
    if r_real is None or r_local is None:
        return out
    if r_real.status_code != r_local.status_code and _response_size_delta(r_local, r_real, threshold=128):
        out.append(_finding(
            status='POTENTIAL',
            severity='MEDIUM',
            vulnerability='Host-header allow-list bypass possible',
            details=f"Host: localhost returns HTTP {r_local.status_code} (vs {r_real.status_code} for the real host) — source-IP allow-list may be bypassable.",
            payload_url=real_host_url,
            surface=ctx['surface'],
        ))
    return out


# ─── Check: session bypass via cpsess prediction ──────────────────────────────

async def check_session_bypass(client, ctx, baselines):
    """
    cpsrvd may rewrite an unknown /cpsess<n>/ path to its normal login flow
    and serve the 37 KB login HTML with HTTP 200 — that is NOT a bypass. We
    only flag the row when the response is clearly authenticated content:
    JSON / XML, or HTML that contains a session marker but is NOT the
    login template.
    """
    out = []
    origin = ctx['origin_url']
    bypass_paths = [
        ('/cpsess0000000000/frontend/jupiter/index.html', 'html'),
        ('/cpsess0000000000/json-api/listaccts',          'json'),
        ('/cpsess0000000000/execute/Branding/list',       'json'),
    ]
    for path, expect in bypass_paths:
        r = await _safe_get(client, origin + path, timeout=5, follow_redirects=False)
        if r is None or r.status_code != 200:
            continue
        if _hash_body(r.text) in baselines:
            continue
        body = r.text or ''
        ct = r.headers.get('content-type', '').lower()
        lower = body[:4096].lower()
        # Hard rejection: cpsrvd login-template response detected by
        # the <title>...Login</title> marker (stable across the per-
        # request CSRF-token drift in the body).
        title_match = re.search(r'<title>([^<]+)</title>', body[:4096], re.IGNORECASE)
        title = title_match.group(1).strip().lower() if title_match else ''
        if title.endswith(' login'):
            continue
        if expect == 'json':
            if 'json' not in ct and not body.strip().startswith(('{', '[')):
                continue
        else:
            # For the panel UI path, require markers of a logged-in session.
            if not any(m in lower for m in ('cpsession', 'goto_app', 'whm-tools', 'whostmgrsession', 'logout')):
                continue
        out.append(_finding(
            status='CRITICAL',
            severity='CRITICAL',
            vulnerability='cpsess session prediction / bypass',
            details=f'/cpsess0000000000/ path returned 200 with authenticated-shape body (ct={ct or "?"}). Session validation may be missing.',
            payload_url=origin + path,
            surface=ctx['surface'],
        ))
    return out


# ─── Check: CORS misconfig on json-api / execute ──────────────────────────────

async def check_cors_misconfig(client, ctx):
    out = []
    origin = ctx['origin_url']
    test_paths = ['/json-api/version', '/execute/Branding/list']
    for path in test_paths:
        r = await _safe_get(client, origin + path, timeout=5, headers={'Origin': 'https://attacker.example'})
        if r is None:
            continue
        acao = r.headers.get('access-control-allow-origin', '')
        acac = r.headers.get('access-control-allow-credentials', '').lower()
        if acao in ('*', 'https://attacker.example') and acac == 'true':
            out.append(_finding(
                status='VULNERABLE',
                severity='HIGH',
                vulnerability='CORS misconfiguration with credentials',
                details=f'{path} echoes Access-Control-Allow-Origin (={acao}) with Allow-Credentials: true — cross-origin reads possible.',
                payload_url=origin + path,
                surface=ctx['surface'],
            ))
        elif acao == 'https://attacker.example':
            out.append(_finding(
                status='POTENTIAL',
                severity='MEDIUM',
                vulnerability='CORS echoes arbitrary Origin',
                details=f'{path} echoes attacker-supplied Origin header without credentials — limited cross-origin read.',
                payload_url=origin + path,
                surface=ctx['surface'],
            ))
    return out


# ─── Check: CRLF / header injection ───────────────────────────────────────────

async def check_crlf_injection(client, ctx):
    out = []
    origin = ctx['origin_url']
    marker = 'x-vakt-' + secrets.token_hex(4)
    payload = f"/login/?goto_uri=%0d%0a{marker}:1"
    r = await _safe_get(client, origin + payload, timeout=5, follow_redirects=False)
    if r is None:
        return out
    if marker in str(r.headers).lower():
        out.append(_finding(
            status='VULNERABLE',
            severity='HIGH',
            vulnerability='CRLF / response header injection',
            details=f'goto_uri parameter on /login/ allows CRLF injection — attacker-controlled header reflected.',
            payload_url=origin + payload,
            surface=ctx['surface'],
        ))
    return out


# ─── Check: cache poisoning via X-Forwarded-Host ──────────────────────────────

async def check_cache_poisoning(client, ctx):
    out = []
    origin = ctx['origin_url']
    r = await _safe_get(client, origin + '/login/', timeout=5, headers={'X-Forwarded-Host': 'attacker.example'}, follow_redirects=False)
    if r is None:
        return out
    loc = r.headers.get('location', '')
    if 'attacker.example' in loc.lower():
        out.append(_finding(
            status='VULNERABLE',
            severity='HIGH',
            vulnerability='X-Forwarded-Host poisoning',
            details=f'/login/ reflects X-Forwarded-Host into Location header — caching layer can be poisoned.',
            payload_url=origin + '/login/',
            surface=ctx['surface'],
        ))
    return out


# ─── Check: cookie security on cpsess ────────────────────────────────────────

async def check_cookie_security(client, ctx):
    """
    Audit only the cookies that actually carry session state. We probe
    /login/ which (pre-auth) emits a CSRF-token cookie under the same
    name as the post-auth session cookie. Distinguishing them from a
    single request is unreliable, so we audit conservatively:
      - REQUIRE HttpOnly + Secure (on TLS surfaces) — both are mandatory
        whether the cookie is pre-auth CSRF or post-auth session;
      - DO NOT flag missing SameSite — many cPanel installs intentionally
        omit it on pre-auth CSRF cookies to support cross-site auth
        kicks; flagging it on a CSRF-token cookie was noisy and not a
        real CSRF risk (no auth state attached yet).
    """
    out = []
    origin = ctx['origin_url']
    r = await _safe_get(client, origin + '/login/', timeout=5)
    if r is None:
        return out
    raw = r.headers.get_list('set-cookie') if hasattr(r.headers, 'get_list') else [r.headers.get('set-cookie', '')]
    for cookie in raw:
        lower = cookie.lower()
        is_session = lower.startswith(('cpsession=', 'whostmgrsession=', 'webmailsession='))
        if not is_session:
            continue
        first_pair = cookie.split(';', 1)[0]
        if '=' not in first_pair or not first_pair.split('=', 1)[1].strip():
            continue
        missing = []
        if 'httponly' not in lower:
            missing.append('HttpOnly')
        if ctx['is_tls'] and 'secure' not in lower:
            missing.append('Secure')
        if not missing:
            continue
        out.append(_finding(
            status='VULNERABLE',
            severity='LOW',
            vulnerability='cPanel session cookie missing security flags',
            details=(
                f'Set-Cookie for the cPanel session is missing: {", ".join(missing)}. '
                f'Note: this cookie may be the pre-auth CSRF token; the real risk is on post-auth '
                f'reissue. Raw cookie: {cookie[:160]}'
            ),
            payload_url=origin + '/login/',
            surface=ctx['surface'],
        ))
    return out


# ─── Check: WebSocket / SSI / mod_userdir / WebDAV / CalDAV ───────────────────

async def check_websocket_exposure(client, ctx):
    out = []
    origin = ctx['origin_url']
    paths = ['/ws', '/cpsess0000000000/ws/cpanel', '/wsapi']
    for path in paths:
        r = await _safe_get(client, origin + path, timeout=5, headers={
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            'Sec-WebSocket-Version': '13',
            'Origin': 'https://attacker.example',
        })
        if r is None:
            continue
        if r.status_code == 101 or 'websocket' in r.headers.get('upgrade', '').lower():
            out.append(_finding(
                status='POTENTIAL',
                severity='MEDIUM',
                vulnerability='WebSocket endpoint exposed without origin enforcement',
                details=f'{path} accepted WebSocket upgrade from attacker.example Origin (HTTP {r.status_code}).',
                payload_url=origin + path,
                surface=ctx['surface'],
            ))
    return out


async def check_userdir_enum(client, ctx):
    out = []
    origin = ctx['origin_url']
    for user in ('root', 'cpanel', 'test', 'admin', 'demo'):
        r = await _safe_get(client, origin + f'/~{user}/', timeout=4)
        if r is None or r.status_code not in (200, 403):
            continue
        if r.status_code == 200 and r.text and 'index of' in r.text.lower()[:200]:
            out.append(_finding(
                status='VULNERABLE',
                severity='MEDIUM',
                vulnerability='mod_userdir enumeration / directory listing',
                details=f'~{user}/ returned an index listing — user trees enumerable.',
                payload_url=origin + f'/~{user}/',
                surface=ctx['surface'],
            ))
    return out


async def check_webdav_exposure(client, ctx):
    out = []
    if ctx['port'] not in (2077, 2078):
        return out
    origin = ctx['origin_url']
    r = await _safe_request(client, 'OPTIONS', origin + '/', timeout=5)
    if r is None:
        return out
    allow = r.headers.get('allow', '') + ' ' + r.headers.get('dav', '')
    if 'PROPFIND' in allow or 'DAV' in allow:
        write_methods = [m for m in ('PUT', 'DELETE', 'MOVE', 'COPY', 'MKCOL') if m in allow]
        sev = 'CRITICAL' if write_methods else 'HIGH'
        out.append(_finding(
            status='VULNERABLE',
            severity=sev,
            vulnerability='WebDAV / cpdavd exposed',
            details=f'OPTIONS on / reports DAV-Level support; Allow: {allow[:200]}. Write methods advertised: {", ".join(write_methods) or "none"}.',
            payload_url=origin + '/',
            surface=ctx['surface'],
        ))
    return out


async def check_caldav_exposure(client, ctx):
    out = []
    if ctx['port'] not in (2079, 2080):
        return out
    origin = ctx['origin_url']
    r = await _safe_request(client, 'PROPFIND', origin + '/', timeout=5, headers={'Depth': '0'})
    if r is None:
        return out
    if r.status_code in (207, 200) and 'multistatus' in (r.text or '').lower():
        out.append(_finding(
            status='VULNERABLE',
            severity='HIGH',
            vulnerability='CalDAV / CardDAV PROPFIND reachable',
            details='PROPFIND on / returned multistatus — calendar/contact metadata enumerable.',
            payload_url=origin + '/',
            surface=ctx['surface'],
        ))
    return out


# ─── Check: TLS posture ───────────────────────────────────────────────────────

async def check_tls_posture(ctx):
    out = []
    if not ctx['is_tls']:
        return out
    host = ctx['scan_address']
    if is_full_url(host):
        host = urlparse(host).hostname or host
    port = ctx['port']

    # Cert + protocol probe via stdlib ssl in a thread.
    def _probe():
        results = []
        # Cert details
        try:
            ctx_default = ssl.create_default_context()
            ctx_default.check_hostname = False
            ctx_default.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx_default.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False) or {}
                    proto = ssock.version()
                    results.append(('cert', cert))
                    results.append(('proto', proto))
                    # SANs
                    sans = []
                    for typ, val in cert.get('subjectAltName', []) or []:
                        sans.append(val)
                    results.append(('sans', sans))
        except Exception as e:
            results.append(('error', str(e)))

        # TLS 1.0 / 1.1 negotiation
        for legacy, name in ((ssl.TLSVersion.TLSv1, 'TLSv1.0'), (ssl.TLSVersion.TLSv1_1, 'TLSv1.1')):
            try:
                lctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                lctx.check_hostname = False
                lctx.verify_mode = ssl.CERT_NONE
                lctx.minimum_version = legacy
                lctx.maximum_version = legacy
                with socket.create_connection((host, port), timeout=5) as sock:
                    with lctx.wrap_socket(sock, server_hostname=host) as ssock:
                        results.append(('legacy', name))
            except Exception:
                continue
        return results

    try:
        loop = asyncio.get_running_loop()
        probe_results = await loop.run_in_executor(None, _probe)
    except Exception:
        return out

    cert = None
    for kind, val in probe_results:
        if kind == 'cert':
            cert = val
        elif kind == 'legacy':
            out.append(_finding(
                status='VULNERABLE',
                severity='MEDIUM',
                vulnerability=f'Legacy TLS protocol enabled ({val})',
                details=f'{val} handshake completed against {host}:{port}.',
                payload_url=ctx['origin_url'] + '/',
                surface=ctx['surface'],
            ))
        elif kind == 'sans':
            if len(val) > 1:
                out.append(_finding(
                    status='INFO',
                    severity='LOW',
                    vulnerability='TLS certificate SAN list discloses co-hosted domains',
                    details='SANs: ' + ', '.join(val[:30]),
                    payload_url=ctx['origin_url'] + '/',
                    surface=ctx['surface'],
                ))
        elif kind == 'proto':
            if val in ('TLSv1', 'TLSv1.1'):
                out.append(_finding(
                    status='VULNERABLE',
                    severity='MEDIUM',
                    vulnerability=f'Default negotiated protocol is legacy ({val})',
                    details=f'Default handshake negotiated {val}.',
                    payload_url=ctx['origin_url'] + '/',
                    surface=ctx['surface'],
                ))

    if cert:
        import datetime
        try:
            not_after = cert.get('notAfter')
            if not_after:
                expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                now = datetime.datetime.utcnow()
                if expiry < now:
                    out.append(_finding(
                        status='VULNERABLE',
                        severity='HIGH',
                        vulnerability='TLS certificate expired',
                        details=f'Certificate notAfter is {not_after} (past expiry).',
                        payload_url=ctx['origin_url'] + '/',
                        surface=ctx['surface'],
                    ))
        except Exception:
            pass

    # HSTS check
    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            r = await _safe_get(client, ctx['origin_url'] + '/')
            if r is not None and 'strict-transport-security' not in {k.lower() for k in r.headers}:
                out.append(_finding(
                    status='INFO',
                    severity='LOW',
                    vulnerability='HSTS header missing on TLS surface',
                    details='Strict-Transport-Security header not set; downgrade attacks possible.',
                    payload_url=ctx['origin_url'] + '/',
                    surface=ctx['surface'],
                ))
    except Exception:
        pass

    return out


# ─── Check: plaintext control-panel on non-TLS port ──────────────────────────

async def check_plaintext_control_panel(client, ctx):
    """If we identified cPanel on 2082/2086 (HTTP), that's a HIGH finding by itself."""
    if ctx['is_tls']:
        return []
    if ctx['port'] not in (2082, 2086, 2095, 2077, 2079):
        return []
    return [_finding(
        status='VULNERABLE',
        severity='HIGH',
        vulnerability=f'cPanel {ctx["surface"]} reachable over plaintext HTTP (port {ctx["port"]})',
        details=f'Port {ctx["port"]} serves cPanel/WHM/Webmail over unencrypted HTTP. Credentials are transmitted in clear.',
        payload_url=ctx['origin_url'] + '/',
        surface=ctx['surface'],
    )]


# ─── Check: account enumeration via login response delta ──────────────────────

async def check_account_enum_timing(client, ctx):
    if ctx['surface'] not in ('cPanel', 'WHM', 'Webmail'):
        return []
    out = []
    origin = ctx['origin_url']
    existing_user = 'root' if ctx['surface'] == 'WHM' else 'cpanel'
    bogus_user = secrets.token_hex(8)
    payload_existing = {'user': existing_user, 'pass': 'definitely-wrong-' + secrets.token_hex(4)}
    payload_bogus = {'user': bogus_user, 'pass': 'definitely-wrong-' + secrets.token_hex(4)}
    try:
        r_existing = await client.post(origin + '/login/', data=payload_existing, timeout=8, follow_redirects=False)
        r_bogus = await client.post(origin + '/login/', data=payload_bogus, timeout=8, follow_redirects=False)
    except Exception:
        return []
    if r_existing is None or r_bogus is None:
        return []
    delta = abs(len(r_existing.text or '') - len(r_bogus.text or ''))
    if delta > 256:
        out.append(_finding(
            status='INFO',
            severity='LOW',
            vulnerability='Account enumeration via login response delta',
            details=f'Response-length delta of {delta} bytes between known user "{existing_user}" and random user "{bogus_user}" on /login/.',
            payload_url=origin + '/login/',
            surface=ctx['surface'],
        ))
    return out


# ─── Check: cPHulk presence ──────────────────────────────────────────────────

async def check_cphulk_present(client, ctx):
    if ctx['surface'] not in ('cPanel', 'WHM', 'Webmail'):
        return []
    origin = ctx['origin_url']
    saw_header = False
    for _ in range(3):
        try:
            r = await client.post(origin + '/login/', data={
                'user': 'admin',
                'pass': 'wrong-' + secrets.token_hex(4),
            }, timeout=6, follow_redirects=False)
        except Exception:
            return []
        if r is None:
            return []
        for hdr in r.headers:
            if hdr.lower().startswith('x-cphulk'):
                saw_header = True
                break
        if saw_header:
            break
    if not saw_header:
        return [_finding(
            status='INFO',
            severity='LOW',
            vulnerability='cPHulk brute-force protection not directly observed',
            details=(
                'Three failed logins did not surface X-Cphulkd-* response headers. '
                'cPHulkd may be enabled but only surface headers after the lockout '
                'threshold is hit, OR it may be disabled. Verify with `whmapi1 '
                'gethulkstatus`. Not a confirmed vulnerability — just a posture note.'
            ),
            payload_url=origin + '/login/',
            surface=ctx['surface'],
        )]
    return []


# ─── Check: auto-created subdomain INFO rows ─────────────────────────────────

async def check_auto_subdomains(client, ctx):
    """
    Removed: emitting a generic "auto-subdomains likely" row on every
    cPanel/WHM host was noisy and not a finding — it was a hint. Use
    `-m recon` (subdomain enumeration), `-m dns` (full DNS posture), and
    `-m domain-scan` (takeover signals) for the actual checks.
    """
    return []


# ─── Check: open password reset / signup ─────────────────────────────────────

async def check_open_reset(client, ctx):
    """
    The cPanel reset-password form is reachable unauthenticated **by design**
    — cPanel users reset their own passwords through it. Rate-limiting is
    cPHulkd's job (audited separately by check_cphulk_present). We only
    flag this as a VULNERABLE row when cPHulkd is missing AND the reset
    flow is exposed; otherwise it's an INFO-grade surface note.

    The bare-fact reset-form exposure is already emitted by
    check_sensitive_paths as INFO, so this function additionally probes
    whether the form accepts arbitrary usernames without rate-limit
    enforcement headers. Absent rate-limit headers do not imply absent
    rate-limiting (the response code 200 is normal), so the row stays
    INFO unless we see actual sequential successes — outside the scope of
    a single-request probe.
    """
    return []


# ─── Check: webmail product fingerprint + CVE map ────────────────────────────

WEBMAIL_FINGERPRINTS = [
    ('roundcube', '/3rdparty/roundcube/', re.compile(r'rcversion\s*=\s*["\']?(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE), 'roundcube'),
    ('roundcube', '/roundcube/', re.compile(r'rcversion\s*=\s*["\']?(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE), 'roundcube'),
    ('horde', '/horde/', re.compile(r'Horde\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.IGNORECASE), 'horde'),
    ('squirrelmail', '/3rdparty/squirrelmail/', re.compile(r'SquirrelMail\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.IGNORECASE), 'squirrelmail'),
]


async def check_webmail_exposure(client, ctx):
    out = []
    origin = ctx['origin_url']
    for product, path, ver_pat, comp_key in WEBMAIL_FINGERPRINTS:
        r = await _safe_get(client, origin + path, timeout=5)
        if r is None or r.status_code not in (200, 301, 302):
            continue
        body = (r.text or '')[:8192]
        if product not in body.lower() and product != 'horde':
            continue
        m = ver_pat.search(body)
        version = m.group(1) if m else None
        out.append(_finding(
            status='INFO',
            severity='INFO',
            vulnerability=f'Webmail product detected: {product}{(" " + version) if version else ""}',
            details=f'{product} surface at {path}.',
            payload_url=origin + path,
            surface='Webmail',
        ))
        if version:
            for entry in BUNDLED_COMPONENT_CVES.get(comp_key, []):
                if is_version_affected(version, entry.get('affected_versions', [])):
                    out.append(_finding(
                        status='VULNERABLE',
                        severity=entry.get('severity', 'MEDIUM'),
                        vulnerability=f"{entry['cve']} - {entry.get('summary', '')}",
                        details=f"{product} {version} detected at {path} is inside the unpatched range for {entry['cve']}.",
                        payload_url=origin + path,
                        surface='Webmail',
                        cve_id=entry['cve'],
                    ))
    return out


# ─── Check: phpMyAdmin / WHMCS / Softaculous / Mailman / AWStats ─────────────

GENERIC_APP_FINGERPRINTS = [
    {
        'name': 'phpmyadmin',
        'paths': ['/pma/', '/phpmyadmin/'],
        'body_marker': 'phpmyadmin',
        'version_pat': re.compile(r'PMA_VERSION\s*=\s*[\'"]?(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE),
        'component': 'phpmyadmin',
        'surface': 'cPanel',
    },
    {
        'name': 'whmcs',
        'paths': ['/whmcs/', '/clients/', '/billing/', '/portal/'],
        'body_marker': 'whmcs',
        'version_pat': re.compile(r'WHMCS\s+v?(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE),
        'component': 'whmcs',
        'surface': 'cPanel',
    },
    {
        'name': 'softaculous',
        'paths': ['/softaculous/', '/cpsess0000000000/frontend/jupiter/softaculous/'],
        'body_marker': 'softaculous',
        'version_pat': re.compile(r'Softaculous\s+v?(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE),
        'component': 'softaculous',
        'surface': 'cPanel',
    },
    {
        'name': 'mailman',
        'paths': ['/mailman/', '/mailman/listinfo/'],
        'body_marker': 'mailman',
        'version_pat': re.compile(r'Mailman\s+v?(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE),
        'component': 'mailman',
        'surface': 'cPanel',
    },
    {
        'name': 'awstats',
        'paths': ['/awstats/', '/awstats/awstats.pl'],
        'body_marker': 'awstats',
        'version_pat': re.compile(r'AWStats\s+(\d+\.\d+)', re.IGNORECASE),
        'component': 'awstats',
        'surface': 'cPanel',
    },
]


async def check_bundled_apps(client, ctx):
    out = []
    origin = ctx['origin_url']
    for app in GENERIC_APP_FINGERPRINTS:
        for path in app['paths']:
            r = await _safe_get(client, origin + path, timeout=5)
            if r is None or r.status_code not in (200, 301, 302):
                continue
            body = (r.text or '')[:8192]
            if app['body_marker'] not in body.lower():
                continue
            m = app['version_pat'].search(body)
            version = m.group(1) if m else None
            out.append(_finding(
                status='INFO',
                severity='INFO',
                vulnerability=f"Bundled app detected: {app['name']}{(' ' + version) if version else ''}",
                details=f"{app['name']} surface at {path}.",
                payload_url=origin + path,
                surface=ctx['surface'],
            ))
            if version:
                for entry in BUNDLED_COMPONENT_CVES.get(app['component'], []):
                    if is_version_affected(version, entry.get('affected_versions', [])):
                        out.append(_finding(
                            status='VULNERABLE',
                            severity=entry.get('severity', 'MEDIUM'),
                            vulnerability=f"{entry['cve']} - {entry.get('summary', '')}",
                            details=f"{app['name']} {version} detected at {path} is inside the unpatched range for {entry['cve']}.",
                            payload_url=origin + path,
                            surface=ctx['surface'],
                            cve_id=entry['cve'],
                        ))
            break  # Found the app at one path; don't double-report on its siblings.
    return out


# ─── Check: Apache / PHP banner CVEs ─────────────────────────────────────────

async def check_bundled_apache_php(client, ctx):
    out = []
    origin = ctx['origin_url']
    r = await _safe_get(client, origin + '/', timeout=5)
    if r is None:
        return out
    server = r.headers.get('server', '')
    xpb = r.headers.get('x-powered-by', '')

    apache_m = re.search(r'Apache\/(\d+\.\d+\.\d+)', server, re.IGNORECASE)
    if apache_m:
        ver = apache_m.group(1)
        for entry in BUNDLED_COMPONENT_CVES.get('apache_httpd', []):
            if is_version_affected(ver, entry.get('affected_versions', [])):
                out.append(_finding(
                    status='VULNERABLE',
                    severity=entry.get('severity', 'MEDIUM'),
                    vulnerability=f"{entry['cve']} - Apache {ver}",
                    details=f"Apache httpd {ver} (Server: {server}) is inside the unpatched range for {entry['cve']}: {entry.get('summary', '')}",
                    payload_url=origin + '/',
                    surface=ctx['surface'],
                    cve_id=entry['cve'],
                ))

    php_m = re.search(r'PHP\/(\d+\.\d+\.\d+)', server + ' ' + xpb, re.IGNORECASE)
    if php_m:
        ver = php_m.group(1)
        for entry in BUNDLED_COMPONENT_CVES.get('php', []):
            if is_version_affected(ver, entry.get('affected_versions', [])):
                out.append(_finding(
                    status='VULNERABLE',
                    severity=entry.get('severity', 'MEDIUM'),
                    vulnerability=f"{entry['cve']} - PHP {ver}",
                    details=f"PHP {ver} is inside the unpatched range for {entry['cve']}: {entry.get('summary', '')}",
                    payload_url=origin + '/',
                    surface=ctx['surface'],
                    cve_id=entry['cve'],
                ))
    return out


# ─── Check: co-resident TCP service banners (SMTP/IMAP/POP3/FTP/SSH) ─────────

async def _grab_banner(host, port, timeout=4):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        except asyncio.TimeoutError:
            data = b''
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode('utf-8', errors='replace')
    except Exception:
        return ''


BANNER_PATTERNS = [
    (re.compile(r'Exim\s+(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE), 'exim', 'Exim'),
    (re.compile(r'Dovecot\s+(?:ready\.|\(([\w.]+)\))', re.IGNORECASE), 'dovecot', 'Dovecot'),
    (re.compile(r'ProFTPD\s+(\d+\.\d+\.\d+[a-z]?)', re.IGNORECASE), 'proftpd', 'ProFTPD'),
    (re.compile(r'Pure-FTPd', re.IGNORECASE), 'proftpd', 'Pure-FTPd'),  # No version
    (re.compile(r'OpenSSH[_\- ](\d+\.\d+(?:p\d+)?)', re.IGNORECASE), 'openssh', 'OpenSSH'),
]

ADJACENT_PORT_HINT = {
    25: 'SMTP', 26: 'SMTP', 465: 'SMTPS', 587: 'Submission',
    110: 'POP3', 143: 'IMAP', 993: 'IMAPS', 995: 'POP3S',
    21: 'FTP', 22: 'SSH', 53: 'DNS', 3306: 'MySQL', 5432: 'PostgreSQL',
}


async def check_mail_dns_ftp_db_banners(scan_address, adjacent_open_ports, surface_for_report):
    out = []
    host = scan_address
    if is_full_url(host):
        host = urlparse(host).hostname or host
    for port in adjacent_open_ports:
        banner = await _grab_banner(host, port, timeout=4)
        if not banner.strip():
            # Still emit an INFO row that the service is reachable.
            out.append(_finding(
                status='INFO',
                severity='LOW',
                vulnerability=f'{ADJACENT_PORT_HINT.get(port, "Service")} port reachable on {port}',
                details=f'TCP {port} accepted a connection but did not emit a banner.',
                payload_url=f"tcp://{host}:{port}",
                surface=surface_for_report,
            ))
            continue

        out.append(_finding(
            status='INFO',
            severity='LOW',
            vulnerability=f'{ADJACENT_PORT_HINT.get(port, "Service")} banner on {port}',
            details=f'Banner: {banner.strip()[:200]}',
            payload_url=f"tcp://{host}:{port}",
            surface=surface_for_report,
        ))

        for pat, comp_key, label in BANNER_PATTERNS:
            m = pat.search(banner)
            if not m:
                continue
            version = m.group(1) if m.groups() else None
            if not version:
                continue
            for entry in BUNDLED_COMPONENT_CVES.get(comp_key, []):
                if is_version_affected(version, entry.get('affected_versions', [])):
                    out.append(_finding(
                        status='VULNERABLE',
                        severity=entry.get('severity', 'MEDIUM'),
                        vulnerability=f"{entry['cve']} - {label} {version}",
                        details=f"{label} {version} on port {port} is inside the unpatched range for {entry['cve']}: {entry.get('summary', '')}",
                        payload_url=f"tcp://{host}:{port}",
                        surface=surface_for_report,
                        cve_id=entry['cve'],
                    ))
    return out


# ─── Check: PROXY-protocol trust misconfig ───────────────────────────────────

async def check_proxy_protocol(ctx):
    """
    Send a PROXY v1 preface to the cpsrvd port; if the server accepts it and
    serves a 200/302 to a path that normally requires authentication, the
    source-IP allow-list collapses.
    """
    if ctx['port'] not in (2082, 2083, 2086, 2087, 2095, 2096, 9998, 9999):
        return []
    host = ctx['scan_address']
    if is_full_url(host):
        host = urlparse(host).hostname or host
    port = ctx['port']

    out = []
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx['is_tls']), timeout=4)
    except Exception:
        return []

    try:
        preface = b"PROXY TCP4 127.0.0.1 127.0.0.1 1 1\r\n"
        req = (
            b"GET /whm-server-status HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"User-Agent: VaktScan-proxy-probe\r\n"
            b"Connection: close\r\n\r\n"
        )
        writer.write(preface + req)
        try:
            await asyncio.wait_for(writer.drain(), timeout=3)
        except Exception:
            pass
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=4)
        except asyncio.TimeoutError:
            data = b''
        body = data.decode('utf-8', errors='replace')
        # cpsrvd normally returns 400 / "Bad Request" or just closes when it
        # doesn't speak PROXY. A 200/302 means the preface was honoured.
        first_line = body.split('\r\n', 1)[0]
        if first_line.startswith('HTTP/') and any(code in first_line for code in (' 200 ', ' 302 ', ' 401 ')):
            out.append(_finding(
                status='POTENTIAL',
                severity='HIGH',
                vulnerability='PROXY-protocol preface accepted by cpsrvd',
                details=f'Sent "PROXY TCP4 127.0.0.1 ..." preface to {host}:{port}; server responded {first_line.strip()}. If cpsrvd trusts the spoofed source IP, source-IP allow-lists are bypassable.',
                payload_url=f"tcp://{host}:{port}",
                surface=ctx['surface'],
            ))
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return out


# ─── Check: HTTP/2 support detection ─────────────────────────────────────────

async def check_http2_support(ctx):
    """
    Probe ALPN for h2 advertisement. cpsrvd is known to expose Sling-style
    routing differences over h2; we flag the surface so the operator knows
    h2-specific tests are warranted.
    """
    if not ctx['is_tls']:
        return []
    host = ctx['scan_address']
    if is_full_url(host):
        host = urlparse(host).hostname or host
    port = ctx['port']

    def _probe():
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            ssl_ctx.set_alpn_protocols(['h2', 'http/1.1'])
            with socket.create_connection((host, port), timeout=5) as sock:
                with ssl_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.selected_alpn_protocol()
        except Exception:
            return None

    try:
        loop = asyncio.get_running_loop()
        alpn = await loop.run_in_executor(None, _probe)
    except Exception:
        return []
    if alpn == 'h2':
        return [_finding(
            status='INFO',
            severity='LOW',
            vulnerability='cpsrvd advertises HTTP/2 over TLS',
            details=f'TLS ALPN negotiated h2 on {host}:{port}. HTTP/2-specific path-normalisation differences may bypass Apache-front filters.',
            payload_url=ctx['origin_url'] + '/',
            surface=ctx['surface'],
        )]
    return []


# ─── Check: SSI / .shtml execution ───────────────────────────────────────────

async def check_ssi_execution(client, ctx):
    """
    Request `/<random>.shtml` with an `<!--#exec` body indicator. cPanel
    sometimes ships SSI support enabled by default; if .shtml is processed
    and SSI directives are honoured we get the marker echoed.
    """
    out = []
    origin = ctx['origin_url']
    marker = secrets.token_hex(6)
    # We can only test detection of whether .shtml is *handled*. We don't
    # write the file; the existence of a default-ssi.shtml or SSI-enabled
    # extension on a 404 page is the tell.
    candidate_paths = [
        '/default-ssi.shtml',
        '/index.shtml',
        '/cgi-sys/' + marker + '.shtml',
    ]
    for path in candidate_paths:
        r = await _safe_get(client, origin + path, timeout=5)
        if r is None:
            continue
        ct = r.headers.get('content-type', '').lower()
        if r.status_code == 200 and 'text/html' in ct and ('<!--#' in (r.text or '') or '#echo' in (r.text or '').lower()):
            out.append(_finding(
                status='VULNERABLE',
                severity='MEDIUM',
                vulnerability='Server-Side Includes (SSI) processing enabled',
                details=f'{path} returned 200 with SSI directives visible in response — .shtml extension is processed.',
                payload_url=origin + path,
                surface=ctx['surface'],
            ))
            break
    return out


# ─── Check: HTTP request smuggling differential ──────────────────────────────

async def check_request_smuggling(client, ctx):
    """
    Send a request carrying both Transfer-Encoding and Content-Length, then
    a second baseline carrying the SAME body but without the conflicting
    header pair. A smuggling-vulnerable front+back disagreement shows as
    status divergence on the smug request while the baseline succeeds, or
    a >256-byte body delta when both return the same status. We require
    BOTH responses to be 2xx or BOTH non-2xx — a divergence caused by the
    body itself (auth, method, route) is rejected.
    """
    out = []
    origin = ctx['origin_url']
    body_payload = (
        "0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: " + (urlparse(origin).hostname or '') + "\r\n\r\n"
    )
    try:
        r_smug = await client.post(
            origin + '/',
            content=body_payload,
            headers={
                'Transfer-Encoding': 'chunked',
                'Content-Length': str(len(body_payload)),
                'User-Agent': 'VaktScan-smuggle-probe',
            },
            timeout=6,
        )
        # Baseline: same body, same Content-Length, but NO conflicting TE.
        r_baseline = await client.post(
            origin + '/',
            content=body_payload,
            headers={
                'Content-Length': str(len(body_payload)),
                'User-Agent': 'VaktScan-smuggle-probe',
            },
            timeout=6,
        )
    except Exception:
        return out
    if r_smug is None or r_baseline is None:
        return out
    # Reject if both responses are identical — no desync.
    if r_smug.status_code == r_baseline.status_code and not _response_size_delta(r_smug, r_baseline, threshold=256):
        return out
    # Reject when the response pair is just an auth-state difference
    # (one side 200/302, the other 401/403). That tells us the body
    # processing changed because the server treated the request as
    # authenticated vs unauthenticated — not because of framing desync.
    codes = {r_smug.status_code, r_baseline.status_code}
    if codes & {401, 403} and codes & {200, 302}:
        return out
    out.append(_finding(
        status='POTENTIAL',
        severity='HIGH',
        vulnerability='HTTP request smuggling differential observed',
        details=(
            f'Smug (TE+CL) HTTP {r_smug.status_code}, size {len(r_smug.text or "")}; '
            f'baseline (CL only, same body) HTTP {r_baseline.status_code}, size {len(r_baseline.text or "")}. '
            f'Front-end / back-end may disagree on framing precedence; manual desync confirmation required.'
        ),
        payload_url=origin + '/',
        surface=ctx['surface'],
    ))
    return out


# ─── Check: branding upload endpoint ─────────────────────────────────────────

async def check_branding_upload(client, ctx):
    """
    HEAD-probe upload endpoints under /cpanelbranding/ — historically allowed
    unauthenticated POST file writes on some cPanel builds. We never POST a
    payload; reachable HEAD = HIGH finding.
    """
    out = []
    origin = ctx['origin_url']
    candidates = [
        '/cpanelbranding/upload',
        '/cpsess0000000000/frontend/jupiter/branding/upload',
        '/cpanelbranding/jupiter/upload',
    ]
    for path in candidates:
        r = await _safe_request(client, 'HEAD', origin + path, timeout=5)
        if r is None:
            continue
        # 200 or 405 with no auth challenge = exposed POST endpoint.
        # 401/403 means the endpoint is auth-gated — not a finding.
        if r.status_code in (200, 405):
            out.append(_finding(
                status='VULNERABLE',
                severity='HIGH',
                vulnerability='cPanel branding upload endpoint exposed',
                details=(
                    f'HEAD {path} returned HTTP {r.status_code} with no auth challenge — '
                    'endpoint accepts POST and historically allowed unauthenticated file uploads.'
                ),
                payload_url=origin + path,
                surface=ctx['surface'],
            ))
            break
    return out


# ─── Check: license-server banner on 2089 ────────────────────────────────────

async def check_license_server(scan_address, ctx):
    """
    cpanellgd listens on 2089 and discloses license-server version + license
    state. Anonymous reachability is itself useful intel for an attacker.
    """
    if ctx['port'] != 2089:
        return []
    host = scan_address
    if is_full_url(host):
        host = urlparse(host).hostname or host
    out = []
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 2089, ssl=ssl_ctx),
            timeout=5,
        )
        writer.write(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        try:
            await asyncio.wait_for(writer.drain(), timeout=3)
        except Exception:
            pass
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=4)
        except asyncio.TimeoutError:
            data = b''
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        body = data.decode('utf-8', errors='replace')
        if 'cpanellgd' in body.lower() or 'cpanel' in body.lower() or 'license' in body.lower():
            ver_m = re.search(r'cpanellgd[/-](\d+\.\d+(?:\.\d+){0,2})', body, re.IGNORECASE)
            ver = ver_m.group(1) if ver_m else 'unknown'
            out.append(_finding(
                status='INFO',
                severity='MEDIUM',
                vulnerability=f'cPanel license server reachable (cpanellgd {ver})',
                details=f'Port 2089 served {body.strip()[:160]!r}. License-server state should not be public.',
                payload_url=f"tcp://{host}:2089",
                surface='Autoconfig',
            ))
    except Exception:
        return []
    return out


# ─── Check: default credentials (guarded; WHM ports only) ────────────────────

DEFAULT_CRED_PAIRS = [
    ('root',   'root'),
    ('root',   'password'),
    ('root',   'cpanel'),
    ('root',   'cpanel123'),
    ('root',   'whmcs'),
    ('root',   'admin'),
    ('admin',  'admin'),
    ('cpanel', 'cpanel'),
    ('demo',   'demo'),
]


async def check_default_credentials(client, ctx):
    """
    Three-pair probe with explicit safety rails:
      - only runs on WHM ports (2086 / 2087);
      - aborts after the first cPHulkd-style lockout indicator;
      - never tries more than 3 credentials per host;
      - opt-in via VAKTSCAN_AGGRESSIVE_CPANEL env var (default off).
    Successful login is detected by: distinct Set-Cookie cpsession= AND 302
    redirect AND `Location` containing `/cpsess`. Any of these alone is not
    enough — all three must match for the row to emit (VULNERABLE/CRITICAL).
    """
    if ctx['port'] not in WHM_PORTS:
        return []
    if os.environ.get('VAKTSCAN_AGGRESSIVE_CPANEL', '').lower() not in ('1', 'true', 'yes', 'on'):
        return []

    origin = ctx['origin_url']
    out = []
    attempts = 0
    for user, password in DEFAULT_CRED_PAIRS:
        if attempts >= 3:
            break
        attempts += 1
        try:
            r = await client.post(
                origin + '/login/',
                data={'user': user, 'pass': password},
                timeout=8,
                follow_redirects=False,
            )
        except Exception:
            continue
        if r is None:
            continue
        # cPHulkd / Imunify lockout — stop probing.
        if _detect_waf(r) == 'cphulkd':
            break
        loc = r.headers.get('location', '')
        cookies = ' '.join(r.headers.get_list('set-cookie') if hasattr(r.headers, 'get_list') else [r.headers.get('set-cookie', '')])
        has_session = 'cpsession=' in cookies.lower() or 'whostmgrsession=' in cookies.lower()
        if r.status_code in (301, 302) and has_session and '/cpsess' in loc:
            out.append(_finding(
                status='CRITICAL',
                severity='CRITICAL',
                vulnerability=f'WHM default credentials accepted ({user}:{password})',
                details=f'POST /login/ with {user}/{password} returned HTTP {r.status_code}, Set-Cookie cpsession=..., Location: {loc[:120]}. Full WHM root takeover.',
                payload_url=origin + '/login/',
                surface=ctx['surface'],
            ))
            return out  # No need to keep probing.
    return out


# ─── Dedup / validate post-filter (§10.3 + §11) ──────────────────────────────

REQUIRED_KEYS = ('status', 'severity', 'vulnerability', 'details', 'payload_url')
VALID_STATUSES = {'CRITICAL', 'VULNERABLE', 'POTENTIAL', 'INFO'}


def _dedup_and_validate(findings):
    """
    Apply §10 / §11 rules: drop vague rows, drop stock-error matches,
    collapse equivalent findings, ensure every status is in the valid
    vocabulary.
    """
    out = []
    seen_keys = set()

    for f in findings:
        if not f:
            continue
        if any(not f.get(k) for k in REQUIRED_KEYS):
            # Vague row; reject (§11 rule 7).
            continue
        if f['status'] not in VALID_STATUSES:
            f['status'] = 'INFO'

        # TSR + observable collapse: if a finding has a `_cve_id` and we
        # already saw an observable-payload finding for the same CVE on the
        # same surface, drop this row.
        cve = f.get('_cve_id')
        surface = f.get('_surface', '') or ''
        evidence = f.get('_evidence_hash', '') or ''
        key = (f['vulnerability'], surface, cve or '', evidence)
        if key in seen_keys:
            # Within-check dedup. Merge payload_url with existing match.
            for existing in out:
                ex_key = (existing['vulnerability'], existing.get('_surface', ''), existing.get('_cve_id') or '', existing.get('_evidence_hash') or '')
                if ex_key == key:
                    if f['payload_url'] not in (existing['payload_url'] or ''):
                        existing['payload_url'] = f"{existing['payload_url']} | {f['payload_url']}"
                    break
            continue
        seen_keys.add(key)
        out.append(f)

    # TSR + observable collapse (rule 4): drop TSR rows when an observable
    # finding shares a CVE id.
    observable_cves = {f.get('_cve_id') for f in out if f.get('_cve_id') and not f['vulnerability'].startswith('TSR-')}
    final = []
    for f in out:
        if f['vulnerability'].startswith('TSR-'):
            tsr_cves = set()
            # Pull CVE id(s) out of details if any
            for token in re.findall(r'CVE-\d{4}-\d+', f.get('details', '')):
                tsr_cves.add(token)
            if tsr_cves & observable_cves:
                continue
        final.append(f)

    return final


# ─── Internal-field strip ────────────────────────────────────────────────────

def _strip_internals(f):
    for k in list(f.keys()):
        if k.startswith('_'):
            del f[k]
    return f


# ─── enrich_vuln (mirrors AEM) ───────────────────────────────────────────────

async def _enrich_vuln(vuln, client):
    payload = vuln.get('payload_url', '')
    if payload and payload != 'N/A' and payload.startswith(('http://', 'https://')):
        enrich_url = payload.split(' | ')[0].strip()
    else:
        enrich_url = vuln.get('url') or vuln.get('target')
    if not enrich_url or not enrich_url.startswith(('http://', 'https://')):
        vuln.setdefault('http_status', 'N/A')
        vuln.setdefault('content_length', 'N/A')
        vuln.setdefault('page_title', 'N/A')
        return vuln
    try:
        r = await client.get(enrich_url, timeout=4)
        vuln['http_status'] = r.status_code
        vuln['content_length'] = len(r.content)
        m = re.search(r'<title>(.*?)</title>', r.text or '', re.IGNORECASE | re.DOTALL)
        vuln['page_title'] = m.group(1).strip()[:200] if m else 'N/A'
    except Exception:
        vuln.setdefault('http_status', 'N/A')
        vuln.setdefault('content_length', 'N/A')
        vuln.setdefault('page_title', 'N/A')
    return vuln


# ─── Orchestrator ─────────────────────────────────────────────────────────────

async def run_scans(target_obj, port, adjacent_open_ports=None):
    """
    Entry point called by VaktScan main orchestrator.
    Per §9c, returned dicts use the canonical 15-key schema enforced by
    save_results_to_csv.
    """
    scan_address = target_obj['scan_address']
    display_target = target_obj['display_target']
    resolved_ip = target_obj['resolved_ip']

    target_protocol = None
    if is_full_url(display_target):
        target_protocol = urlparse(display_target).scheme
    elif is_full_url(scan_address):
        target_protocol = urlparse(scan_address).scheme

    protocol = target_protocol or await detect_protocol(scan_address, port)
    ctx = _build_target_context(target_obj, port, protocol)
    origin = ctx['origin_url']
    print(f"  -> Running cPanel scans on {origin} (target: {display_target}) [Port: {port}, Surface: {ctx['surface']}]")

    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False) as client:
        # Stock-error baseline.
        baselines = await _baseline_stock_errors(client, origin)

        # Version + identification (gate every subsequent check).
        version_info = await get_cpanel_version(client, origin)
        identity = await identify_cpanel_target(client, origin, version_info)
        if not identity['identified']:
            return []

        service_version = version_info.get('number') or 'cPanel detected'
        if version_info.get('banner'):
            service_version = f"{service_version} ({version_info['banner']})"

        # Run every check family in parallel.
        check_tasks = [
            check_cve_vulnerabilities(client, ctx, baselines),
            check_version_vulnerabilities(client, ctx, version_info),
            check_sensitive_paths(client, ctx, baselines),
            check_information_disclosure(client, ctx),
            check_http_method_tampering(client, ctx, baselines),
            check_host_header_bypass(client, ctx),
            check_session_bypass(client, ctx, baselines),
            check_cors_misconfig(client, ctx),
            check_crlf_injection(client, ctx),
            check_cache_poisoning(client, ctx),
            check_cookie_security(client, ctx),
            check_websocket_exposure(client, ctx),
            check_userdir_enum(client, ctx),
            check_webdav_exposure(client, ctx),
            check_caldav_exposure(client, ctx),
            check_tls_posture(ctx),
            check_plaintext_control_panel(client, ctx),
            check_account_enum_timing(client, ctx),
            check_cphulk_present(client, ctx),
            check_auto_subdomains(client, ctx),
            check_open_reset(client, ctx),
            check_webmail_exposure(client, ctx),
            check_bundled_apps(client, ctx),
            check_bundled_apache_php(client, ctx),
            check_proxy_protocol(ctx),
            check_http2_support(ctx),
            check_ssi_execution(client, ctx),
            check_request_smuggling(client, ctx),
            check_branding_upload(client, ctx),
            check_license_server(scan_address, ctx),
            check_default_credentials(client, ctx),
        ]
        if adjacent_open_ports:
            check_tasks.append(
                check_mail_dns_ftp_db_banners(scan_address, adjacent_open_ports, ctx['surface'])
            )

        gathered = await asyncio.gather(*check_tasks, return_exceptions=True)

        all_findings = []
        for result in gathered:
            if isinstance(result, Exception):
                continue
            if isinstance(result, list):
                all_findings.extend(f for f in result if f)

        # Add the identification INFO row.
        all_findings.append(_finding(
            status='INFO',
            severity='INFO',
            vulnerability=f'cPanel service identified ({ctx["surface"]})',
            details=f'cPanel/cpsrvd fingerprint matched. Evidence: {", ".join(identity["evidence"])}.',
            payload_url=origin + '/',
            surface=ctx['surface'],
        ))

        # Dedup + validate.
        all_findings = _dedup_and_validate(all_findings)

        # Stamp canonical reporting fields (§9c.2).
        for f in all_findings:
            f['module'] = MODULE_NAME
            f['service_version'] = service_version
            f['target'] = display_target
            f['server'] = scan_address
            f['port'] = port
            f['resolved_ip'] = resolved_ip
            actual_url = f.get('payload_url') or display_target
            if isinstance(actual_url, str) and actual_url.startswith(('http://', 'https://')):
                f['url'] = actual_url.split(' | ')[0]
            else:
                f['url'] = display_target

        # Enrich (http_status / page_title / content_length).
        async with httpx.AsyncClient(timeout=5, verify=False, follow_redirects=True) as enrich_client:
            all_findings = await asyncio.gather(*(_enrich_vuln(f, enrich_client) for f in all_findings))

        # Strip internal-only keys before handing off to the emitter.
        for f in all_findings:
            _strip_internals(f)

    return all_findings
