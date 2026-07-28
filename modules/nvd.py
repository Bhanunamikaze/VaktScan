"""
NVD API 2.0 CVE lookup utility.

Usage:
    findings = await lookup_cves(product="elasticsearch", version="7.9.0")
    # Returns list of canonical finding dicts (INFO/POTENTIAL severity)
"""

import asyncio
import json
import os
import re
import httpx
from datetime import datetime

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_API_KEY = os.environ.get("NVD_API_KEY", "")

# Local, offline-first CVE index built by scripts/update_cve_db.py. Keyed by
# "<vendor>:<product>" (the same key lookup_cves() computes below) -> list of
# {cve, cvss, severity, affected_versions, summary}. Queried BEFORE any network
# call. Missing / unreadable / corrupt -> fail-open to the live NVD API.
NVD_CVE_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "nvd_cve_db.json")
_LOCAL_DB_CACHE: dict = {}  # resolved path -> index dict (or None if unusable)

# Known product→CPE vendor mappings (expand as needed)
CPE_VENDOR_MAP = {
    "elasticsearch": "elastic",
    "kibana":        "elastic",
    "grafana":       "grafana",
    "prometheus":    "prometheus",
    "jenkins":       "jenkins",
    "gitlab":        "gitlab",
    "jira":          "atlassian",
    "confluence":    "atlassian",
    "sonarqube":     "sonarsource",
    "consul":        "hashicorp",
    "vault":         "hashicorp",
    "tomcat":        "apache",
    "spring":        "pivotal_software",
    "traefik":       "traefik",
    "portainer":     "portainer",
    "minio":         "minio",
    "redis":         "redis",
    "mongodb":       "mongodb",
    "postgresql":    "postgresql",
    "mysql":         "oracle",
    "docker":        "docker",
    "kubernetes":    "kubernetes",
    "openssh":       "openbsd",
    "dropbear":      "dropbear",
    "vsftpd":        "vsftpd",
    "proftpd":       "proftpd",
    "pure-ftpd":     "pureftpd",
    "http_server":   "apache",
    "nginx":         "nginx",
    "iis":           "microsoft",
    # Common web-layer server/framework products (fed by modules/web_tech_cve.py
    # from Server / X-Powered-By headers and webanalyze detections).
    "php":           "php",
    "openssl":       "openssl",
    "lighttpd":      "lighttpd",
    "jetty":         "eclipse",
}


# ── Version-range matching (offline, conservative) ─────────────────────────────
# A detected version is affected only if it satisfies an actual stored range.
# We never emit a CVE whose range does not include the detected version.

_VERSION_NUM_RE = re.compile(r"^[vV]?(\d+(?:\.\d+)*)(.*)$")
_CONSTRAINT_OPS = (">=", "<=", "==", ">", "<")


def _parse_version(v: str) -> tuple[tuple[int, ...], str]:
    """Split a version into (numeric-tuple, lowercase-suffix).

    '1.0.2k' -> ((1, 0, 2), 'k'); '8.2p1' -> ((8, 2), 'p1'). The suffix is a
    tiebreaker used only when the numeric parts are equal, so a bare release
    (no suffix) sorts BEFORE the same release with a suffix ('1.0.2' < '1.0.2k').
    """
    v = (v or "").strip().lower()
    m = _VERSION_NUM_RE.match(v)
    if not m:
        return ((0,), v)
    nums = tuple(int(x) for x in m.group(1).split("."))
    suffix = m.group(2).strip(" .-_")
    return (nums, suffix)


def _compare_versions(v1: str, v2: str) -> int:
    """Return -1/0/1 comparing two version strings (numeric parts first)."""
    n1, s1 = _parse_version(v1)
    n2, s2 = _parse_version(v2)
    ln = max(len(n1), len(n2))
    n1 = n1 + (0,) * (ln - len(n1))
    n2 = n2 + (0,) * (ln - len(n2))
    if n1 < n2:
        return -1
    if n1 > n2:
        return 1
    if s1 == s2:
        return 0
    if not s1:
        return -1
    if not s2:
        return 1
    return -1 if s1 < s2 else 1


def _constraint_holds(version: str, constraint: str) -> bool:
    """True if `version` satisfies a single constraint like '>=1.0' or '<2.0'.

    A bare version (no operator) is treated as an exact-match ('==')."""
    constraint = constraint.strip()
    if not constraint:
        return True
    op = "=="
    ver = constraint
    for cand in _CONSTRAINT_OPS:
        if constraint.startswith(cand):
            op = cand
            ver = constraint[len(cand):].strip()
            break
    if not ver:
        return True
    c = _compare_versions(version, ver)
    if op == ">=":
        return c >= 0
    if op == ">":
        return c > 0
    if op == "<=":
        return c <= 0
    if op == "<":
        return c < 0
    return c == 0


def _version_affected(version: str, ranges) -> bool:
    """True if `version` satisfies ANY expression in `ranges`.

    Each expression is a comma-joined conjunction of constraints, e.g.
    '>=1.0,<2.0' (>=1.0 AND <2.0) or a lone '<3.0' or an exact '==1.2.3'.
    Conservative: an empty version or empty range list -> False, so an entry
    with no version bound never matches every version.
    """
    if not version or not ranges:
        return False
    try:
        for expr in ranges:
            if not expr:
                continue
            if all(_constraint_holds(version, part) for part in str(expr).split(",")):
                return True
    except Exception:
        return False
    return False


# ── Local NVD index (offline-first) ─────────────────────────────────────────────

def _load_local_db(path: str | None = None):
    """Load the offline NVD index. Returns the {"vendor:product": [entries]}
    mapping, or None if the DB is missing / unreadable / corrupt (in which case
    the caller falls back to the live API). Cached per resolved path.
    """
    p = path or NVD_CVE_DB_PATH
    if p in _LOCAL_DB_CACHE:
        return _LOCAL_DB_CACHE[p]
    db = None
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        idx = data.get("index") if isinstance(data, dict) else None
        if isinstance(idx, dict):
            db = idx
    except Exception:
        db = None
    _LOCAL_DB_CACHE[p] = db
    return db


def _make_finding(cve_id: str, cvss_score, severity: str, desc: str,
                  product: str, version: str, target: str, resolved_ip: str,
                  port) -> dict:
    """Build a canonical NVD finding dict. Shared by the offline and live paths
    so both emit byte-for-byte identical shapes (callers must not care which
    path produced a finding).
    """
    try:
        cvss_score = float(cvss_score or 0)
    except (TypeError, ValueError):
        cvss_score = 0.0
    severity = (severity or "INFO").upper()
    status = "CRITICAL" if cvss_score >= 9.0 else "VULNERABLE" if cvss_score >= 7.0 else "POTENTIAL"
    port_s = str(port)
    ref = (f"nvd://{target}:{port_s}/{cve_id}"
           if port and port_s != "N/A" else f"nvd://{target}/{cve_id}")
    return {
        "status":          status,
        "severity":        severity,
        "vulnerability":   f"{cve_id} - {product} {version}",
        "target":          target,
        "resolved_ip":     resolved_ip,
        "port":            port_s,
        "url":             ref,
        "payload_url":     ref,
        "module":          "nvd",
        "service_version": version,
        "details":         f"CVSS {cvss_score:.1f} ({severity}). {desc[:300]} Reference: https://nvd.nist.gov/vuln/detail/{cve_id}",
        "http_status":     "N/A",
        "page_title":      "N/A",
        "content_length":  "N/A",
        "timestamp":       datetime.utcnow().isoformat() + "Z",
    }


def _lookup_local(entries, product: str, version: str, target: str,
                  resolved_ip: str, port, min_cvss: float) -> list[dict]:
    """Match a detected version against the local entries for a product.
    Applies the same CVSS>=min_cvss filter as the live path. No network."""
    findings: list[dict] = []
    seen: set[str] = set()
    for e in entries or []:
        cve_id = e.get("cve", "")
        if not cve_id or cve_id in seen:
            continue
        try:
            cvss_score = float(e.get("cvss", 0) or 0)
        except (TypeError, ValueError):
            cvss_score = 0.0
        if cvss_score < min_cvss:
            continue
        if not _version_affected(version, e.get("affected_versions") or []):
            continue
        seen.add(cve_id)
        findings.append(_make_finding(
            cve_id, cvss_score, e.get("severity", "INFO"),
            e.get("summary", "") or "", product, version,
            target, resolved_ip, port))
    return findings


async def lookup_cves(
    product: str,
    version: str,
    target: str = "N/A",
    resolved_ip: str = "N/A",
    port: str = "N/A",
    min_cvss: float = 7.0,
    timeout: float = 10.0,
) -> list[dict]:
    """
    Look up CVEs for a product+version.

    Local-first: the offline index (modules/data/nvd_cve_db.json) is consulted
    before any network call. If the product/vendor is covered locally the answer
    is returned offline and instantly - even when that answer is [] (a covered
    product on a non-vulnerable version). Only products/vendors NOT in the local
    DB (or a missing/corrupt DB) fall through to the live NVD API 2.0.

    Returns canonical finding dicts for CVEs with CVSS >= min_cvss.
    Returns [] if version is unknown/N/A or the API is unreachable.
    """
    if not version or version in ("Unknown", "N/A", "unknown"):
        return []

    product_lower = product.lower()
    vendor = CPE_VENDOR_MAP.get(product_lower, product_lower)

    # --- Local-first: answer offline when the product is in the vendored index.
    key = f"{vendor}:{product_lower}"
    local_db = _load_local_db()
    if local_db is not None and key in local_db:
        return _lookup_local(local_db[key], product, version,
                             target, resolved_ip, port, min_cvss)

    # --- Fallback: live NVD API 2.0 (product not in the local DB, or DB is
    #     missing/corrupt). Behaviour is identical to the pre-DB code path.
    # Build CPE 2.3 string
    cpe = f"cpe:2.3:a:{vendor}:{product_lower}:{version}:*:*:*:*:*:*:*"

    headers = {}
    if _API_KEY:
        headers["apiKey"] = _API_KEY

    findings = []
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            # Try CPE lookup first
            resp = await client.get(NVD_BASE, params={
                "cpeName": cpe,
                "resultsPerPage": 20,
            })
            if resp.status_code != 200:
                # Fallback: keyword search
                resp = await client.get(NVD_BASE, params={
                    "keywordSearch": f"{product} {version}",
                    "resultsPerPage": 20,
                })
            if resp.status_code != 200:
                return []

            data = resp.json()
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")

                # Get CVSS score
                metrics = cve_data.get("metrics", {})
                cvss_score = 0.0
                severity = "INFO"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        entry = metrics[key][0]
                        cvss_data = entry.get("cvssData", {})
                        cvss_score = float(cvss_data.get("baseScore", 0))
                        severity = cvss_data.get("baseSeverity", "INFO").upper()
                        break

                if cvss_score < min_cvss:
                    continue

                # Get description
                descriptions = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                findings.append(_make_finding(
                    cve_id, cvss_score, severity, desc,
                    product, version, target, resolved_ip, port))

    except Exception as e:
        # NVD API is best-effort - never crash the scan if it's unreachable
        print(f"  [!] NVD lookup failed for {product} {version}: {e}")

    return findings


def extract_product_and_version(finding: dict) -> tuple[str, str]:
    """
    Extract product name and version from a finding.
    First checks if service_version is present. If not, parses details for banners.
    Returns (product, version) or ('', '').
    """
    # A finding whose vulnerability field IS a CVE id (js_cve, nvd, web_tech_cve,
    # nuclei CVE templates, nmap vulners) already names its CVE - re-looking it up
    # against NVD would duplicate the CVE and waste API calls. Skip it.
    if re.match(r"\s*CVE-\d{4}-\d{3,7}", finding.get("vulnerability", ""), re.IGNORECASE):
        return "", ""

    version = finding.get("service_version", "")
    if version in ("Unknown", "N/A", "unknown"):
        version = ""

    module = finding.get("module", "").lower()
    vuln = finding.get("vulnerability", "").lower()
    details = finding.get("details", "")
    port = str(finding.get("port", ""))

    product = finding.get("product", "")
    if product:
        return product, version

    # Try to parse banners or names
    # 1. SSH
    if "ssh" in vuln or port == "22":
        match = re.search(r'openssh[_-]([0-9.a-z\-]+)', details, re.IGNORECASE)
        if match:
            return "openssh", match.group(1)
        match_db = re.search(r'dropbear[_-]([0-9.]+)', details, re.IGNORECASE)
        if match_db:
            return "dropbear", match_db.group(1)
        if not version:
            match_generic = re.search(r'ssh[-_](([0-9.]+)[^\s]*)', details, re.IGNORECASE)
            if match_generic:
                return "ssh", match_generic.group(1)
        return "ssh", version

    # 2. FTP
    if "ftp" in vuln or port == "21":
        match_vs = re.search(r'vsftpd\s*([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match_vs:
            return "vsftpd", match_vs.group(1)
        match_pro = re.search(r'proftpd\s*([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match_pro:
            return "proftpd", match_pro.group(1)
        match_pure = re.search(r'pure-ftpd\s*([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match_pure:
            return "pure-ftpd", match_pure.group(1)
        return "ftp", version

    # 3. MySQL
    if "mysql" in vuln or port == "3306":
        if not version:
            match = re.search(r'(\d+\.\d+\.\d+)', details)
            if match:
                version = match.group(1)
        return "mysql", version

    # 4. Redis
    if "redis" in vuln or port == "6379":
        if not version:
            match = re.search(r'(?:version|redis_version):(\S+)', details, re.IGNORECASE)
            if match:
                version = match.group(1)
        return "redis", version

    # 5. Tomcat
    if "tomcat" in vuln or port in ("8080", "8443"):
        match = re.search(r'tomcat/([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match:
            return "tomcat", match.group(1)

    # 6. Apache httpd
    if "apache" in details.lower() or "apache" in vuln:
        match = re.search(r'apache/([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match:
            return "http_server", match.group(1)

    # 7. Nginx
    if "nginx" in details.lower() or "nginx" in vuln:
        match = re.search(r'nginx/([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match:
            return "nginx", match.group(1)

    # 8. IIS
    if "microsoft-iis" in details.lower() or "iis" in vuln:
        match = re.search(r'microsoft-iis/([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match:
            return "iis", match.group(1)

    if module != "servicerecon":
        return module, version

    return "", version
