import httpx
import re
import os
import json
import time
from datetime import datetime

MODULE_NAME = 'CISA-KEV'
_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
_CACHE_FILE = os.path.join(os.path.dirname(__file__), 'data', 'cisa_kev_cache.json')
_CACHE_TTL = 86400  # 24 hours


async def fetch_kev_catalog() -> dict:
    """Fetch KEV catalog with 24-hour file cache."""
    # Check cache
    if os.path.exists(_CACHE_FILE):
        age = time.time() - os.path.getmtime(_CACHE_FILE)
        if age < _CACHE_TTL:
            with open(_CACHE_FILE) as f:
                return json.load(f)
    # Fetch fresh
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(_KEV_URL)
            if r.status_code == 200:
                data = r.json()
                os.makedirs(os.path.dirname(_CACHE_FILE), exist_ok=True)
                with open(_CACHE_FILE, 'w') as f:
                    json.dump(data, f)
                return data
    except Exception:
        pass
    return {}


def build_kev_index(catalog: dict) -> dict:
    """Build CVE-ID -> KEV entry lookup dict."""
    return {v['cveID']: v for v in catalog.get('vulnerabilities', [])}


def extract_cves(text: str) -> list:
    """Extract all CVE-YYYY-NNNNN patterns from a string."""
    return re.findall(r'CVE-\d{4}-\d+', text or '', re.IGNORECASE)


async def enrich_findings_with_kev(findings: list) -> list:
    """
    For each finding that mentions a CVE, check if it's in CISA KEV.
    If yes, add a new sibling finding with status=CRITICAL, severity=CRITICAL
    flagging it as a known-exploited vulnerability.
    Returns the original findings list with KEV findings appended.
    """
    catalog = await fetch_kev_catalog()
    if not catalog:
        return findings

    kev_index = build_kev_index(catalog)
    kev_findings = []
    seen_cves = set()

    for f in findings:
        # Extract CVEs from vulnerability name + details
        text = f.get('vulnerability', '') + ' ' + f.get('details', '')
        for cve in extract_cves(text):
            cve_upper = cve.upper()
            if cve_upper in seen_cves:
                continue
            entry = kev_index.get(cve_upper)
            if not entry:
                continue
            seen_cves.add(cve_upper)
            kev_findings.append({
                'status': 'CRITICAL',
                'vulnerability': f'CISA KEV: {cve_upper} — {entry["vulnerabilityName"]}',
                'target': f.get('target', ''),
                'resolved_ip': f.get('resolved_ip', ''),
                'port': f.get('port', ''),
                'url': f.get('url', ''),
                'payload_url': f.get('payload_url', ''),
                'module': MODULE_NAME,
                'service_version': f.get('service_version', ''),
                'severity': 'CRITICAL',
                'details': (
                    f'{cve_upper} is on the CISA Known Exploited Vulnerabilities catalog. '
                    f'Product: {entry["vendorProject"]} {entry["product"]}. '
                    f'Required action: {entry["requiredAction"]} '
                    f'(due {entry.get("dueDate", "N/A")}). '
                    f'Ransomware use: {entry.get("knownRansomwareCampaignUse", "Unknown")}.'
                ),
                'http_status': f.get('http_status', 'N/A'),
                'page_title': 'N/A',
                'content_length': 'N/A',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
            })

    return findings + kev_findings
