import httpx
import re
import os
import json
import time
import tempfile

MODULE_NAME = 'CISA-KEV'
_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
_CACHE_FILE = os.path.join(os.path.dirname(__file__), 'data', 'cisa_kev_cache.json')
_CACHE_TTL = 86400  # 24 hours


async def fetch_kev_catalog(*, force: bool = False) -> dict:
    """Fetch KEV catalog with 24-hour file cache."""
    cached = {}
    if os.path.exists(_CACHE_FILE):
        try:
            with open(_CACHE_FILE) as f:
                cached = json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
        age = time.time() - os.path.getmtime(_CACHE_FILE)
        if not force and age < _CACHE_TTL and cached:
            return cached
    # Fetch fresh
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(_KEV_URL)
            if r.status_code == 200:
                data = r.json()
                if not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list) or not data.get('dateReleased'):
                    return cached
                dest_dir = os.path.dirname(_CACHE_FILE)
                os.makedirs(dest_dir, exist_ok=True)
                fd, tmp_path = tempfile.mkstemp(dir=dest_dir, prefix='.cisa_kev_cache.', suffix='.tmp')
                try:
                    with os.fdopen(fd, 'w', encoding='utf-8') as f:
                        json.dump(data, f)
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp_path, _CACHE_FILE)
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                return data
    except Exception:
        pass
    return cached


def build_kev_index(catalog: dict) -> dict:
    """Build CVE-ID -> KEV entry lookup dict."""
    return {v['cveID']: v for v in catalog.get('vulnerabilities', [])}


def extract_cves(text: str) -> list:
    """Extract all CVE-YYYY-NNNNN patterns from a string."""
    return re.findall(r'CVE-\d{4}-\d+', text or '', re.IGNORECASE)


async def enrich_findings_with_kev(findings: list) -> list:
    """
    For each finding that mentions a CVE, check if it's in CISA KEV.
    KEV membership is prioritization context, not deployment-specific impact.
    Annotate the source finding without duplicating it or inflating severity.
    """
    catalog = await fetch_kev_catalog()
    if not catalog:
        return findings

    kev_index = build_kev_index(catalog)
    for f in findings:
        # Extract CVEs from vulnerability name + details
        text = f.get('vulnerability', '') + ' ' + f.get('details', '')
        matched = []
        for cve in extract_cves(text):
            cve_upper = cve.upper()
            entry = kev_index.get(cve_upper)
            if not entry or any(item['cve'] == cve_upper for item in matched):
                continue
            matched.append({'cve': cve_upper, 'entry': entry})

        if not matched:
            continue

        f['cisa_kev'] = True
        f['cisa_kev_ids'] = [item['cve'] for item in matched]
        annotations = []
        for item in matched:
            cve_upper, entry = item['cve'], item['entry']
            annotations.append(
                f'CISA KEV: {cve_upper} is known exploited; '
                f'product {entry["vendorProject"]} {entry["product"]}; '
                f'required action: {entry["requiredAction"]}; '
                f'due {entry.get("dueDate", "N/A")}; '
                f'ransomware use: {entry.get("knownRansomwareCampaignUse", "Unknown")}'
            )
        details = str(f.get('details') or '').rstrip()
        suffix = ' | '.join(annotations)
        if suffix not in details:
            f['details'] = f'{details} | {suffix}' if details else suffix

    return findings
