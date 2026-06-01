import asyncio
from datetime import datetime
import os
import re

import httpx

MODULE_NAME = 'PassiveIntel'

# ---------------------------------------------------------------------------
# IP extraction helpers
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)


def _extract_ips_from_findings(findings: list) -> list:
    """Return a deduplicated list of IPv4 addresses found across all findings."""
    seen: set = set()
    for f in findings:
        for field in ('resolved_ip', 'target'):
            value = f.get(field, '') or ''
            for match in _IPV4_RE.finditer(value):
                ip = match.group()
                if ip not in seen:
                    seen.add(ip)
    return list(seen)


def _make_finding(ip: str, vulnerability: str, status: str, details: str,
                  severity: str, source_finding: dict | None = None) -> dict:
    """Build a finding dict in the same schema used throughout VaktScan."""
    base = source_finding or {}
    return {
        'status': status,
        'vulnerability': vulnerability,
        'target': ip,
        'resolved_ip': ip,
        'port': base.get('port', ''),
        'url': base.get('url', ''),
        'payload_url': base.get('payload_url', ''),
        'module': MODULE_NAME,
        'service_version': '',
        'severity': severity,
        'details': details,
        'http_status': 'N/A',
        'page_title': 'N/A',
        'content_length': 'N/A',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
    }


# ---------------------------------------------------------------------------
# Shodan enrichment
# ---------------------------------------------------------------------------

_SHODAN_HOST_URL = 'https://api.shodan.io/shodan/host/{ip}?key={key}'


async def _query_shodan(client: httpx.AsyncClient, ip: str, api_key: str) -> list:
    """Query Shodan for a single IP. Returns a list of findings."""
    url = _SHODAN_HOST_URL.format(ip=ip, key=api_key)
    findings: list = []
    try:
        r = await client.get(url, timeout=15)
    except Exception:
        return findings

    if r.status_code != 200:
        return findings

    try:
        data = r.json()
    except Exception:
        return findings

    ports: list = data.get('ports', [])
    org: str = data.get('org', 'N/A')
    isp: str = data.get('isp', 'N/A')
    country: str = data.get('country_name', 'N/A')
    hostnames: list = data.get('hostnames', [])
    vulns: dict = data.get('vulns', {})

    # Host intelligence finding (INFO)
    host_details = (
        f'Organisation: {org}. '
        f'ISP: {isp}. '
        f'Country: {country}. '
        f'Open ports: {", ".join(str(p) for p in sorted(ports)) if ports else "none"}. '
        f'Hostnames: {", ".join(hostnames) if hostnames else "none"}.'
    )
    findings.append(_make_finding(
        ip=ip,
        vulnerability='Shodan: Host Intelligence',
        status='INFO',
        severity='INFO',
        details=host_details,
    ))

    # CVE findings (POTENTIAL)
    for cve, info in vulns.items():
        cvss = None
        if isinstance(info, dict):
            cvss = info.get('cvss') or info.get('cvss3') or info.get('cvssv3')
        cvss_str = f' (CVSS: {cvss})' if cvss is not None else ''
        findings.append(_make_finding(
            ip=ip,
            vulnerability=f'Shodan CVE: {cve}',
            status='POTENTIAL',
            severity='HIGH',
            details=f'{cve} reported by Shodan for {ip}{cvss_str}.',
        ))

    return findings


# ---------------------------------------------------------------------------
# Censys enrichment
# ---------------------------------------------------------------------------

_CENSYS_HOST_URL = 'https://search.censys.io/api/v2/hosts/{ip}'


async def _query_censys(client: httpx.AsyncClient, ip: str,
                        api_id: str, api_secret: str) -> list:
    """Query Censys for a single IP. Returns a list of findings."""
    url = _CENSYS_HOST_URL.format(ip=ip)
    findings: list = []
    try:
        r = await client.get(url, auth=(api_id, api_secret), timeout=15)
    except Exception:
        return findings

    if r.status_code != 200:
        return findings

    try:
        body = r.json()
    except Exception:
        return findings

    result = body.get('result', {})
    services: list = result.get('services', [])
    asn_info: dict = result.get('autonomous_system', {})
    location: dict = result.get('location', {})

    org: str = asn_info.get('name', 'N/A')
    asn: str = str(asn_info.get('asn', 'N/A'))
    country: str = location.get('country', 'N/A')

    service_summaries: list = []
    for svc in services:
        port = svc.get('port', '?')
        proto = svc.get('transport_protocol', '').upper()
        name = svc.get('service_name', 'unknown')
        service_summaries.append(f'{port}/{proto} {name}')

    host_details = (
        f'Organisation: {org} (ASN {asn}). '
        f'Country: {country}. '
        f'Services: {", ".join(service_summaries) if service_summaries else "none"}.'
    )
    findings.append(_make_finding(
        ip=ip,
        vulnerability='Censys: Host Intelligence',
        status='INFO',
        severity='INFO',
        details=host_details,
    ))

    return findings


# ---------------------------------------------------------------------------
# Main enrichment entry-point
# ---------------------------------------------------------------------------

async def enrich_findings_with_passive_intel(findings: list) -> list:
    """
    Collect unique IPs from findings, query Shodan and Censys,
    append intelligence findings. Skips gracefully if no API keys set.
    """
    shodan_key = os.environ.get('SHODAN_API_KEY', '').strip()
    censys_id = os.environ.get('CENSYS_API_ID', '').strip()
    censys_secret = os.environ.get('CENSYS_API_SECRET', '').strip()

    use_shodan = bool(shodan_key)
    use_censys = bool(censys_id and censys_secret)

    if not use_shodan and not use_censys:
        return findings

    unique_ips = _extract_ips_from_findings(findings)
    if not unique_ips:
        return findings

    new_findings: list = []

    # Per-API in-process caches so the same IP is never queried twice
    shodan_cache: dict = {}
    censys_cache: dict = {}

    async with httpx.AsyncClient() as client:
        for ip in unique_ips:
            # --- Shodan ---
            if use_shodan and ip not in shodan_cache:
                results = await _query_shodan(client, ip, shodan_key)
                shodan_cache[ip] = results
                new_findings.extend(results)
                await asyncio.sleep(1)  # Shodan free-tier: 1 req/s

            # --- Censys ---
            if use_censys and ip not in censys_cache:
                results = await _query_censys(client, ip, censys_id, censys_secret)
                censys_cache[ip] = results
                new_findings.extend(results)
                await asyncio.sleep(1)  # stay polite to Censys too

    return findings + new_findings
