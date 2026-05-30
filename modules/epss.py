import httpx
import re
import asyncio

MODULE_NAME = 'EPSS'
EPSS_API = 'https://api.first.org/data/v1/epss'

_CVE_RE = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
_BATCH_SIZE = 50


def _extract_cves(text: str) -> list[str]:
    return [m.upper() for m in _CVE_RE.findall(text or '')]


async def fetch_epss_scores(cve_ids: list[str]) -> dict:
    """Batch fetch EPSS scores. Returns {cve_id: {'epss': float, 'percentile': float}}"""
    if not cve_ids:
        return {}

    results: dict = {}
    unique_ids = list(dict.fromkeys(cve_ids))  # deduplicate, preserve order

    # Batch in groups of BATCH_SIZE
    batches = [unique_ids[i:i + _BATCH_SIZE] for i in range(0, len(unique_ids), _BATCH_SIZE)]

    async with httpx.AsyncClient(timeout=20) as client:
        for batch in batches:
            cve_param = ','.join(batch)
            try:
                r = await client.get(EPSS_API, params={'cve': cve_param})
                if r.status_code != 200:
                    continue
                data = r.json()
                for entry in data.get('data', []):
                    cve = entry.get('cve', '').upper()
                    if not cve:
                        continue
                    try:
                        results[cve] = {
                            'epss': float(entry.get('epss', 0)),
                            'percentile': float(entry.get('percentile', 0)),
                        }
                    except (TypeError, ValueError):
                        continue
            except Exception:
                continue

    return results


async def enrich_findings_with_epss(findings: list) -> list:
    """
    Extract all CVE IDs from findings, fetch EPSS scores,
    add EPSS score and percentile to the details field of matching findings.
    Also upgrade status to CRITICAL if epss >= 0.7 (high exploitation probability).
    Returns modified findings list (in-place details update, no new findings added).
    """
    # Collect all unique CVE IDs across all findings
    all_cves: list[str] = []
    for f in findings:
        text = f.get('vulnerability', '') + ' ' + f.get('details', '')
        all_cves.extend(_extract_cves(text))

    if not all_cves:
        return findings

    scores = await fetch_epss_scores(all_cves)
    if not scores:
        return findings

    for f in findings:
        text = f.get('vulnerability', '') + ' ' + f.get('details', '')
        cves = _extract_cves(text)
        # Use the highest EPSS score among all CVEs mentioned in this finding
        best_cve = None
        best_score = -1.0
        for cve in cves:
            entry = scores.get(cve)
            if entry and entry['epss'] > best_score:
                best_score = entry['epss']
                best_cve = cve

        if best_cve is None or best_score < 0.3:
            continue

        entry = scores[best_cve]
        epss_val = entry['epss']
        percentile = entry['percentile']

        if epss_val >= 0.7:
            f['details'] = (
                f.get('details', '') +
                f' | EPSS: {epss_val:.1%} ({percentile:.1%} percentile) — HIGH exploitation probability'
            )
            # Upgrade status to CRITICAL if not already
            if f.get('status') not in ('CRITICAL',):
                f['status'] = 'CRITICAL'
        else:
            # 0.3 <= epss < 0.7
            f['details'] = (
                f.get('details', '') +
                f' | EPSS: {epss_val:.1%} ({percentile:.1%} percentile)'
            )

    return findings
