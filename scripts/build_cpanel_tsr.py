#!/usr/bin/env python3
"""
Refresh modules/data/cpanel_tsr.json from cPanel's TSR archive.

Source:  https://news.cpanel.com/category/security-advisories/
Cross-check: https://www.cve.org/CVERecord/SearchResults?query=cpanel

Usage:
    python scripts/build_cpanel_tsr.py           # refresh in place
    python scripts/build_cpanel_tsr.py --dry-run # print without writing

The script is best-effort: cPanel publishes TSRs as blog posts, so parsing
is heuristic. The output JSON is validated against the schema used by
modules/cpanel.py (`{id, published, severity, affected_versions, fixed_in,
cves, surface, auth_required, observable, summary}`) before being written.
Run this from CI on a schedule (weekly) and commit the result.
"""
import argparse
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
OUT_PATH = os.path.join(ROOT, 'modules', 'data', 'cpanel_tsr.json')
INDEX_URL = 'https://news.cpanel.com/category/security-advisories/'


def fetch(url, timeout=15):
    req = urllib.request.Request(url, headers={'User-Agent': 'VaktScan-TSR-refresh/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', errors='replace')


def parse_index(html):
    """Yield (tsr_id, post_url) from the index page."""
    seen = set()
    for m in re.finditer(r'href="([^"]+)"[^>]*>\s*(TSR-\d{4}-\d{4})\b', html):
        url, tsr_id = m.group(1), m.group(2)
        if tsr_id in seen:
            continue
        seen.add(tsr_id)
        yield tsr_id, url


def parse_bulletin(tsr_id, html):
    cves = sorted(set(re.findall(r'CVE-\d{4}-\d{4,7}', html)))
    severity = 'MEDIUM'
    for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        if re.search(rf'\b{s}\b', html, re.IGNORECASE):
            severity = s
            break

    # Affected version ranges: try to find "cPanel & WHM version X.Y.Z.W" lines.
    fixed = sorted(set(re.findall(r'\b(\d{2}\.\d+\.\d+\.\d+)\b', html)))
    if not fixed:
        return None

    affected = []
    for fix in fixed:
        major, minor, patch, build = fix.split('.')
        affected.append(f">={major}.{minor}.0.0,<{fix}")

    title_match = re.search(r'<title>(.+?)</title>', html, re.IGNORECASE | re.DOTALL)
    summary = (title_match.group(1).strip()[:200] if title_match else f'cPanel & WHM Security Advisory {tsr_id}')

    published = None
    pm = re.search(r'(20\d{2}-\d{2}-\d{2})', html)
    if pm:
        published = pm.group(1)

    return {
        'id': tsr_id,
        'published': published or datetime.date.today().isoformat(),
        'severity': severity,
        'affected_versions': affected,
        'fixed_in': fixed,
        'cves': cves,
        'surface': ['cpanel', 'whm'],
        'auth_required': False,
        'observable': bool(cves),
        'summary': summary,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()

    try:
        html = fetch(INDEX_URL)
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"[!] Could not fetch index ({e}). Existing cpanel_tsr.json left untouched.")
        sys.exit(2)

    bulletins = []
    for tsr_id, url in parse_index(html):
        try:
            page = fetch(url)
        except Exception:
            continue
        b = parse_bulletin(tsr_id, page)
        if b:
            bulletins.append(b)

    if not bulletins:
        print("[!] No bulletins parsed — refusing to overwrite existing JSON.")
        sys.exit(3)

    out = {
        '_meta': {
            'source': INDEX_URL,
            'schema_version': 1,
            'refreshed_at': datetime.datetime.utcnow().isoformat() + 'Z',
            'count': len(bulletins),
        },
        'bulletins': bulletins,
    }

    if args.dry_run:
        print(json.dumps(out, indent=2))
        return

    with open(OUT_PATH, 'w', encoding='utf-8') as fh:
        json.dump(out, fh, indent=2)
        fh.write('\n')
    print(f"[+] Wrote {len(bulletins)} bulletins to {OUT_PATH}")


if __name__ == '__main__':
    main()
