#!/usr/bin/env python3
"""
Refresh modules/data/cpanel_tsr.json from cPanel's release notes.

Source:  https://docs.cpanel.net/release-notes/release-notes/
         (news.cpanel.com/category/security-advisories/ redirects here as of 2025)

The new format is a single mega-page. Security advisories appear as
"cPanel & WHM Security Update" h2 sections listing affected branches
(e.g. "versions 136, 134, and 126") and CVE IDs. There are no longer
separate TSR-XXXX-XXXX per-bulletin pages with 4-part build versions.

Version range strategy: for each affected branch B, emit the range
  >=11.B.0.0,<11.(B+2).0.0
cPanel uses even-numbered branches; B+2 is the next branch boundary.
For branches with no known successor yet, emit >=11.B.0.0 (open-ended).

Usage:
    python scripts/build_cpanel_tsr.py           # refresh in place
    python scripts/build_cpanel_tsr.py --dry-run # print without writing

Run from CI on a schedule (weekly) and commit the result.
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
SOURCE_URL = 'https://docs.cpanel.net/release-notes/release-notes/'


def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={'User-Agent': 'VaktScan-TSR-refresh/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', errors='replace')


def _branches_to_ranges(branches):
    """Convert a list of cPanel branch ints to affected version range strings."""
    if not branches:
        return []
    max_branch = max(branches)
    ranges = []
    for b in sorted(branches):
        next_b = b + 2
        if b == max_branch:
            # Unknown upper bound for the newest branch — open-ended range.
            ranges.append(f">=11.{b}.0.0")
        else:
            ranges.append(f">=11.{b}.0.0,<11.{next_b}.0.0")
    return ranges


def parse_security_blocks(html):
    """
    Parse 'cPanel & WHM Security Update' h2 sections from the release notes page.
    Returns a list of bulletin dicts matching the cpanel.py schema.
    """
    raw_blocks = re.split(r'(?=<h2[^>]*id=)', html)
    bulletins = []
    seen_ids = set()

    for block in raw_blocks:
        title_m = re.search(r'<h2[^>]*>(.+?)</h2>', block, re.DOTALL)
        if not title_m:
            continue
        title_text = re.sub(r'<[^>]+>', '', title_m.group(1)).strip()

        if not re.search(r'cpanel.*whm.*security|security.*update', title_text, re.IGNORECASE):
            continue

        text = re.sub(r'<[^>]+>', ' ', block)

        cves = sorted(set(re.findall(r'CVE-\d{4}-\d{4,7}', block)))
        if not cves:
            continue

        # Parse date
        date_str = None
        date_m = re.search(r'(\d{4} \w+ \d+)', text)
        if date_m:
            for fmt in ('%Y %B %d', '%Y %b %d'):
                try:
                    date_str = datetime.datetime.strptime(date_m.group(1), fmt).strftime('%Y-%m-%d')
                    break
                except ValueError:
                    pass

        # Parse severity
        severity = 'MEDIUM'
        for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            if re.search(rf'\b{s}\b', text, re.IGNORECASE):
                severity = s
                break

        # Extract affected branch numbers: "versions 136, 134, and 126"
        # Also handles "all supported ... versions (136, 134, 132, ...)"
        branch_m = re.search(
            r'versions?\s*\(?([\d,\s]+(?:and\s+\d+)?)\)?',
            text, re.IGNORECASE
        )
        branches = []
        if branch_m:
            nums = [int(n) for n in re.findall(r'\d+', branch_m.group(1))]
            branches = [n for n in nums if 50 < n < 500]

        affected = _branches_to_ranges(branches)

        # Synthetic ID: prefer date-based, fall back to index
        bul_id = f"SEC-{date_str}" if date_str else f"SEC-{len(bulletins):04d}"
        if bul_id in seen_ids:
            bul_id = f"{bul_id}-{len(bulletins)}"
        seen_ids.add(bul_id)

        # Extract a meaningful summary from the advisory text
        summary_m = re.search(r'(addressing.{10,200}?)(?:\.|$)', text)
        if not summary_m:
            summary_m = re.search(r'(patches?.{10,200}?)(?:\.|$)', text, re.IGNORECASE)
        summary = summary_m.group(1).strip()[:200] if summary_m else title_text[:200]

        bulletins.append({
            'id': bul_id,
            'published': date_str or datetime.date.today().isoformat(),
            'severity': severity,
            'affected_versions': affected,
            'fixed_in': [f"11.{b}.latest" for b in sorted(branches)],
            'cves': cves,
            'surface': ['cpanel', 'whm'],
            'auth_required': False,
            'observable': True,
            'summary': summary,
        })

    return bulletins


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()

    try:
        html = fetch(SOURCE_URL)
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"[!] Could not fetch release notes ({e}). Existing cpanel_tsr.json left untouched.")
        sys.exit(2)

    bulletins = parse_security_blocks(html)

    if not bulletins:
        print("[!] No security update blocks parsed — refusing to overwrite existing JSON.")
        sys.exit(3)

    # Preserve any hand-crafted bulletins from the existing file that have
    # real 4-part affected_versions (old TSR format) and aren't in the new data.
    if os.path.exists(OUT_PATH):
        with open(OUT_PATH, 'r', encoding='utf-8') as fh:
            existing = json.load(fh)
        existing_ids = {b['id'] for b in bulletins}
        for old in existing.get('bulletins', []):
            if old['id'] not in existing_ids and any(
                re.match(r'>=\d+\.\d+\.\d+\.\d+', r) for r in old.get('affected_versions', [])
            ):
                bulletins.append(old)

    bulletins.sort(key=lambda b: b['published'], reverse=True)

    out = {
        '_meta': {
            'source': SOURCE_URL,
            'schema_version': 1,
            'refreshed_at': datetime.datetime.utcnow().isoformat() + 'Z',
            'count': len(bulletins),
            'description': (
                'cPanel & WHM security advisories parsed from the release notes page. '
                'affected_versions uses branch-level ranges (>=11.B.0.0,<11.B+2.0.0). '
                'Refreshed by scripts/build_cpanel_tsr.py. Run weekly.'
            ),
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
