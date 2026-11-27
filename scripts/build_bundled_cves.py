#!/usr/bin/env python3
"""
Refresh modules/data/bundled_cves.json from NVD JSON 2.0 feeds.

Source: https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:<vendor>:<product>

The bundled-component table covers every software package cPanel installs
by default. The script queries NVD per-component, filters to entries with
a valid CPE match, and emits the schema used by modules/cpanel.py.

Usage:
    python scripts/build_bundled_cves.py
    python scripts/build_bundled_cves.py --dry-run
    python scripts/build_bundled_cves.py --components apache_httpd,php

Rate-limited (6s pause between component queries) so it stays under NVD's
public limit without an API key.
"""
import argparse
import datetime
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
OUT_PATH = os.path.join(ROOT, 'modules', 'data', 'bundled_cves.json')
CURATED_PATH = os.path.join(ROOT, 'modules', 'data', 'bundled_cves_curated.json')

# Component → NVD CPE prefix.
COMPONENT_CPES = {
    'apache_httpd': 'cpe:2.3:a:apache:http_server',
    'php':          'cpe:2.3:a:php:php',
    'exim':         'cpe:2.3:a:exim:exim',
    'dovecot':      'cpe:2.3:a:dovecot:dovecot',
    'openssh':      'cpe:2.3:a:openbsd:openssh',
    'openssl':      'cpe:2.3:a:openssl:openssl',
    'proftpd':      'cpe:2.3:a:proftpd:proftpd',
    'roundcube':    'cpe:2.3:a:roundcube:webmail',
    'horde':        'cpe:2.3:a:horde:groupware',
    'phpmyadmin':   'cpe:2.3:a:phpmyadmin:phpmyadmin',
    'whmcs':        'cpe:2.3:a:whmcs:whmcs',
    'softaculous':  'cpe:2.3:a:softaculous:softaculous',
    'mailman':      'cpe:2.3:a:gnu:mailman',
    'awstats':      'cpe:2.3:a:awstats:awstats',
    'powerdns':     'cpe:2.3:a:powerdns:authoritative',
    'bind':         'cpe:2.3:a:isc:bind',
    'mysql':        'cpe:2.3:a:oracle:mysql',
    'postgresql':   'cpe:2.3:a:postgresql:postgresql',
    'owncloud':     'cpe:2.3:a:owncloud:owncloud',
    'imagemagick':  'cpe:2.3:a:imagemagick:imagemagick',
}

NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


def severity_from_cvss(cvss):
    if cvss >= 9.0:
        return 'CRITICAL'
    if cvss >= 7.0:
        return 'HIGH'
    if cvss >= 4.0:
        return 'MEDIUM'
    return 'LOW'


def fetch_nvd(cpe, results_per_page=2000):
    """Fetch all NVD results for a CPE, paginating until exhausted."""
    all_vulns = []
    start = 0
    while True:
        params = {
            'virtualMatchString': cpe,
            'resultsPerPage': str(results_per_page),
            'startIndex': str(start),
        }
        url = NVD_API + '?' + urllib.parse.urlencode(params)
        headers = {'User-Agent': 'VaktScan-bundled-refresh/1.0'}
        if os.environ.get('NVD_API_KEY'):
            headers['apiKey'] = os.environ['NVD_API_KEY']
        req = urllib.request.Request(url, headers=headers)
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = json.loads(resp.read().decode('utf-8'))
                break
            except urllib.error.HTTPError as exc:
                if exc.code not in (429, 500, 502, 503, 504) or attempt == 2:
                    raise
                retry_after = exc.headers.get('Retry-After', '')
                delay = min(120, max(5, int(retry_after))) if retry_after.isdigit() else 30
                print(f"[!] NVD returned HTTP {exc.code}; retrying in {delay}s.", flush=True)
                time.sleep(delay)
        batch = data.get('vulnerabilities', [])
        all_vulns.extend(batch)
        total = data.get('totalResults', 0)
        start += len(batch)
        if start >= total or not batch:
            break
        time.sleep(0.6 if os.environ.get('NVD_API_KEY') else 6)
    return {'vulnerabilities': all_vulns}


def extract_entries(nvd_payload, cpe_prefix=None):
    out = []
    for item in nvd_payload.get('vulnerabilities', []):
        cve = item.get('cve', {})
        cve_id = cve.get('id')
        if not cve_id:
            continue
        desc = ''
        for d in cve.get('descriptions', []):
            if d.get('lang') == 'en':
                desc = d.get('value', '')
                break
        cvss = 0.0
        metrics = cve.get('metrics', {})
        for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get('cvssData', {}).get('baseScore', 0.0)
                break
        # Pull affected version ranges from configurations.
        ranges = []
        for cfg in cve.get('configurations', []):
            for node in cfg.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if not match.get('vulnerable'):
                        continue
                    if cpe_prefix and not str(match.get('criteria', '')).startswith(cpe_prefix + ':'):
                        continue
                    lo_inc = match.get('versionStartIncluding')
                    lo_exc = match.get('versionStartExcluding')
                    hi_exc = match.get('versionEndExcluding')
                    hi_inc = match.get('versionEndIncluding')
                    lo = lo_inc or lo_exc
                    hi = hi_exc or hi_inc
                    lo_op = '>=' if lo_inc else '>'
                    hi_op = '<' if hi_exc else '<='
                    if lo and hi:
                        ranges.append(f"{lo_op}{lo},{hi_op}{hi}")
                    elif hi:
                        ranges.append(f"{hi_op}{hi}")
        out.append({
            'cve': cve_id,
            'severity': severity_from_cvss(cvss),
            'affected_versions': sorted(set(ranges)),
            'summary': desc[:200],
        })
    return out


def merge_curated_entries(curated, fetched):
    """Keep project-curated CVEs that NVD's product query omits."""
    by_cve = {entry['cve']: entry for entry in curated if isinstance(entry, dict) and entry.get('cve')}
    for entry in fetched:
        old = by_cve.get(entry['cve'])
        if old and old.get('affected_versions') and not entry.get('affected_versions'):
            continue
        by_cve[entry['cve']] = entry
    return sorted(by_cve.values(), key=lambda entry: entry['cve'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--components', help='Comma-separated subset to refresh')
    args = parser.parse_args()

    components = list(COMPONENT_CPES.keys())
    if args.components:
        wanted = {c.strip() for c in args.components.split(',')}
        components = [c for c in components if c in wanted]

    # Start from existing file so we don't blow away CVEs for components we skip.
    if os.path.exists(OUT_PATH):
        with open(OUT_PATH, 'r', encoding='utf-8') as fh:
            existing = json.load(fh)
    else:
        existing = {'_meta': {}, 'components': {c: [] for c in COMPONENT_CPES}}

    with open(CURATED_PATH, 'r', encoding='utf-8') as fh:
        curated_components = json.load(fh).get('components', {})

    components_out = dict(existing.get('components', {}))
    for comp, entries in curated_components.items():
        components_out[comp] = merge_curated_entries(entries, components_out.get(comp, []))
    failed = []
    pause = 0.6 if os.environ.get('NVD_API_KEY') else 6
    requested = 0
    for comp in components:
        if requested:
            time.sleep(pause)
        requested += 1
        cpe = COMPONENT_CPES[comp]
        try:
            payload = fetch_nvd(cpe)
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"[!] {comp}: NVD fetch failed ({e}), keeping existing entries.")
            failed.append(comp)
            continue
        entries = extract_entries(payload, cpe)
        if entries:
            components_out[comp] = merge_curated_entries(curated_components.get(comp, []), entries)
            print(f"[+] {comp}: {len(entries)} NVD entries, {len(components_out[comp])} including curated entries.")
        elif components_out.get(comp):
            print(f"[!] {comp}: NVD returned no entries; keeping existing entries.")
            failed.append(comp)

    out = {
        '_meta': {
            'source': 'NVD JSON 2.0 feed',
            'curated_source': 'modules/data/bundled_cves_curated.json',
            'schema_version': 1,
            'refreshed_at': (existing.get('_meta', {}).get('refreshed_at') if failed
                             else datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')),
        },
        'components': components_out,
    }
    if args.dry_run:
        print(json.dumps(out, indent=2))
        return 1 if failed else 0
    fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(OUT_PATH), prefix='.bundled_cves.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(out, fh, indent=2)
            fh.write('\n')
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, OUT_PATH)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
    print(f"[+] Wrote {sum(len(v) for v in components_out.values())} entries to {OUT_PATH}")
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
