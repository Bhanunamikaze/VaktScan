#!/usr/bin/env python3
"""
Refresh modules/data/bundled_cves.json from NVD JSON 2.0 feeds.

Source: https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:<vendor>:<product>:*

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
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
OUT_PATH = os.path.join(ROOT, 'modules', 'data', 'bundled_cves.json')

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
    'mysql':        'cpe:2.3:a:mysql:mysql',
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


def fetch_nvd(cpe, results_per_page=200):
    params = {'cpeName': cpe + ':*:*:*:*:*:*:*', 'resultsPerPage': str(results_per_page)}
    url = NVD_API + '?' + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={'User-Agent': 'VaktScan-bundled-refresh/1.0'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode('utf-8'))


def extract_entries(nvd_payload):
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
        for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
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
                    lo = match.get('versionStartIncluding') or match.get('versionStartExcluding')
                    hi = match.get('versionEndExcluding') or match.get('versionEndIncluding')
                    if lo and hi:
                        ranges.append(f">={lo},<{hi}")
                    elif hi:
                        ranges.append(f"<{hi}")
        out.append({
            'cve': cve_id,
            'severity': severity_from_cvss(cvss),
            'affected_versions': sorted(set(ranges)),
            'summary': desc[:200],
        })
    return out


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

    components_out = dict(existing.get('components', {}))
    for comp in components:
        cpe = COMPONENT_CPES[comp]
        try:
            payload = fetch_nvd(cpe)
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"[!] {comp}: NVD fetch failed ({e}), keeping existing entries.")
            continue
        entries = extract_entries(payload)
        if entries:
            components_out[comp] = entries
            print(f"[+] {comp}: {len(entries)} entries.")
        time.sleep(6)  # NVD public rate limit.

    out = {
        '_meta': {
            'source': 'NVD JSON 2.0 feed',
            'schema_version': 1,
            'refreshed_at': datetime.datetime.utcnow().isoformat() + 'Z',
        },
        'components': components_out,
    }
    if args.dry_run:
        print(json.dumps(out, indent=2))
        return
    with open(OUT_PATH, 'w', encoding='utf-8') as fh:
        json.dump(out, fh, indent=2)
        fh.write('\n')
    print(f"[+] Wrote {sum(len(v) for v in components_out.values())} entries to {OUT_PATH}")


if __name__ == '__main__':
    main()
