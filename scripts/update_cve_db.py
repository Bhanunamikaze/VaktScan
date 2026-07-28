#!/usr/bin/env python3
"""
Build / refresh the offline NVD CVE index at modules/data/nvd_cve_db.json.

This is the local, daily-refreshable database that modules/nvd.lookup_cves()
consults BEFORE hitting the live NVD API. It covers the products VaktScan
fingerprints (web servers, web-layer runtimes, and the service_recon stack).

It is a SEPARATE file from modules/data/bundled_cves.json (the cPanel bundled-
component table owned by scripts/build_bundled_cves.py + modules/cpanel.py);
neither that file nor its schema is touched here.

Source:
    https://services.nvd.nist.gov/rest/json/cves/2.0

Design notes
------------
* Per product we issue three narrow queries -
      virtualMatchString=<cpe-prefix> & cvssV3Severity=CRITICAL
      virtualMatchString=<cpe-prefix> & cvssV3Severity=HIGH
      virtualMatchString=<cpe-prefix> & cvssV2Severity=HIGH
  This returns exactly the CVSS>=7 set nvd.lookup_cves() cares about, keeps each
  payload small (fast, no huge pagination), and each CVE is deduped by id with
  its affected-version ranges merged.
* The storage key is computed the SAME way lookup_cves() computes it
  (CPE_VENDOR_MAP.get(product, product) + ':' + product) so a lookup always
  finds the entries this builder writes, even when the NVD CPE vendor/product
  differs from VaktScan's fingerprint name (e.g. IIS).
* Rate-limited: ~6s pause between requests without an API key, ~0.6s with one
  (honours NVD_API_KEY). Matches scripts/build_bundled_cves.py conventions.
* Fail-safe, like scripts/update_js_cve_db.py: the write is atomic (temp file in
  the same directory + os.replace) so a partial/failed fetch can never clobber a
  good DB; a product whose fetch fails keeps its previously-stored entries; the
  process exits non-zero if any product failed. A product that fetches OK but
  yields nothing is left ABSENT from the index so lookups fail open to the live
  API for it (rather than being told "no CVEs" offline).
* TTL: skips the whole refresh when the DB is newer than --ttl-days unless
  --force is given.

Usage:
    python scripts/update_cve_db.py                     # refresh if stale
    python scripts/update_cve_db.py --force             # refresh unconditionally
    python scripts/update_cve_db.py --products nginx,php # subset
    python scripts/update_cve_db.py --ttl-days 1
    python scripts/update_cve_db.py --dry-run

No third-party dependencies (stdlib urllib, like scripts/build_bundled_cves.py).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Reuse the exact vendor mapping lookup_cves() uses so the storage keys line up.
from modules.nvd import CPE_VENDOR_MAP  # noqa: E402

OUT_PATH = os.path.join(ROOT, 'modules', 'data', 'nvd_cve_db.json')
NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
USER_AGENT = 'VaktScan-nvd-cve-db/1.0'
HTTP_TIMEOUT = 60
DEFAULT_TTL_DAYS = 1.0
DEFAULT_MIN_CVSS = 7.0
SCHEMA_VERSION = 1

# The severity buckets that together cover CVSS >= 7.0 while keeping payloads
# small. Extraction re-checks the actual base score, so a bucket that returns a
# borderline CVE is filtered precisely.
SEVERITY_PARAMS = (
    'cvssV3Severity=CRITICAL',
    'cvssV3Severity=HIGH',
    'cvssV2Severity=HIGH',
)

# VaktScan fingerprint product -> NVD CPE prefix(es) (cpe:2.3:a:<vendor>:<product>).
# A product may list several prefixes (e.g. IIS naming variants); all are merged
# under one storage key. The storage key is derived from the product name via
# CPE_VENDOR_MAP (see storage_key()), NOT from these prefixes.
PRODUCT_CPES: dict[str, list[str]] = {
    # web / application servers
    'nginx':        ['cpe:2.3:a:nginx:nginx', 'cpe:2.3:a:f5:nginx'],
    'http_server':  ['cpe:2.3:a:apache:http_server'],          # Apache httpd
    'tomcat':       ['cpe:2.3:a:apache:tomcat'],
    'iis':          ['cpe:2.3:a:microsoft:internet_information_services',
                     'cpe:2.3:a:microsoft:internet_information_server'],
    'lighttpd':     ['cpe:2.3:a:lighttpd:lighttpd'],
    'jetty':        ['cpe:2.3:a:eclipse:jetty'],
    'openresty':    ['cpe:2.3:a:openresty:openresty'],
    # web-layer runtimes / libraries / CMS
    'php':          ['cpe:2.3:a:php:php'],
    'openssl':      ['cpe:2.3:a:openssl:openssl'],
    'wordpress':    ['cpe:2.3:a:wordpress:wordpress'],
    # service_recon stack
    'redis':        ['cpe:2.3:a:redis:redis', 'cpe:2.3:a:redislabs:redis'],
    'mongodb':      ['cpe:2.3:a:mongodb:mongodb'],
    'elasticsearch':['cpe:2.3:a:elastic:elasticsearch',
                     'cpe:2.3:a:elasticsearch:elasticsearch'],
    'rabbitmq':     ['cpe:2.3:a:vmware:rabbitmq',
                     'cpe:2.3:a:pivotal_software:rabbitmq'],
    'mysql':        ['cpe:2.3:a:oracle:mysql'],
    'postgresql':   ['cpe:2.3:a:postgresql:postgresql'],
}


def _log(msg: str) -> None:
    print(msg, flush=True)


def storage_key(product: str) -> str:
    """The "vendor:product" key lookup_cves() will compute for this product."""
    vendor = CPE_VENDOR_MAP.get(product, product)
    return f"{vendor}:{product}"


def severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return 'CRITICAL'
    if cvss >= 7.0:
        return 'HIGH'
    if cvss >= 4.0:
        return 'MEDIUM'
    return 'LOW'


# ── NVD fetch ───────────────────────────────────────────────────────────────────

def _headers(api_key: str) -> dict:
    h = {'User-Agent': USER_AGENT}
    if api_key:
        h['apiKey'] = api_key
    return h


def fetch(cpe_prefix: str, severity_param: str, api_key: str, pause: float) -> list:
    """Fetch all vulnerabilities for one (cpe-prefix, severity) query, paginating
    until exhausted. Raises on network / parse error (caller decides)."""
    all_vulns: list = []
    seen_ids: set[str] = set()
    start = 0
    base = ('virtualMatchString=' + urllib.parse.quote(cpe_prefix)
            + '&' + severity_param + '&resultsPerPage=2000')
    while True:
        url = NVD_API + '?' + base + f'&startIndex={start}'
        req = urllib.request.Request(url, headers=_headers(api_key))
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            status = getattr(resp, 'status', 200) or 200
            if status != 200:
                raise urllib.error.URLError(f'unexpected HTTP status {status}')
            data = json.loads(resp.read().decode('utf-8'))
        batch = data.get('vulnerabilities', [])
        # Guard against a caching layer that ignores startIndex and re-serves the
        # same page: stop as soon as a page contributes no new CVE ids.
        new_ids = {v.get('cve', {}).get('id') for v in batch} - seen_ids
        if not new_ids:
            break
        seen_ids |= new_ids
        all_vulns.extend(batch)
        total = data.get('totalResults', 0)
        start += len(batch)
        if not batch or start >= total:
            break
        time.sleep(pause)  # rate limit between pages
    return all_vulns


# ── Extraction ──────────────────────────────────────────────────────────────────

def _score(cve: dict) -> tuple[float, str]:
    """Base score + severity, using the same v3.1 > v3.0 > v2 precedence as the
    live lookup_cves() path (so offline and live agree on which CVEs qualify)."""
    metrics = cve.get('metrics', {})
    for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        arr = metrics.get(key)
        if arr:
            entry = arr[0]
            data = entry.get('cvssData', {})
            score = float(data.get('baseScore', 0) or 0)
            sev = (data.get('baseSeverity') or entry.get('baseSeverity') or '').upper()
            if not sev:
                sev = severity_from_cvss(score)
            return score, sev
    return 0.0, 'INFO'


def _english_desc(cve: dict) -> str:
    for d in cve.get('descriptions', []):
        if d.get('lang') == 'en':
            return d.get('value', '') or ''
    return ''


def _range_expr(match: dict, criteria: str) -> str | None:
    """Turn one vulnerable cpeMatch into a comma-joined constraint expression,
    e.g. '>=1.0,<2.0', '<3.0', '<=1.4', or an exact '==1.2.3'. Returns None when
    no usable version bound can be derived (such entries are dropped, so we never
    emit a CVE that would match every version)."""
    lo_inc = match.get('versionStartIncluding')
    lo_exc = match.get('versionStartExcluding')
    hi_inc = match.get('versionEndIncluding')
    hi_exc = match.get('versionEndExcluding')
    parts: list[str] = []
    if lo_inc:
        parts.append('>=' + str(lo_inc))
    elif lo_exc:
        parts.append('>' + str(lo_exc))
    if hi_exc:
        parts.append('<' + str(hi_exc))
    elif hi_inc:
        parts.append('<=' + str(hi_inc))
    if parts:
        return ','.join(parts)
    # No range fields: fall back to the exact version embedded in the CPE.
    fields = criteria.split(':')
    if len(fields) > 5:
        ver = fields[5]
        if ver and ver not in ('*', '-'):
            return '==' + ver
    return None


def extract_entries(vulns: list, cpe_prefixes: list[str], min_cvss: float) -> list[dict]:
    """Dedup by CVE id, filter to CVSS >= min_cvss, and collect version ranges
    that belong to THIS product's CPE prefix(es) only (so a multi-product CVE
    does not leak another product's version bounds)."""
    by_cve: dict[str, dict] = {}
    for item in vulns:
        cve = item.get('cve', {})
        cve_id = cve.get('id')
        if not cve_id:
            continue
        cvss, severity = _score(cve)
        if cvss < min_cvss:
            continue
        ranges: set[str] = set()
        for cfg in cve.get('configurations', []):
            for node in cfg.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if not match.get('vulnerable'):
                        continue
                    criteria = match.get('criteria', '') or ''
                    if not any(criteria.startswith(pfx + ':') for pfx in cpe_prefixes):
                        continue
                    expr = _range_expr(match, criteria)
                    if expr:
                        ranges.add(expr)
        if not ranges:
            continue
        if cve_id in by_cve:
            merged = set(by_cve[cve_id]['affected_versions']) | ranges
            by_cve[cve_id]['affected_versions'] = sorted(merged)
        else:
            by_cve[cve_id] = {
                'cve': cve_id,
                'cvss': round(cvss, 1),
                'severity': severity,
                'affected_versions': sorted(ranges),
                'summary': _english_desc(cve)[:200],
            }
    return sorted(by_cve.values(), key=lambda e: e['cve'])


# ── Persistence ─────────────────────────────────────────────────────────────────

def load_existing() -> dict:
    if not os.path.exists(OUT_PATH):
        return {'_meta': {}, 'index': {}}
    try:
        with open(OUT_PATH, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get('index'), dict):
            data.setdefault('_meta', {})
            return data
    except Exception as exc:
        _log(f'[!] Existing DB unreadable ({exc}); starting fresh.')
    return {'_meta': {}, 'index': {}}


def is_fresh(ttl_days: float) -> tuple[bool, float]:
    if not os.path.exists(OUT_PATH):
        return False, 0.0
    age_days = (time.time() - os.path.getmtime(OUT_PATH)) / 86400.0
    return age_days < ttl_days, age_days


def atomic_write(payload: dict) -> None:
    dest_dir = os.path.dirname(OUT_PATH)
    os.makedirs(dest_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=dest_dir, prefix='.nvd_cve_db.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, indent=2)
            fh.write('\n')
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, OUT_PATH)  # atomic on the same filesystem
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ── Main ────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description='Refresh modules/data/nvd_cve_db.json from the NVD JSON 2.0 API.')
    parser.add_argument('--force', action='store_true',
                        help='Refresh even if the DB is within the TTL.')
    parser.add_argument('--ttl-days', type=float, default=DEFAULT_TTL_DAYS,
                        help=f'Skip refresh if the DB is newer than this many days '
                             f'(default: {DEFAULT_TTL_DAYS:g}).')
    parser.add_argument('--products', help='Comma-separated subset to refresh.')
    parser.add_argument('--min-cvss', type=float, default=DEFAULT_MIN_CVSS,
                        help=f'Only store CVEs at or above this base score '
                             f'(default: {DEFAULT_MIN_CVSS:g}).')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print the resulting DB instead of writing it.')
    args = parser.parse_args()

    products = list(PRODUCT_CPES)
    if args.products:
        wanted = {p.strip() for p in args.products.split(',') if p.strip()}
        unknown = wanted - set(PRODUCT_CPES)
        if unknown:
            _log(f'[!] Unknown product(s) ignored: {", ".join(sorted(unknown))}')
        products = [p for p in products if p in wanted]
        if not products:
            _log('[!] No known products selected; nothing to do.')
            return 1

    fresh, age_days = is_fresh(args.ttl_days)
    if fresh and not args.force and not args.dry_run and not args.products:
        _log(f'[*] nvd_cve_db.json is {age_days:.1f} days old '
             f'(within {args.ttl_days:g}-day TTL); skipping. Use --force to override.')
        return 0

    api_key = os.environ.get('NVD_API_KEY', '')
    pause = 0.6 if api_key else 6.0
    _log(f'[*] Refreshing NVD CVE DB ({len(products)} product(s), '
         f'min CVSS {args.min_cvss:g}, {"API key" if api_key else "no API key"}, '
         f'{pause:g}s pause).')

    existing = load_existing()
    prev_index = existing.get('index', {})
    prev_meta_products = existing.get('_meta', {}).get('products', {})
    index = dict(prev_index)                 # carry existing entries forward
    meta_products = dict(prev_meta_products)

    failed: list[str] = []                   # network/fetch failures -> non-zero exit
    empty: list[str] = []                    # fetched OK but no qualifying CVEs
    now = datetime.datetime.utcnow().isoformat() + 'Z'
    request_count = 0

    for product in products:
        prefixes = PRODUCT_CPES[product]
        key = storage_key(product)
        vulns: list = []
        ok = True
        for pfx in prefixes:
            for sev_param in SEVERITY_PARAMS:
                if request_count:
                    time.sleep(pause)        # rate limit between every request
                request_count += 1
                try:
                    vulns.extend(fetch(pfx, sev_param, api_key, pause))
                except (urllib.error.URLError, socket.timeout, TimeoutError,
                        json.JSONDecodeError) as exc:
                    _log(f'[!] {product} ({pfx} / {sev_param}): fetch failed ({exc}); '
                         f'keeping any existing entries.')
                    ok = False
                    break
            if not ok:
                break
        if not ok:
            failed.append(product)
            continue

        entries = extract_entries(vulns, prefixes, args.min_cvss)
        if entries:
            index[key] = entries
            meta_products[key] = {'cpe': prefixes, 'count': len(entries),
                                  'refreshed_at': now}
            _log(f'[+] {product} -> {key}: {len(entries)} CVE(s).')
        else:
            # Nothing qualifying. Preserve prior good data if we had any; else
            # leave the key ABSENT so lookups fail open to the live API.
            if prev_index.get(key):
                index[key] = prev_index[key]
                _log(f'[=] {product} -> {key}: 0 fetched; kept '
                     f'{len(prev_index[key])} existing.')
            else:
                index.pop(key, None)
                meta_products.pop(key, None)
                empty.append(key)
                _log(f'[-] {product} -> {key}: 0 CVE(s); left to live-API fallback.')

    out = {
        '_meta': {
            'source': 'NVD JSON 2.0 feed (services.nvd.nist.gov/rest/json/cves/2.0)',
            'schema_version': SCHEMA_VERSION,
            'min_cvss': args.min_cvss,
            'refreshed_at': now,
            'products': {k: meta_products[k] for k in sorted(meta_products)},
        },
        'index': {k: index[k] for k in sorted(index)},
    }

    total_cves = sum(len(v) for v in out['index'].values())
    if args.dry_run:
        _log(json.dumps(out, indent=2))
        _log(f'[*] DRY RUN: {len(out["index"])} product(s), {total_cves} CVE(s). '
             f'Not written.')
        return 1 if failed else 0

    if not out['index'] and failed:
        _log('[!] All fetches failed and no prior DB to preserve; not writing.')
        return 1

    try:
        atomic_write(out)
    except OSError as exc:
        _log(f'[!] Atomic write failed ({exc}); existing DB preserved.')
        return 1

    _log(f'[+] Wrote {OUT_PATH}')
    _log(f'    products in index: {len(out["index"])}, total CVEs: {total_cves}')
    if empty:
        _log(f'    no-data (live fallback): {", ".join(empty)}')
    if failed:
        _log(f'[!] {len(failed)} product(s) failed to fetch (prior entries kept): '
             f'{", ".join(failed)}')
        _log('    Exit non-zero; the next daily run will fill these in.')
        return 1
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        _log('\n[!] Interrupted by user; existing DB preserved.')
        sys.exit(1)
