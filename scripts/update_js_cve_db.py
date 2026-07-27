#!/usr/bin/env python3
"""
Refresh the vendored Retire.js client-side vulnerability database at
modules/data/retirejs_db.json.

Source:
    https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json

This is the RetireJS community-maintained CLIENT-SIDE (browser / served-JS)
repository -- the jsrepository-v4 variant, chosen because it is the most
complete client-side detection database upstream (full set of vulnerability
entries + extractors: uri, filename, filecontent, func, hashes, ast) in a flat
library-name -> {licenses, vulnerabilities, extractors} shape. It is NOT
npmrepository.json (server-side npm advisories not detectable from served JS).

Behaviour mirrors the repo's other refresh/cache conventions:
  * Like modules/cisa_kev.py and modules/nuclei_runner.sync_nuclei_templates(),
    freshness is tracked by the vendored file's mtime. If the DB is newer than
    the TTL (default 7 days, matching the nuclei template TTL) the refresh is
    skipped unless --force is given.
  * The download is validated (parses as JSON, plausible library count, known
    anchor library present, structural sanity, no large regression) BEFORE it
    replaces the vendored copy. The write is atomic (temp file in the same
    directory + os.replace) so a broken/partial download can never clobber a
    good DB.
  * Fail-safe: any network or validation error leaves the existing DB untouched
    and exits non-zero.

No third-party dependencies (stdlib urllib, like scripts/build_bundled_cves.py).

Usage:
    python scripts/update_js_cve_db.py            # refresh if stale
    python scripts/update_js_cve_db.py --force    # refresh unconditionally
    python scripts/update_js_cve_db.py --ttl-days 3
    python scripts/update_js_cve_db.py --url <alternate raw json url>
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(ROOT, 'modules', 'data', 'retirejs_db.json')

DEFAULT_URL = (
    'https://raw.githubusercontent.com/RetireJS/retire.js/master/'
    'repository/jsrepository-v4.json'
)
DEFAULT_TTL_DAYS = 7  # matches modules/nuclei_runner.sync_nuclei_templates()

# Validation thresholds. The current vendored DB carries ~76 libraries; upstream
# v4 carries more. A truncated / error-page download will fall well under these.
MIN_LIBRARIES = 50
# A library that is effectively always present in the client-side repo, used as
# a cheap "this really is the retire.js DB" anchor.
ANCHOR_LIBRARY = 'jquery'
# Fraction of entries that must look like real library entries (have a
# vulnerabilities list) for the payload to be considered structurally sane.
MIN_STRUCTURAL_FRACTION = 0.8
# Refuse a new DB that has fewer than this fraction of the previous library
# count -- guards against upstream hiccups silently shrinking coverage.
MIN_REGRESSION_FRACTION = 0.5

HTTP_TIMEOUT = 30
USER_AGENT = 'VaktScan-retirejs-refresh/1.0'


class ValidationError(Exception):
    """Raised when a downloaded payload fails sanity checks."""


def _log(msg: str) -> None:
    print(msg, flush=True)


def _library_count(data: dict) -> int:
    return len(data)


def _load_existing() -> tuple[dict | None, int]:
    """Return (parsed_db_or_None, library_count). Never raises."""
    if not os.path.exists(DB_PATH):
        return None, 0
    try:
        with open(DB_PATH, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data, _library_count(data)
    except Exception:
        pass
    return None, 0


def _is_fresh(ttl_days: float) -> tuple[bool, float]:
    """Return (fresh, age_days) based on the vendored file's mtime."""
    if not os.path.exists(DB_PATH):
        return False, 0.0
    age_days = (time.time() - os.path.getmtime(DB_PATH)) / 86400.0
    return age_days < ttl_days, age_days


def download(url: str) -> tuple[str, dict]:
    """Download and JSON-parse the repository. Raises on network / parse error."""
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        status = getattr(resp, 'status', 200) or 200
        if status != 200:
            raise urllib.error.URLError(f'unexpected HTTP status {status}')
        raw = resp.read().decode('utf-8')
    data = json.loads(raw)  # raises json.JSONDecodeError on garbage
    return raw, data


def validate(data: object, prev_count: int) -> int:
    """Validate a parsed payload. Returns library count or raises ValidationError."""
    if not isinstance(data, dict) or not data:
        raise ValidationError('payload is not a non-empty JSON object')

    count = _library_count(data)
    if count < MIN_LIBRARIES:
        raise ValidationError(
            f'only {count} libraries (expected at least {MIN_LIBRARIES}); '
            'download looks truncated'
        )

    if ANCHOR_LIBRARY not in data:
        raise ValidationError(
            f'anchor library {ANCHOR_LIBRARY!r} missing; this does not look '
            'like the retire.js client-side repository'
        )

    structural = sum(
        1
        for entry in data.values()
        if isinstance(entry, dict) and isinstance(entry.get('vulnerabilities'), list)
    )
    if structural < count * MIN_STRUCTURAL_FRACTION:
        raise ValidationError(
            f'only {structural}/{count} entries have a vulnerabilities list; '
            'payload is structurally unexpected'
        )

    if prev_count and count < prev_count * MIN_REGRESSION_FRACTION:
        raise ValidationError(
            f'new DB has {count} libraries vs {prev_count} previously '
            f'(< {int(MIN_REGRESSION_FRACTION * 100)}%); refusing to shrink '
            'coverage on a possibly-bad download'
        )

    return count


def atomic_write(raw_text: str) -> None:
    """Write raw_text to DB_PATH atomically (temp file + os.replace)."""
    dest_dir = os.path.dirname(DB_PATH)
    os.makedirs(dest_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=dest_dir, prefix='.retirejs_db.', suffix='.tmp'
    )
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(raw_text)
            if not raw_text.endswith('\n'):
                fh.write('\n')
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, DB_PATH)  # atomic on the same filesystem
    except Exception:
        # Never leave a stray temp file or a half-written DB behind.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Refresh modules/data/retirejs_db.json from the RetireJS '
                    'client-side (jsrepository-v4) repository.'
    )
    parser.add_argument(
        '--force', action='store_true',
        help='Refresh even if the vendored DB is still within the TTL.',
    )
    parser.add_argument(
        '--ttl-days', type=float, default=DEFAULT_TTL_DAYS,
        help=f'Skip refresh if the DB is newer than this many days '
             f'(default: {DEFAULT_TTL_DAYS}).',
    )
    parser.add_argument(
        '--url', default=DEFAULT_URL,
        help='Override the source repository URL (advanced).',
    )
    args = parser.parse_args()

    prev_data, prev_count = _load_existing()

    fresh, age_days = _is_fresh(args.ttl_days)
    if fresh and not args.force:
        _log(
            f'[*] retirejs_db.json is {age_days:.1f} days old '
            f'(within {args.ttl_days:g}-day TTL); skipping refresh. '
            f'Use --force to override.'
        )
        return 0

    _log(f'[*] Refreshing retire.js DB from {args.url}')
    try:
        raw_text, data = download(args.url)
    except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
        _log(f'[!] Download failed ({exc}); keeping existing DB.')
        return 1
    except json.JSONDecodeError as exc:
        _log(f'[!] Downloaded payload is not valid JSON ({exc}); keeping existing DB.')
        return 1
    except Exception as exc:  # fail-safe: never crash, never clobber
        _log(f'[!] Unexpected download error ({exc}); keeping existing DB.')
        return 1

    try:
        new_count = validate(data, prev_count)
    except ValidationError as exc:
        _log(f'[!] Validation failed: {exc}. Keeping existing DB.')
        return 1

    # Skip the write if content is byte-identical to what we already have.
    if prev_data is not None and data == prev_data:
        # Refresh mtime so the TTL clock resets even when content is unchanged.
        try:
            os.utime(DB_PATH, None)
        except OSError:
            pass
        _log(
            f'[+] Upstream unchanged ({new_count} libraries); '
            f'refreshed freshness timestamp only.'
        )
        return 0

    try:
        atomic_write(raw_text)
    except OSError as exc:
        _log(f'[!] Failed to write DB atomically ({exc}); existing DB preserved.')
        return 1

    delta = new_count - prev_count
    delta_str = f'{delta:+d}' if prev_count else f'{new_count} (new)'
    _log(
        f'[+] Updated {DB_PATH}\n'
        f'    libraries: {prev_count} -> {new_count} ({delta_str})'
    )
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        _log('\n[!] Interrupted by user; existing DB preserved.')
        sys.exit(1)
