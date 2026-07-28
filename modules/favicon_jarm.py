"""
VaktScan favicon-hash + JARM fingerprinting module.

Computes *pivot fingerprints* for alive web hosts so they can be cross-referenced
in Shodan/Censys (whose API keys VaktScan already reads via
``modules/passive_intel.py``):

  * FAVICON HASH - fetch each host's ``/favicon.ico`` and compute the mmh3
    (MurmurHash3) hash the way Shodan expects: base64-encode the raw favicon
    bytes with a newline every 76 chars, then ``mmh3.hash(b64)``. Searchable in
    Shodan as ``http.favicon.hash:<hash>``. When the computed hash matches a
    curated map of well-known favicon fingerprints, an extra INFO finding names
    the identified PRODUCT. IMPORTANT: a favicon identifies the product/appliance
    ONLY - it carries NO version information - so this is an identification /
    pivot signal and is NEVER used to fabricate a version or drive version->CVE
    inference.
  * JARM - compute the JARM active TLS fingerprint per ``host:port``. Searchable
    in Shodan as ``ssl.jarm:<hash>`` (and equivalently in Censys).

Both capabilities degrade gracefully:
  * if ``mmh3`` is not importable, favicon hashing is skipped (one info line);
  * if neither a ``jarm`` CLI nor a ``jarm``/``pyjarm`` python module is present,
    JARM is skipped.

The module never raises out of the scan path - a host that errors simply yields
no finding.

Findings are emitted as canonical VaktScan INFO findings (see
``modules/schema.py``) carrying the hash plus a pivot hint, and are intended to
feed the Shodan/Censys enrichment in ``modules/passive_intel.py``.
"""

import asyncio
import base64
import importlib
import os
import re
import shutil
from urllib.parse import urlparse

import httpx

from modules import proc
from modules.progress import DashboardProgress
from modules.schema import normalize_finding

MODULE_NAME = 'favicon_jarm'

# Short timeouts - a favicon fetch or JARM probe should never stall a scan.
_TIMEOUT = httpx.Timeout(8.0, connect=5.0)

_USER_AGENT = 'VaktScan/1.0 favicon-jarm'

# JARM hashes are 62 lowercase hex characters. An all-zero hash means the target
# did not complete a TLS handshake and carries no pivot value.
_JARM_HASH_RE = re.compile(r'([0-9a-f]{62})')

# ─── Optional dependency: mmh3 ─────────────────────────────────────────────────

try:
    import mmh3  # type: ignore
    _HAVE_MMH3 = True
except Exception:  # pragma: no cover - exercised via monkeypatch in tests
    mmh3 = None
    _HAVE_MMH3 = False


# ─── Finding helper ────────────────────────────────────────────────────────────

def _finding(vulnerability: str, details: str, host: str, url: str, port) -> dict:
    """Build a canonical INFO finding (schema-normalized)."""
    return normalize_finding({
        'status': 'INFO',
        'severity': 'INFO',
        'vulnerability': vulnerability,
        'details': details,
        'target': host,
        'port': port,
        'url': url,
        'payload_url': url,
        'module': MODULE_NAME,
    })


# ─── Target parsing ────────────────────────────────────────────────────────────

def _parse_target(url: str):
    """Return ``(scheme, host, port)`` for *url* or ``None`` if unparseable.

    Accepts full URLs (``https://host:443``) or bare hosts (assumed https).
    """
    url = (url or '').strip()
    if not url:
        return None
    if '://' not in url:
        url = 'https://' + url
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    host = parsed.hostname
    if not host:
        return None
    scheme = (parsed.scheme or 'https').lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    if not port:
        port = 443 if scheme == 'https' else 80
    return scheme, host, port


# ─── Curated favicon-hash -> product identification ────────────────────────────
#
# A small, curated map of well-known favicon mmh3 hashes (Shodan-style: the hash
# of ``base64.encodebytes(favicon_bytes)``) to the PRODUCT that ships that
# favicon. These are publicly documented FOFA/Shodan favicon fingerprints for
# common admin panels / servers / appliances. The map is intentionally
# conservative and meant to be extended.
#
# HONESTY / SCOPE: a favicon hash identifies the PRODUCT ONLY. It says NOTHING
# about the version, so a match is an identification / pivot signal - it is
# emitted as INFO and MUST NOT be used to infer a version or to drive a
# version->CVE lookup. Versions are never fabricated from a favicon.
FAVICON_PRODUCT_MAP: dict[int, str] = {
    81586312:    "Jenkins",
    116323821:   "Spring Boot (default Whitelabel error/favicon)",
    -1968180568: "GitLab",
    -1616143106: "Grafana",
    -1520332186: "phpMyAdmin",
    1073055960:  "pfSense",
    -235216981:  "Cisco (device management)",
    999357577:   "Kibana",
    743365239:   "Fortinet FortiGate",
    -297069493:  "Apache Tomcat (default favicon)",
}


def favicon_product(fhash) -> str | None:
    """Return the product identity for a known favicon mmh3 hash, or ``None``.

    IMPORTANT: this identifies the PRODUCT / appliance only. A favicon carries no
    version information, so the result is used solely as an identification / pivot
    signal and NEVER to infer a version or a CVE. Returns ``None`` for unknown or
    unparseable hashes.
    """
    try:
        return FAVICON_PRODUCT_MAP.get(int(fhash))
    except (TypeError, ValueError):
        return None


# ─── Favicon (mmh3) fingerprint ────────────────────────────────────────────────

def _shodan_favicon_hash(raw: bytes) -> int:
    """Compute the Shodan-style mmh3 favicon hash.

    Shodan base64-encodes the raw favicon bytes with a newline inserted every 76
    characters (MIME/``base64.encodebytes`` style, including a trailing newline)
    and then MurmurHash3-hashes that base64 text. ``mmh3.hash`` uses seed 0 and
    returns a signed 32-bit int, matching Shodan's ``http.favicon.hash`` values.
    """
    b64 = base64.encodebytes(raw)
    return mmh3.hash(b64)


async def _favicon_hash(client: httpx.AsyncClient, sem: asyncio.Semaphore,
                        scheme: str, host: str, port) -> tuple | None:
    """Fetch ``/favicon.ico`` and return ``(hash, favicon_url)`` or ``None``."""
    favicon_url = f'{scheme}://{host}:{port}/favicon.ico'
    try:
        async with sem:
            resp = await client.get(favicon_url)
    except Exception:
        return None

    if resp.status_code == 200 and resp.content:
        try:
            return _shodan_favicon_hash(resp.content), favicon_url
        except Exception:
            return None
    return None


# ─── JARM fingerprint ──────────────────────────────────────────────────────────

def _jarm_cli_path() -> str | None:
    """Return a path to a JARM CLI binary, or ``None``.

    Honours ``VAKT_JARM_BIN`` first (like ``modules/gau_runner.py`` honours its
    own override), then falls back to ``jarm`` / ``pyjarm`` on ``PATH``. Never
    auto-installs.
    """
    override = os.environ.get('VAKT_JARM_BIN')
    if override:
        expanded = os.path.expanduser(override)
        if os.path.isabs(expanded):
            return expanded if os.path.exists(expanded) else None
        resolved = shutil.which(expanded)
        if resolved:
            return resolved
    return shutil.which('jarm') or shutil.which('pyjarm')


def _jarm_py_module():
    """Return an importable ``jarm`` / ``pyjarm`` module, or ``None``."""
    for name in ('jarm', 'pyjarm'):
        try:
            return importlib.import_module(name)
        except Exception:
            continue
    return None


def jarm_available() -> bool:
    """True if a JARM CLI or python module is available."""
    return bool(_jarm_cli_path() or _jarm_py_module())


def _parse_jarm_output(text: str) -> str | None:
    """Extract a JARM hash from CLI output; skip the all-zero (no-TLS) result."""
    for match in _JARM_HASH_RE.finditer(text or ''):
        candidate = match.group(1)
        if set(candidate) != {'0'}:
            return candidate
    return None


async def _jarm_via_cli(binary: str, host: str, port) -> str | None:
    """Run the JARM CLI (``<binary> <host> -p <port>``) and parse its output."""
    cmd = [binary, host, '-p', str(port)]
    try:
        result = await proc.run_tool(cmd)
        stdout = result.stdout
    except Exception:
        return None
    return _parse_jarm_output(stdout.decode(errors='ignore'))


async def _jarm_via_py(module, host: str, port) -> str | None:
    """Best-effort JARM via a python module (``jarm``/``pyjarm``).

    Different libraries expose different APIs; each attempt is guarded so an
    unexpected shape degrades to a graceful skip rather than raising.
    """
    # pyjarm >= 0.x exposes an async Scanner.scan_async(host, port).
    scanner = getattr(module, 'Scanner', None)
    scan_async = getattr(scanner, 'scan_async', None) if scanner is not None else None
    if scan_async is not None:
        try:
            result = await scan_async(host, port)
            if isinstance(result, (list, tuple)) and result:
                result = result[0]
            if result:
                return _parse_jarm_output(str(result))
        except Exception:
            return None

    # A plain module-level scan(host, port) coroutine/function fallback.
    scan = getattr(module, 'scan', None)
    if callable(scan):
        try:
            result = scan(host, port)
            if asyncio.iscoroutine(result):
                result = await result
            if isinstance(result, (list, tuple)) and result:
                result = result[0]
            if result:
                return _parse_jarm_output(str(result))
        except Exception:
            return None
    return None


async def _compute_jarm(host: str, port) -> str | None:
    """Compute a JARM fingerprint, preferring the CLI, then a python module.

    Returns the hash string, or ``None`` when JARM is unavailable / fails.
    """
    cli = _jarm_cli_path()
    if cli:
        return await _jarm_via_cli(cli, host, port)
    module = _jarm_py_module()
    if module is not None:
        return await _jarm_via_py(module, host, port)
    return None


# ─── Per-host worker ───────────────────────────────────────────────────────────

async def _fingerprint_one(client: httpx.AsyncClient, sem: asyncio.Semaphore,
                           url: str, do_favicon: bool = True,
                           do_jarm: bool = True) -> list[dict]:
    """Produce favicon + JARM pivot findings for a single alive URL."""
    findings: list[dict] = []
    parsed = _parse_target(url)
    if not parsed:
        return findings
    scheme, host, port = parsed

    # --- Favicon mmh3 hash ---
    if do_favicon and _HAVE_MMH3:
        fav = await _favicon_hash(client, sem, scheme, host, port)
        if fav is not None:
            fhash, favicon_url = fav
            findings.append(_finding(
                'Favicon Hash (Shodan/Censys Pivot)',
                (
                    f'Favicon mmh3 hash for {host} is {fhash}. '
                    f'pivot: search this favicon hash in Shodan '
                    f'(http.favicon.hash:{fhash}) or Censys to discover other '
                    f'hosts - including attacker infrastructure - serving the '
                    f'same favicon.'
                ),
                host, favicon_url, port,
            ))

            # Curated favicon -> PRODUCT identification. Product only, NO version:
            # this is an identification / pivot signal, not a CVE source.
            product = favicon_product(fhash)
            if product:
                findings.append(_finding(
                    'Product Identified via Favicon',
                    (
                        f'The favicon served by {host} matches the well-known '
                        f'favicon of {product} (mmh3 hash {fhash}). This '
                        f'identifies the PRODUCT only - a favicon carries NO '
                        f'version information, so this is an identification / '
                        f'pivot signal and is NOT used to infer a version or a '
                        f'CVE. Determine the running version by other means '
                        f'before assessing vulnerabilities.'
                    ),
                    host, favicon_url, port,
                ))

    # --- JARM TLS fingerprint ---
    if do_jarm:
        jarm_hash = await _compute_jarm(host, port)
        if jarm_hash:
            target_url = f'{scheme}://{host}:{port}'
            findings.append(_finding(
                'JARM TLS Fingerprint (Shodan/Censys Pivot)',
                (
                    f'JARM TLS fingerprint for {host}:{port} is {jarm_hash}. '
                    f'pivot: search this JARM hash in Shodan (ssl.jarm:{jarm_hash}) '
                    f'or Censys to find hosts with an identical TLS stack.'
                ),
                host, target_url, port,
            ))

    return findings


# ─── Public entry point ────────────────────────────────────────────────────────

def _dedupe(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        key = (u or '').strip()
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out


async def fingerprint_favicon_jarm(alive_urls: list[str], output_dir: str,
                                   concurrency: int = 20) -> list[dict]:
    """
    Compute favicon-hash and JARM pivot fingerprints for *alive_urls*.

    Args:
        alive_urls: full URLs of alive web hosts (e.g. ``https://host:443``).
        output_dir: scan output directory (accepted for signature parity with
            other runners; this module writes no files of its own).
        concurrency: max concurrent favicon fetches.

    Returns a list of canonical INFO findings (favicon + JARM pivots). Returns
    ``[]`` on empty input or when every dependency is missing. Never raises.
    """
    if not alive_urls:
        return []

    have_jarm = jarm_available()

    # Both capabilities unavailable → nothing to compute.
    if not _HAVE_MMH3 and not have_jarm:
        print(
            '\033[93m[!] favicon_jarm: mmh3 not importable and no jarm CLI/module '
            'found - skipping favicon/JARM fingerprinting.\033[0m'
        )
        return []

    if not _HAVE_MMH3:
        print(
            '\033[93m[!] favicon_jarm: mmh3 not importable - skipping favicon '
            'hashing (JARM still computed).\033[0m'
        )
    if not have_jarm:
        print(
            '\033[93m[!] favicon_jarm: no jarm CLI or jarm/pyjarm module found - '
            'skipping JARM (favicon hashing still computed).\033[0m'
        )

    urls = _dedupe(alive_urls)
    sem = asyncio.Semaphore(max(1, concurrency))
    prog = DashboardProgress(MODULE_NAME, total=len(urls), noun='hosts')

    transport = httpx.AsyncHTTPTransport(retries=0)
    async with httpx.AsyncClient(
        timeout=_TIMEOUT,
        follow_redirects=True,
        max_redirects=3,
        verify=False,
        transport=transport,
        headers={'User-Agent': _USER_AGENT},
    ) as client:
        tasks = [
            prog.wrap(_fingerprint_one(
                client, sem, u,
                do_favicon=_HAVE_MMH3,
                do_jarm=have_jarm,
            ))
            for u in urls
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[dict] = []
    for result in results:
        if isinstance(result, list):
            findings.extend(result)
        elif isinstance(result, Exception):
            print(f'\033[91m[!] favicon_jarm error: {result}\033[0m')

    if findings:
        print(
            f'\033[92m[+] favicon_jarm computed {len(findings)} pivot '
            f'fingerprint(s) across {len(urls)} host(s).\033[0m'
        )
    return findings
