"""
tech_fingerprint.py — Technology + version fingerprinting for VaktScan.

Entry point:
    async def fingerprint_tech(
        alive_urls: list[str], output_dir: str, concurrency: int = 20
    ) -> list[dict]

Goal
----
Precise technology / version fingerprinting of alive web hosts, cross-referenced
against End-of-Life (EOL) data from https://endoflife.date so that the existing
NVD / KEV / EPSS enrichment becomes more actionable.

Detection strategy
------------------
1. If ``webanalyze`` (the Wappalyzer engine) is present on ``PATH`` (or pointed at
   by ``VAKT_WEBANALYZE_BIN``) it is invoked per-URL with ``-output json`` and its
   results are parsed. No auto-install — if it is missing we simply fall back.
2. Otherwise (or if webanalyze yields nothing for a URL) a lightweight built-in
   detector inspects the ``Server`` / ``X-Powered-By`` response headers plus a
   couple of common HTML markers (``<meta name="generator">``, WordPress paths)
   via httpx. It never raises.

EOL cross-reference (false-positive disciplined — see TODO.md §1)
----------------------------------------------------------------
A "Software End-of-Life" (VULNERABLE) finding is emitted ONLY when ALL hold:
  1. a concrete PRODUCT *and* a specific VERSION were detected (never guessed
     from a bare product name, never a version-less marker);
  2. the product maps to an endoflife.date slug and its release-cycle table was
     fetched successfully (fetched once per product, cached in-process);
  3. the version matches a concrete release cycle; and
  4. that cycle carries an actual ``eol`` DATE that is in the past.
If any condition fails (unknown product, partial/absent version, no matching
cycle, boolean/undated ``eol``, or a future date) at most an INFO tech-detection
finding is produced — never a VULNERABLE/EOL one. Network failure simply skips
the EOL step and keeps the plain fingerprint — never a crash.

Relationship to modules/web_checks.py
-------------------------------------
``web_checks.py`` already carries a *heuristic* EOL check (``_check_eol_version``
— hardcoded thresholds for php/nginx/apache/openssl, read from the ``Server`` /
``X-Powered-By`` headers). It does NOT query endoflife.date. This module reuses
that exact product vocabulary and the same header sources, but replaces the
hardcoded thresholds with live endoflife.date cycle data. To avoid double-report
/ conflict the two are meant to be reconciled at wiring time (dedup by
(target, product) or retire the heuristic check) — see the wiring note returned
by this task.

Findings emitted (canonical schema, see modules/schema.py)
---------------------------------------------------------
* INFO  — "Technology Detected: <name> <version>"
* MEDIUM/HIGH — "Software End-of-Life: <name> <version>" (includes the EOL date)
"""

from __future__ import annotations

import asyncio
import datetime
import json
import os
import re
import shutil
from urllib.parse import urlparse

import httpx

from modules.progress import DashboardProgress
from modules.schema import normalize_finding

MODULE_NAME = "tech_fingerprint"

ENDOFLIFE_API = "https://endoflife.date/api"

_HTTP_TIMEOUT = httpx.Timeout(8.0, connect=5.0)
_WEBANALYZE_TIMEOUT = 60.0

# Detected technology name (lowercased) -> endoflife.date product slug.
# Kept aligned with the vocabulary already used by modules/web_checks.py.
EOL_PRODUCT_MAP: dict[str, str] = {
    "php": "php",
    "nginx": "nginx",
    "apache": "apache",
    "apache http server": "apache",
    "apache httpd": "apache",
    "httpd": "apache",
    "openssl": "openssl",
    "python": "python",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "apache tomcat": "tomcat",
    "tomcat": "tomcat",
    "django": "django",
    "laravel": "laravel",
    "ubuntu": "ubuntu",
    "debian": "debian",
}


# ─── Binary resolution ─────────────────────────────────────────────────────────

def _webanalyze_binary() -> str | None:
    """Resolve the webanalyze binary (env override first), or None if absent."""
    env = os.environ.get("VAKT_WEBANALYZE_BIN")
    if env:
        expanded = os.path.expanduser(env)
        if os.path.isabs(expanded):
            if os.path.exists(expanded):
                return expanded
        else:
            found = shutil.which(expanded)
            if found:
                return found
    return shutil.which("webanalyze")


# ─── Detection primitives ──────────────────────────────────────────────────────

def _product_slug(name: str) -> str | None:
    """Map a detected technology name to an endoflife.date product slug (or None)."""
    key = (name or "").strip().lower()
    if key in EOL_PRODUCT_MAP:
        return EOL_PRODUCT_MAP[key]
    first = key.split()[0] if key.split() else ""
    return EOL_PRODUCT_MAP.get(first)


def _mk_det(name: str, version: str, categories: list[str], source: str) -> dict:
    return {
        "name": (name or "").strip(),
        "product": _product_slug(name),
        "version": (version or "").strip(),
        "categories": categories or [],
        "source": source,
    }


def _dedup_dets(dets: list[dict]) -> list[dict]:
    """Dedup by (name, version); drop versionless dupes when a versioned one exists."""
    names_with_version = {d["name"].lower() for d in dets if d["version"]}
    out: list[dict] = []
    seen: set[tuple] = set()
    for d in dets:
        if not d.get("name"):
            continue
        nl = d["name"].lower()
        if not d["version"] and nl in names_with_version:
            continue
        key = (nl, d["version"])
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


# Matches "name/version" pairs in Server / X-Powered-By headers, e.g.
# "nginx/1.18.0", "Apache/2.4.7", "OpenSSL/1.0.2k", "PHP/7.4.3".
_HEADER_TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z0-9_+.\-]*?)/([0-9][0-9A-Za-z.\-]*)")
_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I
)


def _parse_generator(content: str) -> dict | None:
    """Parse a `<meta generator>` content string into a detection dict."""
    content = (content or "").strip()
    if not content:
        return None
    m = re.match(r"([A-Za-z][A-Za-z0-9 .\-]*?)\s+v?([0-9][0-9A-Za-z.\-]*)", content)
    if m:
        return _mk_det(m.group(1).strip(), m.group(2), ["CMS"], "builtin")
    return _mk_det(content, "", ["CMS"], "builtin")


async def _builtin_detect(client: httpx.AsyncClient, url: str,
                          sem: asyncio.Semaphore) -> list[dict]:
    """Header + HTML-marker based detection. Never raises."""
    try:
        async with sem:
            resp = await client.get(url)
    except Exception:
        return []

    dets: list[dict] = []
    try:
        headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}
    except Exception:
        headers = {}

    for hv in (headers.get("server", ""), headers.get("x-powered-by", "")):
        if not hv:
            continue
        for m in _HEADER_TOKEN_RE.finditer(hv):
            dets.append(_mk_det(m.group(1), m.group(2), ["Server"], "builtin"))

    try:
        text = resp.text or ""
    except Exception:
        text = ""

    if text:
        gm = _GENERATOR_RE.search(text)
        if gm:
            det = _parse_generator(gm.group(1))
            if det:
                dets.append(det)
        if "wp-content" in text or "wp-includes" in text:
            dets.append(_mk_det("WordPress", "", ["CMS"], "builtin"))

    return _dedup_dets(dets)


def _parse_webanalyze_output(text: str) -> list[dict]:
    """Parse webanalyze `-output json` (single object or JSON-lines). Never raises."""
    text = (text or "").strip()
    if not text:
        return []

    objs: list = []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            objs = data
        elif isinstance(data, dict):
            objs = [data]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    dets: list[dict] = []
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        matches = obj.get("matches") or []
        if not isinstance(matches, list):
            continue
        for mm in matches:
            if not isinstance(mm, dict):
                continue
            # Field name varies across webanalyze versions.
            name = mm.get("app_name") or mm.get("app") or mm.get("name")
            if not name:
                continue
            version = mm.get("version") or ""
            cats = mm.get("categories") or []
            if not isinstance(cats, list):
                cats = []
            dets.append(_mk_det(str(name), str(version),
                                [str(c) for c in cats], "webanalyze"))
    return _dedup_dets(dets)


def _save_raw(output_dir: str, url: str, text: str) -> None:
    """Persist raw webanalyze output for traceability. Never raises."""
    if not (output_dir and text and text.strip()):
        return
    try:
        d = os.path.join(output_dir, "tech_fingerprint")
        os.makedirs(d, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", url)[:150] or "host"
        with open(os.path.join(d, f"{safe}.json"), "w", encoding="utf-8") as fh:
            fh.write(text)
    except Exception:
        pass


async def _run_webanalyze(binary: str, url: str, sem: asyncio.Semaphore,
                          output_dir: str) -> list[dict]:
    """Run webanalyze for a single URL and parse its JSON. Never raises."""
    cmd = [binary, "-host", url, "-output", "json", "-silent"]
    apps = os.environ.get("VAKT_WEBANALYZE_APPS")
    if apps:
        cmd += ["-apps", apps]
    try:
        async with sem:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await asyncio.wait_for(
                proc.communicate(), timeout=_WEBANALYZE_TIMEOUT
            )
    except Exception:
        return []

    text = (stdout or b"").decode("utf-8", errors="replace")
    _save_raw(output_dir, url, text)
    return _parse_webanalyze_output(text)


async def _detect_for_url(client: httpx.AsyncClient, binary: str | None, url: str,
                          sem: asyncio.Semaphore, output_dir: str) -> list[dict]:
    """Fingerprint a single URL: webanalyze if available, else/also built-in."""
    if binary:
        dets = await _run_webanalyze(binary, url, sem, output_dir)
        if dets:
            return dets
        # webanalyze produced nothing (missing apps db, error, no match) →
        # fall back to the built-in detector so we still get a signal.
    return await _builtin_detect(client, url, sem)


# ─── End-of-Life cross-reference ───────────────────────────────────────────────

async def _fetch_eol_cycles(client: httpx.AsyncClient, product: str,
                            cache: dict) -> list | None:
    """Fetch endoflife.date release cycles for *product* (cached). Never raises."""
    if product in cache:
        return cache[product]
    cycles = None
    try:
        resp = await client.get(f"{ENDOFLIFE_API}/{product}.json")
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                cycles = data
    except Exception:
        cycles = None
    cache[product] = cycles
    return cycles


def _match_cycle(version: str, cycles: list) -> dict | None:
    """Return the most-specific release cycle whose prefix matches *version*."""
    if not version or not isinstance(cycles, list):
        return None
    best: dict | None = None
    best_len = -1
    for c in cycles:
        if not isinstance(c, dict):
            continue
        cs = str(c.get("cycle", "")).strip()
        if not cs:
            continue
        # cycle prefix must be followed by a non-digit or end-of-string so that
        # "8.1" does not spuriously match "8.10", while "1.0.2" matches "1.0.2k".
        if re.match(re.escape(cs) + r"(\D|$)", version):
            if len(cs) > best_len:
                best_len = len(cs)
                best = c
    return best


def _eol_status(cycle: dict, today: datetime.date) -> tuple[bool, str | None]:
    """Return (is_eol, eol_date_str) for a matched cycle.

    False-positive prevention: an EOL finding is only warranted when the cycle
    carries a CONCRETE end-of-life *date* that is in the past. A boolean ``eol``
    (true/false), a missing value, an unparseable value, or a future date is NOT
    treated as EOL — at most an INFO tech-detection finding is emitted for those.
    This guarantees every EOL finding can cite an actual date.
    """
    eol = cycle.get("eol")
    if isinstance(eol, str) and eol.strip():
        try:
            d = datetime.date.fromisoformat(eol.strip())
        except ValueError:
            return False, None
        if d <= today:
            return True, eol.strip()
    return False, None


# ─── Finding builders ──────────────────────────────────────────────────────────

def _finding(*, status: str, severity: str, vulnerability: str, details: str,
             url: str, service_version: str = "N/A") -> dict:
    p = urlparse(url)
    host = p.hostname or url
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        port = 443 if p.scheme == "https" else 80
    return normalize_finding({
        "status": status,
        "severity": severity,
        "vulnerability": vulnerability,
        "target": host,
        "resolved_ip": "N/A",
        "port": str(port),
        "url": url,
        "payload_url": url,
        "module": MODULE_NAME,
        "service_version": service_version or "N/A",
        "details": details,
        "http_status": "N/A",
        "page_title": "N/A",
        "content_length": "N/A",
    })


def _info_finding(url: str, det: dict) -> dict:
    label = f"{det['name']} {det['version']}".strip()
    cats = ", ".join(det["categories"]) if det["categories"] else "N/A"
    details = (
        f"Technology fingerprinted via {det['source']}: {label}. "
        f"Categories: {cats}. Feed the product/version into NVD/KEV/EPSS "
        f"enrichment for CVE correlation."
    )
    return _finding(
        status="INFO",
        severity="INFO",
        vulnerability=f"Technology Detected: {label}",
        details=details,
        url=url,
        service_version=det["version"] or "N/A",
    )


def _eol_finding(url: str, det: dict, eol_date: str,
                 today: datetime.date) -> dict:
    name, ver = det["name"], det["version"]
    try:
        d = datetime.date.fromisoformat(eol_date)
        days_past = (today - d).days
    except (ValueError, TypeError):
        days_past = 0
    # Longer-unsupported cycles are higher risk.
    severity = "HIGH" if days_past > 365 else "MEDIUM"
    details = (
        f"{name} version {ver} reached End-of-Life on {eol_date} (per "
        f"endoflife.date). End-of-Life software no longer receives security "
        f"patches, increasing exposure to known and future vulnerabilities. "
        f"Cross-reference this version against NVD/KEV/EPSS to prioritise "
        f"actionable CVEs."
    )
    return _finding(
        status="VULNERABLE",
        severity=severity,
        vulnerability=f"Software End-of-Life: {name} {ver}".strip(),
        details=details,
        url=url,
        service_version=ver or "N/A",
    )


# ─── Public entry point ────────────────────────────────────────────────────────

async def fingerprint_tech(alive_urls: list[str], output_dir: str,
                           concurrency: int = 20) -> list[dict]:
    """
    Fingerprint technologies/versions on *alive_urls* and cross-reference them
    against endoflife.date, returning canonical VaktScan findings.

    Returns [] on empty input and never raises.
    """
    if not alive_urls:
        return []

    urls = list(dict.fromkeys(u.strip() for u in alive_urls if u and u.strip()))
    if not urls:
        return []

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception:
        pass

    binary = _webanalyze_binary()
    sem = asyncio.Semaphore(max(1, int(concurrency)))
    findings: list[dict] = []

    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT,
        follow_redirects=True,
        max_redirects=3,
        verify=False,
        headers={"User-Agent": "VaktScan/1.0 tech-fingerprint"},
    ) as client:
        prog = DashboardProgress("tech_fingerprint", total=len(urls), noun="hosts")

        det_results = await asyncio.gather(
            *(prog.wrap(_detect_for_url(client, binary, u, sem, output_dir))
              for u in urls),
            return_exceptions=True,
        )

        url_dets: list[tuple[str, list[dict]]] = []
        for u, res in zip(urls, det_results):
            if isinstance(res, list):
                url_dets.append((u, res))

        # Fetch EOL cycles once per unique product (in-process cache).
        cache: dict[str, list | None] = {}
        products = {
            d["product"]
            for _u, dets in url_dets
            for d in dets
            if d["product"] and d["version"]
        }
        if products:
            await asyncio.gather(
                *(_fetch_eol_cycles(client, p, cache) for p in products),
                return_exceptions=True,
            )

        today = datetime.date.today()
        for u, dets in url_dets:
            for d in dets:
                findings.append(_info_finding(u, d))
                if not (d["product"] and d["version"]):
                    continue
                cycles = cache.get(d["product"])
                if not cycles:
                    continue
                cyc = _match_cycle(d["version"], cycles)
                if cyc is None:
                    continue
                is_eol, eol_date = _eol_status(cyc, today)
                if is_eol:
                    findings.append(_eol_finding(u, d, eol_date, today))

    return findings
