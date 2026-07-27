"""
archived_urls.py — VaktScan Archived-URL Weaponizer
===================================================
gau/waybackurls harvest thousands of historical URLs but nothing consumes
them. This module turns that raw list into signal:

1. Dedup / normalize the URL list (``uro`` if present, else an internal
   dedup that collapses near-duplicate URLs by ``path + param-key set``).
2. Filter for high-signal URLs (sensitive extensions + interesting path
   keywords).
3. Re-probe the filtered URLs with the existing ``HTTPXRunner`` to find which
   are LIVE *now* (HTTP 200 or auth-required 401/403).
4. For live archived ``.js`` URLs, scan for hardcoded secrets by REUSING the
   secret engine in ``modules/js_paths.py`` (``JSRecon._check_secrets`` — the
   regexes are NOT duplicated here).
5. Emit canonical findings via ``modules/schema.py`` ``normalize_finding``.

Entry point::

    async def scan_archived_urls(archived_urls: list[str],
                                 output_dir: str,
                                 concurrency: int = 50) -> list[dict]

Returns canonical findings. Returns ``[]`` (never crashes) on empty input or
when the required tools/deps are missing. Follows VaktScan conventions: async
tool wrapping, ``shutil.which`` detection, GRACEFUL skip (one info line, return
``[]``) when a tool is absent — never auto-install, never crash.
"""

import asyncio
import shutil
from urllib.parse import parse_qsl, urlparse

from modules.httpx_runner import HTTPXRunner
from modules.progress import DashboardProgress, heartbeat
from modules.schema import normalize_finding


class _C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GREY = "\033[90m"
    RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Signal definitions
# ---------------------------------------------------------------------------

# Extensions that make an archived URL worth re-probing.
SENSITIVE_EXTENSIONS = (
    ".bak", ".sql", ".dump", ".backup", ".zip", ".tar.gz", ".tgz",
    ".log", ".json", ".yml", ".yaml", ".env", ".git", ".config",
    ".ini", ".old", ".swp", ".php~",
)

# Path keywords that make an archived URL interesting.
INTERESTING_KEYWORDS = ("backup", "dump", "config", "secret", "admin", "api", "internal")

# JS files are handled separately (secret scanning), not as "exposed files".
JS_EXTENSIONS = (".js", ".mjs")

# What counts as "live now": reachable (200) or auth-guarded (401/403).
LIVE_STATUS_CODES = {200, 401, 403}

# Severity tiers for a live, exposed sensitive artifact.
#   env/sql/git/backup-type files = HIGH ; config/data files = MEDIUM ; keyword-only = INFO
HIGH_EXTENSIONS = (
    ".env", ".sql", ".git", ".bak", ".backup", ".dump",
    ".old", ".swp", ".zip", ".tar.gz", ".tgz",
)
HIGH_KEYWORDS = ("backup", "dump")
MEDIUM_EXTENSIONS = (".config", ".ini", ".log", ".json", ".yml", ".yaml", ".php~")
MEDIUM_KEYWORDS = ("config", "secret")
INFO_KEYWORDS = ("admin", "api", "internal")

# Defensive cap so a pathological archive dump can't spawn an unbounded probe.
MAX_PROBE_TARGETS = 3000


# ---------------------------------------------------------------------------
# 1. Normalize / dedup
# ---------------------------------------------------------------------------

def _dedup_internal(urls):
    """Collapse near-duplicate URLs by ``(scheme, netloc, path, param-key set)``.

    Two URLs that differ only in *parameter values* (not keys) are treated as
    one; different param keys or different paths are kept. First occurrence wins.
    """
    seen = set()
    out = []
    for u in urls:
        u = (u or "").strip()
        if not u:
            continue
        parsed = urlparse(u)
        param_keys = frozenset(k for k, _ in parse_qsl(parsed.query, keep_blank_values=True))
        key = (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, param_keys)
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out


async def _run_uro(urls):
    """Run ``uro`` over the URL list if it is on PATH.

    Returns the deduped list, or ``None`` when ``uro`` is unavailable/failed so
    the caller can fall back to the internal dedup.
    """
    uro_bin = shutil.which("uro")
    if not uro_bin:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            uro_bin,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await proc.communicate(input="\n".join(urls).encode())
    except Exception as exc:  # uro present but unusable — degrade gracefully
        print(f"{_C.GREY}[!] uro failed ({exc}); using internal dedup.{_C.RESET}")
        return None
    out = [line.strip() for line in stdout.decode("utf-8", "ignore").splitlines() if line.strip()]
    return out or _dedup_internal(urls)


async def _normalize_and_dedup(urls):
    cleaned = [u.strip() for u in urls if u and u.strip()]
    if not cleaned:
        return []
    uro_out = await _run_uro(cleaned)
    if uro_out is not None:
        print(f"{_C.CYAN}[*] uro normalized {len(cleaned)} → {len(uro_out)} archived URLs.{_C.RESET}")
        return uro_out
    deduped = _dedup_internal(cleaned)
    print(f"{_C.CYAN}[*] Internal dedup normalized {len(cleaned)} → {len(deduped)} archived URLs.{_C.RESET}")
    return deduped


# ---------------------------------------------------------------------------
# 2. Filter for high-signal URLs
# ---------------------------------------------------------------------------

def _ext_match(path, ext):
    """Match ``ext`` as a file suffix OR a directory segment (``.git/config``)."""
    return path.endswith(ext) or (ext + "/") in path


def _is_js(url):
    return urlparse(url.lower()).path.endswith(JS_EXTENSIONS)


def _match_reason(url):
    """Return the first sensitive extension or keyword matched, else ``None``."""
    low = url.lower()
    parsed = urlparse(low)
    path = parsed.path
    path_query = path + (("?" + parsed.query) if parsed.query else "")
    for ext in SENSITIVE_EXTENSIONS:
        if _ext_match(path, ext):
            return ext
    for kw in INTERESTING_KEYWORDS:
        if kw in path_query:
            return kw
    return None


def _filter_high_signal(urls):
    """Split URLs into ``(sensitive_files, js_files)``.

    ``.js``/``.mjs`` go to the JS bucket (secret scanning). Everything else that
    matches a sensitive extension or interesting keyword goes to the sensitive
    bucket. Plain assets/pages are dropped.
    """
    sensitive = []
    js = []
    for u in urls:
        if _is_js(u):
            js.append(u)
            continue
        if _match_reason(u):
            sensitive.append(u)
    return sensitive, js


# ---------------------------------------------------------------------------
# 5. Finding construction
# ---------------------------------------------------------------------------

def _classify(url):
    """Return ``(vulnerability, status, severity)`` for a live sensitive URL."""
    low = url.lower()
    parsed = urlparse(low)
    path = parsed.path
    path_query = path + (("?" + parsed.query) if parsed.query else "")

    for ext in HIGH_EXTENSIONS:
        if _ext_match(path, ext):
            return (f"Exposed Sensitive File ({ext})", "VULNERABLE", "HIGH")
    for kw in HIGH_KEYWORDS:
        if kw in path_query:
            return (f"Exposed Backup/Dump Artifact ({kw})", "VULNERABLE", "HIGH")
    for ext in MEDIUM_EXTENSIONS:
        if _ext_match(path, ext):
            return (f"Exposed Config/Data File ({ext})", "POTENTIAL", "MEDIUM")
    for kw in MEDIUM_KEYWORDS:
        if kw in path_query:
            return (f"Sensitive Keyword Endpoint ({kw})", "POTENTIAL", "MEDIUM")
    for kw in INFO_KEYWORDS:
        if kw in path_query:
            return (f"Interesting Archived Endpoint ({kw})", "INFO", "INFO")
    return ("Archived Sensitive URL", "INFO", "INFO")


def _build_exposure_finding(source_url, live_url, http_status):
    vuln, status_val, severity = _classify(source_url)
    parsed = urlparse(live_url or source_url)
    port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
    detail = (
        f"Archived URL is live now (HTTP {http_status}) and exposes a sensitive "
        f"artifact. Harvested source: {source_url}"
    )
    finding = {
        "target": parsed.hostname or source_url,
        "resolved_ip": "N/A",
        "port": port,
        "vulnerability": vuln,
        "status": status_val,
        "severity": severity,
        "module": "archived_urls",
        "service_version": "N/A",
        "url": live_url or source_url,
        "payload_url": source_url,
        "details": detail,
        "http_status": str(http_status),
        "page_title": "N/A",
        "content_length": "N/A",
    }
    return normalize_finding(finding)


# ---------------------------------------------------------------------------
# 4. Secret scanning of live JS (reuse js_paths engine)
# ---------------------------------------------------------------------------

def _extract_secret_findings(js_url, content):
    """Reuse ``JSRecon._check_secrets`` (and its regexes/severities) on JS text.

    Returns the js_paths finding dicts (already carrying js_paths severities),
    re-tagged with ``module='archived_urls'`` and normalized.
    """
    if not content:
        return []
    try:
        from modules.js_paths import JSRecon
    except Exception:
        return []
    try:
        rec = JSRecon(target_urls=[], threads=1, timeout=10)
        rec._check_secrets(js_url, content)
        raw = list(rec.findings)
    except Exception:
        return []
    out = []
    for f in raw:
        merged = dict(f)
        merged["module"] = "archived_urls"
        out.append(normalize_finding(merged))
    return out


async def _fetch_text(url, timeout=10.0):
    """Fetch a URL's body as text. Returns ``None`` on any failure/missing dep.

    Isolated so tests can mock it without real network access.
    """
    try:
        import httpx as _httpx
    except Exception:
        return None
    try:
        async with _httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
            return resp.text
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Helpers for correlating httpx results back to harvested URLs
# ---------------------------------------------------------------------------

def _resolve_source(entry, known):
    """Best-effort map an httpx result row back to the URL we submitted."""
    for cand in (entry.get("input"), entry.get("url")):
        if cand in known:
            return cand
    return entry.get("input") or entry.get("url") or ""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def scan_archived_urls(archived_urls: list[str], output_dir: str, concurrency: int = 50) -> list[dict]:
    """Weaponize harvested archived URLs into canonical findings.

    See module docstring for the full pipeline. Always returns a list; returns
    ``[]`` on empty input or when required tools/deps are missing, never raises.
    """
    findings: list[dict] = []
    try:
        if not archived_urls:
            return []

        # 1. Normalize + dedup.
        normalized = await _normalize_and_dedup(list(archived_urls))
        if not normalized:
            return []

        # 2. Filter for high-signal URLs.
        sensitive_urls, js_urls = _filter_high_signal(normalized)
        probe_targets = sorted(set(sensitive_urls) | set(js_urls))
        if not probe_targets:
            print(f"{_C.YELLOW}[!] No high-signal archived URLs to re-probe.{_C.RESET}")
            return []
        if len(probe_targets) > MAX_PROBE_TARGETS:
            print(
                f"{_C.YELLOW}[!] Capping archived re-probe at {MAX_PROBE_TARGETS} "
                f"(of {len(probe_targets)}) URLs.{_C.RESET}"
            )
            probe_targets = probe_targets[:MAX_PROBE_TARGETS]

        print(
            f"{_C.CYAN}[*] Re-probing {len(probe_targets)} high-signal archived URLs "
            f"({len(sensitive_urls)} sensitive, {len(js_urls)} JS)...{_C.RESET}"
        )

        # Live dashboard task for the re-probe / secret-scan loop.
        try:
            from modules.dashboard import LiveDashboard
            dashboard = LiveDashboard()
        except Exception:
            dashboard = None
        if dashboard is not None and getattr(dashboard, "active", False):
            dashboard.add_task("archived_urls", "Archived URL Re-Probe", total=len(probe_targets))

        try:
            # 3. Re-probe with the existing HTTPXRunner.
            probe_results = []
            try:
                runner = HTTPXRunner(output_dir=output_dir)
                async with heartbeat("archived_urls", "Re-probing archived URLs"):
                    probe_results = await runner.run_httpx(probe_targets, concurrency)
            except Exception as exc:
                print(f"{_C.RED}[!] Archived URL re-probe failed: {exc}{_C.RESET}")
                probe_results = []

            sensitive_set = set(sensitive_urls)
            js_set = set(js_urls)
            known = set(probe_targets)
            live_js = []

            for entry in probe_results or []:
                if not isinstance(entry, dict):
                    continue
                try:
                    status_code = int(entry.get("status_code") or 0)
                except (TypeError, ValueError):
                    status_code = 0
                if status_code not in LIVE_STATUS_CODES:
                    continue

                source = _resolve_source(entry, known)
                live_url = entry.get("url") or source
                if not source:
                    continue

                # Exposed sensitive file (not a .js — those get secret-scanned).
                if source in sensitive_set or (not _is_js(source) and _match_reason(source)):
                    findings.append(_build_exposure_finding(source, live_url, status_code))

                # Live JS → queue for secret scanning.
                if source in js_set or _is_js(source):
                    live_js.append((source, live_url, status_code))

            live_count = sum(
                1 for e in (probe_results or [])
                if isinstance(e, dict) and _safe_int(e.get("status_code")) in LIVE_STATUS_CODES
            )
            print(f"{_C.GREEN}[+] {live_count} archived URL(s) live now; {len(live_js)} live JS to scan.{_C.RESET}")

            # 4. Secret-scan live JS (reusing the js_paths engine).
            if live_js:
                prog = DashboardProgress("archived_urls", total=len(live_js), noun="js")

                async def _scan_one(src, lurl, code):
                    content = await _fetch_text(lurl)
                    for f in _extract_secret_findings(lurl, content):
                        findings.append(f)

                await asyncio.gather(
                    *(prog.wrap(_scan_one(src, lurl, code)) for src, lurl, code in live_js),
                    return_exceptions=True,
                )
        finally:
            if dashboard is not None and getattr(dashboard, "active", False):
                dashboard.complete_task("archived_urls", f"{len(findings)} findings")

        print(f"{_C.GREEN}[+] Archived URL analysis produced {len(findings)} finding(s).{_C.RESET}")
        return findings
    except Exception as exc:
        # Reporting/analysis must never break the pipeline.
        print(f"{_C.RED}[!] scan_archived_urls error: {exc}{_C.RESET}")
        return findings


def _safe_int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
