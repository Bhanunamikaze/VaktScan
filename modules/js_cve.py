"""
js_cve.py - VaktScan client-side JavaScript CVE detector
========================================================
Detects outdated / vulnerable client-side JavaScript libraries from served JS
and emits canonical CVE findings - a pure-Python, zero-dependency reimplementation
of the Retire.js scanner engine (like Burp's Retire.js scanner).

Pipeline
--------
1. Load the bundled Retire.js vulnerability DB (``modules/data/retirejs_db.json``)
   once, lazily. Missing/corrupt -> graceful skip, return ``[]`` (fail-open).
2. Build library matchers from each entry's ``extractors`` (the ``§§version§§``
   token is substituted with a version-capturing regex and compiled once).
   Supported extractors: ``filecontent``, ``uri``, ``filename``, ``filecontentreplace``
   and ``hashes`` (sha1). ``func``/``ast`` extractors require a JS runtime/parser
   and are skipped safely (fail-open) - ``filecontent``/``filename``/``uri``/``hash``
   cover the vast majority of real-world detections.
3. For each JS artifact (from the corpus VaktScan already collected): detect
   ``(library, version)`` using Retire.js precedence - filename + uri on the URL
   first, then, only if nothing matched, the file content (filecontent ->
   filecontentreplace -> sha1 hash).
4. For every detected ``(library, version)`` test the version against that
   library's vulnerability ranges (``below`` exclusive upper bound, ``atOrAbove``
   inclusive lower bound, ``excludes`` exact-string). For every matching advisory
   emit ONE normalized finding per CVE.

ORACLE DISCIPLINE
-----------------
A finding is NEVER emitted without a concretely extracted version that falls in a
vulnerable range. No version -> no finding. Findings are de-duplicated by
``(url, library, version, cve)``.

Enrichment
----------
CVE ids are placed in the ``vulnerability`` field (``"CVE-YYYY-NNNNN - <lib> <ver>"``)
and mirrored in ``details`` so the shared ``_enrich_and_report`` tail adds KEV
sibling findings and EPSS annotations automatically. No network calls for
enrichment are made here. A base ``severity`` floor is taken from the advisory.

Public API
----------
    async def scan_js_cves(js_corpus, *, output_dir=None, concurrency=20,
                           fetch_missing=True, timeout=15.0,
                           max_fetch=300) -> list[dict]

``js_corpus`` accepts the shapes VaktScan already produces: a list of
``{"url": ..., "content": ...}`` dicts, ``(url, content)`` pairs, or bare URL
strings. Content already available is reused (never re-downloaded); only URLs
lacking content are fetched (capped by ``max_fetch``, concurrency-limited).
"""

import asyncio
import hashlib
import json
import os
import re
from urllib.parse import urlparse

from modules.progress import heartbeat
from modules.schema import normalize_finding

MODULE_NAME = "js_cve"

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "retirejs_db.json")

# The literal token Retire.js substitutes at load time (U+00A7 section signs).
_VERSION_TOKEN = "§§version§§"
# Effective compiled sub-pattern: first char a digit, then digit/./a-z/_/- (see spec).
# '-' placed last in the class so no escaping is needed. Case-sensitive (lowercase only).
_VERSION_SUB = r"[0-9][0-9.a-z_-]+"

# Strip a trailing ``.min`` / ``-min`` from the captured version (matches retire.js).
_MIN_TRAIL = re.compile(r"(\.|-)min$")

# retire.js severity string -> VaktScan schema severity.
_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "none": "INFO",
}

# Defensive cap so a pathological corpus can't spawn an unbounded download burst.
_DEFAULT_MAX_FETCH = 300


class _C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GREY = "\033[90m"
    RESET = "\033[0m"


# ---------------------------------------------------------------------------
# DB loading (lazy, cached) + normalization
# ---------------------------------------------------------------------------

_DB_CACHE = None      # normalized {lib: {"extractors": {...}, "vulnerabilities": [...]}}
_DB_LOADED = False
_MATCHERS_CACHE = None


def _normalize_db(raw: dict) -> dict:
    """Normalize both repository shapes into the flat form the engine consumes.

    Flat entries are used as-is. New/"master" entries whose vulnerabilities carry
    a ``ranges`` list are exploded: each range becomes one testable vuln inheriting
    the parent's ``severity/cwe/identifiers/info/details`` (parent ``summary`` is
    folded into ``identifiers`` as retire.js's convertFormat does).
    """
    out = {}
    for lib, entry in (raw or {}).items():
        if not isinstance(entry, dict):
            continue
        flat = []
        for v in entry.get("vulnerabilities", []) or []:
            if isinstance(v, dict) and isinstance(v.get("ranges"), list):
                rest = {
                    k: val for k, val in v.items()
                    if k not in ("ranges", "summary", "identifiers", "info", "details")
                }
                idents = dict(v.get("identifiers") or {})
                if "summary" in v:
                    idents.setdefault("summary", v["summary"])
                for rng in v["ranges"]:
                    if not isinstance(rng, dict):
                        continue
                    fv = dict(rest)
                    fv.update(rng)
                    fv["identifiers"] = idents
                    if "info" in v:
                        fv["info"] = v["info"]
                    if "details" in v:
                        fv["details"] = v["details"]
                    flat.append(fv)
            elif isinstance(v, dict):
                flat.append(v)
        out[lib] = {
            "extractors": entry.get("extractors", {}) or {},
            "vulnerabilities": flat,
        }
    return out


def load_db(force: bool = False) -> dict:
    """Load and cache the normalized Retire.js DB. Fail-open -> ``{}`` on any error.

    Pass ``force=True`` to (re)load from disk (also invalidates the matcher cache).
    """
    global _DB_CACHE, _DB_LOADED, _MATCHERS_CACHE
    if _DB_LOADED and not force:
        return _DB_CACHE or {}
    _DB_LOADED = True
    _MATCHERS_CACHE = None
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        print(f"{_C.GREY}[!] js_cve: DB not found at {DB_PATH}; skipping.{_C.RESET}")
        _DB_CACHE = {}
        return {}
    except Exception as exc:
        print(f"{_C.GREY}[!] js_cve: could not parse DB ({exc}); skipping.{_C.RESET}")
        _DB_CACHE = {}
        return {}
    _DB_CACHE = _normalize_db(raw)
    return _DB_CACHE


# ---------------------------------------------------------------------------
# Matcher compilation
# ---------------------------------------------------------------------------

def _sub_version(pattern: str) -> str:
    """Replace the ``§§version§§`` token with the version-capturing sub-pattern."""
    return pattern.replace(_VERSION_TOKEN, _VERSION_SUB)


def _compile(pattern: str):
    """Compile a regex case-sensitively (Retire.js version class is lowercase-only).

    Returns ``None`` for patterns Python's ``re`` cannot compile (JS/Python regex
    dialect differences) so a single bad pattern never breaks the module.
    """
    try:
        return re.compile(pattern)
    except re.error:
        return None


def _parse_replace(regex_str: str):
    """Parse a ``filecontentreplace`` sed-style ``/PATTERN/REPLACEMENT/`` string.

    Returns ``(compiled_pattern, python_replacement)`` or ``None``. ``$N`` group
    references in the replacement are translated to Python's ``\\N`` form.
    """
    m = re.match(r"^/(.*[^\\])/([^/]+)/$", regex_str, re.DOTALL)
    if not m:
        return None
    pat = _compile(m.group(1))
    if pat is None:
        return None
    repl = re.sub(r"\$(\d+)", r"\\\1", m.group(2))
    return (pat, repl)


def _build_matchers(db: dict) -> dict:
    """Compile every library's extractors once. Only version-capturing content/uri/
    filename patterns (those containing the version token) are kept - a pattern that
    cannot capture a version could never yield a concrete detection."""
    matchers = {}
    for lib, entry in db.items():
        ex = entry.get("extractors", {}) or {}
        m = {
            "filecontent": [],
            "uri": [],
            "filename": [],
            "filecontentreplace": [],
            "hashes": {},
        }
        for typ in ("filecontent", "uri"):
            for rx in ex.get(typ, []) or []:
                if _VERSION_TOKEN not in rx:
                    continue
                c = _compile(_sub_version(rx))
                if c is not None:
                    m[typ].append(c)
        for rx in ex.get("filename", []) or []:
            if _VERSION_TOKEN not in rx:
                continue
            # Retire.js anchors the filename matcher against the basename. Some DB
            # filename patterns carry a leading path separator (e.g. ExtJS's
            # "/ext-all-(§§version§§).js"); a basename never contains a "/", so an
            # anchored pattern that starts with one could NEVER match and the
            # library would be silently missed. Strip a single leading "/" so these
            # match the basename as intended (no over-match: basenames have no "/").
            body = _sub_version(rx)
            if body.startswith("/"):
                body = body[1:]
            c = _compile("^" + body + "$")
            if c is not None:
                m["filename"].append(c)
        for rx in ex.get("filecontentreplace", []) or []:
            parsed = _parse_replace(_sub_version(rx))
            if parsed is not None:
                m["filecontentreplace"].append(parsed)
        hashes = ex.get("hashes", {}) or {}
        if isinstance(hashes, dict):
            m["hashes"] = hashes
        matchers[lib] = m
    return matchers


def _get_matchers() -> dict:
    global _MATCHERS_CACHE
    if _MATCHERS_CACHE is None:
        _MATCHERS_CACHE = _build_matchers(load_db())
    return _MATCHERS_CACHE


# ---------------------------------------------------------------------------
# Version comparison - isAtOrAbove(v1, v2) -> "is v1 >= v2" (exact retire.js port)
# ---------------------------------------------------------------------------

def _to_comparable(seg):
    """Coerce a version segment: missing -> 0, all-digits -> int, else the string."""
    if seg is None:
        return 0
    if re.fullmatch(r"[0-9]+", seg):
        return int(seg)
    return seg


def is_at_or_above(v1: str, v2: str) -> bool:
    """Return True iff version ``v1`` is at-or-above ``v2`` (retire.js semantics).

    Segments split on both ``.`` and ``-``; numeric segments compared as ints;
    at a mixed position the numeric side ranks above the string side (so a plain
    release outranks a same-base pre-release); missing trailing segments are 0.
    """
    a = re.split(r"[.\-]", str(v1))
    b = re.split(r"[.\-]", str(v2))
    for i in range(max(len(a), len(b))):
        x = _to_comparable(a[i] if i < len(a) else None)
        y = _to_comparable(b[i] if i < len(b) else None)
        if type(x) is not type(y):
            # numeric segment ranks ABOVE string segment
            return isinstance(x, int)
        if x > y:
            return True
        if x < y:
            return False
    return True  # all equal -> at-or-above


def _applies(version: str, vuln: dict) -> bool:
    """True iff ``version`` falls in this advisory's vulnerable range.

    ``below`` is an EXCLUSIVE upper bound, ``atOrAbove`` an INCLUSIVE lower bound,
    ``excludes`` an exact-string membership test. (retire.js has no ``above`` /
    ``atOrBelow``.)
    """
    below = vuln.get("below")
    at_or_above = vuln.get("atOrAbove")
    excludes = vuln.get("excludes") or []
    if below is not None and is_at_or_above(version, below):
        return False
    if at_or_above is not None and not is_at_or_above(version, at_or_above):
        return False
    if version in excludes:
        return False
    return True


# ---------------------------------------------------------------------------
# Detection (per artifact)
# ---------------------------------------------------------------------------

def _captured(match):
    """Group 1 of a match (the version) or None if the pattern captured nothing."""
    if match.lastindex:
        try:
            return match.group(1)
        except (IndexError, re.error):
            return None
    return None


def _strip_min(version: str) -> str:
    return _MIN_TRAIL.sub("", version)


def _uniq(results):
    """Dedup detections by ``"{component} {version}"`` (keep first) - retire.js uniq()."""
    seen = set()
    out = []
    for lib, ver, det in results:
        key = f"{lib} {ver}"
        if key in seen:
            continue
        seen.add(key)
        out.append((lib, ver, det))
    return out


def _scan_uri(matchers, uri):
    out = []
    for lib, m in matchers.items():
        for c in m["uri"]:
            for mm in c.finditer(uri):
                ver = _captured(mm)
                if ver:
                    out.append((lib, _strip_min(ver), "uri"))
    return out


def _scan_filename(matchers, basename):
    out = []
    for lib, m in matchers.items():
        for c in m["filename"]:
            for mm in c.finditer(basename):
                ver = _captured(mm)
                if ver:
                    out.append((lib, _strip_min(ver), "filename"))
    return out


def _scan_filecontent(matchers, content):
    out = []
    for lib, m in matchers.items():
        for c in m["filecontent"]:
            for mm in c.finditer(content):
                ver = _captured(mm)
                if ver:
                    out.append((lib, _strip_min(ver), "filecontent"))
    return out


def _scan_filecontentreplace(matchers, content):
    out = []
    for lib, m in matchers.items():
        for pat, repl in m["filecontentreplace"]:
            for mm in pat.finditer(content):
                try:
                    ver = pat.sub(repl, mm.group(0))
                except re.error:
                    continue
                if ver:
                    out.append((lib, _strip_min(ver), "filecontentreplace"))
    return out


def _scan_hash(matchers, content):
    try:
        digest = hashlib.sha1(content.encode("utf-8", "ignore")).hexdigest()
    except Exception:
        return []
    for lib, m in matchers.items():
        version = m["hashes"].get(digest)
        if version:
            return [(lib, version, "hash")]  # first matching component wins
    return []


def detect_in_artifact(matchers, url, content):
    """Detect ``(library, version, detection)`` tuples for one JS artifact.

    Retire.js precedence: filename + uri on the URL first; only if that yields
    nothing is the content read (filecontent -> filecontentreplace -> sha1 hash).
    """
    parsed = urlparse(url or "")
    path = parsed.path or (url or "")
    uri = path.replace("\\", "/")
    basename = uri.split("/")[-1]

    results = _scan_filename(matchers, basename) + _scan_uri(matchers, uri)
    if results:
        return _uniq(results)

    if not content:
        return []
    norm = content.replace("\r\n", "\n").replace("\r", "\n")
    r = _scan_filecontent(matchers, norm)
    if not r:
        r = _scan_filecontentreplace(matchers, norm)
    if not r:
        r = _scan_hash(matchers, norm)
    return _uniq(r)


# ---------------------------------------------------------------------------
# Vulnerability matching + finding construction
# ---------------------------------------------------------------------------

def _cve_list(vuln):
    idents = vuln.get("identifiers") or {}
    cves = idents.get("CVE") or []
    if isinstance(cves, str):
        cves = [cves]
    return [c for c in cves if c]


def _vuln_identity(vuln):
    """Identifier set for retire.js-style vuln identity (CVE ∪ bug ∪ issue ∪ githubID)."""
    idents = vuln.get("identifiers") or {}
    ids = set()
    for c in _cve_list(vuln):
        ids.add(("CVE", c))
    for k in ("bug", "issue", "githubID"):
        v = idents.get(k)
        if v:
            ids.add((k, v))
    return ids


def _dedup_vulns(vulns):
    """Merge advisories that share ANY identifier (keep first). Advisories with no
    identifiers are always kept (they cannot collide)."""
    kept = []
    seen_sets = []
    for v in vulns:
        ident = _vuln_identity(v)
        if ident and any(ident & prev for prev in seen_sets):
            continue
        seen_sets.append(ident)
        kept.append(v)
    return kept


def _map_severity(sev):
    return _SEVERITY_MAP.get((sev or "").strip().lower(), "MEDIUM")


def _range_desc(at_or_above, below):
    if at_or_above and below:
        return f">= {at_or_above} and < {below}"
    if below:
        return f"< {below}"
    if at_or_above:
        return f">= {at_or_above}"
    return "all versions"


def _make_finding(url, lib, version, detection, primary_id, is_cve, vuln):
    parsed = urlparse(url or "")
    # urllib's ``.port`` raises ValueError on a non-numeric/out-of-range port
    # (e.g. an archived URL like "https://host:notaport/x.js"); swallow it so one
    # malformed URL can't abort the detection loop and truncate later findings.
    try:
        _p = parsed.port
    except ValueError:
        _p = None
    port = str(_p or (443 if parsed.scheme == "https" else 80))
    idents = vuln.get("identifiers") or {}
    summary = idents.get("summary") or ""
    severity = _map_severity(vuln.get("severity"))
    cwe = vuln.get("cwe") or []
    info = vuln.get("info") or []
    range_desc = _range_desc(vuln.get("atOrAbove"), vuln.get("below"))

    vuln_text = f"{primary_id} - {lib} {version}"

    parts = []
    if is_cve:
        parts.append(primary_id)  # mirror the CVE id into details for enrichment
    if summary:
        parts.append(summary)
    parts.append(
        f"Vulnerable client-side library {lib} {version} detected via {detection}."
    )
    parts.append(f"Affected range: {range_desc}.")
    if cwe:
        parts.append("CWE: " + ", ".join(str(c) for c in cwe))
    if info:
        parts.append("Refs: " + ", ".join(str(u) for u in info[:5]))
    details = " | ".join(parts)

    return normalize_finding({
        "target": parsed.hostname or (url or "N/A"),
        "resolved_ip": "N/A",
        "port": port,
        "vulnerability": vuln_text,
        "status": "VULNERABLE",
        "severity": severity,
        "module": MODULE_NAME,
        "service_version": f"{lib} {version}",
        "url": url or "N/A",
        "details": details,
        "http_status": "N/A",
        "page_title": "N/A",
        "content_length": "N/A",
    })


def _findings_for_detection(url, lib, version, detection, entry, seen):
    """Emit findings for one detected (lib, version): test every advisory range,
    dedup advisories, and emit ONE finding per CVE (or per non-CVE advisory id)."""
    out = []
    applicable = [v for v in entry.get("vulnerabilities", []) if _applies(version, v)]
    for vuln in _dedup_vulns(applicable):
        cves = _cve_list(vuln)
        if cves:
            for cve in cves:
                key = (url, lib, version, cve)
                if key in seen:
                    continue
                seen.add(key)
                out.append(_make_finding(url, lib, version, detection, cve, True, vuln))
        else:
            idents = vuln.get("identifiers") or {}
            alt_id = (
                idents.get("githubID")
                or idents.get("issue")
                or idents.get("bug")
                or "advisory"
            )
            key = (url, lib, version, alt_id)
            if key in seen:
                continue
            seen.add(key)
            out.append(_make_finding(url, lib, version, detection, alt_id, False, vuln))
    return out


# ---------------------------------------------------------------------------
# Corpus normalization + content fetching
# ---------------------------------------------------------------------------

_URL_KEYS = ("url", "js_url", "link", "href", "loc")
_CONTENT_KEYS = ("content", "body", "text", "data")


def _normalize_corpus(js_corpus):
    """Coerce the accepted corpus shapes into ``[(url, content_or_None), ...]``."""
    artifacts = []
    for item in js_corpus or []:
        url = None
        content = None
        if isinstance(item, dict):
            for k in _URL_KEYS:
                if item.get(k):
                    url = item[k]
                    break
            for k in _CONTENT_KEYS:
                if item.get(k):
                    content = item[k]
                    break
        elif isinstance(item, (tuple, list)) and len(item) >= 2:
            url, content = item[0], item[1]
        elif isinstance(item, str):
            url = item
        else:
            continue
        if not url and not content:
            continue
        artifacts.append((url, content))
    return artifacts


def _looks_like_js_body(status_code, content_type, body) -> bool:
    """True iff an HTTP response plausibly served JavaScript.

    Gates ``_fetch_js`` so a soft-404 / SPA ``index.html`` fallback / login or
    error page is NOT scanned: a library banner embedded in such an HTML body
    would otherwise be mis-attributed as JS served by a URL that never served it
    (a real false positive on dead versionless ``.js`` URLs). We reject anything
    that is not a 200, whose content-type is HTML/XML, or whose body begins with
    an HTML/XML document marker (catches content-type-less HTML). JS-ish or
    absent content-types with a non-HTML body are allowed through (the corpus is
    already gated to ``.js``/``.mjs`` URLs upstream).
    """
    if status_code != 200:
        return False
    ctype = (content_type or "").lower()
    if "html" in ctype or "xml" in ctype:
        return False
    head = (body or "")[:512].lstrip().lower()
    if head.startswith(("<!doctype html", "<html", "<?xml", "<!doctype ")):
        return False
    return True


async def _fetch_js(url, timeout):
    """Fetch a JS URL's body as text. Returns ``None`` on any failure/missing dep,
    and also when the response does not look like served JavaScript (non-200,
    HTML/XML body, soft-404/SPA fallback) so bogus CVEs are not attributed to a
    URL that never served the library. Isolated so tests can mock it without
    real network access."""
    try:
        import httpx
    except Exception:
        return None
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True
        ) as client:
            resp = await client.get(url)
            text = resp.text
            if not _looks_like_js_body(
                resp.status_code, resp.headers.get("content-type"), text
            ):
                return None
            return text
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def scan_js_cves(
    js_corpus,
    *,
    output_dir=None,
    concurrency: int = 20,
    fetch_missing: bool = True,
    timeout: float = 15.0,
    max_fetch: int = _DEFAULT_MAX_FETCH,
) -> list[dict]:
    """Detect vulnerable client-side JS libraries over a JS corpus and emit canonical
    CVE findings.

    Args:
        js_corpus: list of ``{"url", "content"}`` dicts, ``(url, content)`` pairs, or
            bare URL strings. Content already present is reused (never re-downloaded).
        concurrency: max concurrent fetches for URLs lacking content.
        fetch_missing: fetch content for URLs that lack it (capped by ``max_fetch``).
        timeout: per-fetch timeout in seconds.
        max_fetch: hard cap on how many URLs are downloaded.

    Returns:
        A list of normalized findings. Always returns a list; returns ``[]`` on empty
        input or a missing/corrupt DB, and never raises (fail-open / fail-safe).
    """
    findings: list[dict] = []
    try:
        db = load_db()
        if not db:
            return []
        matchers = _get_matchers()

        artifacts = _normalize_corpus(js_corpus)
        if not artifacts:
            return []

        # Fetch content only for URLs that lack it, capped and concurrency-limited.
        fetched = {}
        if fetch_missing:
            need = [(i, u) for i, (u, c) in enumerate(artifacts) if u and not c]
            if len(need) > max_fetch:
                print(
                    f"{_C.YELLOW}[!] js_cve: capping JS download at {max_fetch} "
                    f"(of {len(need)}) URLs.{_C.RESET}"
                )
                need = need[:max_fetch]
            if need:
                sem = asyncio.Semaphore(max(1, concurrency))

                async def _one(idx, u):
                    async with sem:
                        fetched[idx] = await _fetch_js(u, timeout)

                async with heartbeat(MODULE_NAME, "Fetching JS for CVE scan"):
                    await asyncio.gather(
                        *(_one(i, u) for i, u in need), return_exceptions=True
                    )

        merged = [
            (u, c if c else fetched.get(i))
            for i, (u, c) in enumerate(artifacts)
        ]

        async def _detect(u, c):
            try:
                return u, await asyncio.to_thread(detect_in_artifact, matchers, u, c)
            except Exception:
                return u, []

        async with heartbeat(MODULE_NAME, "Scanning JS for vulnerable libraries"):
            results = await asyncio.gather(
                *(_detect(u, c) for u, c in merged), return_exceptions=True
            )

        seen = set()
        detected_count = 0
        for r in results:
            if not isinstance(r, tuple):
                continue
            url, detections = r
            for lib, version, detection in detections:
                entry = db.get(lib)
                if not entry:
                    continue
                detected_count += 1
                findings.extend(
                    _findings_for_detection(url, lib, version, detection, entry, seen)
                )

        print(
            f"{_C.GREEN}[+] js_cve: {detected_count} vulnerable library detection(s) "
            f"-> {len(findings)} CVE finding(s).{_C.RESET}"
        )
        return findings
    except Exception as exc:
        # Detector must never break the pipeline.
        print(f"{_C.RED}[!] js_cve scan error: {exc}{_C.RESET}")
        return findings
