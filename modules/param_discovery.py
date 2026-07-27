"""
param_discovery.py - VaktScan Request-Parameter / Hidden-Input Discovery
========================================================================
Injection and DAST tooling (nuclei ``-dast``, sqlmap, XSS fuzzers) is only as
good as the parameter surface you feed it. Recon already produces a set of
alive web URLs, but nothing mines them for *request parameters* (GET/POST keys,
hidden inputs) - the exact surface those testers need.

This module fills that gap by orchestrating best-of-breed, external tools when
they are present (and gracefully skipping when they are not):

1. ``paramspider`` - PASSIVE. Harvests historical parameterized URLs for each
   in-scope host from web archives (``?id=FUZZ&cat=FUZZ`` style).
2. ``arjun`` - ACTIVE. Brute-forces likely parameter names against each alive
   URL and reports the ones the server actually reflects/accepts.
3. ``gf`` - TAGGING. Applies grep-for patterns (xss / sqli / ssrf / redirect)
   over the aggregated URL list to flag the most interesting candidates.

Alive URLs that *already* carry a query string are seeded into the aggregate as
well, so the feed is useful even when only ``gf`` is installed.

Everything is de-duplicated and written to ``<output_dir>/params/``:
  * ``param_urls_<ts>.txt``  - the parameterized-URL feed for nuclei DAST.
  * ``param_names_<ts>.txt``  - the unique parameter-name wordlist.
  * ``gf_<category>_<ts>.txt`` - per-pattern tagged URLs.

Canonical INFO findings are emitted (via ``modules/schema.py`` ``normalize_finding``)
summarizing the parameterized endpoints discovered per host and the per-category
gf hits.

Entry point::

    async def discover_parameters(alive_urls: list[str],
                                  output_dir: str,
                                  concurrency: int = 20) -> list[dict]

Returns canonical findings. Returns ``[]`` (never crashes) on empty input or
when every external tool is missing. Follows VaktScan conventions: async
subprocess wrapping via ``asyncio.create_subprocess_exec``, ``shutil.which``
detection, GRACEFUL skip (one info line, return ``[]``) when a tool is absent -
never auto-install, never crash.
"""

import asyncio
import os
import re
import shutil
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from modules import proc as proc_runner
from modules.progress import DashboardProgress, heartbeat
from modules.schema import normalize_finding


class _C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GREY = "\033[90m"
    RESET = "\033[0m"


# gf pattern categories we care about for injection/DAST triage. Maps our
# canonical category label -> the gf pattern name that must live in ~/.gf/.
GF_CATEGORIES = {
    "xss": "xss",
    "sqli": "sqli",
    "ssrf": "ssrf",
    "redirect": "redirect",
}

# Defensive caps so a pathological alive-URL set can't spawn unbounded work.
MAX_ARJUN_TARGETS = 200      # arjun probes each URL individually (slow) - bound it.
MAX_FEED_URLS = 5000         # cap the DAST feed / gf input size.

# Matches an http(s) URL sitting anywhere on a line, so we can pull URLs out of
# tool output that is interleaved with banners / progress noise.
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------

def _detect_tools():
    """Resolve external tools via PATH. Returns a dict {name: path|None}."""
    return {
        "paramspider": shutil.which("paramspider"),
        "arjun": shutil.which("arjun"),
        "gf": shutil.which("gf"),
    }


# ---------------------------------------------------------------------------
# Parsing / URL helpers (pure, unit-testable)
# ---------------------------------------------------------------------------

def _parse_url_lines(text):
    """Extract http(s) URLs from arbitrary tool output text.

    Tolerates banners, progress spinners, and log prefixes - anything that is
    not a URL is ignored. Returns URLs in first-seen order, de-duplicated.
    """
    if not text:
        return []
    seen = set()
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        for match in _URL_RE.findall(line):
            url = match.rstrip(".,);]")
            if url not in seen:
                seen.add(url)
                out.append(url)
    return out


def _parse_arjun_json(data):
    """Normalize arjun ``-oJ`` output into ``{url: [param, ...]}``.

    Handles both known arjun JSON shapes:
      * ``{"http://x": ["p1", "p2"]}``                      (older)
      * ``{"http://x": {"params": [...], "method": ...}}``  (newer)
    """
    out = {}
    if not isinstance(data, dict):
        return out
    for url, info in data.items():
        if not url:
            continue
        params = []
        if isinstance(info, dict):
            raw = info.get("params")
            if isinstance(raw, list):
                params = [str(p) for p in raw if p]
        elif isinstance(info, list):
            params = [str(p) for p in info if p]
        out[str(url)] = sorted(set(params))
    return out


def _hosts_from_urls(urls):
    """Return sorted, de-duplicated hostnames from a list of URLs."""
    hosts = set()
    for u in urls:
        host = urlparse((u or "").strip()).hostname
        if host:
            hosts.add(host.lower())
    return sorted(hosts)


def _param_keys(url):
    """Return the list of query-parameter keys present in ``url``."""
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def _build_fuzz_url(base_url, params):
    """Attach ``params`` (as ``key=FUZZ``) to ``base_url``, merging any existing
    query keys. Used to turn arjun's (url, param-names) result into a concrete
    parameterized URL for the DAST feed."""
    parsed = urlparse(base_url)
    merged = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for p in params:
        merged[p] = "FUZZ"
    query = urlencode(merged)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))


def _dedup_param_urls(urls):
    """Collapse URLs that differ only in param *values* (not keys).

    Key = ``(scheme, netloc, path, frozenset(param keys))``; first occurrence
    wins. Only URLs that actually carry parameters are kept.
    """
    seen = set()
    out = []
    for u in urls:
        u = (u or "").strip()
        if not u:
            continue
        parsed = urlparse(u)
        keys = frozenset(k for k, _ in parse_qsl(parsed.query, keep_blank_values=True))
        if not keys:
            continue
        key = (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, keys)
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out


# ---------------------------------------------------------------------------
# External tool runners (async subprocess wrappers)
# ---------------------------------------------------------------------------

async def _run_paramspider(binary, domain, params_dir, semaphore):
    """Run paramspider for a single domain, returning parameterized URLs.

    paramspider (rewrite) writes ``results/<domain>.txt`` relative to its CWD
    and older builds honor ``-o``. We point both at the same path (running with
    ``cwd=params_dir`` and passing ``-o <params_dir>/results/<domain>.txt``) so
    the output lands in one predictable place regardless of version, and also
    parse anything the tool prints to stdout.
    """
    results_dir = os.path.join(params_dir, "results")
    os.makedirs(results_dir, exist_ok=True)
    outfile = os.path.join(results_dir, f"{domain}.txt")
    cmd = [binary, "-d", domain, "-o", outfile]
    urls = []
    try:
        async with semaphore:
            result = await proc_runner.run_tool(cmd, cwd=params_dir)
            stdout, stderr = result.stdout, result.stderr
    except Exception as exc:  # tool present but unusable - degrade, don't crash
        print(f"{_C.GREY}[!] paramspider failed for {domain}: {exc}{_C.RESET}")
        return []

    urls.extend(_parse_url_lines(stdout.decode("utf-8", "ignore") if stdout else ""))
    if os.path.exists(outfile):
        try:
            with open(outfile, "r", encoding="utf-8", errors="ignore") as handle:
                urls.extend(_parse_url_lines(handle.read()))
        except OSError:
            pass
    return urls


async def _run_arjun(binary, urls, params_dir, concurrency):
    """Run arjun against a list of URLs, returning ``{url: [params]}``.

    Uses arjun's ``-i`` (import from file) + ``-oJ`` (JSON output) so the whole
    batch is a single invocation.
    """
    if not urls:
        return {}
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    input_file = os.path.join(params_dir, f"arjun_input_{timestamp}.txt")
    output_json = os.path.join(params_dir, f"arjun_out_{timestamp}.json")
    threads = str(max(1, min(int(concurrency), 10)))
    try:
        with open(input_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(urls))
    except OSError as exc:
        print(f"{_C.RED}[!] Could not stage arjun input: {exc}{_C.RESET}")
        return {}

    cmd = [binary, "-i", input_file, "-oJ", output_json, "-t", threads]
    try:
        result = await proc_runner.run_tool(cmd)
        _stdout, stderr = result.stdout, result.stderr
    except Exception as exc:
        print(f"{_C.GREY}[!] arjun failed: {exc}{_C.RESET}")
        _safe_remove(input_file)
        return {}

    result = {}
    if os.path.exists(output_json):
        try:
            import json
            with open(output_json, "r", encoding="utf-8", errors="ignore") as handle:
                result = _parse_arjun_json(json.load(handle))
        except (OSError, ValueError) as exc:
            print(f"{_C.GREY}[!] Could not parse arjun output: {exc}{_C.RESET}")
    elif stderr:
        err = stderr.decode("utf-8", "ignore").strip()
        if err:
            print(f"{_C.GREY}[!] arjun produced no output: {err.splitlines()[-1]}{_C.RESET}")

    _safe_remove(input_file)
    return result


async def _run_gf(binary, pattern, urls):
    """Run ``gf <pattern>`` over ``urls`` (fed on stdin), returning matches.

    A missing gf pattern makes gf exit non-zero with an empty stdout; we simply
    return no matches for that category (graceful).
    """
    if not urls:
        return []
    try:
        result = await proc_runner.run_tool(
            [binary, pattern], input="\n".join(urls).encode()
        )
        stdout, _stderr = result.stdout, result.stderr
    except Exception as exc:
        print(f"{_C.GREY}[!] gf ({pattern}) failed: {exc}{_C.RESET}")
        return []
    return _parse_url_lines(stdout.decode("utf-8", "ignore") if stdout else "")


def _safe_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------

def _port_for(url):
    parsed = urlparse(url)
    return str(parsed.port or (443 if parsed.scheme == "https" else 80))


def _build_param_finding(host, urls, params, feed_path):
    """Summary INFO finding: parameterized endpoints discovered for a host."""
    sample = sorted(urls)[0] if urls else host
    param_preview = ", ".join(sorted(params)[:15])
    if len(params) > 15:
        param_preview += ", …"
    detail = (
        f"Discovered {len(urls)} parameterized endpoint(s) exposing "
        f"{len(params)} unique parameter(s) on {host} (via paramspider/arjun). "
        f"Feed for injection/DAST testing: {feed_path}. Parameters: "
        f"{param_preview or 'N/A'}"
    )
    finding = {
        "target": host,
        "resolved_ip": "N/A",
        "port": _port_for(sample),
        "vulnerability": "Parameterized Endpoints Discovered",
        "status": "INFO",
        "severity": "INFO",
        "module": "param_discovery",
        "service_version": "N/A",
        "url": sample,
        "payload_url": feed_path,
        "details": detail,
        "http_status": "N/A",
        "page_title": "N/A",
        "content_length": str(len(urls)),
    }
    return normalize_finding(finding)


def _build_gf_candidate_finding(host, category_urls, feed_path):
    """Aggregated INFO finding: parameterized URLs on ``host`` that gf heuristics
    flagged as *candidates* for further testing.

    ``category_urls`` maps ``category -> set(urls)``. This is explicitly a lead,
    NOT a confirmed vulnerability - gf is a grep heuristic, so the finding stays
    INFO/INFO and its wording never claims XSS/SQLi/SSRF/redirect exists.
    """
    all_urls = set()
    for urls in category_urls.values():
        all_urls |= urls
    sample = sorted(all_urls)[0] if all_urls else host
    per_cat = ", ".join(
        f"{cat} ({len(urls)})" for cat, urls in sorted(category_urls.items())
    )
    detail = (
        f"gf heuristics tagged {len(all_urls)} parameterized URL(s) on {host} as "
        f"CANDIDATES for further testing (NOT confirmed vulnerabilities): {per_cat}. "
        f"Use as leads for injection/DAST tooling. Feed: {feed_path}"
    )
    finding = {
        "target": host,
        "resolved_ip": "N/A",
        "port": _port_for(sample),
        "vulnerability": "Parameter Injection Test Candidates (gf)",
        "status": "INFO",
        "severity": "INFO",
        "module": "param_discovery",
        "service_version": "N/A",
        "url": sample,
        "payload_url": feed_path,
        "details": detail,
        "http_status": "N/A",
        "page_title": "N/A",
        "content_length": str(len(all_urls)),
    }
    return normalize_finding(finding)


# ---------------------------------------------------------------------------
# Output writing
# ---------------------------------------------------------------------------

def _write_lines(path, lines):
    """Write ``lines`` (deduped, sorted) to ``path``. Returns path or None."""
    try:
        with open(path, "w", encoding="utf-8") as handle:
            for line in lines:
                handle.write(f"{line}\n")
        return path
    except OSError as exc:
        print(f"{_C.RED}[!] Could not write {path}: {exc}{_C.RESET}")
        return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def discover_parameters(alive_urls: list[str], output_dir: str, concurrency: int = 20) -> list[dict]:
    """Discover request parameters / hidden input surface on alive web URLs.

    See the module docstring for the full pipeline. Always returns a list;
    returns ``[]`` on empty input or when every external tool is missing, and
    never raises out of the scan path.
    """
    findings: list[dict] = []
    try:
        cleaned = sorted({(u or "").strip() for u in (alive_urls or []) if u and u.strip()})
        if not cleaned:
            return []

        tools = _detect_tools()
        paramspider_bin = tools["paramspider"]
        arjun_bin = tools["arjun"]
        gf_bin = tools["gf"]

        if not (paramspider_bin or arjun_bin or gf_bin):
            print(
                f"{_C.YELLOW}[!] param_discovery: none of paramspider/arjun/gf found on PATH. "
                f"Skipping parameter discovery.{_C.RESET}"
            )
            return []

        if not paramspider_bin:
            print(f"{_C.GREY}[!] paramspider not found; skipping passive param harvesting.{_C.RESET}")
        if not arjun_bin:
            print(f"{_C.GREY}[!] arjun not found; skipping active param mining.{_C.RESET}")
        if not gf_bin:
            print(f"{_C.GREY}[!] gf not found; skipping pattern tagging.{_C.RESET}")

        params_dir = os.path.join(output_dir, "params")
        os.makedirs(params_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # host -> set(parameterized urls) ; host -> set(param names)
        host_urls: dict = {}
        host_params: dict = {}

        def _record(url, params=None):
            url = (url or "").strip()
            if not url:
                return
            host = (urlparse(url).hostname or "").lower()
            if not host:
                return
            keys = list(params) if params else _param_keys(url)
            if not keys:
                return
            host_urls.setdefault(host, set()).add(url)
            host_params.setdefault(host, set()).update(keys)

        # Seed: alive URLs that already carry a query string are, by definition,
        # parameterized endpoints worth feeding forward.
        for u in cleaned:
            if _param_keys(u):
                _record(u)

        # Live dashboard task for the discovery phase.
        try:
            from modules.dashboard import LiveDashboard
            dashboard = LiveDashboard()
        except Exception:
            dashboard = None
        if dashboard is not None and getattr(dashboard, "active", False):
            dashboard.add_task("param_discovery", "Parameter Discovery")

        try:
            # 1. PASSIVE - paramspider per in-scope host.
            if paramspider_bin:
                hosts = _hosts_from_urls(cleaned)
                if hosts:
                    print(f"{_C.CYAN}[*] paramspider: harvesting archived params for {len(hosts)} host(s)...{_C.RESET}")
                    semaphore = asyncio.Semaphore(max(1, int(concurrency)))
                    prog = DashboardProgress("param_discovery", total=len(hosts), noun="hosts")
                    tasks = [
                        prog.wrap(_run_paramspider(paramspider_bin, host, params_dir, semaphore))
                        for host in hosts
                    ]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for res in results:
                        if isinstance(res, list):
                            for url in res:
                                _record(url)
                        elif isinstance(res, Exception):
                            print(f"{_C.GREY}[!] paramspider error: {res}{_C.RESET}")

            # 2. ACTIVE - arjun over the alive URLs (bounded).
            if arjun_bin:
                arjun_targets = cleaned[:MAX_ARJUN_TARGETS]
                if len(cleaned) > MAX_ARJUN_TARGETS:
                    print(
                        f"{_C.YELLOW}[!] Capping arjun at {MAX_ARJUN_TARGETS} of "
                        f"{len(cleaned)} URL(s).{_C.RESET}"
                    )
                print(f"{_C.CYAN}[*] arjun: mining parameters on {len(arjun_targets)} URL(s)...{_C.RESET}")
                async with heartbeat("param_discovery", "Mining parameters with arjun"):
                    arjun_map = await _run_arjun(arjun_bin, arjun_targets, params_dir, concurrency)
                for base_url, params in arjun_map.items():
                    if params:
                        _record(_build_fuzz_url(base_url, params), params)

            # 3. Aggregate + dedup the parameterized-URL feed.
            all_param_urls = []
            for urls in host_urls.values():
                all_param_urls.extend(urls)
            # Sort before dedup so the retained representative (and the written
            # feed) is deterministic across runs regardless of set iteration order.
            feed_urls = _dedup_param_urls(sorted(all_param_urls))
            if len(feed_urls) > MAX_FEED_URLS:
                print(
                    f"{_C.YELLOW}[!] Capping parameter feed at {MAX_FEED_URLS} of "
                    f"{len(feed_urls)} URL(s).{_C.RESET}"
                )
                feed_urls = feed_urls[:MAX_FEED_URLS]

            all_param_names = sorted({p for names in host_params.values() for p in names})

            feed_path = "N/A"
            if feed_urls:
                feed_path = _write_lines(
                    os.path.join(params_dir, f"param_urls_{timestamp}.txt"),
                    sorted(feed_urls),
                ) or "N/A"
                _write_lines(
                    os.path.join(params_dir, f"param_names_{timestamp}.txt"),
                    all_param_names,
                )
                print(
                    f"{_C.GREEN}[+] param_discovery: {len(feed_urls)} parameterized URL(s), "
                    f"{len(all_param_names)} unique parameter(s). Feed: {feed_path}{_C.RESET}"
                )
            else:
                print(f"{_C.YELLOW}[!] param_discovery: no parameterized endpoints discovered.{_C.RESET}")

            # 4. TAGGING - gf patterns over the deduped feed. gf is a HEURISTIC
            #    filter, not a confirmation: a hit only marks a URL as a candidate
            #    for that category of testing. Results are folded per-host, never
            #    turned into a per-URL or per-category finding row.
            #    gf_by_host: host -> {category: set(urls)}
            gf_by_host: dict = {}
            if gf_bin and feed_urls:
                gf_input = sorted(feed_urls)
                for category, pattern in GF_CATEGORIES.items():
                    matches = await _run_gf(gf_bin, pattern, gf_input)
                    if not matches:
                        continue
                    _write_lines(
                        os.path.join(params_dir, f"gf_{category}_{timestamp}.txt"),
                        sorted(set(matches)),
                    )
                    print(f"{_C.GREY}[*] gf '{category}': {len(matches)} candidate URL(s) tagged.{_C.RESET}")
                    for url in matches:
                        host = (urlparse(url).hostname or "").lower()
                        if host:
                            gf_by_host.setdefault(host, {}).setdefault(category, set()).add(url)

            # 5. Findings - ONE aggregated INFO summary per host for the parameter
            #    surface, plus (only when gf tagged something) ONE aggregated INFO
            #    "candidate" finding per host. gf candidates are never VULNERABLE.
            for host in sorted(host_urls):
                urls = host_urls[host]
                params = host_params.get(host, set())
                findings.append(_build_param_finding(host, urls, params, feed_path))
                if host in gf_by_host:
                    findings.append(_build_gf_candidate_finding(host, gf_by_host[host], feed_path))
        finally:
            if dashboard is not None and getattr(dashboard, "active", False):
                dashboard.complete_task("param_discovery", f"{len(findings)} findings")

        print(f"{_C.GREEN}[+] Parameter discovery produced {len(findings)} finding(s).{_C.RESET}")
        return findings
    except Exception as exc:
        # Discovery must never break the pipeline.
        print(f"{_C.RED}[!] discover_parameters error: {exc}{_C.RESET}")
        return findings
