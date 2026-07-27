"""DNS resolution hygiene + permutation for VaktScan.

Between raw subdomain enumeration and downstream probing the candidate host list
is noisy: many names are dead, and catch-all (wildcard) DNS makes *every*
random label appear to "resolve", flooding the scan with false positives. This
module cleans and then expands that set:

1. **Resolve + wildcard-filter** the enumerated subdomains.  ``puredns resolve``
   (preferred) does mass resolution *and* native wildcard detection; ``massdns``
   is used as a fallback (resolution only), paired with a lightweight built-in
   wildcard filter (probe random labels per apex, drop any name that resolves
   *only* to the apex's catch-all IP set).
2. **Permute** the surviving hosts with ``alterx`` or ``dnsgen`` to synthesize
   likely-but-undiscovered names (``api-staging``, ``dev2``…), then resolve those
   too.  Candidate generation is **bounded** (``PERMUTATION_CAP`` = 50k) so a
   large host list cannot explode into millions of lookups; the cap is logged.
3. If **none** of the tools are installed, fall back to a best-effort built-in
   async resolver check (``getaddrinfo``) and return the input as ``resolved``
   rather than crashing.

Every external tool is detected with :func:`shutil.which` and skipped gracefully
when absent - no auto-install, no crash.  The entry point always returns a
fully-shaped dict.

Conventions mirrored from ``modules/recon.py`` / ``modules/gau_runner.py``
(async subprocess wrapping, ``shutil.which`` gating, graceful skip),
``modules/horizontal_expand.py`` (dict result + canonical INFO findings),
``modules/dns_recon.py`` (raw DNS constants/resolvers) and
``modules/progress.py`` (``heartbeat`` liveness on long resolution passes).
``modules/schema.py``'s :func:`normalize_finding` guarantees the 15 canonical
finding keys.
"""

import asyncio
import os
import re
import secrets
import shutil

from modules.dns_recon import DEFAULT_RESOLVERS
from modules.progress import heartbeat
from modules.schema import normalize_finding

MODULE_NAME = "dns_resolve"

# Hard ceiling on the number of permutation candidates handed to the resolver.
# A large seed list run through alterx/dnsgen can generate millions of names;
# this cap keeps the follow-up resolution bounded and predictable.
PERMUTATION_CAP = 50_000

# Random labels probed per apex to fingerprint a catch-all/wildcard response
# (used only on the massdns fallback path; puredns filters wildcards natively).
WILDCARD_PROBES_PER_APEX = 3

# A superset of the stdlib resolvers used by dns_recon, written to a resolvers
# file when the operator hasn't supplied one via VAKT_RESOLVERS.
_FALLBACK_PUBLIC_RESOLVERS = tuple(DEFAULT_RESOLVERS) + (
    "8.8.4.4", "1.0.0.1", "208.67.222.222", "208.67.220.220",
)

_DOMAIN_RE = re.compile(r"^(?:[a-z0-9_-]+\.)+[a-z]{2,}$")


# --- tiny ANSI helpers (matches the rest of the codebase) -------------------
class _C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    RESET = "\033[0m"


def _info(msg):
    print(f"{_C.CYAN}[*] {msg}{_C.RESET}")


def _ok(msg):
    print(f"{_C.GREEN}[+] {msg}{_C.RESET}")


def _skip(msg):
    print(f"{_C.YELLOW}[!] {msg}{_C.RESET}")


def _note(msg):
    print(f"{_C.GRAY}[*] {msg}{_C.RESET}")


def _empty_result():
    """A fresh, fully-shaped empty result (never share a single mutable dict)."""
    return {
        "resolved": [],
        "wildcard_filtered": [],
        "permutations_found": [],
        "findings": [],
    }


# --- pure normalization / parsing helpers (unit-tested directly) ------------
def _dedupe(items):
    """Order-preserving de-duplication of truthy items."""
    seen = set()
    out = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _norm_host(value):
    """Lower-case, trim, and strip a trailing dot / surrounding quotes."""
    if not value:
        return None
    host = str(value).strip().strip("\"'").rstrip(".").lower()
    return host or None


def _clean_hosts(hosts):
    """Normalize + dedupe a list of hostnames, keeping only domain-shaped ones."""
    cleaned = []
    for raw in hosts or []:
        host = _norm_host(raw)
        if host and _DOMAIN_RE.match(host):
            cleaned.append(host)
    return _dedupe(cleaned)


def _apex_of(host, apexes):
    """Return the apex from *apexes* that *host* belongs to, else a 2-label guess."""
    host = _norm_host(host) or ""
    best = None
    for apex in apexes or []:
        apex = _norm_host(apex)
        if not apex:
            continue
        if host == apex or host.endswith("." + apex):
            if best is None or len(apex) > len(best):
                best = apex
    if best:
        return best
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _parse_resolved_lines(text):
    """Parse newline-delimited resolved hostnames (puredns / fallback stdout)."""
    return _clean_hosts((text or "").splitlines())


def _parse_massdns_simple(text):
    """Parse ``massdns -o S`` simple output into ``{host: {ip, ...}}``.

    Lines look like ``sub.example.com. A 1.2.3.4``.  A/AAAA records contribute
    their IP; CNAME (and any other) records still register the host as resolved
    but contribute no IP (an empty set means "resolved, address unknown").
    """
    resolved = {}
    for raw in (text or "").splitlines():
        parts = raw.split()
        if len(parts) < 3:
            continue
        host = _norm_host(parts[0])
        if not host or not _DOMAIN_RE.match(host):
            continue
        rtype = parts[1].upper()
        rdata = parts[2].strip()
        bucket = resolved.setdefault(host, set())
        if rtype in ("A", "AAAA") and rdata:
            bucket.add(rdata)
    return resolved


def _filter_wildcards(resolved_map, wildcard_ips_by_apex, apexes):
    """Split a resolved ``{host: {ip}}`` map into (kept, wildcard_filtered).

    A host is treated as a wildcard/catch-all false positive when it has at
    least one address *and* every one of its addresses is drawn from its apex's
    known wildcard IP set (i.e. it resolves *only* because of the catch-all).
    Hosts with no addresses (CNAME-only) or whose apex has no wildcard are kept.
    """
    kept = {}
    filtered = set()
    for host, ips in resolved_map.items():
        apex = _apex_of(host, apexes)
        wips = wildcard_ips_by_apex.get(apex, set())
        if ips and wips and ips <= wips:
            filtered.add(host)
        else:
            kept[host] = ips
    return kept, filtered


def _cap_candidates(candidates, cap=PERMUTATION_CAP):
    """Dedupe + cap permutation candidates.

    Returns ``(capped_list, was_capped)``.  De-duplication happens *before* the
    cap so the surviving list is ``cap`` distinct candidates, not ``cap`` raw
    (possibly duplicate) lines.
    """
    deduped = _clean_hosts(candidates)
    if len(deduped) > cap:
        return deduped[:cap], True
    return deduped, False


# --- resolvers file ---------------------------------------------------------
def _ensure_resolvers_file(results_dir):
    """Return a path to a resolvers file for puredns/massdns.

    Honors ``VAKT_RESOLVERS`` when it points at an existing file; otherwise
    writes a small public-resolver list into *results_dir*.
    """
    env_path = os.environ.get("VAKT_RESOLVERS")
    if env_path and os.path.isfile(env_path):
        return env_path
    path = os.path.join(results_dir, "resolvers.txt")
    try:
        os.makedirs(results_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            for resolver in _FALLBACK_PUBLIC_RESOLVERS:
                handle.write(f"{resolver}\n")
    except OSError as exc:
        _skip(f"dns_resolve: could not write resolvers file: {exc}")
    return path


def _write_lines(path, items):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            for item in items:
                handle.write(f"{item}\n")
    except OSError as exc:
        _skip(f"dns_resolve: failed to write {path}: {exc}")


# --- async subprocess wrapper ----------------------------------------------
async def _run_capture(cmd, stdin_bytes=None):
    """Run ``cmd`` (list) and return decoded ``(stdout, stderr)``.

    Never raises: subprocess/OS errors are swallowed and returned as empty
    output so a single tool failure cannot take down the whole pass.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate(input=stdin_bytes)
    except (OSError, ValueError) as exc:
        _skip(f"dns_resolve: {cmd[0]} failed to run: {exc}")
        return "", ""
    return (
        (stdout or b"").decode(errors="replace"),
        (stderr or b"").decode(errors="replace"),
    )


# --- resolution back-ends ---------------------------------------------------
async def _resolve_puredns(binary, hosts, resolvers_file, results_dir, label):
    """Resolve + wildcard-filter *hosts* with puredns.

    puredns prints the surviving (resolved, non-wildcard) names to stdout.
    Anything in the input that does not come back is reported as filtered.
    Returns ``(resolved_set, filtered_set)``.
    """
    hosts = list(hosts)
    if not hosts:
        return set(), set()
    infile = os.path.join(results_dir, f"{label}_input.txt")
    _write_lines(infile, hosts)
    cmd = [binary, "resolve", infile, "-r", resolvers_file, "--quiet"]
    stdout, _ = await _run_capture(cmd)
    resolved = set(_parse_resolved_lines(stdout))
    filtered = set(hosts) - resolved
    return resolved, filtered


async def _run_massdns(binary, hosts, resolvers_file):
    """Resolve *hosts* with massdns, returning a ``{host: {ip}}`` map."""
    hosts = list(hosts)
    if not hosts:
        return {}
    stdin_bytes = ("\n".join(hosts) + "\n").encode()
    cmd = [binary, "-r", resolvers_file, "-t", "A", "-o", "S", "-q"]
    stdout, _ = await _run_capture(cmd, stdin_bytes=stdin_bytes)
    return _parse_massdns_simple(stdout)


async def _massdns_wildcard_ips(binary, apexes, resolvers_file):
    """Fingerprint each apex's catch-all IPs by resolving random labels.

    For every apex we probe a handful of guaranteed-nonexistent random labels;
    any address they return is, by definition, a wildcard/catch-all address.
    Returns ``{apex: {ip, ...}}`` (apexes with no wildcard map to an empty set).
    """
    apexes = [a for a in (_norm_host(x) for x in apexes or []) if a]
    if not apexes:
        return {}
    probes = []
    probe_apex = {}
    for apex in apexes:
        for _ in range(WILDCARD_PROBES_PER_APEX):
            label = f"vakt{secrets.token_hex(8)}.{apex}"
            probes.append(label)
            probe_apex[label] = apex
    resolved = await _run_massdns(binary, probes, resolvers_file)
    wildcard = {apex: set() for apex in apexes}
    for host, ips in resolved.items():
        apex = probe_apex.get(host) or _apex_of(host, apexes)
        if apex in wildcard:
            wildcard[apex].update(ips)
    return wildcard


async def _resolve_massdns(binary, hosts, apexes, resolvers_file, results_dir, label):
    """Resolve *hosts* with massdns and apply built-in wildcard filtering."""
    hosts = list(hosts)
    if not hosts:
        return set(), set()
    resolved_map = await _run_massdns(binary, hosts, resolvers_file)
    wildcard_ips = await _massdns_wildcard_ips(binary, apexes, resolvers_file)
    kept, filtered = _filter_wildcards(resolved_map, wildcard_ips, apexes)
    _write_lines(os.path.join(results_dir, f"{label}_massdns.txt"), sorted(resolved_map))
    return set(kept), filtered


async def _resolve_one(host):
    """Best-effort single-host resolution via getaddrinfo. Never raises."""
    try:
        loop = asyncio.get_running_loop()
        await loop.getaddrinfo(host, None)
        return True
    except Exception:
        return False


async def _fallback_resolve(hosts, concurrency):
    """Built-in resolver used when no external tool is available.

    Best-effort: probes each host with getaddrinfo and keeps the live ones.  If
    resolution surfaces nothing at all (e.g. no network / sandboxed), the full
    input is returned unchanged so the pipeline still has hosts to work with.
    """
    hosts = list(hosts)
    if not hosts:
        return set()
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _check(host):
        async with sem:
            return host, await _resolve_one(host)

    results = await asyncio.gather(*(_check(h) for h in hosts), return_exceptions=True)
    live = [r[0] for r in results if isinstance(r, tuple) and r[1]]
    return set(live) if live else set(hosts)


# --- permutation generation -------------------------------------------------
async def _generate_permutations(hosts, results_dir, have_alterx, have_dnsgen):
    """Generate permutation candidates from *hosts* via alterx and/or dnsgen."""
    hosts = list(hosts)
    if not hosts:
        return []
    infile = os.path.join(results_dir, "permute_seed.txt")
    _write_lines(infile, hosts)
    candidates = []

    if have_alterx:
        stdout, _ = await _run_capture([have_alterx, "-l", infile, "-silent"])
        candidates.extend(_parse_resolved_lines(stdout))
    if have_dnsgen:
        stdout, _ = await _run_capture([have_dnsgen, infile])
        candidates.extend(_parse_resolved_lines(stdout))

    return candidates


# --- findings ---------------------------------------------------------------
def _info_finding(vulnerability, details, target):
    """Build a canonical INFO finding (all 15 keys via ``normalize_finding``)."""
    return normalize_finding({
        "status": "INFO",
        "severity": "INFO",
        "vulnerability": vulnerability,
        "target": target,
        "module": MODULE_NAME,
        "details": details,
    })


def _preview(items, limit=10):
    items = list(items)
    shown = ", ".join(items[:limit])
    if len(items) > limit:
        shown += f", … (+{len(items) - limit} more)"
    return shown or "N/A"


# --- entry point ------------------------------------------------------------
async def resolve_and_permute(
    subdomains: list[str],
    apex_domains: list[str],
    output_dir: str,
    concurrency: int = 50,
    permute: bool = True,
) -> dict:
    """Clean (resolve + wildcard-filter) and expand (permute) a subdomain set.

    Returns a dict with keys:
      * ``resolved`` - the cleaned **and** expanded set of live hosts to feed
        downstream (original survivors ∪ permutation hits).  This is the list
        callers hand to the next stage (httpx probing).
      * ``wildcard_filtered`` - original inputs dropped during resolution
        (catch-all false positives + dead names).
      * ``permutations_found`` - the subset of ``resolved`` newly discovered via
        alterx/dnsgen (a report/visibility delta; already included in
        ``resolved``).
      * ``findings`` - canonical INFO findings summarizing the counts.

    Returns a fully-shaped **empty** dict (never raises) when the input is empty.
    When no resolution tool is installed it falls back to a best-effort built-in
    resolver and still returns the input as ``resolved``.
    """
    result = _empty_result()

    subs = _clean_hosts(subdomains)
    if not subs:
        _info("dns_resolve: no subdomains supplied - skipping.")
        return result

    apexes = _clean_hosts(apex_domains) or _dedupe(_apex_of(s, []) for s in subs)
    target = (apexes or subs)[0]

    results_dir = os.path.join(output_dir, "dns_resolve")
    resolvers_file = _ensure_resolvers_file(results_dir)

    have_puredns = shutil.which("puredns")
    have_massdns = shutil.which("massdns")
    have_alterx = shutil.which("alterx")
    have_dnsgen = shutil.which("dnsgen")

    # --- Phase 1: resolve + wildcard-filter the enumerated subdomains --------
    if have_puredns:
        backend = "puredns"
        _info(f"dns_resolve: resolving {len(subs)} subdomain(s) with puredns (wildcard-aware)…")
        async with heartbeat(MODULE_NAME, "puredns resolve"):
            resolved, wildcard_filtered = await _resolve_puredns(
                have_puredns, subs, resolvers_file, results_dir, "resolve"
            )
    elif have_massdns:
        backend = "massdns"
        _info(f"dns_resolve: resolving {len(subs)} subdomain(s) with massdns + built-in wildcard filter…")
        async with heartbeat(MODULE_NAME, "massdns resolve"):
            resolved, wildcard_filtered = await _resolve_massdns(
                have_massdns, subs, apexes, resolvers_file, results_dir, "resolve"
            )
    else:
        backend = "builtin"
        _skip("dns_resolve: neither puredns nor massdns found - using built-in resolver (no wildcard filtering).")
        resolved = await _fallback_resolve(subs, concurrency)
        wildcard_filtered = set()

    _ok(
        f"dns_resolve: {len(resolved)} host(s) resolved, "
        f"{len(wildcard_filtered)} filtered (via {backend})."
    )

    # --- Phase 2: permutation expansion (bounded) ----------------------------
    permutations_found = set()
    generated = 0
    capped = False
    can_resolve = bool(have_puredns or have_massdns)

    if permute and resolved and (have_alterx or have_dnsgen):
        if not can_resolve:
            _skip("dns_resolve: permutation tools present but no resolver - skipping permutation resolution.")
        else:
            tools = ", ".join(t for t, ok in (("alterx", have_alterx), ("dnsgen", have_dnsgen)) if ok)
            _info(f"dns_resolve: generating permutations from {len(resolved)} host(s) via {tools}…")
            raw_candidates = await _generate_permutations(
                sorted(resolved), results_dir, have_alterx, have_dnsgen
            )
            candidates, capped = _cap_candidates(raw_candidates, PERMUTATION_CAP)
            generated = len(candidates)
            if capped:
                _note(
                    f"dns_resolve: permutation candidates capped at {PERMUTATION_CAP:,} "
                    f"(generated {len(_clean_hosts(raw_candidates)):,} distinct)."
                )
            # Only resolve candidates we haven't already confirmed live.
            new_candidates = [c for c in candidates if c not in resolved]
            if new_candidates:
                _info(f"dns_resolve: resolving {len(new_candidates)} permutation candidate(s)…")
                async with heartbeat(MODULE_NAME, "permutation resolve"):
                    if have_puredns:
                        perm_resolved, _ = await _resolve_puredns(
                            have_puredns, new_candidates, resolvers_file, results_dir, "permute"
                        )
                    else:
                        perm_resolved, _ = await _resolve_massdns(
                            have_massdns, new_candidates, apexes, resolvers_file, results_dir, "permute"
                        )
                permutations_found = set(perm_resolved) - set(resolved)
            _ok(f"dns_resolve: permutations surfaced {len(permutations_found)} new live host(s).")
    elif resolved and not (have_alterx or have_dnsgen):
        _skip("dns_resolve: neither alterx nor dnsgen found - skipping permutation expansion.")

    # --- Assemble output -----------------------------------------------------
    all_resolved = sorted(set(resolved) | permutations_found)
    result["resolved"] = all_resolved
    result["wildcard_filtered"] = sorted(wildcard_filtered)
    result["permutations_found"] = sorted(permutations_found)

    findings = [
        _info_finding(
            "DNS Resolution & Wildcard Filtering",
            f"Resolved {len(resolved)} of {len(subs)} enumerated subdomain(s) via {backend}; "
            f"{len(wildcard_filtered)} removed as wildcard/catch-all false positives or dead names. "
            f"Survivors (sample): {_preview(sorted(resolved))}.",
            target,
        )
    ]
    if generated or permutations_found:
        cap_note = f" (candidate list capped at {PERMUTATION_CAP:,})" if capped else ""
        findings.append(_info_finding(
            "DNS Permutation Expansion",
            f"Generated {generated} permutation candidate(s){cap_note} and confirmed "
            f"{len(permutations_found)} new live host(s) beyond the enumerated set: "
            f"{_preview(sorted(permutations_found))}.",
            target,
        ))
    result["findings"] = findings

    # --- Persist artifacts (best effort) ------------------------------------
    _write_lines(os.path.join(results_dir, "resolved.txt"), all_resolved)
    _write_lines(os.path.join(results_dir, "wildcard_filtered.txt"), result["wildcard_filtered"])
    _write_lines(os.path.join(results_dir, "permutations_found.txt"), result["permutations_found"])

    return result
