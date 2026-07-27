"""Horizontal / infrastructure expansion for VaktScan.

The core value of External Attack Surface Management is discovering assets that
live *beyond* the scope the operator hands us. Given a set of seed domains this
module reaches outward along three independent axes and folds everything it finds
back into canonical INFO findings:

1. ``asnmap``      - org / domain  → owned ASNs → CIDR ranges.
2. Reverse-DNS     - ``dnsx -ptr`` sweep over the discovered CIDRs to surface
                     hostnames living on owned ranges.  Deliberately *bounded*:
                     ranges larger than ``/20`` are skipped and the total number
                     of probed IPs is capped so a single ``/8`` cannot trigger a
                     multi-million-address sweep.
3. ``amass intel`` - registrant / WHOIS pivot → related root domains.

Every external tool is detected with :func:`shutil.which`.  A missing tool is
skipped gracefully with a single info line - no crash, no auto-install.  When the
seed list is empty or none of the tools are present the entry point still returns
a fully-shaped (empty) result dict rather than raising.

Conventions mirrored from ``modules/recon.py`` / ``modules/gau_runner.py``
(async subprocess wrapping, ``shutil.which`` gating, graceful skip) and
``modules/progress.py`` (``heartbeat`` liveness on the long reverse-DNS sweep).
"""

import asyncio
import ipaddress
import json
import os
import re
import shutil

from modules import proc
from modules.progress import heartbeat
from modules.schema import normalize_finding

MODULE_NAME = "horizontal_expand"

# Reverse-DNS sweep bounds.  ``DEFAULT_MAX_CIDR_PREFIX`` is the *smallest* prefix
# length we are willing to expand: a range "larger than /20" has a prefixlen
# below 20 (e.g. /13) and is skipped.  ``DEFAULT_MAX_TOTAL_IPS`` caps the total
# number of addresses handed to dnsx across all kept ranges.
DEFAULT_MAX_CIDR_PREFIX = 20
DEFAULT_MAX_TOTAL_IPS = 8192


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


# --- regexes ----------------------------------------------------------------
_ASN_RE = re.compile(r"\bAS(\d+)\b", re.IGNORECASE)
_CIDR_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")
_DOMAIN_RE = re.compile(r"(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}")
_HOSTNAME_RE = re.compile(r"(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}")
_ASN_INPUT_RE = re.compile(r"(?:as)?(\d+)$", re.IGNORECASE)


def _empty_result():
    """A fresh, fully-shaped empty result (never share a single mutable dict)."""
    return {
        "asns": [],
        "cidrs": [],
        "related_domains": [],
        "reverse_hosts": [],
        "findings": [],
    }


# --- parsing helpers (pure functions, unit-tested directly) -----------------
def _valid_cidr(candidate):
    """Return a normalized CIDR string if ``candidate`` is a valid network."""
    if not candidate:
        return None
    try:
        return str(ipaddress.ip_network(candidate.strip(), strict=False))
    except ValueError:
        return None


def _norm_asn(value):
    """Normalize an ASN reference to the canonical ``AS<number>`` form."""
    if value is None:
        return None
    text = str(value).strip()
    m = _ASN_INPUT_RE.fullmatch(text) or _ASN_RE.search(text)
    if not m:
        return None
    return f"AS{int(m.group(1))}"


def _parse_asnmap_output(text):
    """Parse asnmap output into ``(asns, cidrs)``.

    Handles both the ``-json`` object-per-line form (which carries the ASN) and
    plain ``-silent`` CIDR-only text, so callers get whatever the tool emitted.
    """
    asns, cidrs = [], []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        obj = None
        if line.startswith("{"):
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    obj = parsed
            except json.JSONDecodeError:
                obj = None

        if obj is not None:
            asn = _norm_asn(obj.get("as_number") or obj.get("asn"))
            if asn:
                asns.append(asn)
            ranges = obj.get("as_range") or obj.get("as_range_cidr") or []
            if isinstance(ranges, str):
                ranges = [ranges]
            for entry in ranges:
                valid = _valid_cidr(entry)
                if valid:
                    cidrs.append(valid)
            continue

        # Plain-text line: pull any ASN / CIDR tokens out of it.
        for num in _ASN_RE.findall(line):
            asns.append(f"AS{int(num)}")
        for candidate in _CIDR_RE.findall(line):
            valid = _valid_cidr(candidate)
            if valid:
                cidrs.append(valid)

    return _dedupe(asns), _dedupe(cidrs)


def _parse_amass_intel_output(text):
    """Parse ``amass intel`` output into a list of related root domains."""
    domains = []
    for raw in (text or "").splitlines():
        line = raw.strip().lower().strip(".")
        if not line:
            continue
        for match in _DOMAIN_RE.findall(line):
            match = match.strip(".")
            if match:
                domains.append(match)
    return _dedupe(domains)


def _parse_dnsx_output(text):
    """Parse ``dnsx -ptr`` output into resolved hostnames.

    Accepts both the ``-resp-only`` bare-hostname form and the ``IP [host]``
    form; bare IPs (no PTR record surfaced) are ignored.
    """
    hosts = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        bracket = re.search(r"\[([^\]]+)\]", line)
        candidate = (bracket.group(1) if bracket else line).strip().rstrip(".")
        if not candidate:
            continue
        # Skip bare IP addresses - we only want hostnames.
        try:
            ipaddress.ip_address(candidate)
            continue
        except ValueError:
            pass
        if _HOSTNAME_RE.fullmatch(candidate):
            hosts.append(candidate.lower())
    return _dedupe(hosts)


def _dedupe(items):
    """Order-preserving de-duplication."""
    seen = set()
    out = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _sort_cidrs(cidrs):
    def key(cidr):
        net = ipaddress.ip_network(cidr, strict=False)
        return (net.version, int(net.network_address), net.prefixlen)

    try:
        return sorted(cidrs, key=key)
    except ValueError:
        return sorted(cidrs)


# --- the bounded CIDR → IP expander (the safety net) ------------------------
def _expand_cidrs_to_ips(cidrs, max_prefix=DEFAULT_MAX_CIDR_PREFIX,
                         cap=DEFAULT_MAX_TOTAL_IPS):
    """Expand IPv4 CIDRs to individual host IPs, bounded.

    Returns ``(ips, skipped_large, capped)`` where:
      * ``skipped_large`` lists ranges bigger than ``/max_prefix`` (prefixlen
        below ``max_prefix``) that were skipped wholesale.
      * ``capped`` is ``True`` when the global ``cap`` on total IPs was hit.

    IPv6 ranges are not swept (the ``/20`` heuristic is IPv4-centric); they are
    reported via ``skipped_large`` so the caller can log them.
    """
    ips = []
    skipped_large = []
    capped = False

    for cidr in cidrs:
        if capped:
            break
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue

        if net.version != 4:
            skipped_large.append(cidr)
            continue

        # "Larger than /20" == a smaller prefix length than the bound.
        if net.prefixlen < max_prefix:
            skipped_large.append(cidr)
            continue

        for host in net.hosts():
            if len(ips) >= cap:
                capped = True
                break
            ips.append(str(host))

    return ips, skipped_large, capped


# --- async subprocess wrapper ----------------------------------------------
async def _run_capture(cmd, stdin_bytes=None):
    """Run ``cmd`` (list) and return ``(stdout, stderr)`` decoded text.

    Never raises: subprocess/OS errors are swallowed and returned as empty
    output so a single tool failure cannot take down the whole expansion.
    """
    try:
        result = await proc.run_tool(cmd, input=stdin_bytes)
    except (OSError, ValueError) as exc:
        _skip(f"{cmd[0]} failed to run: {exc}")
        return "", ""
    return (
        result.stdout.decode(errors="replace"),
        result.stderr.decode(errors="replace"),
    )


async def _run_asnmap(binary, seed):
    """Resolve one seed (domain, org, or ASN) to ``(asns, cidrs)`` via asnmap.

    ``-json`` is requested so we can recover ASNs (plain ``-silent`` emits only
    CIDRs); the parser still copes with either form.  ASN-shaped seeds are routed
    through ``-a`` instead of ``-d``.
    """
    asn_form = _ASN_INPUT_RE.fullmatch(seed)
    if asn_form:
        cmd = [binary, "-a", f"AS{int(asn_form.group(1))}", "-json", "-silent"]
    else:
        cmd = [binary, "-d", seed, "-json", "-silent"]
    stdout, _ = await _run_capture(cmd)
    return _parse_asnmap_output(stdout)


async def _run_amass_intel(binary, seed):
    """Pivot one seed to related root domains via ``amass intel -whois``."""
    cmd = [binary, "intel", "-d", seed, "-whois", "-silent"]
    stdout, _ = await _run_capture(cmd)
    return _parse_amass_intel_output(stdout)


async def _run_dnsx_ptr(binary, ips):
    """Reverse-DNS sweep a list of IPs, returning discovered hostnames."""
    if not ips:
        return []
    cmd = [binary, "-ptr", "-resp-only", "-silent"]
    stdin_bytes = ("\n".join(ips) + "\n").encode()
    stdout, _ = await _run_capture(cmd, stdin_bytes=stdin_bytes)
    return _parse_dnsx_output(stdout)


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
    return shown


def _write_lines(path, items):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            for item in items:
                handle.write(f"{item}\n")
    except OSError as exc:
        _skip(f"Failed to write {path}: {exc}")


# --- entry point ------------------------------------------------------------
async def expand_horizontal(seed_domains: list[str], output_dir: str) -> dict:
    """Discover assets beyond ``seed_domains`` (ASNs, CIDRs, related roots, PTR hosts).

    Returns a dict with keys ``asns``, ``cidrs``, ``related_domains``,
    ``reverse_hosts`` and ``findings`` (canonical INFO findings summarizing what
    was discovered).  Returns an empty version of that dict - never raises - when
    the seed list is empty or the required tools are absent.
    """
    result = _empty_result()

    seeds = _dedupe(
        (d or "").strip().lower() for d in (seed_domains or []) if d and d.strip()
    )
    if not seeds:
        _info("horizontal_expand: no seed domains supplied - skipping.")
        return result

    have_asnmap = shutil.which("asnmap")
    have_dnsx = shutil.which("dnsx")
    have_amass = shutil.which("amass")

    if not any([have_asnmap, have_dnsx, have_amass]):
        _skip("horizontal_expand: none of asnmap/dnsx/amass found in PATH - skipping expansion.")
        return result

    results_dir = os.path.join(output_dir, "horizontal_expand")

    asns, cidrs, related, reverse_hosts = set(), set(), set(), set()

    # --- Phase 1: asnmap → owned ASNs + CIDRs -------------------------------
    if have_asnmap:
        _info(f"horizontal_expand: asnmap over {len(seeds)} seed(s)…")
        pairs = await asyncio.gather(
            *(_run_asnmap(have_asnmap, seed) for seed in seeds),
            return_exceptions=True,
        )
        for pair in pairs:
            if isinstance(pair, Exception):
                _skip(f"asnmap error: {pair}")
                continue
            seed_asns, seed_cidrs = pair
            asns.update(seed_asns)
            cidrs.update(seed_cidrs)
        _ok(f"horizontal_expand: asnmap found {len(asns)} ASN(s), {len(cidrs)} CIDR range(s).")
    else:
        _skip("horizontal_expand: asnmap not found - skipping ASN/CIDR discovery.")

    # --- Phase 2: bounded reverse-DNS sweep over owned CIDRs -----------------
    if have_dnsx and cidrs:
        ips, skipped_large, capped = _expand_cidrs_to_ips(sorted(cidrs))
        if skipped_large:
            _note(
                f"horizontal_expand: skipped {len(skipped_large)} range(s) larger than "
                f"/{DEFAULT_MAX_CIDR_PREFIX} (or non-IPv4): {_preview(skipped_large)}"
            )
        if capped:
            _note(
                f"horizontal_expand: reverse-DNS sweep capped at {DEFAULT_MAX_TOTAL_IPS} IPs "
                "to avoid a runaway sweep."
            )
        if ips:
            _info(f"horizontal_expand: reverse-DNS sweep over {len(ips)} IP(s)…")
            async with heartbeat(MODULE_NAME, "Reverse-DNS sweep"):
                hosts = await _run_dnsx_ptr(have_dnsx, ips)
            reverse_hosts.update(hosts)
            _ok(f"horizontal_expand: reverse-DNS surfaced {len(reverse_hosts)} hostname(s).")
        else:
            _note("horizontal_expand: no in-bounds IPs to sweep after applying limits.")
    elif not have_dnsx:
        _skip("horizontal_expand: dnsx not found - skipping reverse-DNS sweep.")

    # --- Phase 3: amass intel → related root domains ------------------------
    if have_amass:
        _info(f"horizontal_expand: amass intel over {len(seeds)} seed(s)…")
        domain_lists = await asyncio.gather(
            *(_run_amass_intel(have_amass, seed) for seed in seeds),
            return_exceptions=True,
        )
        for domains in domain_lists:
            if isinstance(domains, Exception):
                _skip(f"amass intel error: {domains}")
                continue
            related.update(domains)
        _ok(f"horizontal_expand: amass intel found {len(related)} related root domain(s).")
    else:
        _skip("horizontal_expand: amass not found - skipping related-domain discovery.")

    # --- Assemble output ----------------------------------------------------
    result["asns"] = sorted(asns)
    result["cidrs"] = _sort_cidrs(cidrs)
    result["related_domains"] = sorted(related)
    result["reverse_hosts"] = sorted(reverse_hosts)

    primary_target = seeds[0]
    findings = []
    if asns or cidrs:
        findings.append(_info_finding(
            "Horizontal Expansion: Owned ASN/CIDR Ranges Discovered",
            f"asnmap attributed {len(asns)} ASN(s) and {len(cidrs)} CIDR range(s) to the "
            f"seed(s) {_preview(seeds)}. ASNs: {_preview(result['asns']) or 'N/A'}. "
            f"CIDRs: {_preview(result['cidrs']) or 'N/A'}.",
            primary_target,
        ))
    if reverse_hosts:
        findings.append(_info_finding(
            "Horizontal Expansion: Reverse-DNS Hostnames Discovered",
            f"Reverse-DNS (PTR) sweep across owned CIDR ranges surfaced "
            f"{len(reverse_hosts)} hostname(s): {_preview(result['reverse_hosts'])}.",
            primary_target,
        ))
    if related:
        findings.append(_info_finding(
            "Horizontal Expansion: Related Root Domains Discovered",
            f"amass intel (WHOIS/registrant pivot) surfaced {len(related)} related root "
            f"domain(s) beyond the original scope: {_preview(result['related_domains'])}.",
            primary_target,
        ))
    result["findings"] = findings

    # --- Persist artifacts (best effort) ------------------------------------
    if any([asns, cidrs, related, reverse_hosts]):
        _write_lines(os.path.join(results_dir, "asns.txt"), result["asns"])
        _write_lines(os.path.join(results_dir, "cidrs.txt"), result["cidrs"])
        _write_lines(os.path.join(results_dir, "related_domains.txt"), result["related_domains"])
        _write_lines(os.path.join(results_dir, "reverse_hosts.txt"), result["reverse_hosts"])

    return result
