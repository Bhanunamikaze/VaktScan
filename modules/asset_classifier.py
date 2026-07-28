"""Shared-hosting asset classifier for VaktScan.

On website-builder / bulk-hosting domains (e.g. steinzsecurity.com), the
overwhelming majority of subdomains are CUSTOMER sites that all resolve to a
small set of shared hosting IPs, while the company's own infrastructure sits on
distinct IPs.

This module resolves each subdomain, groups hosts by IP, and classifies:

  * An IP that hosts >= ``shared_ip_threshold`` subdomains is treated as SHARED
    HOSTING, so its hosts are CUSTOMER-facing...
  * ...OR a host whose CNAME target / reverse-DNS (PTR) hostname matches a known
    shared-hosting marker (``DEFAULT_CUSTOMER_DNS_MARKERS`` plus any user-supplied
    ``extra_markers``) is CUSTOMER-facing too. This DNS-marker signal complements
    the shared-IP rule: it catches customers on hosting IPs that fall BELOW the
    shared-IP threshold (multi-IP providers) which the density rule would miss.
  * ...EXCEPT functional-named direct children of the apex (``www``, ``api``,
    ``mail``, ``login``, ``beta``, ``blog``, ``my`` ...), which are kept as
    COMPANY infra even when they sit on a shared IP OR match a marker. On real
    data the hosting PTR is shared by customer sites AND the company's own
    functional pages (beta/blog/app all sit on the same hosting), so this rescue
    is what keeps company pages from being misclassified.
  * Hosts on low-count IPs (< threshold) with no marker, and hosts that do not
    resolve, are COMPANY assets.

Reuses the project's raw DNS query (``dns_recon._query``) - no external tool
required. Fail-open throughout: a missing A / CNAME / PTR is treated as empty and
never drops a target. Never raises.
"""

import asyncio

from modules import dns_recon as _dr
from modules.schema import normalize_finding

MODULE_NAME = "asset_classifier"

# PTR resource-record type (reverse DNS). dns_recon has no RR_PTR constant yet, so
# fall back to the IANA value (12).
RR_PTR = getattr(_dr, "RR_PTR", 12)

# Functional labels that mark a DIRECT child of the apex as company infrastructure
# (kept even when it resolves to a shared hosting IP or matches a DNS marker).
FUNCTIONAL_LABELS = {
    "www", "api", "mail", "mx", "smtp", "imap", "pop", "mailgw", "email", "emailmg",
    "ns", "ns1", "ns2", "ns3", "dns", "admin", "portal", "login", "signin", "sso",
    "auth", "account", "accounts", "billing", "vpn", "git", "gitlab", "jenkins",
    "ci", "cd", "build", "staging", "stage", "preprod", "dev", "test", "qa", "uat",
    "cpanel", "whm", "webmail", "blog", "news", "support", "help", "helpdesk",
    "status", "cdn", "assets", "static", "img", "images", "media", "app", "apps",
    "dashboard", "console", "secure", "ftp", "sftp", "remote", "gateway", "proxy",
    "internal", "corp", "intranet", "beta", "demo", "my", "store", "shop", "chat",
    "community", "editor", "install", "listings", "crm", "hs", "in", "click",
}

# Shared-hosting / cPanel-style substrings. A host whose CNAME target or PTR
# hostname contains any of these (case-insensitive substring match) is treated as
# a customer site sitting on shared hosting infrastructure. Provider-agnostic and
# configurable: on real data the tell-tale marker is the reverse-DNS of the
# hosting IP (e.g. a ``*.unifiedlayer.com`` PTR), not the literal string "cpanel".
DEFAULT_CUSTOMER_DNS_MARKERS = {
    "cpanel", "cpsrvd", "cpcalendars", "cpcontacts", "webdisk", "whm",
    "unifiedlayer", "secureserver", "bluehost", "hostgator", "hostmonster",
    "websitewelcome", "web-hosting", "ipage", "justhost", "fatcow", "webhostbox",
}


def _apex_child_label(host, apex):
    """Return the single label if ``host`` is a DIRECT child of ``apex``
    (e.g. mail.steinzsecurity.com under steinzsecurity.com), else None."""
    host = (host or "").strip().lower().rstrip(".")
    apex = (apex or "").strip().lower().rstrip(".")
    if not host or not apex or not host.endswith("." + apex):
        return None
    prefix = host[: -(len(apex) + 1)]
    if prefix and "." not in prefix:
        return prefix
    return None


def _is_functional(host, apex):
    label = _apex_child_label(host, apex)
    return bool(label and label in FUNCTIONAL_LABELS)


def _build_markers(extra_markers):
    """Merge user-supplied ``extra_markers`` into the defaults (lowercased set).
    Fail-open: bad / empty entries are ignored, never raises."""
    markers = set(DEFAULT_CUSTOMER_DNS_MARKERS)
    try:
        for m in extra_markers or []:
            try:
                m = (m or "").strip().lower()
            except Exception:
                continue
            if m:
                markers.add(m)
    except Exception:
        pass
    return markers


def _marker_match(cname, ptr, markers):
    """Return a matching marker substring if the CNAME target or PTR hostname
    contains one, else None. Case-insensitive substring match."""
    hay = f"{cname or ''} {ptr or ''}".lower()
    if not hay.strip():
        return None
    for m in markers:
        if m and m in hay:
            return m
    return None


def _reverse_ipv4(ip):
    """``1.2.3.4`` -> ``4.3.2.1.in-addr.arpa`` (IPv4 only). Returns "" on anything
    that is not a dotted-quad."""
    try:
        parts = (ip or "").strip().split(".")
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return ""
        return ".".join(reversed(parts)) + ".in-addr.arpa"
    except Exception:
        return ""


def _dns_name_from_hex(hexstr):
    """Best-effort decode of a PTR rdata blob (length-prefixed DNS labels) that
    ``dns_recon._parse_response`` hands back as hex for record types it does not
    special-case. Stops at the root label or a compression pointer (which cannot
    be resolved without the full message). Returns "" on anything unexpected."""
    try:
        raw = bytes.fromhex(hexstr)
    except Exception:
        return ""
    labels = []
    i, n = 0, len(raw)
    while i < n:
        length = raw[i]
        if length == 0:
            break
        if length & 0xC0:  # compression pointer / reserved - not resolvable here
            break
        i += 1
        if i + length > n:
            break
        labels.append(raw[i:i + length].decode("ascii", "replace"))
        i += length
    return ".".join(labels)


def _ptr_hostname(data):
    """Normalize a PTR answer ``data`` field into a hostname string.

    Mocks (and any resolver path that decodes the name) provide a dotted
    hostname directly; the raw ``dns_recon`` parser hands back hex for PTR
    records, so decode that as a fallback. Returns "" when nothing usable."""
    s = str(data or "").strip().strip('"')
    if not s:
        return ""
    # Already a hostname (has a dot and at least one letter).
    if "." in s and any(c.isalpha() for c in s):
        return s.lower().rstrip(".")
    # Looks like raw hex from the generic parser -> decode the DNS name.
    low = s.lower()
    if low and len(low) % 2 == 0 and all(c in "0123456789abcdef" for c in low):
        return _dns_name_from_hex(low).lower().rstrip(".")
    return ""


async def _ptr_of(ip, resolver, sem):
    """Reverse-DNS (PTR) hostname for ``ip``, or "" on miss/error. Concurrency is
    bounded by ``sem``; fail-open (never raises)."""
    arpa = _reverse_ipv4(ip)
    if not arpa:
        return ""
    async with sem:
        try:
            resp = await _dr._query(resolver, arpa, RR_PTR, timeout=4.0)
        except Exception:
            return ""
    try:
        for a in resp.get("answers", []):
            if a.get("type") == RR_PTR and a.get("data"):
                host = _ptr_hostname(a["data"])
                if host:
                    return host
    except Exception:
        return ""
    return ""


async def _resolve_host(host, resolver, sem):
    """Resolve ``host`` and return ``(ip, cname, ptr)``:

      * ip    - first A record (resolver follows CNAMEs), or None.
      * cname - space-joined CNAME target(s) seen in the A answer chain, or "".
      * ptr   - reverse-DNS hostname of the resolved IP, or "".

    Fail-open: any resolution error yields ``(None, "", "")``; never raises."""
    ip, cnames = None, []
    async with sem:
        try:
            resp = await _dr._query(resolver, host, _dr.RR_A, timeout=4.0)
        except Exception:
            resp = None
        if resp:
            try:
                for a in resp.get("answers", []):
                    t, d = a.get("type"), a.get("data")
                    if t == _dr.RR_A and d and ip is None:
                        ip = d
                    elif t == _dr.RR_CNAME and d:
                        cnames.append(str(d).strip().lower().rstrip("."))
            except Exception:
                pass
    cname = " ".join(c for c in cnames if c)
    ptr = await _ptr_of(ip, resolver, sem) if ip else ""
    return ip, cname, ptr


async def classify_by_shared_ip(subdomains, apex, output_dir=None,
                                shared_ip_threshold=10, concurrency=100,
                                extra_markers=None):
    """Resolve + classify subdomains into COMPANY vs CUSTOMER.

    A host is CUSTOMER when (it sits on a SHARED hosting IP) OR (its CNAME target
    / PTR hostname matches a shared-hosting marker), MINUS the functional-name
    rescue: a functional-named direct child of the apex stays COMPANY even when it
    matches a marker or a shared IP.

    Returns::

        {
          "company":   [hosts to scan],
          "customer":  [shared-hosting/customer hosts to skip],
          "ip_map":    {host: ip or None},
          "shared_ips": [ip, ...],           # IPs with >= threshold hosts
          "findings":  [<one INFO summary finding>],
        }

    Always returns a fully-shaped dict; never raises. If nothing resolves, every
    host is treated as COMPANY (fail-open - we do not silently drop targets).
    """
    result = {"company": [], "customer": [], "ip_map": {}, "shared_ips": [], "findings": []}
    try:
        hosts, seen = [], set()
        for h in subdomains or []:
            h = (h or "").strip().lower().rstrip(".")
            if h and h not in seen:
                seen.add(h)
                hosts.append(h)
        if not hosts:
            return result

        markers = _build_markers(extra_markers)
        threshold = max(2, int(shared_ip_threshold or 10))
        resolvers = _dr.DEFAULT_RESOLVERS
        dns_conc = min(max(int(concurrency or 100), 100), 300)
        sem = asyncio.Semaphore(dns_conc)

        # host -> (ip, cname, ptr) captured during resolution.
        meta = {}

        print(f"\033[96m[*] Asset classifier: resolving {len(hosts)} subdomain(s) to map IPs / "
              f"CNAME / PTR (shared-IP threshold: {threshold} hosts/IP, "
              f"{len(markers)} DNS marker(s))...\033[0m")

        try:
            from modules.progress import DashboardProgress
            prog = DashboardProgress("asset_classifier", total=len(hosts), noun="hosts")

            async def _one(h, r):
                ip, cname, ptr = await _resolve_host(h, r, sem)
                meta[h] = (ip, cname, ptr)
                result["ip_map"][h] = ip
            await asyncio.gather(*(prog.wrap(_one(h, resolvers[i % len(resolvers)]))
                                   for i, h in enumerate(hosts)), return_exceptions=True)
        except Exception:
            async def _one2(h, r):
                ip, cname, ptr = await _resolve_host(h, r, sem)
                meta[h] = (ip, cname, ptr)
                result["ip_map"][h] = ip
            await asyncio.gather(*(_one2(h, resolvers[i % len(resolvers)])
                                   for i, h in enumerate(hosts)), return_exceptions=True)

        # Count hosts per IP; IPs at/over the threshold are shared hosting.
        ip_counts = {}
        for h, ip in result["ip_map"].items():
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        shared_ips = {ip for ip, n in ip_counts.items() if n >= threshold}
        result["shared_ips"] = sorted(shared_ips)

        via_shared = via_marker = 0
        for h in hosts:
            ip, cname, ptr = meta.get(h, (None, "", ""))
            on_shared = bool(ip and ip in shared_ips)
            marker_hit = _marker_match(cname, ptr, markers)
            # Functional-named direct apex children are always company (rescue),
            # even on a shared IP or with a marker hit.
            if _is_functional(h, apex):
                result["company"].append(h)
            elif on_shared:
                result["customer"].append(h)
                via_shared += 1
            elif marker_hit:
                # Customer caught by the DNS-marker signal alone (below the
                # shared-IP threshold) - the marker rule's added value.
                result["customer"].append(h)
                via_marker += 1
            else:
                # Distinct IP, non-resolving, or no marker -> COMPANY.
                result["company"].append(h)

        resolved = sum(1 for v in result["ip_map"].values() if v)
        print(f"\033[92m[+] Asset classifier: {len(result['company'])} company asset(s), "
              f"{len(result['customer'])} customer/shared-hosting site(s) "
              f"({via_shared} via shared IP, {via_marker} via DNS marker) "
              f"across {len(shared_ips)} shared IP(s) (of {resolved} resolved).\033[0m")

        # Optionally persist the two lists for transparency.
        if output_dir:
            import os
            try:
                for name, items in (("company_assets", result["company"]),
                                    ("customer_sites", result["customer"])):
                    with open(os.path.join(output_dir, f"{name}.txt"), "w", encoding="utf-8") as fh:
                        for x in sorted(items):
                            fh.write(f"{x}\n")
            except OSError:
                pass

        # One INFO summary finding for the report.
        result["findings"].append(normalize_finding({
            "target": apex,
            "vulnerability": "Asset Classification (shared-hosting split)",
            "status": "INFO",
            "severity": "INFO",
            "module": MODULE_NAME,
            "details": (f"{len(result['customer'])} of {len(hosts)} subdomain(s) classified as "
                        f"customer/shared-hosting and excluded from scanning "
                        f"({via_shared} via shared IP >= {threshold} hosts, "
                        f"{via_marker} via DNS marker); "
                        f"{len(result['company'])} company asset(s) retained. "
                        f"Shared IP(s): {', '.join(result['shared_ips'][:5])}"
                        f"{'...' if len(result['shared_ips']) > 5 else ''}."),
        }))
        return result
    except Exception as exc:
        # Fail-open: on any unexpected error, scan everything (never silently drop).
        print(f"\033[93m[!] Asset classifier error ({exc}); scanning all hosts.\033[0m")
        result["company"] = list(subdomains or [])
        result["customer"] = []
        return result
