"""Shared-hosting asset classifier for VaktScan.

On website-builder / bulk-hosting domains (e.g. homestead.com), the overwhelming
majority of subdomains are CUSTOMER sites that all resolve to a small set of
shared hosting IPs, while the company's own infrastructure sits on distinct IPs.
Empirically for homestead.com: 22,248 / 22,385 subdomains (99.4%) resolved to a
single shared IP.

This module resolves each subdomain, groups hosts by IP, and classifies:

  * An IP that hosts >= ``shared_ip_threshold`` subdomains is treated as SHARED
    HOSTING, so its hosts are CUSTOMER-facing...
  * ...EXCEPT functional-named direct children of the apex (``www``, ``api``,
    ``mail``, ``login``, ``beta``, ``blog``, ``my`` ...), which are kept as
    COMPANY infra even when they sit on a shared IP (validated: beta/blog/my
    live on the shared IP but are company assets).
  * Hosts on low-count IPs (< threshold), and hosts that do not resolve, are
    COMPANY assets.

Reuses the project's raw DNS query (``dns_recon._query``) - no external tool
required. Never raises.
"""

import asyncio

from modules import dns_recon as _dr
from modules.schema import normalize_finding

MODULE_NAME = "asset_classifier"

# Functional labels that mark a DIRECT child of the apex as company infrastructure
# (kept even when it resolves to a shared hosting IP).
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


def _apex_child_label(host, apex):
    """Return the single label if ``host`` is a DIRECT child of ``apex``
    (e.g. mail.homestead.com under homestead.com), else None."""
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


async def _resolve_ip(host, resolver, sem):
    """Resolve ``host`` to its first A record (resolver follows CNAMEs). Returns
    the IP string, or None when it does not resolve / errors."""
    async with sem:
        try:
            resp = await _dr._query(resolver, host, _dr.RR_A, timeout=4.0)
        except Exception:
            return None
        for a in resp.get("answers", []):
            if a.get("type") == _dr.RR_A and a.get("data"):
                return a["data"]
        return None


async def classify_by_shared_ip(subdomains, apex, output_dir=None,
                                shared_ip_threshold=10, concurrency=100):
    """Resolve + classify subdomains into COMPANY vs CUSTOMER by shared-IP density.

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

        threshold = max(2, int(shared_ip_threshold or 10))
        resolvers = _dr.DEFAULT_RESOLVERS
        dns_conc = min(max(int(concurrency or 100), 100), 300)
        sem = asyncio.Semaphore(dns_conc)

        print(f"\033[96m[*] Asset classifier: resolving {len(hosts)} subdomain(s) to map IPs "
              f"(shared-IP threshold: {threshold} hosts/IP)...\033[0m")

        try:
            from modules.progress import DashboardProgress
            prog = DashboardProgress("asset_classifier", total=len(hosts), noun="hosts")

            async def _one(h, r):
                ip = await _resolve_ip(h, r, sem)
                result["ip_map"][h] = ip
            await asyncio.gather(*(prog.wrap(_one(h, resolvers[i % len(resolvers)]))
                                   for i, h in enumerate(hosts)), return_exceptions=True)
        except Exception:
            async def _one2(h, r):
                result["ip_map"][h] = await _resolve_ip(h, r, sem)
            await asyncio.gather(*(_one2(h, resolvers[i % len(resolvers)])
                                   for i, h in enumerate(hosts)), return_exceptions=True)

        # Count hosts per IP; IPs at/over the threshold are shared hosting.
        ip_counts = {}
        for h, ip in result["ip_map"].items():
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        shared_ips = {ip for ip, n in ip_counts.items() if n >= threshold}
        result["shared_ips"] = sorted(shared_ips)

        for h in hosts:
            ip = result["ip_map"].get(h)
            # On a shared hosting IP AND not a functional company host -> CUSTOMER.
            if ip and ip in shared_ips and not _is_functional(h, apex):
                result["customer"].append(h)
            else:
                # Distinct IP, non-resolving, or functional-named -> COMPANY.
                result["company"].append(h)

        resolved = sum(1 for v in result["ip_map"].values() if v)
        print(f"\033[92m[+] Asset classifier: {len(result['company'])} company asset(s), "
              f"{len(result['customer'])} customer/shared-hosting site(s) "
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
                        f"customer/shared-hosting (>= {threshold} hosts on a shared IP) and excluded "
                        f"from scanning; {len(result['company'])} company asset(s) retained. "
                        f"Shared IP(s): {', '.join(result['shared_ips'][:5])}"
                        f"{'…' if len(result['shared_ips']) > 5 else ''}."),
        }))
        return result
    except Exception as exc:
        # Fail-open: on any unexpected error, scan everything (never silently drop).
        print(f"\033[93m[!] Asset classifier error ({exc}); scanning all hosts.\033[0m")
        result["company"] = list(subdomains or [])
        result["customer"] = []
        return result
