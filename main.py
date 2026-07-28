import asyncio
import argparse
import csv
import ipaddress
import sys
import os
import re
import signal
import time
import traceback

# Load .env if present (optional dependency - silently skipped if not installed)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Add vendor directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'vendor'))

from reporter import (
    Colors,
    deduplicate_vulnerabilities,
    save_port_scan_csv,
    save_results_to_csv,
    save_results_to_json,
    save_results_to_html,
    write_sarif_output,
    print_final_results,
)

from utils import (
    build_default_http_probe_urls,
    build_web_probe_urls,
    build_recon_probe_urls,
    build_scan_targets_from_mappings,
    collect_domain_hosts,
    get_service_ports,
    normalize_host_value,
    build_exclusion_matcher,
    load_exclusion_patterns,
    parse_targets_file,
    process_targets,
    process_targets_streaming,
    resolve_hostnames,
    is_valid_domain,
)
from port_scanner import scan_ports, DEFAULT_CONNECT_TIMEOUT, DEFAULT_PORT_RETRIES
from service_validator import validate_service
from scan_state import ScanStateManager
from modules import (
    elastic,
    kibana,
    grafana,
    prometheus,
    react_to_shell,
    recon,
    httpx_runner,
    nuclei_runner,
    nmap_runner,
    dir_enum,
    gau_runner,
    waybackurls_runner,
    domain_scan,
    js_paths,
    js_cve,
    aem,
    cpanel,
    dns_recon,
    service_recon,
    web_checks,
    cisa_kev,
    epss,
    jenkins,
    passive_intel,
    inventory,
    cloud_enum,
    nvd,
    google_dork,
    ct_monitor,
    testssl_runner,
    archived_urls,
    horizontal_expand,
    screenshots,
    param_discovery,
    dns_resolve,
    favicon_jarm,
    tech_fingerprint,
    web_tech_cve,
    default_creds,
    notify,
    asset_classifier,
    proc,
)

# Exceptions that indicate a programming bug rather than an environmental,
# per-target, or external-tool failure. `UnboundLocalError` is a subclass of
# `NameError`, so this also covers the "free variable ... not associated with a
# value" crash that a `return_exceptions=True` gather once masked as
# "no usable targets". Resilience wrappers below re-raise these so real bugs
# surface loudly instead of being silently swallowed, while genuine runtime
# failures (network, subprocess, bad target data) are still tolerated.
_PROGRAMMING_ERRORS = (NameError, ImportError)


def _reraise_if_bug(exc):
    """Re-raise `exc` if it looks like a programming bug; otherwise return it.

    Used at `asyncio.gather(..., return_exceptions=True)` sites and broad
    `except` blocks so that a code defect is never hidden behind a generic
    "task failed, continuing" message.
    """
    if isinstance(exc, _PROGRAMMING_ERRORS):
        raise exc
    return exc


# Map service names to their corresponding modules
SERVICE_TO_MODULE = {
    "elasticsearch": elastic,
    "kibana": kibana,
    "grafana": grafana,
    "prometheus": prometheus,
    "nextjs": react_to_shell,
    "aem": aem,
    "cpanel": cpanel,
    "service_recon": service_recon,
    "jenkins": jenkins,
    "testssl": testssl_runner,
}


def target_classifier(target: str):
    """Classify a target string as 'domain', 'ip', 'cidr', or 'file'."""
    import ipaddress
    # File: existing path on disk
    if os.path.isfile(target):
        return 'file'
    # Strip brackets from IPv6 addresses (e.g., [::1] -> ::1)
    stripped_target = target.strip('[]')
    # CIDR: contains slash and is a valid network
    if '/' in stripped_target:
        try:
            ipaddress.ip_network(stripped_target, strict=False)
            return 'cidr'
        except ValueError:
            pass
    # IP: valid IP address
    try:
        ipaddress.ip_address(stripped_target)
        return 'ip'
    except ValueError:
        pass
    # Domain: anything else with at least one dot
    return 'domain'


def make_output_dir(target: str, subcommand: str = 'scan', base: str = 'reports') -> str:
    """
    Create and return an output directory path.
    - scan: reports/<target>_<YYYYMMDD_HHMMSS>/
    - others: reports/<target>/
    """
    # Sanitize target for use as directory name
    safe_target = re.sub(r'[^\w\.\-]', '_', target)[:64]
    if subcommand == 'scan':
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(base, f"{safe_target}_{ts}")
    else:
        path = os.path.join(base, safe_target)
    os.makedirs(path, exist_ok=True)
    return path


# Global to track partial findings for SIGINT handler
_partial_findings: list = []

LOGO_PRINTED = False

def print_logo():
    """Display VaktScan ASCII logo with colors."""
    global LOGO_PRINTED
    if LOGO_PRINTED:
        return
    # Check if output is to terminal for color support
    if not sys.stdout.isatty():
        Colors.disable()
    
    logo = f"""
{Colors.BRIGHT_CYAN}╔════════════════════════════════════════════════════════════════════════╗{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                                        {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_BLUE}██╗   ██╗ █████╗ ██╗  ██╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗{Colors.RESET}  {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_BLUE}██║   ██║██╔══██╗██║ ██╔╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║{Colors.RESET}  {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_BLUE}██║   ██║███████║█████╔╝    ██║   ███████╗██║     ███████║██╔██╗ ██║{Colors.RESET}  {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}  {Colors.BRIGHT_BLUE}╚██╗ ██╔╝██╔══██║██╔═██╗    ██║   ╚════██║██║     ██╔══██║██║╚██╗██║{Colors.RESET}  {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}   {Colors.BRIGHT_BLUE}╚████╔╝ ██║  ██║██║  ██╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║{Colors.RESET}  {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}    {Colors.BRIGHT_BLUE}╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Colors.RESET}  {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                                        {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}                  {Colors.BRIGHT_YELLOW}        Attack Surface Scanner   {Colors.RESET}                     {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}                         {Colors.BRIGHT_MAGENTA}   Nordic Vigilance   {Colors.RESET}                         {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                                        {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.GREEN}Recon & Port Scans{Colors.RESET} • {Colors.GREEN}CVE Detection{Colors.RESET} • {Colors.GREEN}Vuln Detection{Colors.RESET} • {Colors.GREEN}Dir Enum{Colors.RESET}    {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}                     {Colors.YELLOW}Web Service Detection {Colors.RESET} • {Colors.YELLOW}Vuln Exploits             {Colors.RESET}{Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                                        {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}╚════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(logo)
    LOGO_PRINTED = True


def _looks_like_js(url):
    """True when a URL's path points at a JavaScript file (.js/.mjs), ignoring
    any query string/fragment. Used to build the js_cve corpus from URLs VaktScan
    already discovered."""
    try:
        from urllib.parse import urlparse as _urlparse
        return _urlparse((url or "").lower()).path.endswith((".js", ".mjs"))
    except Exception:
        return False


async def run_recon_followups(
    subdomains,
    recon_domain,
    output_dir,
    concurrency,
    nmap_enabled,
    wordlist=None,
    connect_timeout=DEFAULT_CONNECT_TIMEOUT,
    port_retries=DEFAULT_PORT_RETRIES,
    enable_archived=True,
    enable_screenshots=False,
    extra_scans=frozenset(),
    enable_js_cve=True,
):
    """Run HTTPX, dirsearch, nuclei, and optional Nmap on recon results."""
    all_findings = []
    # JS corpus for the client-side CVE scan (js_cve). We REUSE the JS VaktScan
    # already discovers - JS URLs from js_paths, JS-looking alive/absolute URLs,
    # and archived .js URLs - rather than adding a second crawl/download pass.
    js_cve_corpus = set()

    if not subdomains:
        print(f"{Colors.YELLOW}[!] No subdomains discovered to probe further.{Colors.RESET}")
        return all_findings

    http_runner = httpx_runner.HTTPXRunner(output_dir=output_dir)
    unique_targets = sorted({target.strip().lower() for target in subdomains if target and target.strip()})
    if not unique_targets:
        print(f"{Colors.YELLOW}[!] No normalized subdomains remained after filtering.{Colors.RESET}")
        return all_findings

    host_to_ip, ip_to_hosts, unresolved_hosts = await resolve_hostnames(unique_targets)
    recon_targets = build_scan_targets_from_mappings(unique_targets, host_to_ip)

    # Note: DomainClassification happens right before we probe and saves to the output_dir
    scanner = domain_scan.DomainScanner(output_dir=output_dir)
    classified = scanner.classify_domains(unique_targets)
    scanner.save_classification_csv(unique_targets)
    print(f"{Colors.GRAY}[*] Domain mix: {len(classified['INTERNAL'])} INTERNAL, {len(classified['EXTERNAL'])} EXTERNAL{Colors.RESET}")

    print(
        f"{Colors.CYAN}[*] Running preliminary web-port scan on {len(unique_targets)} hosts "
        f"mapped to {len(ip_to_hosts)} unique IPv4 addresses...{Colors.RESET}"
    )
    if unresolved_hosts:
        print(
            f"{Colors.YELLOW}[!] Could not resolve {len(unresolved_hosts)} hostnames during pre-processing. "
            f"Default httpx hostname probes will still be attempted for them.{Colors.RESET}"
        )

    service_ports = get_service_ports()
    common_web_ports = sorted(set(service_ports.get("web", [])))
    port_scan_results = []
    nmap_followup_task = None

    async def _await_nmap_task():
        if nmap_followup_task:
            await nmap_followup_task

    if recon_targets:
        port_scan_results = await scan_ports(
            recon_targets,
            common_web_ports,
            concurrency,
            state_manager=None,
            connect_timeout=connect_timeout,
            retries=port_retries,
        )
    else:
        print(
            f"{Colors.YELLOW}[!] No resolved scan targets remained after hostname/IP deduplication. "
            f"Skipping the TCP web-port sweep and relying on hostname-first httpx probing.{Colors.RESET}"
        )

    # Nmap CVE scanning is NOT done here with a separate full 1-65535 sweep.
    # It runs once in the main scan phase, executing `nmap --script vuln,vulners`
    # ONLY on the open ports the port scanner already discovered (all service
    # ports + any --ports). Kept the scaffolding above as a no-op for callers.
    default_probe_urls = build_default_http_probe_urls(unique_targets)
    probe_urls = build_recon_probe_urls(unique_targets, port_scan_results, ip_to_hosts)
    if not probe_urls:
        print(f"{Colors.YELLOW}[!] No hostname or port-scan HTTP targets were generated; skipping httpx probe.{Colors.RESET}")
        await _await_nmap_task()
        return all_findings

    print(
        f"{Colors.CYAN}[*] Probing {len(probe_urls)} URLs with httpx "
        f"({len(default_probe_urls)} default hostname probes + shared-IP expanded port discoveries)...{Colors.RESET}"
    )
    httpx_data = await http_runner.run_httpx(probe_urls, concurrency)
    if not httpx_data:
        print(f"{Colors.YELLOW}[!] No alive HTTP services detected by httpx.{Colors.RESET}")
        await _await_nmap_task()
        return all_findings

    http_runner.save_csv(httpx_data, recon_domain.replace('.', '_'))

    alive_urls = []
    for entry in httpx_data:
        url = entry.get('url')
        if url:
            alive_urls.append(url)

    alive_urls = sorted(set(alive_urls))
    dir_enumerator = dir_enum.DirEnumerator(recon_domain, wordlist=wordlist, output_dir=output_dir)

    if wordlist:
        print(f"{Colors.CYAN}[*] Running ffuf (post-httpx) for additional vhosts...{Colors.RESET}")
        ffuf_subdomains = await dir_enumerator.fuzz_subdomains()
        new_targets = []
        for sub in ffuf_subdomains:
            if sub and sub not in unique_targets:
                unique_targets.append(sub)
                new_targets.append(sub)
        if new_targets:
            ffuf_probe_urls = build_default_http_probe_urls(new_targets)
            print(
                f"{Colors.CYAN}[*] Probing {len(ffuf_probe_urls)} ffuf-discovered default HTTP targets with httpx...{Colors.RESET}"
            )
            ffuf_httpx = await http_runner.run_httpx(ffuf_probe_urls, concurrency)
            if ffuf_httpx:
                http_runner.save_csv(ffuf_httpx, f"{recon_domain.replace('.', '_')}_ffuf")
                httpx_data.extend(ffuf_httpx)
                for entry in ffuf_httpx:
                    url = entry.get('url')
                    if url:
                        alive_urls.append(url)
            else:
                print(f"{Colors.YELLOW}[!] No additional alive hosts found from ffuf results.{Colors.RESET}")

    alive_urls = sorted(set(alive_urls))
    
    # Run domain scanner, dirsearch, nuclei, web checks, and JS paths concurrently -
    # all are read-only against alive_urls and write to their own files in output_dir.
    if alive_urls:
        print(f"{Colors.CYAN}[*] Running domain scanner, dirsearch, nuclei, web checks, and JS paths in parallel on {len(alive_urls)} URL(s)...{Colors.RESET}")
        nuclei_inst = nuclei_runner.NucleiRunner(output_dir=output_dir)
        js_scanner = js_paths.JSPathsScanner(alive_urls, output_dir=output_dir)

        from modules.dashboard import LiveDashboard
        dashboard = LiveDashboard()
        if dashboard.active:
            dashboard.add_task("domain_scan", "Domain Scan")
            dashboard.add_task("dirsearch", "Dirsearch Scan")
            dashboard.add_task("nuclei", "Nuclei Scan")
            dashboard.add_task("web_checks", "Web Checks")
            dashboard.add_task("js_paths", "JS Paths Scan")

        try:
            (
                domain_scan_findings,
                _dirsearch,
                nuclei_results,
                wc_results,
                js_result,
            ) = await asyncio.gather(
                scanner.run(
                    domains=unique_targets,
                    httpx_data=httpx_data,
                    alive_urls=alive_urls,
                    concurrency=concurrency,
                ),
                dir_enumerator.run_dirsearch(alive_urls),
                nuclei_inst.run_nuclei(alive_urls),
                web_checks.run_checks(alive_urls, concurrency),
                js_scanner.run(),
                return_exceptions=True,
            )
        finally:
            if dashboard.active:
                loc = locals()
                
                # domain_scan
                ds_val = loc.get("domain_scan_findings")
                ds_count = len(ds_val) if isinstance(ds_val, list) else 0
                dashboard.complete_task("domain_scan", f"Found {ds_count} vulnerabilities")
                
                # dirsearch
                dir_val = loc.get("_dirsearch")
                dir_count = len(dir_val) if isinstance(dir_val, (list, dict)) else 0
                dashboard.complete_task("dirsearch", f"Found {dir_count} directories")
                
                # nuclei
                nuc_val = loc.get("nuclei_results")
                nuc_count = len(nuc_val) if isinstance(nuc_val, list) else 0
                dashboard.complete_task("nuclei", f"Found {nuc_count} vulnerabilities")
                
                # web_checks
                wc_val = loc.get("wc_results")
                wc_count = len(wc_val) if isinstance(wc_val, list) else 0
                dashboard.complete_task("web_checks", f"Found {wc_count} vulnerabilities")
                
                # js_paths
                js_val = loc.get("js_result")
                js_count = len(js_val) if isinstance(js_val, list) else 0
                dashboard.complete_task("js_paths", f"Found {js_count} findings")

        if isinstance(domain_scan_findings, Exception):
            _reraise_if_bug(domain_scan_findings)
            print(f"{Colors.YELLOW}[!] Domain scanner error: {domain_scan_findings}{Colors.RESET}")
            domain_scan_findings = []
        if domain_scan_findings:
            print(f"{Colors.GREEN}[+] Domain scanner identified {len(domain_scan_findings)} web issues.{Colors.RESET}")
            for finding in domain_scan_findings:
                print(f"    - {finding['status']} | {finding['vulnerability']} | {finding['url']}")
            all_findings.extend(domain_scan_findings)
            save_results_to_csv(domain_scan_findings, filename=os.path.join(output_dir, f"domain_scan_vulns_{time.strftime('%Y%m%d_%H%M%S')}.csv"))

        if isinstance(nuclei_results, Exception):
            _reraise_if_bug(nuclei_results)
            print(f"{Colors.YELLOW}[!] Nuclei error: {nuclei_results}{Colors.RESET}")
            nuclei_results = []
        if nuclei_results:
            print(f"{Colors.GREEN}[+] Nuclei identified {len(nuclei_results)} findings.{Colors.RESET}")
            for vuln in nuclei_results:
                print(f"    - {vuln['status']} | {vuln['vulnerability']} | {vuln['url']}")
            all_findings.extend(nuclei_results)
        else:
            print(f"{Colors.GREEN}[+] Nuclei scan complete with no findings.{Colors.RESET}")

        if isinstance(wc_results, Exception):
            _reraise_if_bug(wc_results)
            print(f"{Colors.YELLOW}[!] Web checks error: {wc_results}{Colors.RESET}")
            wc_results = []
        if wc_results:
            print(f"{Colors.GREEN}[+] Web checks: {len(wc_results)} finding(s).{Colors.RESET}")
            all_findings.extend(wc_results)
        else:
            print(f"{Colors.GREEN}[+] Web checks complete. No findings.{Colors.RESET}")

        if isinstance(js_result, Exception):
            _reraise_if_bug(js_result)
            print(f"{Colors.YELLOW}[!] JS paths error: {js_result}{Colors.RESET}")
            js_result = []
        js_findings = js_result.get('findings', []) if isinstance(js_result, dict) else (js_result or [])
        if js_findings:
            print(f"{Colors.GREEN}[+] JS paths: {len(js_findings)} finding(s).{Colors.RESET}")
            all_findings.extend(js_findings)

        # Harvest the JS that js_paths already discovered (JS file URLs + any
        # JS-looking absolute URLs it extracted) for the client-side CVE scan.
        if enable_js_cve and isinstance(js_result, dict):
            for _u in js_result.get('js_urls', []) or []:
                if _u:
                    js_cve_corpus.add(_u)
            for _u in js_result.get('absolute_urls', []) or []:
                if _u and _looks_like_js(_u):
                    js_cve_corpus.add(_u)
        # Also fold in any JS that httpx probed directly as an alive URL.
        if enable_js_cve:
            for _u in alive_urls:
                if _looks_like_js(_u):
                    js_cve_corpus.add(_u)

        # Visual triage: screenshot alive URLs (opt-in via --screenshots; capped,
        # since a recon run can yield tens of thousands of alive hosts). Gracefully
        # skips when gowitness/aquatone isn't installed.
        if enable_screenshots:
            _cap = 500
            _shot_urls = alive_urls[:_cap]
            if len(alive_urls) > _cap:
                print(f"{Colors.YELLOW}[*] Screenshotting first {_cap} of {len(alive_urls)} alive URL(s).{Colors.RESET}")
            _shot_findings = await screenshots.capture_screenshots(_shot_urls, output_dir, concurrency)
            if _shot_findings:
                print(f"{Colors.GREEN}[+] Screenshots: {len(_shot_findings)} finding(s).{Colors.RESET}")
                all_findings.extend(_shot_findings)

        # Optional alive-URL analyses (opt-in - each can be heavy at recon scale;
        # all gracefully skip when their external tool isn't installed).
        if "params" in extra_scans:
            _pf = await param_discovery.discover_parameters(alive_urls, output_dir, concurrency)
            if _pf:
                print(f"{Colors.GREEN}[+] Parameter discovery: {len(_pf)} finding(s).{Colors.RESET}")
                all_findings.extend(_pf)
        if "favicon" in extra_scans:
            _ff = await favicon_jarm.fingerprint_favicon_jarm(alive_urls, output_dir, concurrency)
            if _ff:
                print(f"{Colors.GREEN}[+] Favicon/JARM pivots: {len(_ff)} finding(s).{Colors.RESET}")
                all_findings.extend(_ff)
        if "tech" in extra_scans:
            _tf = await tech_fingerprint.fingerprint_tech(alive_urls, output_dir, concurrency)
            if _tf:
                print(f"{Colors.GREEN}[+] Tech/EOL fingerprint: {len(_tf)} finding(s).{Colors.RESET}")
                all_findings.extend(_tf)
        if "default_creds" in extra_scans:
            _dcf = await default_creds.check_default_credentials(alive_urls, output_dir, concurrency)
            if _dcf:
                print(f"{Colors.BRIGHT_RED}[!] Default credentials: {len(_dcf)} confirmed finding(s).{Colors.RESET}")
                all_findings.extend(_dcf)

    # GAU + waybackurls in parallel
    domain_hosts = collect_domain_hosts(alive_urls)
    if domain_hosts:
        print(f"{Colors.CYAN}[*] Harvesting archived URLs for {len(domain_hosts)} host(s) (gau + waybackurls in parallel)...{Colors.RESET}")
        gau_inst = gau_runner.GAURunner(output_dir=output_dir)
        wayback_inst = waybackurls_runner.WaybackURLsRunner(output_dir=output_dir)

        from modules.dashboard import LiveDashboard
        dashboard = LiveDashboard()
        if dashboard.active:
            dashboard.add_task("gau", "GAU Archival")
            dashboard.add_task("wayback", "Wayback Archival")

        try:
            gau_result, wayback_result = await asyncio.gather(
                gau_inst.run(domain_hosts),
                wayback_inst.run(domain_hosts),
                return_exceptions=True,
            )
        finally:
            if dashboard.active:
                dashboard.complete_task("gau")
                dashboard.complete_task("wayback")

        # Weaponize the harvested archive: dedup → filter high-signal → re-probe
        # for live endpoints → secret-scan archived JS. Reuses the URLs gau/wayback
        # already produced (previously discarded).
        if enable_archived:
            _archived_urls = []
            for _res in (gau_result, wayback_result):
                if isinstance(_res, dict):
                    for _urls in _res.values():
                        _archived_urls.extend(_urls or [])
            _archived_urls = sorted(set(_archived_urls))
            # Fold archived .js URLs into the client-side CVE corpus too.
            if enable_js_cve:
                for _u in _archived_urls:
                    if _looks_like_js(_u):
                        js_cve_corpus.add(_u)
            if _archived_urls:
                _arch_findings = await archived_urls.scan_archived_urls(_archived_urls, output_dir, concurrency)
                if _arch_findings:
                    print(f"{Colors.GREEN}[+] Archived-URL analysis: {len(_arch_findings)} finding(s).{Colors.RESET}")
                    all_findings.extend(_arch_findings)
    else:
        print(f"{Colors.YELLOW}[!] No hostname targets available for gau/waybackurls.{Colors.RESET}")

    # Client-side JS CVE scan (js_cve) over the JS VaktScan already discovered.
    # Default-ON; --no-js-cve opts out; silently no-ops if the Retire.js DB is
    # absent. Reuses the collected corpus - no extra crawl pass.
    if enable_js_cve and js_cve_corpus:
        all_findings.extend(
            await _run_js_cve_over_corpus(js_cve_corpus, output_dir, concurrency)
        )

    await _await_nmap_task()
    return all_findings

def load_subdomains_file(file_path):
    """Load targets from a file, or treat a direct URL/domain/IP string as a single target."""
    if os.path.isfile(file_path):
        entries = parse_targets_file(file_path)
        if not entries:
            print(f"{Colors.YELLOW}[!] File '{file_path}' contained no usable targets after normalization.{Colors.RESET}")
        return entries
    # Not a file path - try to parse as a direct target (URL, domain, or IP)
    import ipaddress as _ipa
    host = normalize_host_value(file_path)
    if host:
        try:
            _ipa.ip_network(host, strict=False)
            return [host]
        except ValueError:
            pass
        if is_valid_domain(host):
            return [host]
    print(f"{Colors.YELLOW}[!] '{file_path}' is not a valid file path or target.{Colors.RESET}")
    return []


def expand_recon_inputs(recon_args):
    """
    Expand --recon arguments which may include literal domains and/or files.
    """
    if not recon_args:
        return []

    expanded = []
    for raw in recon_args:
        if not raw:
            continue
        candidate = raw.strip()
        if not candidate:
            continue

        if os.path.isfile(candidate):
            expanded.extend(parse_targets_file(candidate))
        else:
            expanded.append(candidate.lower())

    return expanded

async def _run_parallel_passive(domain: str, concurrency: int = 20, detailed_dashboard: bool = True) -> tuple:
    """Run DNS recon, cloud enum, and CT monitoring in parallel for a domain.

    Returns (dns_findings, cloud_findings, ct_findings).
    """
    from modules.dashboard import LiveDashboard
    dashboard = LiveDashboard()
    if dashboard.active and detailed_dashboard:
        dashboard.add_task("dns_recon", "DNS Recon")
        dashboard.add_task("cloud_enum", "Cloud Enum")
        dashboard.add_task("ct_monitor", "CT Monitor")

    try:
        dns_f, cloud_f, ct_f = await asyncio.gather(
            dns_recon.run_dns_recon([domain], concurrency=concurrency),
            cloud_enum.enumerate_cloud_assets(domain),
            ct_monitor.check_new_certificates(domain),
            return_exceptions=True,
        )
    finally:
        if dashboard.active and detailed_dashboard:
            loc = locals()
            
            dns_val = loc.get("dns_f")
            dns_count = len(dns_val) if isinstance(dns_val, list) else 0
            dashboard.complete_task("dns_recon", f"Found {dns_count} findings")
            
            cloud_val = loc.get("cloud_f")
            cloud_count = len(cloud_val) if isinstance(cloud_val, list) else 0
            dashboard.complete_task("cloud_enum", f"Found {cloud_count} findings")
            
            ct_val = loc.get("ct_f")
            ct_count = len(ct_val) if isinstance(ct_val, list) else 0
            dashboard.complete_task("ct_monitor", f"Found {ct_count} findings")

    if isinstance(dns_f, Exception):
        _reraise_if_bug(dns_f)
        print(f"[!] DNS recon error: {dns_f}")
        dns_f = []
    if isinstance(cloud_f, Exception):
        _reraise_if_bug(cloud_f)
        print(f"[!] Cloud enum error: {cloud_f}")
        cloud_f = []
    if isinstance(ct_f, Exception):
        _reraise_if_bug(ct_f)
        print(f"[!] CT monitor error: {ct_f}")
        ct_f = []
    return dns_f, cloud_f, ct_f


# Common multi-label public suffixes so apex extraction doesn't stop too early.
_MULTI_LABEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "net.au", "org.au",
    "co.nz", "co.in", "co.za", "com.br", "com.cn", "com.mx", "com.sg", "co.kr",
}


def _registrable_domain(host):
    """Best-effort registrable/apex domain without a Public Suffix List dependency:
    handles common two-label suffixes (co.uk, com.au, …), else the last two labels."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_LABEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# Number of URLs to fully probe before persisting a web-probe checkpoint. Sized
# so ordinary scans (a handful of web URLs) still run as a SINGLE batch -
# byte-for-byte the pre-checkpoint behavior - while large URL sets get periodic
# checkpoints a resume can continue from.
WEB_PROBE_CHECKPOINT_BATCH = 50


async def _probe_web_urls(web_probe_urls, output_dir, domain_label, concurrency,
                          completed_urls=None, record_completed=None, batch_size=None,
                          enable_js_cve=True, record_findings=None):
    """httpx-probe the given URLs, then run nuclei + web_checks + dirsearch + JS
    path extraction on the alive ones. Returns the collected findings (dirsearch
    writes its own reports). Shared by the normal scan and (opt-in) streaming mode.

    Resumable checkpointing (optional): URLs already in ``completed_urls`` are
    skipped, and after each batch of ``batch_size`` URLs is fully probed,
    ``record_completed(batch)`` is invoked so an interrupted web-probe resumes
    from the URLs it had not reached yet. When no checkpoint hooks are supplied
    the whole set is probed as one batch (unchanged behavior).

    ``record_findings`` (optional): when supplied, each batch's findings are
    persisted via this callback *before* the batch's URLs are marked completed,
    and are NOT included in the returned list (the caller must not re-add them).
    Because no ``await`` runs between persisting a batch's findings and marking
    its URLs done, a cancellation (only injected at await points) can never land
    between the two - so a batch's findings and its completed-URL checkpoint are
    written atomically w.r.t. interrupt, preventing the loss of findings whose
    URLs would otherwise be skipped on resume.
    """
    findings = []
    if not web_probe_urls:
        return findings

    if completed_urls:
        completed_set = set(completed_urls)
        remaining = [u for u in web_probe_urls if u not in completed_set]
        skipped = len(web_probe_urls) - len(remaining)
        if skipped:
            print(f"{Colors.GRAY}[*] Resuming web probe - skipping {skipped} "
                  f"already-probed URL(s).{Colors.RESET}")
        web_probe_urls = remaining
        if not web_probe_urls:
            return findings

    # Split into checkpointed batches only when a recorder is supplied and there
    # is more than one batch's worth of work; otherwise probe everything at once.
    if record_completed is not None and batch_size and len(web_probe_urls) > batch_size:
        batches = [web_probe_urls[i:i + batch_size]
                   for i in range(0, len(web_probe_urls), batch_size)]
    else:
        batches = [web_probe_urls]

    for batch in batches:
        batch_findings = await _run_web_probe_batch(
            batch, output_dir, domain_label, concurrency, enable_js_cve=enable_js_cve)
        # Persist this batch's findings BEFORE marking its URLs complete. No
        # await separates these two synchronous steps, so an interrupt (injected
        # only at await points) cannot land between them: the batch's findings
        # and its completed-URL checkpoint are written together w.r.t. cancel.
        # Without this, batch 1's URLs get checkpointed (and skipped on resume)
        # while its findings - buffered for a bulk add after the whole call -
        # are discarded when a later batch is interrupted, losing them forever.
        if record_findings is not None:
            for _f in batch_findings:
                record_findings(_f)
        else:
            findings.extend(batch_findings)
        if record_completed is not None:
            # Mark the batch done only after its full pipeline finished.
            record_completed(batch)
    return findings


async def _run_js_cve_over_corpus(js_cve_corpus, output_dir, concurrency):
    """Run the client-side JS CVE scan (js_cve) over a pre-collected corpus of JS
    URLs and return the findings. Shared by the recon, direct-target, and streaming
    web-probe paths so js_cve fires in ALL of them (not only recon mode).

    No-ops (returns ``[]``) when the corpus is empty or the Retire.js DB is absent,
    and never raises (fail-open) - a js_cve failure must not break the pipeline.
    """
    findings = []
    if not js_cve_corpus or not os.path.exists(js_cve.DB_PATH):
        return findings
    _js_corpus = sorted(js_cve_corpus)
    print(f"{Colors.CYAN}[*] Scanning {len(_js_corpus)} JS artifact(s) for vulnerable "
          f"client-side libraries (js_cve)...{Colors.RESET}")
    from modules.dashboard import LiveDashboard
    dashboard = LiveDashboard()
    if dashboard.active:
        dashboard.add_task("js_cve", "JS CVE Scan")
    try:
        findings = await js_cve.scan_js_cves(
            _js_corpus, output_dir=output_dir, concurrency=concurrency
        )
    except Exception as exc:
        _reraise_if_bug(exc)
        print(f"{Colors.YELLOW}[!] js_cve error: {exc}{Colors.RESET}")
        findings = []
    finally:
        if dashboard.active:
            dashboard.complete_task(
                "js_cve",
                f"Found {len(findings) if isinstance(findings, list) else 0} CVEs",
            )
    if findings:
        print(f"{Colors.GREEN}[+] js_cve: {len(findings)} client-side CVE finding(s).{Colors.RESET}")
    return findings


def _js_cve_corpus_from_web(js_result, alive_urls):
    """Build a js_cve corpus (set of JS URLs) from a js_paths result and the alive
    URLs - the JS VaktScan already discovered, reused with no extra crawl pass."""
    corpus = set()
    if isinstance(js_result, dict):
        for _u in js_result.get('js_urls', []) or []:
            if _u:
                corpus.add(_u)
        for _u in js_result.get('absolute_urls', []) or []:
            if _u and _looks_like_js(_u):
                corpus.add(_u)
    for _u in alive_urls or []:
        if _looks_like_js(_u):
            corpus.add(_u)
    return corpus


async def _run_web_probe_batch(web_probe_urls, output_dir, domain_label, concurrency,
                               enable_js_cve=True):
    """Run the full web-probe pipeline (httpx→nuclei→web_checks→dirsearch→JS→js_cve)
    on one batch of URLs and return the collected findings."""
    findings = []
    if not web_probe_urls:
        return findings
    print(f"{Colors.CYAN}[*] Probing {len(web_probe_urls)} open web port URL(s) with httpx...{Colors.RESET}")
    http_runner = httpx_runner.HTTPXRunner(output_dir=output_dir)
    httpx_data = await http_runner.run_httpx(web_probe_urls, concurrency)
    if not httpx_data:
        print(f"{Colors.YELLOW}[!] No alive web services found on open web ports.{Colors.RESET}")
        return findings
    http_runner.save_csv(httpx_data, domain_label)
    alive_urls = sorted({e.get("url") for e in httpx_data if e.get("url")})
    print(f"{Colors.GREEN}[+] {len(alive_urls)} alive web URL(s) found.{Colors.RESET}")
    if not alive_urls:
        return findings

    nuclei_inst = nuclei_runner.NucleiRunner(output_dir=output_dir)
    nuclei_results = await nuclei_inst.run_nuclei(alive_urls)
    if nuclei_results:
        print(f"{Colors.GREEN}[+] Nuclei: {len(nuclei_results)} finding(s).{Colors.RESET}")
        findings.extend(nuclei_results)

    wc_results = await web_checks.run_checks(alive_urls, concurrency)
    if wc_results:
        print(f"{Colors.GREEN}[+] Web checks: {len(wc_results)} finding(s).{Colors.RESET}")
        findings.extend(wc_results)

    dir_enumerator = dir_enum.DirEnumerator(domain_label, output_dir=output_dir)
    await dir_enumerator.run_dirsearch(alive_urls)

    js_scanner = js_paths.JSPathsScanner(alive_urls, output_dir=output_dir)
    js_result = await js_scanner.run()
    js_findings = js_result.get('findings', []) if isinstance(js_result, dict) else (js_result or [])
    findings.extend(js_findings)

    # Client-side JS CVE scan (js_cve) over the JS this probe just discovered.
    # Previously only ran in recon-domain mode; wiring it here makes it fire in the
    # direct-target (-f targets.txt) and streaming web-probe paths too. Reuses the
    # discovered JS - no extra crawl pass. Default-ON; --no-js-cve opts out.
    if enable_js_cve:
        corpus = _js_cve_corpus_from_web(js_result, alive_urls)
        findings.extend(await _run_js_cve_over_corpus(corpus, output_dir, concurrency))
    return findings


def _web_port_set(base_ports, custom_ports):
    """The set of ports to treat as HTTP(S) for web probing: the configured web
    ports plus any custom ports the user supplied."""
    ports = set(base_ports.get("web", []))
    if custom_ports:
        try:
            ports |= {int(p.strip()) for p in custom_ports.split(',')}
        except ValueError:
            pass
    return ports


async def _enrich_and_report(final_vulnerabilities, run_id, output_dir, sarif_output, output_format=None):
    """Shared finalization tail for BOTH the non-streaming and streaming scan
    paths: NVD → CISA-KEV → EPSS → passive-intel enrichment, inventory delta +
    scan-run close-out, and CSV/JSON/SARIF output. The caller passes an already
    de-duplicated list. Returns the enriched findings.

    Extracted so streaming mode (>1000 targets) gets the same enrichment and
    outputs as a normal scan instead of silently dropping them.
    """
    # ── Web-layer version->CVE (modules/web_tech_cve) ──────────────────────────
    # Turn the concrete versions VaktScan already detected at the WEB layer into
    # NVD CVE findings so they reach KEV/EPSS/CVSS enrichment like js_cve does.
    # Two paths, both reusing already-fetched data (NO new HTTP requests):
    #   1. DEFAULT-ON: the Server / X-Powered-By header versions web_checks
    #      surfaced (its "…Header Discloses…" findings carry the raw header in
    #      service_version).
    #   2. --tech: the webanalyze product/version pairs tech_fingerprint detected
    #      (its "Technology Detected: <name> <version>" INFO findings).
    # Emitted BEFORE the KEV/EPSS/passive gather so these CVEs get enriched too.
    # Deduped against CVEs already reported by nuclei/nmap/service_recon/js_cve.
    try:
        _wt_existing_keys = web_tech_cve.collect_existing_cve_keys(final_vulnerabilities)
        _wt_headers, _wt_tech = [], []
        for _f in final_vulnerabilities:
            _mod = _f.get("module", "")
            _vuln = _f.get("vulnerability", "") or ""
            _sv = _f.get("service_version", "") or ""
            _ctx = {
                "target":      _f.get("target", "N/A"),
                "resolved_ip": _f.get("resolved_ip", "N/A"),
                "port":        str(_f.get("port", "N/A")),
                "url":         _f.get("url", "N/A"),
            }
            if (_mod == "WebChecks" and _sv not in ("", "N/A", "Unknown")
                    and ("Server Header Discloses Version" in _vuln
                         or "X-Powered-By Header Discloses" in _vuln)):
                _wt_headers.append({**_ctx, "header": _sv})
            elif (_mod == tech_fingerprint.MODULE_NAME
                    and _vuln.startswith("Technology Detected:")):
                _label = _vuln[len("Technology Detected:"):].strip()
                _name = _label
                if _sv not in ("", "N/A") and _label.endswith(_sv):
                    _name = _label[:-len(_sv)].strip()
                _wt_tech.append({**_ctx, "name": _name, "version": _sv})

        _wt_header_cves, _wt_tech_cves = await asyncio.gather(
            web_tech_cve.cves_from_headers(_wt_headers, existing_cve_keys=_wt_existing_keys),
            web_tech_cve.cves_from_tech_detections(_wt_tech, existing_cve_keys=_wt_existing_keys),
        )
        _wt_cves = _wt_header_cves + _wt_tech_cves
        # De-dup the two paths against each other by (target, CVE id).
        _wt_added = 0
        for _wf in _wt_cves:
            _cid = ""
            _cm = web_tech_cve.CVE_RE.search(_wf.get("vulnerability", "") or "")
            if _cm:
                _cid = _cm.group(0).upper()
            _k = (_wf.get("target", "N/A"), _cid)
            if _cid and _k not in _wt_existing_keys:
                _wt_existing_keys.add(_k)
                final_vulnerabilities.append(_wf)
                _wt_added += 1
        if _wt_added:
            print(f"{Colors.CYAN}[*] Web-tech version->CVE added {_wt_added} "
                  f"version-inferred CVE finding(s).{Colors.RESET}")
    except Exception as _wt_exc:
        _reraise_if_bug(_wt_exc)
        print(f"{Colors.YELLOW}[!] Web-tech CVE mapping skipped: {_wt_exc}{Colors.RESET}")

    # NVD CVE lookups for unique (product, version) pairs.
    _nvd_seen_versions = set()
    _nvd_tasks = []
    for _f in final_vulnerabilities:
        _prod, _ver = nvd.extract_product_and_version(_f)
        if _prod and _ver and (_prod, _ver) not in _nvd_seen_versions:
            _nvd_seen_versions.add((_prod, _ver))
            _nvd_tasks.append(nvd.lookup_cves(
                product=_prod, version=_ver,
                target=_f.get("target", "N/A"),
                resolved_ip=_f.get("resolved_ip", "N/A"),
                port=_f.get("port", "N/A"),
            ))

    kev_result, epss_result, passive_result, *nvd_results_list = await asyncio.gather(
        cisa_kev.enrich_findings_with_kev(final_vulnerabilities),
        epss.enrich_findings_with_epss(final_vulnerabilities),
        passive_intel.enrich_findings_with_passive_intel(final_vulnerabilities),
        *_nvd_tasks,
    )
    # kev/epss enrich in-place on the shared list; kev_result is the base.
    final_vulnerabilities = kev_result
    _existing_urls = {f.get("url") for f in final_vulnerabilities}
    for _f in passive_result:
        if _f.get("url") not in _existing_urls:
            final_vulnerabilities.append(_f)
            _existing_urls.add(_f.get("url"))
    # Seed the banner-NVD dedup with CVEs ALREADY present (js_cve, nuclei, nmap,
    # and the web_tech_cve version-inferred findings added above) so the banner
    # path never re-adds a duplicate of a CVE already reported for the same
    # host:port - notably the nginx/apache/iis header versions web_tech_cve now
    # owns as conservative POTENTIAL findings.
    _seen_cve_keys = set()
    for _f in final_vulnerabilities:
        _cm = web_tech_cve.CVE_RE.search(_f.get("vulnerability", "") or "")
        if _cm:
            _seen_cve_keys.add(
                (_f.get("target", "N/A"), str(_f.get("port", "N/A")), _cm.group(0).upper())
            )
    _added_cve_count = 0
    for _batch in nvd_results_list:
        for _f in _batch:
            _cve_id = _f.get("vulnerability", "").split(" - ")[0].strip()
            _key = (_f.get("target", "N/A"), str(_f.get("port", "N/A")), _cve_id.upper())
            if _cve_id and _key not in _seen_cve_keys:
                _seen_cve_keys.add(_key)
                final_vulnerabilities.append(_f)
                _added_cve_count += 1
    print(f"{Colors.CYAN}[*] CISA KEV cross-reference complete.{Colors.RESET}")
    if _added_cve_count:
        print(f"{Colors.CYAN}[*] NVD enrichment added {_added_cve_count} CVE finding(s).{Colors.RESET}")

    # Inventory delta + scan-run close-out.
    if run_id is not None:
        delta = inventory.save_findings(run_id, final_vulnerabilities)
        inventory.complete_scan_run(run_id, len(final_vulnerabilities))
        inventory.print_delta_report(delta)
        inventory.print_executive_summary(run_id, len(final_vulnerabilities))
        # Alert on NEW findings (Slack/Discord/webhook/email). No-ops silently
        # when no *_WEBHOOK_URL / SMTP env vars are configured.
        try:
            _new = list(delta.get("new", [])) if isinstance(delta, dict) else []
            if _new:
                await notify.send_alerts(_new, {}, scan_label=str(output_dir or ""))
        except Exception as _exc:
            print(f"{Colors.YELLOW}[!] Alert delivery skipped: {_exc}{Colors.RESET}")

    fmt = (output_format or "").lower()
    _ts = time.strftime('%Y%m%d_%H%M%S')

    # CSV + HTML are ALWAYS written (the default human-readable reports), even at
    # 0 findings for a clean report. JSON/SARIF are opt-in via --format / --sarif.
    csv_file = save_results_to_csv(
        final_vulnerabilities,
        filename=os.path.join(output_dir, f"scan_results_{_ts}.csv") if output_dir else None,
    )
    if csv_file:
        print(f"{Colors.GREEN}[+] CSV report generated: {csv_file}{Colors.RESET}")

    html_path = os.path.join(output_dir, f"scan_results_{_ts}.html") if output_dir else None
    save_results_to_html(final_vulnerabilities, filename=html_path,
                         scan_label=os.path.basename(output_dir) if output_dir else None)

    if fmt in ("json", "all"):
        json_path = os.path.join(output_dir, f"scan_results_{_ts}.json") if output_dir else None
        save_results_to_json(final_vulnerabilities, filename=json_path)

    if sarif_output:
        write_sarif_output(final_vulnerabilities, sarif_output)
    elif fmt in ("sarif", "all"):
        sarif_path = os.path.join(output_dir, f"scan_results_{_ts}.sarif") if output_dir else f"scan_results_{_ts}.sarif"
        write_sarif_output(final_vulnerabilities, sarif_path)

    return final_vulnerabilities


def _decide_resume(state_manager, resume_mode="auto"):
    """Decide whether this run resumes persisted state, per the Phase-5 UX.

    ``resume_mode`` is one of:

    * ``"auto"`` (default) - recompute the scan id and resume IF a matching,
      non-completed state exists; a finished scan is reset to a clean start.
    * ``"fresh"`` (``--fresh`` / ``--no-resume``) - ignore & overwrite any
      existing state; never load.
    * ``"require"`` (``--resume``) - a resumable state MUST exist; error out
      (``SystemExit``) if none is found.
    * ``"id"`` (``--resume-id``) - like ``require`` but the id was forced; a
      stored targets/scope mismatch is refused (point the user at ``--fresh``).

    ``load_existing_state()`` restores saved progress (phase, open ports,
    findings) as a side effect, so it MUST run for every resuming mode.
    """
    if resume_mode == "fresh":
        # Overwrite: don't load anything; the default state is already clean.
        state_manager.reset_to_fresh()
        return False

    strict = (resume_mode == "id")
    loaded = state_manager.load_existing_state(strict=strict)

    if resume_mode == "auto":
        if loaded and state_manager.state.get("completed"):
            # A completed scan is not resumable - start fresh instead.
            print(f"{Colors.CYAN}[*] Matching scan already completed; starting fresh.{Colors.RESET}")
            state_manager.reset_to_fresh()
            return False
        if loaded:
            print(f"{Colors.CYAN}[*] Found resumable state '{state_manager.scan_id}' "
                  f"(phase: {state_manager.state.get('phase')}); auto-resuming. "
                  f"Use --fresh to start over.{Colors.RESET}")
        return loaded

    # require / id: a resumable state is mandatory.
    if not loaded:
        if strict and getattr(state_manager, "identity_mismatch", False):
            print(f"{Colors.RED}[!] --resume-id '{state_manager.scan_id}': the stored scan's "
                  f"targets/scope differ from this command. Refusing to resume a scope "
                  f"mismatch.{Colors.RESET}")
            print(f"{Colors.YELLOW}    Re-run with the original target/flags, or use --fresh "
                  f"to start a new scan.{Colors.RESET}")
        else:
            which = "--resume-id" if strict else "--resume"
            print(f"{Colors.RED}[!] {which}: no resumable state found for this scan.{Colors.RESET}")
            print(f"{Colors.YELLOW}    Use 'scan --list-resumable' to see resumable scans, "
                  f"or omit {which} to start fresh.{Colors.RESET}")
        sys.exit(1)
    return loaded


async def main(
    targets_file,
    concurrency,
    resume=False,
    fresh=False,
    resume_id=None,
    primary_target=None,
    non_scope_config=None,
    module_filter=None,
    custom_ports=None,
    chunk_size=30000,
    recon_domains=None,
    wordlist=None,
    scan_found=False,
    nmap_enabled=False,
    subdomains_file=None,
    module_mode=None,
    domain_scan_file=None,
    domain_scan_concurrency=50,
    recon_concurrency=2,
    connect_timeout=DEFAULT_CONNECT_TIMEOUT,
    port_retries=DEFAULT_PORT_RETRIES,
    js_url=None,
    js_timeout=10,
    sarif_output=None,
    no_dork=False,
    dork_method='auto',
    stream_web_probe=False,
    archived_scan=True,
    enable_screenshots=False,
    enable_horizontal=False,
    extra_scans=frozenset(),
    js_cve_scan=True,
    output_format=None,
    dns_hygiene=True,
    dns_permute=False,
    dns_takeover=True,
    exclude_patterns=None,
    include_only_patterns=None,
    company_only=False,
    shared_ip_threshold=10,
    scan_id=None,
    canonical_targets=None,
    scope=None,
):
    """
    Main orchestrator for the scanning tool.
    """
    # Predicate: host -> True when it must be EXCLUDED from scanning (still listed
    # in the enumerated subdomain output, just never scanned).
    _is_excluded = build_exclusion_matcher(exclude_patterns)
    # Predicate: host -> True when it matches an --include-only allowlist pattern.
    _include_only = build_exclusion_matcher(include_only_patterns) if include_only_patterns else None
    # Signal handling is installed by run_command() in __main__ (single top-level
    # runner that cancels the main task on the first Ctrl+C and force-quits on the
    # second). The old per-scan add_signal_handler that raised KeyboardInterrupt
    # inside a loop callback did not propagate into awaiting coroutines.

    print_logo()
    
    # Auto-sync Nuclei templates on scan start
    try:
        nuclei_runner.sync_nuclei_templates(force=False)
    except Exception as e:
        print(f"[*] Warning: nuclei auto-sync check failed: {e}")

    # Store recon results to pass to scanner if needed
    nuclei_vulns_found = False
    recon_targets_file = None
    recon_targets_count = 0
    # Recon findings are persisted straight into state_manager.add_vulnerability
    # (force-saves) as they are discovered - state_manager is now built BEFORE
    # the recon block (Phase 6), so an interrupt mid-recon still checkpoints.
    # Set once the recon phase has already run the full web pipeline
    # (httpx→dirsearch→nuclei→web_checks→js→nmap) via run_recon_followups, so the
    # main scan can skip re-probing the identical hosts (avoids ~2x work).
    recon_web_probed = False
    # Registrable domains whose cloud assets were already enumerated during passive
    # recon, so the main scan's phase 3b can reuse that instead of re-enumerating.
    cloud_enumerated_domains = set()

    # --- DNS RECON MODE (-m dns) ---
    if module_mode == 'dns':
        dns_targets = []
        if domain_scan_file:
            dns_targets.extend(load_subdomains_file(domain_scan_file))
        if recon_domains:
            dns_targets.extend(expand_recon_inputs(recon_domains))
        # Also accept a plain targets file with one domain per line.
        if targets_file and os.path.isfile(targets_file):
            dns_targets.extend(parse_targets_file(targets_file))
        dns_targets = list(dict.fromkeys(dns_targets))
        if not dns_targets:
            print(
                f"{Colors.RED}[!] -m dns requires at least one domain.\n"
                f"    Provide via --sub-domains <file>, --recon-domain <DOMAIN ...>, "
                f"or a targets file with one domain per line.{Colors.RESET}"
            )
            sys.exit(1)
        print(f"{Colors.CYAN}[*] Starting DNS recon on {len(dns_targets)} domain(s)...{Colors.RESET}")
        findings = await dns_recon.run_dns_recon(dns_targets, concurrency=concurrency)
        if findings:
            for f in findings:
                status_color = {
                    'CRITICAL':   Colors.RED + Colors.BOLD,
                    'VULNERABLE': Colors.BRIGHT_RED,
                    'POTENTIAL':  Colors.YELLOW,
                    'INFO':       Colors.BLUE,
                }.get(f.get('status', 'INFO'), Colors.WHITE)
                print(f"{status_color}[{f['status']}]{Colors.RESET} {f['vulnerability']} on {Colors.UNDERLINE}{f['target']}{Colors.RESET}")
                print(f"    {Colors.GRAY}{f['details']}{Colors.RESET}")
            csv_file = save_results_to_csv(findings)
            if csv_file:
                print(f"{Colors.GREEN}[+] CSV report generated: {csv_file}{Colors.RESET}")
            save_results_to_json(findings)
        else:
            print(f"{Colors.GREEN}[*] DNS recon completed; no findings.{Colors.RESET}")
        return

    # --- CLOUD ENUM MODE (-m cloud) ---
    if module_mode == 'cloud':
        cloud_targets = []
        if domain_scan_file:
            cloud_targets.extend(load_subdomains_file(domain_scan_file))
        if recon_domains:
            cloud_targets.extend(expand_recon_inputs(recon_domains))
        if targets_file and os.path.isfile(targets_file):
            try:
                cloud_targets.extend(parse_targets_file(targets_file))
            except Exception:
                pass
        # Deduplicate, preserving order; skip raw IPs
        seen_cloud: set[str] = set()
        deduped_cloud: list[str] = []
        for t in cloud_targets:
            if t in seen_cloud:
                continue
            seen_cloud.add(t)
            try:
                import ipaddress as _ipa
                _ipa.ip_network(t, strict=False)
                # It's an IP/CIDR - skip for cloud enum
                continue
            except ValueError:
                pass
            deduped_cloud.append(t)
        if not deduped_cloud:
            print(
                f"{Colors.RED}[!] -m cloud requires at least one domain target.\n"
                f"    Provide via --recon-domain <DOMAIN ...>, --ds-file <file>, "
                f"or a targets file with one domain per line.{Colors.RESET}"
            )
            sys.exit(1)
        print(
            f"{Colors.CYAN}[*] Starting cloud asset enumeration on "
            f"{len(deduped_cloud)} domain(s) "
            f"(AWS S3, Azure Blob, GCP GCS)...{Colors.RESET}"
        )
        all_cloud_findings: list = []
        for domain_target in deduped_cloud:
            print(f"{Colors.GRAY}[*]   Enumerating cloud assets for: {domain_target}{Colors.RESET}")
            domain_findings = await cloud_enum.enumerate_cloud_assets(
                domain_target, concurrency=concurrency
            )
            all_cloud_findings.extend(domain_findings)
        if all_cloud_findings:
            for f in all_cloud_findings:
                sev_color = {
                    'CRITICAL':   Colors.RED + Colors.BOLD,
                    'HIGH':       Colors.BRIGHT_RED,
                    'INFO':       Colors.BLUE,
                }.get(f.get('severity', 'INFO'), Colors.WHITE)
                print(
                    f"{sev_color}[{f['severity']}]{Colors.RESET} "
                    f"{f['vulnerability']} - {Colors.UNDERLINE}{f['url']}{Colors.RESET}"
                )
                print(f"    {Colors.GRAY}{f['details']}{Colors.RESET}")
            csv_file = save_results_to_csv(all_cloud_findings)
            if csv_file:
                print(f"{Colors.GREEN}[+] CSV report generated: {csv_file}{Colors.RESET}")
            save_results_to_json(all_cloud_findings)
        else:
            print(f"{Colors.GREEN}[*] Cloud enumeration completed; no exposed assets found.{Colors.RESET}")
        return

    # --- JS PATHS MODE (-m js-paths) ---
    if module_mode == 'js-paths':
        js_targets = []
        if js_url:
            js_targets.append(js_url)
        if domain_scan_file:
            js_targets.extend(load_subdomains_file(domain_scan_file))
        if not js_targets:
            print(
                f"{Colors.RED}[!] -m js-paths requires at least one target URL.\n"
                f"    Use --url <URL> for a single target or --ds-file <file> "
                f"for a list of URLs.{Colors.RESET}"
            )
            sys.exit(1)

        js_targets = list(dict.fromkeys(js_targets))  # deduplicate, preserve order
        timestamp  = time.strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join("reports", f"js_paths_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)

        print(
            f"{Colors.CYAN}[*] Starting JS Paths Module on "
            f"{len(js_targets)} target(s)...{Colors.RESET}"
        )

        scanner = js_paths.JSPathsScanner(
            target_urls=js_targets,
            threads=concurrency,
            timeout=js_timeout,
        )
        result   = await scanner.run()
        findings      = result.get("findings", [])
        paths         = result.get("paths", [])
        hosts         = result.get("hosts", [])
        absolute_urls = result.get("absolute_urls", [])
        js_urls       = result.get("js_urls", [])
        probe_results = result.get("probe_results", [])

        # ── Save raw recon data ──
        def _write_lines(name, items):
            fpath = os.path.join(output_dir, name)
            with open(fpath, "w", encoding="utf-8") as fh:
                fh.write("\n".join(items) + "\n")
            print(f"{Colors.GRAY}[*] Saved {len(items):,} entries → {fpath}{Colors.RESET}")

        if paths:
            _write_lines(f"extracted_paths_{timestamp}.txt", paths)
        if hosts:
            _write_lines(f"discovered_hosts_{timestamp}.txt", hosts)
        if absolute_urls:
            _write_lines(f"extracted_urls_{timestamp}.txt", absolute_urls)
        if js_urls:
            _write_lines(f"js_files_{timestamp}.txt", js_urls)

        # ── Save all probe results to CSV ──
        if probe_results:
            probe_csv = os.path.join(output_dir, f"probe_results_{timestamp}.csv")
            fieldnames = ["Hostname", "URL", "Path", "Status Code", "Server Header"]
            try:
                with open(probe_csv, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.DictWriter(fh, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(probe_results)
                print(
                    f"{Colors.GREEN}[+] {len(probe_results):,} probe hit(s) saved → "
                    f"{Colors.BOLD}{probe_csv}{Colors.RESET}"
                )
            except IOError as exc:
                print(f"{Colors.RED}[!] Failed to write probe CSV: {exc}{Colors.RESET}")

        # ── Print & save vulnerability findings ──
        print(f"{Colors.BRIGHT_CYAN}\n" + "="*50 + f"{Colors.RESET}")
        print(f"{Colors.BRIGHT_YELLOW}{Colors.BOLD}      JS Paths Scan Results{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}" + "="*50 + f"\n{Colors.RESET}")

        if findings:
            for f in findings:
                sev_color = (
                    Colors.BRIGHT_RED   if f['status'] == 'VULNERABLE' else
                    Colors.RED + Colors.BOLD if f['status'] == 'CRITICAL'  else
                    Colors.YELLOW       if f['status'] == 'POTENTIAL'  else
                    Colors.BLUE
                )
                print(
                    f"{sev_color}[!] {f['status']}{Colors.RESET}: "
                    f"{Colors.BOLD}{f['vulnerability']}{Colors.RESET} "
                    f"→ {Colors.UNDERLINE}{f['url']}{Colors.RESET}"
                )
                print(f"    {Colors.GRAY}Details: {f['details']}{Colors.RESET}\n")
            csv_file = save_results_to_csv(
                findings,
                filename=os.path.join(
                    output_dir,
                    f"js_paths_findings_{timestamp}.csv"
                )
            )
            if csv_file:
                print(f"{Colors.GREEN}[+] Findings saved → {Colors.BOLD}{csv_file}{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}[*] No vulnerability findings.{Colors.RESET}")

        print(
            f"\n{Colors.BRIGHT_GREEN}[*] JS Paths scan finished. "
            f"Output directory: {Colors.BOLD}{output_dir}{Colors.RESET}"
        )
        return

    # --- TECH-ONLY MODE (scan --tech-only) ---
    # Lightweight web-technology fingerprint + version->CVE only. Minimal pipeline:
    # resolve/expand targets -> web-port scan -> httpx alive-probe ->
    # tech_fingerprint.fingerprint_tech, then route the resulting "Technology
    # Detected" findings through _enrich_and_report so the web_tech_cve header +
    # tech CVE paths, NVD/KEV/EPSS/CVSS enrichment, and CSV/HTML/JSON/SARIF
    # reporting all fire (run_id=None -> inventory persistence is skipped).
    # Deliberately SKIPS subdomain enum, passive/DNS/cloud/CT recon, nuclei,
    # dirsearch, web_checks, js_paths, js_cve, domain_scan, archived_urls, the
    # service-scan modules, and nmap. tech-only never enumerates subdomains, so
    # --no-subdomain-enum is honored implicitly. Supports domain / IP / CIDR / file.
    if module_mode == 'tech-only':
        target_input = domain_scan_file or subdomains_file
        if not target_input:
            print(f"{Colors.RED}[!] Error: --tech-only requires a target "
                  f"(domain, IP, CIDR) or a --sub-domains <file>.{Colors.RESET}")
            sys.exit(1)

        raw_targets = load_subdomains_file(target_input)
        if not raw_targets:
            return
        unique_targets = sorted(set(raw_targets))

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join("reports", f"tech_only_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)

        print(f"{Colors.CYAN}[*] Starting tech-only scan "
              f"(web-tech fingerprint + version->CVE) on {len(unique_targets)} target(s)...{Colors.RESET}")

        # 1. Expand + resolve targets (handles domain / IP / CIDR / file). CIDRs
        # expand to individual hosts and domains resolve to IPs here.
        scan_targets = await process_targets(unique_targets)
        ip_to_hosts = {}
        for _t in scan_targets:
            _ip = _t.get("resolved_ip")
            _host = _t.get("display_target")
            if _ip and _host and _host != _ip:
                ip_to_hosts.setdefault(_ip, []).append(_host)
        for _hosts in ip_to_hosts.values():
            _hosts.sort()

        # 2. Web-port scan (configured web ports + any --ports). No nmap.
        web_ports = sorted(_web_port_set(get_service_ports(), custom_ports))
        port_scan_results = []
        if scan_targets:
            print(f"{Colors.CYAN}[*] tech-only: web-port scan on {len(scan_targets)} "
                  f"target(s) over ports {web_ports}...{Colors.RESET}")
            port_scan_results = await scan_ports(
                scan_targets,
                web_ports,
                concurrency,
                state_manager=None,
                connect_timeout=connect_timeout,
                retries=port_retries,
            )

        # 3. HTTP alive-probe (httpx only - NO nuclei / web_checks / dirsearch / js).
        http_runner = httpx_runner.HTTPXRunner(output_dir=output_dir)
        probe_urls = build_recon_probe_urls(unique_targets, port_scan_results, ip_to_hosts)
        print(f"{Colors.CYAN}[*] tech-only: probing {len(probe_urls)} web URL(s) with httpx...{Colors.RESET}")
        httpx_data = await http_runner.run_httpx(probe_urls, domain_scan_concurrency)
        if httpx_data:
            http_runner.save_csv(httpx_data, "tech_only")
        alive_urls = sorted({e.get("url") for e in httpx_data if e.get("url")})
        print(f"{Colors.GREEN}[+] tech-only: {len(alive_urls)} alive web URL(s) found.{Colors.RESET}")

        # 4. Web-technology fingerprint (webanalyze) -> "Technology Detected" findings.
        tech_findings = []
        if alive_urls:
            tech_findings = await tech_fingerprint.fingerprint_tech(
                alive_urls, output_dir, concurrency
            )
            if tech_findings:
                print(f"{Colors.GREEN}[+] tech-only: {len(tech_findings)} technology "
                      f"finding(s).{Colors.RESET}")

        # 5. web_tech_cve (header + tech CVE paths) + NVD/KEV/EPSS/CVSS enrichment,
        # and CSV/HTML (always) + JSON/SARIF (per --format / --sarif). run_id=None
        # skips inventory persistence (tech-only is an ad-hoc lightweight triage).
        await _enrich_and_report(
            tech_findings, None, output_dir, sarif_output, output_format=output_format,
        )

        print(f"{Colors.BRIGHT_GREEN}[*] tech-only scan finished. "
              f"Output directory: {Colors.BOLD}{output_dir}{Colors.RESET}")
        return

    # --- DOMAIN SCAN MODE ---
    if module_mode == 'domain-scan':
        target_file = domain_scan_file or subdomains_file
        if not target_file:
            print(f"{Colors.RED}[!] Error: --posture requires a target domain or a --sub-domains <file>.{Colors.RESET}")
            sys.exit(1)
        
        print(f"{Colors.CYAN}[*] Starting Domain Scanner Module...{Colors.RESET}")
        domains = load_subdomains_file(target_file)
        if not domains:
            return

        unique_domains = sorted(set(domains))
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join("reports", f"domain_scan_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        
        # 1. Resolve and Port Scan
        host_to_ip, ip_to_hosts, unresolved_hosts = await resolve_hostnames(unique_domains)
        scan_targets = build_scan_targets_from_mappings(unique_domains, host_to_ip)
        
        print(f"{Colors.CYAN}[*] Running preliminary web-port scan on {len(unique_domains)} domains...{Colors.RESET}")
        web_ports = get_service_ports().get("web", [80, 443])
        port_scan_results = []
        if scan_targets:
            port_scan_results = await scan_ports(
                scan_targets,
                web_ports,
                concurrency,
                state_manager=None,
                connect_timeout=connect_timeout,
                retries=port_retries
            )
        
        # 2. HTTP Alive Probes
        http_runner = httpx_runner.HTTPXRunner(output_dir=output_dir)
        # build_recon_probe_urls automatically tests 80/443 for all, plus only the discovered open ports
        probe_urls = build_recon_probe_urls(unique_domains, port_scan_results, ip_to_hosts)
        print(f"{Colors.CYAN}[*] Probing {len(probe_urls)} active web URLs with httpx...{Colors.RESET}")
        httpx_data = await http_runner.run_httpx(probe_urls, domain_scan_concurrency)
        
        if httpx_data:
            http_runner.save_csv(httpx_data, "domain_scan")
        
        alive_urls = [entry.get('url') for entry in httpx_data if entry.get('url')]
        
        # 2. Main Scan (Classification, Anomalies, Broken Components)
        scanner = domain_scan.DomainScanner(output_dir=output_dir)
        findings = await scanner.run(
            domains=unique_domains,
            httpx_data=httpx_data,
            alive_urls=alive_urls,
            concurrency=domain_scan_concurrency
        )
        
        # CSV + HTML reports are always written (consistent with the full scan).
        _ds_ts = time.strftime('%Y%m%d_%H%M%S')
        save_results_to_csv(findings, filename=os.path.join(output_dir, f"domain_scan_vulns_{_ds_ts}.csv"))
        save_results_to_html(findings, filename=os.path.join(output_dir, f"domain_scan_{_ds_ts}.html"),
                             scan_label="domain-posture")

        print(f"{Colors.GREEN}[+] Domain-posture scan completed.{Colors.RESET}")
        return

    # --- STANDALONE --sub-domains MODE (no -m recon needed) ---
    if subdomains_file and not recon_domains:
        print(f"{Colors.CYAN}[*] Running in standalone --sub-domains mode (no recon label)...{Colors.RESET}")
        subdomains = load_subdomains_file(subdomains_file)
        unique_subdomains = sorted(set(subdomains))
        if not unique_subdomains:
            print(f"{Colors.RED}[!] No usable subdomains found in '{subdomains_file}'.{Colors.RESET}")
            return
        safe_label = os.path.splitext(os.path.basename(subdomains_file))[0]
        safe_label = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in safe_label.lower())
        domain_output_dir = os.path.join("reports", safe_label or "subdomains")
        os.makedirs(domain_output_dir, exist_ok=True)
        dedup_file = os.path.join(domain_output_dir, f"manual_subdomains_{time.strftime('%Y%m%d_%H%M%S')}.txt")
        try:
            with open(dedup_file, "w", encoding="utf-8") as handle:
                for host in unique_subdomains:
                    handle.write(f"{host}\n")
        except OSError as exc:
            print(f"{Colors.RED}[!] Failed to write normalized subdomain file: {exc}{Colors.RESET}")
            return
        print(f"{Colors.GRAY}[*] {len(unique_subdomains)} subdomains loaded. Starting HTTP probing...{Colors.RESET}")
        recon_findings = await run_recon_followups(
            unique_subdomains,
            safe_label,         # used as the output label
            domain_output_dir,
            concurrency,
            nmap_enabled,
            wordlist,
            connect_timeout,
            port_retries,
            enable_archived=archived_scan,
            enable_screenshots=enable_screenshots,
            extra_scans=extra_scans,
            enable_js_cve=js_cve_scan,
        )
        if recon_findings:
            print(f"{Colors.GREEN}[+] Recon pipeline: {len(recon_findings)} total finding(s) from {safe_label}{Colors.RESET}")
            # This branch returns without building a state_manager, so persist
            # findings directly to CSV (mirrors cmd_probe / domain-scan mode).
            csv_file = save_results_to_csv(
                recon_findings,
                filename=os.path.join(domain_output_dir, f"recon_findings_{time.strftime('%Y%m%d_%H%M%S')}.csv"),
            )
            if csv_file:
                print(f"{Colors.GREEN}[+] CSV report generated: {csv_file}{Colors.RESET}")
        return

    # ------------------------------------------------------------------
    # Durable state manager - constructed EARLY (Phase 6), before the
    # reconnaissance block, so recon findings persist as they are discovered
    # (add_vulnerability force-saves) and an interrupt mid-recon still leaves a
    # resumable checkpoint. The old design built state_manager only after recon,
    # buffering findings in a volatile list that Ctrl+C during enumeration lost.
    #
    # cmd_scan precomputes scan_id / canonical_targets / scope from the ORIGINAL
    # target + scope config (independent of the recon-derived temp targets file),
    # so resume works for every target type; fall back to deriving them from
    # targets_file for any direct main() caller that does not supply them.
    if scan_id is None:
        from state_key import (
            canonical_targets as _ct,
            scope_signature as _ss,
            compute_scan_id as _cid,
        )
        try:
            canonical_targets = _ct('file', targets_file, parse_targets_file)
        except Exception:
            # A malformed/unreadable targets file must not abort scan_id
            # derivation; degrade to a path-based identity (still deterministic).
            canonical_targets = [os.path.abspath(targets_file)] if targets_file else ["recon"]
        scope = _ss({
            "module_filter": module_filter,
            "ports": custom_ports,
            "no_subdomain_enum": recon_domains is None,
            "dns_permute": dns_permute,
            "dns_hygiene": dns_hygiene,
            "dns_takeover": dns_takeover,
            "company_only": company_only,
            "shared_ip_threshold": shared_ip_threshold,
            "horizontal": enable_horizontal,
            "archived_scan": archived_scan,
            "stream_web_probe": stream_web_probe,
            "extra_scans": list(extra_scans) if extra_scans else [],
            "nmap": nmap_enabled,
            "no_dork": no_dork,
            "exclude": exclude_patterns,
            "include_only": include_only_patterns,
        })
        _id_label = (os.path.splitext(os.path.basename(targets_file))[0] if targets_file
                     else (recon_domains[0] if recon_domains else "recon"))
        scan_id = _cid(_id_label, canonical_targets, scope)

    # Phase-5 resume UX. A forced --resume-id overrides the target-derived id so
    # a specific saved scan can be resumed; the load stays strict (a stored
    # targets/scope mismatch is refused rather than silently forked).
    if resume_id:
        scan_id = resume_id
    if fresh:
        resume_mode = "fresh"
    elif resume_id:
        resume_mode = "id"
    elif resume:
        resume_mode = "require"
    else:
        resume_mode = "auto"

    # Non-scope settings ride along in the state so a change on resume can warn
    # and adopt the new value (never changes the scan identity).
    if non_scope_config is None:
        non_scope_config = {
            "concurrency": concurrency,
            "connect_timeout": connect_timeout,
            "port_retries": port_retries,
            "recon_concurrency": recon_concurrency,
            "chunk_size": chunk_size,
            "js_timeout": js_timeout,
        }
    if primary_target is None:
        primary_target = (canonical_targets[0] if canonical_targets
                          else os.path.splitext(os.path.basename(targets_file or "recon"))[0])
    state_manager = ScanStateManager(scan_id, canonical_targets, scope,
                                     non_scope_config=non_scope_config,
                                     primary_target=primary_target)

    # Load persisted state (or reset for --fresh) BEFORE recon runs, so recon
    # findings/phase writes build on the resumed state instead of being clobbered
    # by a later load - and a genuinely fresh run does not mistake its own
    # in-progress recon writes for a resumable scan.
    is_resume = _decide_resume(state_manager, resume_mode)
    if is_resume:
        print(f"{Colors.CYAN}[*] Resuming VaktScan...{Colors.RESET}")
    else:
        print(f"{Colors.CYAN}[*] Starting VaktScan - Nordic Security Scanner...{Colors.RESET}")

    # --- RECONNAISSANCE MODE (-m recon or --sub-domains WITH a recon domain) ---
    recon_targets_label = None
    if recon_domains:
        # Recon is its own resumable phase now (state_manager already exists).
        # Advance to "recon" only from a clean start so a resume that is already
        # past recon is never regressed to an earlier phase.
        if state_manager.state.get("phase") == "initializing":
            state_manager.update_phase("recon")

        def _persist_orphan_recon_findings():
            """On an early return (e.g. no subdomains discovered), also drop the
            recon findings - already persisted in state_manager - into a CSV so
            takeovers/exposed buckets/CT alerts remain visible even though the
            main scan never runs. Findings live in state now (add_vulnerability
            force-saves), so this reads them from there rather than a buffer."""
            _found = state_manager.get_vulnerabilities()
            if not _found:
                return
            passive_dir = os.path.join("reports", "passive_recon")
            os.makedirs(passive_dir, exist_ok=True)
            csv_file = save_results_to_csv(
                list(_found),
                filename=os.path.join(passive_dir, f"passive_findings_{time.strftime('%Y%m%d_%H%M%S')}.csv"),
            )
            if csv_file:
                print(f"{Colors.GREEN}[+] Passive recon findings saved: {csv_file}{Colors.RESET}")

        normalized_domains = []
        seen_domains = set()
        for domain in expand_recon_inputs(recon_domains):
            domain = domain.strip().lower()
            if not domain:
                continue
            if not is_valid_domain(domain):
                continue
            if domain in seen_domains:
                continue
            seen_domains.add(domain)
            normalized_domains.append(domain)

        if not normalized_domains:
            print(f"{Colors.RED}[!] No valid recon domains supplied.{Colors.RESET}")
            return

        if subdomains_file:
            if len(recon_domains) != 1:
                print(f"{Colors.RED}[!] Error: --sub-domains currently supports exactly one -m recon domain.{Colors.RESET}")
                sys.exit(1)
            recon_domain = normalized_domains[0]
            print(f"{Colors.CYAN}[*] Starting Reconnaissance Mode for: {Colors.BOLD}{recon_domain}{Colors.RESET}")
            subdomains = load_subdomains_file(subdomains_file)
            unique_subdomains = sorted(set(subdomains))
            if not unique_subdomains:
                print(f"{Colors.RED}[!] No usable subdomains found in '{subdomains_file}'. Nothing to probe.{Colors.RESET}")
                return
            safe_domain = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in recon_domain.lower())
            domain_output_dir = os.path.join("reports", safe_domain or "domain")
            os.makedirs(domain_output_dir, exist_ok=True)
            dedup_file = os.path.join(domain_output_dir, f"manual_subdomains_{time.strftime('%Y%m%d_%H%M%S')}.txt")
            try:
                with open(dedup_file, "w", encoding="utf-8") as handle:
                    for host in unique_subdomains:
                        handle.write(f"{host}\n")
                print(f"{Colors.GRAY}[*] Normalized subdomain list saved to {dedup_file}{Colors.RESET}")
            except OSError as exc:
                print(f"{Colors.RED}[!] Failed to write normalized subdomain file: {exc}{Colors.RESET}")
                return
            # Resume skip (Phase 6): if this domain's HTTP-probe pipeline already
            # completed on a prior run, do NOT re-run it - that would re-add all
            # its findings (add_vulnerability does not dedup). The subdomain set
            # is the user-provided file (unchanged), so we reuse dedup_file.
            if recon_domain in state_manager.get_completed_recon_domains():
                print(f"{Colors.CYAN}[*] Resume: recon for {recon_domain} already complete; "
                      f"skipping HTTP-probe pipeline ({len(unique_subdomains)} subdomain(s)).{Colors.RESET}")
            else:
                print(f"{Colors.GRAY}[*] Using provided subdomain list '{subdomains_file}'. Skipping passive recon and starting with HTTP probing.{Colors.RESET}")
                recon_findings = await run_recon_followups(
                    unique_subdomains,
                    recon_domain,
                    domain_output_dir,
                    concurrency,
                    nmap_enabled,
                    wordlist,
                    connect_timeout,
                    port_retries,
                    enable_archived=archived_scan,
                    enable_screenshots=enable_screenshots,
                    extra_scans=extra_scans,
                    enable_js_cve=js_cve_scan,
                )
                if recon_findings:
                    print(f"{Colors.GREEN}[+] Recon pipeline: {len(recon_findings)} total finding(s) from {recon_domain}{Colors.RESET}")
                    for _f in recon_findings:
                        state_manager.add_vulnerability(_f)
                # Checkpoint so a resume skips this domain's pipeline (Phase 6).
                state_manager.mark_recon_domain_done(recon_domain, unique_subdomains)
            recon_web_probed = True  # run_recon_followups already probed these hosts
            recon_targets_file = dedup_file
            recon_targets_count = len(unique_subdomains)
            recon_targets_label = dedup_file
        else:
            from modules.dashboard import LiveDashboard
            dashboard = LiveDashboard()
            print(f"{Colors.CYAN}[*] Running passive recon for {len(normalized_domains)} domain(s) concurrently...{Colors.RESET}")
            print(f"{Colors.GRAY}[*] Toolchain: Amass, Subfinder, Assetfinder, Findomain, Sublist3r, Knockpy, bbot, Censys, crtsh + DirEnumerator(ffuf){Colors.RESET}")
            tool_limit = getattr(recon, "TOOL_CONCURRENCY_LIMIT", None)
            if tool_limit:
                print(f"{Colors.GRAY}[*] Recon tool concurrency capped at {tool_limit} parallel process(es) "
                      f"(set VAKT_RECON_TOOL_LIMIT to adjust).{Colors.RESET}")

            async def handle_domain(domain):
                # Resume skip (Phase 6): if this domain's recon pipeline already
                # completed on a prior run, do NOT re-run it. Re-running re-adds
                # every recon finding (add_vulnerability does not dedup), so each
                # resume would duplicate findings and inflate the count. Rebuild
                # the downstream target set from the checkpointed subdomains.
                if domain in state_manager.get_completed_recon_domains():
                    _subs = state_manager.get_recon_subdomains(domain)
                    _safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in domain.lower())
                    _dir = os.path.join("reports", _safe or "domain")
                    os.makedirs(_dir, exist_ok=True)
                    _f = os.path.join(_dir, f"resumed_subdomains_{time.strftime('%Y%m%d_%H%M%S')}.txt")
                    try:
                        with open(_f, "w", encoding="utf-8") as _h:
                            for _s in _subs:
                                _h.write(f"{_s}\n")
                    except OSError:
                        pass
                    print(f"{Colors.CYAN}[*] Resume: recon for {domain} already complete; "
                          f"skipping pipeline ({len(_subs)} subdomain(s) from checkpoint).{Colors.RESET}")
                    if not _subs:
                        return None
                    return {"domain": domain, "file": _f, "count": len(_subs), "subdomains": _subs}
                if not dashboard.active:
                    print(f"{Colors.CYAN}[*] Enumerating subdomains for {domain}...{Colors.RESET}")
                is_detailed = (len(normalized_domains) == 1)
                scanner = recon.ReconScanner(domain, wordlist=wordlist, detailed_dashboard=is_detailed)

                # Run subdomain enum and Google Dork in parallel
                _gapi_key = os.environ.get('GOOGLE_API_KEY', '')
                _gcx     = os.environ.get('GOOGLE_CX', '')

                async def _maybe_dork():
                    if no_dork:
                        return []
                    if not dashboard.active:
                        print(f"{Colors.CYAN}[*] Google Dork recon running in parallel for {domain}...{Colors.RESET}")
                    return await google_dork.run(
                        domain, api_key=_gapi_key, cx=_gcx,
                        method=dork_method
                    )

                (enum_result, dork_findings, passive_tuple) = await asyncio.gather(
                    scanner.run_all(),
                    _maybe_dork(),
                    _run_parallel_passive(domain, concurrency, detailed_dashboard=is_detailed),
                    return_exceptions=False,
                )
                results_file, subdomains = enum_result
                dns_findings, cloud_findings, ct_findings = passive_tuple

                if isinstance(dork_findings, list) and dork_findings:
                    print(f"{Colors.GREEN}[+] Google Dork: {len(dork_findings)} finding(s) for {domain}{Colors.RESET}")
                    for _df in dork_findings:
                        state_manager.add_vulnerability(_df)
                elif isinstance(dork_findings, Exception):
                    print(f"{Colors.YELLOW}[!] Google Dork error for {domain}: {dork_findings}{Colors.RESET}")

                for _f in dns_findings + cloud_findings + ct_findings:
                    state_manager.add_vulnerability(_f)
                if dns_findings:
                    print(f"{Colors.GREEN}[+] DNS recon: {len(dns_findings)} finding(s) for {domain}{Colors.RESET}")
                if cloud_findings:
                    print(f"{Colors.GREEN}[+] Cloud enum: {len(cloud_findings)} finding(s) for {domain}{Colors.RESET}")
                if ct_findings:
                    new_ct = [f for f in ct_findings if f.get("severity") == "HIGH"]
                    if new_ct:
                        print(f"{Colors.BRIGHT_RED}[!] CT monitor: {len(new_ct)} NEW certificate(s) detected for {domain}{Colors.RESET}")
                    else:
                        print(f"{Colors.GREEN}[+] CT monitor: baseline established for {domain}{Colors.RESET}")
                if not subdomains:
                    print(f"{Colors.YELLOW}[!] Recon completed for {domain} but no subdomains were discovered.{Colors.RESET}")
                    return None
                domain_output_dir = os.path.dirname(results_file)

                # Exclusion patterns (--exclude / --exclude-file): matched subdomains
                # STAY in the enumerated list (results_file) but are removed from
                # everything downstream - never resolved, probed, or scanned.
                if exclude_patterns:
                    _excluded = [s for s in subdomains if _is_excluded(s)]
                    if _excluded:
                        subdomains = [s for s in subdomains if not _is_excluded(s)]
                        try:
                            _ex_path = os.path.join(domain_output_dir, "excluded_subdomains.txt")
                            with open(_ex_path, "w", encoding="utf-8") as _eh:
                                for _s in sorted(set(_excluded)):
                                    _eh.write(f"{_s}\n")
                            print(f"{Colors.YELLOW}[*] Excluded {len(_excluded)} subdomain(s) from scanning "
                                  f"(matched exclusion pattern); listed in {_ex_path}.{Colors.RESET}")
                        except OSError:
                            print(f"{Colors.YELLOW}[*] Excluded {len(_excluded)} subdomain(s) from scanning (matched exclusion pattern).{Colors.RESET}")
                        if not subdomains:
                            print(f"{Colors.YELLOW}[!] All discovered subdomains for {domain} were excluded - nothing to scan.{Colors.RESET}")
                            return None

                # --include-only (allowlist): keep ONLY hosts matching the patterns.
                # Runs after --exclude so the two compose (exclude wins on overlap).
                if _include_only is not None:
                    _before = len(subdomains)
                    subdomains = [s for s in subdomains if _include_only(s)]
                    print(f"{Colors.YELLOW}[*] --include-only kept {len(subdomains)}/{_before} host(s).{Colors.RESET}")
                    if not subdomains:
                        print(f"{Colors.YELLOW}[!] No subdomains matched --include-only for {domain} - nothing to scan.{Colors.RESET}")
                        return None

                # --company-only: resolve + map IPs, then drop customer/shared-hosting
                # sites (>= shared_ip_threshold hosts on one IP), keeping company assets
                # (distinct IPs + functional-named hosts). Runs AFTER exclude/include so
                # we only resolve the reduced set (saves DNS work).
                if company_only and subdomains:
                    _cls = await asset_classifier.classify_by_shared_ip(
                        subdomains, domain, domain_output_dir,
                        shared_ip_threshold=shared_ip_threshold, concurrency=concurrency,
                    )
                    for _cf in _cls.get("findings", []):
                        state_manager.add_vulnerability(_cf)
                    if _cls.get("customer"):
                        subdomains = _cls["company"]
                        if not subdomains:
                            print(f"{Colors.YELLOW}[!] All hosts classified as customer/shared-hosting for {domain} - nothing to scan.{Colors.RESET}")
                            return None

                # Horizontal / infrastructure expansion (opt-in via --horizontal):
                # asnmap → CIDRs, reverse-DNS sweep, amass intel → related domains.
                # Gracefully skips when the tools aren't installed.
                if enable_horizontal:
                    _expansion = await horizontal_expand.expand_horizontal([domain], domain_output_dir)
                    for _hf in _expansion.get("findings", []):
                        state_manager.add_vulnerability(_hf)
                    _rh, _rd = len(_expansion.get("reverse_hosts", [])), len(_expansion.get("related_domains", []))
                    if _rh or _rd:
                        print(f"{Colors.GREEN}[+] Horizontal expansion: {_rd} related domain(s), "
                              f"{_rh} reverse-DNS host(s) discovered for {domain}.{Colors.RESET}")

                # DNS hygiene (ON by default; --no-dns-hygiene to disable): wildcard-
                # filter the enumerated subdomains before probing to drop catch-all
                # false-positive names. Permutation expansion (--dns-permute) is
                # opt-in. Passthrough when puredns/massdns aren't installed.
                if dns_hygiene:
                    _dns = await dns_resolve.resolve_and_permute(
                        subdomains, [domain], domain_output_dir, concurrency, permute=dns_permute
                    )
                    for _f in _dns.get("findings", []):
                        state_manager.add_vulnerability(_f)
                    if _dns.get("resolved"):
                        _before = len(subdomains)
                        subdomains = _dns["resolved"]
                        _how = "wildcard-filtered + permutation-expanded" if dns_permute else "wildcard-filtered"
                        print(f"{Colors.GREEN}[+] DNS hygiene: {_before} → {len(subdomains)} host(s) ({_how}).{Colors.RESET}")

                # Per-subdomain DNS-level takeover: flag dangling CNAMEs (CNAME ->
                # NXDOMAIN) across ALL discovered subdomains. Complements the
                # HTTP-based takeover check by catching targets that serve no HTTP.
                if dns_takeover and subdomains:
                    _dangling = await dns_recon.check_dangling_cnames(subdomains, concurrency=concurrency)
                    for _df in _dangling:
                        state_manager.add_vulnerability(_df)

                if scan_found:
                    recon_findings = await run_recon_followups(
                        subdomains,
                        domain,
                        domain_output_dir,
                        concurrency,
                        nmap_enabled,
                        wordlist,
                        connect_timeout,
                        port_retries,
                        enable_archived=archived_scan,
                        enable_screenshots=enable_screenshots,
                        extra_scans=extra_scans,
                        enable_js_cve=js_cve_scan,
                    )
                    if recon_findings:
                        print(f"{Colors.GREEN}[+] Recon pipeline: {len(recon_findings)} total finding(s) from {domain}{Colors.RESET}")
                        for _f in recon_findings:
                            state_manager.add_vulnerability(_f)
                else:
                    print(f"{Colors.GRAY}[*] Recon ({domain}) complete. Use --scan-found to automatically probe recon targets (httpx → dirsearch → nuclei).{Colors.RESET}")
                # Checkpoint this domain's recon as finished (Phase 6), storing
                # the final subdomain set so a resume can skip re-running the
                # pipeline yet still rebuild this domain's target list.
                state_manager.mark_recon_domain_done(domain, subdomains)
                return {
                    "domain": domain,
                    "file": results_file,
                    "count": len(subdomains),
                    "subdomains": subdomains,
                }

            max_recon = max(1, recon_concurrency or 1)
            semaphore = asyncio.Semaphore(max_recon)

            async def limited_domain_run(domain):
                async with semaphore:
                    return await handle_domain(domain)

            tasks = [asyncio.create_task(limited_domain_run(domain)) for domain in normalized_domains]
            passive_results = await asyncio.gather(*tasks, return_exceptions=True)
            successes = []
            for result in passive_results:
                if isinstance(result, dict):
                    successes.append(result)
                elif isinstance(result, Exception):
                    # A programming bug (e.g. NameError/UnboundLocalError) must
                    # never be swallowed here - that is exactly what once turned
                    # a code crash into a misleading "no usable targets".
                    _reraise_if_bug(result)
                    print(f"{Colors.RED}[!] Recon error: {result}{Colors.RESET}")
                    if os.environ.get("VAKT_DEBUG"):
                        traceback.print_exception(type(result), result, result.__traceback__)

            if not successes:
                print(f"{Colors.RED}[!] Recon finished with no usable targets.{Colors.RESET}")
                _persist_orphan_recon_findings()
                return

            # handle_domain ran run_recon_followups (the full web pipeline) for
            # each domain iff scan_found; if so, the main scan must not re-probe.
            recon_web_probed = scan_found
            # Passive recon (_run_parallel_passive) already ran cloud enum on each
            # apex domain - record them so phase 3b doesn't repeat the work.
            cloud_enumerated_domains.update(_registrable_domain(d) for d in normalized_domains)

            if len(successes) == 1:
                meta = successes[0]
                recon_targets_file = meta["file"]
                recon_targets_count = meta["count"]
                recon_targets_label = meta["file"]
            else:
                combined_targets = sorted({sub for meta in successes for sub in meta["subdomains"]})
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                combined_dir = os.path.join("reports", "combined")
                os.makedirs(combined_dir, exist_ok=True)
                combined_file = os.path.join(combined_dir, f"recon_targets_{timestamp}.txt")
                try:
                    with open(combined_file, "w", encoding="utf-8") as handle:
                        for item in combined_targets:
                            handle.write(f"{item}\n")
                except OSError as exc:
                    print(f"{Colors.RED}[!] Failed to write combined recon targets: {exc}{Colors.RESET}")
                    _persist_orphan_recon_findings()
                    return
                print(f"{Colors.GRAY}[*] Combined recon targets saved to {combined_file}{Colors.RESET}")
                recon_targets_file = combined_file
                recon_targets_count = len(combined_targets)
                recon_targets_label = combined_file

        if recon_targets_count == 0:
            print(f"{Colors.YELLOW}[!] Recon input did not yield any valid targets. Exiting.{Colors.RESET}")
            _persist_orphan_recon_findings()
            return

        if targets_file:
            print(f"{Colors.YELLOW}[!] Ignoring provided targets file because -m recon supplies its own target set.{Colors.RESET}")
        targets_file = recon_targets_file
        print(
            f"{Colors.CYAN}[*] Continuing with full service scanning for {recon_targets_count} recon target(s) "
            f"from {recon_targets_label}.{Colors.RESET}"
        )
        # Recon finished and yielded scannable targets (Phase 6). Advance only
        # from recon/initializing so a resume already past recon is not regressed.
        if state_manager.state.get("phase") in ("initializing", "recon"):
            state_manager.update_phase("recon_complete")

    # --- MAIN SCANNING LOGIC ---
    if not targets_file:
        print(f"{Colors.RED}[!] Error: No targets file provided and --recon not used.{Colors.RESET}")
        print("Usage: python main.py <targets_file> OR python main.py --recon <domain>")
        return

    # state_manager was constructed and state loaded EARLY (before the recon
    # block, Phase 6) so recon findings persist immediately; scan_id /
    # canonical_targets / scope / resume_mode / is_resume are already resolved.

    # Inventory: initialise DB and open a new scan run
    inventory.init_db()
    run_id = inventory.start_scan_run(targets_file or 'recon')

    try:
        # 1. Process targets - use robust parser (handles schemas, comments,
        #    inline comments, commas, tabs, BOM, encoding issues, etc.)
        raw_targets = parse_targets_file(targets_file)

        # Decide streaming on the EXPANDED host count, not the raw line count - a
        # single large CIDR is one line but can be millions of hosts, and the
        # non-streaming path hard-caps at 50,000 (silently dropping the rest).
        def _expanded_target_count(lines):
            n = 0
            for t in lines:
                t = (t or "").strip()
                if not t or t.startswith('#'):
                    continue
                try:
                    n += ipaddress.ip_network(t, strict=False).num_addresses
                except ValueError:
                    n += 1
                if n > 1000:
                    break
            return n

        should_stream = _expanded_target_count(raw_targets) > 1000

        if should_stream:
            print(f"{Colors.YELLOW}[*] Large target set detected - using streaming mode{Colors.RESET}")
            return await process_streaming_scan(
                raw_targets,
                concurrency,
                module_filter=module_filter,
                custom_ports=custom_ports,
                chunk_size=chunk_size,
                state_manager=state_manager,
                connect_timeout=connect_timeout,
                port_retries=port_retries,
                nmap_enabled=nmap_enabled,
                run_id=run_id,
                sarif_output=sarif_output,
                web_probe=stream_web_probe,
                output_format=output_format,
                enable_js_cve=js_cve_scan,
            )

        if not is_resume or state_manager.state["phase"] == "initializing":
            print(f"{Colors.CYAN}[*] Parsing targets from {targets_file}...{Colors.RESET}")
            try:
                targets = await process_targets(raw_targets)
                print(f"{Colors.GREEN}[+] Successfully processed {len(targets)} scan targets.{Colors.RESET}")
                state_manager.update_phase("target_processing_complete")
            except FileNotFoundError:
                print(f"{Colors.RED}[!] Error: Input file not found at {targets_file}{Colors.RESET}")
                return
            except Exception as e:
                _reraise_if_bug(e)
                print(f"[!] An error occurred during target processing: {e}")
                return
        else:
            print(f"[*] Using previously processed {state_manager.state.get('total_targets', 'N/A')} targets.")
            targets = await process_targets(raw_targets) 

        if not targets:
            print("[!] No valid targets to scan. Exiting.")
            return

        # Exclusion patterns apply to the final scan set too (belt-and-suspenders for
        # file/IP scans and any recon fall-through): drop excluded hosts by hostname.
        if exclude_patterns:
            _kept = [t for t in targets
                     if not _is_excluded(t.get('display_target') or t.get('scan_address', ''))]
            if len(_kept) < len(targets):
                print(f"{Colors.YELLOW}[*] Exclusion patterns removed {len(targets) - len(_kept)} "
                      f"target(s) from scanning.{Colors.RESET}")
                targets = _kept
            if not targets:
                print("[!] All targets were excluded. Exiting.")
                return

        # --include-only allowlist on the final scan set (file/IP scans).
        if _include_only is not None:
            _kept = [t for t in targets
                     if _include_only(t.get('display_target') or t.get('scan_address', ''))]
            if len(_kept) < len(targets):
                print(f"{Colors.YELLOW}[*] --include-only kept {len(_kept)}/{len(targets)} target(s).{Colors.RESET}")
                targets = _kept
            if not targets:
                print("[!] No targets matched --include-only. Exiting.")
                return

        # 2. Define service ports (only modules that have scanners)
        full_service_ports = get_service_ports()
        service_ports = {
            service: ports
            for service, ports in full_service_ports.items()
            if service in SERVICE_TO_MODULE
        }
        
        if module_filter:
            print(f"{Colors.YELLOW}[*] Module filter: Scanning only {module_filter.capitalize()} services{Colors.RESET}")
            service_ports = {module_filter: service_ports.get(module_filter, [])}
        
        # Scan all ports from every service definition (service modules + web + cpanel_adjacent + etc.)
        all_ports_to_scan = list(set(
            port for ports in full_service_ports.values() for port in ports
        ))
        
        if custom_ports:
            try:
                custom_port_list = [int(port.strip()) for port in custom_ports.split(',')]
                all_ports_to_scan.extend(custom_port_list)
                all_ports_to_scan = list(set(all_ports_to_scan))
                print(f"{Colors.YELLOW}[*] Added custom ports: {custom_port_list}{Colors.RESET}")
            except ValueError as e:
                print(f"{Colors.RED}[!] Error parsing custom ports: {e}. Ignoring custom ports.{Colors.RESET}")
        
        # Output dir shared by all artifacts from this scan (port CSV, httpx, nuclei, results CSV)
        web_output_dir = None
        # Defined up front so the resumable web-probe phase below has a label even
        # on a resume that skips the fresh port-scan branch.
        domain_label = os.path.splitext(os.path.basename(targets_file))[0]

        # --- STANDARD PORT SCAN LOGIC ---
        if state_manager.state["phase"] in ["initializing", "recon", "recon_complete",
                                             "target_processing_complete", "port_scanning"]:
            # process_targets emits both a hostname object and a bare-IP object per
            # host (both connect to the same resolved IP), which doubles the port
            # scan AND every downstream per-service module run. De-duplicate by
            # resolved IP for scanning, preferring the hostname-bearing object (it
            # is emitted first), so each IP is scanned once but keeps its hostname.
            scan_targets = []
            _seen_scan_ips = set()
            for _t in targets:
                _key = _t.get('resolved_ip') or _t.get('scan_address')
                if _key in _seen_scan_ips:
                    continue
                _seen_scan_ips.add(_key)
                scan_targets.append(_t)
            if len(scan_targets) < len(targets):
                print(f"{Colors.GRAY}[*] De-duplicated {len(targets)} target objects to "
                      f"{len(scan_targets)} unique host(s) for scanning.{Colors.RESET}")

            state_manager.set_totals(len(scan_targets), len(scan_targets) * len(all_ports_to_scan))

            print(f"{Colors.CYAN}[*] Starting concurrent port scan for {len(scan_targets)} targets across {len(all_ports_to_scan)} unique ports...{Colors.RESET}")
            state_manager.update_phase("port_scanning")

            open_ports_results = await scan_ports(
                scan_targets,
                all_ports_to_scan,
                concurrency,
                state_manager,
                connect_timeout=connect_timeout,
                retries=port_retries,
            )
            print(f"{Colors.GREEN}[+] Port scanning complete.{Colors.RESET}")
            state_manager.update_phase("port_scanning_complete")

            # Create a single output directory for all artifacts from this scan
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            web_output_dir = os.path.join("reports", f"web_probe_{domain_label}_{timestamp}")
            os.makedirs(web_output_dir, exist_ok=True)

            save_port_scan_csv(open_ports_results, domain_label, output_dir=web_output_dir)

            # Persist discovered assets into inventory
            for _target_obj, _data in open_ports_results:
                _open_ports = _data.get('open_ports', [])
                if not _open_ports:
                    continue
                _ip       = _target_obj.get('resolved_ip') or _target_obj.get('scan_address', '')
                _hostname = _target_obj.get('display_target', '')
                if _ip:
                    inventory.upsert_asset(_ip, _hostname, _open_ports)

            # If Nmap is enabled, run `nmap --script vuln,vulners` ONLY on the open
            # ports the port scanner already found (no separate full-range sweep).
            if nmap_enabled:
                nmap_targets_data = []
                for target_obj, data in open_ports_results:
                    open_ports = data.get('open_ports', [])
                    if open_ports:
                        ip = target_obj.get('resolved_ip') or target_obj.get('scan_address')
                        host = target_obj.get('display_target') or ip
                        nmap_targets_data.append((ip, sorted(open_ports), host))
                if nmap_targets_data:
                    nmap_inst = nmap_runner.NmapRunner(output_base_dir=web_output_dir or "reports")
                    nmap_cve_findings = await nmap_inst.run_cve_scan_batch(nmap_targets_data, concurrency=concurrency)
                    if nmap_cve_findings:
                        print(f"{Colors.GREEN}[+] Nmap CVE Scan: {len(nmap_cve_findings)} finding(s).{Colors.RESET}")
                        for v in nmap_cve_findings:
                            state_manager.add_vulnerability(v)
        else:
            print(f"[*] Using previously scanned port results...")
            # Rebuild as (target_obj, data) tuples from `targets` (which retains the
            # hostname/display_target), pulling persisted open ports by resolved IP.
            # This preserves hostname attribution on resume instead of collapsing
            # every finding to a bare IP. De-dup by IP (targets has hostname+IP objects).
            open_ports_results = []
            _resume_seen_ips = set()
            for target in targets:
                resolved_ip = target.get('resolved_ip')
                if not resolved_ip or resolved_ip in _resume_seen_ips:
                    continue
                _resume_seen_ips.add(resolved_ip)
                open_ports_results.append(
                    (target, {'open_ports': state_manager.state["open_ports"].get(resolved_ip, [])})
                )

        # --- WEB-PROBE PHASE (resumable) ---
        # httpx→nuclei→web_checks→dirsearch→JS on any open web ports. This is a
        # first-class checkpointed phase: an interrupt here resumes from the URLs
        # not yet probed (completed URLs are persisted and skipped) instead of
        # restarting the probe or - worse - skipping it entirely on resume. It runs
        # in BOTH the fresh and resume branches because `open_ports_results` is now
        # populated either way. Skipped only when recon already probed these hosts.
        if not recon_web_probed and state_manager.state["phase"] in ("port_scanning_complete", "web_probing"):
            state_manager.update_phase("web_probing")
            # A resume that skipped the fresh branch has no output dir yet.
            if not web_output_dir:
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                web_output_dir = os.path.join("reports", f"web_probe_{domain_label}_{timestamp}")
                os.makedirs(web_output_dir, exist_ok=True)
            # Probe the standard web ports plus any custom HTTP ports the user supplied.
            from utils import format_url
            web_port_set = _web_port_set(full_service_ports, custom_ports)
            web_probe_urls = []
            for target_obj, data in open_ports_results:
                for port in data.get("open_ports", []):
                    if port in web_port_set:
                        host = target_obj.get("display_target") or target_obj.get("scan_address")
                        for scheme in ("http", "https"):
                            web_probe_urls.append(format_url(scheme, host, port))
            web_probe_urls = sorted(set(web_probe_urls))

            web_findings = await _probe_web_urls(
                web_probe_urls, web_output_dir, domain_label, concurrency,
                completed_urls=state_manager.get_completed_web_urls(),
                record_completed=state_manager.add_completed_web_urls,
                batch_size=WEB_PROBE_CHECKPOINT_BATCH,
                enable_js_cve=js_cve_scan,
                # Persist each batch's findings atomically with its completed-URL
                # checkpoint (see _probe_web_urls) so an interrupt can't lose the
                # findings of an already-checkpointed batch. With this hook the
                # returned list is empty, so there is nothing to re-add below.
                record_findings=state_manager.add_vulnerability,
            )
            for _wf in web_findings:
                state_manager.add_vulnerability(_wf)
            state_manager.update_phase("web_probing_complete")
        elif recon_web_probed and state_manager.state["phase"] == "port_scanning_complete":
            print(f"{Colors.GRAY}[*] Skipping web re-probe - recon already ran "
                  f"httpx/nuclei/web-checks/dirsearch/JS on these hosts.{Colors.RESET}")

    except (KeyboardInterrupt, asyncio.CancelledError):
        # First Ctrl+C cancels the main task -> CancelledError unwinds here.
        # Force-save the checkpoint, then RE-RAISE so the top-level run_command
        # runner observes the cancellation and tears down child process groups.
        print(f"\n[!] Scan interrupted. Saving final state...")
        state_manager.save_state(force=True)
        print(f"[+] State saved to {state_manager.state_file}")
        print("[!] Use --resume to continue this scan later.")
        raise
    finally:
        # Durable checkpoint independent of the 2-minute timer / atexit hook,
        # on cancellation, error, or normal completion of the phase body.
        state_manager.save_state(force=True)

    # 3. Validate services and create tasks for service-specific scanners
    if state_manager.state["phase"] in ["port_scanning_complete", "web_probing_complete",
                                        "full_port_scanning", "service_validation",
                                        "vulnerability_scanning"]:
        validation_tasks = []
        service_mapping = []
        
        print(f"\n[*] Validating services on open ports...")
        state_manager.update_phase("service_validation")
        
        # Determine iterator based on structure of open_ports_results
        if isinstance(open_ports_results, dict):
            # For resume mode structure
            iterator = []
            for ip, data in open_ports_results.items():
                # Reconstruct target obj roughly for resume
                iterator.append(({'scan_address': ip, 'display_target': ip, 'resolved_ip': ip}, data))
        else:
            iterator = open_ports_results

        for target_obj, data in iterator:
            if not data['open_ports']:
                continue

            scan_address = target_obj['scan_address']
            target_open_ports = data['open_ports']

            # This logic works perfectly with Full Scan results too.
            # It checks if the open ports found (e.g., 9200) match our service definitions.
            for port in target_open_ports:
                for service, service_ports_list in service_ports.items():
                    if port in service_ports_list:
                        scanner_func = SERVICE_TO_MODULE[service].run_scans
                        validation_tasks.append(validate_service(service, target_obj, port))
                        service_mapping.append((service, target_obj, port, scanner_func, target_open_ports))

                if custom_ports and port not in [p for ports in service_ports.values() for p in ports]:
                    for service_name in SERVICE_TO_MODULE.keys():
                        if module_filter is None or service_name == module_filter:
                            scanner_func = SERVICE_TO_MODULE[service_name].run_scans
                            validation_tasks.append(validate_service(service_name, target_obj, port))
                            service_mapping.append((service_name, target_obj, port, scanner_func, target_open_ports))
        
        if not validation_tasks:
            print("\n[*] No specific VaktScan services (Elastic/Kibana/etc) found on open ports.")
            if not nuclei_vulns_found and not nmap_enabled:
                state_manager.mark_completed()
                return
            else:
                print(f"{Colors.GREEN}[*] Proceeding (Standard services not found, but Nmap/Nuclei ran).{Colors.RESET}")
        
        if validation_tasks:
            validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
            
            validated_services = 0
            scan_tasks = []

            # Already-completed {ip}:{port}:{service} scans (Phase 6): on a resume
            # of an interrupted vulnerability_scanning phase, skip the service
            # scanners that already ran to completion instead of redoing them.
            _done_service_scans = state_manager.get_completed_service_scans()
            _skipped_service_scans = 0

            async def scan_with_state_saving(scan_func, target_obj, port, service, adjacent_open_ports=None):
                try:
                    if adjacent_open_ports is not None:
                        results = await scan_func(target_obj, port, adjacent_open_ports=adjacent_open_ports)
                    else:
                        results = await scan_func(target_obj, port)
                    for result in results:
                        state_manager.add_vulnerability(result)
                    # Checkpoint this service scan as done (Phase 6) so a resume
                    # after an interrupt does not run it again.
                    state_manager.mark_service_scan_done(
                        target_obj.get('resolved_ip') or target_obj.get('scan_address'), port, service)
                    return results
                except Exception as e:
                    # Keep tolerating per-scanner runtime failures, but never a bug.
                    _reraise_if_bug(e)
                    if os.environ.get("VAKT_DEBUG"):
                        print(f"{Colors.YELLOW}[!] Error scanning {target_obj['scan_address']}:{port} - {e}{Colors.RESET}")
                    return []

            for is_valid, (service, target_obj, port, scanner_func, target_open_ports) in zip(validation_results, service_mapping):
                if isinstance(is_valid, Exception):
                    # A raised validation result used to be silently read as
                    # "not a valid service" and the target skipped without a word.
                    _reraise_if_bug(is_valid)
                    if os.environ.get("VAKT_DEBUG"):
                        print(f"{Colors.YELLOW}[!] Service validation error for {service} on "
                              f"{target_obj.get('scan_address', '?')}:{port} - {is_valid}{Colors.RESET}")
                    continue
                if isinstance(is_valid, bool) and is_valid:
                    _svc_ip = target_obj.get('resolved_ip') or target_obj.get('scan_address')
                    if f"{_svc_ip}:{port}:{service}" in _done_service_scans:
                        _skipped_service_scans += 1
                        validated_services += 1
                        continue
                    display_url = target_obj['scan_address']
                    if not display_url.startswith(('http://', 'https://')):
                        display_url = f"http://{display_url}:{port}"
                    print(f"  -> Running {service.capitalize()} scans on {display_url} [Port: {port}]")
                    state_manager.add_validated_service(target_obj['resolved_ip'], port, service)
                    adj = target_open_ports if service == 'cpanel' else None
                    scan_tasks.append(scan_with_state_saving(scanner_func, target_obj, port, service, adjacent_open_ports=adj))
                    validated_services += 1

            if _skipped_service_scans:
                print(f"{Colors.CYAN}[*] Resume: skipping {_skipped_service_scans} service scan(s) "
                      f"already completed.{Colors.RESET}")
            
            if validated_services == 0 and not nuclei_vulns_found and not nmap_enabled:
                print("\n[*] No validated services found on the provided targets.")
                state_manager.mark_completed()
                return

            if validated_services > 0:
                print(f"{Colors.CYAN}\n[*] Validated {validated_services} service(s). Starting VaktScan vulnerability assessment...{Colors.RESET}")
                state_manager.update_phase("vulnerability_scanning")
                
                if scan_tasks:
                    await asyncio.gather(*scan_tasks, return_exceptions=True)
            
        state_manager.update_phase("vulnerability_scanning_complete")

    else:
        print(f"\n[*] Using previously found vulnerabilities...")

    # 3b. Cloud asset enumeration for domain targets.
    # Cloud bucket names derive from the registrable/org domain, not each
    # subdomain, so enumerate ONCE per registrable domain (not per host), and skip
    # any apex already enumerated during passive recon - reuse, don't repeat.
    if not module_filter or module_filter == 'cloud':
        apex_targets = []
        seen_apex = set()
        for t in targets:
            host = t.get('display_target') or t.get('scan_address', '')
            if not host:
                continue
            try:
                ipaddress.ip_network(host, strict=False)
                continue  # skip raw IPs
            except ValueError:
                pass
            apex = _registrable_domain(host)
            if not apex or apex in seen_apex or apex in cloud_enumerated_domains:
                continue
            seen_apex.add(apex)
            apex_targets.append(apex)
        if apex_targets:
            print(
                f"{Colors.CYAN}[*] Running cloud asset enumeration on "
                f"{len(apex_targets)} registrable domain(s)...{Colors.RESET}"
            )
            for _cloud_domain in apex_targets:
                _cloud_findings = await cloud_enum.enumerate_cloud_assets(
                    _cloud_domain, concurrency=concurrency
                )
                for _cf in _cloud_findings:
                    state_manager.add_vulnerability(_cf)
                cloud_enumerated_domains.add(_cloud_domain)
            print(f"{Colors.GREEN}[+] Cloud asset enumeration complete.{Colors.RESET}")
        elif cloud_enumerated_domains:
            print(f"{Colors.GRAY}[*] Cloud enumeration already covered during recon - skipping re-enumeration.{Colors.RESET}")

    # 4. Print Results
    print(f"{Colors.BRIGHT_CYAN}\n" + "="*50 + f"{Colors.RESET}")
    print(f"{Colors.BRIGHT_YELLOW}{Colors.BOLD}      Vulnerability Scan Results{Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}" + "="*50 + f"\n{Colors.RESET}")
    
    all_vulnerabilities = state_manager.get_vulnerabilities()
    final_vulnerabilities = deduplicate_vulnerabilities(all_vulnerabilities)
    
    if final_vulnerabilities:
        for result in final_vulnerabilities:
            if result['status'] == 'VULNERABLE':
                status_color = Colors.BRIGHT_RED
            elif result['status'] == 'CRITICAL':
                status_color = Colors.RED + Colors.BOLD
            elif result['status'] == 'POTENTIAL':
                status_color = Colors.YELLOW
            elif result['status'] == 'INFO':
                status_color = Colors.BLUE
            else:
                status_color = Colors.WHITE
            
            print(f"{status_color}[!] {result['status']}{Colors.RESET}: {Colors.BOLD}{result['vulnerability']}{Colors.RESET} on {Colors.UNDERLINE}{result['target']}{Colors.RESET}")
            print(f"    {Colors.GRAY}Details: {result['details']}{Colors.RESET}\n")
    else:
        print(f"{Colors.GREEN}[*] No vulnerabilities found.{Colors.RESET}")
    
    # Enrich (NVD/KEV/EPSS/passive-intel), persist to inventory, and write
    # CSV/JSON/SARIF via the shared finalization tail (also used by streaming mode).
    final_vulnerabilities = await _enrich_and_report(
        final_vulnerabilities, run_id, web_output_dir, sarif_output, output_format=output_format,
    )

    state_manager.mark_completed()
    print(f"\n{state_manager.get_scan_summary()}")
    print(f"{Colors.BRIGHT_GREEN}[*] Scan finished.{Colors.RESET}")
    
    state_manager.cleanup_state_file()

# Helper for streaming process (remains mostly unchanged, just ensured it's accessible)
async def process_streaming_scan(
    raw_targets,
    concurrency,
    module_filter=None,
    custom_ports=None,
    chunk_size=30000,
    state_manager=None,
    connect_timeout=DEFAULT_CONNECT_TIMEOUT,
    port_retries=DEFAULT_PORT_RETRIES,
    nmap_enabled=False,
    run_id=None,
    sarif_output=None,
    web_probe=False,
    output_format=None,
    enable_js_cve=True,
):
    print(f"{Colors.CYAN}[*] Calculating total targets for progress estimation...{Colors.RESET}")
    total_targets = 0
    for target in raw_targets:
        if not target or target.startswith('#'): continue
        try:
            network = ipaddress.ip_network(target, strict=False)
            total_targets += network.num_addresses
        except ValueError:
            total_targets += 1
    
    total_chunks = (total_targets + chunk_size - 1) // chunk_size if chunk_size > 0 else 1
    print(f"{Colors.CYAN}[*] Starting streaming scan: ~{total_targets:,} total targets across {total_chunks} chunks{Colors.RESET}")
    
    base_ports = get_service_ports()
    service_ports = {
        service: ports
        for service, ports in base_ports.items()
        if service in SERVICE_TO_MODULE
    }
    if module_filter:
        service_ports = {module_filter: service_ports.get(module_filter, [])}
    
    all_ports_to_scan = list(set(
        port for ports in base_ports.values() for port in ports
    ))
    if custom_ports:
        try:
            custom_port_list = [int(p.strip()) for p in custom_ports.split(',')]
            all_ports_to_scan.extend(custom_port_list)
            all_ports_to_scan = list(set(all_ports_to_scan))
        except ValueError: pass

    all_vulnerabilities = []
    all_port_scan_results = []
    chunk_count = 0

    try:
        async for target_chunk in process_targets_streaming(raw_targets, chunk_size):
            chunk_count += 1
            print(f"\n{Colors.BRIGHT_CYAN}=== Processing Chunk {chunk_count}/{total_chunks} ({len(target_chunk):,} targets) ==={Colors.RESET}")

            open_ports_results = await scan_ports(
                target_chunk,
                all_ports_to_scan,
                concurrency,
                state_manager,
                connect_timeout=connect_timeout,
                retries=port_retries,
            )
            all_port_scan_results.extend(open_ports_results)
            chunk_vulnerabilities = await process_chunk_services(open_ports_results, service_ports, module_filter, custom_ports, state_manager)

            # Opt-in (--stream-web-probe): run httpx→nuclei→web_checks→dirsearch→JS
            # on this chunk's open web ports. Off by default because a large target
            # set can expand to an enormous number of web URLs.
            if web_probe:
                web_port_set = _web_port_set(base_ports, custom_ports)
                chunk_web_urls = []
                for target_obj, data in open_ports_results:
                    for port in data.get("open_ports", []):
                        if port in web_port_set:
                            host = target_obj.get("display_target") or target_obj.get("scan_address")
                            for scheme in ("http", "https"):
                                from utils import format_url
                                chunk_web_urls.append(format_url(scheme, host, port))
                chunk_web_urls = sorted(set(chunk_web_urls))
                if chunk_web_urls:
                    web_findings = await _probe_web_urls(
                        chunk_web_urls, "reports", "streaming", concurrency,
                        enable_js_cve=enable_js_cve)
                    for _wf in web_findings:
                        state_manager.add_vulnerability(_wf)
                    chunk_vulnerabilities.extend(web_findings)


            # Run Nmap CVE scan if enabled
            if nmap_enabled:
                nmap_targets_data = []
                for target_obj, data in open_ports_results:
                    open_ports = data.get('open_ports', [])
                    if open_ports:
                        ip = target_obj.get('resolved_ip') or target_obj.get('scan_address')
                        host = target_obj.get('display_target') or ip
                        nmap_targets_data.append((ip, sorted(open_ports), host))
                if nmap_targets_data:
                    nmap_inst = nmap_runner.NmapRunner(output_base_dir="reports")
                    nmap_cve_findings = await nmap_inst.run_cve_scan_batch(nmap_targets_data, concurrency=concurrency)
                    if nmap_cve_findings:
                        print(f"{Colors.GREEN}[+] Nmap CVE Scan: {len(nmap_cve_findings)} finding(s).{Colors.RESET}")
                        for v in nmap_cve_findings:
                            state_manager.add_vulnerability(v)
                            chunk_vulnerabilities.append(v)

            all_vulnerabilities.extend(chunk_vulnerabilities)
            
            if state_manager:
                state_manager.state["completed_chunks"] = chunk_count
                state_manager.save_state()
            
            print(f"{Colors.GREEN}[+] Chunk {chunk_count}/{total_chunks} completed.{Colors.RESET}")

    except (KeyboardInterrupt, asyncio.CancelledError):
        # On POSIX a single Ctrl+C now surfaces as CancelledError (not
        # KeyboardInterrupt); catch both so the chunk loop stops and the partial
        # CSV/report finalization below still runs. Per-chunk state was already
        # force-saved (save_state + add_vulnerability), and the in-flight
        # subprocess groups already tore down as the cancel unwound their
        # run_tool/spawn_tool contexts on the way here, so finalizing (rather
        # than re-raising) simply salvages the results gathered so far.
        print(f"\n[!] Streaming scan interrupted.")

    if all_port_scan_results:
        save_port_scan_csv(all_port_scan_results, "streaming")

    # Dedup, then run the SAME finalization tail as a normal scan: NVD/KEV/EPSS/
    # passive-intel enrichment, inventory delta, and CSV/JSON/SARIF output. Streaming
    # previously fed raw (non-deduped, non-enriched) findings to inventory/SARIF and
    # skipped KEV/EPSS entirely - this brings it to parity.
    final_vulnerabilities = deduplicate_vulnerabilities(all_vulnerabilities)
    print(f"\n{Colors.BRIGHT_CYAN}=== Final Vulnerability Results ({len(final_vulnerabilities)}) ==={Colors.RESET}")
    for result in final_vulnerabilities:
        print(f"[!] {result.get('status', '?')}: {result.get('vulnerability', '?')} on {result.get('target', '?')}")

    final_vulnerabilities = await _enrich_and_report(
        final_vulnerabilities, run_id, None, sarif_output, output_format=output_format,
    )
    return final_vulnerabilities

# Helper functions for streaming (included to ensure self-contained file)
async def process_chunk_services(open_ports_results, service_ports, module_filter, custom_ports, state_manager):
    validation_tasks = []
    service_mapping = []
    
    for target_obj, data in open_ports_results:
        if not data['open_ports']: continue
        scan_address = target_obj['scan_address']
        target_open_ports = data['open_ports']

        for port in target_open_ports:
            for service, service_ports_list in service_ports.items():
                if port in service_ports_list:
                    scanner_func = SERVICE_TO_MODULE[service].run_scans
                    validation_tasks.append(validate_service(service, target_obj, port))
                    service_mapping.append((service, target_obj, port, scanner_func, target_open_ports))
            if custom_ports and port not in [p for ports in service_ports.values() for p in ports]:
                for service_name in SERVICE_TO_MODULE.keys():
                    if module_filter is None or service_name == module_filter:
                        scanner_func = SERVICE_TO_MODULE[service_name].run_scans
                        validation_tasks.append(validate_service(service_name, target_obj, port))
                        service_mapping.append((service_name, target_obj, port, scanner_func, target_open_ports))

    chunk_vulnerabilities = []
    if not validation_tasks: return chunk_vulnerabilities

    validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
    scan_tasks = []

    async def scan_with_state_saving(scan_func, target_obj, port, adjacent_open_ports=None):
        try:
            if adjacent_open_ports is not None:
                results = await scan_func(target_obj, port, adjacent_open_ports=adjacent_open_ports)
            else:
                results = await scan_func(target_obj, port)
            for result in results: state_manager.add_vulnerability(result)
            return results
        except Exception as e:
            # Was a bare `except` - that also swallowed KeyboardInterrupt/SystemExit
            # and hid programming bugs. Tolerate scanner runtime errors only.
            _reraise_if_bug(e)
            if os.environ.get("VAKT_DEBUG"):
                print(f"{Colors.YELLOW}[!] Error scanning {target_obj.get('scan_address', '?')}:{port} - {e}{Colors.RESET}")
            return []

    for is_valid, (service, target_obj, port, scanner_func, target_open_ports) in zip(validation_results, service_mapping):
        if isinstance(is_valid, Exception):
            _reraise_if_bug(is_valid)
            if os.environ.get("VAKT_DEBUG"):
                print(f"{Colors.YELLOW}[!] Service validation error for {service} on "
                      f"{target_obj.get('scan_address', '?')}:{port} - {is_valid}{Colors.RESET}")
            continue
        if isinstance(is_valid, bool) and is_valid:
            state_manager.add_validated_service(target_obj['resolved_ip'], port, service)
            adj = target_open_ports if service == 'cpanel' else None
            scan_tasks.append(scan_with_state_saving(scanner_func, target_obj, port, adjacent_open_ports=adj))

    if scan_tasks:
        results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, list): chunk_vulnerabilities.extend(res)
            
    return chunk_vulnerabilities


# ---------------------------------------------------------------------------
# Subcommand handler functions
# ---------------------------------------------------------------------------

async def cmd_scan(args):
    """Handler for `vaktscan scan` - calls the existing main() orchestrator."""
    global _partial_findings
    import ipaddress
    import tempfile

    # --list-resumable: print the resumable-scan index and exit (no target
    # needed). Handled first so it never touches the dashboard or a target.
    if getattr(args, "list_resumable", False):
        from scan_state import format_resumable_table
        print(format_resumable_table())
        return

    if not getattr(args, "target", None):
        print(f"{Colors.RED}[!] scan requires a target (domain, IP, CIDR, or file), "
              f"or use --list-resumable.{Colors.RESET}")
        sys.exit(1)

    from modules.dashboard import LiveDashboard
    dashboard = LiveDashboard()
    if not getattr(args, 'no_dashboard', False):
        dashboard.start()

    target_type = target_classifier(args.target)
    print(f"{Colors.CYAN}[*] Target type: {target_type} - {args.target}{Colors.RESET}")

    if target_type == 'domain' and not is_valid_domain(args.target):
        print(f"{Colors.RED}[!] Error: '{args.target}' is not a valid domain name.{Colors.RESET}")
        sys.exit(1)

    # --tech-only: lightweight web-technology fingerprint + version->CVE only.
    # Runs a minimal pipeline (resolve -> web-port scan -> httpx alive-probe ->
    # tech_fingerprint -> web_tech_cve) and routes findings through the shared
    # finalization tail for NVD/KEV/EPSS/CVSS enrichment + CSV/HTML/JSON/SARIF.
    # Deliberately skips subdomain enum, passive recon, nuclei, dirsearch,
    # web_checks, js/js_cve, domain_scan, archived_urls, service modules, and nmap.
    # Accepts a domain, IP, CIDR, URL, or a --sub-domains/file list. Takes
    # precedence over --posture when both flags are supplied.
    if getattr(args, 'tech_only', False):
        if getattr(args, 'posture', False):
            print(f"{Colors.YELLOW}[*] Both --tech-only and --posture given; "
                  f"running --tech-only (takes precedence).{Colors.RESET}")
        await main(
            targets_file=None,
            concurrency=args.concurrency,
            module_mode='tech-only',
            domain_scan_file=getattr(args, 'sub_domains_file', None) or args.target,
            domain_scan_concurrency=args.concurrency,
            custom_ports=args.ports,
            connect_timeout=args.connect_timeout,
            port_retries=args.port_retries,
            sarif_output=args.sarif,
            output_format=getattr(args, 'format', None),
        )
        return

    # --posture: lightweight domain-posture triage only (formerly the `domain-scan`
    # subcommand) - classification, subdomain-takeover, CORS, and security-header
    # checks on the given domain(s). Skips subdomain enum, port/service scanning,
    # nuclei, and dirsearch. Accepts a domain, a URL, or a --sub-domains/file list.
    if getattr(args, 'posture', False):
        await main(
            targets_file=None,
            concurrency=args.concurrency,
            module_mode='domain-scan',
            domain_scan_file=getattr(args, 'sub_domains_file', None) or args.target,
            domain_scan_concurrency=args.concurrency,
            connect_timeout=args.connect_timeout,
            port_retries=args.port_retries,
            output_format=getattr(args, 'format', None),
        )
        return

    # For file targets: use robust parser then classify each entry
    _file_domains = []
    _file_ips = []
    if target_type == 'file':
        _lines = parse_targets_file(args.target)
        for _line in _lines:
            if target_classifier(_line) == 'domain':
                if is_valid_domain(_line):
                    _file_domains.append(_line)
            else:
                _file_ips.append(_line)
        if _file_domains:
            if args.no_subdomain_enum:
                print(f"{Colors.CYAN}[*] Mixed file: {len(_file_domains)} domain(s), {len(_file_ips)} IP/CIDR(s) - subdomain enum skipped (--no-subdomain-enum){Colors.RESET}")
            else:
                print(f"{Colors.CYAN}[*] Mixed file: {len(_file_domains)} domain(s), {len(_file_ips)} IP/CIDR(s) - subdomain enum will run for domains{Colors.RESET}")

    # Guard against IPv6 CIDR ranges that are too large to scan
    if target_type == 'cidr' and ':' in args.target:
        try:
            stripped_target = args.target.strip('[]')
            net = ipaddress.ip_network(stripped_target, strict=False)
            if isinstance(net, ipaddress.IPv6Network) and net.prefixlen < 112:
                print(f"{Colors.RED}[!] IPv6 CIDR /{net.prefixlen} would scan {net.num_addresses:,} addresses - too large. Use /{112}+ (max 65536 hosts).{Colors.RESET}")
                sys.exit(1)
        except ValueError:
            pass

    # Phase 4: compute the stable state identity BEFORE writing the throwaway
    # temp targets file, so the scan_id derives from the ORIGINAL target + scope
    # config (not the random temp path). This is what makes ad-hoc
    # `scan <ip|domain|cidr>` runs resumable.
    from state_key import (
        canonical_targets as _canonical_targets,
        scope_signature as _scope_signature,
        compute_scan_id as _compute_scan_id,
    )
    _exclude_loaded = load_exclusion_patterns(
        getattr(args, 'exclude', None), getattr(args, 'exclude_file', None)
    )
    _include_only_loaded = load_exclusion_patterns(
        getattr(args, 'include_only', None), getattr(args, 'include_only_file', None)
    )
    _scope_cfg = {
        "module_filter": args.module,
        "ports": args.ports,
        "no_subdomain_enum": bool(getattr(args, 'no_subdomain_enum', False)),
        "dns_permute": bool(getattr(args, 'dns_permute', False)),
        "dns_hygiene": bool(getattr(args, 'dns_hygiene', True)),
        "dns_takeover": bool(getattr(args, 'dns_takeover', True)),
        "company_only": bool(getattr(args, 'company_only', False)),
        "shared_ip_threshold": getattr(args, 'shared_ip_threshold', 10),
        "horizontal": bool(getattr(args, 'horizontal', False)),
        "archived_scan": bool(getattr(args, 'archived_scan', True)),
        "stream_web_probe": bool(getattr(args, 'stream_web_probe', False)),
        "extra_scans": [
            name for name, on in (
                ("params", getattr(args, 'params', False)),
                ("favicon", getattr(args, 'favicon', False)),
                ("tech", not getattr(args, 'no_tech', False)),
                ("default_creds", getattr(args, 'default_creds', False)),
            ) if on
        ],
        "nmap": bool(getattr(args, 'nmap', False)),
        "no_dork": bool(getattr(args, 'no_dork', False)),
        "exclude": _exclude_loaded,
        "include_only": _include_only_loaded,
    }
    _scan_scope = _scope_signature(_scope_cfg)
    _canon_targets = _canonical_targets(target_type, args.target, parse_targets_file)
    _primary_label = (
        os.path.splitext(os.path.basename(args.target))[0]
        if target_type == 'file' else args.target
    )
    _scan_id = _compute_scan_id(_primary_label, _canon_targets, _scan_scope)
    # Non-scope settings tracked in state so a change on resume warns + adopts
    # (never affects the scan id).
    _non_scope_config = {
        "concurrency": args.concurrency,
        "connect_timeout": args.connect_timeout,
        "port_retries": args.port_retries,
        "recon_concurrency": args.recon_concurrency,
        "chunk_size": args.chunk_size,
    }

    # main() expects a targets file path - write single targets to a temp file
    # Name it after the target so domain_label / output dirs are readable
    _tmp_file = None
    targets_file = args.target
    if target_type in ('ip', 'cidr', 'domain'):
        safe_name = re.sub(r'[^\w\.\-]', '_', args.target)[:48]
        _tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.txt', delete=False,
            prefix=f'{safe_name}_', dir=tempfile.gettempdir(),
        )
        _tmp.write(args.target + '\n')
        _tmp.close()
        targets_file = _tmp.name
        _tmp_file = _tmp.name

    try:
        await main(
            targets_file=targets_file,
            concurrency=args.concurrency,
            resume=args.resume,
            fresh=getattr(args, 'fresh', False),
            resume_id=getattr(args, 'resume_id', None),
            primary_target=_primary_label,
            non_scope_config=_non_scope_config,
            module_filter=args.module,
            custom_ports=args.ports,
            chunk_size=args.chunk_size,
            recon_domains=(
                [args.target] if target_type == 'domain' and not args.no_subdomain_enum
                else (_file_domains if _file_domains and not args.no_subdomain_enum else None)
            ),
            wordlist=args.wordlist,
            scan_found=True,  # scan subcommand always probes discovered subdomains
            nmap_enabled=args.nmap,
            subdomains_file=args.sub_domains_file,
            module_mode=None,
            domain_scan_file=None,
            domain_scan_concurrency=50,
            recon_concurrency=args.recon_concurrency,
            connect_timeout=args.connect_timeout,
            port_retries=args.port_retries,
            js_url=None,
            js_timeout=10,
            sarif_output=args.sarif,
            no_dork=getattr(args, 'no_dork', False),
            dork_method=getattr(args, 'dork_method', 'auto'),
            stream_web_probe=getattr(args, 'stream_web_probe', False),
            archived_scan=getattr(args, 'archived_scan', True),
            enable_screenshots=getattr(args, 'screenshots', False),
            enable_horizontal=getattr(args, 'horizontal', False),
            extra_scans=frozenset(
                name for name, on in (
                    ("params", getattr(args, 'params', False)),
                    ("favicon", getattr(args, 'favicon', False)),
                    ("tech", not getattr(args, 'no_tech', False)),
                    ("default_creds", getattr(args, 'default_creds', False)),
                ) if on
            ),
            js_cve_scan=getattr(args, 'js_cve', True),
            output_format=getattr(args, 'format', None),
            dns_hygiene=getattr(args, 'dns_hygiene', True),
            dns_permute=getattr(args, 'dns_permute', False),
            dns_takeover=getattr(args, 'dns_takeover', True),
            exclude_patterns=_exclude_loaded,
            include_only_patterns=_include_only_loaded,
            company_only=getattr(args, 'company_only', False),
            shared_ip_threshold=getattr(args, 'shared_ip_threshold', 10),
            scan_id=_scan_id,
            canonical_targets=_canon_targets,
            scope=_scan_scope,
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        if _partial_findings:
            ts = time.strftime("%Y%m%d_%H%M%S")
            partial_path = f"scan_results_{ts}_PARTIAL.csv"
            save_results_to_csv(_partial_findings, partial_path)
            print(f"\n{Colors.YELLOW}[!] Partial results ({len(_partial_findings)} findings) saved to: {partial_path}{Colors.RESET}")
        raise  # re-raise so run_command()/the outer __main__ handler sees the cancel
    finally:
        if not getattr(args, 'no_dashboard', False):
            dashboard.stop()
        if _tmp_file and os.path.exists(_tmp_file):
            os.unlink(_tmp_file)


async def cmd_enum(args):
    """Handler for `vaktscan enum` - subdomain enumeration only."""
    os.makedirs(args.output_dir, exist_ok=True)

    if not is_valid_domain(args.domain):
        print(f"{Colors.RED}[!] Error: '{args.domain}' is not a valid domain name.{Colors.RESET}")
        sys.exit(1)

    from modules.dashboard import LiveDashboard
    dashboard = LiveDashboard()
    if not getattr(args, 'no_dashboard', False):
        dashboard.start()

    try:
        scanner = recon.ReconScanner(args.domain, output_dir=args.output_dir, wordlist=args.wordlist)
        results_file, subdomains = await scanner.run_all()
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(args.output_dir, f"{args.domain}_subdomains_{ts}.txt")
        with open(out_file, 'w') as f:
            for sub in sorted(subdomains):
                f.write(sub + '\n')
        print(f"{Colors.GREEN}[+] {len(subdomains)} subdomains found. Written to: {out_file}{Colors.RESET}")
        if args.probe:
            await cmd_probe(argparse.Namespace(
                target=out_file,
                ports=None,
                concurrency=args.concurrency,
                timeout=10.0,
                output_dir=args.output_dir,
                no_dashboard=getattr(args, 'no_dashboard', False),
            ))
    finally:
        if not getattr(args, 'no_dashboard', False):
            dashboard.stop()


async def cmd_probe(args):
    """Handler for `vaktscan probe` - httpx + parallel web analysis on a host list or file."""
    os.makedirs(args.output_dir, exist_ok=True)
    if os.path.isfile(args.target):
        targets = parse_targets_file(args.target)
    else:
        targets = [args.target]
    if not targets:
        print(f"{Colors.RED}[!] No targets found: {args.target}{Colors.RESET}")
        return
    recon_domain = targets[0]
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r'[^\w.-]', '_', recon_domain)
    output_dir = os.path.join(args.output_dir, f"probe_{safe_name}_{ts}")
    os.makedirs(output_dir, exist_ok=True)

    from modules.dashboard import LiveDashboard
    dashboard = LiveDashboard()
    if not getattr(args, 'no_dashboard', False):
        dashboard.start()

    print(f"{Colors.CYAN}[*] Probe: {len(targets)} target(s) → {output_dir}{Colors.RESET}")
    try:
        findings = await run_recon_followups(
            subdomains=targets,
            recon_domain=recon_domain,
            output_dir=output_dir,
            concurrency=args.concurrency,
            nmap_enabled=False,
            connect_timeout=args.timeout,
        )
    finally:
        if not getattr(args, 'no_dashboard', False):
            dashboard.stop()

    if findings:
        out_csv = os.path.join(output_dir, f"probe_findings_{ts}.csv")
        save_results_to_csv(findings, out_csv)
        print(f"{Colors.GREEN}[+] Probe complete: {len(findings)} finding(s). CSV: {out_csv}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[+] Probe complete. No findings.{Colors.RESET}")


async def cmd_dns(args):
    """Handler for `vaktscan dns` - DNS recon only."""
    os.makedirs(args.output_dir, exist_ok=True)
    domains = args.domain  # list of domains
    print(f"{Colors.CYAN}[*] DNS recon on {len(domains)} domain(s)...{Colors.RESET}")
    findings = await dns_recon.run_dns_recon(domains, concurrency=args.concurrency)
    if findings:
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(args.output_dir, f"dns_{ts}.csv")
        save_results_to_csv(findings, out_path)
        print(f"{Colors.GREEN}[+] DNS findings: {len(findings)}. CSV: {out_path}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[*] DNS recon complete. No findings.{Colors.RESET}")


async def cmd_cloud(args):
    """Handler for `vaktscan cloud` - cloud asset enum only."""
    os.makedirs(args.output_dir, exist_ok=True)
    print(f"{Colors.CYAN}[*] Cloud enum for: {args.domain}{Colors.RESET}")
    findings = await cloud_enum.enumerate_cloud_assets(args.domain)
    if findings:
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(args.output_dir, f"cloud_{ts}.csv")
        save_results_to_csv(findings, out_path)
        print(f"{Colors.GREEN}[+] Cloud findings: {len(findings)}. CSV: {out_path}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[*] Cloud enum complete. No findings.{Colors.RESET}")


async def cmd_js_paths(args):
    """Handler for `vaktscan js-paths` - JS path extraction only."""
    os.makedirs(args.output_dir, exist_ok=True)
    # Build URL list from target (file or single URL)
    if os.path.isfile(args.target):
        with open(args.target) as f:
            urls = [l.strip() for l in f if l.strip()]
    else:
        urls = [args.target]
    scanner_js = js_paths.JSPathsScanner(urls, threads=args.threads, timeout=args.timeout)
    result = await scanner_js.run()
    findings = result.get('findings', []) if isinstance(result, dict) else result
    if findings:
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(args.output_dir, f"js_paths_{ts}.csv")
        save_results_to_csv(findings, out_path)
        print(f"{Colors.GREEN}[+] JS path findings: {len(findings)}. CSV: {out_path}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[*] JS paths complete. No findings.{Colors.RESET}")


async def cmd_google_dork(args):
    """Handler for `vaktscan google-dork` - Google Dorking passive recon."""
    if args.method == "api" and (not args.google_api_key or not args.google_cx):
        print(f"{Colors.RED}[!] --google-api-key and --google-cx are required for 'api' method (or set GOOGLE_API_KEY / GOOGLE_CX env vars){Colors.RESET}")
        sys.exit(1)
    os.makedirs(args.output_dir, exist_ok=True)
    findings = await google_dork.run(
        domain=args.domain,
        api_key=args.google_api_key,
        cx=args.google_cx,
        dorks=args.dorks,
        delay=args.delay,
        max_results=args.max_results,
        method=args.method,
    )
    if findings:
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(args.output_dir, f"google_dork_{ts}.csv")
        save_results_to_csv(findings, out_path)
        print(f"{Colors.GREEN}[+] Google Dork findings: {len(findings)}. CSV: {out_path}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[*] Google Dork complete. No findings.{Colors.RESET}")


def run_command(coro):
    """Single top-level runner for every subcommand coroutine.

    Installs SIGINT/SIGTERM handlers on the running loop (POSIX only). The first
    signal requests a graceful cancel of the main task -- coroutines unwind,
    `except asyncio.CancelledError` handlers checkpoint state, and child process
    groups are torn down. A second signal force-kills every live child group and
    exits 130. `kill_all_process_groups()` in the `finally` is an orphan safety
    net for any spawn site whose own cleanup was bypassed.
    """
    async def _runner():
        loop = asyncio.get_running_loop()
        main_task = asyncio.current_task()
        hits = {"n": 0}

        def _on_signal():
            hits["n"] += 1
            if hits["n"] == 1:
                print("\n[!] Interrupt - cancelling scan, cleaning up child "
                      "processes... (Ctrl+C again to force-quit)")
                main_task.cancel()
            else:
                print("\n[!] Second interrupt - force-killing children.")
                proc.kill_all_process_groups()
                os._exit(130)

        if sys.platform != "win32":
            for s in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(s, _on_signal)
        try:
            return await coro
        except asyncio.CancelledError:
            print("[!] Scan cancelled. State checkpointed; use --resume to continue.")
        finally:
            proc.kill_all_process_groups()   # safety net for orphaned child groups

    return asyncio.run(_runner())


if __name__ == "__main__":
    print_logo()

    # --- Root parser ---
    parser = argparse.ArgumentParser(
        prog="vaktscan",
        description="VaktScan - Attack Surface Scanner",
    )
    subparsers = parser.add_subparsers(dest="subcommand", metavar="COMMAND")
    subparsers.required = True

    # ---- scan subcommand ----
    sp_scan = subparsers.add_parser("scan", help="Full attack surface scan")
    sp_scan.add_argument("target", nargs="?", default=None,
                         help="Domain, IP, CIDR, or targets file (optional with --list-resumable)")
    sp_scan.add_argument("-c", "--concurrency", type=int, default=100)
    sp_scan.add_argument("--connect-timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT)
    sp_scan.add_argument("--port-retries", type=int, default=DEFAULT_PORT_RETRIES)
    # Resume UX (Phase 5). Default is AUTO-RESUME: the scan id is recomputed from
    # the target + scope and a matching, non-completed state is resumed with a
    # notice. --resume REQUIRES such a state (errors if none); --fresh ignores &
    # overwrites it; --resume-id resumes a specific saved scan; --list-resumable
    # prints the index and exits.
    sp_scan.add_argument("-r", "--resume", action="store_true",
                         help="Require and resume an existing state (error if none exists)")
    sp_scan.add_argument("--fresh", "--no-resume", action="store_true", dest="fresh",
                         help="Ignore and overwrite any existing resumable state for this target")
    sp_scan.add_argument("--resume-id", metavar="SCAN_ID", dest="resume_id", default=None,
                         help="Resume a specific saved scan by id (see --list-resumable)")
    sp_scan.add_argument("--list-resumable", action="store_true", dest="list_resumable",
                         help="List resumable scans (id, target, phase, progress, age) and exit")
    sp_scan.add_argument("--format",
        choices=["csv", "json", "sarif", "all"],
        default=None,
        help="CSV + HTML reports are ALWAYS written by default; pass json/sarif/all "
             "to additionally emit those machine-readable formats")
    sp_scan.add_argument("--sarif", metavar="FILE", default=None)
    sp_scan.add_argument("-m", "--module",
        choices=["elasticsearch", "kibana", "grafana", "prometheus", "nextjs",
                 "aem", "cpanel", "jenkins", "service_recon"],
        help="Run only this service module (all modules by default)")
    sp_scan.add_argument("--ports", type=str)
    sp_scan.add_argument("--chunk-size", type=int, default=30000)
    sp_scan.add_argument("--stream-web-probe", action="store_true", dest="stream_web_probe",
                         help="In streaming mode (large target sets >1000 hosts), also run "
                              "httpx/nuclei/dirsearch/web-checks on open web ports per chunk "
                              "(off by default - can expand to a very large number of URLs)")
    sp_scan.add_argument("--no-archived-scan", action="store_false", dest="archived_scan", default=True,
                         help="Skip weaponizing gau/waybackurls archived URLs (dedup → filter → "
                              "re-probe live → secret-scan archived JS). On by default.")
    sp_scan.add_argument("--no-js-cve", action="store_false", dest="js_cve", default=True,
                         help="Skip the client-side JavaScript CVE scan (Retire.js engine) over the "
                              "JS VaktScan already discovers. On by default; silently no-ops if the "
                              "bundled vulnerability DB is absent.")
    sp_scan.add_argument("--screenshots", action="store_true", dest="screenshots",
                         help="Screenshot alive web URLs for visual triage via gowitness/aquatone "
                              "(off by default; capped; skips if the tool isn't installed)")
    sp_scan.add_argument("--horizontal", action="store_true", dest="horizontal",
                         help="Horizontal/infra expansion for domain targets: asnmap → CIDRs, "
                              "reverse-DNS sweep, amass intel → related domains (off by default; "
                              "skips tools that aren't installed)")
    sp_scan.add_argument("--params", action="store_true", dest="params",
                         help="Parameter discovery on alive URLs (arjun/paramspider/gf) → INFO param surface")
    sp_scan.add_argument("--favicon", action="store_true", dest="favicon",
                         help="Favicon mmh3 hash + JARM fingerprint on alive URLs (Shodan/Censys pivots)")
    sp_scan.add_argument("--tech", action="store_true", dest="tech",
                         help="(Default ON) Technology fingerprint + EOL + version->CVE on alive URLs (webanalyze + endoflife.date). Kept for back-compat; tech now runs by default.")
    sp_scan.add_argument("--no-tech", action="store_true", dest="no_tech",
                         help="Disable the default technology fingerprint / EOL / web-tech CVE pass")
    sp_scan.add_argument("--default-creds", action="store_true", dest="default_creds",
                         help="Confirmed default-credential checks on alive URLs (Tomcat/Jenkins/Grafana/Basic-Auth)")
    sp_scan.add_argument("--no-dns-hygiene", action="store_false", dest="dns_hygiene", default=True,
                         help="Disable the default DNS wildcard-filtering of enumerated subdomains "
                              "(puredns/massdns; passthrough if not installed). On by default.")
    sp_scan.add_argument("--dns-permute", action="store_true", dest="dns_permute",
                         help="Additionally generate + resolve subdomain permutations (alterx/dnsgen) "
                              "during DNS hygiene - can greatly expand the host set")
    sp_scan.add_argument("--no-dns-takeover", action="store_false", dest="dns_takeover", default=True,
                         help="Disable the per-subdomain DNS-level takeover check (dangling CNAME -> "
                              "NXDOMAIN across all discovered subdomains). On by default.")
    sp_scan.add_argument("--exclude", action="append", metavar="PATTERN", dest="exclude",
                         help="Exclude hosts matching this glob (e.g. 'customer1*.homestead.com') from "
                              "scanning - they stay in the enumerated subdomain list but are never "
                              "resolved/probed/scanned. Repeatable; prefix 're:' for a regex.")
    sp_scan.add_argument("--exclude-file", metavar="FILE", dest="exclude_file",
                         help="File of exclusion patterns, one per line (# comments allowed). See --exclude.")
    sp_scan.add_argument("--include-only", action="append", metavar="PATTERN", dest="include_only",
                         help="Allowlist: scan ONLY hosts matching this glob/regex (see --exclude syntax). "
                              "Repeatable. Applied after --exclude.")
    sp_scan.add_argument("--include-only-file", metavar="FILE", dest="include_only_file",
                         help="File of --include-only patterns, one per line.")
    sp_scan.add_argument("--company-only", action="store_true", dest="company_only",
                         help="Skip customer/shared-hosting sites: resolve every subdomain, and drop hosts "
                              "that sit on a shared hosting IP (a website-builder platform), keeping only the "
                              "company's own assets (distinct IPs + functional-named hosts like www/api/mail). "
                              "Writes company_assets.txt / customer_sites.txt. Runs after --exclude/--include-only.")
    sp_scan.add_argument("--shared-ip-threshold", type=int, default=10, dest="shared_ip_threshold",
                         metavar="N",
                         help="For --company-only: an IP hosting N or more subdomains is treated as shared "
                              "hosting (its hosts = customer sites). Default: 10.")
    sp_scan.add_argument("--wordlist")
    # --scan-found removed: the scan subcommand always probes discovered subdomains
    sp_scan.add_argument("--nmap", action="store_true")
    sp_scan.add_argument("--sub-domains", metavar="FILE", dest="sub_domains_file")
    sp_scan.add_argument("--recon-concurrency", type=int, default=2)
    sp_scan.add_argument("--posture", action="store_true", dest="posture",
                         help="Domain-posture triage ONLY: internal/external classification, "
                              "subdomain-takeover, CORS, and security-header checks on the target "
                              "domain(s). Skips subdomain enum, port/service scanning, nuclei, and "
                              "dirsearch - fast triage of a domain or a --sub-domains/file list. "
                              "(Replaces the old `domain-scan` subcommand.)")
    sp_scan.add_argument("--tech-only", action="store_true", dest="tech_only",
                         help="Lightweight mode: ONLY web-tech fingerprint + version->CVE "
                              "(skips subdomain enum, nuclei, dirsearch, web_checks, js, "
                              "domain_scan, archived, service modules, nmap).")
    sp_scan.add_argument("--no-subdomain-enum", action="store_true", dest="no_subdomain_enum",
        help="Skip subdomain enumeration for domain targets")
    sp_scan.add_argument("--no-dashboard", action="store_true", help="Disable the multi-row live progress dashboard")
    sp_scan.add_argument("--proxy", metavar="URL", default=None)
    sp_scan.add_argument("--update-templates", action="store_true", dest="update_templates")
    sp_scan.add_argument("--no-dork", action="store_true", help="Skip Google Dorking passive recon")
    sp_scan.add_argument("--dork-method", choices=["api", "playwright", "html", "auto"], default="auto",
                         help="Search method for Google Dorking (default: auto)")

    # ---- enum subcommand ----
    sp_enum = subparsers.add_parser("enum", help="Subdomain enumeration only")
    sp_enum.add_argument("domain", help="Apex domain to enumerate")
    sp_enum.add_argument("-c", "--concurrency", type=int, default=20)
    sp_enum.add_argument("--wordlist")
    sp_enum.add_argument("--output-dir", default="reports/")
    sp_enum.add_argument("--probe", action="store_true", help="Chain into probe after enum")
    sp_enum.add_argument("--no-dashboard", action="store_true", help="Disable the multi-row live progress dashboard")

    # ---- probe subcommand ----
    sp_probe = subparsers.add_parser("probe", help="Port scan + httpx probe")
    sp_probe.add_argument("target", help="Domain, IP, CIDR, or file")
    sp_probe.add_argument("--ports", type=str)
    sp_probe.add_argument("-c", "--concurrency", type=int, default=50)
    sp_probe.add_argument("--timeout", type=float, default=10.0)
    sp_probe.add_argument("--no-dashboard", action="store_true", help="Disable the multi-row live progress dashboard")
    sp_probe.add_argument("--output-dir", default="reports/")
    sp_probe.add_argument("--proxy", metavar="URL", default=None, help="Route traffic through proxy (e.g. http://127.0.0.1:8080)")

    # ---- dns subcommand ----
    sp_dns = subparsers.add_parser("dns", help="DNS recon only")
    sp_dns.add_argument("domain", nargs="+", help="Domain(s) to recon")
    sp_dns.add_argument("-c", "--concurrency", type=int, default=20)
    sp_dns.add_argument("--output-dir", default="reports/")

    # ---- cloud subcommand ----
    sp_cloud = subparsers.add_parser("cloud", help="Cloud asset enumeration")
    sp_cloud.add_argument("domain", help="Apex domain")
    sp_cloud.add_argument("-c", "--concurrency", type=int, default=50)
    sp_cloud.add_argument("--output-dir", default="reports/")

    # ---- js-paths subcommand ----
    sp_js = subparsers.add_parser("js-paths", help="JS path extraction")
    sp_js.add_argument("target", help="Single URL or file of URLs")
    sp_js.add_argument("--threads", type=int, default=20)
    sp_js.add_argument("--timeout", type=int, default=10)
    sp_js.add_argument("--output-dir", default="reports/")

    # ---- domain-scan subcommand ----
    # NOTE: the standalone `domain-scan` subcommand was merged into `scan --posture`.

    # ---- google-dork subcommand ----
    sp_dork = subparsers.add_parser("google-dork", help="Google Dorking passive recon")
    sp_dork.add_argument("domain", help="Target domain")
    sp_dork.add_argument("--google-api-key", default=os.environ.get("GOOGLE_API_KEY", ""))
    sp_dork.add_argument("--google-cx", default=os.environ.get("GOOGLE_CX", ""))
    sp_dork.add_argument("--dorks", metavar="FILE", default=None)
    sp_dork.add_argument("--output-dir", default="reports/")
    sp_dork.add_argument("--delay", type=float, default=1.0)
    sp_dork.add_argument("--max-results", type=int, default=10)
    sp_dork.add_argument("--method", choices=["api", "playwright", "html", "auto"], default="auto",
                         help="Search method: api, playwright, html, or auto (default: auto)")
    sp_dork.add_argument("--proxy", metavar="URL", default=None, help="Route traffic through proxy (e.g. http://127.0.0.1:8080)")

    args = parser.parse_args()

    # --- Shared setup ---
    if hasattr(args, 'proxy') and args.proxy:
        os.environ['HTTP_PROXY'] = args.proxy
        os.environ['HTTPS_PROXY'] = args.proxy
        os.environ['ALL_PROXY'] = args.proxy
        print(f"[*] Proxy set: {args.proxy} (HTTP_PROXY / HTTPS_PROXY / ALL_PROXY)")

    if hasattr(args, 'update_templates') and args.update_templates:
        nuclei_runner.sync_nuclei_templates()

    try:
        if args.subcommand == "scan":
            run_command(cmd_scan(args))
        elif args.subcommand == "enum":
            run_command(cmd_enum(args))
        elif args.subcommand == "probe":
            run_command(cmd_probe(args))
        elif args.subcommand == "dns":
            run_command(cmd_dns(args))
        elif args.subcommand == "cloud":
            run_command(cmd_cloud(args))
        elif args.subcommand == "js-paths":
            run_command(cmd_js_paths(args))
        elif args.subcommand == "google-dork":
            run_command(cmd_google_dork(args))
    except KeyboardInterrupt:
        print("\n[*] Scanner terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        # Always surface the traceback for an uncaught error so bugs are
        # diagnosable instead of collapsing to a one-line message.
        traceback.print_exc()
        sys.exit(1)
