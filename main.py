import asyncio
import argparse
import sys
import os
import re
import signal
import time

# Load .env if present (optional dependency — silently skipped if not installed)
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
    parse_targets_file,
    process_targets,
    process_targets_streaming,
    resolve_hostnames,
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
)

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


async def run_recon_followups(
    subdomains,
    recon_domain,
    output_dir,
    concurrency,
    nmap_enabled,
    wordlist=None,
    connect_timeout=DEFAULT_CONNECT_TIMEOUT,
    port_retries=DEFAULT_PORT_RETRIES,
):
    """Run HTTPX, dirsearch, nuclei, and optional Nmap on recon results."""
    all_findings = []

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

    if nmap_enabled and recon_targets:
        print(
            f"{Colors.BRIGHT_MAGENTA}[*] Running background full-range port scan "
            f"(1-65535) to prep Nmap follow-up...{Colors.RESET}"
        )
        full_port_range = list(range(1, 65536))
        full_port_scan_task = asyncio.create_task(
            scan_ports(
                recon_targets,
                full_port_range,
                concurrency,
                state_manager=None,
                connect_timeout=connect_timeout,
                retries=port_retries,
            )
        )

        async def _nmap_followup():
            full_results = await full_port_scan_task
            ip_port_map = {}
            ip_host_map = {}
            for target_obj, data in full_results:
                open_ports = data.get('open_ports', [])
                if not open_ports:
                    continue
                ip = target_obj.get('resolved_ip') or target_obj.get('scan_address')
                host = next(iter(ip_to_hosts.get(ip, [])), target_obj.get('display_target') or ip)
                if not ip:
                    continue
                ip_port_map.setdefault(ip, set()).update(open_ports)
                ip_host_map.setdefault(ip, host)
            nmap_jobs = [
                (ip, sorted(ports), ip_host_map.get(ip, ip))
                for ip, ports in ip_port_map.items()
            ]
            if not nmap_jobs:
                print(
                    f"{Colors.YELLOW}[!] No open ports discovered during full-range scan; "
                    f"skipping Nmap follow-up.{Colors.RESET}"
                )
                return
            print(
                f"{Colors.CYAN}[*] Starting Nmap follow-up for {len(nmap_jobs)} host(s)...{Colors.RESET}"
            )
            nmap_inst = nmap_runner.NmapRunner(output_base_dir=output_dir)
            await nmap_inst.run_batch(nmap_jobs, concurrency=concurrency)
            nmap_cve_findings = await nmap_inst.run_cve_scan_batch(nmap_jobs, concurrency=concurrency)
            if nmap_cve_findings:
                all_findings.extend(nmap_cve_findings)
            print(
                f"{Colors.GREEN}[+] Nmap follow-up completed for {len(nmap_jobs)} host(s).{Colors.RESET}"
            )

        nmap_followup_task = asyncio.create_task(_nmap_followup())
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
    
    # Run domain scanner, dirsearch, nuclei, web checks, and JS paths concurrently —
    # all are read-only against alive_urls and write to their own files in output_dir.
    if alive_urls:
        print(f"{Colors.CYAN}[*] Running domain scanner, dirsearch, nuclei, web checks, and JS paths in parallel on {len(alive_urls)} URL(s)...{Colors.RESET}")
        nuclei_inst = nuclei_runner.NucleiRunner(output_dir=output_dir)
        js_scanner = js_paths.JSPathsScanner(alive_urls, output_dir=output_dir)

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

        if isinstance(domain_scan_findings, Exception):
            print(f"{Colors.YELLOW}[!] Domain scanner error: {domain_scan_findings}{Colors.RESET}")
            domain_scan_findings = []
        if domain_scan_findings:
            print(f"{Colors.GREEN}[+] Domain scanner identified {len(domain_scan_findings)} web issues.{Colors.RESET}")
            for finding in domain_scan_findings:
                print(f"    - {finding['status']} | {finding['vulnerability']} | {finding['url']}")
            all_findings.extend(domain_scan_findings)
            save_results_to_csv(domain_scan_findings, filename=os.path.join(output_dir, f"domain_scan_vulns_{time.strftime('%Y%m%d_%H%M%S')}.csv"))

        if isinstance(nuclei_results, Exception):
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
            print(f"{Colors.YELLOW}[!] Web checks error: {wc_results}{Colors.RESET}")
            wc_results = []
        if wc_results:
            print(f"{Colors.GREEN}[+] Web checks: {len(wc_results)} finding(s).{Colors.RESET}")
            all_findings.extend(wc_results)
        else:
            print(f"{Colors.GREEN}[+] Web checks complete. No findings.{Colors.RESET}")

        if isinstance(js_result, Exception):
            print(f"{Colors.YELLOW}[!] JS paths error: {js_result}{Colors.RESET}")
            js_result = []
        js_findings = js_result.get('findings', []) if isinstance(js_result, dict) else (js_result or [])
        if js_findings:
            print(f"{Colors.GREEN}[+] JS paths: {len(js_findings)} finding(s).{Colors.RESET}")
            all_findings.extend(js_findings)

    # GAU + waybackurls in parallel
    domain_hosts = collect_domain_hosts(alive_urls)
    if domain_hosts:
        print(f"{Colors.CYAN}[*] Harvesting archived URLs for {len(domain_hosts)} host(s) (gau + waybackurls in parallel)...{Colors.RESET}")
        gau_inst = gau_runner.GAURunner(output_dir=output_dir)
        wayback_inst = waybackurls_runner.WaybackURLsRunner(output_dir=output_dir)
        await asyncio.gather(
            gau_inst.run(domain_hosts),
            wayback_inst.run(domain_hosts),
            return_exceptions=True,
        )
    else:
        print(f"{Colors.YELLOW}[!] No hostname targets available for gau/waybackurls.{Colors.RESET}")

    await _await_nmap_task()
    return all_findings

def load_subdomains_file(file_path):
    """Load targets from a file using the robust parse_targets_file parser."""
    entries = parse_targets_file(file_path)
    if not entries:
        print(f"{Colors.YELLOW}[!] File '{file_path}' contained no usable targets after normalization.{Colors.RESET}")
    return entries


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

async def _run_parallel_passive(domain: str, concurrency: int = 20) -> tuple:
    """Run DNS recon, cloud enum, and CT monitoring in parallel for a domain.

    Returns (dns_findings, cloud_findings, ct_findings).
    """
    dns_f, cloud_f, ct_f = await asyncio.gather(
        dns_recon.run_dns_recon([domain], concurrency=concurrency),
        cloud_enum.enumerate_cloud_assets(domain),
        ct_monitor.check_new_certificates(domain),
        return_exceptions=True,
    )
    if isinstance(dns_f, Exception):
        print(f"[!] DNS recon error: {dns_f}")
        dns_f = []
    if isinstance(cloud_f, Exception):
        print(f"[!] Cloud enum error: {cloud_f}")
        cloud_f = []
    if isinstance(ct_f, Exception):
        print(f"[!] CT monitor error: {ct_f}")
        ct_f = []
    return dns_f, cloud_f, ct_f


async def main(
    targets_file,
    concurrency,
    resume=False,
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
):
    """
    Main orchestrator for the scanning tool.
    """
    # Set up signal handlers
    def signal_handler():
        print(f"\n[!] Received interrupt signal. Shutting down gracefully...")
        raise KeyboardInterrupt
    
    if sys.platform != 'win32':
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, signal_handler)
    
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
                # It's an IP/CIDR — skip for cloud enum
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
                    f"{f['vulnerability']} — {Colors.UNDERLINE}{f['url']}{Colors.RESET}"
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

    # --- DOMAIN SCAN MODE ---
    if module_mode == 'domain-scan':
        target_file = domain_scan_file or subdomains_file
        if not target_file:
            print(f"{Colors.RED}[!] Error: -m domain-scan requires a domains file via --ds-file <file> or --sub-domains <file>.{Colors.RESET}")
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
        
        if findings:
            save_results_to_csv(findings, filename=os.path.join(output_dir, f"domain_scan_vulns_{time.strftime('%Y%m%d_%H%M%S')}.csv"))

        print(f"{Colors.GREEN}[+] Domain scan module completed.{Colors.RESET}")
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
        )
        if recon_findings:
            print(f"{Colors.GREEN}[+] Recon pipeline: {len(recon_findings)} total finding(s) from {safe_label}{Colors.RESET}")
            for _f in recon_findings:
                state_manager.add_vulnerability(_f)
        return

    # --- RECONNAISSANCE MODE (-m recon or --sub-domains WITH a recon domain) ---
    recon_targets_label = None
    if recon_domains:
        normalized_domains = []
        seen_domains = set()
        for domain in expand_recon_inputs(recon_domains):
            domain = domain.strip().lower()
            if not domain:
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
            )
            if recon_findings:
                print(f"{Colors.GREEN}[+] Recon pipeline: {len(recon_findings)} total finding(s) from {recon_domain}{Colors.RESET}")
                for _f in recon_findings:
                    state_manager.add_vulnerability(_f)
            recon_targets_file = dedup_file
            recon_targets_count = len(unique_subdomains)
            recon_targets_label = dedup_file
        else:
            print(f"{Colors.CYAN}[*] Running passive recon for {len(normalized_domains)} domain(s) concurrently...{Colors.RESET}")
            print(f"{Colors.GRAY}[*] Toolchain: Amass, Subfinder, Assetfinder, Findomain, Sublist3r, Knockpy, bbot, Censys, crtsh + DirEnumerator(ffuf){Colors.RESET}")
            tool_limit = getattr(recon, "TOOL_CONCURRENCY_LIMIT", None)
            if tool_limit:
                print(f"{Colors.GRAY}[*] Recon tool concurrency capped at {tool_limit} parallel process(es) "
                      f"(set VAKT_RECON_TOOL_LIMIT to adjust).{Colors.RESET}")

            async def handle_domain(domain):
                print(f"{Colors.CYAN}[*] Enumerating subdomains for {domain}...{Colors.RESET}")
                scanner = recon.ReconScanner(domain, wordlist=wordlist)

                # Run subdomain enum and Google Dork in parallel
                _gapi_key = os.environ.get('GOOGLE_API_KEY', '')
                _gcx     = os.environ.get('GOOGLE_CX', '')

                async def _maybe_dork():
                    if getattr(args, 'no_dork', False):
                        return []
                    print(f"{Colors.CYAN}[*] Google Dork recon running in parallel for {domain}...{Colors.RESET}")
                    dork_method = getattr(args, 'dork_method', 'auto')
                    return await google_dork.run(
                        domain, api_key=_gapi_key, cx=_gcx,
                        method=dork_method
                    )

                (enum_result, dork_findings, passive_tuple) = await asyncio.gather(
                    scanner.run_all(),
                    _maybe_dork(),
                    _run_parallel_passive(domain, concurrency),
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
                    )
                    if recon_findings:
                        print(f"{Colors.GREEN}[+] Recon pipeline: {len(recon_findings)} total finding(s) from {domain}{Colors.RESET}")
                        for _f in recon_findings:
                            state_manager.add_vulnerability(_f)
                else:
                    print(f"{Colors.GRAY}[*] Recon ({domain}) complete. Use --scan-found to automatically probe recon targets (httpx → dirsearch → nuclei).{Colors.RESET}")
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
                    print(f"{Colors.RED}[!] Recon error: {result}{Colors.RESET}")

            if not successes:
                print(f"{Colors.RED}[!] Recon finished with no usable targets.{Colors.RESET}")
                return

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
                    return
                print(f"{Colors.GRAY}[*] Combined recon targets saved to {combined_file}{Colors.RESET}")
                recon_targets_file = combined_file
                recon_targets_count = len(combined_targets)
                recon_targets_label = combined_file

        if recon_targets_count == 0:
            print(f"{Colors.YELLOW}[!] Recon input did not yield any valid targets. Exiting.{Colors.RESET}")
            return

        if targets_file:
            print(f"{Colors.YELLOW}[!] Ignoring provided targets file because -m recon supplies its own target set.{Colors.RESET}")
        targets_file = recon_targets_file
        print(
            f"{Colors.CYAN}[*] Continuing with full service scanning for {recon_targets_count} recon target(s) "
            f"from {recon_targets_label}.{Colors.RESET}"
        )

    # --- MAIN SCANNING LOGIC ---
    if not targets_file:
        print(f"{Colors.RED}[!] Error: No targets file provided and --recon not used.{Colors.RESET}")
        print("Usage: python main.py <targets_file> OR python main.py --recon <domain>")
        return

    # Initialize state manager
    state_manager = ScanStateManager(targets_file, concurrency)

    # Inventory: initialise DB and open a new scan run
    inventory.init_db()
    run_id = inventory.start_scan_run(targets_file or 'recon')

    try:
        # Load existing state or start fresh
        is_resume = resume or state_manager.load_existing_state()
        
        if is_resume:
            print(f"{Colors.CYAN}[*] Resuming VaktScan...{Colors.RESET}")
        else:
            print(f"{Colors.CYAN}[*] Starting VaktScan - Nordic Security Scanner...{Colors.RESET}")

        # 1. Process targets — use robust parser (handles schemas, comments,
        #    inline comments, commas, tabs, BOM, encoding issues, etc.)
        raw_targets = parse_targets_file(targets_file)

        should_stream = len(raw_targets) > 1000

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
                print(f"[!] An error occurred during target processing: {e}")
                return
        else:
            print(f"[*] Using previously processed {state_manager.state.get('total_targets', 'N/A')} targets.")
            targets = await process_targets(raw_targets) 

        if not targets:
            print("[!] No valid targets to scan. Exiting.")
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

        # --- STANDARD PORT SCAN LOGIC ---
        if state_manager.state["phase"] in ["initializing", "target_processing_complete", "port_scanning"]:
            state_manager.set_totals(len(targets), len(targets) * len(all_ports_to_scan))
            
            print(f"{Colors.CYAN}[*] Starting concurrent port scan for {len(targets)} targets across {len(all_ports_to_scan)} unique ports...{Colors.RESET}")
            state_manager.update_phase("port_scanning")
            
            open_ports_results = await scan_ports(
                targets,
                all_ports_to_scan,
                concurrency,
                state_manager,
                connect_timeout=connect_timeout,
                retries=port_retries,
            )
            print(f"{Colors.GREEN}[+] Port scanning complete.{Colors.RESET}")
            state_manager.update_phase("port_scanning_complete")
            domain_label = os.path.splitext(os.path.basename(targets_file))[0]

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

            # If Nmap is enabled, run Nmap CVE script scan on open ports
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

            # Run httpx + nuclei on any open web ports found (80, 443, 8080, etc.)
            # These ports have no specific service module — probe them directly.
            web_port_set = set(full_service_ports.get("web", []))
            web_probe_urls = []
            for target_obj, data in open_ports_results:
                for port in data.get("open_ports", []):
                    if port in web_port_set:
                        host = target_obj.get("display_target") or target_obj.get("scan_address")
                        for scheme in ("http", "https"):
                            from utils import format_url
                            web_probe_urls.append(format_url(scheme, host, port))
            web_probe_urls = sorted(set(web_probe_urls))

            if web_probe_urls:
                print(f"{Colors.CYAN}[*] Probing {len(web_probe_urls)} open web port URL(s) with httpx...{Colors.RESET}")
                http_runner = httpx_runner.HTTPXRunner(output_dir=web_output_dir)
                httpx_data = await http_runner.run_httpx(web_probe_urls, concurrency)
                if httpx_data:
                    http_runner.save_csv(httpx_data, domain_label)
                    alive_urls = sorted({e.get("url") for e in httpx_data if e.get("url")})
                    print(f"{Colors.GREEN}[+] {len(alive_urls)} alive web URL(s) found.{Colors.RESET}")
                    if alive_urls:
                        nuclei_inst = nuclei_runner.NucleiRunner(output_dir=web_output_dir)
                        nuclei_results = await nuclei_inst.run_nuclei(alive_urls)
                        if nuclei_results:
                            print(f"{Colors.GREEN}[+] Nuclei: {len(nuclei_results)} finding(s).{Colors.RESET}")
                            for v in nuclei_results:
                                state_manager.add_vulnerability(v)
                        wc_results = await web_checks.run_checks(alive_urls, concurrency)
                        if wc_results:
                            print(f"{Colors.GREEN}[+] Web checks: {len(wc_results)} finding(s).{Colors.RESET}")
                            for v in wc_results:
                                state_manager.add_vulnerability(v)

                        # dirsearch
                        dir_enumerator = dir_enum.DirEnumerator(domain_label, output_dir=web_output_dir)
                        await dir_enumerator.run_dirsearch(alive_urls)

                        # JS path extraction
                        js_scanner = js_paths.JSPathsScanner(alive_urls, output_dir=web_output_dir)
                        js_result = await js_scanner.run()
                        js_findings = js_result.get('findings', []) if isinstance(js_result, dict) else (js_result or [])
                        for _jf in js_findings:
                            state_manager.add_vulnerability(_jf)
                else:
                    print(f"{Colors.YELLOW}[!] No alive web services found on open web ports.{Colors.RESET}")
        else:
            print(f"[*] Using previously scanned port results...")
            open_ports_results = {}
            for target in targets:
                resolved_ip = target['resolved_ip']
                open_ports_results[resolved_ip] = {'open_ports': state_manager.state["open_ports"].get(resolved_ip, [])}
    
    except KeyboardInterrupt:
        print(f"\n[!] Scan interrupted. Saving final state...")
        state_manager.flush_pending_saves()
        print(f"[+] State saved to {state_manager.state_file}")
        print("[!] Use --resume to continue this scan later.")
        return

    # 3. Validate services and create tasks for service-specific scanners
    if state_manager.state["phase"] in ["port_scanning_complete", "full_port_scanning", "service_validation"]:
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
            
            # This logic works perfectly with Full Scan results too.
            # It checks if the open ports found (e.g., 9200) match our service definitions.
            for port in data['open_ports']:
                for service, service_ports_list in service_ports.items():
                    if port in service_ports_list:
                        scanner_func = SERVICE_TO_MODULE[service].run_scans
                        validation_tasks.append(validate_service(service, target_obj, port))
                        service_mapping.append((service, target_obj, port, scanner_func))

                if custom_ports and port not in [p for ports in service_ports.values() for p in ports]:
                    for service_name in SERVICE_TO_MODULE.keys():
                        if module_filter is None or service_name == module_filter:
                            scanner_func = SERVICE_TO_MODULE[service_name].run_scans
                            validation_tasks.append(validate_service(service_name, target_obj, port))
                            service_mapping.append((service_name, target_obj, port, scanner_func))
        
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

            async def scan_with_state_saving(scan_func, target_obj, port):
                try:
                    results = await scan_func(target_obj, port)
                    for result in results:
                        state_manager.add_vulnerability(result)
                    return results
                except Exception as e:
                    # print(f"[!] Error scanning {target_obj['scan_address']}:{port} - {e}")
                    return []

            for is_valid, (service, target_obj, port, scanner_func) in zip(validation_results, service_mapping):
                if isinstance(is_valid, bool) and is_valid:
                    display_url = target_obj['scan_address']
                    if not display_url.startswith(('http://', 'https://')):
                        display_url = f"http://{display_url}:{port}"
                    print(f"  -> Running {service.capitalize()} scans on {display_url} [Port: {port}]")
                    state_manager.add_validated_service(target_obj['resolved_ip'], port, service)
                    scan_tasks.append(scan_with_state_saving(scanner_func, target_obj, port))
                    validated_services += 1
            
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

    # 3b. Cloud asset enumeration for domain targets
    # Run after service scanning; only for non-IP targets (domains).
    if not module_filter or module_filter == 'cloud':
        domain_targets_for_cloud = []
        for t in targets:
            host = t.get('display_target') or t.get('scan_address', '')
            if not host:
                continue
            try:
                import ipaddress as _ipa
                _ipa.ip_network(host, strict=False)
                continue  # skip raw IPs
            except ValueError:
                pass
            domain_targets_for_cloud.append(host)
        domain_targets_for_cloud = list(dict.fromkeys(domain_targets_for_cloud))
        if domain_targets_for_cloud:
            print(
                f"{Colors.CYAN}[*] Running cloud asset enumeration on "
                f"{len(domain_targets_for_cloud)} domain target(s)...{Colors.RESET}"
            )
            for _cloud_domain in domain_targets_for_cloud:
                _cloud_findings = await cloud_enum.enumerate_cloud_assets(
                    _cloud_domain, concurrency=concurrency
                )
                for _cf in _cloud_findings:
                    state_manager.add_vulnerability(_cf)
            print(f"{Colors.GREEN}[+] Cloud asset enumeration complete.{Colors.RESET}")

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
    
    # Collect NVD CVE findings for unique (product, version) pairs from existing findings
    _nvd_seen_versions: set[tuple[str, str]] = set()
    _nvd_tasks = []
    for _f in final_vulnerabilities:
        _prod, _ver = nvd.extract_product_and_version(_f)
        if _prod and _ver and (_prod, _ver) not in _nvd_seen_versions:
            _nvd_seen_versions.add((_prod, _ver))
            _nvd_tasks.append(nvd.lookup_cves(
                product=_prod,
                version=_ver,
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
    # kev and epss operate in-place on the same list; use kev_result as the base
    final_vulnerabilities = kev_result
    # Merge EPSS enrichment (in-place updates) — epss_result shares the same finding objects
    # Merge passive intel additions
    _existing_urls = {f.get("url") for f in final_vulnerabilities}
    for _f in passive_result:
        if _f.get("url") not in _existing_urls:
            final_vulnerabilities.append(_f)
            _existing_urls.add(_f.get("url"))
    # Merge NVD CVE findings, deduplicate by target, port, and CVE ID
    _seen_cve_keys: set[tuple[str, str, str]] = set()
    _added_cve_count = 0
    for _batch in nvd_results_list:
        for _f in _batch:
            _cve_id = _f.get("vulnerability", "").split(" — ")[0].strip()
            _target = _f.get("target", "N/A")
            _port = _f.get("port", "N/A")
            _key = (_target, _port, _cve_id)
            if _cve_id and _key not in _seen_cve_keys:
                _seen_cve_keys.add(_key)
                final_vulnerabilities.append(_f)
                _added_cve_count += 1
    print(f"{Colors.CYAN}[*] CISA KEV cross-reference complete.{Colors.RESET}")
    if _added_cve_count:
        print(f"{Colors.CYAN}[*] NVD enrichment added {_added_cve_count} CVE finding(s).{Colors.RESET}")

    # Inventory delta report
    delta = inventory.save_findings(run_id, final_vulnerabilities)
    inventory.complete_scan_run(run_id, len(final_vulnerabilities))
    inventory.print_delta_report(delta)
    inventory.print_executive_summary(run_id, len(final_vulnerabilities))

    # Always write CSV — even when 0 findings (gives a clean empty report)
    csv_file = save_results_to_csv(
        final_vulnerabilities,
        filename=os.path.join(web_output_dir, f"scan_results_{time.strftime('%Y%m%d_%H%M%S')}.csv") if web_output_dir else None,
    )
    if csv_file:
        print(f"{Colors.GREEN}[+] CSV report generated: {csv_file}{Colors.RESET}")

    if final_vulnerabilities:
        json_path = os.path.join(web_output_dir, f"scan_results_{time.strftime('%Y%m%d_%H%M%S')}.json") if web_output_dir else None
        save_results_to_json(final_vulnerabilities, filename=json_path)

    if sarif_output:
        write_sarif_output(final_vulnerabilities, sarif_output)

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

    except KeyboardInterrupt:
        print(f"\n[!] Streaming scan interrupted.")

    if all_port_scan_results:
        save_port_scan_csv(all_port_scan_results, "streaming")

    # Collect NVD CVE findings for unique (product, version) pairs from existing findings
    _nvd_seen_versions = set()
    _nvd_tasks = []
    for _f in all_vulnerabilities:
        _prod, _ver = nvd.extract_product_and_version(_f)
        if _prod and _ver and (_prod, _ver) not in _nvd_seen_versions:
            _nvd_seen_versions.add((_prod, _ver))
            _nvd_tasks.append(nvd.lookup_cves(
                product=_prod,
                version=_ver,
                target=_f.get("target", "N/A"),
                resolved_ip=_f.get("resolved_ip", "N/A"),
                port=_f.get("port", "N/A"),
            ))

    if _nvd_tasks:
        nvd_results_list = await asyncio.gather(*_nvd_tasks)
        _seen_cve_keys = set()
        _added_cve_count = 0
        for _batch in nvd_results_list:
            for _f in _batch:
                _cve_id = _f.get("vulnerability", "").split(" — ")[0].strip()
                _target = _f.get("target", "N/A")
                _port = _f.get("port", "N/A")
                _key = (_target, _port, _cve_id)
                if _cve_id and _key not in _seen_cve_keys:
                    _seen_cve_keys.add(_key)
                    all_vulnerabilities.append(_f)
                    _added_cve_count += 1
        if _added_cve_count:
            print(f"{Colors.CYAN}[*] NVD enrichment added {_added_cve_count} CVE finding(s).{Colors.RESET}")

    await print_final_results(all_vulnerabilities)
    return all_vulnerabilities

# Helper functions for streaming (included to ensure self-contained file)
async def process_chunk_services(open_ports_results, service_ports, module_filter, custom_ports, state_manager):
    validation_tasks = []
    service_mapping = []
    
    for target_obj, data in open_ports_results:
        if not data['open_ports']: continue
        scan_address = target_obj['scan_address']
        
        for port in data['open_ports']:
            for service, service_ports_list in service_ports.items():
                if port in service_ports_list:
                    scanner_func = SERVICE_TO_MODULE[service].run_scans
                    validation_tasks.append(validate_service(service, target_obj, port))
                    service_mapping.append((service, target_obj, port, scanner_func))
            if custom_ports and port not in [p for ports in service_ports.values() for p in ports]:
                for service_name in SERVICE_TO_MODULE.keys():
                    if module_filter is None or service_name == module_filter:
                        scanner_func = SERVICE_TO_MODULE[service_name].run_scans
                        validation_tasks.append(validate_service(service_name, target_obj, port))
                        service_mapping.append((service_name, target_obj, port, scanner_func))

    chunk_vulnerabilities = []
    if not validation_tasks: return chunk_vulnerabilities

    validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
    scan_tasks = []
    
    async def scan_with_state_saving(scan_func, target_obj, port):
        try:
            results = await scan_func(target_obj, port)
            for result in results: state_manager.add_vulnerability(result)
            return results
        except: return []

    for is_valid, (service, target_obj, port, scanner_func) in zip(validation_results, service_mapping):
        if isinstance(is_valid, bool) and is_valid:
            state_manager.add_validated_service(target_obj['resolved_ip'], port, service)
            scan_tasks.append(scan_with_state_saving(scanner_func, target_obj, port))

    if scan_tasks:
        results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, list): chunk_vulnerabilities.extend(res)
            
    return chunk_vulnerabilities


# ---------------------------------------------------------------------------
# Subcommand handler functions
# ---------------------------------------------------------------------------

async def cmd_scan(args):
    """Handler for `vaktscan scan` — calls the existing main() orchestrator."""
    global _partial_findings
    import ipaddress
    import tempfile
    target_type = target_classifier(args.target)
    print(f"{Colors.CYAN}[*] Target type: {target_type} — {args.target}{Colors.RESET}")

    # For file targets: use robust parser then classify each entry
    _file_domains = []
    _file_ips = []
    if target_type == 'file':
        _lines = parse_targets_file(args.target)
        for _line in _lines:
            if target_classifier(_line) == 'domain':
                _file_domains.append(_line)
            else:
                _file_ips.append(_line)
        if _file_domains:
            if args.no_subdomain_enum:
                print(f"{Colors.CYAN}[*] Mixed file: {len(_file_domains)} domain(s), {len(_file_ips)} IP/CIDR(s) — subdomain enum skipped (--no-subdomain-enum){Colors.RESET}")
            else:
                print(f"{Colors.CYAN}[*] Mixed file: {len(_file_domains)} domain(s), {len(_file_ips)} IP/CIDR(s) — subdomain enum will run for domains{Colors.RESET}")

    # Guard against IPv6 CIDR ranges that are too large to scan
    if target_type == 'cidr' and ':' in args.target:
        try:
            stripped_target = args.target.strip('[]')
            net = ipaddress.ip_network(stripped_target, strict=False)
            if isinstance(net, ipaddress.IPv6Network) and net.prefixlen < 112:
                print(f"{Colors.RED}[!] IPv6 CIDR /{net.prefixlen} would scan {net.num_addresses:,} addresses — too large. Use /{112}+ (max 65536 hosts).{Colors.RESET}")
                sys.exit(1)
        except ValueError:
            pass

    # main() expects a targets file path — write single targets to a temp file
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
        )
    except KeyboardInterrupt:
        if _partial_findings:
            ts = time.strftime("%Y%m%d_%H%M%S")
            partial_path = f"scan_results_{ts}_PARTIAL.csv"
            save_results_to_csv(_partial_findings, partial_path)
            print(f"\n{Colors.YELLOW}[!] Partial results ({len(_partial_findings)} findings) saved to: {partial_path}{Colors.RESET}")
        raise  # re-raise so the outer try/except in __main__ handles sys.exit
    finally:
        if _tmp_file and os.path.exists(_tmp_file):
            os.unlink(_tmp_file)


async def cmd_enum(args):
    """Handler for `vaktscan enum` — subdomain enumeration only."""
    os.makedirs(args.output_dir, exist_ok=True)
    scanner = recon.ReconScanner(args.domain, output_dir=args.output_dir, wordlist=args.wordlist)
    subdomains = await scanner.run_all()
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
        ))


async def cmd_probe(args):
    """Handler for `vaktscan probe` — httpx + parallel web analysis on a host list or file."""
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
    print(f"{Colors.CYAN}[*] Probe: {len(targets)} target(s) → {output_dir}{Colors.RESET}")
    findings = await run_recon_followups(
        subdomains=targets,
        recon_domain=recon_domain,
        output_dir=output_dir,
        concurrency=args.concurrency,
        nmap_enabled=False,
        connect_timeout=args.timeout,
    )
    if findings:
        out_csv = os.path.join(output_dir, f"probe_findings_{ts}.csv")
        save_results_to_csv(findings, out_csv)
        print(f"{Colors.GREEN}[+] Probe complete: {len(findings)} finding(s). CSV: {out_csv}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[+] Probe complete. No findings.{Colors.RESET}")


async def cmd_dns(args):
    """Handler for `vaktscan dns` — DNS recon only."""
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
    """Handler for `vaktscan cloud` — cloud asset enum only."""
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
    """Handler for `vaktscan js-paths` — JS path extraction only."""
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


async def cmd_domain_scan(args):
    """Handler for `vaktscan domain-scan` — domain HTTP analysis only."""
    os.makedirs(args.output_dir, exist_ok=True)
    await main(
        targets_file=None,
        concurrency=args.concurrency,
        resume=False,
        module_filter=None,
        module_mode='domain-scan',
        domain_scan_file=args.domain,
        domain_scan_concurrency=args.concurrency,
        sarif_output=None,
    )


async def cmd_google_dork(args):
    """Handler for `vaktscan google-dork` — Google Dorking passive recon."""
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


if __name__ == "__main__":
    print_logo()

    # --- Root parser ---
    parser = argparse.ArgumentParser(
        prog="vaktscan",
        description="VaktScan — Attack Surface Scanner",
    )
    subparsers = parser.add_subparsers(dest="subcommand", metavar="COMMAND")
    subparsers.required = True

    # ---- scan subcommand ----
    sp_scan = subparsers.add_parser("scan", help="Full attack surface scan")
    sp_scan.add_argument("target", help="Domain, IP, CIDR, or targets file")
    sp_scan.add_argument("-c", "--concurrency", type=int, default=100)
    sp_scan.add_argument("--connect-timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT)
    sp_scan.add_argument("--port-retries", type=int, default=DEFAULT_PORT_RETRIES)
    sp_scan.add_argument("-r", "--resume", action="store_true")
    sp_scan.add_argument("--format",
        choices=["csv", "json", "sarif", "all"],
        default=None,
        help="Additional output format (csv always written; use json/sarif/all for extras)")
    sp_scan.add_argument("--sarif", metavar="FILE", default=None)
    sp_scan.add_argument("-m", "--module",
        choices=["elasticsearch", "kibana", "grafana", "prometheus", "nextjs",
                 "aem", "cpanel", "jenkins", "service_recon"],
        help="Run only this service module (all modules by default)")
    sp_scan.add_argument("--ports", type=str)
    sp_scan.add_argument("--chunk-size", type=int, default=30000)
    sp_scan.add_argument("--wordlist")
    # --scan-found removed: the scan subcommand always probes discovered subdomains
    sp_scan.add_argument("--nmap", action="store_true")
    sp_scan.add_argument("--sub-domains", metavar="FILE", dest="sub_domains_file")
    sp_scan.add_argument("--recon-concurrency", type=int, default=2)
    sp_scan.add_argument("--no-subdomain-enum", action="store_true", dest="no_subdomain_enum",
        help="Skip subdomain enumeration for domain targets")
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

    # ---- probe subcommand ----
    sp_probe = subparsers.add_parser("probe", help="Port scan + httpx probe")
    sp_probe.add_argument("target", help="Domain, IP, CIDR, or file")
    sp_probe.add_argument("--ports", type=str)
    sp_probe.add_argument("-c", "--concurrency", type=int, default=50)
    sp_probe.add_argument("--timeout", type=float, default=10.0)
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
    sp_ds = subparsers.add_parser("domain-scan", help="Domain-level HTTP analysis")
    sp_ds.add_argument("domain", help="Apex domain")
    sp_ds.add_argument("--httpx-data", metavar="FILE", help="Existing httpx JSON output")
    sp_ds.add_argument("-c", "--concurrency", type=int, default=50)
    sp_ds.add_argument("--output-dir", default="reports/")

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
            asyncio.run(cmd_scan(args))
        elif args.subcommand == "enum":
            asyncio.run(cmd_enum(args))
        elif args.subcommand == "probe":
            asyncio.run(cmd_probe(args))
        elif args.subcommand == "dns":
            asyncio.run(cmd_dns(args))
        elif args.subcommand == "cloud":
            asyncio.run(cmd_cloud(args))
        elif args.subcommand == "js-paths":
            asyncio.run(cmd_js_paths(args))
        elif args.subcommand == "domain-scan":
            asyncio.run(cmd_domain_scan(args))
        elif args.subcommand == "google-dork":
            asyncio.run(cmd_google_dork(args))
    except KeyboardInterrupt:
        print("\n[*] Scanner terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)
