import asyncio
import argparse
import sys
import os
import signal
import csv
import time
import ipaddress

# Add vendor directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'vendor'))

from utils import process_targets, process_targets_streaming, get_service_ports
from port_scanner import scan_ports
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
)

# Map service names to their corresponding modules
SERVICE_TO_MODULE = {
    "elasticsearch": elastic,
    "kibana": kibana,
    "grafana": grafana,
    "prometheus": prometheus,
    "nextjs": react_to_shell,
}


# Color codes for terminal output
class Colors:
    # Basic colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    
    # Bright colors
    BRIGHT_RED = '\033[1;91m'
    BRIGHT_GREEN = '\033[1;92m'
    BRIGHT_YELLOW = '\033[1;93m'
    BRIGHT_BLUE = '\033[1;94m'
    BRIGHT_MAGENTA = '\033[1;95m'
    BRIGHT_CYAN = '\033[1;96m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    @staticmethod
    def disable():
        """Disable colors for non-terminal environments."""
        Colors.RED = Colors.GREEN = Colors.YELLOW = Colors.BLUE = ''
        Colors.MAGENTA = Colors.CYAN = Colors.WHITE = Colors.GRAY = ''
        Colors.BRIGHT_RED = Colors.BRIGHT_GREEN = Colors.BRIGHT_YELLOW = ''
        Colors.BRIGHT_BLUE = Colors.BRIGHT_MAGENTA = Colors.BRIGHT_CYAN = ''
        Colors.BOLD = Colors.DIM = Colors.UNDERLINE = Colors.RESET = ''

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

def save_port_scan_csv(scan_results, domain):
    """
    Save full port scan results to a CSV file.
    scan_results structure: list of tuples (target_obj, {'open_ports': []})
    """
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"portscan_results_{domain}_{timestamp}.csv"
    
    headers = ['Timestamp', 'Hostname', 'IP Address', 'Open Ports', 'Count']
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            
            scan_time = time.strftime("%Y-%m-%d %H:%M:%S")
            
            count = 0
            for target_obj, result in scan_results:
                open_ports = result.get('open_ports', [])
                if not open_ports:
                    continue
                
                hostname = target_obj.get('display_target', 'N/A')
                ip = target_obj.get('resolved_ip', 'N/A')
                ports_str = ", ".join(map(str, sorted(open_ports)))
                
                writer.writerow([
                    scan_time,
                    hostname,
                    ip,
                    ports_str,
                    len(open_ports)
                ])
                count += 1
                
        print(f"{Colors.GREEN}[+] Full port scan results saved to: {Colors.BOLD}{filename}{Colors.RESET}")
        return filename
    except Exception as e:
        print(f"{Colors.RED}[!] Error saving port scan CSV: {e}{Colors.RESET}")
        return None

def save_results_to_csv(vulnerabilities, filename=None):
    """Save vulnerability results to CSV format."""
    if not filename:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.csv"
    
    csv_headers = ['Timestamp', 'Status', 'Vulnerability', 'Hostname', 'IP Address', 'Port', 'URL', 'Module', 'Service_Version', 'Severity', 'Details']
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(csv_headers)
            
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            for vuln in vulnerabilities:
                hostname = vuln.get('target', 'N/A')
                try:
                    # If the target is a valid IP, it's not a hostname
                    ipaddress.ip_address(hostname)
                    hostname = ''
                except ValueError:
                    pass

                writer.writerow([
                    timestamp,
                    vuln.get('status', 'UNKNOWN'),
                    vuln.get('vulnerability', 'N/A'),
                    hostname,
                    vuln.get('resolved_ip', 'N/A'),
                    vuln.get('port', 'N/A'),
                    vuln.get('url', 'N/A'),
                    vuln.get('module', 'N/A'),
                    vuln.get('service_version', 'N/A'),
                    vuln.get('severity', 'N/A'),
                    vuln.get('details', 'N/A')
                ])
        
        print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.RESET}")
        return filename
        
    except Exception as e:
        print(f"{Colors.RED}[!] Error saving CSV file: {e}{Colors.RESET}")
        return None

async def run_recon_followups(subdomains, recon_domain, output_dir, concurrency, nmap_enabled, wordlist=None):
    """Run HTTPX, dirsearch, nuclei, and optional Nmap on recon results."""
    if not subdomains:
        print(f"{Colors.YELLOW}[!] No subdomains discovered to probe further.{Colors.RESET}")
        return

    http_runner = httpx_runner.HTTPXRunner(output_dir=output_dir)
    unique_targets = sorted(set(subdomains))

    print(f"{Colors.CYAN}[*] Running preliminary web-port scan on {len(unique_targets)} hosts...{Colors.RESET}")
    recon_targets = await process_targets(unique_targets)
    if not recon_targets:
        print(f"{Colors.RED}[!] No targets to probe after preprocessing.{Colors.RESET}")
        return

    service_ports = get_service_ports()
    common_web_ports = sorted(set(service_ports.get("web", [])))
    port_scan_results = await scan_ports(recon_targets, common_web_ports, concurrency, state_manager=None)
    probe_urls = []
    nmap_followup_task = None

    async def _await_nmap_task():
        if nmap_followup_task:
            await nmap_followup_task

    if nmap_enabled:
        print(
            f"{Colors.BRIGHT_MAGENTA}[*] Running background full-range port scan "
            f"(1-65535) to prep Nmap follow-up...{Colors.RESET}"
        )
        full_port_range = list(range(1, 65536))
        full_port_scan_task = asyncio.create_task(
            scan_ports(recon_targets, full_port_range, concurrency, state_manager=None)
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
                host = target_obj.get('display_target') or ip
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
            print(
                f"{Colors.GREEN}[+] Nmap follow-up completed for {len(nmap_jobs)} host(s).{Colors.RESET}"
            )

        nmap_followup_task = asyncio.create_task(_nmap_followup())

    def _format_url(scheme, host_value, port_value):
        default_port = 80 if scheme == "http" else 443
        suffix = "" if port_value == default_port else f":{port_value}"
        return f"{scheme}://{host_value}{suffix}"

    def _normalize_host(host_value):
        host_value = (host_value or "").strip().lower()
        if not host_value:
            return ""
        if "://" in host_value:
            host_value = host_value.split("://", 1)[1]
        if "/" in host_value:
            host_value = host_value.split("/", 1)[0]
        if host_value.count(":") == 1 and host_value.split(":")[1].isdigit():
            host_value = host_value.split(":")[0]
        return host_value

    def _collect_domain_hosts(host_iterable):
        domains = set()
        for host_value in host_iterable:
            candidate = _normalize_host(host_value)
            if not candidate:
                continue
            try:
                ipaddress.ip_address(candidate)
                continue
            except ValueError:
                pass
            if "." not in candidate:
                continue
            domains.add(candidate)
        return sorted(domains)

    for target_obj, data in port_scan_results:
        open_ports = sorted(set(data.get('open_ports', [])))
        if not open_ports:
            continue
        host = target_obj.get('display_target') or target_obj.get('scan_address')
        ip = target_obj.get('resolved_ip') or target_obj.get('scan_address')
        for port in open_ports:
            for scheme in ("http", "https"):
                probe_urls.append(_format_url(scheme, host, port))
                if ip != host:
                    probe_urls.append(_format_url(scheme, ip, port))

    probe_urls = sorted(set(probe_urls))
    if not probe_urls:
        print(f"{Colors.YELLOW}[!] No open web ports detected; skipping httpx probe.{Colors.RESET}")
        await _await_nmap_task()
        return

    print(f"{Colors.CYAN}[*] Probing {len(probe_urls)} URLs with httpx...{Colors.RESET}")
    httpx_data = await http_runner.run_httpx(probe_urls, concurrency)
    if not httpx_data:
        print(f"{Colors.YELLOW}[!] No alive HTTP services detected by httpx.{Colors.RESET}")
        await _await_nmap_task()
        return

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
            print(f"{Colors.CYAN}[*] Probing {len(new_targets)} ffuf-discovered hosts with httpx...{Colors.RESET}")
            ffuf_httpx = await http_runner.run_httpx(new_targets, concurrency)
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
    if alive_urls:
        #print("Commented Out DIR ENUM - Continue to Nuclei")
        await dir_enumerator.run_dirsearch(alive_urls)

    if alive_urls:
        nuclei_inst = nuclei_runner.NucleiRunner(output_dir=output_dir)
        nuclei_results = await nuclei_inst.run_nuclei(alive_urls)
        if nuclei_results:
            print(f"{Colors.GREEN}[+] Nuclei identified {len(nuclei_results)} findings.{Colors.RESET}")
            for vuln in nuclei_results:
                print(f"    - {vuln['status']} | {vuln['vulnerability']} | {vuln['url']}")
        else:
            print(f"{Colors.GREEN}[+] Nuclei scan complete with no findings.{Colors.RESET}")

    domain_hosts = _collect_domain_hosts(alive_urls)
    if domain_hosts:
        print(f"{Colors.CYAN}[*] Harvesting archived URLs for {len(domain_hosts)} host(s) (gau → waybackurls)...{Colors.RESET}")
        gau_inst = gau_runner.GAURunner(output_dir=output_dir)
        await gau_inst.run(domain_hosts)
        wayback_inst = waybackurls_runner.WaybackURLsRunner(output_dir=output_dir)
        await wayback_inst.run(domain_hosts)
    else:
        print(f"{Colors.YELLOW}[!] No hostname targets available for gau/waybackurls.{Colors.RESET}")

    await _await_nmap_task()

def load_subdomains_file(file_path):
    """
    Load subdomains from a user-provided file, stripping blanks/comments.
    """
    entries = []
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                entries.append(line.lower())
    except OSError as exc:
        print(f"{Colors.RED}[!] Unable to read subdomain file '{file_path}': {exc}{Colors.RESET}")
        sys.exit(1)

    if not entries:
        print(f"{Colors.YELLOW}[!] Subdomain file '{file_path}' did not contain any usable entries.{Colors.RESET}")
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
            try:
                with open(candidate, "r", encoding="utf-8") as handle:
                    for line in handle:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        expanded.append(line.lower())
            except OSError as exc:
                print(f"{Colors.RED}[!] Unable to read recon domain file '{candidate}': {exc}{Colors.RESET}")
        else:
            expanded.append(candidate.lower())

    return expanded

def deduplicate_vulnerabilities(vulnerabilities):
    """
    Deduplicates a list of vulnerabilities.
    """
    unique_vulns = {}
    
    for vuln in vulnerabilities:
        vuln_key = (
            vuln.get('resolved_ip', vuln.get('target')), 
            vuln.get('port'),
            vuln.get('vulnerability')
        )
        
        if vuln_key not in unique_vulns:
            unique_vulns[vuln_key] = vuln
        else:
            existing_vuln = unique_vulns[vuln_key]
            try:
                import ipaddress
                ipaddress.ip_address(existing_vuln['target'])
                try:
                    ipaddress.ip_address(vuln['target'])
                except ValueError:
                    unique_vulns[vuln_key] = vuln
            except ValueError:
                pass

    return list(unique_vulns.values())

async def main(targets_file, concurrency, resume=False, output_csv=False, module_filter=None, custom_ports=None, chunk_size=30000, recon_domains=None, wordlist=None, scan_found=False, nmap_enabled=False, subdomains_file=None, recon_concurrency=2):
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
    
    # Store recon results to pass to scanner if needed
    nuclei_vulns_found = False
    recon_targets_file = None
    recon_targets_count = 0

    # Validation: --nmap needs --recon
    if nmap_enabled and not recon_domains:
        print(f"{Colors.RED}[!] Error: --nmap cannot be used without --recon.{Colors.RESET}")
        sys.exit(1)
    if subdomains_file:
        if not recon_domains:
            print(f"{Colors.RED}[!] Error: --sub-domains requires --recon to be specified.{Colors.RESET}")
            sys.exit(1)
        if len(recon_domains) != 1:
            print(f"{Colors.RED}[!] Error: --sub-domains currently supports exactly one --recon domain.{Colors.RESET}")
            sys.exit(1)

    # --- RECONNAISSANCE MODE ---
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
            recon_domain = normalized_domains[0]
            print(f"{Colors.CYAN}[*] Starting Reconnaissance Mode for: {Colors.BOLD}{recon_domain}{Colors.RESET}")
            subdomains = load_subdomains_file(subdomains_file)
            unique_subdomains = sorted(set(subdomains))
            if not unique_subdomains:
                print(f"{Colors.RED}[!] No usable subdomains found in '{subdomains_file}'. Nothing to probe.{Colors.RESET}")
                return
            safe_domain = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in recon_domain.lower())
            domain_output_dir = os.path.join("recon_results", safe_domain or "domain")
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
            await run_recon_followups(unique_subdomains, recon_domain, domain_output_dir, concurrency, nmap_enabled, wordlist)
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
                results_file, subdomains = await scanner.run_all()
                if not subdomains:
                    print(f"{Colors.YELLOW}[!] Recon completed for {domain} but no subdomains were discovered.{Colors.RESET}")
                    return None
                domain_output_dir = os.path.dirname(results_file)
                if scan_found:
                    await run_recon_followups(subdomains, domain, domain_output_dir, concurrency, nmap_enabled, wordlist)
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
            recon_results = await asyncio.gather(*tasks, return_exceptions=True)
            successes = []
            for result in recon_results:
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
                combined_dir = os.path.join("recon_results", "combined")
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
            print(f"{Colors.YELLOW}[!] Ignoring provided targets file because --recon supplies its own target set.{Colors.RESET}")
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
    
    try:
        # Load existing state or start fresh
        is_resume = resume or state_manager.load_existing_state()
        
        if is_resume:
            print(f"{Colors.CYAN}[*] Resuming VaktScan...{Colors.RESET}")
        else:
            print(f"{Colors.CYAN}[*] Starting VaktScan - Nordic Security Scanner...{Colors.RESET}")

        # 1. Process targets
        raw_targets = [line.strip() for line in open(targets_file, 'r')]
        
        should_stream = len(raw_targets) > 1000

        if should_stream:
            print(f"{Colors.YELLOW}[*] Large target set detected - using streaming mode{Colors.RESET}")
            return await process_streaming_scan(raw_targets, concurrency, output_csv, module_filter, custom_ports, chunk_size, state_manager)
        
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
        
        # Default scan ports (standard VaktScan mode)
        all_ports_to_scan = [
            port
            for ports in service_ports.values()
            for port in ports
        ]
        
        if custom_ports:
            try:
                custom_port_list = [int(port.strip()) for port in custom_ports.split(',')]
                all_ports_to_scan.extend(custom_port_list)
                all_ports_to_scan = list(set(all_ports_to_scan))
                print(f"{Colors.YELLOW}[*] Added custom ports: {custom_port_list}{Colors.RESET}")
            except ValueError as e:
                print(f"{Colors.RED}[!] Error parsing custom ports: {e}. Ignoring custom ports.{Colors.RESET}")
        
        # --- STANDARD PORT SCAN LOGIC ---
        if state_manager.state["phase"] in ["initializing", "target_processing_complete", "port_scanning"]:
            state_manager.set_totals(len(targets), len(targets) * len(all_ports_to_scan))
            
            print(f"{Colors.CYAN}[*] Starting concurrent port scan for {len(targets)} targets across {len(all_ports_to_scan)} unique ports...{Colors.RESET}")
            state_manager.update_phase("port_scanning")
            
            open_ports_results = await scan_ports(targets, all_ports_to_scan, concurrency, state_manager)
            print(f"{Colors.GREEN}[+] Port scanning complete.{Colors.RESET}")
            state_manager.update_phase("port_scanning_complete")
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
                        validation_tasks.append(validate_service(service, scan_address, port))
                        service_mapping.append((service, target_obj, port, scanner_func))

                if custom_ports and port not in [p for ports in service_ports.values() for p in ports]:
                    for service_name in SERVICE_TO_MODULE.keys():
                        if module_filter is None or service_name == module_filter:
                            scanner_func = SERVICE_TO_MODULE[service_name].run_scans
                            validation_tasks.append(validate_service(service_name, scan_address, port))
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
                    print(f"  -> Running {service.capitalize()} scans on http://{target_obj['scan_address']}:{port}")
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
    
    if output_csv and final_vulnerabilities:
        csv_file = save_results_to_csv(final_vulnerabilities)
        if csv_file:
            print(f"{Colors.GREEN}[+] CSV report generated: {csv_file}{Colors.RESET}")
    
    state_manager.mark_completed()
    print(f"\n{state_manager.get_scan_summary()}")
    print(f"{Colors.BRIGHT_GREEN}[*] Scan finished.{Colors.RESET}")
    
    state_manager.cleanup_state_file()

# Helper for streaming process (remains mostly unchanged, just ensured it's accessible)
async def process_streaming_scan(raw_targets, concurrency, output_csv=False, module_filter=None, custom_ports=None, chunk_size=30000, state_manager=None):
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
    
    all_ports_to_scan = [port for ports in service_ports.values() for port in ports]
    if custom_ports:
        try:
            custom_port_list = [int(p.strip()) for p in custom_ports.split(',')]
            all_ports_to_scan.extend(custom_port_list)
            all_ports_to_scan = list(set(all_ports_to_scan))
        except ValueError: pass

    all_vulnerabilities = []
    chunk_count = 0
    
    try:
        async for target_chunk in process_targets_streaming(raw_targets, chunk_size):
            chunk_count += 1
            print(f"\n{Colors.BRIGHT_CYAN}=== Processing Chunk {chunk_count}/{total_chunks} ({len(target_chunk):,} targets) ==={Colors.RESET}")
            
            open_ports_results = await scan_ports(target_chunk, all_ports_to_scan, concurrency, state_manager)
            chunk_vulnerabilities = await process_chunk_services(open_ports_results, service_ports, module_filter, custom_ports, state_manager)
            all_vulnerabilities.extend(chunk_vulnerabilities)
            
            if state_manager:
                state_manager.state["completed_chunks"] = chunk_count
                state_manager.save_state()
            
            print(f"{Colors.GREEN}[+] Chunk {chunk_count}/{total_chunks} completed.{Colors.RESET}")

    except KeyboardInterrupt:
        print(f"\n[!] Streaming scan interrupted.")
    
    await print_final_results(all_vulnerabilities, output_csv)
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
                    validation_tasks.append(validate_service(service, scan_address, port))
                    service_mapping.append((service, target_obj, port, scanner_func))
            if custom_ports and port not in [p for ports in service_ports.values() for p in ports]:
                for service_name in SERVICE_TO_MODULE.keys():
                    if module_filter is None or service_name == module_filter:
                        scanner_func = SERVICE_TO_MODULE[service_name].run_scans
                        validation_tasks.append(validate_service(service_name, scan_address, port))
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

async def print_final_results(all_vulnerabilities, output_csv):
    final_vulnerabilities = deduplicate_vulnerabilities(all_vulnerabilities)
    print(f"\n{Colors.BRIGHT_CYAN}=== Final Vulnerability Results ==={Colors.RESET}")
    if final_vulnerabilities:
        for result in final_vulnerabilities:
            print(f"[!] {result['status']}: {result['vulnerability']} on {result['target']}")
    else:
        print("[*] No vulnerabilities found.")
    if output_csv and final_vulnerabilities:
        save_results_to_csv(final_vulnerabilities)

if __name__ == "__main__":
    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        print_logo()
    
    parser = argparse.ArgumentParser(
        description="VaktScan - Attack Surface Scanner for ELK, Grafana, Prometheus, Next.js stacks."
    )
    parser.add_argument(
        "targets_file",
        nargs='?',
        help="Targets file (IPs/hostnames/CIDRs). Optional when using --recon."
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=100,
        help="Concurrency level for network operations (default: 100)."
    )
    parser.add_argument(
        "-r", "--resume",
        action="store_true",
        help="Resume an interrupted infrastructure scan."
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Save consolidated vulnerability results to CSV."
    )
    parser.add_argument(
        "-m", "--module",
        choices=["elasticsearch", "kibana", "grafana", "prometheus", "nextjs"],
        help="Only scan the specified service module."
    )
    parser.add_argument(
        "-p", "--ports",
        type=str,
        help="Additional comma-separated ports to scan (e.g., 8080,8443,9999)."
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=30000,
        help="Chunk size for streaming mode (default: 30000)."
    )
    parser.add_argument(
        "--recon",
        metavar="DOMAIN",
        nargs="+",
        help="Run subdomain enumeration and passive recon on one or more DOMAIN values or files."
    )
    parser.add_argument(
        "--recon-concurrency",
        type=int,
        default=2,
        help="Number of recon domains to run at once when multiple are provided."
    )
    parser.add_argument(
        "--wordlist",
        help="Wordlist for ffuf-based VHost fuzzing during recon (--recon required)."
    )
    parser.add_argument(
        "--sub-domains",
        metavar="FILE",
        dest="sub_domains_file",
        help="File containing newline-separated subdomains to probe directly (requires --recon)."
    )
    parser.add_argument(
        "--scan-found",
        action="store_true",
        help="Automatically probe recon subdomains via httpx → dirsearch → nuclei."
    )
    parser.add_argument(
        "--nmap",
        action="store_true",
        help="After recon, run a full 1-65535 port scan and nmap -sCV -Pn on alive hosts."
    )

    args = parser.parse_args()

    try:
        asyncio.run(main(
            args.targets_file, 
            args.concurrency, 
            args.resume, 
            args.csv, 
            args.module, 
            args.ports, 
            args.chunk_size,
            args.recon,
            args.wordlist,
            args.scan_found,
            args.nmap,
            args.sub_domains_file,
            args.recon_concurrency
        ))
    except KeyboardInterrupt:
        print("\n[*] Scanner terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        # traceback.print_exc()
        sys.exit(1)
