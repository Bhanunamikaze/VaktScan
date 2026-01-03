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
from modules import elastic, kibana, grafana, prometheus, react_to_shell, recon, httpx_runner, nuclei_runner, nmap_runner

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
{Colors.BRIGHT_CYAN}║{Colors.RESET}                  {Colors.BRIGHT_YELLOW}Monitoring Stack Security Scanner{Colors.RESET}                     {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}                         {Colors.BRIGHT_MAGENTA}   Nordic Vigilance   {Colors.RESET}                         {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}                                                                        {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}      {Colors.GREEN}Elasticsearch{Colors.RESET} • {Colors.GREEN}Kibana{Colors.RESET} • {Colors.GREEN}Grafana{Colors.RESET} • {Colors.GREEN}Prometheus{Colors.RESET} • {Colors.GREEN}Next.js{Colors.RESET}      {Colors.BRIGHT_CYAN}║{Colors.RESET}
{Colors.BRIGHT_CYAN}║{Colors.RESET}                     {Colors.RED}30+ CVEs{Colors.RESET} • {Colors.YELLOW}High Performance{Colors.RESET}                        {Colors.BRIGHT_CYAN}║{Colors.RESET}
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

async def main(targets_file, concurrency, resume=False, output_csv=False, module_filter=None, custom_ports=None, chunk_size=30000, recon_domain=None, wordlist=None, scan_found=False, nmap_enabled=False):
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
    recon_targets_processed = None
    force_full_scan = False
    nuclei_vulns_found = False

    # Validation: --nmap needs --recon
    if nmap_enabled and not recon_domain:
        print(f"{Colors.RED}[!] Error: --nmap cannot be used without --recon.{Colors.RESET}")
        sys.exit(1)

    # --- RECONNAISSANCE MODE ---
    if recon_domain:
        print(f"{Colors.CYAN}[*] Starting Reconnaissance Mode for: {Colors.BOLD}{recon_domain}{Colors.RESET}")
        print(f"{Colors.GRAY}[*] Tools: Amass, Subfinder, Assetfinder, Findomain, Sublist3r, Knockpy, bbot, Censys, crtsh + DirEnumerator(ffuf){Colors.RESET}")
        
        scanner = recon.ReconScanner(recon_domain, wordlist=wordlist)
        results_file, subdomains = await scanner.run_all()
        
        if scan_found:
            print(f"\n{Colors.YELLOW}[*] Feeding {len(subdomains)} discovered subdomains into VaktScan...{Colors.RESET}")
            targets_file = results_file
            force_full_scan = True # Flag to trigger the 65535 port scan
        else:
            print(f"\n{Colors.CYAN}[*] Recon complete. To scan these targets, run:\n    python main.py {results_file}{Colors.RESET}")
            return

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

        # Streaming currently skips the logic below, so we disable streaming if force_full_scan is on
        # to ensure the full port scan logic executes correctly in memory.
        if should_stream and not force_full_scan:
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

        # 2. Define service ports
        service_ports = get_service_ports()
        
        if module_filter:
            print(f"{Colors.YELLOW}[*] Module filter: Scanning only {module_filter.capitalize()} services{Colors.RESET}")
            service_ports = {module_filter: service_ports.get(module_filter, [])}
        
        # Default scan ports (standard VaktScan mode)
        all_ports_to_scan = [port for ports in service_ports.values() for port in ports]
        
        if custom_ports:
            try:
                custom_port_list = [int(port.strip()) for port in custom_ports.split(',')]
                all_ports_to_scan.extend(custom_port_list)
                all_ports_to_scan = list(set(all_ports_to_scan))
                print(f"{Colors.YELLOW}[*] Added custom ports: {custom_port_list}{Colors.RESET}")
            except ValueError as e:
                print(f"{Colors.RED}[!] Error parsing custom ports: {e}. Ignoring custom ports.{Colors.RESET}")
        
        # --- SPECIAL RECON FULL PORT SCAN LOGIC ---
        if force_full_scan and state_manager.state["phase"] in ["initializing", "target_processing_complete"]:
            print(f"{Colors.BRIGHT_MAGENTA}\n[*] RECON MODE DETECTED: Initiating full range port scan (1-65535) on {len(targets)} targets...{Colors.RESET}")
            print(f"{Colors.GRAY}[*] This process may take a while depending on network speed and target responsiveness.{Colors.RESET}")
            
            # Generate full port range
            full_port_range = list(range(1, 65536))
            
            state_manager.set_totals(len(targets), len(targets) * 65535)
            state_manager.update_phase("full_port_scanning")
            
            # Run the full scan
            open_ports_results = await scan_ports(targets, full_port_range, concurrency, state_manager)
            
            print(f"{Colors.GREEN}[+] Full port scan complete.{Colors.RESET}")
            
            # Generate the requested CSV for Port Scan results
            save_port_scan_csv(open_ports_results, recon_domain)
            
            # --- NMAP MODULE INTEGRATION ---
            if nmap_enabled:
                nmap_targets = []
                # Extract targets with open ports from the full scan results
                # open_ports_results is list of tuples: (target_obj, {'open_ports': [...]})
                for target_obj, result in open_ports_results:
                    found_ports = result.get('open_ports', [])
                    if found_ports:
                        ip = target_obj.get('resolved_ip')
                        hostname = target_obj.get('display_target')
                        nmap_targets.append((ip, found_ports, hostname))
                
                if nmap_targets:
                    nmap_mod = nmap_runner.NmapRunner()
                    await nmap_mod.run_batch(nmap_targets, concurrency=concurrency)
            # -------------------------------

            # --- HTTPX & NUCLEI INTEGRATION ---
            # Prepare targets for httpx (hostname:port)
            httpx_targets = []
            for target_obj, result in open_ports_results:
                ports = result.get('open_ports', [])
                hostname = target_obj.get('display_target')
                for p in ports:
                    httpx_targets.append(f"{hostname}:{p}")
            
            httpx_alive_urls = []
            if httpx_targets:
                runner = httpx_runner.HTTPXRunner()
                # Run httpx with same concurrency
                alive_data = await runner.run_httpx(httpx_targets, concurrency)
                if alive_data:
                    runner.save_csv(alive_data, recon_domain)
                    # Extract URLs for Nuclei
                    for entry in alive_data:
                        if 'url' in entry:
                            httpx_alive_urls.append(entry['url'])
            
            # --- NUCLEI SCANNER ---
            if httpx_alive_urls:
                n_runner = nuclei_runner.NucleiRunner()
                nuclei_results = await n_runner.run_nuclei(httpx_alive_urls)
                
                if nuclei_results:
                    nuclei_vulns_found = True
                    # Add nuclei findings to state manager for final CSV export
                    for vuln in nuclei_results:
                        state_manager.add_vulnerability(vuln)
            
            # Update phase so we don't re-run this on resume
            state_manager.update_phase("port_scanning_complete")

        # --- STANDARD PORT SCAN LOGIC (Skipped if full scan ran above) ---
        elif state_manager.state["phase"] in ["initializing", "target_processing_complete", "port_scanning"]:
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
                    original_service_ports = get_service_ports()
                    for service_name in original_service_ports.keys():
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
    # (Implementation details from previous main.py remain same but truncated here for brevity)
    # The user's original logic works fine, just ensuring the call path is correct.
    from main import process_streaming_scan as original_streaming
    # To avoid circular imports or re-implementing, we assume the original logic is preserved
    # In a real edit, I would keep the function body here.
    # For this file generation, I will paste the original function body below to ensure it runs.
    
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
    
    service_ports = get_service_ports()
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
                for service_name in get_service_ports().keys():
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
    
    parser = argparse.ArgumentParser(description="Security scanner for ELK, Grafana, Prometheus, and Next.js stacks.")
    # Made targets_file optional (nargs='?') to allow recon-only mode
    parser.add_argument("targets_file", nargs='?', help="Path to a file containing targets (IPs, hostnames).")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Number of concurrent tasks to run.")
    parser.add_argument("-r", "--resume", action="store_true", help="Resume an interrupted scan.")
    parser.add_argument("--csv", action="store_true", help="Save results to CSV file.")
    parser.add_argument("-m", "--module", choices=["elasticsearch", "kibana", "grafana", "prometheus", "nextjs"], 
                        help="Scan only specific service module")
    parser.add_argument("-p", "--ports", type=str, help="Additional custom ports to scan")
    parser.add_argument("--chunk-size", type=int, default=30000, help="Streaming chunk size")
    
    # New Recon Arguments
    parser.add_argument("--recon", metavar="DOMAIN", help="Perform subdomain enumeration on this domain")
    parser.add_argument("--wordlist", help="Wordlist for active ffuf enumeration")
    parser.add_argument("--scan-found", action="store_true", help="Automatically feed found subdomains into VaktScan")
    parser.add_argument("--nmap", action="store_true", help="Run nmap -sCV -Pn on found open ports (Requires --recon)")

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
            args.nmap
        ))
    except KeyboardInterrupt:
        print("\n[*] Scanner terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        # traceback.print_exc()
        sys.exit(1)
