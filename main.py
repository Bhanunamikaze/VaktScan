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

from utils import process_targets, get_service_ports
from port_scanner import scan_ports
from service_validator import validate_service
from scan_state import ScanStateManager
from modules import elastic, kibana, grafana, prometheus, react_to_shell

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

def print_logo():
    """Display VaktScan ASCII logo with colors."""
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
    If the same vulnerability is found on a hostname and its resolved IP,
    it prioritizes the one associated with the hostname.
    """
    unique_vulns = {}
    
    # The key for uniqueness is (resolved_ip, port, vulnerability_name)
    # We will store the vulnerability with the best target (hostname > IP)
    
    for vuln in vulnerabilities:
        # Create a unique key for each vulnerability instance
        vuln_key = (
            vuln.get('resolved_ip', vuln.get('target')), # Use resolved_ip if available
            vuln.get('port'),
            vuln.get('vulnerability')
        )
        
        # If this vulnerability is not yet recorded, add it
        if vuln_key not in unique_vulns:
            unique_vulns[vuln_key] = vuln
        else:
            # If a duplicate is found, decide which one to keep.
            # We prefer the one where the 'target' is not an IP address (i.e., it's a hostname).
            existing_vuln = unique_vulns[vuln_key]
            
            try:
                # If the existing target is an IP and the new one is not, replace it
                import ipaddress
                ipaddress.ip_address(existing_vuln['target'])
                # If the above line doesn't raise a ValueError, it's an IP.
                # So, if the new one is a hostname, we prefer it.
                try:
                    ipaddress.ip_address(vuln['target'])
                except ValueError:
                    # New one is a hostname, so it's better
                    unique_vulns[vuln_key] = vuln
            except ValueError:
                # The existing one is already a hostname, so we keep it
                pass

    return list(unique_vulns.values())

async def main(targets_file, concurrency, resume=False, output_csv=False, module_filter=None, custom_ports=None, chunk_size=30000):
    """
    Main orchestrator for the scanning tool.
    """
    # Set up signal handlers for graceful shutdown
    def signal_handler():
        print(f"\n[!] Received interrupt signal. Shutting down gracefully...")
        raise KeyboardInterrupt
    
    # Handle both SIGINT (Ctrl+C) and SIGTERM
    if sys.platform != 'win32':
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, signal_handler)
    
    # Initialize state manager
    state_manager = ScanStateManager(targets_file, concurrency)
    
    try:
        # Load existing state or start fresh
        is_resume = resume or state_manager.load_existing_state()
        
        if is_resume:
            print(f"{Colors.CYAN}[*] Resuming VaktScan...{Colors.RESET}")
        else:
            print_logo()
            print(f"{Colors.CYAN}[*] Starting VaktScan - Nordic Security Scanner...{Colors.RESET}")

        # 1. Process and expand all targets from the input file
        raw_targets = [line.strip() for line in open(targets_file, 'r')]
        
        # This estimation logic can be simplified as process_targets handles it
        should_stream = len(raw_targets) > 1000  # Simple heuristic for streaming

        if should_stream:
            print(f"{Colors.YELLOW}[*] Large target set detected - using streaming mode{Colors.RESET}")
            # Streaming logic needs to be updated to handle new target objects
            return await process_streaming_scan(raw_targets, concurrency, output_csv, module_filter, custom_ports, chunk_size, state_manager)
        
        # Regular processing for smaller target sets
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
            targets = await process_targets(raw_targets) # Reprocess to get the objects

        if not targets:
            print("[!] No valid targets to scan. Exiting.")
            return

        # 2. Define service ports and run the port scan
        service_ports = get_service_ports()
        
        if module_filter:
            print(f"{Colors.YELLOW}[*] Module filter: Scanning only {module_filter.capitalize()} services{Colors.RESET}")
            service_ports = {module_filter: service_ports.get(module_filter, [])}
        
        all_ports_to_scan = [port for ports in service_ports.values() for port in ports]
        
        if custom_ports:
            try:
                custom_port_list = [int(port.strip()) for port in custom_ports.split(',')]
                all_ports_to_scan.extend(custom_port_list)
                all_ports_to_scan = list(set(all_ports_to_scan))
                print(f"{Colors.YELLOW}[*] Added custom ports: {custom_port_list}{Colors.RESET}")
            except ValueError as e:
                print(f"{Colors.RED}[!] Error parsing custom ports: {e}. Ignoring custom ports.{Colors.RESET}")
        
        state_manager.set_totals(len(targets), len(targets) * len(all_ports_to_scan))
        
        if state_manager.state["phase"] in ["initializing", "target_processing_complete", "port_scanning"]:
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
    if state_manager.state["phase"] in ["port_scanning_complete", "service_validation"]:
        validation_tasks = []
        service_mapping = []
        
        print(f"\n[*] Validating services on open ports...")
        state_manager.update_phase("service_validation")
        
        for target_obj, data in open_ports_results:
            if not data['open_ports']:
                continue

            scan_address = target_obj['scan_address']
            display_target = target_obj['display_target']
            
           # print(f"\n[*] Found open ports on {display_target} ({scan_address}): {data['open_ports']}")
            
            for port in data['open_ports']:
                for service, service_ports_list in service_ports.items():
                    if port in service_ports_list:
                        scanner_func = SERVICE_TO_MODULE[service].run_scans
                        validation_tasks.append(validate_service(service, scan_address, port))
                        service_mapping.append((service, target_obj, port, scanner_func))

                if custom_ports and port not in [p for ports in service_ports.values() for p in ports]:
                    print(f"{Colors.YELLOW}[*] Custom port {port} detected, attempting service identification...{Colors.RESET}")
                    original_service_ports = get_service_ports()
                    for service_name in original_service_ports.keys():
                        if module_filter is None or service_name == module_filter:
                            scanner_func = SERVICE_TO_MODULE[service_name].run_scans
                            validation_tasks.append(validate_service(service_name, scan_address, port))
                            service_mapping.append((service_name, target_obj, port, scanner_func))
        
        if not validation_tasks:
            print("\n[*] No potential services found on open ports.")
            state_manager.mark_completed()
            return
        
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
                print(f"[!] Error scanning {target_obj['scan_address']}:{port} - {e}")
                return []

        for is_valid, (service, target_obj, port, scanner_func) in zip(validation_results, service_mapping):
            if isinstance(is_valid, bool) and is_valid:
                print(f"  -> Running {service.capitalize()} scans on http://{target_obj['scan_address']}:{port}")
                state_manager.add_validated_service(target_obj['resolved_ip'], port, service)
                scan_tasks.append(scan_with_state_saving(scanner_func, target_obj, port))
                validated_services += 1
            else:
                # This can get noisy, so we'll omit the "skipped" message for now
                pass
        
        if validated_services == 0:
            print("\n[*] No validated services found on the provided targets.")
            state_manager.mark_completed()
            return

        print(f"{Colors.CYAN}\n[*] Validated {validated_services} service(s). Starting VaktScan vulnerability assessment...{Colors.RESET}")
        state_manager.update_phase("vulnerability_scanning")
        
        if scan_tasks:
            await asyncio.gather(*scan_tasks, return_exceptions=True)
        state_manager.update_phase("vulnerability_scanning_complete")
        
    else:
        print(f"\n[*] Using previously found vulnerabilities...")

    # 4. Deduplicate, print results, and optionally save to CSV
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
    elif output_csv and not final_vulnerabilities:
        print("[*] No vulnerabilities to save to CSV.")
    
    state_manager.mark_completed()
    print(f"\n{state_manager.get_scan_summary()}")
    print(f"{Colors.BRIGHT_GREEN}[*] Scan finished.{Colors.RESET}")
    
    state_manager.cleanup_state_file()

async def process_streaming_scan(raw_targets, concurrency, output_csv=False, module_filter=None, custom_ports=None, chunk_size=30000, state_manager=None):
    """
    Processes large target sets in streaming chunks.
    (Note: This function needs significant updates to align with the new object structure)
    """
    print(f"{Colors.RED}[!] Streaming mode is not fully compatible with the new hostname/IP logic yet. Running in non-streaming mode.{Colors.RESET}")
    # Fallback to regular main function for now. A proper implementation would require
    # careful state management of target objects across chunks.
    await main(state_manager.targets_file, concurrency, state_manager.is_resume, output_csv, module_filter, custom_ports, chunk_size)
    return

async def print_final_results(all_vulnerabilities, output_csv):
    """Deduplicates and prints final vulnerability results."""
    final_vulnerabilities = deduplicate_vulnerabilities(all_vulnerabilities)
    
    print(f"{Colors.BRIGHT_CYAN}\n" + "="*50 + f"{Colors.RESET}")
    print(f"{Colors.BRIGHT_YELLOW}{Colors.BOLD}      Final Vulnerability Results{Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}" + "="*50 + f"\n{Colors.RESET}")
    
    if final_vulnerabilities:
        for result in final_vulnerabilities:
            if result['status'] == 'VULNERABLE':
                status_color = Colors.BRIGHT_RED
            # ... (rest of the printing logic) ...
    else:
        print(f"{Colors.GREEN}[*] No vulnerabilities found.{Colors.RESET}")
    
    if output_csv and final_vulnerabilities:
        save_results_to_csv(final_vulnerabilities)

async def resume_streaming_scan(state_manager, raw_targets, concurrency, output_csv=False, module_filter=None, custom_ports=None, chunk_size=30000):
    """
    Resume a streaming scan from saved state.
    (Note: This also needs updates for the new logic)
    """
    print(f"{Colors.RED}[!] Resuming streaming scans is not fully compatible with the new logic yet.{Colors.RESET}")
    await main(state_manager.targets_file, concurrency, True, output_csv, module_filter, custom_ports, chunk_size)
    return


if __name__ == "__main__":
    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        print_logo()
    
    parser = argparse.ArgumentParser(description="Security scanner for ELK, Grafana, Prometheus, and Next.js stacks.")
    parser.add_argument("targets_file", help="Path to a file containing targets (IPs, hostnames, domains, subnets).")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Number of concurrent tasks to run.")
    parser.add_argument("-r", "--resume", action="store_true", help="Resume an interrupted scan from saved state.")
    parser.add_argument("--csv", action="store_true", help="Save results to CSV file.")
    parser.add_argument("-m", "--module", choices=["elasticsearch", "kibana", "grafana", "prometheus", "nextjs"], 
                        help="Scan only specific service module (default: all modules)")
    parser.add_argument("-p", "--ports", type=str, 
                        help="Additional custom ports to scan (comma-separated, e.g., 8080,8443,9999)")
    parser.add_argument("--chunk-size", type=int, default=30000,
                        help="Number of IPs to process per chunk in streaming mode (default: 30000, auto-enabled for 30k+ IPs)")
    args = parser.parse_args()

    try:
        asyncio.run(main(args.targets_file, args.concurrency, args.resume, args.csv, args.module, args.ports, args.chunk_size))
    except KeyboardInterrupt:
        print("\n[*] Scanner terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)