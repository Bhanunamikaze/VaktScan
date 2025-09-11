import asyncio
import argparse
import sys
import os
import signal
import csv
import time
from urllib.parse import urlparse

# Add vendor directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'vendor'))

from utils import process_targets, get_service_ports
from port_scanner import scan_ports
from service_validator import validate_service
from scan_state import ScanStateManager
from modules import elastic, kibana, grafana, prometheus

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
{Colors.BRIGHT_CYAN}║{Colors.RESET}              {Colors.GREEN}Elasticsearch{Colors.RESET} • {Colors.GREEN}Kibana{Colors.RESET} • {Colors.GREEN}Grafana{Colors.RESET} • {Colors.GREEN}Prometheus{Colors.RESET}             {Colors.BRIGHT_CYAN}║{Colors.RESET}
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
    
    csv_headers = ['Timestamp', 'Status', 'Vulnerability', 'Target', 'Server', 'Port', 'Module', 'Service_Version', 'Severity', 'Details']
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(csv_headers)
            
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            for vuln in vulnerabilities:
                writer.writerow([
                    timestamp,
                    vuln.get('status', 'UNKNOWN'),
                    vuln.get('vulnerability', 'N/A'),
                    vuln.get('target', 'N/A'),
                    vuln.get('server', 'N/A'),
                    vuln.get('port', 'N/A'),
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

async def main(targets_file, concurrency, resume=False, output_csv=False, module_filter=None, custom_ports=None):
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
        if not is_resume or state_manager.state["phase"] == "initializing":
            print(f"{Colors.CYAN}[*] Parsing targets from {targets_file}...{Colors.RESET}")
            try:
                raw_targets = [line.strip() for line in open(targets_file, 'r')]
                unique_ips = await process_targets(raw_targets)
                print(f"{Colors.GREEN}[+] Successfully resolved {len(unique_ips)} unique IP addresses.{Colors.RESET}")
                state_manager.update_phase("target_processing_complete")
            except FileNotFoundError:
                print(f"{Colors.RED}[!] Error: Input file not found at {targets_file}{Colors.RESET}")
                return
            except Exception as e:
                print(f"[!] An error occurred during target processing: {e}")
                return
        else:
            print(f"[*] Using previously resolved {state_manager.state['total_ips']} unique IP addresses.")
            # For resume, we still need the IP list for processing
            raw_targets = [line.strip() for line in open(targets_file, 'r')]
            unique_ips = await process_targets(raw_targets)

        if not unique_ips:
            print("[!] No valid targets to scan. Exiting.")
            return

        # 2. Define service ports and run the port scan
        service_ports = get_service_ports()
        
        # Apply module filter if specified
        if module_filter:
            print(f"{Colors.YELLOW}[*] Module filter: Scanning only {module_filter.capitalize()} services{Colors.RESET}")
            service_ports = {module_filter: service_ports.get(module_filter, [])}
        
        all_ports_to_scan = [port for ports in service_ports.values() for port in ports]
        
        # Add custom ports if specified
        if custom_ports:
            try:
                custom_port_list = [int(port.strip()) for port in custom_ports.split(',')]
                all_ports_to_scan.extend(custom_port_list)
                all_ports_to_scan = list(set(all_ports_to_scan))  # Remove duplicates
                print(f"{Colors.YELLOW}[*] Added custom ports: {custom_port_list}{Colors.RESET}")
            except ValueError as e:
                print(f"{Colors.RED}[!] Error parsing custom ports: {e}. Ignoring custom ports.{Colors.RESET}")
        
        state_manager.set_totals(len(unique_ips), len(unique_ips) * len(all_ports_to_scan))
        
        if state_manager.state["phase"] in ["initializing", "target_processing_complete", "port_scanning"]:
            print(f"{Colors.CYAN}[*] Starting concurrent port scan for {len(unique_ips)} IPs across {len(all_ports_to_scan)} unique ports...{Colors.RESET}")
            state_manager.update_phase("port_scanning")
            
            open_ports_results = await scan_ports(unique_ips, all_ports_to_scan, concurrency, state_manager)
            print(f"{Colors.GREEN}[+] Port scanning complete.{Colors.RESET}")
            state_manager.update_phase("port_scanning_complete")
        else:
            print(f"[*] Using previously scanned port results...")
            # Reconstruct results from saved state
            open_ports_results = {}
            for ip in unique_ips:
                open_ports_results[ip] = {'open_ports': state_manager.state["open_ports"].get(ip, [])}
    
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
        
        for ip, data in open_ports_results.items():
            if not data['open_ports']:
                continue

            print(f"\n[*] Found open ports on {ip}: {data['open_ports']}")
            
            for port in data['open_ports']:
                # Check each potential service for this port
                # Only check services that are in the filtered service_ports dictionary
                if 'elasticsearch' in service_ports and port in service_ports.get('elasticsearch', []):
                    validation_tasks.append(validate_service('elasticsearch', ip, port))
                    service_mapping.append(('elasticsearch', ip, port, elastic.run_scans))
                if 'kibana' in service_ports and port in service_ports.get('kibana', []):
                    validation_tasks.append(validate_service('kibana', ip, port))
                    service_mapping.append(('kibana', ip, port, kibana.run_scans))
                if 'grafana' in service_ports and port in service_ports.get('grafana', []):
                    validation_tasks.append(validate_service('grafana', ip, port))
                    service_mapping.append(('grafana', ip, port, grafana.run_scans))
                if 'prometheus' in service_ports and port in service_ports.get('prometheus', []):
                    validation_tasks.append(validate_service('prometheus', ip, port))
                    service_mapping.append(('prometheus', ip, port, prometheus.run_scans))
                
                # Handle custom ports - attempt to identify service by trying validation
                if custom_ports and port not in [p for ports in service_ports.values() for p in ports]:
                    print(f"{Colors.YELLOW}[*] Custom port {port} detected, attempting service identification...{Colors.RESET}")
                    # Try to validate against all available services for custom ports
                    original_service_ports = get_service_ports()
                    for service_name in original_service_ports.keys():
                        if module_filter is None or service_name == module_filter:
                            validation_tasks.append(validate_service(service_name, ip, port))
                            if service_name == 'elasticsearch':
                                service_mapping.append((service_name, ip, port, elastic.run_scans))
                            elif service_name == 'kibana':
                                service_mapping.append((service_name, ip, port, kibana.run_scans))
                            elif service_name == 'grafana':
                                service_mapping.append((service_name, ip, port, grafana.run_scans))
                            elif service_name == 'prometheus':
                                service_mapping.append((service_name, ip, port, prometheus.run_scans))
        
        if not validation_tasks:
            print("\n[*] No potential services found on open ports.")
            state_manager.mark_completed()
            return
        
        # Run all validations concurrently
        validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
        
        # Create tasks only for validated services
        validated_services = 0
        for is_valid, (service, ip, port, scanner_func) in zip(validation_results, service_mapping):
            if isinstance(is_valid, bool) and is_valid:
                print(f"  -> Running {service.capitalize()} scans on http://{ip}:{port}")
                state_manager.add_validated_service(ip, port, service)
                validated_services += 1
            else:
                print(f"  -> Port {port} on {ip} is not running {service.capitalize()} (skipped)")
        
        if validated_services == 0:
            print("\n[*] No validated services found on the provided targets.")
            state_manager.mark_completed()
            return

        print(f"{Colors.CYAN}\n[*] Validated {validated_services} service(s). Starting VaktScan vulnerability assessment...{Colors.RESET}")
        state_manager.update_phase("vulnerability_scanning")
        
        # Custom wrapper to save vulnerabilities as they're found
        async def scan_with_state_saving(scan_func, ip, port):
            try:
                results = await scan_func(ip, port)
                for result in results:
                    state_manager.add_vulnerability(result)
                return results
            except Exception as e:
                print(f"[!] Error scanning {ip}:{port} - {e}")
                return []
        
        # Build scan tasks more clearly
        scan_tasks = []
        for is_valid, mapping in zip(validation_results, service_mapping):
            if isinstance(is_valid, bool) and is_valid:
                service, ip, port, scanner_func = mapping
                scan_tasks.append(scan_with_state_saving(scanner_func, ip, port))
        
        if scan_tasks:
            await asyncio.gather(*scan_tasks, return_exceptions=True)
        state_manager.update_phase("vulnerability_scanning_complete")
        
    else:
        print(f"\n[*] Using previously found vulnerabilities...")
        # For resume, vulnerabilities are already loaded in state

    # 4. Print results and optionally save to CSV
    print(f"{Colors.BRIGHT_CYAN}\n" + "="*50 + f"{Colors.RESET}")
    print(f"{Colors.BRIGHT_YELLOW}{Colors.BOLD}      Vulnerability Scan Results{Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}" + "="*50 + f"\n{Colors.RESET}")
    
    # Get all vulnerabilities from state
    all_vulnerabilities = state_manager.get_vulnerabilities()
    
    if all_vulnerabilities:
        for result in all_vulnerabilities:
            # Color code by vulnerability status
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
    
    # Save to CSV if requested
    if output_csv and all_vulnerabilities:
        csv_file = save_results_to_csv(all_vulnerabilities)
        if csv_file:
            print(f"{Colors.GREEN}[+] CSV report generated: {csv_file}{Colors.RESET}")
    elif output_csv and not all_vulnerabilities:
        print("[*] No vulnerabilities to save to CSV.")
    
    # Mark scan as completed and cleanup
    state_manager.mark_completed()
    print(f"\n{state_manager.get_scan_summary()}")
    print(f"{Colors.BRIGHT_GREEN}[*] Scan finished.{Colors.RESET}")
    
    # Clean up state file after successful completion
    state_manager.cleanup_state_file()

if __name__ == "__main__":
    # Show logo if no arguments or help is requested
    if len(sys.argv) == 1:
        print_logo()
        print(f"{Colors.RED}Error: Missing required argument{Colors.RESET}\n")
    elif '-h' in sys.argv or '--help' in sys.argv:
        print_logo()
    
    parser = argparse.ArgumentParser(description="Security scanner for ELK, Grafana, and Prometheus.")
    parser.add_argument("targets_file", help="Path to a file containing targets (IPs, hostnames, domains, subnets).")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Number of concurrent tasks to run.")
    parser.add_argument("-r", "--resume", action="store_true", help="Resume an interrupted scan from saved state.")
    parser.add_argument("--csv", action="store_true", help="Save results to CSV file.")
    parser.add_argument("-m", "--module", choices=["elasticsearch", "kibana", "grafana", "prometheus"], 
                        help="Scan only specific service module (default: all modules)")
    parser.add_argument("-p", "--ports", type=str, 
                        help="Additional custom ports to scan (comma-separated, e.g., 8080,8443,9999)")
    args = parser.parse_args()

    try:
        asyncio.run(main(args.targets_file, args.concurrency, args.resume, args.csv, args.module, args.ports))
    except KeyboardInterrupt:
        print("\n[*] Scanner terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)
