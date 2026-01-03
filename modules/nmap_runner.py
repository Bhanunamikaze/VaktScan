import asyncio
import shutil
import os
from datetime import datetime

class NmapRunner:
    def __init__(self, output_base_dir="recon_results"):
        self.output_base_dir = output_base_dir
        # Create a specific nmap directory inside recon_results
        self.nmap_dir = os.path.join(self.output_base_dir, "nmap_scans")
        if not os.path.exists(self.nmap_dir):
            os.makedirs(self.nmap_dir)
        self.binary = "nmap"
        self.check_installed()

    def check_installed(self):
        """Checks if nmap is available in the system PATH."""
        if not shutil.which(self.binary):
             self.binary = None

    async def run_nmap_on_target(self, ip, ports, hostname=None):
        """
        Runs nmap on a specific target for specific ports.
        """
        if not self.binary or not ports:
            return

        # Sanitize filename: use hostname if available, else IP
        raw_name = hostname if hostname and hostname != 'N/A' else ip
        # Basic sanitization to prevent filesystem issues
        safe_name = "".join([c for c in raw_name if c.isalnum() or c in ['.', '-', '_']]).strip()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        output_file = os.path.join(self.nmap_dir, f"{safe_name}_{timestamp}.nmap")
        
        ports_str = ",".join(map(str, ports))
        
        # Command: nmap -sCV -Pn -p <ports> <ip> -oN <file>
        # -sCV: Script scan + Version detection
        # -Pn: Treat host as online (skip discovery)
        cmd = f"{self.binary} -sCV -Pn -p {ports_str} {ip} -oN {output_file}"
        
        print(f"\033[96m[*] Starting nmap on {safe_name} ({len(ports)} ports)...\033[0m")
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            # We await communication to ensure process finishes
            stdout, stderr = await process.communicate()
            
            if os.path.exists(output_file):
                print(f"\033[92m[+] Nmap finished for {safe_name}. Saved to: {output_file}\033[0m")
            else:
                 # Only print error if file wasn't created, as nmap writes progressively
                 print(f"\033[91m[!] Nmap failed to create output for {safe_name}.\033[0m")
                 if stderr:
                     print(f"\033[90m    Error: {stderr.decode().strip()}\033[0m")

        except Exception as e:
            print(f"\033[91m[!] Error running nmap on {safe_name}: {e}\033[0m")

    async def run_batch(self, targets_data, concurrency=10):
        """
        Orchestrates concurrent nmap scans.
        targets_data: list of tuples (ip, ports_list, hostname)
        """
        if not self.binary:
            print("\033[93m[!] nmap binary not found. Skipping nmap scans.\033[0m")
            return

        if not targets_data:
            print("\033[93m[*] No targets with open ports to scan with Nmap.\033[0m")
            return

        print(f"\n\033[95m[+] Starting Nmap Script/Version Scans on {len(targets_data)} targets...\033[0m")
        print(f"\033[90m[*] Results directory: {self.nmap_dir}\033[0m")
        
        # Nmap is heavy, so we limit concurrency separate from the main scanner
        # default to 10 or user provided if lower
        actual_concurrency = min(concurrency, 10) 
        semaphore = asyncio.Semaphore(actual_concurrency)

        async def sem_task(t_data):
            async with semaphore:
                await self.run_nmap_on_target(t_data[0], t_data[1], t_data[2])

        tasks = [sem_task(t) for t in targets_data]
        await asyncio.gather(*tasks)
        print(f"\033[92m[+] All Nmap scans completed.\033[0m")