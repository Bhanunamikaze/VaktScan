import asyncio
import shutil
import os
import sys
from datetime import datetime

# Color codes (matching main.py)
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

class ReconScanner:
    def __init__(self, domain, output_dir="recon_results", wordlist=None):
        self.domain = domain
        self.output_dir = output_dir
        self.wordlist = wordlist
        self.subdomains = set()
        self.tools = {
            "amass": "amass",
            "subfinder": "subfinder",
            "assetfinder": "assetfinder",
            "findomain": "findomain",
            "sublist3r": "sublist3r",
            "ffuf": "ffuf"
        }
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def check_tools(self):
        """Verifies that required tools are installed in PATH."""
        missing = []
        for name, binary in self.tools.items():
            if not shutil.which(binary):
                # Special check for sublist3r as it might be a python script
                if name == "sublist3r" and shutil.which("sublist3r.py"):
                    self.tools["sublist3r"] = "sublist3r.py"
                    continue
                missing.append(name)
        return missing

    async def _run_command(self, cmd, tool_name):
        """Helper to run async subprocess commands."""
        print(f"{Colors.CYAN}[*] Running {tool_name}...{Colors.RESET}")
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                print(f"{Colors.GREEN}[+] {tool_name} completed successfully.{Colors.RESET}")
                return stdout.decode().strip().split('\n')
            else:
                # Some tools exit with non-zero even on partial success, so we still return output
                # but log the error
                error_msg = stderr.decode().strip()
                if error_msg:
                    # Filter out common "update" or "banner" noise
                    if "update" not in error_msg.lower(): 
                         pass # print(f"{Colors.YELLOW}[!] {tool_name} stderr: {error_msg}{Colors.RESET}")
                return stdout.decode().strip().split('\n')
        except Exception as e:
            print(f"{Colors.RED}[!] Error running {tool_name}: {e}{Colors.RESET}")
            return []

    async def run_amass(self):
        # Amass passive enum
        outfile = os.path.join(self.output_dir, f"amass_{self.domain}.txt")
        cmd = f"amass enum -passive -d {self.domain} -o {outfile} -silent"
        await self._run_command(cmd, "Amass")
        self._collect_results(outfile)

    async def run_subfinder(self):
        outfile = os.path.join(self.output_dir, f"subfinder_{self.domain}.txt")
        cmd = f"subfinder -d {self.domain} -o {outfile} -silent"
        await self._run_command(cmd, "Subfinder")
        self._collect_results(outfile)

    async def run_assetfinder(self):
        # Assetfinder outputs to stdout
        cmd = f"assetfinder --subs-only {self.domain}"
        results = await self._run_command(cmd, "Assetfinder")
        for line in results:
            self._add_subdomain(line)

    async def run_findomain(self):
        outfile = os.path.join(self.output_dir, f"findomain_{self.domain}.txt")
        # Findomain requires -q for quiet
        cmd = f"findomain -t {self.domain} -u {outfile} -q"
        await self._run_command(cmd, "Findomain")
        self._collect_results(outfile)

    async def run_sublist3r(self):
        outfile = os.path.join(self.output_dir, f"sublist3r_{self.domain}.txt")
        cmd = f"sublist3r -d {self.domain} -o {outfile}"
        await self._run_command(cmd, "Sublist3r")
        self._collect_results(outfile)

    async def run_ffuf_fuzzing(self):
        """Use ffuf to brute force subdomains/vhosts."""
        if not self.wordlist:
            print(f"{Colors.YELLOW}[!] No wordlist provided. Skipping active ffuf fuzzing.{Colors.RESET}")
            return

        outfile = os.path.join(self.output_dir, f"ffuf_{self.domain}.json")
        print(f"{Colors.CYAN}[*] Running ffuf for active subdomain fuzzing (this may take time)...{Colors.RESET}")
        
        # Fuzz Host header for VHost discovery/subdomain enumeration
        # -mc 200,301,302,403 filters for interesting codes
        # -ac Auto-calibrate to filter out false positives
        cmd = (
            f"ffuf -u https://{self.domain} -H 'Host: FUZZ.{self.domain}' "
            f"-w {self.wordlist} -o {outfile} -of json -mc 200,301,302,403 -ac -s"
        )
        
        await self._run_command(cmd, "ffuf")
        
        # Parse ffuf JSON output
        try:
            import json
            if os.path.exists(outfile):
                with open(outfile, 'r') as f:
                    data = json.load(f)
                    if 'results' in data:
                        count = 0
                        for result in data['results']:
                            sub = result['input']['FUZZ']
                            full_domain = f"{sub}.{self.domain}"
                            if self._add_subdomain(full_domain):
                                count += 1
                        print(f"{Colors.GREEN}[+] ffuf found {count} new subdomains/vhosts.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error parsing ffuf output: {e}{Colors.RESET}")

    def _collect_results(self, filepath):
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    for line in f:
                        self._add_subdomain(line.strip())
            except Exception:
                pass

    def _add_subdomain(self, sub):
        sub = sub.strip()
        # Basic validation to ensure it looks like a subdomain of our target
        if sub and self.domain in sub:
            # Remove protocol if present
            if "://" in sub:
                sub = sub.split("://")[1]
            if sub not in self.subdomains:
                self.subdomains.add(sub)
                return True
        return False

    async def run_all(self):
        missing = self.check_tools()
        if missing:
            print(f"{Colors.YELLOW}[!] Warning: The following tools were not found in PATH: {', '.join(missing)}{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Scanning will proceed with available tools.{Colors.RESET}")

        tasks = []
        if "amass" not in missing: tasks.append(self.run_amass())
        if "subfinder" not in missing: tasks.append(self.run_subfinder())
        if "assetfinder" not in missing: tasks.append(self.run_assetfinder())
        if "findomain" not in missing: tasks.append(self.run_findomain())
        if "sublist3r" not in missing: tasks.append(self.run_sublist3r())
        
        # Run passive tools concurrently
        if tasks:
            await asyncio.gather(*tasks)
        
        # Run active ffuf scanning sequentially after passive tools (to avoid network congestion)
        if "ffuf" not in missing:
            await self.run_ffuf_fuzzing()

        # Save final aggregated list
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        final_file = f"all_subdomains_{self.domain}_{timestamp}.txt"
        
        with open(final_file, 'w') as f:
            for sub in sorted(self.subdomains):
                f.write(f"{sub}\n")
        
        print(f"\n{Colors.GREEN}[+] Enumeration complete!{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Found {len(self.subdomains)} unique subdomains.{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Results saved to: {Colors.BOLD}{final_file}{Colors.RESET}")
        
        return final_file, list(self.subdomains)