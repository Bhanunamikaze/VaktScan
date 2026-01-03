import asyncio
import ast
import getpass
import json
import os
import re
import shlex
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

# Color codes (matching main.py)
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

class ReconScanner:
    def __init__(self, domain, output_dir="recon_results", wordlist=None):
        self.domain = domain.strip().lower()
        self.output_dir = output_dir
        self.wordlist = wordlist
        self.subdomains = set()
        self.raw_candidates = []
        self.tools = {
            "amass": "amass",
            "subfinder": "subfinder",
            "assetfinder": "assetfinder",
            "findomain": "findomain",
            "sublist3r": "sublist3r",
            "knockpy": "knockpy",
            "bbot": "bbot",
            "censys": "censys",
            "crtsh": "crtsh"
        }
        self.domain_pattern = re.compile(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}")
        self.sudo_ready = os.geteuid() == 0 if hasattr(os, "geteuid") else False

        os.makedirs(self.output_dir, exist_ok=True)
        safe_domain = re.sub(r"[^a-z0-9._-]", "_", self.domain)
        self.domain_dir = os.path.join(self.output_dir, safe_domain or "domain")
        os.makedirs(self.domain_dir, exist_ok=True)

        self._ansi_regex = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        self.sudo_tools = set()

    def check_tools(self):
        """Verifies that required tools are installed in PATH."""
        missing = []
        for name, binary in self.tools.items():
            if not shutil.which(binary):
                # Special check for sublist3r as it might be a python script
                if name == "sublist3r" and shutil.which("sublist3r.py"):
                    self.tools["sublist3r"] = "sublist3r.py"
                    continue
                if name == "bbot":
                    local_bbot = os.path.expanduser("~/.local/bin/bbot")
                    if os.path.exists(local_bbot):
                        self.tools["bbot"] = local_bbot
                        continue
                missing.append(name)
        return missing

    def ensure_sudo_session(self):
        """Prompt once for sudo if required tools need elevation."""
        if self.sudo_ready or os.name != "posix":
            return True
        if not shutil.which("sudo"):
            print(f"{Colors.YELLOW}[!] sudo not available. Skipping tools that require it.{Colors.RESET}")
            return False
        print(f"{Colors.CYAN}[*] Elevated privileges required for: {', '.join(sorted(self.sudo_tools))}.{Colors.RESET}")
        try:
            password = getpass.getpass(prompt="sudo password (input hidden): ")
        except Exception:
            password = ""
        if not password:
            print(f"{Colors.YELLOW}[!] No sudo password provided. Privileged tools will be skipped.{Colors.RESET}")
            return False
        try:
            subprocess.run(
                ["sudo", "-S", "-v"],
                input=f"{password}\n",
                check=True,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.sudo_ready = True
            return True
        except subprocess.CalledProcessError:
            print(f"{Colors.RED}[!] sudo authentication failed. Skipping privileged tools.{Colors.RESET}")
            return False

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
        outfile = os.path.join(self.domain_dir, f"amass_{self.domain}.txt")
        cmd = f"amass enum -passive -d {self.domain} -o {outfile} -silent"
        await self._run_command(cmd, "Amass")
        self._collect_results(outfile)

    async def run_subfinder(self):
        outfile = os.path.join(self.domain_dir, f"subfinder_{self.domain}.txt")
        cmd = f"subfinder -d {self.domain} -o {outfile} -silent"
        await self._run_command(cmd, "Subfinder")
        self._collect_results(outfile)

    async def run_assetfinder(self):
        # Assetfinder outputs to stdout
        cmd = f"assetfinder --subs-only {self.domain}"
        results = await self._run_command(cmd, "Assetfinder")
        outfile = os.path.join(self.domain_dir, f"assetfinder_{self.domain}.txt")
        with open(outfile, 'w') as f:
            for line in results:
                f.write(f"{line}\n")
                self._add_subdomain(line)

    async def run_findomain(self):
        outfile = os.path.join(self.domain_dir, f"findomain_{self.domain}.txt")
        # Findomain requires -q for quiet
        cmd = f"findomain -t {self.domain} -u {outfile} -q"
        await self._run_command(cmd, "Findomain")
        self._collect_results(outfile)

    async def run_sublist3r(self):
        outfile = os.path.join(self.domain_dir, f"sublist3r_{self.domain}.txt")
        cmd = f"sublist3r -d {self.domain} -o {outfile}"
        await self._run_command(cmd, "Sublist3r")
        self._collect_results(outfile)

    async def run_knockpy(self):
        """Fixed knockpy - captures JSON directly from stdout"""
        binary = shlex.quote(self.tools.get("knockpy", "knockpy"))
        # Use --silent json to get output directly on stdout
        cmd = f"{binary} -d {shlex.quote(self.domain)} --recon --json"
        
        results = await self._run_command(cmd, "Knockpy")
        
        if not results:
            print(f"{Colors.YELLOW}[!] Knockpy produced no output.{Colors.RESET}")
            return
        
        # Save the JSON output
        json_outfile = os.path.join(self.domain_dir, f"knockpy_{self.domain}.json")
        raw_text = "\n".join(results).strip()
        
        try:
            with open(json_outfile, 'w') as f:
                f.write(raw_text)
            #print(f"{Colors.GREEN}[+] Knockpy output saved to: {json_outfile}{Colors.RESET}")
        except OSError as e:
            print(f"{Colors.YELLOW}[!] Failed to write knockpy output: {e}{Colors.RESET}")
        
        # Parse the JSON payload
        parsed = self._parse_knockpy_payload(raw_text)
        if parsed:
            for entry in parsed:
                if isinstance(entry, dict):
                    domain = entry.get("domain", "") or entry.get("Domain", "")
                    if domain:
                        self._add_subdomain(domain)
            #print(f"{Colors.GREEN}[+] Knockpy found {len(parsed)} entries.{Colors.RESET}")
        else:
            # Fallback: try to extract domains from raw output
            self._collect_from_lines(results)


    async def run_bbot(self):
        """Run bbot and harvest subdomain output."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        outdir = os.path.join(self.domain_dir, "bbot_results")
        os.makedirs(outdir, exist_ok=True)

        binary = shlex.quote(self.tools.get("bbot", "bbot"))
        cmd = (
            f"{binary} -t {shlex.quote(self.domain)} "
            f"-p subdomain-enum "
            f"-o {shlex.quote(outdir)} "
            "-y --force"
        )

        print(f"{Colors.CYAN}[*] Running BBOT scan (this may take time)...{Colors.RESET}")
        results = await self._run_command(cmd, "bbot")

        path_obj = Path(outdir)
        candidates = list(path_obj.rglob("subdomains.txt")) + list(path_obj.rglob("output.txt"))

        if candidates:
            candidates.sort(key=lambda p: -p.stat().st_mtime)
            for idx, fpath in enumerate(candidates[:3], start=1):
                try:
                    dest_name = f"bbot_{self.domain}_{timestamp}_{idx}_{fpath.name}"
                    dest_path = os.path.join(self.domain_dir, dest_name)
                    shutil.copy2(fpath, dest_path)
                    self._collect_results(dest_path)
                    #print(f"{Colors.GREEN}[+] BBOT results saved: {dest_path}{Colors.RESET}")
                except Exception as exc:
                    print(f"{Colors.YELLOW}[!] Failed to copy {fpath}: {exc}{Colors.RESET}")
            return

        print(f"{Colors.YELLOW}[!] No BBOT output files found, falling back to console output.{Colors.RESET}")
        self._collect_from_lines(results if results else [])

    async def run_censys(self):
        binary = shlex.quote(self.tools.get("censys", "censys"))
        query = shlex.quote(f"names: {self.domain}")
        cmd = (
            f"{binary} search {query} --index-type hosts "
            "--per-page 500 --virtual-hosts INCLUDE --no-color"
        )
        results = await self._run_command(cmd, "Censys")
        outfile = os.path.join(self.domain_dir, f"censys_{self.domain}.txt")
        self._write_list(outfile, results)
        self._collect_results(outfile)

    async def run_crtsh(self):
        binary = shlex.quote(self.tools.get("crtsh", "crtsh"))
        cmd = f"{binary} -d {shlex.quote(self.domain)} -r"
        results = await self._run_command(cmd, "crtsh")
        outfile = os.path.join(self.domain_dir, f"crtsh_{self.domain}.txt")
        self._write_list(outfile, results)
        self._collect_results(outfile)

    def _collect_results(self, filepath):
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    for line in f:
                        self._add_subdomain(line.strip())
            except Exception:
                pass

    def _collect_from_lines(self, lines):
        if not lines:
            return
        for line in lines:
            self._add_subdomain(line)

    def _extract_candidates(self, text):
        matches = []
        if not text:
            return matches
        lower_text = text.lower()
        seen = set()
        for match in self.domain_pattern.findall(lower_text):
            match = match.strip(".")
            if match == self.domain or match.endswith(f".{self.domain}"):
                if match not in seen:
                    seen.add(match)
                    matches.append(match)
        return matches

    def _add_subdomain(self, sub):
        if not sub:
            return False
        added = False
        sub = sub.strip()
        if not sub:
            return False
        candidates = self._extract_candidates(sub)
        for candidate in candidates:
            self.raw_candidates.append(candidate)
            if candidate not in self.subdomains:
                self.subdomains.add(candidate)
                added = True
        return added

    def _write_list(self, path, values):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            for value in values:
                f.write(f"{value}\n")

    async def run_all(self):
        missing = self.check_tools()
        if missing:
            print(f"{Colors.YELLOW}[!] Warning: The following tools were not found in PATH: {', '.join(missing)}{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Scanning will proceed with available tools.{Colors.RESET}")

        disabled = set()
        sudo_needed = [tool for tool in self.sudo_tools if tool not in missing]
        if sudo_needed and not self.ensure_sudo_session():
            disabled.update(sudo_needed)
            print(f"{Colors.YELLOW}[!] Skipping privileged tools: {', '.join(sorted(disabled))}{Colors.RESET}")

        tasks = []
        if "amass" not in missing: tasks.append(self.run_amass())
        if "subfinder" not in missing: tasks.append(self.run_subfinder())
        if "assetfinder" not in missing: tasks.append(self.run_assetfinder())
        if "findomain" not in missing: tasks.append(self.run_findomain())
        if "sublist3r" not in missing: tasks.append(self.run_sublist3r())
        if "knockpy" not in missing: tasks.append(self.run_knockpy())
        if "bbot" not in missing and "bbot" not in disabled: tasks.append(self.run_bbot())
        if "censys" not in missing: tasks.append(self.run_censys())
        if "crtsh" not in missing: tasks.append(self.run_crtsh())
        
        # Run passive tools concurrently
        if tasks:
            await asyncio.gather(*tasks)
        
        # Run ffuf-based enumeration via the standalone DirEnumerator
        # Save combined + deduplicated results inside the domain output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        raw_file = os.path.join(self.domain_dir, f"raw_subdomains_{timestamp}.txt")
        final_file = os.path.join(self.domain_dir, f"all_subdomains_{timestamp}.txt")

        self._write_list(raw_file, self.raw_candidates)
        self._write_list(final_file, sorted(self.subdomains))
        
        print(f"\n{Colors.GREEN}[+] Enumeration complete!{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Found {len(self.subdomains)} unique subdomains.{Colors.RESET}")
        print(f"{Colors.GRAY}[*] Raw combined output: {raw_file}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Results saved to: {Colors.BOLD}{final_file}{Colors.RESET}")
        
        return final_file, sorted(self.subdomains)

    def _parse_knockpy_payload(self, payload):
        if not payload:
            return None
        cleaned = self._ansi_regex.sub('', payload)
        cleaned = cleaned.strip()
        if not cleaned:
            return None

        markers = ["[{'domain'", '[{"domain"', "[{'Domain'", '[{"Domain"']
        start_idx = -1
        for marker in markers:
            idx = cleaned.find(marker)
            if idx != -1:
                start_idx = cleaned.rfind('[', 0, idx + 1)
                if start_idx == -1:
                    start_idx = idx
                break
        if start_idx == -1:
            start_idx = cleaned.find('[')

        if start_idx > 0:
            cleaned = cleaned[start_idx:]

        end_idx = cleaned.rfind(']')
        if end_idx != -1:
            cleaned = cleaned[:end_idx + 1]

        if not cleaned.startswith('['):
            return None

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        try:
            return ast.literal_eval(cleaned)
        except Exception:
            return None
