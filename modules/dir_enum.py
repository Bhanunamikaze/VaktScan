import asyncio
import json
import os
import shlex
import shutil
from datetime import datetime


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


class DirEnumerator:
    """
    Wrapper around ffuf to keep directory/subdomain brute-force logic separate
    from the ReconScanner. Currently focuses on virtual-host (subdomain) fuzzing.
    """

    def __init__(self, domain, wordlist=None, output_dir="recon_results", protocol="https"):
        self.domain = domain.strip().lower()
        self.wordlist = wordlist
        self.output_dir = output_dir
        self.protocol = protocol
        self.binary = shutil.which("ffuf")

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def is_available(self):
        return self.binary is not None

    async def fuzz_subdomains(self, match_codes="200,301,302,403"):
        """
        Run ffuf using a Host header fuzz technique to discover virtual hosts.
        Returns a list of discovered subdomains (as FQDNs).
        """
        if not self.wordlist:
            print(f"{Colors.YELLOW}[!] Wordlist not provided. Skipping ffuf enumeration.{Colors.RESET}")
            return []

        if not self.is_available():
            print(f"{Colors.YELLOW}[!] ffuf binary not found in PATH. Skipping DirEnumerator.{Colors.RESET}")
            return []

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        outfile = os.path.join(self.output_dir, f"ffuf_{self.domain}_{timestamp}.json")

        binary = shlex.quote(self.binary)
        cmd = (
            f"{binary} -u {self.protocol}://{self.domain} "
            f"-H 'Host: FUZZ.{self.domain}' "
            f"-w {shlex.quote(self.wordlist)} -o {shlex.quote(outfile)} "
            f"-of json -mc {match_codes} -ac -s"
        )

        print(f"{Colors.CYAN}[*] Running ffuf for active vhost fuzzing (DirEnumerator)...{Colors.RESET}")
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            _, stderr = await process.communicate()
        except Exception as exc:
            print(f"{Colors.RED}[!] Error starting ffuf: {exc}{Colors.RESET}")
            return []

        if not os.path.exists(outfile):
            if stderr:
                print(f"{Colors.RED}[!] ffuf failed: {stderr.decode().strip()}{Colors.RESET}")
            return []

        discovered = []
        try:
            with open(outfile, 'r') as f:
                data = json.load(f)
            for result in data.get("results", []):
                fuzz_value = result.get("input", {}).get("FUZZ")
                if fuzz_value:
                    full_domain = f"{fuzz_value}.{self.domain}"
                    discovered.append(full_domain.lower())
        except Exception as exc:
            print(f"{Colors.RED}[!] Error parsing ffuf output: {exc}{Colors.RESET}")
            return []

        unique_subs = sorted(set(discovered))
        print(f"{Colors.GREEN}[+] DirEnumerator discovered {len(unique_subs)} potential subdomains with ffuf.{Colors.RESET}")
        return unique_subs
