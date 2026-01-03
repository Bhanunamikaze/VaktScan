import asyncio
import importlib
import json
import os
import re
import shlex
import shutil
import subprocess
from datetime import datetime
from urllib.parse import urlparse


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
        self.dirsearch_binary = shutil.which("dirsearch")

        if self.dirsearch_binary:
            self._ensure_dirsearch_dependencies()

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def is_available(self):
        return self.binary is not None

    def dirsearch_available(self):
        return self.dirsearch_binary is not None

    def _install_python_dependency(self, module_name):
        try:
            subprocess.run(
                ["python3", "-m", "pip", "install", "--user", module_name],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            print(f"{Colors.GREEN}[+] Installed Python dependency '{module_name}' for dirsearch.{Colors.RESET}")
            return True
        except subprocess.CalledProcessError as exc:
            print(f"{Colors.RED}[!] Failed to install '{module_name}': {exc.stderr.strip() if exc.stderr else exc}{Colors.RESET}")
            return False

    def _ensure_dirsearch_dependencies(self):
        """Installs dirsearch python dependencies if they are missing."""
        dependencies = {
            "requests_ntlm": "requests-ntlm",
            "pyparsing": "pyparsing",
        }
        for module_name, pip_name in dependencies.items():
            try:
                importlib.import_module(module_name)
            except ImportError:
                print(
                    f"{Colors.YELLOW}[!] dirsearch dependency '{module_name}' missing. Installing locally...{Colors.RESET}"
                )
                self._install_python_dependency(pip_name)

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

    async def _run_dirsearch_target(self, url, threads, env, reports_dir):
        binary = shlex.quote(self.dirsearch_binary)
        parsed = urlparse(url)
        label = parsed.netloc or parsed.path or url
        safe_label = re.sub(r"[^a-z0-9._-]", "_", label.lower()) or "target"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(reports_dir, f"dirsearch_report_{safe_label}_{timestamp}.txt")
        cmd = (
            f"{binary} -u {shlex.quote(url)} "
            f"--output={shlex.quote(output_file)} --format=simple "
            "--force-recursive --exclude-status=404,401,400,403,500-599 "
            f"-t {threads} --random-agent"
        )

        attempt = 0
        while attempt < 2:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=None,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            _, stderr = await process.communicate()

            if process.returncode == 0:
                if stderr:
                    err = stderr.decode().strip()
                    if err:
                        print(err)
                print(f"{Colors.GREEN}[+] dirsearch report saved: {output_file}{Colors.RESET}")
                return output_file

            err_text = stderr.decode().strip() if stderr else ""
            match = re.search(r"ModuleNotFoundError: No module named '([^']+)'", err_text)
            if match and attempt == 0:
                missing = match.group(1)
                print(f"{Colors.YELLOW}[!] dirsearch missing Python module '{missing}'. Installing...{Colors.RESET}")
                if self._install_python_dependency(missing):
                    print(f"{Colors.CYAN}[*] Retrying dirsearch after installing '{missing}'.{Colors.RESET}")
                    attempt += 1
                    continue

            if err_text:
                print(err_text)
            print(f"{Colors.RED}[!] dirsearch failed for {url} with exit code {process.returncode}.{Colors.RESET}")
            return None

        return None

    async def run_dirsearch(self, urls, threads=30, parallel_targets=20):
        """
        Runs dirsearch against a list of alive URLs with limited parallel execution.
        """
        if not urls:
            print(f"{Colors.YELLOW}[!] No HTTP services provided to dirsearch.{Colors.RESET}")
            return None
        if not self.dirsearch_available():
            print(f"{Colors.YELLOW}[!] dirsearch not found in PATH. Skipping directory enumeration.{Colors.RESET}")
            return None

        reports_dir = os.path.join(self.output_dir, "dirsearch_reports")
        os.makedirs(reports_dir, exist_ok=True)

        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        env.pop("VIRTUAL_ENV", None)

        unique_urls = sorted(set(urls))
        max_parallel = max(1, parallel_targets)
        semaphore = asyncio.Semaphore(max_parallel)

        print(
            f"{Colors.CYAN}[*] Running dirsearch against {len(unique_urls)} alive targets "
            f"(max {max_parallel} concurrent)...{Colors.RESET}"
        )

        async def runner(target_url):
            async with semaphore:
                try:
                    return await self._run_dirsearch_target(target_url, threads, env, reports_dir)
                except Exception as exc:
                    print(f"{Colors.RED}[!] dirsearch internal error for {target_url}: {exc}{Colors.RESET}")
                    return exc

        try:
            tasks = [asyncio.create_task(runner(url)) for url in unique_urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as exc:
            print(f"{Colors.RED}[!] dirsearch execution error: {exc}{Colors.RESET}")
            return None

        success = [res for res in results if isinstance(res, str)]
        failures = [res for res in results if res is None or isinstance(res, Exception)]

        if success:
            print(f"{Colors.GREEN}[+] dirsearch completed for {len(success)} target(s). Reports stored in {reports_dir}.{Colors.RESET}")
            if failures:
                print(f"{Colors.YELLOW}[!] {len(failures)} target(s) failed. Check logs above for details.{Colors.RESET}")
            return reports_dir

        print(f"{Colors.RED}[!] dirsearch failed for all targets.{Colors.RESET}")
        return None
