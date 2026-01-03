import asyncio
import os
import re
import shutil
from datetime import datetime


class WaybackURLsRunner:
    """
    Wrapper for tomnomnom/waybackurls to fetch archived endpoints.
    """

    def __init__(self, output_dir="recon_results", concurrency=20):
        self.output_dir = output_dir
        self.concurrency = max(1, concurrency)
        os.makedirs(self.output_dir, exist_ok=True)
        self.results_dir = os.path.join(self.output_dir, "waybackurls")
        os.makedirs(self.results_dir, exist_ok=True)
        self.binary = self._resolve_binary()

    def _resolve_binary(self):
        candidates = [
            os.environ.get("VAKT_WAYBACK_BIN"),
            "/usr/local/bin/waybackurls",
            "/opt/homebrew/bin/waybackurls",
            shutil.which("waybackurls"),
            os.path.expanduser("~/.local/bin/waybackurls"),
        ]
        for cand in candidates:
            path = self._normalize_path(cand)
            if path:
                return path
        return None

    def _normalize_path(self, candidate):
        if not candidate:
            return None
        expanded = os.path.expanduser(candidate)
        if os.path.isabs(expanded):
            return expanded if os.path.exists(expanded) else None
        return shutil.which(expanded)

    async def run(self, domains):
        """
        Runs waybackurls against a list of domains, saving output per host.
        Returns dict {domain: [urls]}.
        """
        if not self.binary:
            print("\033[93m[!] waybackurls binary not found in PATH. Skipping Wayback collection.\033[0m")
            return {}

        normalized = sorted({(domain or "").strip().lower() for domain in domains if domain})
        if not normalized:
            return {}

        semaphore = asyncio.Semaphore(self.concurrency)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tasks = [
            asyncio.create_task(self._run_single(domain, semaphore, timestamp))
            for domain in normalized
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        aggregated = {}
        total_urls = 0
        for result in results:
            if isinstance(result, tuple):
                domain, urls = result
                aggregated[domain] = urls
                total_urls += len(urls)
            elif isinstance(result, Exception):
                print(f"\033[91m[!] waybackurls error: {result}\033[0m")

        if aggregated:
            print(f"\033[92m[+] waybackurls collected {total_urls} URLs across {len(aggregated)} domains.\033[0m")
        else:
            print(f"\033[93m[!] waybackurls did not return any URLs.\033[0m")
        return aggregated

    async def _run_single(self, domain, semaphore, timestamp):
        safe_domain = re.sub(r"[^a-z0-9._-]", "_", domain)
        outfile = os.path.join(self.results_dir, f"waybackurls_{safe_domain}_{timestamp}.txt")
        cmd = [self.binary, domain]
        print(f"\033[96m[*] waybackurls → {domain}\033[0m")
        async with semaphore:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

        if stderr:
            err_text = stderr.decode().strip()
            if err_text:
                print(f"\033[90m[!] waybackurls ({domain}) stderr: {err_text}\033[0m")

        urls = [line.strip() for line in stdout.decode().splitlines() if line.strip()]
        if urls:
            try:
                with open(outfile, "w", encoding="utf-8") as handle:
                    for url in urls:
                        handle.write(f"{url}\n")
                print(f"\033[92m[+] waybackurls results saved: {outfile}\033[0m")
            except OSError as exc:
                print(f"\033[91m[!] Failed to write waybackurls output for {domain}: {exc}\033[0m")
        else:
            try:
                if os.path.exists(outfile):
                    os.remove(outfile)
            except OSError:
                pass

        return domain, urls
