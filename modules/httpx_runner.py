import asyncio
import csv
import json
import os
import shutil
import subprocess
from datetime import datetime
from urllib.parse import urlparse

class HTTPXRunner:
    def __init__(self, output_dir="recon_results"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.binary = self._resolve_binary()

    def _resolve_binary(self):
        """Prefer the ProjectDiscovery binary (v1.7.4+) over any python httpx CLI."""
        candidates = [
            os.environ.get("VAKT_HTTPX_BIN"),
            "/usr/local/bin/httpx",
            "/opt/homebrew/bin/httpx",
            shutil.which("httpx"),
            shutil.which("pd-httpx"),
        ]
        seen = set()
        for cand in candidates:
            path = self._normalize_path(cand)
            if not path or path in seen:
                continue
            seen.add(path)
            if self._is_projectdiscovery_httpx(path):
                return path
        fallback = shutil.which("httpx")
        if fallback:
            print("\033[93m[!] ProjectDiscovery httpx not found. Falling back to system httpx at: "
                  f"{fallback}\033[0m")
            if "-l, -list" not in self._get_help_output(fallback):
                print("\033[91m[!] System httpx does not support the required CLI flags. "
                      "Please install the ProjectDiscovery httpx binary.\033[0m")
                return None
            return fallback
        return None

    def _normalize_path(self, candidate):
        if not candidate:
            return None
        expanded = os.path.expanduser(candidate)
        if os.path.isabs(expanded):
            return expanded if os.path.exists(expanded) else None
        return shutil.which(expanded)

    def _is_projectdiscovery_httpx(self, path):
        try:
            result = subprocess.run(
                [path, "--help"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            help_text = (result.stdout or "") + (result.stderr or "")
            if "Usage:" in help_text and "[flags]" in help_text:
                return True
            if "-l, -list" in help_text:
                return True
            if "<URL> [OPTIONS]" in help_text:
                return False
        except Exception:
            pass
        return False

    async def run_httpx(self, targets, concurrency=100):
        """
        Runs httpx on a list of targets (host:port) using the specified concurrency.
        """
        if not self.binary:
            print("\033[93m[!] httpx binary not found in PATH. Skipping HTTP probing.\033[0m")
            return []

        if not targets:
            return []

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        input_file = os.path.join(self.output_dir, f"httpx_input_{timestamp}.txt")
        json_output = os.path.join(self.output_dir, f"httpx_raw_{timestamp}.json")

        try:
            with open(input_file, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
        except Exception as e:
            print(f"\033[91m[!] Error creating httpx input file: {e}\033[0m")
            return []

        cmd = [
            self.binary,
            "-l", input_file,
            "-json",
            "-nc",
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-follow-redirects",
            "-ip",
            "-o", json_output,
            "-t", str(concurrency),
        ]

        print(f"\033[96m[*] Running httpx on {len(targets)} hosts to find alive web services (Concurrency: {concurrency})...\033[0m")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if not os.path.exists(json_output):
                if stderr:
                    print(f"\033[91m[!] httpx failed to generate output: {stderr.decode()}\033[0m")
                return []

            results = []
            with open(json_output, 'r') as f:
                for line in f:
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError:
                        continue

            try:
                os.remove(input_file)
                os.remove(json_output)
            except OSError:
                pass

            print(f"\033[92m[+] httpx finished. Found {len(results)} alive services.\033[0m")
            return results

        except Exception as e:
            print(f"\033[91m[!] Error running httpx: {e}\033[0m")
            return []

    def save_csv(self, httpx_data, domain_label):
        """
        Saves parsed httpx data to CSV with columns: IP, Domain, Port, etc.
        """
        if not httpx_data:
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"httpx_alive_{domain_label}_{timestamp}.csv"
        filepath = os.path.join(self.output_dir, filename)
        
        # requested columns: IP, Domain, Port
        # added useful context: URL, Status, Title
        headers = ['IP Address', 'Domain', 'Port', 'URL', 'Status Code', 'Title', 'Technologies']

        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)
                
                for entry in httpx_data:
                    # Extract Data
                    ip = entry.get('host', 'N/A')
                    port = entry.get('port', '')
                    url = entry.get('url', '')
                    title = entry.get('title', '')
                    status = entry.get('status_code', '')
                    tech = ",".join(entry.get('tech', []))
                    
                    # Extract Domain
                    domain = 'N/A'
                    if 'input' in entry:
                         # input is usually "domain:port"
                         parts = entry['input'].split(':')
                         domain = parts[0]
                    elif url:
                        parsed = urlparse(url)
                        domain = parsed.hostname

                    writer.writerow([ip, domain, port, url, status, title, tech])
            
            print(f"\033[92m[+] Alive services CSV saved to: \033[1m{filepath}\033[0m")
            return filepath
        except Exception as e:
            print(f"\033[91m[!] Error saving httpx CSV: {e}\033[0m")
            return None
