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

        # Create a temporary input file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        input_file = os.path.join(self.output_dir, f"httpx_input_{timestamp}.txt")
        
        try:
            with open(input_file, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
        except Exception as e:
            print(f"\033[91m[!] Error creating httpx input file: {e}\033[0m")
            return []

        # Define output file for raw JSON
        json_output = os.path.join(self.output_dir, f"httpx_raw_{timestamp}.json")

        # httpx command construction
        # -l: input file
        # -t: threads (concurrency)
        # -json: output format
        # -silent: suppress banner
        # -status-code -title -tech-detect -follow-redirects -ip: gather enriched data
        cmd = (
            f"{self.binary} -l {input_file} -json -o {json_output} "
            f"-t {concurrency} -silent -status-code -title -tech-detect -follow-redirects -ip"
        )
        
        print(f"\033[96m[*] Running httpx on {len(targets)} ports to find alive web services (Concurrency: {concurrency})...\033[0m")
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            # httpx might return non-zero on some network errors, but we check if output exists
            if not os.path.exists(json_output):
                if stderr:
                    print(f"\033[91m[!] httpx failed to generate output: {stderr.decode()}\033[0m")
                return []
            
            # Parse JSON results
            results = []
            with open(json_output, 'r') as f:
                for line in f:
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError:
                        continue
            
            # Clean up temporary input/output files to keep folder clean
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
        
        # requested columns: IP, Domain, Port
        # added useful context: URL, Status, Title
        headers = ['IP Address', 'Domain', 'Port', 'URL', 'Status Code', 'Title', 'Technologies']

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
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
            
            print(f"\033[92m[+] Alive services CSV saved to: \033[1m{filename}\033[0m")
            return filename
        except Exception as e:
            print(f"\033[91m[!] Error saving httpx CSV: {e}\033[0m")
            return None
