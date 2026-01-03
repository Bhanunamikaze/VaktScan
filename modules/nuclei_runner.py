import asyncio
import json
import os
import shutil
import subprocess
from datetime import datetime

class NucleiRunner:
    def __init__(self, output_dir="recon_results"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.binary = self._resolve_binary()

    def _resolve_binary(self):
        candidates = [
            os.environ.get("VAKT_NUCLEI_BIN"),
            "/usr/local/bin/nuclei",
            "/opt/homebrew/bin/nuclei",
            shutil.which("nuclei"),
            os.path.expanduser("~/.local/bin/nuclei"),
        ]
        seen = set()
        for cand in candidates:
            path = self._normalize_path(cand)
            if not path or path in seen:
                continue
            seen.add(path)
            if self._is_projectdiscovery_nuclei(path):
                return path
        fallback = shutil.which("nuclei")
        if fallback:
            print("\033[93m[!] ProjectDiscovery nuclei not found. Falling back to system nuclei at: "
                  f"{fallback}\033[0m")
            return fallback
        return None

    def _normalize_path(self, candidate):
        if not candidate:
            return None
        expanded = os.path.expanduser(candidate)
        if os.path.isabs(expanded):
            return expanded if os.path.exists(expanded) else None
        return shutil.which(expanded)

    def _is_projectdiscovery_nuclei(self, path):
        try:
            result = subprocess.run(
                [path, "-version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = (result.stdout or "") + (result.stderr or "")
            return "Nuclei" in output or "projectdiscovery" in output.lower()
        except Exception:
            return False

    async def run_nuclei(self, targets):
        """
        Runs nuclei on a list of targets (URLs).
        Returns a list of vulnerability dictionaries formatted for VaktScan.
        """
        if not self.binary:
            print("\033[93m[!] nuclei binary not found in PATH. Skipping vulnerability scanning.\033[0m")
            return []

        if not targets:
            return []

        # Create input file for nuclei
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        input_file = os.path.join(self.output_dir, f"nuclei_targets_{timestamp}.txt")
        json_output = os.path.join(self.output_dir, f"nuclei_results_{timestamp}.json")

        try:
            with open(input_file, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
        except Exception as e:
            print(f"\033[91m[!] Error creating nuclei input file: {e}\033[0m")
            return []

        # Construct command
        # -l: list of targets
        # -json: output json format (essential for parsing)
        # -silent: reduce noise
        # -nc: no color in output file
        cmd = f"{self.binary} -l {input_file} -json -o {json_output} -silent -nc"

        print(f"\033[96m[*] Running nuclei on {len(targets)} alive services...\033[0m")

        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            # Check if output file exists (Nuclei might not create it if no vulns found)
            if not os.path.exists(json_output):
                if stderr and b"error" in stderr.lower():
                     print(f"\033[93m[!] Nuclei warning/error: {stderr.decode().strip()}\033[0m")
                return []

            vulnerabilities = []
            with open(json_output, 'r') as f:
                for line in f:
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        
                        # Map Nuclei JSON to VaktScan Vulnerability Structure
                        severity_raw = data.get('info', {}).get('severity', 'info')
                        mapped_status = self._map_severity(severity_raw)
                        
                        vuln = {
                            'target': data.get('host', ''), # Hostname usually
                            'resolved_ip': data.get('ip', ''), 
                            'port': self._extract_port(data.get('matched-at', '')),
                            'vulnerability': data.get('info', {}).get('name', 'Unknown Vulnerability'),
                            'status': mapped_status,
                            'severity': severity_raw.upper(),
                            'module': 'nuclei',
                            'service_version': 'N/A',
                            'url': data.get('matched-at', ''),
                            'details': data.get('info', {}).get('description', '') or data.get('matcher-name', '')
                        }
                        vulnerabilities.append(vuln)
                    except json.JSONDecodeError:
                        continue

            # Cleanup
            try:
                os.remove(input_file)
                os.remove(json_output)
            except OSError:
                pass

            if vulnerabilities:
                print(f"\033[92m[+] Nuclei found {len(vulnerabilities)} vulnerabilities/info items.\033[0m")
            else:
                print(f"\033[92m[+] Nuclei scan complete. No vulnerabilities found.\033[0m")
            
            return vulnerabilities

        except Exception as e:
            print(f"\033[91m[!] Error running nuclei: {e}\033[0m")
            return []

    def _map_severity(self, severity):
        """Maps nuclei severity to VaktScan status codes."""
        severity = severity.lower()
        if severity in ['critical', 'high']:
            return 'CRITICAL' if severity == 'critical' else 'VULNERABLE'
        elif severity == 'medium':
            return 'POTENTIAL'
        elif severity == 'low':
            return 'POTENTIAL'
        else:
            return 'INFO'

    def _extract_port(self, url):
        """Helper to extract port from URL if present."""
        if not url: return ''
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.port:
                return str(parsed.port)
            if parsed.scheme == 'https': return '443'
            if parsed.scheme == 'http': return '80'
        except:
            pass
        return ''
