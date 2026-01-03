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
        self.output_flag = self._detect_output_flag()

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

    def _detect_output_flag(self):
        if not self.binary:
            return None
        try:
            result = subprocess.run(
                [self.binary, "-h"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception:
            return "-json"

        help_text = (result.stdout or "") + (result.stderr or "")
        lower_help = help_text.lower()
        if "-jsonl" in lower_help:
            return "-jsonl"
        if "-json" in lower_help:
            return "-json"
        return "-json"

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
        json_output_tmp = os.path.join(self.output_dir, f"nuclei_raw_{timestamp}.json")
        final_json_output = os.path.join(self.output_dir, f"nuclei_results_{timestamp}.json")

        try:
            with open(input_file, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
        except Exception as e:
            print(f"\033[91m[!] Error creating nuclei input file: {e}\033[0m")
            return []

        # Construct command following ProjectDiscovery best practices (Ultimate Guide)
        cmd = [
            self.binary,
            "-l", input_file,
            "-c", "50",
            "-rl", "150",
            "-bs", "100",
            "-timeout", "15",
            "-severity", "critical,high,medium",
            "-nc",
        ]
        if self.output_flag:
            cmd.append(self.output_flag)
        cmd.extend(["-silent", "-o", json_output_tmp])

        print(f"\033[96m[*] Running nuclei on {len(targets)} alive services...\033[0m")
        print(f"\033[90m[*] Nuclei targets file: {input_file}\033[0m")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode not in (0, None):
                print(f"\033[93m[!] Nuclei exited with code {process.returncode}.\033[0m")
                stderr_text = stderr.decode().strip()
                if stderr_text:
                    print(f"\033[90m[*] nuclei stderr:\033[0m\n{stderr_text}")

            # Prefer file output, but fall back to stdout if file missing
            data_lines = []
            if os.path.exists(json_output_tmp):
                with open(json_output_tmp, 'r') as f:
                    data_lines = [line.strip() for line in f if line.strip()]
            else:
                stdout_lines = [line.strip() for line in stdout.decode().splitlines() if line.strip()]
                if stdout_lines:
                    data_lines = stdout_lines
                    try:
                        with open(json_output_tmp, 'w') as handle:
                            for line in stdout_lines:
                                handle.write(f"{line}\n")
                    except OSError:
                        pass

            # Cleanup
            try:
                os.remove(input_file)
            except OSError:
                pass

            if not data_lines:
                print(f"\033[92m[+] Nuclei scan complete. No vulnerabilities found.\033[0m")
                try:
                    os.remove(json_output_tmp)
                except OSError:
                    pass
                return []

            vulnerabilities = []
            for line in data_lines:
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                severity_raw = data.get('info', {}).get('severity', 'info')
                mapped_status = self._map_severity(severity_raw)
                vuln = {
                    'target': data.get('host', ''),
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

            try:
                shutil.move(json_output_tmp, final_json_output)
            except Exception:
                final_json_output = json_output_tmp

            if vulnerabilities:
                print(f"\033[92m[+] Nuclei found {len(vulnerabilities)} vulnerabilities/info items.\033[0m")
            else:
                print(f"\033[92m[+] Nuclei scan complete. No vulnerabilities found.\033[0m")
            print(f"\033[90m[*] Nuclei raw results saved to: {final_json_output}\033[0m")

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
