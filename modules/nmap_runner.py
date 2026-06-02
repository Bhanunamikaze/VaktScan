import asyncio
import shutil
import os
from datetime import datetime

class NmapRunner:
    def __init__(self, output_base_dir="reports"):
        self.output_base_dir = output_base_dir
        # Create a specific nmap directory inside reports
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

        # Sanitize filename: hostname (if available) + IP to guarantee uniqueness
        raw_name = hostname if hostname and hostname != 'N/A' else ip
        safe_name = "".join([c for c in raw_name if c.isalnum() or c in ['.', '-', '_']]).strip()
        safe_ip = ip.replace('.', '_').replace(':', '_')

        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        output_file = os.path.join(self.nmap_dir, f"{safe_name}_{safe_ip}_{timestamp}.nmap")
        
        ports_str = ",".join(map(str, ports))
        
        # Command: nmap -sCV -Pn -p <ports> <ip> -oN <file>
        # -sCV: Script scan + Version detection
        # -Pn: Treat host as online (skip discovery)
        cmd = f"{self.binary} -sCV -Pn -p {ports_str} {ip} -oN {output_file}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            # We await communication to ensure process finishes
            stdout, stderr = await process.communicate()
            
            if os.path.exists(output_file):
                pass
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

        from modules.dashboard import LiveDashboard
        dashboard = LiveDashboard()
        if dashboard.active:
            dashboard.add_task("nmap", "Nmap Scan", total=len(targets_data))

        actual_concurrency = max(1, concurrency)
        semaphore = asyncio.Semaphore(actual_concurrency)
        completed = 0

        async def sem_task(t_data):
            nonlocal completed
            async with semaphore:
                await self.run_nmap_on_target(t_data[0], t_data[1], t_data[2])
                completed += 1
                if dashboard.active:
                    dashboard.update_task("nmap", completed=completed, status=f"Scanned {completed}/{len(targets_data)} hosts")

        try:
            tasks = [sem_task(t) for t in targets_data]
            await asyncio.gather(*tasks)
        finally:
            if dashboard.active:
                dashboard.complete_task("nmap")

    async def run_cve_scan_on_target(self, ip, ports, hostname=None):
        if not self.binary or not ports:
            return []

        raw_name = hostname if hostname and hostname != 'N/A' else ip
        safe_name = "".join([c for c in raw_name if c.isalnum() or c in ['.', '-', '_']]).strip()
        safe_ip = ip.replace('.', '_').replace(':', '_')

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_output = os.path.join(self.nmap_dir, f"{safe_name}_{safe_ip}_cve_{timestamp}.nmap")
        xml_output = os.path.join(self.nmap_dir, f"{safe_name}_{safe_ip}_cve_{timestamp}.xml")
        
        ports_str = ",".join(map(str, ports))
        cmd = f"{self.binary} -sV --script vuln,vulners -Pn -p {ports_str} {ip} -oX {xml_output} -oN {txt_output}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if os.path.exists(xml_output):
                return self.parse_nmap_xml(xml_output, hostname or ip, ip)
            else:
                print(f"\033[91m[!] Nmap CVE scan failed to create output for {safe_name}.\033[0m")
                if stderr:
                    print(f"\033[90m    Error: {stderr.decode().strip()}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error running Nmap CVE scan on {safe_name}: {e}\033[0m")
        return []

    def parse_nmap_xml(self, xml_file, target, resolved_ip):
        import xml.etree.ElementTree as ET
        import re
        findings = []
        if not os.path.exists(xml_file):
            return findings
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for host in root.findall('host'):
                ip_elem = host.find("address[@addrtype='ipv4']")
                if ip_elem is None:
                    ip_elem = host.find("address")
                ip = ip_elem.get('addr') if ip_elem is not None else resolved_ip

                hostname = target
                hostname_elem = host.find("hostnames/hostname")
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')

                for port_elem in host.findall('ports/port'):
                    port_id = port_elem.get('portid')
                    state_elem = port_elem.find('state')
                    if state_elem is None or state_elem.get('state') != 'open':
                        continue

                    service_elem = port_elem.find('service')
                    product = ""
                    version = ""
                    if service_elem is not None:
                        product = service_elem.get('product', '')
                        version = service_elem.get('version', '')

                    for script in port_elem.findall('script'):
                        script_id = script.get('id', '')
                        output = script.get('output', '')

                        if script_id == 'vulners':
                            for cpe_table in script.findall('table'):
                                for vuln_table in cpe_table.findall('table'):
                                    vuln_id = ""
                                    cvss_score = 0.0
                                    for elem in vuln_table.findall('elem'):
                                        key = elem.get('key')
                                        if key == 'id':
                                            vuln_id = elem.text
                                        elif key == 'cvss':
                                            try:
                                                cvss_score = float(elem.text)
                                            except (TypeError, ValueError):
                                                pass
                                    if vuln_id.startswith('CVE-') and cvss_score >= 7.0:
                                        status = "CRITICAL" if cvss_score >= 9.0 else "VULNERABLE"
                                        severity = "CRITICAL" if cvss_score >= 9.0 else "HIGH"
                                        findings.append({
                                            'status': status,
                                            'severity': severity,
                                            'vulnerability': f"{vuln_id} — {product or 'Service'} {version or ''}".strip(),
                                            'target': hostname,
                                            'resolved_ip': ip,
                                            'port': str(port_id),
                                            'url': f"https://nvd.nist.gov/vuln/detail/{vuln_id}",
                                            'payload_url': f"https://nvd.nist.gov/vuln/detail/{vuln_id}",
                                            'module': 'nmap',
                                            'service_version': version or 'N/A',
                                            'details': f"Nmap vulners script detected {vuln_id} with CVSS {cvss_score:.1f}.",
                                            'http_status': 'N/A',
                                            'page_title': 'N/A',
                                            'content_length': 'N/A',
                                            'timestamp': datetime.utcnow().isoformat() + 'Z',
                                        })
                        else:
                            is_vuln = False
                            if "vulnerable" in output.lower():
                                    is_vuln = True

                            if is_vuln:
                                cves = re.findall(r'CVE-\d{4}-\d+', script_id + " " + output, re.IGNORECASE)
                                cves = sorted(list(set(cves)))

                                cvss_match = re.search(r'CVSS\s*(?:Score)?\s*:\s*([0-9.]+)', output, re.IGNORECASE)
                                cvss_score = 0.0
                                if cvss_match:
                                    try:
                                        cvss_score = float(cvss_match.group(1))
                                    except ValueError:
                                        pass

                                if cves:
                                    for cve in cves:
                                        cve_upper = cve.upper()
                                        if cvss_score == 0.0 or cvss_score >= 7.0:
                                            status = "CRITICAL" if cvss_score >= 9.0 else "VULNERABLE"
                                            severity = "CRITICAL" if cvss_score >= 9.0 else "HIGH"
                                            findings.append({
                                                'status': status,
                                                'severity': severity,
                                                'vulnerability': f"{cve_upper} — {product or 'Service'} {version or ''}".strip(),
                                                'target': hostname,
                                                'resolved_ip': ip,
                                                'port': str(port_id),
                                                'url': f"https://nvd.nist.gov/vuln/detail/{cve_upper}",
                                                'payload_url': f"https://nvd.nist.gov/vuln/detail/{cve_upper}",
                                                'module': 'nmap',
                                                'service_version': version or 'N/A',
                                                'details': f"Nmap script {script_id} detected {cve_upper} on port {port_id}. Output: {output[:300]}",
                                                'http_status': 'N/A',
                                                'page_title': 'N/A',
                                                'content_length': 'N/A',
                                                'timestamp': datetime.utcnow().isoformat() + 'Z',
                                            })
                                else:
                                    if cvss_score == 0.0 or cvss_score >= 7.0:
                                        status = "CRITICAL" if cvss_score >= 9.0 else "VULNERABLE"
                                        severity = "CRITICAL" if cvss_score >= 9.0 else "HIGH"
                                        findings.append({
                                            'status': status,
                                            'severity': severity,
                                            'vulnerability': f"Nmap script vulnerability: {script_id}",
                                            'target': hostname,
                                            'resolved_ip': ip,
                                            'port': str(port_id),
                                            'url': f"nmap://{ip}:{port_id}/{script_id}",
                                            'payload_url': f"nmap://{ip}:{port_id}/{script_id}",
                                            'module': 'nmap',
                                            'service_version': version or 'N/A',
                                            'details': f"Nmap script {script_id} flagged port {port_id} as vulnerable. Output: {output[:500]}",
                                            'http_status': 'N/A',
                                            'page_title': 'N/A',
                                            'content_length': 'N/A',
                                            'timestamp': datetime.utcnow().isoformat() + 'Z',
                                        })
        except Exception as e:
            print(f"\033[91m[!] Error parsing Nmap XML {xml_file}: {e}\033[0m")
        return findings

    async def run_cve_scan_batch(self, targets_data, concurrency=10):
        if not self.binary:
            print("\033[93m[!] nmap binary not found. Skipping Nmap CVE scans.\033[0m")
            return []

        if not targets_data:
            print("\033[93m[*] No targets with open ports to scan with Nmap CVE scripts.\033[0m")
            return []

        from modules.dashboard import LiveDashboard
        dashboard = LiveDashboard()
        if dashboard.active:
            dashboard.add_task("nmap_cve", "Nmap CVE Scan", total=len(targets_data))

        print(f"\033[96m[*] Running Nmap CVE/vuln scans on {len(targets_data)} target(s)...\033[0m")
        actual_concurrency = max(1, concurrency)
        semaphore = asyncio.Semaphore(actual_concurrency)
        all_findings = []
        completed = 0

        async def sem_task(t_data):
            nonlocal completed
            async with semaphore:
                res = await self.run_cve_scan_on_target(t_data[0], t_data[1], t_data[2])
                all_findings.extend(res)
                completed += 1
                if dashboard.active:
                    dashboard.update_task("nmap_cve", completed=completed, status=f"Scanned {completed}/{len(targets_data)} hosts (findings: {len(all_findings)})")

        try:
            tasks = [sem_task(t) for t in targets_data]
            await asyncio.gather(*tasks)
        finally:
            if dashboard.active:
                dashboard.complete_task("nmap_cve")
        return all_findings

