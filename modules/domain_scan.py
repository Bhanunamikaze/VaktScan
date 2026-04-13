import asyncio
import csv
import json
import os
import re
import time
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BRIGHT_CYAN = '\033[1;96m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

INTERNAL_KEYWORDS = [
    "builder-svcs", "uat", "qa", "staging",
    "dev", "internal", "local", "corp", "intranet",
    "preprod", "sandbox", "test", "sit", "int", "nonprod",
]

DEFAULT_PAGE_SIGNATURES = {
    "It works!":               "Apache default page",
    "Welcome to nginx":        "nginx default page",
    "IIS Windows Server":      "IIS default page",
    "Coming Soon":             "Placeholder / parked page",
    "domain for sale":         "Domain parking",
    "buy this domain":         "Domain parking",
}

class SubResourceParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.resources = set()

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'script' and 'src' in attrs_dict:
            self.resources.add(attrs_dict['src'])
        elif tag == 'link' and 'href' in attrs_dict:
            self.resources.add(attrs_dict['href'])
        elif tag == 'img' and 'src' in attrs_dict:
            self.resources.add(attrs_dict['src'])

    def handle_data(self, data):
        # Very basic inline JS API endpoint extraction
        api_pattern = re.compile(r'["\'](/api/[\w/.-]+)["\']')
        for match in api_pattern.finditer(data):
            self.resources.add(match.group(1))

class DomainScanner:
    def __init__(self, output_dir: str, extra_keywords: list = None):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.keywords = INTERNAL_KEYWORDS.copy()
        if extra_keywords:
            self.keywords.extend(k.lower().strip() for k in extra_keywords if k.strip())

    def classify_domains(self, domains: list) -> dict:
        """Classify domains as INTERNAL or EXTERNAL."""
        classified = {'INTERNAL': [], 'EXTERNAL': []}
        for domain in domains:
            domain_lower = domain.lower()
            is_internal = False
            for kw in self.keywords:
                if kw in domain_lower:
                    is_internal = True
                    break
            
            if is_internal:
                classified['INTERNAL'].append(domain)
            else:
                classified['EXTERNAL'].append(domain)
        return classified

    def save_classification_csv(self, domains: list) -> str:
        """Saves classification results to CSV."""
        classified = self.classify_domains(domains)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.output_dir, f"domain_classification_{timestamp}.csv")
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Domain', 'Classification'])
                for domain in classified['INTERNAL']:
                    writer.writerow([domain, 'INTERNAL'])
                for domain in classified['EXTERNAL']:
                    writer.writerow([domain, 'EXTERNAL'])
            print(f"{Colors.GREEN}[+] Classification saved to {filename}{Colors.RESET}")
            return filename
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to save classification CSV: {e}{Colors.RESET}")
            return ""

    def _create_vuln_entry(self, httpx_entry: dict, finding_name: str, status: str, severity: str, details: str) -> dict:
        url = httpx_entry.get('url', '')
        parsed = urlparse(url)
        return {
            "target":          parsed.hostname or httpx_entry.get('input', '').split(':')[0],
            "resolved_ip":     httpx_entry.get('host', ''),
            "port":            str(httpx_entry.get('port', parsed.port or (443 if parsed.scheme == 'https' else 80))),
            "vulnerability":   finding_name,
            "status":          status,
            "severity":        severity,
            "module":          "domain_scan",
            "service_version": "N/A",
            "url":             url,
            "details":         details,
        }

    def detect_default_pages(self, httpx_data: list) -> list[dict]:
        """Detect default/parked pages based on httpx titles and inferred body content without extra requests."""
        findings = []
        for entry in httpx_data:
            title = entry.get('title', '')
            for sig, description in DEFAULT_PAGE_SIGNATURES.items():
                if sig.lower() in title.lower():
                    find = self._create_vuln_entry(
                        entry,
                        f"Default/Parked Page: {description}",
                        "POTENTIAL",
                        "LOW",
                        f"Matched signature '{sig}' in page title"
                    )
                    findings.append(find)
        return findings

    async def check_broken_components(self, httpx_data: list, concurrency: int = 50) -> list[dict]:
        """Scan alive URLs for broken sub-resources (JS, CSS, Img, API)."""
        findings = []
        # Two separate semaphores to avoid deadlock:
        # page_sem gates the parent GET fetches; probe_sem gates the child HEAD probes.
        page_sem  = asyncio.Semaphore(max(1, min(concurrency // 2, 10)))
        probe_sem = asyncio.Semaphore(max(1, concurrency))

        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
            async def probe_resource(parent_entry, resource_url, parent_url):
                async with probe_sem:
                    try:
                        resp = await client.head(resource_url)
                        if resp.status_code >= 400 and resp.status_code not in (401, 403):
                            findings.append(self._create_vuln_entry(
                                parent_entry,
                                f"Broken Component: {urlparse(resource_url).path}",
                                "POTENTIAL",
                                "MEDIUM",
                                f"Sub-resource '{resource_url}' returned HTTP {resp.status_code}. Parent: {parent_url}"
                            ))
                    except Exception:
                        pass

            async def fetch_and_collect(entry):
                url = entry.get('url')
                if not url:
                    return []
                async with page_sem:
                    try:
                        resp = await client.get(url)
                        parser = SubResourceParser()
                        parser.feed(resp.text)
                        tasks = []
                        for res in parser.resources:
                            abs_url = urljoin(url, res)
                            if abs_url.startswith('http'):
                                tasks.append(probe_resource(entry, abs_url, url))
                        if tasks:
                            await asyncio.gather(*tasks, return_exceptions=True)
                    except Exception:
                        pass

            print(f"{Colors.CYAN}[*] Checking for broken components on {len(httpx_data)} alive URLs...{Colors.RESET}")
            page_tasks = [fetch_and_collect(entry) for entry in httpx_data]
            if page_tasks:
                await asyncio.gather(*page_tasks, return_exceptions=True)

        return findings

    async def run_anomaly_checks(self, alive_urls: list, httpx_data: list = None, concurrency: int = 50) -> list[dict]:
        """Run additional misconfiguration/anomaly checks on alive URLs."""
        # We need httpx_data to create proper vuln entries
        url_to_entry = {entry.get('url'): entry for entry in (httpx_data or []) if entry.get('url')}
        
        findings = []
        semaphore = asyncio.Semaphore(max(1, concurrency))
        
        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False) as client:
            async def check_url(url):
                entry = url_to_entry.get(url, {'url': url, 'input': url})
                async with semaphore:
                    try:
                        # 1. Base response anomalies and headers
                        resp = await client.get(url)
                        headers = resp.headers
                        
                        # 5xx on base
                        if resp.status_code >= 500:
                            findings.append(self._create_vuln_entry(
                                entry, "5xx Server Error on Base Path", "POTENTIAL", "LOW",
                                f"HTTP {resp.status_code} returned on root"
                            ))
                            
                        # Response size
                        body_len = len(resp.content)
                        if body_len < 50:
                            findings.append(self._create_vuln_entry(
                                entry, "Anomalous Response Size (Too Small)", "INFO", "INFO",
                                f"Response body is {body_len} bytes"
                            ))
                        elif body_len > 2 * 1024 * 1024:
                            findings.append(self._create_vuln_entry(
                                entry, "Anomalous Response Size (Too Large)", "INFO", "INFO",
                                f"Response body is {body_len} bytes"
                            ))
                            
                        # Missing security headers
                        missing_headers = []
                        if 'strict-transport-security' not in headers: missing_headers.append('HSTS')
                        if 'x-frame-options' not in headers and 'content-security-policy' not in headers: missing_headers.append('X-Frame-Options/CSP')
                        if 'x-content-type-options' not in headers: missing_headers.append('X-Content-Type-Options')
                        
                        if missing_headers:
                            findings.append(self._create_vuln_entry(
                                entry, "Missing Security Headers", "INFO", "INFO",
                                f"Headers absent: {', '.join(missing_headers)}"
                            ))
                            
                        # JSON leak in HTML
                        if 'text/html' in headers.get('content-type', '').lower():
                            text_body = resp.text.strip()
                            if text_body.startswith('{') and text_body.endswith('}'):
                                findings.append(self._create_vuln_entry(
                                    entry, "Potential JSON Data Leak in HTML", "POTENTIAL", "MEDIUM",
                                    "Response has Content-Type text/html but body appears to be JSON"
                                ))
                                
                        # Directory Listing
                        if "Index of /" in resp.text:
                            findings.append(self._create_vuln_entry(
                                entry, "Directory Listing Enabled", "VULNERABLE", "HIGH",
                                "Found 'Index of /' in response body"
                            ))

                        # 2. CORS Misconfig
                        cors_headers = {'Origin': 'https://evil.com'}
                        cors_resp = await client.options(url, headers=cors_headers)
                        acao = cors_resp.headers.get('access-control-allow-origin', '')
                        if acao == '*' or acao == 'https://evil.com':
                            findings.append(self._create_vuln_entry(
                                entry, "Permissive CORS Configuration", "POTENTIAL", "MEDIUM",
                                f"Access-Control-Allow-Origin returned: {acao} for origin evil.com"
                            ))

                        # 3. Open Redirect (Basic smoke test)
                        for param in ['url', 'redirect', 'next', 'return']:
                            or_url = f"{url}?{param}=https://example.com"
                            or_resp = await client.get(or_url)
                            if or_resp.status_code in (301, 302, 307, 308):
                                loc = or_resp.headers.get('location', '')
                                if 'example.com' in loc:
                                    findings.append(self._create_vuln_entry(
                                        entry, f"Potential Open Redirect ({param})", "POTENTIAL", "MEDIUM",
                                        f"Redirected to {loc} via parameter {param}"
                                    ))
                                    break
                    except Exception:
                        pass
            
            print(f"{Colors.CYAN}[*] Running anomaly and misconfig checks on {len(alive_urls)} alive URLs...{Colors.RESET}")
            tasks = [check_url(url) for url in alive_urls]
            if tasks:
                await asyncio.gather(*tasks)
                
        return findings

    async def run(self, domains: list, httpx_data: list, alive_urls: list, concurrency: int = 50) -> list[dict]:
        """
        Orchestrate all domain scan checks.
        NOTE: Callers are responsible for calling save_classification_csv() if they
        want the classification CSV — this method only prints the summary to avoid
        double-writing when integrated into run_recon_followups().
        """
        print(f"{Colors.BRIGHT_CYAN}[*] Starting domain checks on {len(domains)} targets...{Colors.RESET}")

        # 1. Classify (no CSV here — caller does it once before calling run())
        classified = self.classify_domains(domains)
        print(f"{Colors.GRAY}[*] Domain mix: {len(classified['INTERNAL'])} INTERNAL, {len(classified['EXTERNAL'])} EXTERNAL{Colors.RESET}")

        # 2. Web Checks
        findings = self.detect_default_pages(httpx_data)
        findings += await self.check_broken_components(httpx_data, concurrency)
        findings += await self.run_anomaly_checks(alive_urls, httpx_data, concurrency)

        print(f"{Colors.GREEN}[+] Domain scan finished. Found {len(findings)} web anomalies/issues.{Colors.RESET}")
        return findings
