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

# Subdomain-takeover fingerprints. Each entry is (vendor, body_marker,
# trigger_status_codes, severity). A finding fires when a 404/200 response
# body contains the marker — the dangling DNS still resolves but the
# back-end service has been deprovisioned, so an attacker who re-claims the
# vendor slot inherits the subdomain.
#
# Source-set: maintained by https://github.com/EdOverflow/can-i-take-over-xyz
# plus cPanel-specific defaultwebpage.cgi (orphaned cPanel account).
TAKEOVER_SIGNATURES = [
    ("GitHub Pages",     "There isn't a GitHub Pages site here.",                             (200, 404),       "CRITICAL"),
    ("AWS S3",           "NoSuchBucket",                                                       (200, 404),       "CRITICAL"),
    ("AWS S3",           "The specified bucket does not exist",                                (200, 404),       "CRITICAL"),
    ("Heroku",           "No such app",                                                        (200, 404),       "CRITICAL"),
    ("Heroku",           "herokucdn.com/error-pages/no-such-app.html",                         (200, 404),       "CRITICAL"),
    ("Shopify",          "Sorry, this shop is currently unavailable.",                         (200, 404),       "HIGH"),
    ("Bitbucket",        "Repository not found",                                               (404,),           "HIGH"),
    ("Ghost",            "The thing you were looking for is no longer here, or never was",     (200, 404),       "HIGH"),
    ("Pantheon",         "The gods are wise, but do not know of the site which you seek",      (200, 404),       "HIGH"),
    ("Surge.sh",         "project not found",                                                  (200, 404),       "HIGH"),
    ("Tumblr",           "There's nothing here.",                                              (200, 404),       "HIGH"),
    ("Tumblr",           "Whatever you were looking for doesn't currently exist at this address", (200, 404),    "HIGH"),
    ("UserVoice",        "This UserVoice subdomain is currently available!",                   (200, 404),       "HIGH"),
    ("WordPress.com",    "Do you want to register",                                            (200, 404),       "MEDIUM"),
    ("Cargo",            "404 Not Found",                                                      (404,),           "INFO"),
    ("Fastly",           "Fastly error: unknown domain",                                       (200, 404),       "HIGH"),
    ("Fastly",           "Please check that this domain has been added to a service",          (200, 404),       "HIGH"),
    ("Cloudfront",       "ERROR: The request could not be satisfied",                          (403, 404),       "MEDIUM"),
    ("Webflow",          "The page you are looking for doesn't exist or has been moved",       (404,),           "MEDIUM"),
    ("Tilda",            "Please renew your subscription",                                     (200, 404),       "HIGH"),
    ("Unbounce",         "The requested URL was not found on this server.",                   (404,),           "INFO"),
    ("Strikingly",       "But if you're looking to build your own website",                    (404,),           "HIGH"),
    ("Vercel",           "The deployment could not be found on Vercel",                        (404,),           "HIGH"),
    ("Netlify",          "Not Found - Request ID",                                             (404,),           "MEDIUM"),
    ("Azure",            "404 Web Site not found",                                             (404,),           "HIGH"),
    ("Read the Docs",    "unknown to Read the Docs",                                           (404,),           "HIGH"),
    ("Help Scout",       "No settings were found for this company",                            (200, 404),       "HIGH"),
    ("HelpJuice",        "We could not find what you're looking for.",                         (404,),           "MEDIUM"),
    ("Intercom",         "This page is reserved for artistic dogs",                            (404,),           "HIGH"),
    ("Statuspage",       "You are being redirected",                                           (302, 404),       "MEDIUM"),
    ("Acquia",           "The site you are looking for could not be found",                    (404,),           "HIGH"),
    ("Tave",             "<h1>Error 404: Page Not Found</h1>",                                 (404,),           "INFO"),
    ("Zendesk",          "Help Center Closed",                                                 (200, 404),       "HIGH"),
    ("cPanel orphan",    "<title>Default Web Site Page</title>",                              (200, 404),       "HIGH"),
    ("cPanel orphan",    "cgi-sys/defaultwebpage.cgi",                                         (200, 404),       "HIGH"),
    ("LaunchRock",       "It looks like you may have taken a wrong turn somewhere",            (404,),           "HIGH"),
    ("Smugmug",          "<h1>Page Not Found</h1>",                                            (404,),           "INFO"),
    ("ngrok",            "Tunnel not found",                                                   (404,),           "HIGH"),
    ("Worksites.net",    "Hello! Sorry, but this website is",                                  (200, 404),       "MEDIUM"),
    ("Pingdom",          "public report page not activated",                                   (200, 404),       "MEDIUM"),
    ("Brightcove",       "<p class=\"bc-gallery-error-code\">Error Code: 404</p>",            (404,),           "HIGH"),
    ("Anima",            "If this is your website and you've just created it",                 (404,),           "MEDIUM"),
    ("Kinsta",           "No Site For Domain",                                                 (404,),           "HIGH"),
    ("Wishpond",         "https://www.wishpond.com/404?campaign=true",                         (200, 404),       "HIGH"),
    ("Hatena Blog",      "404 Blog is not found",                                              (404,),           "HIGH"),
    ("Aftership",        "Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist.", (404,), "MEDIUM"),
    ("Help Juice",       "We could not find what you're looking for.",                         (404,),           "MEDIUM"),
    ("Pixpa",            "Sorry, this page is no longer available.",                           (404,),           "MEDIUM"),
    ("Teamwork",         "Oops - We didn't find your site.",                                   (404,),           "HIGH"),
    ("JetBrains",        "is not a registered InCloud YouTrack",                               (200, 404),       "HIGH"),
    ("Smartling",        "Domain is not configured",                                           (200, 404),       "MEDIUM"),
    ("Surveygizmo",      "data-html-name=\"Default error page\"",                              (404,),           "MEDIUM"),
    ("Mashery",          "Unrecognized domain <strong>",                                       (200, 404),       "HIGH"),
    ("Thinkific",        "You may have mistyped the address",                                  (404,),           "MEDIUM"),
    ("Tictail",          "to buy this domain.",                                                (200, 404),       "MEDIUM"),
    ("Uservoice",        "This UserVoice instance does not exist",                             (200, 404),       "HIGH"),
    ("Wishpond",         "https://www.wishpond.com/404",                                       (404,),           "HIGH"),
    ("Wpengine",         "The site you were looking for couldn't be found",                    (200, 404),       "HIGH"),
]

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
            "service_version": httpx_entry.get('webserver', 'N/A'),
            "url":             url,
            "details":         details,
            "http_status":     str(httpx_entry.get('status_code', 'N/A')),
            "page_title":      httpx_entry.get('title', 'N/A'),
            "content_length":  str(httpx_entry.get('content_length', 'N/A'))
        }

    def detect_takeover_from_response(self, httpx_entry: dict, status_code: int, body_excerpt: str) -> dict | None:
        """
        Match a single (status, body) pair against TAKEOVER_SIGNATURES.
        Returns a finding dict (already in the canonical reporting schema)
        when a vendor fingerprint matches. Body is matched case-insensitive.
        """
        if not body_excerpt:
            return None
        lower = body_excerpt[:8192].lower()
        for vendor, marker, allowed_codes, severity in TAKEOVER_SIGNATURES:
            if status_code not in allowed_codes:
                continue
            if marker.lower() not in lower:
                continue
            status = "CRITICAL" if severity == "CRITICAL" else "VULNERABLE"
            return self._create_vuln_entry(
                httpx_entry,
                f"Subdomain takeover candidate: {vendor}",
                status,
                severity,
                (
                    f"HTTP {status_code} response body matches a known {vendor} takeover fingerprint "
                    f"('{marker[:80]}'). DNS still resolves to {vendor} but the back-end service is "
                    "deprovisioned — re-registering the slot lets an attacker serve content on this hostname."
                ),
            )
        return None

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

                        # Subdomain-takeover signatures (also re-fetches a
                        # /<random> path to surface vendor-specific 404
                        # markers that only appear on missing routes).
                        takeover = self.detect_takeover_from_response(entry, resp.status_code, resp.text)
                        if takeover:
                            findings.append(takeover)
                        else:
                            try:
                                rand_path = f"/_vakt_{int(time.time() * 1000) % 100000}_takeover"
                                miss = await client.get(url.rstrip('/') + rand_path)
                                takeover = self.detect_takeover_from_response(entry, miss.status_code, miss.text)
                                if takeover:
                                    findings.append(takeover)
                            except Exception:
                                pass

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
