import asyncio
import csv
import json
import os
import re
import time
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from modules.progress import DashboardProgress

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
# body contains the marker - the dangling DNS still resolves but the
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
    ("Fly.io",           "App not found",                                                      (404,),           "HIGH"),
    ("Readme.io",        "Let's write some docs!",                                             (404,),           "HIGH"),
    ("ActiveCampaign",   "Account not found",                                                  (200, 404),       "HIGH"),
    ("Campaign Monitor", "Trying to send email?",                                              (200, 404),       "HIGH"),
]

# An HTTP error-page fingerprint is not sufficient evidence of a dangling DNS
# record.  Require the target's CNAME to point at the matching provider before
# reporting a takeover candidate.  The hints are deliberately conservative;
# providers without a stable, claimable CNAME pattern are not auto-reported.
TAKEOVER_CNAME_HINTS = {
    "GitHub Pages": ("github.io",),
    "AWS S3": ("s3.amazonaws.com", "s3-website"),
    "Heroku": ("herokudns.com", "herokuapp.com"),
    "Shopify": ("myshopify.com",),
    "Pantheon": ("pantheonsite.io",),
    "Surge.sh": ("surge.sh",),
    "Tumblr": ("domains.tumblr.com",),
    "UserVoice": ("uservoice.com",),
    "Uservoice": ("uservoice.com",),
    "WordPress.com": ("wordpress.com",),
    "Fastly": ("fastly.net", "fastlylb.net"),
    "Cloudfront": ("cloudfront.net",),
    "Webflow": ("proxy-ssl.webflow.com", "webflow.io"),
    "Unbounce": ("unbouncepages.com",),
    "Vercel": ("vercel-dns.com", "vercel.app"),
    "Netlify": ("netlify.app", "netlify.com"),
    "Azure": ("azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"),
    "Read the Docs": ("readthedocs.io",),
    "Help Scout": ("helpscoutdocs.com",),
    "Statuspage": ("statuspage.io",),
    "Zendesk": ("zendesk.com",),
    "Kinsta": ("kinsta.cloud",),
    "Thinkific": ("thinkific.com",),
    "Wpengine": ("wpengine.com", "wpenginepowered.com"),
    "Fly.io": ("fly.dev",),
    "Readme.io": ("readme.io",),
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

    def _create_vuln_entry(
        self, httpx_entry: dict, finding_name: str, status: str,
        severity: str, details: str, *, evidence_url: str | None = None,
        http_status=None, page_title=None, content_length=None,
    ) -> dict:
        """Create a canonical finding using the URL that produced the evidence.

        Historically this copied the parent httpx URL even for a child resource
        or payload URL.  That made the final CSV lose the path being tested and
        also attached the parent's status/title/length to the finding.
        """
        url = evidence_url or httpx_entry.get('url', '')
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
            "payload_url":     url,
            "details":         details,
            "http_status":     str(http_status if http_status is not None else httpx_entry.get('status_code', 'N/A')),
            "page_title":      page_title if page_title is not None else httpx_entry.get('title', 'N/A'),
            "content_length":  str(content_length if content_length is not None else httpx_entry.get('content_length', 'N/A')),
            "timestamp":       datetime.utcnow().isoformat() + "Z",
        }

    def detect_takeover_from_response(self, httpx_entry: dict, status_code: int, body_excerpt: str) -> dict | None:
        """
        Match a single (status, body) pair against TAKEOVER_SIGNATURES.
        Returns a finding dict (already in the canonical reporting schema)
        when a vendor fingerprint matches. Body is matched case-insensitive.
        """
        if not body_excerpt:
            return None
        raw_cnames = httpx_entry.get("cname") or httpx_entry.get("cnames") or []
        if isinstance(raw_cnames, str):
            raw_cnames = [raw_cnames]
        cnames = [str(value).rstrip(".").lower() for value in raw_cnames if value]
        lower = body_excerpt[:8192].lower()
        for vendor, marker, allowed_codes, severity in TAKEOVER_SIGNATURES:
            if status_code not in allowed_codes:
                continue
            if marker.lower() not in lower:
                continue
            hints = TAKEOVER_CNAME_HINTS.get(vendor, ())
            matched_cname = next(
                (cname for cname in cnames if any(hint in cname for hint in hints)),
                None,
            )
            if not matched_cname:
                continue
            status = "CRITICAL" if severity == "CRITICAL" else "VULNERABLE"
            return self._create_vuln_entry(
                httpx_entry,
                f"Subdomain takeover candidate: {vendor}",
                status,
                severity,
                (
                    f"HTTP {status_code} response body matches a known {vendor} takeover fingerprint "
                    f"('{marker[:80]}'). DNS evidence: CNAME {matched_cname} points to the matching "
                    "provider. Manual claimability confirmation is still required before reporting impact."
                ),
                http_status=status_code,
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
        """Collect confirmed same-origin broken resources as diagnostics.

        Broken images/scripts are quality observations, not security
        vulnerabilities.  They are kept in a separate CSV artifact and are not
        added to the vulnerability report.
        """
        diagnostics = []
        # One shared request budget makes ``-c`` the actual aggregate ceiling.
        # Parent GETs release it before awaiting child HEAD probes, so a shared
        # semaphore cannot deadlock and page fetching is no longer capped at 10.
        request_sem = asyncio.Semaphore(max(1, concurrency))

        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
            async def probe_resource(parent_entry, resource_url, parent_url):
                async with request_sem:
                    try:
                        head_resp = await client.head(resource_url)
                        if head_resp.status_code not in (404, 410):
                            return
                        # Some CDNs reject HEAD while serving GET normally.  A
                        # GET confirmation prevents those false positives.
                        get_resp = await client.get(resource_url)
                        if get_resp.status_code not in (404, 410):
                            return
                        diagnostics.append(self._create_vuln_entry(
                                parent_entry,
                                f"Broken Component: {urlparse(resource_url).path}",
                                "INFO",
                                "INFO",
                                f"Diagnostic only: sub-resource '{resource_url}' returned HTTP "
                                f"{get_resp.status_code} to GET. Parent: {parent_url}",
                                evidence_url=resource_url,
                                http_status=get_resp.status_code,
                                page_title="N/A",
                                content_length=len(get_resp.content),
                            ))
                    except Exception:
                        pass

            async def fetch_and_collect(entry):
                url = entry.get('url')
                if not url:
                    return []
                resource_tasks = []
                async with request_sem:
                    try:
                        resp = await client.get(url)
                        if not 200 <= resp.status_code < 300:
                            return
                        if "html" not in resp.headers.get("content-type", "").lower() and "<html" not in resp.text[:2048].lower():
                            return
                        parser = SubResourceParser()
                        parser.feed(resp.text)
                        for res in parser.resources:
                            abs_url = urljoin(url, res)
                            parsed_parent = urlparse(url)
                            parsed_resource = urlparse(abs_url)
                            if (
                                parsed_resource.scheme in ("http", "https")
                                and parsed_resource.hostname == parsed_parent.hostname
                                and not parsed_resource.path.startswith("/cdn-cgi/")
                            ):
                                resource_tasks.append(probe_resource(entry, abs_url, url))
                    except Exception:
                        pass
                if resource_tasks:
                    await asyncio.gather(*resource_tasks, return_exceptions=True)

            print(f"{Colors.CYAN}[*] Checking for broken components on {len(httpx_data)} alive URLs...{Colors.RESET}")
            progress = DashboardProgress("domain_scan", total=len(httpx_data), noun="URLs")
            page_tasks = [progress.wrap(fetch_and_collect(entry)) for entry in httpx_data]
            if page_tasks:
                await asyncio.gather(*page_tasks, return_exceptions=True)

        return diagnostics

    def save_broken_component_diagnostics(self, diagnostics: list[dict]) -> str:
        """Persist non-vulnerability broken-resource observations."""
        if not diagnostics:
            return ""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.output_dir, f"broken_components_{timestamp}.csv")
        with open(filename, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Parent_or_Evidence_URL", "Resource_URL", "HTTP_Status", "Details"])
            for item in diagnostics:
                writer.writerow([
                    item.get("url", ""), item.get("payload_url", ""),
                    item.get("http_status", ""), item.get("details", ""),
                ])
        print(f"{Colors.GREEN}[+] Broken-resource diagnostics saved to {filename}{Colors.RESET}")
        return filename

    async def run_anomaly_checks(self, alive_urls: list, httpx_data: list = None, concurrency: int = 50) -> list[dict]:
        """Run evidence-backed vulnerability checks on alive URLs.

        Operational anomalies such as 5xx responses, unusual body sizes, and
        generic missing headers are deliberately excluded from vulnerability
        output.  They are not proof of a security defect and created substantial
        false-positive noise in earlier reports.
        """
        # We need httpx_data to create proper vuln entries
        url_to_entry = {entry.get('url'): entry for entry in (httpx_data or []) if entry.get('url')}
        
        findings = []
        semaphore = asyncio.Semaphore(max(1, concurrency))
        
        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False) as client:
            async def check_url(url):
                entry = url_to_entry.get(url, {'url': url, 'input': url})
                async with semaphore:
                    try:
                        # 1. Base response and high-confidence body checks.
                        resp = await client.get(url)

                        # Directory Listing
                        if (
                            resp.status_code == 200
                            and re.search(r"<title>\s*Index of /", resp.text, re.I)
                            and re.search(r"<a[^>]+href=[\"'][^\"']+[\"']", resp.text, re.I)
                        ):
                            findings.append(self._create_vuln_entry(
                                entry, "Directory Listing Enabled", "VULNERABLE", "HIGH",
                                "Confirmed directory-index title and browsable file links in the response.",
                                evidence_url=url,
                                http_status=resp.status_code,
                                page_title="Index of /",
                                content_length=len(resp.content),
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
                        canary_origin = 'https://cors-test.invalid'
                        cors_headers = {'Origin': canary_origin}
                        cors_resp = await client.get(url, headers=cors_headers)
                        acao = cors_resp.headers.get('access-control-allow-origin', '')
                        acac = cors_resp.headers.get('access-control-allow-credentials', '')
                        if acao == canary_origin and acac.lower() == 'true':
                            findings.append(self._create_vuln_entry(
                                entry, "CORS: Arbitrary Origin Reflection with Credentials", "VULNERABLE", "HIGH",
                                f"Confirmed arbitrary origin reflection with credentials: ACAO={acao}; ACAC={acac}.",
                                evidence_url=url,
                                http_status=cors_resp.status_code,
                                page_title="N/A",
                                content_length=len(cors_resp.content),
                            ))

                        # 3. Open redirect.  Compare the parsed Location host to
                        # an exact canary; substring matching mistakes a query
                        # string echoed into a same-origin redirect for a flaw.
                        redirect_host = "redirect-test.invalid"
                        for param in ['url', 'redirect', 'next', 'return']:
                            parsed_url = urlparse(url)
                            query = dict(parse_qsl(parsed_url.query, keep_blank_values=True))
                            query[param] = f"https://{redirect_host}/vaktscan"
                            or_url = urlunparse(parsed_url._replace(query=urlencode(query)))
                            or_resp = await client.get(or_url)
                            if or_resp.status_code in (301, 302, 307, 308):
                                loc = or_resp.headers.get('location', '')
                                resolved = urlparse(urljoin(or_url, loc))
                                if resolved.hostname == redirect_host:
                                    findings.append(self._create_vuln_entry(
                                        entry, f"Confirmed Open Redirect ({param})", "VULNERABLE", "MEDIUM",
                                        f"Confirmed external redirect host {redirect_host}: HTTP "
                                        f"{or_resp.status_code} Location={loc} via parameter {param}.",
                                        evidence_url=or_url,
                                        http_status=or_resp.status_code,
                                        page_title="N/A",
                                        content_length=len(or_resp.content),
                                    ))
                                    break
                    except Exception:
                        pass
            
            print(f"{Colors.CYAN}[*] Running anomaly and misconfig checks on {len(alive_urls)} alive URLs...{Colors.RESET}")
            prog = DashboardProgress("domain_scan", total=len(alive_urls), noun="URLs")
            tasks = [prog.wrap(check_url(url)) for url in alive_urls]
            if tasks:
                await asyncio.gather(*tasks)
                
        return findings

    async def run(self, domains: list, httpx_data: list, alive_urls: list, concurrency: int = 50) -> list[dict]:
        """
        Orchestrate all domain scan checks.
        NOTE: Callers are responsible for calling save_classification_csv() if they
        want the classification CSV - this method only prints the summary to avoid
        double-writing when integrated into run_recon_followups().
        """
        print(f"{Colors.BRIGHT_CYAN}[*] Starting domain checks on {len(domains)} targets...{Colors.RESET}")

        # 1. Classify (no CSV here - caller does it once before calling run())
        classified = self.classify_domains(domains)
        print(f"{Colors.GRAY}[*] Domain mix: {len(classified['INTERNAL'])} INTERNAL, {len(classified['EXTERNAL'])} EXTERNAL{Colors.RESET}")

        # 2. Web Checks
        findings = self.detect_default_pages(httpx_data)
        broken_diagnostics = await self.check_broken_components(httpx_data, concurrency)
        self.save_broken_component_diagnostics(broken_diagnostics)
        findings += await self.run_anomaly_checks(alive_urls, httpx_data, concurrency)

        print(f"{Colors.GREEN}[+] Domain scan finished. Found {len(findings)} web anomalies/issues.{Colors.RESET}")
        return findings
