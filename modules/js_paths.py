"""
js_paths.py — VaktScan JS Paths Module
=======================================
Crawls target URLs, discovers JS files, extracts embedded paths/hosts,
probes endpoint permutations, and returns VaktScan-compatible vuln dicts
for aggregation by main.py.

Usage:
    python main.py -m js-paths --url https://example.com
    python main.py -m js-paths --ds-file urls.txt [-c 30] [--js-timeout 15]
"""

import asyncio
import os
import re
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Colors:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(url: str, vulnerability: str, status: str,
                  severity: str, details: str, http_status="N/A") -> dict:
    """Return a VaktScan-compatible vulnerability dict."""
    parsed = urlparse(url)
    port   = str(parsed.port or (443 if parsed.scheme == 'https' else 80))
    return {
        "target":          parsed.hostname or url,
        "resolved_ip":     "",
        "port":            port,
        "vulnerability":   vulnerability,
        "status":          status,
        "severity":        severity,
        "module":          "js_paths",
        "service_version": "N/A",
        "url":             url,
        "details":         details,
        "http_status":     str(http_status),
        "page_title":      "N/A",
        "content_length":  "N/A",
    }


# ---------------------------------------------------------------------------
# Core recon engine
# ---------------------------------------------------------------------------

class JSRecon:
    EXCLUDED_DOMAINS = [
        "cloudflare.com", "github.com", "apple.com", "google.com",
        "adobe.ly", "trustpilot.com", "w3.org", "twitter.com",
        "instagram.com", "facebook.com","bit.ly","angular.dev","jquery.com","adobedtm.com"
    ]

    # Hardcoded-secret patterns
    SECRET_PATTERNS = {
        "AWS Access Key":      re.compile(r'AKIA[0-9A-Z]{16}'),
        "AWS Secret Key":      re.compile(r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s"\'=:]+([A-Za-z0-9/+=]{40})'),
        "Google API Key":      re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "Slack Token":         re.compile(r'xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}'),
        "GitHub Token":        re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
        "JWT Token":           re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-\.]+'),
        "Private Key Block":   re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
        "Bearer Token":        re.compile(r'(?i)authorization[\s"\'=:]+["\']?Bearer\s+([A-Za-z0-9_\-\.=]{20,})["\']?'),
        "Generic API Key":     re.compile(r'(?i)api[_\-]?key[\s"\'=:]+["\']([A-Za-z0-9_\-]{20,})["\']'),
        "Hardcoded Password":  re.compile(r'(?i)(?:password|passwd|pwd)[\s"\'=:]+["\']([^\s"\']{6,})["\']'),
        "Generic Secret":      re.compile(r'(?i)(?:secret|token)[\s"\'=:]+["\']([A-Za-z0-9_\-\.]{16,})["\']'),
        "Firebase URL":        re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com'),
    }

    # Paths that are high-value when accessible
    SENSITIVE_PATH_KEYWORDS = {
        "/.env":       ("Environment File Exposed",  "CRITICAL"),
        "/.git":       ("Git Repository Exposed",    "CRITICAL"),
        "/api/":       ("API Endpoint",              "HIGH"),
        "/graphql":    ("GraphQL Endpoint",          "HIGH"),
        "/swagger":    ("Swagger/OpenAPI Docs",      "HIGH"),
        "/admin":      ("Admin Panel",               "HIGH"),
        "/actuator":   ("Spring Actuator",           "HIGH"),
        "/debug":      ("Debug Interface",           "HIGH"),
        "/metrics":    ("Metrics/Telemetry Exposed", "MEDIUM"),
        "/health":     ("Health-Check Endpoint",     "LOW"),
        "/backup":     ("Backup File",               "HIGH"),
        "/upload":     ("Upload Endpoint",           "MEDIUM"),
        "/internal":   ("Internal Endpoint",         "MEDIUM"),
        "/private":    ("Private Endpoint",          "MEDIUM"),
        "/config":     ("Config Endpoint",           "HIGH"),
        "/v1/":        ("Versioned API",             "MEDIUM"),
        "/v2/":        ("Versioned API",             "MEDIUM"),
        "/v3/":        ("Versioned API",             "MEDIUM"),
    }

    INTERNAL_IP_RE = re.compile(
        r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
        r'|192\.168\.\d{1,3}\.\d{1,3})\b'
    )

    def __init__(self, target_urls: list, threads: int = 20, timeout: int = 10):
        self.target_urls = target_urls
        self.threads     = threads
        self.timeout     = timeout
        self._stop       = threading.Event()

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/114.0.0.0 Safari/537.36"
            )
        })

        self.js_urls       = set()
        self.paths         = set()
        self.hosts         = set()
        self.findings      = []   # VaktScan vuln dicts
        self.probe_results = []   # every interesting probe hit

        # ── Full URL pattern (captures scheme://host:port/path) ──
        self.url_pattern = re.compile(
            r'(https?://[a-zA-Z0-9.\-]+(?::\d+)?(?:/[a-zA-Z0-9_./:@!$&\'()*+,;=\-~%]*)?)'
        )

        # ── Multi-strategy path extraction patterns ──
        # Each tuple: (compiled regex, group index to extract)
        self._path_extractors = self._build_path_extractors()

        # Junk suffixes/fragments to strip after extraction
        self._junk_trail = re.compile(r'["\'\s;,\)\}\]\\]+$')

        # Minimum path quality filter
        self._static_ext = {
            '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.webm', '.mp3',
        }

    @staticmethod
    def _build_path_extractors():
        """Compile all regex strategies once at init time."""
        return [
            # 1. Classic quoted paths: "/api/v1/users"
            (re.compile(r'''["'](/[a-zA-Z0-9_.\-][a-zA-Z0-9_./:@!$&()*+,;=\-~%?#]*)["']'''), 0),

            # 2. fetch / axios / http.get / http.post / $.ajax calls
            (re.compile(
                r'''(?:fetch|axios\.(?:get|post|put|patch|delete|request)|'''
                r'''\.(?:get|post|put|delete|patch|ajax|open))\s*\(\s*["'`](/[^"'`\s]{2,})["'`]'''
            ), 0),

            # 3. Template literal paths:  `/api/users/${id}`  →  /api/users/
            (re.compile(r'`(/[a-zA-Z0-9_.\-/]+(?:\$\{[^}]*\}[a-zA-Z0-9_.\-/]*)*)`'), 0),

            # 4. Route definitions: path: "/dashboard", route: '/settings'
            (re.compile(r'''(?:path|route|url|endpoint|href|to|redirect|navigate)\s*[:=]\s*["'`](/[^"'`\s]{2,})["'`]'''), 0),

            # 5. String concatenation:  "/api/" + version + "/users"
            (re.compile(r'''["'](/[a-zA-Z0-9_.\-/]+)/?\s*["']\s*\+'''), 0),

            # 6. Webpack/Vite chunk maps:  123: "/static/js/chunk"
            (re.compile(r'''\d+\s*:\s*["'](/[a-zA-Z0-9_.\-/]+)["']'''), 0),

            # 7. XMLHttpRequest.open:  .open("GET", "/api/data")
            (re.compile(r'''\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["'`](/[^"'`\s]{2,})["'`]'''), 0),

            # 8. React-Router / Vue-Router component routes
            (re.compile(r'''<\s*(?:Route|router-link|Link|NavLink|Redirect)\s[^>]*(?:path|to|href)\s*=\s*["'](/[^"']{2,})["']'''), 0),

            # 9. File references: "/data/config.json", "/export.csv"
            (re.compile(r'''["'](/[a-zA-Z0-9_.\-/]+\.(?:json|xml|yaml|yml|csv|txt|log|sql|bak|conf|cfg|ini|env|key|pem))["']'''), 0),

            # 10. Assignment to URL-like vars:  apiUrl = "/v2/search"
            (re.compile(r'''(?:url|uri|endpoint|api|path|base|href|src)\s*=\s*["'`](/[a-zA-Z0-9_.\-/]{2,})["'`]''', re.I), 0),

            # 11. Hash/fragment routes: "#/admin", "#!/settings"
            (re.compile(r'''["'](#!?/[a-zA-Z0-9_.\-/]{2,})["']'''), 0),

            # 12. Relative multi-segment paths without leading slash (api/v1/users)
            (re.compile(r'''["']((?:api|v[0-9]+|rest|graphql|internal|admin|auth|oauth)/[a-zA-Z0-9_.\-/]{2,})["']''', re.I), 0),
        ]

    # ------------------------------------------------------------------
    # Path extraction & filtering
    # ------------------------------------------------------------------

    def _extract_paths(self, content: str) -> set:
        """Run all extraction strategies on JS content and return clean paths."""
        raw = set()
        for pattern, _grp in self._path_extractors:
            for m in pattern.finditer(content):
                raw.add(m.group(1))

        cleaned = set()
        for p in raw:
            # Strip trailing junk from over-greedy matches
            p = self._junk_trail.sub('', p)
            # Collapse template literal placeholders → wildcard segment
            p = re.sub(r'\$\{[^}]*\}', '*', p)
            # Normalise repeated slashes
            p = re.sub(r'/{2,}', '/', p)
            # Ensure leading slash (for relative patterns like api/v1/...)
            if not p.startswith('/') and not p.startswith('#'):
                p = '/' + p
            # Drop pure static assets
            ext = os.path.splitext(p.split('?')[0])[1].lower()
            if ext in self._static_ext:
                continue
            # Must have at least one alpha char to be useful
            if not re.search(r'[a-zA-Z]', p):
                continue
            # Length sanity (skip overly short or absurdly long)
            if len(p) < 2 or len(p) > 500:
                continue
            cleaned.add(p)
        return cleaned

    def _extract_hosts_and_paths_from_urls(self, content: str) -> None:
        """Pull full URLs, split into hosts + path components."""
        for url in self.url_pattern.findall(content):
            parsed    = urlparse(url)
            base_host = f"{parsed.scheme}://{parsed.netloc}"
            if self._is_allowed(base_host):
                self.hosts.add(base_host)
            if parsed.path and parsed.path != '/':
                self.paths.add(parsed.path)
            # Also add the full URL path with query for probing
            if parsed.query:
                self.paths.add(f"{parsed.path}?{parsed.query}")

    # ------------------------------------------------------------------
    # Allowlist helper
    # ------------------------------------------------------------------

    def _is_allowed(self, host_url: str) -> bool:
        try:
            domain = urlparse(host_url).netloc.lower().split(':')[0]
            return not any(
                domain == ex or domain.endswith('.' + ex)
                for ex in self.EXCLUDED_DOMAINS
            )
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Phase 1 — collect JS URLs from each target page
    # ------------------------------------------------------------------

    def collect_js_files(self, target_url: str) -> None:
        print(f"{Colors.CYAN}[*] Fetching: {target_url}{Colors.RESET}")
        try:
            r    = self.session.get(target_url, verify=False, timeout=self.timeout)
            soup = BeautifulSoup(r.text, 'html.parser')

            # Standard <script src>
            for tag in soup.find_all('script', src=True):
                self.js_urls.add(urljoin(target_url, tag['src']))

            # Module preloads (React/Vue/Vite)
            for link in soup.find_all('link', href=True):
                rel = link.get('rel', [])
                if isinstance(rel, str):
                    rel = [rel]
                if 'modulepreload' in rel or ('preload' in rel and link.get('as') == 'script'):
                    self.js_urls.add(urljoin(target_url, link['href']))

            # Inline <script> blocks — extract paths directly from HTML JS
            for inline in soup.find_all('script', src=False):
                if inline.string:
                    self.paths.update(self._extract_paths(inline.string))
                    self._extract_hosts_and_paths_from_urls(inline.string)

        except Exception as exc:
            print(f"{Colors.YELLOW}[-] Failed to fetch {target_url}: {exc}{Colors.RESET}")

    # ------------------------------------------------------------------
    # Phase 2 — parse each JS file
    # ------------------------------------------------------------------

    def _check_source_map(self, js_url: str) -> None:
        """Flag exposed .js.map source-map files."""
        map_url = js_url + ".map"
        try:
            r = self.session.get(map_url, verify=False, timeout=self.timeout,
                                 allow_redirects=False)
            if r.status_code == 200 and 'mappings' in r.text[:1000]:
                self.findings.append(_make_finding(
                    map_url,
                    "Exposed JS Source Map",
                    "VULNERABLE", "HIGH",
                    f"Source map at {map_url} — leaks original source code.",
                    http_status=200,
                ))
        except Exception:
            pass

    def _check_secrets(self, js_url: str, content: str) -> None:
        """Scan JS content for hardcoded secrets."""
        for name, pattern in self.SECRET_PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                sample = str(matches[0])[:60]
                self.findings.append(_make_finding(
                    js_url,
                    f"Hardcoded Secret: {name}",
                    "VULNERABLE", "CRITICAL",
                    f"Pattern matched in {js_url}. Sample: {sample}…",
                    http_status=200,
                ))

    def _check_internal_ips(self, js_url: str, content: str) -> None:
        """Flag RFC-1918 addresses embedded in JS."""
        for ip in set(self.INTERNAL_IP_RE.findall(content)):
            self.findings.append(_make_finding(
                js_url,
                "Internal IP Disclosure",
                "POTENTIAL", "MEDIUM",
                f"RFC-1918 address '{ip}' found in {js_url}",
                http_status=200,
            ))

    def parse_js_file(self, js_url: str) -> None:
        if self._stop.is_set():
            return
        try:
            r       = self.session.get(js_url, verify=False, timeout=self.timeout)
            content = r.text

            # Multi-strategy path extraction
            self.paths.update(self._extract_paths(content))

            # Full URL extraction → hosts + paths
            self._extract_hosts_and_paths_from_urls(content)

            # Vuln checks
            self._check_secrets(js_url, content)
            self._check_internal_ips(js_url, content)
            self._check_source_map(js_url)

        except Exception:
            pass

    # keep old name for compat
    def is_allowed_host(self, h): return self._is_allowed(h)

    def run_js_analysis(self) -> None:
        import concurrent.futures
        print(f"{Colors.CYAN}[*] Parsing {len(self.js_urls)} JS file(s)...{Colors.RESET}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(self.parse_js_file, u) for u in self.js_urls]
            try:
                for f in as_completed(futs):
                    if self._stop.is_set():
                        break
                    f.result()  # propagate exceptions if needed
            except KeyboardInterrupt:
                self._stop.set()
                ex.shutdown(wait=False, cancel_futures=True)
                raise

        for url in self.target_urls:
            parsed = urlparse(url)
            h      = f"{parsed.scheme}://{parsed.netloc}"
            if self._is_allowed(h):
                self.hosts.add(h)

        print(
            f"{Colors.GREEN}[+] {len(self.paths)} path(s), "
            f"{len(self.hosts)} host(s), "
            f"{len(self.findings)} finding(s) so far.{Colors.RESET}"
        )

    # ------------------------------------------------------------------
    # Phase 3 — probe host × path permutations
    # ------------------------------------------------------------------

    def probe_endpoint(self, combo: tuple) -> None:
        if self._stop.is_set():
            return
        host, path = combo
        url      = f"{host.rstrip('/')}{path}"
        hostname = urlparse(url).netloc
        try:
            r            = self.session.get(url, verify=False, timeout=self.timeout,
                                            allow_redirects=False)
            status       = r.status_code
            server       = r.headers.get('Server', 'unknown')
            content_type = r.headers.get('Content-Type', '')

            if status not in (200, 201, 301, 302, 401, 403):
                return

            # Record every valid probe hit
            self.probe_results.append({
                "Hostname":      hostname,
                "URL":           url,
                "Path":          path,
                "Status Code":   status,
                "Server Header": server,
            })

            print(f"{Colors.GREEN}[Probe] {status} | {server[:15]:<15} | {url}{Colors.RESET}")

            # --- Sensitive path detection ---
            for kw, (label, base_sev) in self.SENSITIVE_PATH_KEYWORDS.items():
                if kw in path.lower():
                    if status == 200:
                        vuln_status = "VULNERABLE"
                        sev         = base_sev
                    else:
                        vuln_status = "POTENTIAL"
                        sev         = "MEDIUM"
                    self.findings.append(_make_finding(
                        url,
                        f"Sensitive Path Accessible: {label}",
                        vuln_status, sev,
                        f"HTTP {status} on '{path}'. Server: {server}",
                        http_status=status,
                    ))
                    break

            # --- Unauthenticated JSON data ---
            if status == 200 and 'application/json' in content_type:
                preview = r.text[:150].strip()
                self.findings.append(_make_finding(
                    url,
                    "Unauthenticated JSON Endpoint",
                    "POTENTIAL", "MEDIUM",
                    f"Open JSON response at '{path}'. Preview: {preview}",
                    http_status=status,
                ))

            # --- Directory listing ---
            if status == 200 and 'text/html' in content_type and 'Index of /' in r.text:
                self.findings.append(_make_finding(
                    url,
                    "Directory Listing Enabled",
                    "VULNERABLE", "HIGH",
                    f"'Index of /' found at {url}",
                    http_status=status,
                ))

        except requests.exceptions.RequestException:
            pass

    def execute_probing(self) -> None:
        import concurrent.futures
        combos = [(h, p) for h in self.hosts for p in self.paths]
        print(f"{Colors.CYAN}[*] Probing {len(combos):,} permutation(s)...{Colors.RESET}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(self.probe_endpoint, c) for c in combos]
            try:
                for f in as_completed(futs):
                    if self._stop.is_set():
                        break
                    f.result()
            except KeyboardInterrupt:
                self._stop.set()
                ex.shutdown(wait=False, cancel_futures=True)
                raise

    # ------------------------------------------------------------------
    # Orchestrator — returns VaktScan vuln dicts
    # ------------------------------------------------------------------

    def run(self) -> dict:
        """Run full workflow. Returns dict with findings + raw data."""
        try:
            for url in self.target_urls:
                if self._stop.is_set():
                    break
                self.collect_js_files(url)

            if not self.js_urls:
                print(f"{Colors.YELLOW}[-] No JS files found. Exiting.{Colors.RESET}")
                return self._result_dict()

            self.run_js_analysis()

            if not self.paths or not self.hosts:
                print(f"{Colors.YELLOW}[-] No paths/hosts extracted. Skipping probing.{Colors.RESET}")
                return self._result_dict()

            self.execute_probing()
        except KeyboardInterrupt:
            self._stop.set()
            print(f"\n{Colors.YELLOW}[!] Interrupted — returning partial results.{Colors.RESET}")

        return self._result_dict()

    def _result_dict(self) -> dict:
        return {
            "findings":      self.findings,
            "paths":         sorted(self.paths),
            "hosts":         sorted(self.hosts),
            "js_urls":       sorted(self.js_urls),
            "probe_results": self.probe_results,
        }


# ---------------------------------------------------------------------------
# VaktScan async wrapper
# ---------------------------------------------------------------------------

class JSPathsScanner:
    def __init__(self, target_urls: list, threads: int = 20, timeout: int = 10):
        self.target_urls = target_urls
        self.threads     = threads
        self.timeout     = timeout

    async def run(self) -> dict:
        """
        Run JSRecon in a thread pool.
        Returns dict with keys: findings, paths, hosts, js_urls, probe_results.
        """
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = await loop.run_in_executor(pool, self._run_sync)
        return result

    def _run_sync(self) -> dict:
        return JSRecon(
            target_urls=self.target_urls,
            threads=self.threads,
            timeout=self.timeout,
        ).run()
