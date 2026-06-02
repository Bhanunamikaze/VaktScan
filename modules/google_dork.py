"""Google Dorking passive recon module for VaktScan."""

import asyncio
import httpx
from datetime import datetime
import ipaddress

try:
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None

try:
    from playwright_stealth import stealth_async
except ImportError:
    stealth_async = None

MODULE_NAME = "google_dork"

# Built-in dork templates (28 categories targeting critical exposures and vulnerabilities)
BUILTIN_DORKS = [
    # 1. Cloud Storage Exposure
    ("open_s3_bucket",          'site:s3.amazonaws.com "{domain}"'),
    ("azure_blob_exposure",     'site:blob.core.windows.net "{domain}"'),
    ("gcp_storage",             'site:storage.googleapis.com "{domain}"'),
    ("digitalocean_spaces",     'site:digitaloceanspaces.com "{domain}"'),
    
    # 2. Configuration & Environment Exposure
    ("exposed_configs",         'site:{domain} ext:env OR ext:cfg OR ext:conf OR ext:ini OR ext:yml OR ext:yaml OR ext:toml'),
    ("exposed_logs",            'site:{domain} ext:log OR ext:txt "error" OR "warning" OR "exception" OR "debug"'),
    ("docker_compose_exposure", 'site:{domain} filename:docker-compose.yml OR filename:Dockerfile OR filename:docker-compose.yaml'),
    
    # 3. Third-Party Code & Text Leaks
    ("github_leaks",            'site:github.com "{domain}" password OR secret OR token OR apikey OR "db_password"'),
    ("gitlab_leaks",            'site:gitlab.com "{domain}" password OR secret OR token OR apikey'),
    ("pastebin_leaks",          'site:pastebin.com "{domain}" password OR secret OR token OR apikey'),
    ("trello_leaks",            'site:trello.com "{domain}"'),
    
    # 4. Backup & Archive Artifacts
    ("backup_files",            'site:{domain} ext:bak OR ext:old OR ext:backup OR ext:temp OR ext:tmp OR ext:swp'),
    ("database_dumps",          'site:{domain} ext:sql OR ext:db OR ext:dump OR ext:sqlite OR ext:sqlite3 OR ext:mdb'),
    ("compressed_archives",     'site:{domain} ext:zip OR ext:tar.gz OR ext:tgz OR ext:rar OR ext:7z OR ext:war OR ext:tar'),
    
    # 5. Directory & Version Control Disclosures
    ("directory_listing",       'site:{domain} intitle:"index of" "parent directory"'),
    ("version_control_leak",    'site:{domain} inurl:/.git OR inurl:/.svn OR inurl:/.hg OR inurl:/.bzr'),
    
    # 6. Administrative & Control Panels
    ("admin_panels",            'site:{domain} inurl:admin OR inurl:login OR inurl:wp-admin OR inurl:dashboard OR inurl:cpanel OR inurl:controlpanel'),
    ("phpmyadmin_exposure",     'site:{domain} inurl:phpmyadmin OR inurl:pma OR intitle:phpmyadmin'),
    ("kibana_dashboard",        'site:{domain} inurl:5601 OR inurl:app/kibana OR intitle:Kibana'),
    
    # 7. Debugging & Testing Diagnostics
    ("phpinfo_exposure",        'site:{domain} inurl:phpinfo.php OR inurl:info.php OR inurl:test.php OR intitle:"phpinfo()"'),
    ("django_debug_mode",       'site:{domain} "DisallowedHost" OR "TemplateDoesNotExist" OR "Django Version" OR "Traceback (most recent call last)"'),
    ("prometheus_metrics",      'site:{domain} inurl:metrics OR inurl:prometheus OR intitle:Prometheus'),
    
    # 8. Exposed Credentials & API Keys
    ("api_key_in_url",          'site:{domain} inurl:api_key= OR inurl:secret= OR inurl:token= OR inurl:auth_key= OR inurl:apikey='),
    ("cloud_metadata_ssrf",     'site:{domain} inurl:169.254.169.254 OR inurl:latest/meta-data/'),
    
    # 9. Vulnerability-Prone URL Parameters
    ("open_redirect_params",    'site:{domain} inurl:redir= OR inurl:redirect= OR inurl:url= OR inurl:return= OR inurl:next= OR inurl:dest='),
    ("sql_injection_params",    'site:{domain} inurl:id= OR inurl:cat= OR inurl:prod= OR inurl:select= OR inurl:query='),
    
    # 10. Document Exposure (Spreadsheets & PDFs)
    ("sensitive_pdfs",          'site:{domain} ext:pdf "confidential" OR "internal use only" OR "proprietary" OR "not for public redistribution"'),
    ("exposed_spreadsheets",    'site:{domain} ext:xls OR ext:xlsx OR ext:csv OR ext:tsv "password" OR "email" OR "credential" OR "salary"'),
]


def _is_raw_ip(domain: str) -> bool:
    """Check if domain is a raw IP address (no dots or valid IP format)."""
    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        pass

    # Check if it looks like a domain (has dots) or some other text
    if '.' not in domain:
        return True

    return False


def _read_dorks_from_file(filepath: str) -> list[tuple]:
    """
    Read dorks from a newline-delimited file.
    Each line is treated as a dork template with {domain} placeholder.
    Returns a list of (name, template) tuples.
    """
    dorks = []
    try:
        with open(filepath, 'r') as f:
            for idx, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    # Use line index as name for custom dorks
                    dorks.append((f"custom_dork_{idx}", line))
    except Exception as e:
        print(f"Warning: Could not read dorks file '{filepath}': {e}")
        return []
    return dorks


import urllib.parse


def _build_finding(domain: str, category_name: str, dork_query: str, url: str, title: str, snippet: str) -> dict:
    """Helper to build a canonical finding dictionary."""
    return {
        "status": "INFO",
        "severity": "INFO",
        "vulnerability": f"Google Dork: {category_name}",
        "target": domain,
        "resolved_ip": "N/A",
        "port": "443",
        "url": url,
        "payload_url": url,
        "module": MODULE_NAME,
        "service_version": "N/A",
        "details": f"Dork: {dork_query} | Snippet: {snippet}",
        "http_status": "N/A",
        "page_title": title,
        "content_length": "N/A",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


async def run(
    domain: str,
    api_key: str = None,
    cx: str = None,
    dorks=None,
    delay: float = 1.0,
    max_results: int = 10,
    method: str = "auto"
) -> list[dict]:
    """
    Run Google Dorking passive recon for a target domain.

    Args:
        domain: Target domain to search for
        api_key: Google Custom Search API key (optional)
        cx: Google Custom Search engine ID (optional)
        dorks: None to use BUILTIN_DORKS, or a file path (string) to read custom dorks
        delay: Delay in seconds between requests (default 1.0)
        max_results: Maximum results per dork query (default 10)
        method: Search method: 'api', 'playwright', 'html', or 'auto' (default 'auto')

    Returns:
        List of finding dictionaries in canonical schema.
    """
    findings = []

    # Early exit: check if domain is a raw IP
    if _is_raw_ip(domain):
        from modules.dashboard import LiveDashboard
        if not LiveDashboard().active:
            print(f"Warning: Skipping raw IP address '{domain}' for Google Dorking")
        return []

    # Determine which dorks to use
    if dorks is None:
        dork_list = BUILTIN_DORKS
    elif isinstance(dorks, str):
        # Treat as file path
        dork_list = _read_dorks_from_file(dorks)
        if not dork_list:
            print(f"Warning: No dorks loaded from file '{dorks}'")
            return []
    else:
        # If dorks is something else (e.g., list), use it as-is
        dork_list = dorks if isinstance(dorks, list) else BUILTIN_DORKS

    # Track seen URLs to deduplicate across all dorks
    seen_urls = set()

    # Determine selected method
    selected_method = method.lower()
    if selected_method == "auto":
        if api_key and cx:
            selected_method = "api"
        else:
            if async_playwright is not None:
                selected_method = "playwright"
            else:
                selected_method = "html"

    from modules.dashboard import LiveDashboard
    if not LiveDashboard().active:
        print(f"[*] Running Google Dorking using method: {selected_method}")

    if selected_method == "api":
        if not api_key or not cx:
            print("Warning: Missing Google Custom Search credentials (api_key/cx) for api method.")
            return []

        # Google Custom Search API URL
        api_url = "https://customsearch.googleapis.com/customsearch/v1"

        async with httpx.AsyncClient() as client:
            for category_name, dork_template in dork_list:
                # Substitute domain into the dork template
                dork_query = dork_template.format(domain=domain)

                try:
                    # Make the API request
                    params = {
                        "key": api_key,
                        "cx": cx,
                        "q": dork_query,
                        "num": max_results,
                    }

                    response = await client.get(api_url, params=params, timeout=15)

                    # Handle quota exceeded (429)
                    if response.status_code == 429:
                        print("Warning: Google Custom Search quota exceeded (429). Stopping further requests.")
                        break

                    # Handle other HTTP errors gracefully
                    if response.status_code != 200:
                        print(f"Warning: Google Custom Search returned status {response.status_code} for dork '{category_name}': {dork_query}")
                        await asyncio.sleep(delay)
                        continue

                    try:
                        data = response.json()
                    except Exception as e:
                        print(f"Warning: Failed to parse JSON response for dork '{category_name}': {e}")
                        await asyncio.sleep(delay)
                        continue

                    # Process search results
                    items = data.get("items", [])
                    for item in items:
                        url = item.get("link", "N/A")

                        # Skip if we've already seen this URL
                        if url in seen_urls:
                            continue
                        seen_urls.add(url)

                        finding = _build_finding(
                            domain, category_name, dork_query, url,
                            item.get("title", "N/A"), item.get("snippet", "N/A")
                        )
                        findings.append(finding)

                except httpx.RequestError as e:
                    print(f"Warning: Request error for dork '{category_name}': {e}")
                    continue
                except Exception as e:
                    print(f"Warning: Unexpected error processing dork '{category_name}': {e}")
                    continue

                # Respect rate limiting
                await asyncio.sleep(delay)

    elif selected_method == "playwright":
        if async_playwright is None:
            print("Warning: Playwright not installed. Falling back to html method.")
            selected_method = "html"

    # Handle playwright scraping if selected
    if selected_method == "playwright":
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-setuid-sandbox"]
                )
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
                page = await context.new_page()
                if stealth_async is not None:
                    await stealth_async(page)

                captcha_detected = False
                for category_name, dork_template in dork_list:
                    dork_query = dork_template.format(domain=domain)
                    encoded_query = urllib.parse.quote_plus(dork_query)
                    search_url = f"https://www.google.com/search?q={encoded_query}"

                    try:
                        await page.goto(search_url, wait_until="domcontentloaded", timeout=15000)
                        content = await page.content()

                        if "detected unusual traffic" in content or "captcha" in content.lower():
                            captcha_detected = True
                            break

                        # Extract results via JavaScript evaluation in page context
                        items = await page.evaluate("""() => {
                            const results = [];
                            const blocks = document.querySelectorAll('div.g');
                            for (const block of blocks) {
                                const linkEl = block.querySelector('a[href]');
                                const titleEl = block.querySelector('h3');
                                if (linkEl && titleEl) {
                                    let snippet = "";
                                    const snippetEls = block.querySelectorAll('div[style*="-webkit-line-clamp"], div.VwiC3b, div.yDgn2d');
                                    if (snippetEls.length > 0) {
                                        snippet = Array.from(snippetEls).map(el => el.innerText).join(" ");
                                    } else {
                                        const divs = block.querySelectorAll('div');
                                        for (const div of divs) {
                                            if (div.innerText && div.innerText.length > 30 && !div.querySelector('h3') && !div.querySelector('a')) {
                                                snippet = div.innerText;
                                                break;
                                            }
                                        }
                                    }
                                    results.push({
                                        link: linkEl.href,
                                        title: titleEl.innerText,
                                        snippet: snippet
                                    });
                                }
                            }
                            return results;
                        }""")

                        for item in items[:max_results]:
                            url = item.get("link")
                            if not url or url in seen_urls:
                                continue
                            seen_urls.add(url)

                            finding = _build_finding(
                                domain, category_name, dork_query, url,
                                item.get("title", "N/A"), item.get("snippet", "N/A")
                            )
                            findings.append(finding)

                    except Exception as e:
                        print(f"Warning: Playwright error for dork '{category_name}': {e}")

                    # Respect rate limiting delay
                    await asyncio.sleep(delay)

                await browser.close()
                if captcha_detected:
                    raise Exception("Google unusual traffic / CAPTCHA block detected")
        except Exception as e:
            from modules.dashboard import LiveDashboard
            if not LiveDashboard().active:
                print(f"Warning: Playwright browser execution failed: {e}. Falling back to html method.")
            selected_method = "html"

    # Handle html/httpx scraping fallback
    if selected_method == "html":
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            print("Warning: BeautifulSoup4 (bs4) not installed. Cannot scrape HTML google results.")
            return findings

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": "https://www.google.com/",
        }

        async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
            for category_name, dork_template in dork_list:
                dork_query = dork_template.format(domain=domain)
                encoded_query = urllib.parse.quote_plus(dork_query)
                url = f"https://www.google.com/search?q={encoded_query}&gbv=1"

                try:
                    response = await client.get(url, timeout=15)
                    if response.status_code == 429:
                        from modules.dashboard import LiveDashboard
                        if not LiveDashboard().active:
                            print("Warning: Google HTML scraping returned status 429 (blocked). Stopping.")
                        break
                    if response.status_code != 200:
                        print(f"Warning: Google HTML scraping returned status {response.status_code} for '{category_name}'")
                        await asyncio.sleep(delay)
                        continue

                    if "detected unusual traffic" in response.text or "captcha" in response.text.lower():
                        from modules.dashboard import LiveDashboard
                        if not LiveDashboard().active:
                            print("Warning: Google detected unusual traffic (CAPTCHA block) during HTML scraping. Stopping.")
                        break

                    soup = BeautifulSoup(response.text, "html.parser")
                    blocks = soup.find_all("div", class_=["g", "ZINbbc"])
                    count = 0

                    for block in blocks:
                        if count >= max_results:
                            break

                        link_tag = block.find("a")
                        if not link_tag or not link_tag.get("href"):
                            continue

                        href = link_tag.get("href")
                        # Decode redirected links
                        if href.startswith("/url?"):
                            parsed_href = urllib.parse.urlparse(href)
                            qs = urllib.parse.parse_qs(parsed_href.query)
                            if "q" in qs:
                                href = qs["q"][0]
                            else:
                                continue
                        elif href.startswith("/") or "google.com" in href:
                            continue

                        if href in seen_urls:
                            continue
                        seen_urls.add(href)

                        title_tag = block.find("h3")
                        title = title_tag.get_text() if title_tag else "N/A"

                        snippet = ""
                        divs = block.find_all("div")
                        for div in divs:
                            text = div.get_text().strip()
                            if text and len(text) > 30 and title not in text and not div.find("h3") and not div.find("a"):
                                snippet = text
                                break

                        finding = _build_finding(domain, category_name, dork_query, href, title, snippet)
                        findings.append(finding)
                        count += 1

                except Exception as e:
                    print(f"Warning: HTML scraping error for dork '{category_name}': {e}")

                # Respect rate limiting delay
                await asyncio.sleep(delay)

    return findings
