"""Google Dorking passive recon module for VaktScan."""

import asyncio
import httpx
from datetime import datetime
import ipaddress

MODULE_NAME = "google_dork"

# Built-in dork templates (12 categories)
BUILTIN_DORKS = [
    ("open_s3_bucket",      'site:s3.amazonaws.com "{domain}"'),
    ("azure_blob_exposure", 'site:blob.core.windows.net "{domain}"'),
    ("gcp_storage",         'site:storage.googleapis.com "{domain}"'),
    ("exposed_configs",     'site:{domain} ext:env OR ext:cfg OR ext:conf OR ext:ini'),
    ("exposed_logs",        'site:{domain} ext:log'),
    ("pastebin_leaks",      'site:pastebin.com "{domain}" password OR passwd OR secret OR token OR apikey'),
    ("github_leaks",        'site:github.com "{domain}" password OR secret OR token OR apikey'),
    ("backup_files",        'site:{domain} ext:bak OR ext:sql OR ext:dump OR ext:backup'),
    ("directory_listing",   'site:{domain} intitle:"index of" "parent directory"'),
    ("admin_panels",        'site:{domain} inurl:admin OR inurl:login OR inurl:wp-admin'),
    ("api_key_in_url",      'site:{domain} inurl:api_key= OR inurl:secret= OR inurl:token='),
    ("cloud_metadata_ssrf", 'site:{domain} inurl:169.254.169.254'),
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


async def run(
    domain: str,
    api_key: str,
    cx: str,
    dorks=None,
    delay: float = 1.0,
    max_results: int = 10
) -> list[dict]:
    """
    Run Google Dorking passive recon for a target domain.

    Args:
        domain: Target domain to search for
        api_key: Google Custom Search API key
        cx: Google Custom Search engine ID
        dorks: None to use BUILTIN_DORKS, or a file path (string) to read custom dorks
        delay: Delay in seconds between requests (default 1.0)
        max_results: Maximum results per dork query (default 10)

    Returns:
        List of finding dictionaries in canonical schema.
    """
    findings = []

    # Early exit: check for missing credentials
    if not api_key or not cx:
        print(f"Warning: Missing Google Custom Search credentials (api_key={bool(api_key)}, cx={bool(cx)})")
        return []

    # Early exit: check if domain is a raw IP
    if _is_raw_ip(domain):
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
                    print(f"Warning: Google Custom Search quota exceeded (429). Stopping further requests.")
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

                    # Build finding in canonical schema
                    finding = {
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
                        "details": f"Dork: {dork_query} | Snippet: {item.get('snippet', 'N/A')}",
                        "http_status": "N/A",
                        "page_title": item.get("title", "N/A"),
                        "content_length": "N/A",
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                    }
                    findings.append(finding)

            except httpx.RequestError as e:
                print(f"Warning: Request error for dork '{category_name}': {e}")
                continue
            except Exception as e:
                print(f"Warning: Unexpected error processing dork '{category_name}': {e}")
                continue

            # Respect rate limiting
            await asyncio.sleep(delay)

    return findings
