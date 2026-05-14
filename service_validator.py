import asyncio
import sys
import os

# Add vendor directory to Python path for httpx
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'vendor'))

import httpx
from urllib.parse import urlparse


def _is_full_url(value):
    return isinstance(value, str) and (value.startswith("http://") or value.startswith("https://"))


def _extract_scan_address(target_or_scan_address):
    if isinstance(target_or_scan_address, dict):
        return target_or_scan_address.get("scan_address", "")
    return target_or_scan_address


def _extract_aem_validation_context(target_or_scan_address, port):
    if isinstance(target_or_scan_address, dict):
        scan_address = target_or_scan_address.get("scan_address", "")
        display_target = target_or_scan_address.get("display_target", scan_address)
    else:
        scan_address = target_or_scan_address
        display_target = scan_address

    full_url = None
    for candidate in [display_target, scan_address]:
        if _is_full_url(candidate):
            full_url = candidate
            break

    parsed = urlparse(full_url) if full_url else None
    origin_url = f"{parsed.scheme}://{parsed.netloc}" if parsed and parsed.netloc else None
    path = (parsed.path or "").rstrip("/") if parsed and parsed.netloc else ""
    return scan_address, origin_url, full_url, path

async def validate_elasticsearch(scan_address, port, timeout=5):
    """
    Validates if Elasticsearch is running on the given address:port.
    Checks both HTTP and HTTPS protocols.
    Returns True if Elasticsearch is detected, False otherwise.
    """
    protocols = ['http', 'https']
    
    for protocol in protocols:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                # Try root endpoint
                response = await client.get(f"{protocol}://{scan_address}:{port}/")
                if response.status_code == 200:
                    content = response.text.lower()
                    if '"cluster_name"' in content or '"tagline"' in content and 'elasticsearch' in content:
                        return True
                
                # Try _cluster/health endpoint
                response = await client.get(f"{protocol}://{scan_address}:{port}/_cluster/health")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'cluster_name' in content or 'status' in content:
                        return True
        except:
            continue
    return False

async def validate_kibana(scan_address, port, timeout=5):
    """
    Validates if Kibana is running on the given address:port.
    Checks both HTTP and HTTPS protocols.
    Returns True if Kibana is detected, False otherwise.
    """
    protocols = ['http', 'https']
    
    for protocol in protocols:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                # Try main Kibana page
                response = await client.get(f"{protocol}://{scan_address}:{port}/")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'kibana' in content or 'elastic' in content:
                        return True
                
                # Try API status endpoint
                response = await client.get(f"{protocol}://{scan_address}:{port}/api/status")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'kibana' in content or 'version' in content:
                        return True
                
                # Try app/kibana endpoint
                response = await client.get(f"{protocol}://{scan_address}:{port}/app/kibana")
                if response.status_code in [200, 302]:
                    return True
        except:
            continue
    return False

async def validate_grafana(scan_address, port, timeout=5):
    """
    Validates if Grafana is running on the given address:port.
    Checks both HTTP and HTTPS protocols.
    Returns True if Grafana is detected, False otherwise.
    """
    protocols = ['http', 'https']
    
    for protocol in protocols:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                # Try main Grafana page
                response = await client.get(f"{protocol}://{scan_address}:{port}/")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'grafana' in content:
                        return True
                
                # Try login page
                response = await client.get(f"{protocol}://{scan_address}:{port}/login")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'grafana' in content:
                        return True
                
                # Try API health endpoint
                response = await client.get(f"{protocol}://{scan_address}:{port}/api/health")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'database' in content or 'commit' in content:
                        return True
                
                # Check for Grafana-specific headers
                if 'grafana' in str(response.headers).lower():
                    return True
        except:
            continue
    return False

async def validate_prometheus(scan_address, port, timeout=5):
    """
    Validates if Prometheus is running on the given address:port.
    Checks both HTTP and HTTPS protocols.
    Returns True if Prometheus is detected, False otherwise.
    """
    protocols = ['http', 'https']
    
    for protocol in protocols:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                # Try main Prometheus page - look for specific Prometheus indicators
                response = await client.get(f"{protocol}://{scan_address}:{port}/")
                if response.status_code == 200:
                    content = response.text.lower()
                    # More specific check - look for Prometheus-specific content
                    if 'prometheus time series database' in content or 'prometheus server' in content:
                        return True
                
                # Try metrics endpoint - most reliable Prometheus indicator
                response = await client.get(f"{protocol}://{scan_address}:{port}/metrics")
                if response.status_code == 200:
                    content = response.text
                    # Look for Prometheus-specific metrics format and actual prometheus_ metrics
                    if ('prometheus_' in content and '# HELP' in content and '# TYPE' in content) or \
                       ('# HELP prometheus_' in content):
                        return True
                
                # Try API query endpoint - Prometheus-specific API
                response = await client.get(f"{protocol}://{scan_address}:{port}/api/v1/query?query=up")
                if response.status_code == 200:
                    content = response.text.lower()
                    # Look for Prometheus-specific JSON response structure
                    if '"status":"success"' in content and '"resulttype":"' in content and '"data":{' in content:
                        return True
                
                # Try graph endpoint - Prometheus web UI
                response = await client.get(f"{protocol}://{scan_address}:{port}/graph")
                if response.status_code == 200:
                    content = response.text.lower()
                    # Look for Prometheus-specific UI elements
                    if 'prometheus graph' in content or 'prometheus expression browser' in content:
                        return True
                
                # Try config endpoint - Prometheus-specific
                response = await client.get(f"{protocol}://{scan_address}:{port}/api/v1/status/config")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'scrape_configs' in content or 'global:' in content:
                        return True
        except:
            continue
    return False

async def validate_nextjs(scan_address, port, timeout=5):
    """
    Validates if a Next.js application is running on the given address:port.
    """
    protocols = ['http', 'https']
    for protocol in protocols:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                response = await client.get(f"{protocol}://{scan_address}:{port}/")
                
                # Check for x-powered-by header
                if 'next.js' in response.headers.get('x-powered-by', '').lower():
                    return True

                # Check for common Next.js patterns in the body
                if '/_next/' in response.text:
                    return True
                
                if 'react-dom' in response.text:
                    return True

        except:
            continue
    return False

async def validate_aem(target_or_scan_address, port, timeout=5):
    """
    Validates if Adobe Experience Manager (AEM) is running on the given address:port.
    Checks both HTTP and HTTPS. Looks for AEM-specific login pages, CRXDE, and content indicators.
    Returns True if AEM is detected, False otherwise.
    """
    scan_address, supplied_origin, supplied_url, supplied_path = _extract_aem_validation_context(target_or_scan_address, port)
    protocols = ['https', 'http']
    aem_indicators = [
        'granite', 'adobe experience manager', 'cq5', 'cq.shared',
        'crx', 'sling', 'j_security_check', 'coral-shell', 'crxde',
    ]
    jcr_keys = ["jcr:primarytype", "jcr:mixintypes", "sling:resourcetype", "cq:tags", "dam:"]

    candidate_bases = []
    if supplied_origin:
        candidate_bases.append(supplied_origin.rstrip('/'))
    for protocol in protocols:
        candidate = f"{protocol}://{scan_address}:{port}"
        if candidate not in candidate_bases:
            candidate_bases.append(candidate)

    def path_probes():
        if not supplied_origin or not supplied_path or supplied_path == "/":
            return []
        parts = [part for part in supplied_path.strip("/").split("/") if part]
        prefixes = []
        for length in [len(parts), len(parts) - 1, 2, 1]:
            if length <= 0 or length > len(parts):
                continue
            prefix = "/" + "/".join(parts[:length])
            if prefix not in prefixes:
                prefixes.append(prefix)
        probes = [supplied_url]
        for prefix in prefixes:
            if prefix.endswith(".json"):
                candidates = [prefix]
            else:
                candidates = [prefix, f"{prefix}.json", f"{prefix}.1.json", f"{prefix}.infinity.json"]
            for candidate in candidates:
                url = f"{supplied_origin}{candidate}"
                if url not in probes:
                    probes.append(url)
        return probes

    extra_path_probes = path_probes()

    for base_url in candidate_bases:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                # Try AEM Touch UI login page
                r = await client.get(f"{base_url}/libs/granite/core/content/login.html")
                if r.status_code == 200:
                    if any(ind in r.text.lower() for ind in aem_indicators):
                        return True

                # Try authoring surfaces often exposed on author nodes
                for author_path in ["/aem/start.html", "/sites.html", "/assets.html"]:
                    try:
                        ra = await client.get(f"{base_url}{author_path}")
                        if ra.status_code == 200 and any(ind in ra.text.lower() for ind in ['aem', 'sites', 'assets', 'granite', 'crx']):
                            return True
                    except Exception:
                        pass

                # Try AEM Classic login page
                r = await client.get(f"{base_url}/libs/cq/core/content/login.html")
                if r.status_code in [200, 302] and any(ind in r.text.lower() for ind in aem_indicators):
                    return True

                # CRXDE accessible (strong AEM indicator even if 401/403)
                r = await client.get(f"{base_url}/crx/de/index.jsp")
                if r.status_code == 200 and any(ind in r.text.lower() for ind in ['crxde', 'repository', 'jcr']):
                    return True

                # Check root page for AEM-specific content
                r = await client.get(f"{base_url}/")
                if any(ind in r.text.lower() for ind in aem_indicators):
                    return True
                if any(marker in r.headers.get(hdr, '').lower() for hdr in ['Server', 'X-Powered-By', 'X-Generator'] for marker in ['aem', 'adobe experience manager', 'apache sling', 'crx']):
                    return True

                # Product info endpoint is a very strong signal
                try:
                    rp = await client.get(f"{base_url}/system/console/status-productinfo.json")
                    if rp.status_code == 200 and 'adobe experience manager' in rp.text.lower():
                        return True
                except Exception:
                    pass

                # Fingerprint via Sling GET servlet JCR JSON response
                # Even headless/BFF-fronted AEM leaks jcr:* keys in .json endpoints
                for jcr_path in [
                    "/content.json",
                    "/content.1.json",
                    "/content/dam.json",
                    "/conf.json",
                    "/content/cq:graphql/global/endpoint.json",
                ]:
                    try:
                        rj = await client.get(f"{base_url}{jcr_path}", timeout=3)
                        if rj.status_code == 200:
                            body = rj.text.lower()
                            if any(k in body for k in jcr_keys + ['graphql', 'endpoint']):
                                return True
                    except Exception:
                        pass

                for probe_url in extra_path_probes:
                    try:
                        rp = await client.get(probe_url, timeout=3)
                        if rp.status_code != 200:
                            continue
                        body = rp.text.lower()
                        content_type = rp.headers.get("content-type", "").lower()
                        if any(k in body for k in jcr_keys) and ("json" in content_type or body.startswith("{")):
                            return True
                        if any(ind in body for ind in aem_indicators):
                            return True
                    except Exception:
                        pass
        except Exception:
            continue
    return False

async def validate_cpanel(target_or_scan_address, port, timeout=5):
    """
    Validates if cPanel / WHM / Webmail / cpdavd is running on the given
    address:port. Honours full-URL inputs the same way validate_aem does.
    Returns True if any cPanel daemon fingerprint matches, False otherwise.
    """
    scan_address, supplied_origin, supplied_url, supplied_path = _extract_aem_validation_context(target_or_scan_address, port)
    protocols = ['https', 'http']

    # Strong fingerprint markers that appear in cpsrvd / cpdavd responses.
    cpanel_indicators = [
        'cpsrvd', 'cpanel', 'webhost manager', 'whm', 'paper_lantern',
        'jupiter', 'cpsess', 'cpanelbranding', 'cpanel_magic_revision',
        'cpaneld', 'webmaild', 'cpdavd', 'cpanellgd',
    ]
    header_markers = ['cpsrvd', 'cpanel']

    candidate_bases = []
    if supplied_origin:
        candidate_bases.append(supplied_origin.rstrip('/'))
    for protocol in protocols:
        candidate = f"{protocol}://{scan_address}:{port}"
        if candidate not in candidate_bases:
            candidate_bases.append(candidate)

    paths = [
        "/",
        "/login/",
        "/cgi-sys/defaultwebpage.cgi",
        "/unprotected/redirect.html",
        "/cpanelbranding/",
        "/webmail/",
        "/json-api/cpanel?cpanel_jsonapi_apiversion=2&cpanel_jsonapi_module=Branding&cpanel_jsonapi_func=spritelist",
    ]

    for base_url in candidate_bases:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
                for path in paths:
                    try:
                        r = await client.get(f"{base_url}{path}")
                    except Exception:
                        continue

                    server_hdr = r.headers.get("server", "").lower()
                    powered_hdr = r.headers.get("x-powered-by", "").lower()
                    if any(m in server_hdr for m in header_markers):
                        return True
                    if any(m in powered_hdr for m in header_markers):
                        return True
                    # cPanel-specific custom headers
                    for hdr in r.headers:
                        if hdr.lower().startswith("x-cpanel"):
                            return True

                    if r.status_code in (200, 301, 302, 401, 403):
                        body = (r.text or "")[:8192].lower()
                        if any(ind in body for ind in cpanel_indicators):
                            return True
                        # cPanel-specific Location redirector
                        loc = r.headers.get("location", "").lower()
                        if any(ind in loc for ind in ("cpsess", "/login/", "cpanel")):
                            return True
        except Exception:
            continue
    return False


async def validate_service(service, target_or_scan_address, port):
    """
    Validates if a specific service is running on the given address:port.
    Returns True if the service is detected, False otherwise.
    """
    validators = {
        'elasticsearch': validate_elasticsearch,
        'kibana': validate_kibana,
        'grafana': validate_grafana,
        'prometheus': validate_prometheus,
        'nextjs': validate_nextjs,
        'aem': validate_aem,
        'cpanel': validate_cpanel,
    }

    validator = validators.get(service)
    if validator:
        if service in ('aem', 'cpanel'):
            return await validator(target_or_scan_address, port)
        return await validator(_extract_scan_address(target_or_scan_address), port)
    return False
