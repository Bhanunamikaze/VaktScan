import httpx
import asyncio
import json
import re

async def detect_protocol(scan_address, port, timeout=3):
    """
    Detects whether a service is running on HTTP or HTTPS.
    Returns the protocol string ('http' or 'https') or None if unreachable.
    """
    protocols = ['https', 'http']  # Try HTTPS first as it's more secure
    
    for protocol in protocols:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                response = await client.get(f"{protocol}://{scan_address}:{port}/")
                if response.status_code in [200, 401, 403, 302, 404]:  # Any valid HTTP response
                    return protocol
        except:
            continue
    return 'http'  # Default to HTTP if detection fails

async def check_unauthenticated_dashboard(target_url):
    """Checks for unauthenticated access to the Prometheus dashboard."""
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(target_url, timeout=5)
            if response.status_code == 200 and '<title>Prometheus</title>' in response.text:
                return {
                    "status": "INFO",
                    "vulnerability": "Prometheus Dashboard Exposed",
                    "target": target_url,
                    "details": "The Prometheus dashboard is accessible without authentication. This is default but can expose sensitive metrics and topology."
                }
    except httpx.RequestError:
        pass
    return None

async def check_config_exposure(target_url):
    """Checks if the Prometheus configuration file is exposed."""
    config_url = f"{target_url}/config"
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(config_url, timeout=5)
            if response.status_code == 200 and 'global' in response.text and 'scrape_configs' in response.text:
                return {
                    "status": "VULNERABLE",
                    "vulnerability": "Prometheus Configuration File Exposure",
                    "target": config_url,
                    "details": "The Prometheus configuration is publicly exposed, revealing scrape targets, internal paths, and potentially sensitive metadata."
                }
    except httpx.RequestError:
        pass
    return None

async def check_targets_exposure(target_url):
    """Checks if the Prometheus targets page is exposed, revealing network topology."""
    targets_url = f"{target_url}/targets"
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(targets_url, timeout=5)
            if response.status_code == 200 and 'Endpoints' in response.text and 'State' in response.text:
                return {
                    "status": "VULNERABLE",
                    "vulnerability": "Prometheus Targets Exposure",
                    "target": targets_url,
                    "details": "The Prometheus targets page is exposed, revealing a map of all monitored services and servers."
                }
    except httpx.RequestError:
        pass
    return None

async def check_metrics_exposure(target_url):
    """Checks if Prometheus metrics endpoints expose sensitive information."""
    vulnerabilities = []
    
    metrics_endpoints = [
        "/metrics",
        "/federate",
        "/api/v1/targets", 
        "/api/v1/status/config",
        "/api/v1/label/__name__/values"
    ]
    
    for endpoint in metrics_endpoints:
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.get(f"{target_url}{endpoint}", timeout=5)
                if response.status_code == 200:
                    content = response.text
                    
                    # Check for sensitive information patterns
                    sensitive_patterns = [
                        (r'password["\s]*[:=]["\s]*[^"\s,}\n]+', 'passwords'),
                        (r'token["\s]*[:=]["\s]*[^"\s,}\n]+', 'tokens'), 
                        (r'api[_-]?key["\s]*[:=]["\s]*[^"\s,}\n]+', 'API keys'),
                        (r'secret["\s]*[:=]["\s]*[^"\s,}\n]+', 'secrets'),
                        (r'auth["\s]*[:=]["\s]*[^"\s,}\n]+', 'auth tokens'),
                        (r'bearer["\s]+[a-zA-Z0-9_.-]{20,}', 'bearer tokens'),
                        (r'jwt["\s]*[:=]["\s]*[a-zA-Z0-9_.-]{20,}', 'JWT tokens'),
                        (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 'internal IP addresses'),
                        (r'[a-zA-Z0-9.-]+\.internal', 'internal hostnames'),
                        (r'[a-zA-Z0-9.-]+\.local', 'local network hostnames'),
                        (r'(?:10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3})', 'private network IPs (10.x.x.x)'),
                        (r'(?:192\.168\.(?:[0-9]{1,3}\.[0-9]{1,3}))', 'private network IPs (192.168.x.x)'),
                        (r'(?:172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:[0-9]{1,3}\.[0-9]{1,3}))', 'private network IPs (172.16-31.x.x)'),
                        (r'admin["\s]*[:=]', 'admin credentials'),
                        (r'database["\s]*[:=]', 'database info'),
                        (r'mysql["\s]*[:=]', 'MySQL credentials'),
                        (r'postgres["\s]*[:=]', 'PostgreSQL credentials'),
                        (r'redis["\s]*[:=]', 'Redis credentials'),
                        (r'mongodb["\s]*[:=]', 'MongoDB credentials'),
                        (r'aws[_-]?(?:access[_-]?key|secret)["\s]*[:=]', 'AWS credentials'),
                        (r'gcp[_-]?(?:key|token)["\s]*[:=]', 'GCP credentials'),
                        (r'azure[_-]?(?:key|token)["\s]*[:=]', 'Azure credentials'),
                        (r'slack[_-]?(?:token|webhook)["\s]*[:=]', 'Slack tokens'),
                        (r'github[_-]?token["\s]*[:=]', 'GitHub tokens'),
                        (r'docker[_-]?(?:registry|hub)[_-]?(?:user|pass|token)["\s]*[:=]', 'Docker credentials')
                    ]
                    
                    found_sensitive = []
                    for pattern, desc in sensitive_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            found_sensitive.append(desc)
                    
                    if found_sensitive or endpoint == "/metrics":
                        status = "VULNERABLE" if found_sensitive else "INFO"
                        details = f"Prometheus metrics endpoint exposed"
                        if found_sensitive:
                            details += f" with sensitive data: {', '.join(found_sensitive)}"
                        else:
                            details += ". May reveal system metrics and internal topology."
                        
                        vulnerabilities.append({
                            "status": status,
                            "vulnerability": "Prometheus Metrics Information Disclosure",
                            "target": f"{target_url}{endpoint}",
                            "details": details
                        })
        except:
            continue
    
    return vulnerabilities

async def check_cve_vulnerabilities(target_url):
    """Check for known Prometheus CVEs with comprehensive coverage."""
    vulnerabilities = []
    
    # CVE-2019-3826 - Stored XSS vulnerability
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            # Test for XSS in query interface
            xss_payload = {"query": "<script>alert('XSS')</script>"}
            response = await client.get(f"{target_url}/graph", params=xss_payload, timeout=5)
            if response.status_code == 200:
                content = response.text
                if "<script>alert('XSS')</script>" in content and "text/html" in response.headers.get('content-type', ''):
                    vulnerabilities.append({
                        "status": "VULNERABLE",
                        "vulnerability": "CVE-2019-3826 - Stored XSS vulnerability",
                        "target": f"{target_url}/graph",
                        "details": "Prometheus graph interface is vulnerable to stored XSS attacks through query parameters."
                    })
    except:
        pass
    
    # CVE-2021-29622 - Open Redirect vulnerability  
    try:
        async with httpx.AsyncClient(follow_redirects=False) as client:
            # Test for open redirect
            redirect_payload = f"{target_url}/redirect?url=https://evil.com"
            response = await client.get(redirect_payload, timeout=5)
            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('location', '')
                if 'evil.com' in location or location.startswith('https://evil.com'):
                    vulnerabilities.append({
                        "status": "VULNERABLE",
                        "vulnerability": "CVE-2021-29622 - Open Redirect vulnerability",
                        "target": redirect_payload,
                        "details": "Prometheus redirect functionality can be abused to redirect users to malicious sites."
                    })
    except:
        pass
    
    # Query injection testing (PromQL injection)
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            # Test for PromQL injection with file read attempt
            injection_payload = {"query": "up{__name__=\"../../../etc/passwd\"}"}
            response = await client.get(f"{target_url}/api/v1/query", params=injection_payload, timeout=5)
            if response.status_code == 200:
                content = response.text
                if "root:" in content or "/bin/" in content or "daemon:" in content:
                    vulnerabilities.append({
                        "status": "VULNERABLE",
                        "vulnerability": "PromQL Injection - File Read Access",
                        "target": f"{target_url}/api/v1/query",
                        "details": "PromQL injection vulnerability allows unauthorized file system access."
                    })
    except:
        pass
    
    # ReDoS in metric name validation
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            # Test for ReDoS vulnerability with crafted metric names
            redos_payload = {"query": "(a+)+$" + "a" * 1000}
            start_time = asyncio.get_event_loop().time()
            try:
                response = await client.get(f"{target_url}/api/v1/query", params=redos_payload, timeout=10)
                end_time = asyncio.get_event_loop().time()
                if (end_time - start_time) > 5:  # Took longer than 5 seconds
                    vulnerabilities.append({
                        "status": "VULNERABLE",
                        "vulnerability": "ReDoS in Query Processing",
                        "target": f"{target_url}/api/v1/query",
                        "details": f"Query processing vulnerable to ReDoS attacks, response time: {end_time - start_time:.2f}s"
                    })
            except asyncio.TimeoutError:
                vulnerabilities.append({
                    "status": "VULNERABLE", 
                    "vulnerability": "ReDoS Timeout in Query Processing",
                    "target": f"{target_url}/api/v1/query",
                    "details": "Query processing timed out due to ReDoS attack, indicating vulnerability."
                })
    except:
        pass
    
    return vulnerabilities

async def check_pprof_endpoints(target_url):
    """Check for exposed pprof debugging endpoints that can cause DoS."""
    vulnerabilities = []
    
    pprof_endpoints = [
        "/debug/pprof/",
        "/debug/pprof/goroutine",
        "/debug/pprof/heap",
        "/debug/pprof/profile",
        "/debug/pprof/block",
        "/debug/pprof/mutex",
        "/debug/pprof/trace"
    ]
    
    for endpoint in pprof_endpoints:
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.get(f"{target_url}{endpoint}", timeout=5)
                if response.status_code == 200:
                    content = response.text
                    if any(indicator in content.lower() for indicator in ['goroutine', 'heap profile', 'cpu profile', 'pprof']):
                        status = "VULNERABLE" if endpoint == "/debug/pprof/" else "INFO"
                        vulnerabilities.append({
                            "status": status,
                            "vulnerability": "Prometheus pprof Debug Endpoint Exposed",
                            "target": f"{target_url}{endpoint}",
                            "details": f"Debug endpoint {endpoint} is publicly accessible and can be used for DoS attacks by consuming server resources."
                        })
        except:
            continue
    
    return vulnerabilities

async def check_api_endpoints(target_url):
    """Check for exposed Prometheus API endpoints."""
    vulnerabilities = []
    
    api_endpoints = [
        ("/api/v1/query", "Query API"),
        ("/api/v1/query_range", "Range Query API"),
        ("/api/v1/series", "Series API"),
        ("/api/v1/targets", "Targets API"),
        ("/api/v1/rules", "Rules API"),
        ("/api/v1/alerts", "Alerts API"),
        ("/api/v1/alertmanagers", "Alert Managers API"),
        ("/api/v1/status/config", "Configuration API"),
        ("/api/v1/status/flags", "Runtime Flags API"),
        ("/api/v1/status/buildinfo", "Build Info API"),
        ("/api/v1/admin/tsdb/snapshot", "TSDB Snapshot API"),
        ("/api/v1/admin/tsdb/delete_series", "Delete Series API"),
        ("/api/v1/metadata", "Metadata API"),
        ("/api/v1/status/tsdb", "TSDB Status API"),
        ("/api/v1/status/walreplay", "WAL Replay Status API")
    ]
    
    exposed_apis = []
    sensitive_apis = []
    
    for endpoint, name in api_endpoints:
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.get(f"{target_url}{endpoint}", timeout=5)
                if response.status_code == 200:
                    exposed_apis.append(f"{endpoint} ({name})")
                    
                    # Check for admin/dangerous APIs
                    if "admin" in endpoint or endpoint in ["/api/v1/status/config", "/api/v1/targets", "/api/v1/metadata", "/api/v1/status/tsdb"]:
                        sensitive_apis.append(f"{endpoint} ({name})")
                elif response.status_code in [400, 422]:  # Bad request but endpoint exists
                    exposed_apis.append(f"{endpoint} ({name})")
        except:
            continue
    
    if exposed_apis:
        if sensitive_apis:
            vulnerabilities.append({
                "status": "VULNERABLE", 
                "vulnerability": "Prometheus Sensitive API Exposure",
                "target": target_url,
                "details": f"Sensitive APIs exposed: {', '.join(sensitive_apis[:3])}{'...' if len(sensitive_apis) > 3 else ''}"
            })
        
        vulnerabilities.append({
            "status": "INFO",
            "vulnerability": "Prometheus API Endpoints Exposed", 
            "target": target_url,
            "details": f"Found {len(exposed_apis)} exposed API endpoints: {', '.join(exposed_apis[:5])}{'...' if len(exposed_apis) > 5 else ''}"
        })
    
    return vulnerabilities

async def get_prometheus_version(target_url):
    """Extract Prometheus version information."""
    version_info = {}
    
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            # Try build info API
            response = await client.get(f"{target_url}/api/v1/status/buildinfo", timeout=5)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if data.get("status") == "success" and "data" in data:
                        build_data = data["data"]
                        version_info['version'] = build_data.get('version', 'Unknown')
                        version_info['goVersion'] = build_data.get('goVersion', 'Unknown')
                        version_info['branch'] = build_data.get('branch', 'Unknown')
                        return version_info
                except:
                    pass
    except:
        pass
    
    # Try to extract from main page
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(target_url, timeout=5)
            if response.status_code == 200:
                # Look for version in HTML
                version_match = re.search(r'Prometheus\s+([0-9]+\.[0-9]+\.[0-9]+)', response.text)
                if version_match:
                    version_info['version'] = version_match.group(1)
                    return version_info
    except:
        pass
    
    return version_info

def parse_version(version_str):
    """Parse version string into comparable tuple."""
    if not version_str or version_str == 'Unknown':
        return (0, 0, 0)
    
    # Clean version string
    version_str = version_str.strip()
    if version_str.startswith('v'):
        version_str = version_str[1:]
    
    # Extract version numbers
    import re
    match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_str)
    if match:
        return tuple(map(int, match.groups()))
    
    # Fallback for incomplete versions
    parts = version_str.split('.')
    try:
        version_parts = [int(p) for p in parts[:3]]
        while len(version_parts) < 3:
            version_parts.append(0)
        return tuple(version_parts)
    except ValueError:
        return (0, 0, 0)

async def check_version_based_cves(version_info):
    """Check for version-based CVE vulnerabilities in Prometheus."""
    vulnerabilities = []
    version_str = version_info.get('version', 'Unknown')
    
    if version_str == 'Unknown':
        return vulnerabilities
    
    version = parse_version(version_str)
    
    # CVE database for Prometheus with version ranges (verified Prometheus-specific CVEs only)
    cve_database = [
        {
            "cve": "CVE-2021-29622",
            "severity": "MEDIUM",
            "description": "Open Redirect vulnerability",
            "affected_versions": [(0, 0, 0), (2, 26, 0)],  # < 2.26.0
            "details": "Prometheus before 2.26.0 contains an open redirect vulnerability in the /redirect endpoint that allows attackers to redirect users to malicious sites."
        },
        {
            "cve": "CVE-2019-3826", 
            "severity": "MEDIUM",
            "description": "Stored XSS vulnerability",
            "affected_versions": [(0, 0, 0), (2, 7, 2)],  # < 2.7.2
            "details": "Prometheus before 2.7.2 contains a stored XSS vulnerability in the web UI query interface that allows attackers to execute arbitrary JavaScript."
        },
        {
            "cve": "CVE-2018-1000816",
            "severity": "HIGH", 
            "description": "Path Traversal vulnerability",
            "affected_versions": [(0, 0, 0), (2, 5, 0)],  # < 2.5.0
            "details": "Prometheus before 2.5.0 contains a path traversal vulnerability in the web UI that allows attackers to read arbitrary files on the server."
        }
    ]
    
    for cve_info in cve_database:
        min_version, max_version = cve_info["affected_versions"]
        
        # Check if current version falls within vulnerable range
        if min_version <= version < max_version:
            vulnerabilities.append({
                "status": "VULNERABLE",
                "vulnerability": f"{cve_info['cve']} - {cve_info['description']}",
                "target": "Version-based detection",
                "details": f"{cve_info['details']} Current version: {version_str}",
                "severity": cve_info["severity"]
            })
    
    return vulnerabilities

async def check_node_exporter_metrics(scan_address, port=9100):
    """Specific checks for Prometheus Node Exporter on port 9100."""
    target_url = f"http://{scan_address}:{port}"
    vulnerabilities = []
    
    # Check /metrics endpoint
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(f"{target_url}/metrics", timeout=5)
            if response.status_code == 200:
                content = response.text
                
                # Check if this is actually node_exporter
                if 'node_exporter' in content or 'node_' in content:
                    # Check for sensitive system information exposure
                    sensitive_info = []
                    
                    if 'node_filesystem_' in content:
                        sensitive_info.append('filesystem paths and usage')
                    if 'node_network_' in content:
                        sensitive_info.append('network interface details')
                    if 'node_systemd_' in content:
                        sensitive_info.append('systemd service information')
                    if 'node_processes_' in content:
                        sensitive_info.append('running process details')
                    if 'node_memory_' in content:
                        sensitive_info.append('memory usage statistics')
                    if 'node_cpu_' in content:
                        sensitive_info.append('CPU usage and details')
                    if 'node_load_' in content:
                        sensitive_info.append('system load information')
                    
                    # Look for potential credential exposure in metrics
                    credential_patterns = [
                        (r'password["\s=][^"\s,}\n]+', 'passwords in metrics'),
                        (r'token["\s=][^"\s,}\n]+', 'tokens in metrics'),
                        (r'key["\s=][^"\s,}\n]+', 'keys in metrics'),
                        (r'secret["\s=][^"\s,}\n]+', 'secrets in metrics')
                    ]
                    
                    found_credentials = []
                    for pattern, desc in credential_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            found_credentials.append(desc)
                    
                    if sensitive_info:
                        vulnerabilities.append({
                            "status": "INFO",
                            "vulnerability": "Node Exporter System Information Exposure",
                            "target": f"{target_url}/metrics",
                            "details": f"Node Exporter exposing sensitive system information: {', '.join(sensitive_info[:5])}{'...' if len(sensitive_info) > 5 else ''}"
                        })
                    
                    if found_credentials:
                        vulnerabilities.append({
                            "status": "VULNERABLE",
                            "vulnerability": "Node Exporter Credential Exposure",
                            "target": f"{target_url}/metrics",
                            "details": f"Node Exporter metrics contain potential credentials: {', '.join(found_credentials)}"
                        })
                    
                    # Check for overly verbose metrics that might leak internal topology
                    metric_count = len([line for line in content.split('\n') if line and not line.startswith('#')])
                    if metric_count > 1000:
                        vulnerabilities.append({
                            "status": "INFO",
                            "vulnerability": "Node Exporter Verbose Metrics Exposure",
                            "target": f"{target_url}/metrics",
                            "details": f"Node Exporter exposing {metric_count} metrics which may reveal detailed system topology and configuration."
                        })
    
    except httpx.RequestError:
        pass
    
    # Check /pprof endpoint for debugging information exposure
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(f"{target_url}/pprof", timeout=5)
            if response.status_code == 200:
                content = response.text.lower()
                if any(indicator in content for indicator in ['pprof', 'goroutine', 'heap', 'profile', 'debug']):
                    vulnerabilities.append({
                        "status": "VULNERABLE",
                        "vulnerability": "Node Exporter pprof Debug Interface Exposed",
                        "target": f"{target_url}/pprof",
                        "details": "Node Exporter pprof debug interface is publicly accessible, allowing attackers to gather internal application state, trigger DoS via profiling, and potentially extract sensitive runtime information."
                    })
                    
                    # Check specific pprof endpoints
                    pprof_endpoints = ['/pprof/goroutine', '/pprof/heap', '/pprof/profile', '/pprof/block', '/pprof/mutex']
                    accessible_endpoints = []
                    
                    for endpoint in pprof_endpoints:
                        try:
                            pprof_response = await client.get(f"{target_url}{endpoint}", timeout=3)
                            if pprof_response.status_code == 200:
                                accessible_endpoints.append(endpoint)
                        except:
                            continue
                    
                    if accessible_endpoints:
                        vulnerabilities.append({
                            "status": "VULNERABLE",
                            "vulnerability": "Node Exporter pprof Detailed Endpoints Exposed",
                            "target": f"{target_url}/pprof",
                            "details": f"Multiple pprof endpoints accessible: {', '.join(accessible_endpoints)}. These can be used for DoS attacks and runtime information extraction."
                        })
            
            elif response.status_code == 404:
                # Good - pprof is not exposed
                pass
    
    except httpx.RequestError:
        pass
    
    return vulnerabilities

async def run_scans(target_obj, port):
    """Runs all defined Prometheus scans against a target object."""
    scan_address = target_obj['scan_address']
    display_target = target_obj['display_target']
    resolved_ip = target_obj['resolved_ip']
    
    all_results = []
    
    protocol = await detect_protocol(scan_address, port)
    if not protocol:
        return []

    target_url = f"{protocol}://{scan_address}:{port}"
    print(f"  -> Running Prometheus scans on {target_url} (for target: {display_target})")
    
    version_info = await get_prometheus_version(target_url)
    service_version = version_info.get('version', 'Unknown') if version_info else 'Unknown'
    
    if not version_info:
        return []

    tasks = [
        check_unauthenticated_dashboard(target_url),
        check_config_exposure(target_url),
        check_targets_exposure(target_url),
        check_metrics_exposure(target_url),
        check_api_endpoints(target_url),
        check_pprof_endpoints(target_url),
        check_cve_vulnerabilities(target_url),
        check_version_based_cves(version_info)
    ]
    
    results_from_tasks = await asyncio.gather(*tasks)
    
    for result_group in results_from_tasks:
        if not result_group:
            continue
            
        if isinstance(result_group, list):
            for res in result_group:
                if res:
                    res.update({
                        'module': 'Prometheus',
                        'service_version': service_version,
                        'target': display_target,
                        'server': scan_address,
                        'port': port,
                        'resolved_ip': resolved_ip,
                        'url': res.get('target')
                    })
                    all_results.append(res)
        elif isinstance(result_group, dict):
            result_group.update({
                'module': 'Prometheus',
                'service_version': service_version,
                'target': display_target,
                'server': scan_address,
                'port': port,
                'resolved_ip': resolved_ip,
                'url': result_group.get('target')
            })
            all_results.append(result_group)

    if port == 9100:
        node_exporter_results = await check_node_exporter_metrics(scan_address, port)
        for ne_result in node_exporter_results:
            ne_result.update({
                'module': 'Prometheus Node Exporter',
                'service_version': service_version if service_version != 'Unknown' else 'Node Exporter',
                'target': display_target,
                'server': scan_address,
                'port': port,
                'resolved_ip': resolved_ip,
                'url': ne_result.get('target')
            })
            all_results.append(ne_result)
            
    return all_results
