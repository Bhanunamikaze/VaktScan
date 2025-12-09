import asyncio
import sys
import os

# Add vendor directory to Python path for httpx
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'vendor'))

import httpx

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

async def validate_service(service, scan_address, port):
    """
    Validates if a specific service is running on the given address:port.
    Returns True if the service is detected, False otherwise.
    """
    validators = {
        'elasticsearch': validate_elasticsearch,
        'kibana': validate_kibana,
        'grafana': validate_grafana,
        'prometheus': validate_prometheus,
        'nextjs': validate_nextjs
    }
    
    validator = validators.get(service)
    if validator:
        return await validator(scan_address, port)
    return False