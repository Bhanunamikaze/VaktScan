import asyncio
import sys
import os

# Add vendor directory to Python path for httpx
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'vendor'))

import httpx

async def validate_elasticsearch(ip, port, timeout=5):
    """
    Validates if Elasticsearch is running on the given IP:port.
    Checks both HTTP and HTTPS protocols.
    Returns True if Elasticsearch is detected, False otherwise.
    """
    protocols = ['http', 'https']
    
    for protocol in protocols:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                # Try root endpoint
                response = await client.get(f"{protocol}://{ip}:{port}/")
                if response.status_code == 200:
                    content = response.text.lower()
                    if '"cluster_name"' in content or '"tagline"' in content and 'elasticsearch' in content:
                        return True
                
                # Try _cluster/health endpoint
                response = await client.get(f"{protocol}://{ip}:{port}/_cluster/health")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'cluster_name' in content or 'status' in content:
                        return True
        except:
            continue
    return False

async def validate_kibana(ip, port, timeout=5):
    """
    Validates if Kibana is running on the given IP:port.
    Checks both HTTP and HTTPS protocols.
    Returns True if Kibana is detected, False otherwise.
    """
    protocols = ['http', 'https']
    
    for protocol in protocols:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                # Try main Kibana page
                response = await client.get(f"{protocol}://{ip}:{port}/")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'kibana' in content or 'elastic' in content:
                        return True
                
                # Try API status endpoint
                response = await client.get(f"{protocol}://{ip}:{port}/api/status")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'kibana' in content or 'version' in content:
                        return True
                
                # Try app/kibana endpoint
                response = await client.get(f"{protocol}://{ip}:{port}/app/kibana")
                if response.status_code in [200, 302]:
                    return True
        except:
            continue
    return False

async def validate_grafana(ip, port, timeout=5):
    """
    Validates if Grafana is running on the given IP:port.
    Checks both HTTP and HTTPS protocols.
    Returns True if Grafana is detected, False otherwise.
    """
    protocols = ['http', 'https']
    
    for protocol in protocols:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                # Try main Grafana page
                response = await client.get(f"{protocol}://{ip}:{port}/")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'grafana' in content:
                        return True
                
                # Try login page
                response = await client.get(f"{protocol}://{ip}:{port}/login")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'grafana' in content:
                        return True
                
                # Try API health endpoint
                response = await client.get(f"{protocol}://{ip}:{port}/api/health")
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

async def validate_prometheus(ip, port, timeout=5):
    """
    Validates if Prometheus is running on the given IP:port.
    Checks both HTTP and HTTPS protocols.
    Returns True if Prometheus is detected, False otherwise.
    """
    protocols = ['http', 'https']
    
    for protocol in protocols:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                # Try main Prometheus page
                response = await client.get(f"{protocol}://{ip}:{port}/")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'prometheus' in content:
                        return True
                
                # Try metrics endpoint
                response = await client.get(f"{protocol}://{ip}:{port}/metrics")
                if response.status_code == 200:
                    content = response.text
                    if 'prometheus_' in content or 'TYPE' in content:
                        return True
                
                # Try API query endpoint
                response = await client.get(f"{protocol}://{ip}:{port}/api/v1/query?query=up")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'resulttype' in content or 'metric' in content:
                        return True
                
                # Try graph endpoint
                response = await client.get(f"{protocol}://{ip}:{port}/graph")
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'prometheus' in content:
                        return True
        except:
            continue
    return False

async def validate_service(service, ip, port):
    """
    Validates if a specific service is running on the given IP:port.
    Returns True if the service is detected, False otherwise.
    """
    validators = {
        'elasticsearch': validate_elasticsearch,
        'kibana': validate_kibana,
        'grafana': validate_grafana,
        'prometheus': validate_prometheus
    }
    
    validator = validators.get(service)
    if validator:
        return await validator(ip, port)
    return False