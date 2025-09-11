import asyncio
import socket
import ipaddress
from urllib.parse import urlparse

def get_service_ports():
    """Returns a dictionary of services and their common ports."""
    return {
        "elasticsearch": [9200, 9300],
        "kibana": [5601],
        "grafana": [3000,3003],
        "prometheus": [9090, 9100,9101,9102,9103,9104] # Includes node_exporter and other common exporters
    }

async def resolve_hostname(hostname):
    """Asynchronously resolves a hostname to an IP address."""
    try:
        # Use asyncio's event loop to perform DNS resolution without blocking
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(hostname, None)
        # Return the first IPv4 address found
        for family, socktype, proto, canonname, sockaddr in addr_info:
            if family == socket.AF_INET:
                return sockaddr[0]
        return None
    except socket.gaierror:
        return None

async def process_targets(raw_targets):
    """
    Processes a list of raw target strings into a set of unique IP addresses.
    Handles IPs, hostnames, and CIDR subnets.
    """
    unique_ips = set()
    resolution_tasks = []

    for target in raw_targets:
        if not target or target.startswith('#'):
            continue
        
        # Check if it's a CIDR notation
        try:
            network = ipaddress.ip_network(target, strict=False)
            for ip in network.hosts():
                unique_ips.add(str(ip))
            # Also add the network address itself if it's a single IP like /32
            if network.num_addresses == 1:
                 unique_ips.add(str(network.network_address))
            continue
        except ValueError:
            pass # Not a valid CIDR, proceed to next checks

        # Check if it's a valid IP address
        try:
            ipaddress.ip_address(target)
            unique_ips.add(target)
            continue
        except ValueError:
            pass # Not a valid IP, assume it's a hostname

        # If not CIDR or IP, assume it's a hostname and schedule for resolution
        resolution_tasks.append(resolve_hostname(target))

    resolved_ips = await asyncio.gather(*resolution_tasks)
    for ip in resolved_ips:
        if ip:
            unique_ips.add(ip)

    return list(unique_ips)
