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

async def process_targets_streaming(raw_targets, chunk_size=30000):
    """
    Processes targets in streaming fashion to avoid memory exhaustion.
    Yields chunks of exactly chunk_size IPs (except the last chunk).
    """
    print(f"[*] Processing targets with chunk size: {chunk_size:,}")
    
    current_chunk = []
    total_processed = 0
    resolution_tasks = []
    
    for target in raw_targets:
        if not target or target.startswith('#'):
            continue
        
        # Check if it's a CIDR notation
        try:
            network = ipaddress.ip_network(target, strict=False)
            network_size = network.num_addresses
            
            # Warn for large networks but process them
            if network_size > 65536:  # Warn for /15 and larger
                print(f"[*] Processing very large network {target} ({network_size:,} IPs)")
            elif network_size > 8192:  # Warn for /19 and larger
                print(f"[*] Processing large network {target} ({network_size:,} IPs)")
            
            # Add all IPs from this network to our current chunk, yielding full chunks as needed
            for ip in network.hosts():
                current_chunk.append(str(ip))
                total_processed += 1
                
                # Yield when we hit the chunk size
                if len(current_chunk) >= chunk_size:
                    yield current_chunk
                    current_chunk = []
            
            # Handle single IP networks (like /32)
            if network.num_addresses == 1:
                current_chunk.append(str(network.network_address))
                total_processed += 1
                
                if len(current_chunk) >= chunk_size:
                    yield current_chunk
                    current_chunk = []
            continue
            
        except ValueError:
            pass # Not a valid CIDR, proceed to next checks

        # Check if it's a valid IP address
        try:
            ipaddress.ip_address(target)
            current_chunk.append(target)
            total_processed += 1
            if len(current_chunk) >= chunk_size:
                yield current_chunk
                current_chunk = []
            continue
        except ValueError:
            pass # Not a valid IP, assume it's a hostname

        # If not CIDR or IP, assume it's a hostname and schedule for resolution
        resolution_tasks.append(resolve_hostname(target))
    
    # Process any remaining hostnames
    if resolution_tasks:
        print(f"[*] Resolving {len(resolution_tasks)} hostnames...")
        resolved_ips = await asyncio.gather(*resolution_tasks)
        for ip in resolved_ips:
            if ip:
                current_chunk.append(ip)
                total_processed += 1
                if len(current_chunk) >= chunk_size:
                    yield current_chunk
                    current_chunk = []
    
    # Yield any remaining IPs in the final chunk
    if current_chunk:
        yield current_chunk
    
    print(f"[+] Total IPs processed: {total_processed:,}")

async def process_targets(raw_targets):
    """
    Legacy function for backward compatibility.
    Now uses streaming processing with safety limits.
    """
    all_ips = set()
    total_count = 0
    
    async for ip_chunk in process_targets_streaming(raw_targets, chunk_size=1000):
        all_ips.update(ip_chunk)
        total_count += len(ip_chunk)
        
        # Safety limit to prevent system freeze
        if total_count > 50000:
            print(f"[!] Hit safety limit of 50,000 IPs. Use streaming mode for larger scans.")
            break
    
    return list(all_ips)
