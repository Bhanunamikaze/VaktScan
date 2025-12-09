import asyncio
import socket
import ipaddress
from urllib.parse import urlparse

def get_service_ports():
    """Returns a dictionary of services and their common ports."""
    return {
        "elasticsearch": [9200, 9300],
        "kibana": [5601],
        "grafana": [3000, 3003],
        "prometheus": [9090, 9100, 9101, 9102, 9103, 9104],
        "nextjs": [3000, 80, 443, 8080] # Common ports for Next.js applications (React_To_Shell)
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
    Processes targets in a streaming fashion.
    Yields chunks of target objects, where each object contains:
    - 'scan_address': The address to scan (hostname or IP).
    - 'display_target': The original target for reporting.
    - 'resolved_ip': The resolved IP for state management.
    """
    print(f"[*] Processing targets with chunk size: {chunk_size:,}")

    current_chunk = []
    total_processed = 0
    processed_ips = set()
    hostname_targets = []

    for target in raw_targets:
        if not target or target.startswith('#'):
            continue

        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses > 65536:
                print(f"[*] Processing very large network {target} ({network.num_addresses:,} IPs)")

            for ip in network.hosts():
                ip_str = str(ip)
                if ip_str not in processed_ips:
                    current_chunk.append({
                        "scan_address": ip_str,
                        "display_target": ip_str,
                        "resolved_ip": ip_str
                    })
                    processed_ips.add(ip_str)
                    total_processed += 1
                    if len(current_chunk) >= chunk_size:
                        yield current_chunk
                        current_chunk = []
            continue
        except ValueError:
            pass

        try:
            ip_addr = ipaddress.ip_address(target)
            ip_str = str(ip_addr)
            if ip_str not in processed_ips:
                current_chunk.append({
                    "scan_address": ip_str,
                    "display_target": ip_str,
                    "resolved_ip": ip_str
                })
                processed_ips.add(ip_str)
                total_processed += 1
                if len(current_chunk) >= chunk_size:
                    yield current_chunk
                    current_chunk = []
            continue
        except ValueError:
            hostname_targets.append(target)

    if hostname_targets:
        print(f"[*] Resolving {len(hostname_targets)} hostnames...")
        resolution_tasks = [resolve_hostname(h) for h in hostname_targets]
        resolved_results = await asyncio.gather(*resolution_tasks)

        unresolved_count = 0
        for hostname, resolved_ip in zip(hostname_targets, resolved_results):
            if resolved_ip and resolved_ip not in processed_ips:
                # Add target object for the hostname
                current_chunk.append({
                    "scan_address": hostname,
                    "display_target": hostname,
                    "resolved_ip": resolved_ip
                })
                total_processed += 1

                # Add target object for the resolved IP
                current_chunk.append({
                    "scan_address": resolved_ip,
                    "display_target": hostname,
                    "resolved_ip": resolved_ip
                })
                processed_ips.add(resolved_ip)
                total_processed += 1

                if len(current_chunk) >= chunk_size:
                    yield current_chunk
                    current_chunk = []
            elif not resolved_ip:
                unresolved_count += 1
                # print(f"[!] Could not resolve hostname: {hostname}")
        
        if unresolved_count > 0:
            print(f"[!] Could not resolve {unresolved_count} hostnames.")

    if current_chunk:
        yield current_chunk

    print(f"[+] Total scan targets generated: {total_processed:,}")


async def process_targets(raw_targets):
    """
    Processes a list of targets (hostnames, IPs, CIDRs) and returns a list of target objects.
    Each object contains 'scan_address', 'display_target', and 'resolved_ip'.
    """
    all_targets = []
    total_count = 0
    
    async for target_chunk in process_targets_streaming(raw_targets, chunk_size=1000):
        all_targets.extend(target_chunk)
        total_count += len(target_chunk)
        
        # Safety limit
        if total_count > 50000:
            print(f"[!] Hit safety limit of 50,000 targets. Use streaming mode for larger scans.")
            break
            
    return all_targets