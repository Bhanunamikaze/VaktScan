import asyncio
import socket
import ipaddress


def normalize_host_value(host_value):
    """Normalize a host or URL-like value down to a hostname/IP token."""
    host_value = (host_value or "").strip().lower()
    if not host_value:
        return ""
    if "://" in host_value:
        host_value = host_value.split("://", 1)[1]
    if "/" in host_value:
        host_value = host_value.split("/", 1)[0]
    if host_value.startswith("[") and "]" in host_value:
        closing = host_value.find("]")
        remainder = host_value[closing + 1:]
        if remainder.startswith(":") and remainder[1:].isdigit():
            return host_value[1:closing]
        return host_value[1:closing]
    if host_value.count(":") == 1 and host_value.split(":")[1].isdigit():
        host_value = host_value.split(":")[0]
    return host_value


def collect_domain_hosts(host_iterable):
    """Return normalized hostnames while excluding raw IP addresses."""
    domains = set()
    for host_value in host_iterable:
        candidate = normalize_host_value(host_value)
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
            continue
        except ValueError:
            pass
        if "." not in candidate:
            continue
        domains.add(candidate)
    return sorted(domains)


def format_url(scheme, host_value, port_value):
    """Format a URL while omitting the default port for the chosen scheme."""
    default_port = 80 if scheme == "http" else 443
    suffix = "" if port_value == default_port else f":{port_value}"
    return f"{scheme}://{host_value}{suffix}"


def build_default_http_probe_urls(host_iterable):
    """Build explicit http/https probe URLs for every hostname."""
    probe_urls = set()
    for host in collect_domain_hosts(host_iterable):
        probe_urls.add(format_url("http", host, 80))
        probe_urls.add(format_url("https", host, 443))
    return sorted(probe_urls)


def build_web_probe_urls(host_iterable, ports):
    """Build http/https probe URLs across a specific list of ports."""
    probe_urls = set()
    for host in collect_domain_hosts(host_iterable):
        for port in ports:
            # We don't try to guess http vs https per port because some custom 
            # ports might run HTTPS. Tools like httpx handle fallback gracefully.
            probe_urls.add(format_url("http", host, port))
            probe_urls.add(format_url("https", host, port))
    return sorted(probe_urls)


def build_port_scan_probe_urls(port_scan_results, ip_to_hosts=None):
    """
    Expand discovered web ports across every hostname that maps to the same IP.
    """
    ip_to_hosts = ip_to_hosts or {}
    probe_urls = set()

    for target_obj, data in port_scan_results:
        open_ports = sorted(set(data.get("open_ports", [])))
        if not open_ports:
            continue

        ip = normalize_host_value(target_obj.get("resolved_ip") or target_obj.get("scan_address"))
        candidate_hosts = set(ip_to_hosts.get(ip, []))

        fallback_host = normalize_host_value(
            target_obj.get("display_target") or target_obj.get("scan_address")
        )
        if fallback_host:
            try:
                ipaddress.ip_address(fallback_host)
            except ValueError:
                if "." in fallback_host:
                    candidate_hosts.add(fallback_host)

        for port in open_ports:
            for scheme in ("http", "https"):
                for host in sorted(candidate_hosts):
                    probe_urls.add(format_url(scheme, host, port))
                if ip:
                    probe_urls.add(format_url(scheme, ip, port))

    return sorted(probe_urls)


def build_recon_probe_urls(host_iterable, port_scan_results, ip_to_hosts=None):
    """
    Combine hostname-first default probes with port-scan-expanded probes.
    """
    return sorted(
        set(build_default_http_probe_urls(host_iterable))
        | set(build_port_scan_probe_urls(port_scan_results, ip_to_hosts))
    )


async def resolve_hostnames(hostnames):
    """
    Resolve hostnames and return hostname/IP lookup maps for shared-IP recon flows.
    """
    normalized_hosts = []
    seen = set()

    for host in hostnames:
        candidate = normalize_host_value(host)
        if not candidate or candidate in seen:
            continue
        try:
            ipaddress.ip_address(candidate)
            continue
        except ValueError:
            pass
        seen.add(candidate)
        normalized_hosts.append(candidate)

    if not normalized_hosts:
        return {}, {}, []

    resolution_tasks = [resolve_hostname(host) for host in normalized_hosts]
    resolved_results = await asyncio.gather(*resolution_tasks)

    host_to_ip = {}
    ip_to_hosts = {}
    unresolved_hosts = []

    for hostname, resolved_ip in zip(normalized_hosts, resolved_results):
        if not resolved_ip:
            unresolved_hosts.append(hostname)
            continue
        host_to_ip[hostname] = resolved_ip
        ip_to_hosts.setdefault(resolved_ip, []).append(hostname)

    for hosts in ip_to_hosts.values():
        hosts.sort()

    return host_to_ip, ip_to_hosts, unresolved_hosts


def build_scan_targets_from_mappings(raw_targets, host_to_ip):
    """
    Build deduplicated scan targets while preserving hostname/IP attribution.
    """
    scan_targets = []
    processed_ips = set()

    for target in raw_targets:
        candidate = normalize_host_value(target)
        if not candidate:
            continue

        try:
            ip_addr = str(ipaddress.ip_address(candidate))
            if ip_addr in processed_ips:
                continue
            scan_targets.append({
                "scan_address": ip_addr,
                "display_target": ip_addr,
                "resolved_ip": ip_addr,
            })
            processed_ips.add(ip_addr)
            continue
        except ValueError:
            pass

        resolved_ip = host_to_ip.get(candidate)
        if not resolved_ip or resolved_ip in processed_ips:
            continue

        scan_targets.append({
            "scan_address": candidate,
            "display_target": candidate,
            "resolved_ip": resolved_ip,
        })
        scan_targets.append({
            "scan_address": resolved_ip,
            "display_target": candidate,
            "resolved_ip": resolved_ip,
        })
        processed_ips.add(resolved_ip)

    return scan_targets

def get_service_ports():
    """Returns a dictionary of services and their common ports."""
    return {
        "elasticsearch": [9200, 9300],
        "kibana": [5601],
        "grafana": [3000, 3003],
        "prometheus": [9090, 9100, 9101, 9102, 9103, 9104],
        "nextjs": [3000, 80, 443, 8080],
        "aem": [4502, 4503, 80, 443, 8080, 8443],
        "web": [
            80, 81, 443, 444, 591, 593, 832,
            981, 1010, 1311, 2082, 2083, 2086, 2087,
            2095, 2096, 2375, 2376, 2379, 2380,
            2480, 3000, 3001, 3128, 3333,
            4243, 4443, 4567, 4711, 4712, 4993, 5000, 5104, 5108,
            5800, 5900, 5985, 5986, 6080, 6443,
            7000, 7071, 7080, 7443, 7777, 7779,
            8000, 8008, 8010, 8011, 8012, 8014, 8042, 8069,
            8080, 8081, 8083, 8087, 8088, 8090, 8095, 8096, 8100,
            8181, 8200, 8222, 8243, 8280, 8281, 8333, 8337,
            8443, 8444, 8463, 8500, 8543, 8585, 8600, 8649,
            8800, 8880, 8888, 8983, 9000, 9001, 9002, 9003, 9004, 9006, 9009,
            9043, 9080, 9081, 9090, 9091, 9092, 9093,
            9100, 9110, 9191, 9200, 9443, 9485, 9711,
            9800, 9850, 9898, 9900, 9943, 9966,
            9999, 10000, 10001, 10250
        ]
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
