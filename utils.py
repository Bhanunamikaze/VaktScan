import asyncio
import socket
import ipaddress
import re
import urllib.parse


def _normalize_target_token(raw: str) -> str:
    """
    Normalize a single target token to a clean hostname/IP/CIDR string.

    Handles:
    - URL schemas (http://, https://, ftp://) → strip schema
    - URL paths (/path/to/resource) → strip path
    - URL ports in URLs (https://host:8443/path) → returns 'host' (port discovered by scanner)
    - IPv6 brackets [::1] → ::1
    - Trailing dots on domains (example.com.) → example.com
    - Whitespace, null bytes
    """
    t = raw.strip().strip('\x00')
    if not t:
        return ''
    # Strip schema
    if '://' in t:
        parsed = urllib.parse.urlparse(t)
        t = parsed.hostname or ''
        if not t:
            return ''
    # Strip path (anything after first /)
    if '/' in t and not t.startswith('['):
        # But preserve IPv6 CIDRs like 2001:db8::/32
        if ':' not in t.split('/')[0]:
            t = t.split('/')[0]
    # Strip port suffix from non-CIDR entries: host:port
    # IPv6: [::1]:8080 or ::1 (no colon-port strip)
    if t.startswith('['):
        # Bracketed IPv6: [::1] or [::1]:8080
        t = t.lstrip('[').split(']')[0]
    elif ':' in t:
        # Could be IPv6 (multiple colons) or host:port (single colon)
        parts = t.split(':')
        if len(parts) == 2:
            # host:port — strip the port
            t = parts[0]
        # else IPv6 address — keep as-is
    # Strip trailing dot (FQDN notation)
    t = t.rstrip('.')
    return t.lower().strip()


def is_valid_domain(domain: str) -> bool:
    """
    Validate if a domain name is structured correctly for public DNS/recon.
    A valid domain must:
    - Not be empty
    - Contain at least one dot ('.') separating labels
    - Not start or end with a dot or hyphen
    - Not contain consecutive dots (e.g., '..')
    - Only contain alphanumeric characters, dots, and hyphens (and underscores, though rare on root domains)
    - Not be a local domain (like 'localhost' or ending in '.local')
    - Not be a raw IP address
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return False
    
    # Exclude localhost or local domain suffixes
    if domain == "localhost" or domain.endswith(".local") or domain.endswith(".internal"):
        return False

    # Check for at least one dot
    if "." not in domain:
        return False

    # Check for starting/ending with dots or hyphens
    if domain.startswith(".") or domain.endswith(".") or domain.startswith("-") or domain.endswith("-"):
        return False

    # Check for consecutive dots
    if ".." in domain:
        return False

    # Check for invalid characters
    import re
    if not re.match(r"^[a-z0-9\-_\.]+$", domain):
        return False

    # Exclude IP addresses
    import ipaddress
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass

    # Each label must be between 1 and 63 characters
    labels = domain.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False

    return True


def parse_targets_file(filepath: str) -> list:
    """
    Robustly parse a targets file into a deduplicated list of clean target strings.

    Handles:
    - UTF-8 BOM, latin-1 fallback, null bytes, binary garbage
    - Windows (\\r\\n), old Mac (\\r), Unix (\\n) line endings
    - Full-line comments (# ...) and inline comments (target # comment)
    - Empty and whitespace-only lines
    - URL schemas (http://, https://) → extract hostname
    - URL paths and ports → extract hostname only
    - Comma-separated targets on one line: 192.168.1.1,192.168.1.2
    - Tab-separated targets on one line
    - Multiple spaces between targets on one line
    - IPv4, IPv4 CIDR, IPv6, IPv6 CIDR, domains, subdomains
    - IPv6 bracket notation [::1]
    - Trailing dots on FQDNs (example.com.)
    - Duplicate entries (preserved order, first occurrence wins)
    """
    try:
        try:
            with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as fh:
                content = fh.read()
        except OSError:
            return []
    except Exception:
        return []

    seen = set()
    results = []

    for raw_line in re.split(r'\r\n|\r|\n', content):
        # Strip whitespace
        line = raw_line.strip()
        if not line:
            continue
        # Strip full-line comments
        if line.startswith('#'):
            continue
        # Strip inline comments: keep everything before the first ' #' or '\t#'
        for sep in (' #', '\t#'):
            idx = line.find(sep)
            if idx != -1:
                line = line[:idx].strip()
        if not line:
            continue
        # Split on commas or tabs to handle multiple targets per line
        # Also split on whitespace runs IF neither token looks like it needs spaces
        tokens = re.split(r'[,\t]+', line)
        if len(tokens) == 1:
            # No comma/tab — try splitting on whitespace only if it produces
            # valid-looking tokens (avoids splitting "sub domain.com" incorrectly)
            ws_tokens = line.split()
            if len(ws_tokens) > 1:
                # Validate each ws_token looks like a target before using them
                all_look_like_targets = all(
                    re.match(r'^[\w\.\-\:\[\]/]+$', t) for t in ws_tokens
                )
                if all_look_like_targets:
                    tokens = ws_tokens

        for raw_token in tokens:
            t = _normalize_target_token(raw_token)
            if not t:
                continue
            # Skip obviously invalid tokens (single chars, pure punctuation)
            if len(t) < 2:
                continue
            if t not in seen:
                seen.add(t)
                results.append(t)

    return results


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
        "cpanel": [
            2077, 2078, 2079, 2080,    # cpdavd (WebDisk / CalDAV / CardDAV)
            2082, 2083,                # cPanel user
            2086, 2087,                # WHM root/reseller
            2089,                      # cPanel autoconfig
            2095, 2096,                # Webmail
            9998, 9999,                # alt cpsrvd listeners
            80, 443,                   # Apache fronting (/cpanel, /whm, etc.)
        ],
        "cpanel_adjacent": [
            25, 26, 465, 587,          # Exim SMTP
            110, 143, 993, 995,        # Dovecot IMAP/POP3
            21,                        # FTP (Pure-FTPd / ProFTPD)
            53,                        # DNS (BIND / PowerDNS)
            3306,                      # MySQL / MariaDB
            5432,                      # PostgreSQL
            22,                        # OpenSSH
            2768,                      # Mailman
            783,                       # spamd
            1097, 2812,                # tailwatchd / queueprocd
            8053,                      # PowerDNS web UI
            953,                       # BIND control / dnsadmin
        ],
        "jenkins": [8080, 8090, 8443, 8888],
        "service_recon": [
            # FTP / SSH / SMTP / DNS / Kerberos / RPC / NTP
            21, 22, 25, 53, 88, 111, 123, 135,
            # SMB / SNMP / LDAP
            139, 161, 389, 445, 465, 587, 593, 636,
            # Rsync / VMware / Java RMI / MSSQL / Oracle / NFS / ZooKeeper / Docker
            623, 873, 902, 1098, 1099, 1433, 1521, 2049, 2181, 2375, 2376,
            # etcd / Loki / MySQL / RDP / OpenTelemetry gRPC+HTTP / GlassFish / PostgreSQL
            2379, 2380, 3100, 3306, 3389, 4317, 4318, 4848, 5432,
            # AMQP / VNC / CouchDB / WinRM
            5671, 5672, 5900, 5901, 5984, 5985, 5986,
            # Redis / K8s / WebLogic / Splunk / Spring Actuator
            6379, 6443, 7001, 7002, 8000, 8009,
            # Spring Actuator / Nexus / Artifactory / Hadoop YARN / Splunk REST
            8080, 8081, 8082, 8088, 8089, 8090,
            # TeamCity / Vault / Spring Actuator TLS / Consul
            8111, 8200, 8443, 8500, 8501,
            # Jolokia / Jupyter / Solr / SonarQube / MinIO / Kafka / Alertmanager
            8778, 8888, 8889, 8983, 9000, 9001, 9042, 9092, 9093,
            # Cassandra / Zipkin / Portainer TLS / Hadoop HDFS / JBoss
            9160, 9411, 9443, 9870, 9990,
            # Kubelet / Zabbix Server / Envoy Admin / RabbitMQ Management / Jaeger
            10051, 10250, 11211, 15000, 15001, 15672, 16686,
            # MongoDB / Hadoop HDFS Legacy / ActiveMQ
            27017, 50070, 55679, 61616,
        ],
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
    """Asynchronously resolves a hostname to an IP address (IPv4 or IPv6)."""
    try:
        # Use asyncio's event loop to perform DNS resolution without blocking
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(hostname, None)
        # Return the first IPv4 address found, falling back to IPv6
        ipv4_addr = None
        ipv6_addr = None
        for family, socktype, proto, canonname, sockaddr in addr_info:
            if family == socket.AF_INET and not ipv4_addr:
                ipv4_addr = sockaddr[0]
            elif family == socket.AF_INET6 and not ipv6_addr:
                ipv6_addr = sockaddr[0]
        # Prefer IPv4 for backward compatibility, but fall back to IPv6 if available
        return ipv4_addr if ipv4_addr else ipv6_addr
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
        import urllib.parse
        print(f"[*] Resolving {len(hostname_targets)} hostnames/URLs...")
        
        actual_hostnames = []
        for h in hostname_targets:
            if h.startswith(('http://', 'https://')):
                parsed = urllib.parse.urlparse(h)
                actual_hostnames.append(parsed.hostname or h)
            else:
                actual_hostnames.append(h)

        resolution_tasks = [resolve_hostname(h) for h in actual_hostnames]
        resolved_results = await asyncio.gather(*resolution_tasks)

        unresolved_count = 0
        for original_target, actual_host, resolved_ip in zip(hostname_targets, actual_hostnames, resolved_results):
            if resolved_ip:
                is_url = original_target.startswith(('http://', 'https://'))
                
                if is_url or resolved_ip not in processed_ips:
                    # Add target object for the original target (hostname or URL)
                    current_chunk.append({
                        "scan_address": original_target,
                        "display_target": original_target,
                        "resolved_ip": resolved_ip
                    })
                    total_processed += 1

                    # Add target object for the resolved IP (only if not a URL)
                    if not is_url:
                        current_chunk.append({
                            "scan_address": resolved_ip,
                            "display_target": original_target,
                            "resolved_ip": resolved_ip
                        })
                    
                    processed_ips.add(resolved_ip)

                    if len(current_chunk) >= chunk_size:
                        yield current_chunk
                        current_chunk = []
            elif not resolved_ip:
                unresolved_count += 1
                # print(f"[!] Could not resolve hostname: {actual_host}")
        
        if unresolved_count > 0:
            print(f"[!] Could not resolve {unresolved_count} hostnames/URLs.")

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
