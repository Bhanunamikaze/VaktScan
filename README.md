# VaktScan - Attack Surface Mapper & Vulnerability Scanner

> **VaktScan** (*pronounced "vahkt-scan"*) - Named after the Nordic word "vakt" meaning "guard" or "watch", representing the vigilant nature of security monitoring.

An advanced, high-performance attack surface mapper and vulnerability scanner designed for comprehensive security assessment of infrastructure, web services, and domains. VaktScan provides enterprise-grade scanning capabilities with concurrent processing, extensive CVE coverage, and can efficiently scan millions of IP addresses using intelligent streaming technology.


## Features

### Comprehensive Attack Surface Coverage
- **Full-Port Scanning**: Every scan automatically covers all service-specific ports plus 100+ web ports and 79 service_recon port mappings. No configuration needed — `python main.py targets.txt` runs everything.
- **Discovery & Mapping**: Passive recon (amass, subfinder, findomain, assetfinder, bbot, knockpy, censys, crt.sh) inside a first-class `-m recon` module. Includes active VHost fuzzing (ffuf) and directory busting (dirsearch), with an automatic httpx → dirsearch → nuclei chain when `--scan-found` is set.
- **Domain Validation & Fingerprinting (`-m domain-scan`)**: Classifies internal vs. external domains, detects default/parked pages, identifies broken frontend components (4xx/5xx on sub-resources), and probes for anomalies (CORS, missing headers, open redirects, 5xx bodies, size mismatches). 58-signature subdomain takeover detection covering GitHub Pages, AWS S3, Heroku, Shopify, Fastly, CloudFront, Webflow, Vercel, Netlify, Azure, Tilda, Read the Docs, Statuspage, Acquia, Zendesk, WP Engine, and more.
- **JavaScript Analysis (`-m js-paths`)**: Deep parsing of JS files using 12+ extraction strategies. Detects hardcoded secrets, exposed source maps, internal IPs, and probes extracted endpoints.
- **DNS Attack Surface (`-m dns`)**: Pure-stdlib wire-format DNS module. Per-domain: A/AAAA/MX/NS/TXT/SOA/CAA/DNSKEY, SPF policy classification (`+all`, `?all`, multi-record), DMARC `p=none` detection, DKIM probing across 16 common selectors, CAA absence, DNSSEC missing flag. Per-nameserver: AXFR zone transfer (CRITICAL on success), open-recursion test, `version.bind` CHAOS TXT banner.
- **cPanel/WHM/Webmail (`-m cpanel`)**: Full oracle-validated CVE suite, anti-FP baselining, WAF/cPHulk detection, bundled-component CVE matrix, and co-resident service banner checks.
- **Web Checks (automatic on all alive URLs)**: HTTP security headers audit, sensitive file exposure (.git/HEAD, .env, phpinfo, wp-config), GraphQL introspection, Swagger/OpenAPI spec exposure, SSL certificate expiry, admin panel detection, directory listing, default CMS credentials.
- **Service Recon (automatic on 79 port mappings)**: 30+ service-specific checks covering the full infrastructure stack from FTP to Kubernetes — see the full list below.

### Advanced Vulnerability Detection
- **Smart Deduplication**: When the same vulnerability is found on both a hostname and its resolved IP, it is deduplicated and reported against the hostname for cleaner, actionable output.
- **Dual Protocol Testing**: All service modules automatically test both HTTP and HTTPS for complete coverage, with graceful fallback when one protocol is unavailable.
- **Version-Based Detection**: Custom version parsing and vulnerability mapping without external CVE database dependencies.
- **Severity Classification**: CRITICAL, HIGH, MEDIUM risk categorization with detailed descriptions and CVE identifiers.
- **Active Payload Testing**: Exploitation attempts for vulnerability confirmation where applicable.
- **Bundled CVE Data**: Pre-built `modules/data/bundled_cves.json` and `modules/data/cpanel_tsr.json` for offline operation.

### High-Performance Architecture
- **Dual Hostname & IP Scanning**: When a hostname is provided, VaktScan intelligently scans both the hostname and its resolved IP for complete coverage.
- **Concurrent DNS Resolution**: All hostnames are resolved concurrently at startup, minimizing initialization time for large target sets.
- **Multi-target Support**: IPs, hostnames, domains, and CIDR subnets accepted in any combination.
- **Asyncio Concurrency**: Configurable up to 2000+ concurrent connections.
- **Streaming Technology**: Memory-efficient scanning of millions of IPs using intelligent 30k-IP chunks.
- **Resumable Scans**: 2-minute checkpoint intervals with chunk-level progress tracking — resume interrupted scans without restarting from scratch.
- **Real-time Progress**: Live scanning progress with ETA, rate calculations, and overall completion status.

### Professional Reporting
- **Vulnerability CSV**: Always saved automatically after every scan — no flag required.
- **Port Scan CSV**: Saved automatically after every port scan.
- **Web Probe Results**: Saved to `recon_results/web_probe_<target>_<ts>/`.
- **Nuclei Results**: Saved to the output directory per scan.
- **httpx CSV**: Saved per scan session.


## Project Structure
```
VaktScan/
├── main.py                      # Main orchestrator and CLI interface
├── utils.py                     # Target processing utilities (IPs, domains, CIDR)
├── port_scanner.py              # High-concurrency port scanner with progress tracking
├── service_validator.py         # Service fingerprinting and validation
├── scan_state.py                # State management for resumable scans
├── requirements.sh              # Install script for all 40+ external tools
├── targets.txt                  # Example targets file
├── modules/                     # Service-specific vulnerability scanners
│   ├── __init__.py
│   ├── elastic.py               # Elasticsearch scanner (11+ CVEs)
│   ├── kibana.py                # Kibana scanner (4 CVEs + API testing)
│   ├── grafana.py               # Grafana scanner (18+ CVEs)
│   ├── prometheus.py            # Prometheus scanner (3 CVEs + metrics analysis)
│   ├── react_to_shell.py        # Next.js/React RCE scanner (CVE-2025-55182)
│   ├── aem.py                   # Adobe AEM scanner (CRXDE, Sling, JCR)
│   ├── cpanel.py                # cPanel/WHM/Webmail full attack surface
│   ├── dns_recon.py             # DNS attack surface module
│   ├── domain_scan.py           # HTTP validation, classification, takeover detection
│   ├── js_paths.py              # JavaScript analysis and endpoint extraction
│   ├── service_recon.py         # 30+ service checks across 79 port mappings
│   ├── web_checks.py            # Web security checks on all alive URLs
│   ├── recon.py                 # Passive subdomain enumeration orchestrator
│   ├── dir_enum.py              # Directory busting (dirsearch)
│   ├── httpx_runner.py          # ProjectDiscovery httpx integration
│   ├── nuclei_runner.py         # ProjectDiscovery nuclei integration
│   ├── nmap_runner.py           # Nmap deep scan integration
│   ├── gau_runner.py            # GAU URL harvesting integration
│   ├── waybackurls_runner.py    # Wayback Machine URL harvesting
│   └── data/
│       ├── bundled_cves.json    # Pre-built CVE data for offline operation
│       └── cpanel_tsr.json      # cPanel TSR vulnerability matrix
├── scripts/
│   ├── setup_recon_tools.py     # Tool checker/installer
│   ├── build_bundled_cves.py    # Rebuild bundled CVE data
│   ├── build_cpanel_tsr.py      # Rebuild cPanel TSR data
│   └── verify_cpanel_coverage.py # Verify cPanel CVE coverage
└── tests/
    ├── test_cpanel_dedup.py
    ├── test_cpanel_extra_checks.py
    ├── test_cpanel_oracles.py
    ├── test_cpanel_reporting.py
    ├── test_dns_recon.py
    ├── test_domain_scan_takeover.py
    ├── test_httpx_runner.py
    ├── test_js_paths.py
    ├── test_port_scanner.py
    └── test_recon_utils.py
```


## Requirements

- **Python**: 3.8+ (tested on 3.8, 3.9, 3.10, 3.11)
- **Core dependency**: `httpx` bundled in `vendor/` (no system install needed)
- **External tools**: Install all 40+ tools with `bash requirements.sh`
- **Memory**: ~50 MB RAM per 1000 concurrent connections; streaming mode uses minimal memory regardless of target count
- **Network**: Raw socket access for port scanning


## Installation

```bash
git clone https://github.com/Bhanunamikaze/VaktScan.git
cd VaktScan

# Install Python httpx dependency
pip install httpx --target=./vendor

# Install all external tools (amass, subfinder, httpx, nuclei, ffuf, nmap, etc.)
bash requirements.sh
```

The `requirements.sh` script installs all 40+ external binaries. You can also use the Python helper to check or selectively install tools:

```bash
# View install status of all tools
python scripts/setup_recon_tools.py

# Install all missing tools
python scripts/setup_recon_tools.py --install

# Install specific tools only
python scripts/setup_recon_tools.py --install --tools amass ffuf httpx nuclei
```


## Quick Start

### 1. Create Targets File
```
# Single IPs
192.168.1.100
10.0.0.5

# Hostnames
grafana.company.com
kibana.internal.net

# CIDR subnets
192.168.0.0/24
10.0.0.0/16

# URLs (protocol and port extracted automatically)
http://monitoring.example.com:3000
https://logs.company.com:5601
```

### 2. Run Scanner

```bash
# Full scan — port scan ALL ports, service checks, web probe, nuclei, web_checks
# CSV output is automatic, no flag needed
python main.py targets.txt

# High-concurrency scan
python main.py targets.txt -c 1000

# Resume an interrupted scan
python main.py targets.txt --resume

# Scan specific service only
python main.py targets.txt -m elasticsearch
python main.py targets.txt -m grafana
python main.py targets.txt -m cpanel

# Add extra ports to the scan
python main.py targets.txt -p 8080,8443,9999

# Passive subdomain recon → httpx → dirsearch → nuclei
python main.py -m recon --recon-domain target.com --scan-found

# Recon multiple domains concurrently
python main.py -m recon --recon-domain target.com api.target.com --scan-found

# Recon with VHost fuzzing wordlist
python main.py -m recon --recon-domain target.com --wordlist wordlist.txt --scan-found

# Probe an existing subdomain list directly (skip passive recon)
python main.py --sub-domains subs.txt

# Domain validation, classification, and takeover detection
python main.py -m domain-scan --sub-domains subs.txt

# cPanel / WHM / Webmail attack surface
python main.py targets.txt -m cpanel
python main.py -m cpanel --sub-domains subs.txt

# DNS attack surface (SPF/DMARC/DKIM/AXFR/recursion/CAA/DNSSEC)
python main.py -m dns --sub-domains domains.txt
python main.py -m dns --recon-domain target.com

# JavaScript analysis and endpoint extraction
python main.py -m js-paths --url https://example.com
python main.py -m js-paths --ds-file subs.txt -c 30 --js-timeout 15

# Full nmap deep scan on recon findings
python main.py -m recon --recon-domain target.com --nmap

# Large-scale scan with custom chunk size
python main.py targets.txt -c 1000 --chunk-size 25000
```


## CLI Reference

```
python main.py [targets_file] [OPTIONS]

Positional:
  targets_file            File with IPs, hostnames, domains, CIDRs, or URLs
                          (omit when using -m recon or --sub-domains alone)

Options:
  -c, --concurrency INT   Concurrency level (default: 100, max: 2000)
  -m, --module MODULE     Limit to a specific module or scan mode:
                            elasticsearch | kibana | grafana | prometheus |
                            nextjs | aem | cpanel | recon | domain-scan |
                            dns | js-paths
  -p, --ports PORTS       Extra comma-separated ports to include
  --url URL               Single target URL (used with -m js-paths)
  --js-timeout SECS       Request timeout for js-paths module
  --sub-domains FILE      Newline-separated subdomain/host list; feeds
                          domain-scan, dns, js-paths, and web probing
  --ds-file FILE          Alias for --sub-domains (used with js-paths)
  --recon-domain DOMAIN   Domain(s) for passive recon/VHost fuzzing
  --wordlist PATH         Wordlist for ffuf VHost fuzzing during recon
  --scan-found            After recon, auto-run httpx → dirsearch → nuclei
  --nmap                  Run full 1-65535 port scan + nmap -sCV -Pn on results
  --chunk-size INT        IPs per streaming chunk (default: 30000)
  --resume                Resume a previously interrupted scan
  -h, --help              Show help

Streaming Mode:
  Automatically enabled for target sets with 30,000+ IP addresses.
  Processes targets in memory-efficient chunks with checkpoint-based resume.
```


## Sample Output

```
[*] Starting VaktScan - Nordic Security Scanner...
[*] Parsing targets from targets.txt...
[+] Successfully resolved 1,250 unique IP addresses.
[*] Starting concurrent port scan for 1,250 IPs across all service ports...
[*] Progress: 8,750/10,000 (87.5%) | Rate: 892.3 scans/sec | ETA: 1s
[*] Port scanning completed. Found 45 open ports across 12 services.
[*] Validated 12 service(s). Starting vulnerability assessment...
  -> Running Elasticsearch scans on http://192.168.1.100:9200
  -> Running Grafana scans on http://192.168.1.102:3000
  -> Running service_recon on 192.168.1.103:6379 (Redis)
  -> Running web_checks on https://192.168.1.104:443

[CRITICAL] CVE-2021-44228 - Log4Shell RCE | http://192.168.1.100:9200
[CRITICAL] Redis unauthenticated INFO + CONFIG GET | http://192.168.1.103:6379
[HIGH]     CVE-2018-17246 - Kibana File Read | http://192.168.1.101:5601
[CRITICAL] .git/HEAD exposed | https://192.168.1.104:443
[VULNERABLE] Grafana Default Credentials (admin:admin) | http://192.168.1.102:3000

[+] Scan completed. Found 12 vulnerabilities across 3 severity levels.
[+] Vulnerability results saved to scan_results_20260101_143022.csv
[+] Port scan results saved to portscan_results_20260101_143022.csv
```


## Vulnerability Coverage

### Service Modules (run automatically when port is found open)

#### Elasticsearch (11+ CVEs)
- **CVE-2021-44228** — Log4Shell RCE (CRITICAL)
- **CVE-2015-1427** — Groovy Sandbox Bypass RCE
- **CVE-2014-3120** — Dynamic Scripting RCE
- **CVE-2024-23450** — Document processing DoS
- Plus 7 additional CVEs: authentication bypass, privilege escalation, information disclosure

#### Kibana (4 CVEs + API Testing)
- **CVE-2018-17246** — Local File Inclusion (CRITICAL)
- **CVE-2019-7609** — Timelion RCE (CRITICAL)
- **CVE-2019-7608** — Cross-Site Scripting
- **CVE-2021-22137** — Information Disclosure
- Plus comprehensive API endpoint enumeration

#### Grafana (18+ CVEs)
- **CVE-2024-9264** — SQL Expressions RCE (CRITICAL)
- **CVE-2021-43798** — Path Traversal File Access
- **CVE-2020-13379** — SSRF via Avatar Endpoint
- **CVE-2022-32276** — Unauthenticated Snapshot Access
- Plus 14 additional CVEs: XSS, authentication bypass, privilege escalation

#### Prometheus (3 CVEs + Metrics Analysis)
- **CVE-2021-29622** — Open Redirect
- **CVE-2019-3826** — Stored XSS
- **CVE-2018-1000816** — Path Traversal
- Plus metrics endpoint analysis, target enumeration, Node Exporter, pprof exposure

#### Next.js / React (CVE-2025-55182)
- react-to-shell RCE and associated supply chain checks on ports 3000, 80, 443, 8080

#### Adobe AEM (ports 4502, 4503, 80, 443, 8080, 8443)
- CRXDE Lite exposure, Sling servlet enumeration, JCR content exposure

#### cPanel / WHM / Webmail (ports 2077–2096, 9998–9999, 80, 443)
- **CVE-2023-29489**, **CVE-2022-44762/3**, **CVE-2019-11680**, **CVE-2021-38583** — oracle-validated, version-anchored checks
- Bundled-component matrix: Apache `mod_rewrite` (CVE-2024-38476/7), PHP CGI (CVE-2024-4577), Roundcube (CVE-2024-37383), WHMCS (CVE-2024-25602), Horde RCE (CVE-2022-30287), AWStats, phpMyAdmin, Softaculous, Mailman, ownCloud (CVE-2023-49103), OpenSSL Heartbleed
- Co-resident banners: Exim 21Nails, Dovecot, ProFTPD, OpenSSH regreSSHion
- PROXY-protocol misconfig, HTTP/2 ALPN, SSI execution, HTTP request smuggling, branding-upload exposure
- Anti-FP post-filter: stock-error baselining, WAF/cPHulk detection, content-type sanity, length-delta thresholding, TSR deduplication
- Aggressive credential probe opt-in via `VAKTSCAN_AGGRESSIVE_CPANEL=1`

### service_recon Module (runs automatically on 79 port mappings)

| Service | Port(s) | Check |
|---|---|---|
| FTP | 21 | Anonymous login |
| SSH | 22 | Banner + ssh-audit weak config |
| SMTP | 25, 465, 587 | VRFY user enum + smtp-user-enum |
| DNS | 53 | Zone transfer + dnsrecon |
| Kerberos | 88 | KDC detection |
| RPC | 111, 135, 593 | rpcinfo + null session |
| NTP | 123 | nmap ntp-info |
| SMB | 139, 445 | smbmap + smbclient + enum4linux |
| SNMP | 161 | Community "public" snmpwalk + snmp-check |
| LDAP | 389, 636 | Anonymous bind |
| Rsync | 873 | Unauthenticated listing |
| VMware ESXi | 902 | Interface detection |
| MSSQL | 1433 | Detection + impacket |
| Oracle | 1521 | TNS + tnscmd10g |
| NFS | 2049 | showmount exports |
| Docker API | 2375, 2376 | Unauthenticated /version /containers /images /info |
| etcd / Kubernetes | 2379, 2380 | Unauthenticated member list + secrets dump |
| ZooKeeper | 2181 | ruok/stat/dump TCP |
| MySQL | 3306 | Unauthenticated root |
| Loki | 3100 | Unauthenticated log query |
| RDP | 3389 | Detection + rdp-sec-check |
| GlassFish | 4848 | admin:(empty) |
| PostgreSQL | 5432 | Unauthenticated postgres |
| AMQP / ActiveMQ | 5671, 5672, 61616 | Default admin:admin |
| VNC | 5900, 5901 | RFB banner |
| CouchDB | 5984 | Unauthenticated / + _all_dbs + _users |
| WinRM | 5985, 5986 | Detection |
| Kubernetes API | 6443 | Unauthenticated /api/v1/pods + namespaces |
| Redis | 6379 | Unauthenticated INFO + CONFIG GET |
| WebLogic | 7001, 7002 | CVE-2020-14882 path traversal |
| AJP / Ghostcat | 8009 | CVE-2020-1938 probe |
| Jenkins | 8080 | Unauthenticated API + script console RCE + user enum |
| Spring Boot Actuator | 8080, 8081, 8443 | /actuator/heapdump (CRITICAL), /actuator/env (CRITICAL) |
| Apache Tomcat | 8080, 8443 | /manager/html default credentials |
| Traefik | 8080 | /api/rawdata (CRITICAL) |
| HashiCorp Consul | 8500, 8501 | Unauthenticated KV store + catalog |
| Jolokia JMX | 8778 | Unauthenticated MBeans + SystemProperties |
| Apache Solr | 8983 | Unauthenticated admin cores |
| Jupyter Notebook | 8888, 8889 | Unauthenticated /api/kernels RCE |
| Hadoop YARN | 8088 | Unauthenticated ResourceManager RCE |
| HashiCorp Vault | 8200 | Unauthenticated /v1/sys/mounts |
| MinIO | 9000, 9001 | Default minioadmin:minioadmin |
| Portainer | 9000, 9443 | Default credentials (CRITICAL) |
| SonarQube | 9000 | Default admin:admin |
| Alertmanager | 9093 | Unauthenticated alert API |
| Kafka | 9092 | Banner detection |
| JBoss / WildFly | 9990 | Unauthenticated /management |
| Nexus Repository | 8081 | Default credentials |
| Artifactory | 8081, 8082 | Default credentials |
| TeamCity | 8111 | CVE-2024-27198 auth bypass RCE |
| RabbitMQ Management | 15672 | guest:guest (CRITICAL) |
| Memcached | 11211 | Unauthenticated stats |
| Splunk | 8000, 8089 | Default admin:changeme |
| Hadoop HDFS | 50070, 9870 | Unauthenticated NameNode |
| Cassandra | 9042, 9160 | Unauthenticated cqlsh |
| MongoDB | 27017 | Unauthenticated listDatabases |
| IPMI | 623 | Cipher-0 bypass CVE-2013-4786 |
| Kubelet | 10250 | Unauthenticated /pods |
| Istio / Envoy Admin | 15000, 15001 | /config_dump (CRITICAL) |
| Zipkin | 9411 | Unauthenticated /api/v2/services |
| Jaeger | 16686 | Unauthenticated /api/services |

### web_checks Module (runs on all alive HTTP/HTTPS URLs)

- HTTP security headers audit: HSTS, CSP, X-Frame-Options, server version banner
- Sensitive file exposure: `.git/HEAD` (CRITICAL), `.env` (CRITICAL), `phpinfo`, `wp-config`, backup files
- GraphQL introspection (CRITICAL if `__schema` exposed)
- Swagger/OpenAPI spec exposure (HIGH)
- SSL certificate expiry (CRITICAL if expired or <7 days, HIGH if <30 days, MEDIUM if self-signed)
- Admin panel detection (12 common paths)
- Directory listing enabled
- Default credentials for WordPress, Joomla, and Drupal


## Development & Extension

### Adding a New Service Scanner

1. Create `modules/newservice.py` with an async `run_scans(ip, port)` function that tests both HTTP and HTTPS.
2. Register its ports in `utils.py` → `get_service_ports()`.
3. Import and wire it into `main.py`'s scanner delegation logic.

### Rebuilding Bundled Data

```bash
# Rebuild offline CVE bundle
python scripts/build_bundled_cves.py

# Rebuild cPanel TSR matrix
python scripts/build_cpanel_tsr.py

# Verify cPanel CVE coverage
python scripts/verify_cpanel_coverage.py
```

### Running Tests

```bash
python -m pytest tests/
```


## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.


## Disclaimer

VaktScan is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have explicit permission to scan target systems. Unauthorized scanning of systems you do not own or have permission to test is illegal and unethical.
