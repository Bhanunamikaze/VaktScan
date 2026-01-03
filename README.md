# VaktScan - Attack Surface Scanner

> **VaktScan** (*pronounced "vahkt-scan"*) - Named after the Nordic word "vakt" meaning "guard" or "watch", representing the vigilant nature of security monitoring.

An advanced, high-performance security scanner designed for comprehensive vulnerability assessment of monitoring and logging infrastructure stacks. VaktScan provides enterprise-grade scanning capabilities with concurrent processing, extensive CVE coverage, and can efficiently scan millions of IP addresses using intelligent streaming technology.


##  Features

###  Comprehensive Service Coverage
- **Elasticsearch**: 11+ CVEs (2014-2024), version vulnerabilities, authentication bypass, sensitive endpoint exposure
- **Kibana**: CVE testing (CVE-2018-17246, CVE-2019-7609), UI exposure detection, default credentials, API enumeration
- **Grafana**: 18+ CVEs, default credentials, directory traversal, XSS vulnerabilities, comprehensive CVE database
- **Prometheus**: Dashboard exposure, configuration leaks, target enumeration, Node Exporter analysis, pprof endpoints
- **Next.js (React)**: RCE detection for `react-to-shell` (CVE-2025-55182).

###  Advanced Vulnerability Detection
- **Smart Vulnerability Deduplication**: If the same vulnerability is discovered on both a hostname and its corresponding IP, the scanner now treats it as a single finding and reports it against the hostname, providing cleaner and more actionable reports.
- **30+ CVE Database**: Comprehensive vulnerability coverage with payload testing
- **Dual Protocol Support**: Automated HTTP and HTTPS testing for complete coverage
- **Version-Based Detection**: Custom version parsing and vulnerability mapping without external dependencies
- **Severity Classification**: CRITICAL, HIGH, MEDIUM risk categorization with detailed descriptions
- **Active Payload Testing**: Exploitation attempts for vulnerability confirmation
- **Service Validation**: Ensures accurate service identification before scanning

###  High-Performance Architecture
- **Dual Hostname & IP Scanning**: When a hostname is provided as a target, VaktScan now intelligently scans both the hostname and its resolved IP address, ensuring comprehensive coverage.
- **Concurrent DNS Resolution**: The target processing engine has been refactored to resolve all hostnames concurrently, dramatically reducing the initial setup time for scans involving many hostname targets.
- **Multi-target Support**: IPs, hostnames, domains, and CIDR subnets
- **Concurrent Processing**: Asyncio-based high-concurrency scanning (configurable up to 2000+ threads)
- **Streaming Technology**: Memory-efficient scanning of millions of IPs using intelligent chunking (30k IPs per chunk)
- **Smart State Management**: Resume interrupted scans with 2-minute checkpoint intervals and chunk-level progress tracking
- **Real-time Progress**: Live scanning progress with ETA, rate calculations, and overall completion status

###  Professional Reporting
- **CSV Export**: Enterprise-ready reports with timestamps, severity, and detailed findings
- **Structured Output**: Standardized vulnerability format for integration
- **Service Version Detection**: Comprehensive version identification across all services
- **Port and Service Mapping**: Accurate service-to-port correlation

##  Project Structure
```
VaktScan/
├── main.py                 # Main orchestrator and CLI interface
├── utils.py                # Target processing utilities (IPs, domains, CIDR)
├── port_scanner.py         # High-concurrency port scanner with progress tracking
├── service_validator.py    # Service fingerprinting and validation
├── scan_state.py          # State management for resumable scans
├── requirements.txt        # Python dependencies
├── targets.txt            # Example targets file
└── modules/               # Service-specific vulnerability scanners
    ├── __init__.py        # Python package initialization
    ├── elastic.py         # Elasticsearch scanner (11+ CVEs)
    ├── kibana.py          # Kibana scanner (4 CVEs + API testing)
    ├── grafana.py         # Grafana scanner (18+ CVEs)
    ├── prometheus.py      # Prometheus scanner (3 CVEs + metrics analysis)
    └── react_to_shell.py  # Next.js (React) RCE scanner
```

##  Requirements

- **Python**: 3.8+ (tested on 3.8, 3.9, 3.10, 3.11)
- **Dependencies**: All bundled in `vendor/` directory (no external installation required)
- **Memory**: ~50MB RAM per 1000 concurrent connections (streaming mode uses minimal memory regardless of target count)
- **Network**: Raw socket access for port scanning
- **Scalability**: Can scan millions of IP addresses efficiently using streaming chunks

## Recon Module Tooling

The optional recon/HTTP probing helpers (`modules/recon.py`, `modules/dir_enum.py`, `modules/httpx_runner.py`, and `modules/nmap_runner.py`) call out to several third-party binaries such as `amass`, `subfinder`, `assetfinder`, `findomain`, `sublist3r`, `knockpy`, `bbot`, `censys`, `crtsh`, `dirsearch`, `ffuf`, `httpx`, and `nmap`. Use the provided helper to check/install them:

```bash
# View status only
python scripts/setup_recon_tools.py

# Attempt to install every missing binary (requires sudo + Go for ffuf/httpx/assetfinder)
python scripts/setup_recon_tools.py --install

# Limit to specific tools
python scripts/setup_recon_tools.py --install --tools amass ffuf httpx bbot
```

The script mirrors the setup flow used by the Xeref project and reports installation commands you can run manually if you prefer tight control over your environment.

##  Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/Bhanunamikaze/VaktScan.git
cd VaktScan
pip install httpx --target=./vendor
```

### 2. Create Targets File
Create `targets.txt` with your scan targets:
```bash
# Comments start with #
192.168.1.100
scanme.nmap.org
10.0.0.0/24
grafana.example.com
kibana.internal.com
```

### 3. Run Scanner
```bash
# Basic scan (auto-detects streaming mode for large target sets)
python main.py targets.txt

# High-concurrency scan
python main.py targets.txt -c 1000

# Resume interrupted scan
python main.py targets.txt --resume

# Run recon (passive + optional active chain)
python main.py --recon squareup.com --wordlist wordlist.txt

# Recon + auto follow-up (httpx → dirsearch → nuclei)
python main.py --recon squareup.com --wordlist wordlist.txt --scan-found

# Recon + follow-up + full-range Nmap on alive hosts
python main.py --recon squareup.com --wordlist wordlist.txt --scan-found --nmap

# Traditional service-only scan
python main.py targets.txt -m elasticsearch

# Add custom ports to scan
python main.py targets.txt -p 8080,8443,9999

# Configure chunk size for streaming mode (default: 30,000 IPs)
python main.py targets.txt --chunk-size 50000

# Combined options for large-scale scanning
python main.py targets.txt -m grafana -p 3001,3002 -c 1000 --chunk-size 25000
```

##  Sample Output

### Small-Scale Scan
```
[*] Starting VaktScan - Nordic Security Scanner...
[*] Parsing targets from targets.txt...
[+] Successfully resolved 1,250 unique IP addresses.
[*] Starting concurrent port scan for 1,250 IPs across 8 unique ports...
[*] Progress: 8,750/10,000 (87.5%) | Rate: 892.3 scans/sec | ETA: 1s
[*] Port scanning completed. Found 45 open ports across 12 services.
[*] Validated 12 service(s). Starting VaktScan vulnerability assessment...
  -> Running Elasticsearch scans on http://192.168.1.100:9200
  -> Running Grafana scans on http://192.168.1.102:3000

[CRITICAL] CVE-2021-44228 - Log4Shell RCE | http://192.168.1.100:9200
[HIGH] CVE-2018-17246 - Kibana File Read | http://192.168.1.101:5601
[VULNERABLE] Grafana Default Credentials (admin:admin) | http://192.168.1.102:3000

[+] Scan completed. Found 8 vulnerabilities across 3 severity levels.
[+] Results saved to scan_results_20250910_143022.csv
```

### Large-Scale Streaming Scan
```
[*] Starting VaktScan - Nordic Security Scanner...
[*] Large target set detected (705,560+ IPs) - using streaming mode
[*] Starting streaming scan: 705,560 total IPs across 24 chunks (chunk size: 30,000)

=== Processing Chunk 1/24 (30,000 IPs) ===
[*] Overall Progress: 30,000/705,560 IPs (4.3%) | Remaining: 675,560 IPs
[*] Scanning chunk 1: 30,000 IPs across 11 ports (330,000 combinations)
[*] Progress: 165,000/330,000 (50.0%) | Rate: 1,247.3 scans/sec | ETA: 132s

[*] State checkpoint saved at 14:32:15

[+] Chunk 1/24 completed. Found 3 new vulnerabilities (3 total). 23 chunks remaining.

=== Processing Chunk 2/24 (30,000 IPs) ===
[*] Overall Progress: 60,000/705,560 IPs (8.5%) | Remaining: 645,560 IPs
...
```

## 🔧 Configuration Options

### Command Line Arguments
```bash
python main.py targets.txt [OPTIONS]

Options:
  targets_file            File with IPs/hosts/CIDRs (omit when using --recon)
  -c, --concurrency INT   Set concurrency level (default: 100, max: 2000)
  -r, --resume            Resume an interrupted infrastructure scan
  --csv                   Save consolidated results to CSV
  -m, --module SERVICE    Scan only elasticsearch|kibana|grafana|prometheus|nextjs
  -p, --ports PORTS       Extra comma-separated ports to scan
  --chunk-size INT        Chunk size for streaming mode (default: 30000)
  --recon DOMAIN          Run passive/active subdomain enumeration for DOMAIN
  --wordlist PATH         Wordlist for ffuf VHost fuzzing during recon
  --scan-found            Immediately probe recon results (httpx→dirsearch→nuclei)
  --nmap                  Full 1-65535 port scan on recon hosts followed by nmap -sCV -Pn
  -h, --help              Show help

Streaming Mode:
  • Automatically enabled for scans with 30,000+ IP addresses
  • Processes targets in memory-efficient chunks
  • Supports resumable scanning with chunk-level progress tracking
  • Ideal for scanning large CIDR ranges and enterprise networks
```

### Target File Format
```bash
# Single IP addresses
192.168.1.1
10.0.0.5

# Hostnames and domains
grafana.company.com
kibana.internal.net

# CIDR subnets (supports any size - from /32 to /8)
192.168.0.0/24
10.0.0.0/16
172.16.0.0/12

# Large enterprise networks (streaming mode auto-enabled)
203.0.113.0/24
198.51.100.0/24
# Multiple /16 networks totaling 1M+ IPs

# URLs (protocol and port extracted automatically)  
http://monitoring.example.com:3000
https://logs.company.com:5601

# Recon-only mode (domains)
squareup.com
api.squareup.com
```

### Service Port Mapping
- **Elasticsearch**: 9200, 9300
- **Kibana**: 5601  
- **Grafana**: 3000, 3003
- **Prometheus**: 9090, 9100, 9101, 9102, 9103, 9104

##  Vulnerability Coverage

### Elasticsearch (11 CVEs)
- **CVE-2024-23450** - Document processing DoS
- **CVE-2021-44228** - Log4Shell RCE (CRITICAL)  
- **CVE-2015-1427** - Groovy Sandbox Bypass RCE
- **CVE-2014-3120** - Dynamic Scripting RCE
- And 7 additional CVEs covering authentication bypass, privilege escalation, and information disclosure

### Kibana (4 CVEs + API Testing)
- **CVE-2018-17246** - Local File Inclusion (CRITICAL)
- **CVE-2019-7609** - Timelion RCE (CRITICAL)
- **CVE-2019-7608** - Cross-Site Scripting
- **CVE-2021-22137** - Information Disclosure
- Plus comprehensive API endpoint enumeration

### Grafana (18 CVEs)
- **CVE-2024-9264** - SQL Expressions RCE (CRITICAL)
- **CVE-2021-43798** - Path Traversal File Access
- **CVE-2020-13379** - SSRF via Avatar Endpoint
- **CVE-2022-32276** - Unauthenticated Snapshot Access
- And 14 additional CVEs covering XSS, authentication bypass, and privilege escalation

### Prometheus (3 CVEs + Metrics Analysis)
- **CVE-2021-29622** - Open Redirect 
- **CVE-2019-3826** - Stored XSS
- **CVE-2018-1000816** - Path Traversal
- Plus comprehensive metrics endpoint analysis and Node Exporter security assessment

## 🔐 HTTP/HTTPS Protocol Support

VaktScan automatically tests **both HTTP and HTTPS protocols** for complete coverage:

### **Dual Protocol Testing**
- **Automatic Detection**: Tests both HTTP and HTTPS on every service
- **Complete Coverage**: Detects services running on secure (HTTPS) or insecure (HTTP) configurations
- **Production Ready**: Handles self-signed certificates and SSL/TLS configurations
- **No Duplicates**: Intelligent filtering prevents duplicate vulnerability reports

### **SSL/TLS Handling**
- **Self-Signed Certificates**: Automatically handles development/testing environments
- **Certificate Validation**: Configurable SSL verification (disabled by default for compatibility)
- **Timeout Management**: Intelligent timeout handling prevents hanging on unresponsive HTTPS services
- **Graceful Fallback**: Continues scanning even when one protocol fails

### **Example Output**
```bash
  -> Running Elasticsearch scans on http://192.168.1.100:9200    # HTTP test
  -> Running Elasticsearch scans on https://192.168.1.100:9200   # HTTPS test
  -> Running Grafana scans on http://192.168.1.102:3000          # HTTP test  
  -> Running Grafana scans on https://192.168.1.102:3000         # HTTPS test
```

**All services (Elasticsearch, Kibana, Grafana, Prometheus) automatically test both protocols for comprehensive security assessment.**

##  Development & Extension

### Adding New Service Scanners

1. **Create scanner module**:
```python
# modules/newservice.py
async def run_scans(ip, port):
    # Test both HTTP and HTTPS protocols
    protocols = ['http', 'https']
    all_results = []
    
    for protocol in protocols:
        target_url = f"{protocol}://{ip}:{port}"
        # Implementation here for this protocol
        # Skip if can't connect
        if not version_info:
            continue
        # Add results to all_results
        
    return all_results
```

2. **Register service ports**:
```python
# utils.py
def get_service_ports():
    return {
        # existing services...
        "newservice": [8080, 8443]
    }
```

3. **Add scanner integration**:
```python
# main.py  
from modules import elastic, kibana, grafana, prometheus, newservice
# Add to scanner delegation logic
```

### Adding New Vulnerability Checks

```python
async def check_new_vulnerability(target_url):
    """Check for specific vulnerability."""
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.get(f"{target_url}/vulnerable-endpoint")
            if response.status_code == 200 and "vulnerable_indicator" in response.text:
                return {
                    "status": "VULNERABLE",
                    "vulnerability": "New Vulnerability Name", 
                    "target": target_url,
                    "details": "Detailed description of the vulnerability"
                }
    except:
        pass
    return None

# Add to tasks list in run_scans() for each protocol
for protocol in protocols:
    target_url = f"{protocol}://{ip}:{port}"
    tasks.append(check_new_vulnerability(target_url))
```

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Disclaimer

VaktScan is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have explicit permission to scan target systems. Unauthorized scanning of systems you do not own or have permission to test is illegal and unethical.
