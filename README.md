# VaktScan - Monitoring Stack Security Scanner

> **VaktScan** (*pronounced "vahkt-scan"*) - Named after the Nordic word "vakt" meaning "guard" or "watch", representing the vigilant nature of security monitoring.

An advanced, high-performance security scanner designed for comprehensive vulnerability assessment of monitoring and logging infrastructure stacks. VaktScan provides enterprise-grade scanning capabilities with concurrent processing and extensive CVE coverage.


##  Features

###  Comprehensive Service Coverage
- **Elasticsearch**: 11+ CVEs (2014-2024), version vulnerabilities, authentication bypass, sensitive endpoint exposure
- **Kibana**: CVE testing (CVE-2018-17246, CVE-2019-7609), UI exposure detection, default credentials, API enumeration
- **Grafana**: 18+ CVEs, default credentials, directory traversal, XSS vulnerabilities, comprehensive CVE database
- **Prometheus**: Dashboard exposure, configuration leaks, target enumeration, Node Exporter analysis, pprof endpoints

###  Advanced Vulnerability Detection
- **30+ CVE Database**: Comprehensive vulnerability coverage with payload testing
- **Version-Based Detection**: Custom version parsing and vulnerability mapping without external dependencies
- **Severity Classification**: CRITICAL, HIGH, MEDIUM risk categorization with detailed descriptions
- **Active Payload Testing**: Exploitation attempts for vulnerability confirmation
- **Service Validation**: Ensures accurate service identification before scanning

###  High-Performance Architecture
- **Multi-target Support**: IPs, hostnames, domains, and CIDR subnets
- **Concurrent Processing**: Asyncio-based high-concurrency scanning (configurable up to 2000+ threads)
- **Smart State Management**: Resume interrupted scans with 2-minute checkpoint intervals
- **Real-time Progress**: Live scanning progress with ETA and rate calculations
- **Modular Design**: Easily extensible for new services and vulnerability checks

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
    └── prometheus.py      # Prometheus scanner (3 CVEs + metrics analysis)
```

##  Requirements

- **Python**: 3.8+ (tested on 3.8, 3.9, 3.10, 3.11)
- **Dependencies**: All bundled in `vendor/` directory (no external installation required)
- **Memory**: ~50MB RAM per 1000 concurrent connections
- **Network**: Raw socket access for port scanning

##  Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/Bhanunamikaze/VaktScan.git
cd VaktScan
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
# Basic scan
python main.py targets.txt

# High-concurrency scan
python main.py targets.txt -c 500

# Resume interrupted scan
python main.py targets.txt --resume
```

##  Sample Output

```
[*] Starting VaktScan - Nordic Security Scanner...
[*] Parsing targets from targets.txt...
[+] Successfully resolved 1,250 unique IP addresses.
[*] Starting concurrent port scan for 1,250 IPs across 8 unique ports...
[*] Progress: 1,250/10,000 (12.5%) | Rate: 892.3 scans/sec | ETA: 10s
[*] Port scanning completed. Found 45 open ports across 12 services.
[*] Validated 12 service(s). Starting VaktScan vulnerability assessment...

[CRITICAL] CVE-2021-44228 - Log4Shell RCE | http://192.168.1.100:9200
[HIGH] CVE-2018-17246 - Kibana File Read | http://192.168.1.101:5601
[VULNERABLE] Grafana Default Credentials (admin:admin) | http://192.168.1.102:3000

[+] Scan completed. Found 8 vulnerabilities across 3 severity levels.
[+] Results saved to scan_results_20250910_143022.csv
```

## 🔧 Configuration Options

### Command Line Arguments
```bash
python main.py targets.txt [OPTIONS]

Options:
  -c, --concurrency INT    Set concurrency level (default: 100, max: 2000)
  --resume                Resume from previous interrupted scan
  -h, --help              Show help message
```

### Target File Format
```bash
# Single IP addresses
192.168.1.1
10.0.0.5

# Hostnames and domains
grafana.company.com
kibana.internal.net

# CIDR subnets
192.168.0.0/24
10.0.0.0/16

# URLs (protocol and port extracted automatically)  
http://monitoring.example.com:3000
https://logs.company.com:5601
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


##  Development & Extension

### Adding New Service Scanners

1. **Create scanner module**:
```python
# modules/newservice.py
async def run_scans(ip, port):
    target_url = f"http://{ip}:{port}"
    # Implementation here
    return results
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
        async with httpx.AsyncClient() as client:
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

# Add to tasks list in run_scans()
tasks.append(check_new_vulnerability(target_url))
```

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Disclaimer

VaktScan is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have explicit permission to scan target systems. Unauthorized scanning of systems you do not own or have permission to test is illegal and unethical.
