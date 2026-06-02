# VaktScan — Attack Surface Scanner

> *"vakt"* is the Nordic word for "guard" or "watch".

VaktScan is a high-performance attack surface scanner that accepts domains, IPs, CIDRs, or mixed target files and runs the full pipeline — subdomain enumeration, port scanning, HTTP probing, service-specific CVE checks, JavaScript analysis, DNS recon, cloud asset discovery, Google dorking, and multi-source enrichment — concurrently. Results land in a timestamped output directory as CSV, JSON, and SARIF.


## Architecture

See `docs/architecture.svg` for the full visual diagram.

```
Input: <domain | IP | CIDR | file>
        │
        ▼
  target_classifier
        │
  ┌─────┴──────────────────────────────────────────────────────────────┐
  │ Domain target                                                       │
  │                                                                     │
  │  Stage 1 — Passive Recon (all five run in parallel):                │
  │  ┌──────────────┐  ┌───────────┐  ┌───────────────┐  ┌──────────┐  │
  │  │ Subdomain    │  │ DNS Recon │  │ Cloud Enum    │  │    CT    │  │
  │  │ Enum +       │  │ SPF/DMARC │  │ S3/Azure/GCS  │  │ Monitor  │  │
  │  │ Google Dork  │  │ AXFR/DKIM │  │ CloudFront    │  │ crt.sh   │  │
  │  │ (28 dorks)   │  │ DNSSEC    │  │ bucket guess  │  │ baseline │  │
  │  └──────────────┘  └───────────┘  └───────────────┘  └──────────┘  │
  └─────────────────────────────────────────────────────────────────────┘
              │ (subdomains + apex domain)
              ▼  ◄── IP/CIDR targets enter here (skip Stage 1)
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Stage 2 — Active Discovery                                          │
  │                                                                     │
  │  Port Scanner (200 ports default, custom with --ports)              │
  │       │                                                             │
  │       ├── [--nmap] Nmap -sCV --script vuln,vulners (CVE scan)       │
  │       ▼                                                             │
  │  HTTPX Probe → alive URLs list                                      │
  └─────────────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Stage 3 — Web Analysis (all 5 run in parallel on alive URLs)         │
  │                                                                     │
  │  ┌──────────┐ ┌────────────┐ ┌─────────────┐ ┌──────────┐          │
  │  │  Nuclei  │ │ Web Checks │ │ Domain Scan │ │Dirsearch │          │
  │  │  (CVEs)  │ │ git/env    │ │ takeover    │ │dir brute │          │
  │  │          │ │ admin/CORS │ │ CORS/headers│ │-force    │          │
  │  └──────────┘ └────────────┘ └─────────────┘ └──────────┘          │
  │  ┌──────────┐                                                       │
  │  │ JS Paths │  + GAU ┐  (domain only, both parallel)               │
  │  │ secrets/ │        ├── URL harvest → archived endpoint analysis   │
  │  │ endpoints│  WaybackURLs ┘                                        │
  │  └──────────┘                                                       │
  └─────────────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Stage 4 — Service Vulnerability Scanning (per open port, parallel)  │
  │                                                                     │
  │  elastic │ kibana │ grafana │ prometheus │ cpanel │ jenkins         │
  │  aem │ service_recon (30+ checks: Redis/SMB/k8s/RMI/IPMI/...)      │
  │                                                                     │
  │  (fingerprint guard — checks only fire when service is confirmed)   │
  └─────────────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Stage 5 — Enrichment (parallel)                                     │
  │                                                                     │
  │  CISA KEV ──┐                                                       │
  │  EPSS       ├── asyncio.gather → merged into final findings         │
  │  NVD CVE  ──┘                                                       │
  │  Passive Intel (Shodan + Censys)                                    │
  └─────────────────────────────────────────────────────────────────────┘
              │
              ▼
  reports/<target>_<YYYYMMDD_HHMMSS>/
  ├── portscan_results_*.csv
  ├── httpx_alive_*.csv
  ├── scan_results_*.csv     ← always written
  ├── scan_results_*.json    ← with --format json/all
  └── scan_results_*.sarif   ← with --format sarif/all
```

> **IP/CIDR targets** skip Stage 1 (no subdomain enum, DNS recon, cloud enum, CT monitor, or Google Dork)
> and go directly to Stage 2. GAU/WaybackURLs also skip for raw IP targets.


## Quick Start

### Installation

```bash
git clone https://github.com/Bhanunamikaze/VaktScan.git
cd VaktScan

# Install the vendored Python httpx dependency
pip install httpx --target=./vendor

# Install all 40+ external tools (amass, subfinder, httpx, nuclei, ffuf, nmap, ...)
bash requirements.sh
```

Check or selectively install tools:

```bash
python scripts/setup_recon_tools.py            # view install status
python scripts/setup_recon_tools.py --install  # install all missing tools
python scripts/setup_recon_tools.py --install --tools amass httpx nuclei
```

### Basic Usage

```bash
# Full scan of a single domain (subdomain enum + all modules)
python main.py scan example.com

# Full scan of an IP or CIDR
python main.py scan 192.168.1.0/24

# Scan a mixed targets file (IPs, hostnames, domains, CIDRs)
python main.py scan targets.txt

# Skip subdomain enumeration for domain targets
python main.py scan example.com --no-subdomain-enum

# Resume an interrupted scan
python main.py scan targets.txt --resume

# High-concurrency scan with JSON + SARIF output
python main.py scan targets.txt -c 500 --format all
```


## CLI Reference

VaktScan uses subcommands. Run `python main.py <subcommand> --help` for per-command flags.

| Subcommand | Key Flags | What It Does |
|---|---|---|
| `scan` | `target` `-c` `--module` `--ports` `--no-subdomain-enum` `--resume` `--format` `--proxy` `--nmap` `--update-templates` | Full attack surface scan: enum → port scan → httpx → service modules → enrichment → report |
| `enum` | `domain` `-c` `--wordlist` `--output-dir` `--probe` | Subdomain enumeration only (subfinder, amass, crt.sh, ffuf VHost fuzzing); optionally chains into `probe` |
| `probe` | `target` `--ports` `-c` `--timeout` `--output-dir` | Port scan + httpx probe; outputs open-port CSV and alive-URL list |
| `dns` | `domain [...]` `-c` `--output-dir` | DNS recon: A/AAAA/MX/NS/TXT/SOA/CAA/DNSKEY, SPF/DMARC/DKIM, AXFR, open recursion, DNSSEC |
| `cloud` | `domain` `-c` `--output-dir` | Cloud asset enumeration: S3 bucket guessing, Azure Blob, GCP storage, CloudFront detection |
| `js-paths` | `target` `--threads` `--timeout` `--output-dir` | JavaScript path extraction: secrets, source maps, internal IPs, endpoint probing |
| `domain-scan` | `domain` `--httpx-data` `-c` `--output-dir` | HTTP-level domain analysis: classification, takeover detection (58 signatures), CORS, header audit |
| `google-dork` | `domain` `--google-api-key` `--google-cx` `--dorks` `--delay` `--max-results` `--output-dir` | Passive recon via Google Custom Search API using operator-crafted dorks |

### Selected `scan` Flags

| Flag | Default | Description |
|---|---|---|
| `-c`, `--concurrency` | `100` | Concurrent connections (max ~2000) |
| `--module` | all | Restrict to one service module: `elasticsearch` `kibana` `grafana` `prometheus` `nextjs` `aem` `cpanel` `jenkins` `service_recon` |
| `--ports` | — | Extra comma-separated ports to add to the scan |
| `--no-subdomain-enum` | off | Skip subdomain discovery for domain targets |
| `--resume` | off | Resume a checkpointed scan |
| `--format` | csv | Additional output formats: `json` `sarif` `all` |
| `--proxy` | — | HTTP/HTTPS proxy URL (e.g. `http://127.0.0.1:8080`) |
| `--nmap` | off | Run full 1–65535 port scan + `nmap -sCV -Pn` on open ports |
| `--update-templates` | off | Pull latest Nuclei templates before scanning |
| `--chunk-size` | `30000` | IPs per streaming chunk for large CIDR scans |


## Output

Each `scan` run writes to `reports/<target>_<YYYYMMDD_HHMMSS>/`:

| File | Contents |
|---|---|
| `portscan_results_*.csv` | Open ports: IP, port, service, banner |
| `httpx_*.csv` | Alive URLs from httpx probe: URL, status code, title, tech |
| `scan_results_*.csv` | All vulnerability findings: target, module, CVE, severity, description |
| `scan_results_*.json` | Same findings in JSON (with `--format json` or `--format all`) |
| `scan_results_*.sarif` | SARIF 2.1 report for CI/CD integration (with `--format sarif` or `--format all`) |
| `nuclei_*.txt` | Raw Nuclei output |

Non-scan subcommands write to `reports/<target>/` (no timestamp).


## Configuration (.env)

Create a `.env` file in the project root (or export variables in your shell). All are optional — modules degrade gracefully when keys are absent.

| Variable | Module | Purpose |
|---|---|---|
| `SHODAN_API_KEY` | `passive_intel` | Shodan host lookups for passive enrichment |
| `CENSYS_API_ID` | `passive_intel` | Censys search API credentials |
| `CENSYS_API_SECRET` | `passive_intel` | Censys search API credentials |
| `GOOGLE_API_KEY` | `google-dork` | Google Custom Search API key |
| `GOOGLE_CX` | `google-dork` | Google Custom Search engine ID |
| `NVD_API_KEY` | `nvd` | NVD API key (unauthenticated works but is rate-limited) |
| `VAKTSCAN_AGGRESSIVE_CPANEL` | `cpanel` | Set to `1` to enable credential brute-force probes |
| `VAKT_NUCLEI_BIN` | `nuclei_runner` | Override path to `nuclei` binary |
| `VAKT_HTTPX_BIN` | `httpx_runner` | Override path to `httpx` binary |
| `VAKT_GAU_BIN` | `gau_runner` | Override path to `gau` binary |


## Modules

### Service Modules (triggered automatically when the matching port is found open)

| Module | Default Ports | What It Checks |
|---|---|---|
| `elastic` | 9200, 9300 | 11+ CVEs: Log4Shell, Groovy RCE, auth bypass, info disclosure |
| `kibana` | 5601 | 4 CVEs: LFI, Timelion RCE, XSS, info disclosure; API enumeration |
| `grafana` | 3000 | 18+ CVEs: SQL RCE, path traversal, SSRF, snapshot access, XSS |
| `prometheus` | 9090 | 3 CVEs: open redirect, stored XSS, path traversal; metrics/target exposure |
| `cpanel` | 2077–2096, 9998–9999, 80, 443 | Full cPanel/WHM/Webmail CVE suite, bundled-component matrix (Roundcube, WHMCS, phpMyAdmin, Exim, Dovecot), anti-FP baselining |
| `jenkins` | 8080 | Unauthenticated API, script console RCE, user enumeration |
| `aem` | 4502, 4503, 80, 443, 8080, 8443 | CRXDE Lite exposure, Sling servlet enum, JCR content exposure |
| `service_recon` | 79 port mappings | 30+ service checks: FTP anon login, SMB null session, Redis unauth, Docker API, etcd secrets, Kubernetes API/Kubelet, MongoDB, Cassandra, RabbitMQ, Vault, TeamCity CVE-2024-27198, IPMI Cipher-0, Jupyter RCE, Hadoop YARN RCE, and more |
| `nuclei` | all alive URLs | ProjectDiscovery Nuclei template engine; auto-syncs templates with `--update-templates` |

### Recon / Analysis Modules

| Module | Subcommand | What It Does |
|---|---|---|
| `dns_recon` | `dns` | Wire-format DNS: SPF classification, DMARC `p=none`, DKIM (16 selectors), AXFR, open recursion, CAA/DNSSEC absence |
| `cloud_enum` | `cloud` | S3/Azure/GCP bucket and blob permutation + existence checks; CloudFront detection |
| `google_dork` | `google-dork` | 28 operator-crafted dorks via Custom Search API or Playwright/HTML scraping fallback |
| `js_paths` | `js-paths` | 12+ JS extraction strategies: hardcoded secrets, source maps, internal IPs, endpoint probing |
| `domain_scan` | `domain-scan` | Internal/external classification, parked-page detection, 58-signature takeover detection (GitHub Pages, S3, Heroku, Cloudflare, Vercel, Netlify, Azure, and more), CORS/header anomalies |
| `web_checks` | auto on all alive URLs | Security headers, `.git/HEAD`/`.env` exposure, GraphQL introspection, Swagger/OpenAPI exposure, SSL expiry, admin panels, directory listing, default CMS credentials |
| `nvd` | enrichment | NVD CVE lookup for detected product/version pairs |
| `cisa_kev` | enrichment | Flags findings that appear in the CISA Known Exploited Vulnerabilities catalog |
| `epss` | enrichment | Appends EPSS exploit-probability scores to CVE findings |
| `passive_intel` | enrichment | Shodan + Censys passive host data for discovered IPs |


## Adding a New Module

See `docs/adding-a-module.md` for a step-by-step walkthrough. The short version: create `modules/newservice.py` with an async `run_scans(ip, port)` function, register its ports in `utils.py` → `get_service_ports()`, and wire the module into `main.py`'s scanner delegation block.


## Requirements

- Python 3.8+ (tested on 3.8–3.11)
- `httpx` vendored in `vendor/` — no system install needed
- 40+ external tools installed via `bash requirements.sh`
- Raw socket access for port scanning
- ~50 MB RAM per 1000 concurrent connections; streaming mode handles millions of IPs with minimal memory


## License

MIT — see [LICENSE](LICENSE).


## Disclaimer

VaktScan is intended for authorized security testing and educational purposes only. Always obtain explicit written permission before scanning systems you do not own. Unauthorized scanning is illegal.
