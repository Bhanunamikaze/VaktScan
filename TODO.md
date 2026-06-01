# VaktScan — ASM Coverage TODO

Current state: port scan → service identification → CVE/vuln checks → web recon → DNS recon → JS analysis → cPanel module → DNS recon module.

---

## 1. False Positive Validation ✅ DONE

These are the same class of bug as the cPanel false positive fix. Every item here produces noisy, incorrect findings today.

### service_recon.py — missing service identity gates

**Root problem**: Port 8080 (and other shared ports) triggers Spring Boot, Tomcat, Jenkins, Traefik, JBoss, and Hadoop YARN checks simultaneously without first confirming which service is actually present.

**Root fix — `service_fingerprint()` dispatch guard**
- Implement a lightweight `service_fingerprint(host, port)` function that probes the root URL once and returns a set of detected technologies based on: `Server` header, `X-Powered-By`, response body keywords, and specific path probes
- `PORT_DISPATCH` entries for shared ports (8080, 9000, 8081, 8443) must only invoke a check when the fingerprint confirms that service is present
- This single fix gates all per-service checks below

**Per-check fixes (required even after fingerprint guard)**

| Check | Current behavior | Required fix |
|---|---|---|
| `check_spring_actuator` | Any `/actuator/env` 200 → VULNERABLE | Require "spring" or "actuator" in response body or headers |
| `check_tomcat` | `/manager/html` 401 → fires finding | 401 is correct auth behavior — only fire if 200 without auth, or if default creds actually succeed (confirm via response body, not just status) |
| `check_traefik` | `/dashboard/` 200 → fires | Require "traefik" in response body or headers |
| `check_portainer` | `/api/status` any 200 JSON → INFO | Require "portainer" keyword in response body |
| `check_sonarqube` | `/api/system/status` any JSON 200 → fires | Require "sonarQube" or `"status":"UP"` in body |
| `check_teamcity` | CVE-2024-27198 `/app/rest/users` 200 → fires | Require actual user data in response body, not just HTTP 200 |
| `check_minio` | Default cred check fires without service confirmation | Detect MinIO by response headers (`x-amz-request-id` or "minio" in `Server` header) before attempting default cred check |
| `check_consul` | `/v1/catalog/services` any 200 JSON → HIGH | Require consul-specific fields (`Service`, `Datacenter`) in response body |

### web_checks.py — missing body validation

| Check | Current behavior | Required fix |
|---|---|---|
| `check_sensitive_files` — `.git/HEAD` | HTTP 200 → VULNERABLE | Require `"ref: refs/heads/"` in body (catch-all servers return 200 for everything) |
| `check_sensitive_files` — `.env` | HTTP 200 → VULNERABLE | Require `"="` in body and at least one line matching `KEY=value` pattern, minimum 20 chars |
| `check_sensitive_files` — backup files (`.zip`, `.tar.gz`) | HTTP 200 → fires | Check `Content-Type` for `application/zip` or `application/octet-stream` to confirm actual file download |
| `check_admin_panels` | `/admin` 401 → VULNERABLE | 401 means auth is working correctly — downgrade to INFO; only fire VULNERABLE if 200 AND body contains login form markers (`input type=password`, login form HTML) |
| `check_directory_listing` | "Index of" text in body → fires | Require at least 3 file entries visible, not just the "Index of" string which appears in some legitimate page content |

---

## 2. Missing Service Checks ✅ DONE

### CI/CD & DevTools

| Service | Ports | What to check |
|---|---|---|
| **Jenkins** | 8080 | *(partial)* Add CVE-2024-23897 (arbitrary file read via CLI) |
| **GitLab** | 80, 443 | Public projects listing, user enumeration via `/api/v4/users`, unauthenticated API access |
| **Jira** | 8080 | CVE-2022-0540 (authentication bypass) — unauthenticated project access |
| **Confluence** | 8090, 8443 | CVE-2023-22518 (improper auth), CVE-2022-26134 (OGNL RCE) — both unauthenticated |

### Cloud-Native

| Service | Ports | What to check |
|---|---|---|
| **ArgoCD** | 80, 443 | CVE-2022-29165 (authentication bypass), unauthenticated API |
| **Rancher** | 80, 443 | Unauthenticated API access |
| **OpenTelemetry Collector** | 4317, 4318, 55679 | Unauthenticated gRPC/HTTP OTLP ingestion — telemetry data exfil |

### Infrastructure & Monitoring

| Service | Ports | What to check |
|---|---|---|
| **Java RMI** | 1099, 1098 | BaRMIe enum, rmg.jar, beanshooter — deserialization gadget check |
| **Nagios / Zabbix** | 80, 10051 | Default credential check |
| **IPMI** | 623 | Cipher suite 0 authentication bypass (`ipmitool -I lanplus -C 0`), hash capture |

---

## 3. Missing Recon / Discovery

### Cloud Asset Discovery

- **AWS**: S3 bucket enumeration (permutation-based), CloudFront origin IP leak, EC2 metadata endpoint (169.254.169.254) SSRF indicator
- **Azure**: Blob storage enumeration, Azure AD tenant discovery
- **GCP**: GCS bucket enumeration, GCP metadata endpoint SSRF

### Google Dorking (domain/subdomain targets only — not applicable to raw IPs)

Passive recon via Google Search Operators to surface exposed assets and leaked credentials indexed by Google. Requires a Google Custom Search API key + Search Engine ID (or a scraping fallback with rate limiting).

**Dork categories and example queries** (parameterized with `{domain}`):

| Category | Dork | Finding |
|---|---|---|
| Open S3 buckets | `site:s3.amazonaws.com "{domain}"` | Publicly indexed S3 content |
| Azure Blob exposure | `site:blob.core.windows.net "{domain}"` | Publicly indexed Azure storage |
| GCP storage exposure | `site:storage.googleapis.com "{domain}"` | Publicly indexed GCS content |
| Exposed env/config files | `site:{domain} ext:env OR ext:cfg OR ext:conf OR ext:ini` | Config files with potential credentials |
| Exposed log files | `site:{domain} ext:log` | Application/server logs |
| Pastebin credential leaks | `site:pastebin.com "{domain}" password OR passwd OR secret OR token OR apikey` | Leaked credentials in pastes |
| GitHub credential leaks | `site:github.com "{domain}" password OR secret OR token OR apikey` | Secrets in public repos |
| Exposed backup files | `site:{domain} ext:bak OR ext:sql OR ext:dump OR ext:backup` | Database dumps and backups |
| Directory listings | `site:{domain} intitle:"index of" "parent directory"` | Apache/Nginx open directory |
| Login panel exposure | `site:{domain} inurl:admin OR inurl:login OR inurl:wp-admin` | Admin panels indexed by Google |
| API key/secret in URLs | `site:{domain} inurl:api_key= OR inurl:secret= OR inurl:token=` | Secrets embedded in URLs |
| Cloud metadata SSRF | `site:{domain} inurl:169.254.169.254` | SSRF to cloud metadata service |

**Implementation notes:**
- Only run on `domain` and `subdomain` targets — skip if target is a raw IP or CIDR
- Use Google Custom Search JSON API (`https://customsearch.googleapis.com/customsearch/v1`) — requires `--google-api-key` and `--google-cx` args
- Rate limit to 1 request/second (API quota: 100 queries/day free tier)
- Deduplicate results across dork categories before reporting
- Each result: severity INFO with dork used, matched URL, and snippet from Google
- Expose as `-m google-dork` standalone mode and wire into full scan pipeline for domain targets

### Passive Intelligence

- **Shodan** API integration — pull known open ports/banners for target IPs without active scanning
- **Censys** API integration — certificate and host data enrichment

### Certificate Transparency

- Monitor CT logs for new subdomains (crt.sh polling, Certstream)
- Alert on newly issued certificates for target domain

### Email Security (extend dns_recon)

- MX record banner grabbing (mail server version)
- SMTP open relay test
- BIMI record check

---

## 4. Vulnerability Correlation (partial — see Remaining Backlog)

- **Version → CVE mapping**: detected service version → NVD API lookup → filter by CVSS ≥ 7
- **CPE generation** from banner strings for accurate CVE matching
- **CISA KEV cross-reference**: flag CVEs that appear on CISA's Known Exploited Vulnerabilities catalog
- **EPSS scoring**: enrich CVE findings with FIRST.org exploitation probability score
- **Nuclei template auto-sync**: pull latest community templates before scan run

---

## 5. Output / Reporting ✅ DONE

- **JSON output** — machine-readable per-finding export
- **SARIF output format** — for GitHub/GitLab security tab integration
- **Risk scoring per asset** — aggregate severity of all findings per IP/domain
- **Delta reports** — "new since last scan" vs "resolved since last scan"
- **Executive summary** — finding counts by severity, top 5 critical assets

---

## 6. Operational / Platform (partial)

- **Asset inventory persistence** — SQLite store of discovered assets across runs
- **Proxy support** — route scans through Burp / upstream proxy
- **IPv6 scanning** — currently IPv4 only

---

## Priority Order

> Items marked ✅ are shipped. Remaining items are the actual backlog.

1. ✅ **False positive validation — service_recon.py + web_checks.py** — `_fingerprint()` dispatch guard + per-check body validation all done
2. ✅ **Shodan/Censys passive enrichment** — `modules/passive_intel.py`, reads `SHODAN_API_KEY` / `CENSYS_API_ID` / `CENSYS_API_SECRET` from env
3. ✅ **Jira CVE-2022-0540 + Confluence CVE-2023-22518/CVE-2022-26134** — `check_jira()` and `check_confluence()` in `service_recon.py`
4. ✅ **JSON output** — `save_results_to_json()` in `reporter.py`; `--format json` flag on `scan` subcommand
5. ✅ **CISA KEV cross-reference** — `modules/cisa_kev.py`
6. ✅ **Java RMI checks** — `check_java_rmi()` in `service_recon.py`, ports 1099/1098
7. ✅ **GitLab public project exposure + user enumeration** — `check_gitlab()` in `service_recon.py`
8. ✅ **Asset inventory persistence (SQLite)** — `modules/inventory.py`
9. ✅ **EPSS scoring** — `modules/epss.py`
10. ✅ **Delta reports** — `inventory.print_delta_report()` called in main scan pipeline
11. ✅ **Google Dorking** — `modules/google_dork.py`; `vaktscan google-dork` subcommand; `GOOGLE_API_KEY` / `GOOGLE_CX` env vars

### Remaining backlog

1. **NVD API generic version→CVE mapping** — per-module version checks exist (grafana, kibana, prometheus) but no generic `detected_version → NVD API → CVSS ≥ 7` pipeline; CPE generation from banner strings also missing
2. **IPv6 scanning** — `port_scanner.py` is IPv4 only; `socket.AF_INET6` support needed throughout scan pipeline
3. **Certificate Transparency alerting** — crt.sh polling for *new* certificates (change detection) is not yet wired; current CT log lookup is one-shot per scan only
4. **Nuclei template auto-sync on schedule** — `sync_nuclei_templates()` exists but is only called via `--update-templates`; could run automatically if templates are > N days old

---

## 7. CLI Redesign — Subcommands + Unified Pipeline

This section tracks the full CLI redesign approved in the June 2026 brainstorm.

### Design Goals
- argparse subparsers: scan, enum, probe, dns, cloud, js-paths, google-dork
- `scan <domain>` runs the full pipeline (enum → all checks → reports/)
- `scan <ip/cidr>` runs port scan → web checks → service vuln checks
- All modules return the same finding schema
- CSV auto-generated in reports/ for every run (no flag needed)
- Subdomain enum is ON by default for domain targets; --no-subdomain-enum to skip

### Tasks

#### 7.1 CLI Architecture
- [ ] Refactor main.py to use argparse subparsers (scan, enum, probe, dns, cloud, js-paths, google-dork)
- [ ] Auto-detect target type (IP/CIDR/domain/file) inside scan subcommand
- [ ] Add --no-subdomain-enum flag to scan subcommand
- [ ] Add -m/--module flag to scan subcommand (all modules by default, one module when specified)
- [ ] Write per-subcommand help text that is accurate and complete
- [ ] Pass args.module only as module_filter (remove the double-pass bug where it's sent as both module_filter and module_mode)

#### 7.2 Full Scan Pipeline (Domain)
- [ ] Wire full domain pipeline in scan subcommand: enum → DNS recon → cloud enum → port scan → httpx → web checks + nuclei (parallel) → service vuln checks → dirsearch → gau + waybackurls → JS paths → enrichments → CSV
- [ ] Run DNS recon and cloud enum in parallel (both take domain, no dependency on each other)
- [ ] Run web checks and nuclei in parallel on alive URLs (currently sequential)
- [ ] Run GAU and waybackurls in parallel (currently sequential)
- [ ] Run per-host service vuln checks in parallel (each host/port is independent)
- [ ] After enum, feed discovered subs + primary domain together into port scan

#### 7.3 probe Subcommand
- [ ] Implement probe subcommand: accepts a file of hosts/URLs and runs httpx → web checks + nuclei (parallel) → dirsearch → gau → waybackurls → JS paths
- [ ] Wire probe as the reusable web-pipeline step (used internally by scan after enum, and standalone)

#### 7.4 Unified Finding Schema
- [ ] Define canonical finding schema in a shared module (e.g. utils.py or a new findings.py)
- [ ] Patch elastic, kibana, grafana, prometheus modules to emit all required schema keys
- [ ] Patch aem, cpanel, jenkins, service_recon, react_to_shell modules similarly
- [ ] Patch dns_recon, cloud_enum, web_checks, domain_scan to match schema
- [ ] Patch js_paths module to match schema
- [ ] Add schema validation helper function that normalises a finding dict (fills missing keys with N/A)

#### 7.5 Reporting — reports/ Directory
- [ ] Create reports/ directory at startup in all scan paths (scan, probe, dns, cloud, js-paths, google-dork)
- [ ] Move save_results_to_csv() to always write into reports/ with naming: reports/{subcommand}_{target}_{timestamp}.csv
- [ ] Move save_port_scan_csv() to reports/ as well
- [ ] Ensure every subcommand writes its CSV at the end regardless of --csv flag (make it always-on)
- [ ] Remove --csv flag (CSV is now always generated)
- [ ] Extend existing reporting/inventory module rather than duplicating output logic

#### 7.6 Google Dork Subcommand
- [ ] Implement google-dork subcommand (domain target, --google-api-key, --google-cx flags)
- [ ] Wire google-dork into the full scan pipeline (runs after cloud enum, before port scan) for domain targets
- [ ] Rate limit to 1 req/s, deduplicate results across dork categories
- [ ] Emit findings in canonical schema with severity INFO

#### 7.7 enum Subcommand
- [ ] Implement enum subcommand: subdomain discovery only (amass, subfinder, etc.), writes subs to reports/{domain}_subdomains_{timestamp}.txt
- [ ] Add --probe flag to enum that auto-chains into probe subcommand when done

---

## 8. Mixed Target File Handling ✅ DONE

- [x] Detect domain vs IP lines in a mixed targets file
- [x] Print info message showing domain count vs IP count when mixed file detected
- [x] Pass domain lines to recon pipeline (subdomain enum) when --no-subdomain-enum is not set
- [x] --no-subdomain-enum skips enum for domain lines but they still get port-scanned
- [ ] Full integration test: mixed file with 1 domain + 1 IP completes both pipelines

## 9. Documentation ✅ DONE

- [x] README.md rewritten with ASCII architecture diagram, CLI reference, quick start, module table
- [x] docs/adding-a-module.md — step-by-step guide for adding a new scanner module (all 7 touch points)
- [ ] Add screenshot/GIF of a real scan run to README
- [ ] docs/adding-a-module.md — add example for adding a check to an existing module (not just new module)
