# VaktScan — ASM Coverage TODO

Current state: port scan → service identification → CVE/vuln checks → web recon → DNS recon → JS analysis → cPanel module → DNS recon module.

---

## 1. False Positive Validation (NEW — HIGHEST PRIORITY)

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

## 2. Missing Service Checks

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

## 4. Vulnerability Correlation

- **Version → CVE mapping**: detected service version → NVD API lookup → filter by CVSS ≥ 7
- **CPE generation** from banner strings for accurate CVE matching
- **CISA KEV cross-reference**: flag CVEs that appear on CISA's Known Exploited Vulnerabilities catalog
- **EPSS scoring**: enrich CVE findings with FIRST.org exploitation probability score
- **Nuclei template auto-sync**: pull latest community templates before scan run

---

## 5. Output / Reporting

- **JSON output** — machine-readable per-finding export
- **SARIF output format** — for GitHub/GitLab security tab integration
- **Risk scoring per asset** — aggregate severity of all findings per IP/domain
- **Delta reports** — "new since last scan" vs "resolved since last scan"
- **Executive summary** — finding counts by severity, top 5 critical assets

---

## 6. Operational / Platform

- **Asset inventory persistence** — SQLite store of discovered assets across runs
- **Proxy support** — route scans through Burp / upstream proxy
- **IPv6 scanning** — currently IPv4 only

---

## Priority Order

1. **False positive validation — service_recon.py + web_checks.py** (URGENT — prevents noise, same class of bug as cPanel FP fix)
   - Start with `service_fingerprint()` dispatch guard, then per-check body validation
2. **Shodan/Censys passive enrichment** — zero-noise context, no active scanning required
3. **Jira CVE-2022-0540 + Confluence CVE-2023-22518/CVE-2022-26134** — actively exploited in the wild
4. **JSON output** — unblocks downstream integrations and delta reports
5. **CISA KEV cross-reference** — immediate severity context for existing findings
6. **Java RMI checks** — deserialization via BaRMIe/rmg.jar/beanshooter
7. **GitLab public project exposure + user enumeration**
8. **Asset inventory persistence (SQLite)** — required for delta reports and change detection
9. **EPSS scoring** — enriches CVE findings with exploitation probability
10. **Delta reports** — new vs resolved findings across scan runs
