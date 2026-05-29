# VaktScan — ASM Coverage TODO

Current state: port scan → service identification → CVE/vuln checks → web recon → DNS recon → JS analysis.

---

## 1. Missing Service / Protocol Modules

### Infrastructure & DevOps (High Value)

| Service | Ports | What to check |
|---|---|---|
| **Apache Tomcat** | 8080, 8443 | Manager UI default creds (`/manager/html`), CVE-2019-0232, PUT method RCE |
| **Spring Boot Actuator** | 8080, 8081, 8443 | `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`, `/actuator/logfile` |
| **Jupyter Notebook** | 8888, 8889 | Unauthenticated `/api/kernels` → direct RCE |
| **Apache Solr** | 8983 | Unauthenticated admin, CVE-2019-17558 (VelocityResponseWriter RCE) |
| **Apache Hadoop HDFS** | 50070, 9870 | Unauthenticated NameNode web UI — file listing/download |
| **Apache Hadoop YARN** | 8088 | Unauthenticated ResourceManager REST API — RCE via app submission |
| **ZooKeeper** | 2181 | `ruok`, `dump`, `stat` commands — unauthenticated config/cluster data |
| **Kafka** | 9092 | Unauthenticated broker — topic listing, message consumption |
| **RabbitMQ** | 15672, 5672 | Management UI default `guest:guest`, virtual host enum |
| **HashiCorp Consul** | 8500, 8501 | Unauthenticated KV store, service catalog, ACL bypass |
| **HashiCorp Vault** | 8200 | Unauthenticated `/v1/sys/health`, `/v1/sys/seal-status`, secret listing |
| **MinIO** | 9000, 9001 | Unauthenticated bucket listing, default `minioadmin:minioadmin` |
| **IPMI** | 623 | Cipher suite 0 auth bypass (`ipmitool -I lanplus -C 0`), hash capture |
| **Java RMI** | 1099, 1098 | BaRMIe enum, rmg.jar, beanshooter — deserialization gadget check |
| **WebLogic** | 7001, 7002, 4848 | CVE-2019-2725, CVE-2020-14882 (unauth RCE), `/console` default creds |
| **JBoss / WildFly** | 8080, 9990 | Unauthenticated admin console (`/jmx-console`, `/web-console`) |
| **GlassFish** | 4848 | Default `admin:` (blank password) on admin console |

### Monitoring & Observability

| Service | Ports | What to check |
|---|---|---|
| **Alertmanager** | 9093 | Unauthenticated — silence all alerts, read receiver configs |
| **Loki** | 3100 | Unauthenticated log query API |
| **Jaeger** | 16686 | Unauthenticated tracing UI — service/endpoint enumeration |
| **Zipkin** | 9411 | Unauthenticated trace data |
| **Splunk** | 8000, 8089 | Default `admin:changeme`, unauthenticated REST API |
| **Nagios / Zabbix** | 80, 10051 | Default creds, CVE checks |
| **Traefik** | 8080 | Dashboard exposed (`/dashboard/`), route enumeration |

### CI/CD & DevTools

| Service | Ports | What to check |
|---|---|---|
| **Jenkins** | 8080 | *(partially done)* Add CVE-2024-23897 (file read), CSRF bypass |
| **GitLab** | 80, 443 | Public projects, user enum via `/api/v4/users`, unauthenticated API |
| **Jira** | 8080 | Unauthenticated project listing, CVE-2022-0540 (auth bypass) |
| **Confluence** | 8090, 8443 | CVE-2023-22518, CVE-2022-26134 (OGNL RCE) — unauthenticated |
| **SonarQube** | 9000 | Default `admin:admin`, public project source code exposure |
| **Nexus Repository** | 8081 | Default `admin:admin123`, unauthenticated repo browsing |
| **Artifactory** | 8081, 8082 | Default `admin:password`, anonymous artifact access |
| **TeamCity** | 8111 | CVE-2024-27198 (auth bypass RCE), guest access |
| **Portainer** | 9000, 9443 | Unauthenticated Docker/K8s management, default creds |

### Cloud-Native

| Service | Ports | What to check |
|---|---|---|
| **ArgoCD** | 80, 443 | CVE-2022-29165 (auth bypass), unauthenticated API, default `admin:` |
| **Rancher** | 80, 443 | Unauthenticated API, default creds |
| **Istio/Envoy** | 15000, 15001 | Admin API exposed — config dump, traffic interception |
| **OpenTelemetry Collector** | 4317, 4318, 55679 | Unauthenticated gRPC/HTTP OTLP ingestion |

---

## 2. Missing Web Application Checks

### HTTP Security Headers Audit
- Missing: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
- Add to `domain_scan.py` or a new `headers_audit.py` module

### Exposed Sensitive Files & Paths
- `.git/` directory exposed (git repo clone possible)
- `.env` / `.env.local` / `.env.production` file exposed
- `phpinfo.php` / `info.php`
- `wp-config.php`, `config.php`, `database.yml`, `secrets.yml`
- Backup files: `.bak`, `.old`, `.zip`, `.tar.gz`, `~` suffix
- `/.well-known/security.txt` — parse for contact/scope info (positive signal)
- `/crossdomain.xml`, `/clientaccesspolicy.xml` — flash/Silverlight CORS
- `robots.txt` — enumerate disallowed paths as attack surface

### API Surface Discovery
- GraphQL introspection endpoint exposed (`/graphql`, `/api/graphql`)
- Swagger / OpenAPI spec exposed (`/swagger.json`, `/openapi.json`, `/api-docs`)
- gRPC reflection enabled (port 50051)
- OData endpoints (`/$metadata`)

### Authentication Issues
- Admin panels auto-detected and flagged: `/admin`, `/administrator`,
  `/wp-admin`, `/phpmyadmin`, `/adminer.php`
- HTTP Basic Auth prompts on sensitive paths (401 check)
- Default credential spray for detected CMS/apps (WordPress, Joomla, Drupal)

### SSL / TLS Gaps
- Certificate expiry < 30 days → WARNING, expired → CRITICAL
- Self-signed certificate detection
- Weak cipher suites (RC4, 3DES, NULL, EXPORT)
- Missing HSTS / HSTS preload
- Certificate CN mismatch

---

## 3. Missing Recon / Discovery

### Cloud Asset Discovery
- **AWS**: S3 bucket enumeration (permutation-based), CloudFront origin IP leak,
  EC2 metadata endpoint (169.254.169.254) SSRF indicator, public AMIs
- **Azure**: Blob storage enumeration, Azure AD tenant discovery
- **GCP**: GCS bucket enumeration, GCP metadata endpoint SSRF

### Passive Intelligence
- **Shodan** API integration — pull known open ports/banners for target IPs
- **Censys** API integration — certificate and host data
- **FOFA** / **Hunter.io** integration
- **GreyNoise** — tag IPs as scanners/bots vs real services
- **CISA KEV** cross-reference — flag CVEs on CISA Known Exploited list
- **EPSS scoring** — enrich CVE findings with exploitation probability

### Certificate Transparency
- Monitor CT logs for new subdomains (crt.sh polling, Certstream)
- Alert on newly issued certificates for target domain

### Email Security (Extend dns_recon)
- MX record banner grabbing (mail server version)
- SMTP open relay test
- Email spoofing simulation (SPF/DMARC bypass check)
- BIMI record check

---

## 4. Missing Vulnerability Correlation

- **Version → CVE mapping**: detected service version → NVD lookup → filter by CVSS ≥ 7
- **CPE generation** from banner strings for accurate CVE matching
- **Nuclei template sync**: auto-pull latest community templates before scan
- **Metasploit module cross-reference**: flag findings that have public exploit modules

---

## 5. Output / Reporting Gaps

- **SARIF output format** — for GitHub/GitLab security tab integration
- **JSON output** — machine-readable per-finding export
- **Severity deduplication across modules** — same CVE found by multiple modules counted once
- **Risk scoring per asset** — aggregate severity of all findings per IP/domain
- **Delta reports** — "new since last scan" vs "resolved since last scan"
- **Executive summary** — finding counts by severity, top 5 critical assets

---

## 6. Operational / Platform

- **Scan scheduling** — cron-based recurring scans per target
- **Asset inventory persistence** — SQLite/Postgres store of discovered assets across runs
- **Change detection** — alert when new port opens or service version changes
- **Rate limiting / politeness** — respect robots.txt, configurable req/s cap
- **Proxy support** — route scans through Burp / upstream proxy
- **IPv6 scanning** — currently IPv4 only

---

## Priority Order

1. **Spring Boot Actuator** — extremely common in enterprise, `/actuator/heapdump` = credentials
2. **Jupyter unauthenticated** — direct RCE, very common in data teams
3. **Exposed .git / .env files** — trivially exploitable, widespread
4. **HTTP security headers audit** — fast, zero network cost beyond existing httpx data
5. **Hadoop YARN unauthenticated RCE** — critical, often internet-exposed in cloud envs
6. **Consul / Vault unauthenticated** — common in Kubernetes clusters
7. **GraphQL introspection** — exposes full API schema unauthenticated
8. **SSL cert expiry** — ops visibility, low noise
9. **IPMI cipher 0** — critical on bare-metal infra
10. **Shodan/Censys passive enrichment** — zero-noise context with no active scanning
