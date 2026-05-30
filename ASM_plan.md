# VaktScan → Full-Fledged Attack Surface Management (ASM) Platform

> **Goal:** Evolve VaktScan from a one-shot CLI vulnerability scanner into a continuous,
> multi-tenant Attack Surface Management platform that **discovers, inventories, monitors,
> correlates, and prioritizes** an organization's external attack surface — comparable in
> scope to Tenable ASM, CrowdStrike Falcon Surface, Microsoft Defender EASM, Palo Alto
> Cortex Xpanse, Detectify, and ProjectDiscovery Cloud.

**Status:** Plan / blueprint. Created 2026-05-20.
**Target GA:** Phased delivery over 4 quarters (~12 months).

---

## 1. Executive Summary

VaktScan already has best-in-class building blocks for an ASM platform:
- Strong **active scanning core** (async, streaming, millions of IPs/chunked).
- Deep **service modules** (Elastic, Kibana, Grafana, Prometheus, Next.js, AEM, cPanel/WHM, DNS).
- Solid **passive recon** integrations (amass, subfinder, assetfinder, findomain, bbot, knockpy, censys, crt.sh).
- Real **HTTP probing** (httpx, nuclei, dirsearch, gau, waybackurls, nmap).
- Mature **subdomain-takeover** (58-signature table), **DNS surface** (SPF/DMARC/DKIM/AXFR/CAA/DNSSEC), **JS recon** with secrets/source-maps/internal-IP extraction.

What it does **not** have today:
- Persistent **asset inventory** with history, ownership, and diffs.
- **Continuous** (scheduled / event-driven) scanning.
- A **web UI**, **REST/GraphQL API**, **multi-tenancy**, or **RBAC**.
- **Cloud-native asset discovery** (AWS / Azure / GCP / Cloudflare / Fastly / Akamai).
- **Continuous CT-log monitoring**, **WHOIS / reverse-WHOIS**, **ASN/IP-range pivoting**.
- **CVE correlation engine** (NVD / EPSS / CISA-KEV / vendor advisories) with risk-scoring.
- **Notifications/alerting** (Slack, Teams, email, webhook, Jira, ServiceNow).
- **Brand / typosquatting / leaked-credential / public-repo / paste-site** monitoring.
- **Distributed worker pool** with queues, retries, rate-limit budgeting.

The plan below closes those gaps in four phases (**P0 → P3**) while preserving the existing
CLI as a first-class entry point.

---

## 2. Current Codebase Inventory (baseline)

| Layer | File / Module | Responsibility |
|---|---|---|
| Orchestrator | `main.py` | CLI argparse, scan lifecycle, CSV export, recon → scan pipeline |
| Targets | `utils.py` | IP/CIDR/hostname/URL parsing, resolution, URL builders |
| Port scan | `port_scanner.py` | Async TCP connect-scan, FD budgeting, progress reporter |
| Validation | `service_validator.py` | Per-port HTTP fingerprinting to confirm service identity |
| State | `scan_state.py` | Resumable scan state w/ checkpointing |
| Recon | `modules/recon.py` | Wrapper around amass/subfinder/assetfinder/findomain/sublist3r/knockpy/bbot/censys/crt.sh |
| HTTP probe | `modules/httpx_runner.py` | ProjectDiscovery httpx (binary or python lib) |
| Dir enum | `modules/dir_enum.py` | dirsearch + ffuf vhost fuzzing |
| Nuclei | `modules/nuclei_runner.py` | ProjectDiscovery nuclei wrapper |
| Nmap | `modules/nmap_runner.py` | Full-range port + `-sCV -Pn` follow-up |
| URL harvest | `modules/gau_runner.py`, `modules/waybackurls_runner.py` | Historical URL ingestion |
| Domain scan | `modules/domain_scan.py` | Classification + takeover detection (58 sigs) + anomaly checks |
| DNS | `modules/dns_recon.py` | Stdlib DNS wire-format, SPF/DMARC/DKIM/AXFR/recursion/CAA |
| JS recon | `modules/js_paths.py` | 12+ path-extractors, secret detection, source-maps |
| Service modules | `modules/{elastic,kibana,grafana,prometheus,react_to_shell,aem,cpanel}.py` | Service-specific CVE + misconfig probes |
| Data | `modules/data/` | cPanel TSR archive, bundled CVE matrix, must-call-out CVEs |
| Tests | `tests/test_*.py` | 56 tests, ~10 test files covering dedup, oracles, takeover, DNS, JS, port scanner |
| Scripts | `scripts/` | Tool installer, CVE/TSR data builders, coverage verifier |

**Languages:** Python only · **Files:** 37 · **Nodes:** 529 · **Edges:** 5,036.

This is a single-process, single-tenant, file-output CLI. Everything below is additive — the
CLI must keep working.

---

## 3. Gap Analysis vs. Industry ASM

The ASM problem space is conventionally split into five pillars. Below is what VaktScan has
vs. what a full-fledged ASM needs.

| Pillar | VaktScan today | Full ASM needs | Gap |
|---|---|---|---|
| **1. Discovery (External)** | Subdomain enum, DNS, JS recon, port scan | Seed-based discovery (domains, IPs, ASNs, orgs, CIDRs, emails, brands). Reverse-WHOIS, ASN expansion, CT logs (continuous), favicon-hash pivoting, JARM, passive DNS, BGP, Shodan/Censys/FOFA/Quake APIs, GitHub/GitLab dorking, paste/leak monitoring, mobile-app store crawl, SaaS-app discovery, typosquat/dnstwist | **Large** |
| **2. Inventory** | None (CSV only) | Persistent DB of assets (domain, host, IP, cert, port, service, tech, owner, env, tag), provenance, confidence, first/last seen, change events, hierarchical tags, BU/team ownership | **Critical** |
| **3. Analysis / Risk** | Per-scan CVE checks, signature-based; CSV output | Real-time CVE correlation (NVD + EPSS + CISA-KEV + GHSA + vendor feeds), risk score (CVSS + exploitability + asset criticality + exposure), exploit-availability flag, business-context weighting, prioritization queues | **Large** |
| **4. Monitoring / Continuous** | One-shot CLI | Scheduled (cron, interval) and event-driven scans, diff engine ("new subdomain", "cert expiring in 14 d", "port newly open"), drift detection, baseline + delta, rate-limit budgets per target | **Critical** |
| **5. Reporting / Workflow** | CSV file | Web UI, REST/GraphQL API, dashboards, executive PDF, JSON/STIX/CSV export, Slack/Teams/email/webhook alerts, Jira/ServiceNow/Linear ticket sync, SAML/SSO + RBAC, audit log | **Critical** |

There are also cross-cutting gaps:

- **Multi-tenancy** (orgs, workspaces, users, roles, scopes).
- **Distributed scanning** (workers, queues, regional egress, IPv6).
- **Authenticated scanning** (Burp/ZAP-style cookie + header injection).
- **Cloud asset discovery** (AWS/Azure/GCP/Cloudflare/Fastly/Akamai via API or DNS heuristics).
- **Compliance mapping** (PCI-DSS, HIPAA, ISO 27001, SOC 2 control linkage).
- **Observability** (Prometheus metrics, OpenTelemetry traces, structured logs).
- **Supply-chain surface** (third-party JS, SaaS vendors, dependency CVEs).

---

## 4. Target Architecture

```
                    ┌──────────────────────────────────────────────────────────┐
                    │                    USERS / SSO (OIDC)                     │
                    └────────────────┬─────────────────────────────────────────┘
                                     │
                  ┌──────────────────▼──────────────────┐   ┌────────────────┐
                  │            Web UI (Next.js)          │   │   CLI (today)  │
                  │  Dashboard / Inventory / Findings    │   │   main.py      │
                  └──────────────────┬──────────────────┘   └───────┬────────┘
                                     │ REST + GraphQL                │
                                     │                               │
                  ┌──────────────────▼──────────────────────────────▼─────────┐
                  │                   API Gateway (FastAPI)                    │
                  │  Auth (OIDC/JWT) · RBAC · Rate-limit · Audit log           │
                  └─┬──────────────┬──────────────────┬──────────────┬────────┘
                    │              │                  │              │
        ┌───────────▼─┐  ┌─────────▼────────┐  ┌──────▼───────┐  ┌──▼──────────┐
        │ Inventory    │  │ Scan Scheduler  │  │ Risk Engine  │  │ Alerts /    │
        │ Service      │  │ (APScheduler /  │  │ (CVE corr.,  │  │ Webhooks    │
        │ (assets,     │  │  Celery beat)   │  │  EPSS, KEV)  │  │  Slack/Jira │
        │  graphs,     │  └─────────┬────────┘  └──────┬───────┘  └──┬──────────┘
        │  diffs)      │            │                  │             │
        └──┬───────────┘            │                  │             │
           │                        ▼                  ▼             ▼
           │             ┌───────────────────┐   ┌──────────────────────────┐
           │             │  Task Queue       │   │  Notification Bus        │
           │             │  (Redis/RabbitMQ) │   │  (Kafka or Redis stream) │
           │             └─────┬─────────────┘   └──────────────────────────┘
           │                   │
           │       ┌───────────┴────────────┐
           │       ▼           ▼            ▼
           │   ┌────────┐  ┌────────┐  ┌────────┐    Worker pool (horizontal):
           │   │ Worker │  │ Worker │  │ Worker │    - Discovery jobs
           │   │  (k8s) │  │  (k8s) │  │  (k8s) │    - Port + service scans
           │   └────┬───┘  └────┬───┘  └────┬───┘    - Nuclei, dirsearch
           │        │           │           │        - DNS, CT, WHOIS, ASN
           │        ▼           ▼           ▼        - JS recon, secret scan
           │   ┌────────────────────────────────┐
           │   │   VaktScan Core (today's code) │
           │   │   - port_scanner, validators   │
           │   │   - modules/*                  │
           │   │   - recon wrappers             │
           │   └─────────────┬──────────────────┘
           │                 │ findings
           ▼                 ▼
   ┌────────────────────────────────────────────┐    ┌───────────────────────┐
   │  PostgreSQL (assets, findings, jobs, users)│    │  Object store (S3-API)│
   │  + TimescaleDB (timeseries: ports, certs)  │    │  raw artifacts, PDFs  │
   │  + OpenSearch (full-text on findings, JS)  │    │  HTML response bodies │
   │  + Redis (cache, queues, locks, rate-lim.) │    │  nuclei JSON, nmap XML│
   └────────────────────────────────────────────┘    └───────────────────────┘
                 │                          ▲
                 ▼                          │
         ┌────────────────┐        ┌────────────────┐
         │ Threat Feeds   │        │  External APIs │
         │ NVD, EPSS, KEV │        │ Shodan, Censys │
         │ GHSA, OSV      │        │ crt.sh, RDAP   │
         │ CIRCL, vendor  │        │ HIBP, GitHub   │
         └────────────────┘        └────────────────┘
```

**Design tenets:**
1. **CLI remains a first-class client** — the same code paths run from CLI or worker.
2. **Stateless workers, stateful core.** Workers pull from queue, write to DB, emit events.
3. **Idempotent scans.** Same input + same module version ⇒ same canonical finding key.
4. **Provenance everywhere.** Every asset / finding tagged with `source`, `confidence`, `first_seen`, `last_seen`, `evidence_url`.
5. **Open by default.** Open-source core with optional commercial integrations.

---

## 5. Feature Catalog

Organized by ASM pillar. Each feature lists **status** (✅ exists / 🟡 partial / ⬜ new),
the **proposed module/path**, and the **phase** it lands in.

### 5.1 Discovery — External

| # | Feature | Status | Module | Phase |
|---|---|---|---|---|
| D1 | Seed types: domain, host, IP, CIDR, ASN, org, email, brand-name | 🟡 (domain/IP/CIDR) | `seeds/` + DB table `seeds` | P1 |
| D2 | Subdomain enumeration (amass, subfinder, assetfinder, findomain, bbot, knockpy) | ✅ | `modules/recon.py` | — |
| D3 | Certificate Transparency monitoring (continuous, not one-shot) | 🟡 (one-shot crt.sh) | `modules/ct_monitor.py` (new) + scheduler | P1 |
| D4 | Reverse-WHOIS / RDAP lookup → org → domains | ⬜ | `modules/rdap.py` (new) | P1 |
| D5 | ASN expansion → BGP prefixes → IP ranges | ⬜ | `modules/asn_expander.py` (new) | P1 |
| D6 | Favicon-hash pivoting (Shodan-style) | ⬜ | `modules/favicon_hash.py` (new) | P2 |
| D7 | JARM / JA3S fingerprint pivoting | ⬜ | `modules/jarm.py` (new) | P2 |
| D8 | Passive DNS (Mnemonic, SecurityTrails, CIRCL) | ⬜ | `modules/pdns.py` (new) | P2 |
| D9 | Shodan / Censys / FOFA / Quake / ZoomEye search API | 🟡 (censys cli) | `modules/internet_search.py` (new) | P1 |
| D10 | DNS brute-force w/ wildcard handling (puredns / massdns) | 🟡 (knockpy/bbot) | `modules/dns_bruteforce.py` (new) | P2 |
| D11 | Typosquat / look-alike domains (dnstwist, urlcrazy) | ⬜ | `modules/typosquat.py` (new) | P2 |
| D12 | Public-repo dorking (GitHub/GitLab/Bitbucket code search) | ⬜ | `modules/scm_dorks.py` (new) | P3 |
| D13 | Paste-site monitoring (Pastebin, Ghostbin, paste.ee) | ⬜ | `modules/paste_monitor.py` (new) | P3 |
| D14 | Mobile-app discovery (Play Store / App Store crawl) | ⬜ | `modules/mobile_apps.py` (new) | P3 |
| D15 | SaaS-app inventory (DNS heuristics: zendesk, salesforce, atlassian) | ⬜ | `modules/saas_detect.py` (new) | P3 |
| D16 | JS endpoint extraction (12+ strategies) | ✅ | `modules/js_paths.py` | — |
| D17 | URL history harvest (gau, waybackurls) | ✅ | `modules/{gau,waybackurls}_runner.py` | — |
| D18 | Cloud asset discovery — AWS (S3, CloudFront, ELB, EC2 PTRs) | ⬜ | `modules/cloud/aws.py` (new) | P2 |
| D19 | Cloud asset discovery — Azure (Front Door, Blob, App Service) | ⬜ | `modules/cloud/azure.py` (new) | P2 |
| D20 | Cloud asset discovery — GCP (Cloud Storage, GCE, Cloud Run) | ⬜ | `modules/cloud/gcp.py` (new) | P2 |
| D21 | CDN attribution (Cloudflare, Fastly, Akamai, CloudFront) via CNAME + ASN | ⬜ | `modules/cdn_attr.py` (new) | P2 |

### 5.2 Inventory

| # | Feature | Status | Module / Path | Phase |
|---|---|---|---|---|
| I1 | Asset model: domain / host / ip / port / service / cert / tech / url / cloud-resource / repo / mobile-app | ⬜ | `core/models/` + Postgres schema | P0 |
| I2 | Provenance per asset (source module, confidence, first/last seen, evidence ref) | ⬜ | `core/models/provenance.py` | P0 |
| I3 | Ownership tags (BU, team, owner email, env=prod/stage/dev, criticality) | ⬜ | `core/models/ownership.py` + UI | P1 |
| I4 | Asset graph (relationships: domain → host → ip → port → service → cve) | ⬜ | Postgres adjacency table + optional Neo4j | P2 |
| I5 | Change events (new asset, removed asset, mutated tech, cert rotated) | ⬜ | `core/diff_engine.py` | P1 |
| I6 | Confidence scoring (multi-source corroboration boosts confidence) | ⬜ | `core/confidence.py` | P1 |
| I7 | Soft-delete + dedup across sources (canonical asset key) | ⬜ | `core/canonical.py` | P0 |
| I8 | Tech fingerprinting (Wappalyzer-style, ~3,000 sig DB) | 🟡 (httpx tech) | `modules/tech_fingerprint.py` (new) | P1 |
| I9 | TLS/cert inventory (SAN, issuer, validity, weak ciphers, expiry tracking) | 🟡 (TLS posture) | `modules/cert_inventory.py` (new) | P1 |
| I10 | Hostname/IP/cert pivots ("show me everything sharing this cert / IP / ASN") | ⬜ | UI + API | P2 |

### 5.3 Vulnerability / Risk Analysis

| # | Feature | Status | Module | Phase |
|---|---|---|---|---|
| V1 | Service-specific CVE modules (Elastic, Kibana, Grafana, Prometheus, AEM, cPanel, Next.js) | ✅ | `modules/*.py` | — |
| V2 | Nuclei integration with severity filtering | ✅ | `modules/nuclei_runner.py` | — |
| V3 | DNS misconfig surface (SPF/DMARC/DKIM/AXFR/CAA/DNSSEC) | ✅ | `modules/dns_recon.py` | — |
| V4 | Subdomain takeover (58-sig table) | ✅ | `modules/domain_scan.py` | — |
| V5 | Continuous CVE feed ingest (NVD JSON 2.0, daily delta) | ⬜ | `feeds/nvd.py` (new) + scheduler | P1 |
| V6 | EPSS (exploit-probability) ingest | ⬜ | `feeds/epss.py` (new) | P1 |
| V7 | CISA-KEV (known-exploited) ingest | ⬜ | `feeds/kev.py` (new) | P1 |
| V8 | GHSA / OSV ingest for OSS components | ⬜ | `feeds/ghsa.py` (new) | P2 |
| V9 | Risk score = f(CVSS, EPSS, KEV, asset criticality, exposure) | ⬜ | `core/risk_engine.py` | P1 |
| V10 | Auto-correlation: tech-stack → CVE list per asset | ⬜ | `core/correlator.py` | P1 |
| V11 | Exposure score (auth required? internal? auth bypass?) | ⬜ | `core/exposure.py` | P2 |
| V12 | Secrets in JS / CT / public-repo (extend `js_paths` to all sources) | 🟡 | `modules/secret_scanner.py` | P2 |
| V13 | Authenticated scanning (cookie/header/Bearer injection) | ⬜ | `modules/auth_scan.py` (new) | P3 |
| V14 | API surface (OpenAPI/Swagger discovery + endpoint enumeration) | ⬜ | `modules/api_discovery.py` (new) | P3 |
| V15 | GraphQL introspection + abuse checks | ⬜ | `modules/graphql_scan.py` (new) | P3 |
| V16 | Cloud config exposure (open S3, public RDS snapshot, public blob) | ⬜ | `modules/cloud/exposure.py` (new) | P2 |
| V17 | Credential-leak correlation (HIBP / DeHashed / Constella API) | ⬜ | `modules/cred_leak.py` (new) | P3 |
| V18 | Compliance mapping (PCI / HIPAA / ISO / SOC2 controls per finding) | ⬜ | `core/compliance.py` | P3 |
| V19 | False-positive suppression rules (per-org, per-rule, per-asset) | 🟡 (per-module dedup) | `core/suppression.py` | P1 |

### 5.4 Monitoring / Continuous

| # | Feature | Status | Module | Phase |
|---|---|---|---|---|
| M1 | Scheduled scans (cron-like, per-workspace) | ⬜ | `scheduler/` (APScheduler) | P0 |
| M2 | Distributed worker pool (Celery + Redis or Dramatiq) | ⬜ | `workers/` | P0 |
| M3 | Per-target rate-limit budget (RPS, concurrency) | 🟡 (per-CLI) | `core/budget.py` | P1 |
| M4 | Job retries / DLQ / poison-pill handling | ⬜ | queue config | P0 |
| M5 | Diff engine: emits events on inventory delta | ⬜ | `core/diff_engine.py` | P1 |
| M6 | Cert-expiry watcher (alerts 30/14/7/1 days out) | ⬜ | `monitors/cert_expiry.py` | P1 |
| M7 | Drift detection (port newly open, tech changed, banner changed) | ⬜ | `monitors/drift.py` | P1 |
| M8 | Continuous CT-log subscription (Calidog / CertStream) | ⬜ | `monitors/ct_stream.py` | P2 |
| M9 | Backoff / re-queue on transient errors | 🟡 | queue config | P0 |
| M10 | Per-module circuit breaker on repeated failures | ⬜ | `core/circuit_breaker.py` | P1 |

### 5.5 Reporting / Workflow / UX

| # | Feature | Status | Module | Phase |
|---|---|---|---|---|
| R1 | CSV export | ✅ | `main.py::save_results_to_csv` | — |
| R2 | JSON export (per-finding NDJSON) | ⬜ | `exporters/json.py` | P0 |
| R3 | STIX 2.1 + SARIF export | ⬜ | `exporters/{stix,sarif}.py` | P2 |
| R4 | Executive PDF report | ⬜ | `exporters/pdf.py` (WeasyPrint) | P2 |
| R5 | REST API (FastAPI) | ⬜ | `api/` | P0 |
| R6 | GraphQL API (Strawberry) | ⬜ | `api/graphql.py` | P2 |
| R7 | Web UI dashboard (Next.js + Tailwind + shadcn/ui) | ⬜ | `web/` | P1 |
| R8 | Inventory browser w/ facets (tech, env, owner, severity, age) | ⬜ | `web/inventory/` | P1 |
| R9 | Asset detail view (graph, history, evidence, findings) | ⬜ | `web/asset/` | P1 |
| R10 | Findings queue (triage, assign, suppress, resolve) | ⬜ | `web/findings/` | P1 |
| R11 | Slack / Teams / Discord webhook alerts | ⬜ | `integrations/chatops.py` | P1 |
| R12 | Email alerts (SendGrid / SES / SMTP) | ⬜ | `integrations/email.py` | P1 |
| R13 | Jira / ServiceNow / Linear ticket sync | ⬜ | `integrations/ticketing.py` | P2 |
| R14 | SIEM / SOAR push (Splunk HEC, Sentinel, Cortex XSOAR) | ⬜ | `integrations/siem.py` | P3 |
| R15 | OIDC SSO (Auth0, Okta, Azure AD, Google) | ⬜ | `api/auth.py` | P1 |
| R16 | RBAC (Owner / Admin / Analyst / Read-only) | ⬜ | `api/rbac.py` | P1 |
| R17 | Audit log (all writes + admin reads) | ⬜ | `api/audit.py` | P1 |
| R18 | Multi-tenant orgs / workspaces / scopes | ⬜ | `core/tenancy.py` | P1 |
| R19 | API tokens (scoped, revocable) | ⬜ | `api/tokens.py` | P1 |
| R20 | Prometheus metrics endpoint + OpenTelemetry traces | ⬜ | `observability/` | P0 |

---

## 6. Phased Roadmap

Goal: ship value every phase. Each phase ends with a tagged release and a usable product.

### **Phase 0 — Foundations** (≈ 4–6 weeks, 1 release: `v1.0.0-asm`)

> Make VaktScan a **service**, not just a CLI. Stand up DB, API, queue, workers. Keep CLI working.

- [ ] **0.1** Migrate to a `vaktscan/` Python package (proper `pyproject.toml`).
  Split `main.py` into `vaktscan/cli/`, `vaktscan/core/`, `vaktscan/modules/`.
- [ ] **0.2** Postgres schema v1 (`alembic`):
  - `orgs`, `workspaces`, `users`, `api_tokens`
  - `seeds`, `assets`, `assets_provenance`, `findings`, `evidence`
  - `scan_jobs`, `scan_runs`, `scan_events`
- [ ] **0.3** Redis + Celery (or Dramatiq) worker. Move recon + scan modules behind the queue.
  Workers import the same `modules/*` code paths — no logic duplication.
- [ ] **0.4** Canonical asset key + dedup (`core/canonical.py`).
- [ ] **0.5** FastAPI app with `/healthz`, `/seeds`, `/assets`, `/findings`, `/jobs` (read-only initially).
- [ ] **0.6** Result writer: every module now writes to Postgres (in addition to today's CSV).
- [ ] **0.7** Docker Compose for local dev (postgres + redis + api + worker + minio).
- [ ] **0.8** Prometheus `/metrics`, structured JSON logs, OpenTelemetry traces.
- [ ] **0.9** Keep `python main.py targets.txt …` working unchanged via a shim that wraps the new core.
- [ ] **0.10** CI: `pytest`, `ruff`, `mypy`, container build, schema migration check.

**Exit criteria:** `vaktscan-api`, `vaktscan-worker`, and the existing CLI all run from a single
`docker compose up`. Findings land in Postgres. Existing 56 tests still pass.

---

### **Phase 1 — ASM Core** (≈ 8–10 weeks, release: `v1.1.0-asm`)

> Become a real **ASM platform**: scheduling, diffs, alerts, basic UI, CVE correlation, ownership.

- [ ] **1.1** Scheduler (APScheduler + cron strings). Per-workspace recurring scans.
- [ ] **1.2** Diff engine: detect `new`, `removed`, `mutated` for every asset class. Emit events.
- [ ] **1.3** CVE feed ingest (NVD JSON 2.0 + CISA-KEV + EPSS). Nightly job.
- [ ] **1.4** Risk engine v1: `risk = severity_weight × (1 + 5·KEV) × (1 + 2·EPSS) × asset_criticality × exposure`.
- [ ] **1.5** Tech fingerprint module (Wappalyzer rules YAML; ship 3,000+ sigs).
- [ ] **1.6** Cert inventory + expiry watcher.
- [ ] **1.7** Reverse-WHOIS / RDAP module.
- [ ] **1.8** ASN expander (Team Cymru whois / RIPEstat).
- [ ] **1.9** Continuous CT-log monitoring (Calidog CertStream or polling crt.sh).
- [ ] **1.10** Internet-search adapters: Shodan, Censys, FOFA (pluggable, API-key-gated).
- [ ] **1.11** Notifications: Slack + email + generic webhook. Per-rule severity threshold.
- [ ] **1.12** Web UI v1 (Next.js): Dashboard, Inventory, Findings, Seeds, Settings.
- [ ] **1.13** OIDC SSO (Auth0/Okta/Azure AD/Google) + RBAC (Owner/Admin/Analyst/RO).
- [ ] **1.14** Multi-tenant orgs/workspaces + API tokens.
- [ ] **1.15** Audit log table + write hooks on all mutating endpoints.
- [ ] **1.16** Suppression rules (regex on asset / finding fields, expiry, reason, author).
- [ ] **1.17** Per-target rate-limit budget (token-bucket per host/per-ASN).

**Exit criteria:** A user can sign in, add a seed domain, see assets/findings populate over
24 h, get Slack/email alerts on new criticals, see risk-ranked findings, mark items as
"accepted risk" with expiry.

---

### **Phase 2 — Breadth + Cloud + Graph** (≈ 8–10 weeks, release: `v1.2.0-asm`)

> Expand discovery into cloud + non-web surface. Deeper graph. Richer integrations.

- [ ] **2.1** Cloud-native discovery: AWS, Azure, GCP via read-only API keys (or DNS heuristics).
- [ ] **2.2** Cloud-config exposure: open S3 / public Blob / public GCS / public RDS snapshots.
- [ ] **2.3** CDN attribution (CNAME + ASN → Cloudflare/Fastly/Akamai/CloudFront/Akamai/Google).
- [ ] **2.4** Favicon-hash pivoting + JARM/JA3S fingerprinting.
- [ ] **2.5** Passive-DNS adapter (Mnemonic, SecurityTrails, CIRCL, DNSDB).
- [ ] **2.6** DNS brute-force with massdns / puredns (high-RPS recursive).
- [ ] **2.7** Typosquat / look-alike (dnstwist core re-implemented or wrapped).
- [ ] **2.8** GHSA / OSV ingest + SBOM upload + dep-CVE correlation.
- [ ] **2.9** Asset-graph viewer (frontend): cluster of related assets via shared cert / IP / favicon / ASN.
- [ ] **2.10** Pivots in UI: "show me everything sharing this cert / IP / favicon hash / ASN".
- [ ] **2.11** Jira / ServiceNow / Linear ticket sync (bi-directional status).
- [ ] **2.12** STIX 2.1 + SARIF export.
- [ ] **2.13** Exec PDF report (WeasyPrint, branded).
- [ ] **2.14** GraphQL API.
- [ ] **2.15** Secrets scanner expansion: scan **all** sources (JS, CT names, recon outputs).
- [ ] **2.16** Exposure score (auth-required vs anon, internal vs external, behind-WAF).
- [ ] **2.17** Circuit breaker per module (auto-disable a misbehaving check).

**Exit criteria:** Single workspace covers domain, cloud, cert, and component-CVE attack
surface end-to-end. Tickets auto-flow to Jira. Exec PDF goes out weekly.

---

### **Phase 3 — Brand, Supply-chain, Advanced Coverage** (≈ 10–12 weeks, release: `v1.3.0-asm`)

> Cover the long tail: brand / typo / repo / paste / mobile / SaaS / authenticated / API.

- [ ] **3.1** GitHub / GitLab / Bitbucket dorking (org-scoped + global secret keyword scan).
- [ ] **3.2** Paste-site monitoring (Pastebin/Ghostbin/paste.ee/throwbin).
- [ ] **3.3** HIBP / DeHashed / Constella credential-leak correlation.
- [ ] **3.4** Mobile-app discovery (Play Store, App Store scraping → APK/IPA metadata).
- [ ] **3.5** SaaS-app inventory (DNS-CNAME heuristics + login-page recognition).
- [ ] **3.6** Authenticated scanning: cookie/header/Bearer injection profile per asset.
- [ ] **3.7** OpenAPI/Swagger discovery + endpoint enumeration + fuzzing.
- [ ] **3.8** GraphQL introspection + abuse checks.
- [ ] **3.9** SIEM / SOAR push (Splunk HEC, Sentinel, XSOAR, Chronicle).
- [ ] **3.10** Compliance mapping (PCI-DSS 4.0, HIPAA, ISO 27001 A.12, SOC 2 CC).
- [ ] **3.11** "What changed this week" weekly digest UI + email.
- [ ] **3.12** Bring-your-own-nuclei-templates and bring-your-own-Wappalyzer-rules.
- [ ] **3.13** Plugin SDK (Python entry-points) for third-party modules.
- [ ] **3.14** Multi-region scanner pool (egress IP affinity, geo-aware routing).

**Exit criteria:** VaktScan ASM covers ~90% of the categories enumerated by EASM analyst
reports (Gartner Magic Quadrant, Forrester Wave). Plugin SDK + docs published.

---

## 7. Data Model (Phase 0/1 baseline)

Postgres tables (Alembic-managed). Names are illustrative; final schema lives in
`alembic/versions/`.

```sql
-- Tenancy
CREATE TABLE orgs            (id UUID PK, name TEXT, slug TEXT UNIQUE, created_at TIMESTAMPTZ);
CREATE TABLE workspaces      (id UUID PK, org_id UUID FK, name TEXT, created_at TIMESTAMPTZ);
CREATE TABLE users           (id UUID PK, email CITEXT UNIQUE, oidc_subject TEXT, created_at TIMESTAMPTZ);
CREATE TABLE memberships     (org_id UUID FK, user_id UUID FK, role TEXT, PRIMARY KEY (org_id, user_id));
CREATE TABLE api_tokens      (id UUID PK, workspace_id UUID FK, hash TEXT, scopes TEXT[], expires_at TIMESTAMPTZ);

-- Seeds (the inputs the user owns)
CREATE TABLE seeds (
    id UUID PRIMARY KEY,
    workspace_id UUID REFERENCES workspaces(id),
    kind TEXT CHECK (kind IN ('domain','ip','cidr','asn','org','email','brand')),
    value TEXT,
    in_scope BOOLEAN DEFAULT TRUE,
    tags JSONB,
    created_at TIMESTAMPTZ
);

-- Canonical assets
CREATE TABLE assets (
    id UUID PRIMARY KEY,
    workspace_id UUID REFERENCES workspaces(id),
    kind TEXT CHECK (kind IN
        ('domain','host','ip','port','service','cert','tech','url',
         'cloud_resource','repo','mobile_app','saas_app')),
    canonical_key TEXT,           -- deterministic dedup key, UNIQUE(workspace_id, canonical_key)
    attributes JSONB,             -- kind-specific structured data
    parent_asset_id UUID REFERENCES assets(id),
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    confidence FLOAT,             -- 0..1
    ownership JSONB,              -- {owner_email, bu, team, env, criticality}
    UNIQUE (workspace_id, canonical_key)
);
CREATE INDEX ON assets (workspace_id, kind);
CREATE INDEX ON assets USING GIN (attributes jsonb_path_ops);

CREATE TABLE asset_provenance (
    asset_id UUID FK,
    source TEXT,                  -- 'amass','subfinder','crt.sh','ct-stream','manual', ...
    evidence_ref TEXT,            -- pointer into S3-object-store
    confidence FLOAT,
    seen_at TIMESTAMPTZ,
    PRIMARY KEY (asset_id, source, seen_at)
);

CREATE TABLE asset_relationships (
    src_asset_id UUID FK,
    dst_asset_id UUID FK,
    kind TEXT CHECK (kind IN ('resolves_to','hosts','signed_by','shares_cert','shares_favicon','shares_asn','runs')),
    PRIMARY KEY (src_asset_id, dst_asset_id, kind)
);

-- Findings (the security events)
CREATE TABLE findings (
    id UUID PRIMARY KEY,
    workspace_id UUID FK,
    asset_id UUID FK,
    rule_id TEXT,                  -- 'cpanel.cve-2023-29489','dns.spf.plus_all', ...
    severity TEXT CHECK (severity IN ('critical','high','medium','low','info')),
    status TEXT CHECK (status IN ('open','triaged','accepted','resolved','suppressed')) DEFAULT 'open',
    title TEXT,
    description TEXT,
    cve_ids TEXT[],
    evidence JSONB,                -- request/response/snippet/payload_url
    risk_score FLOAT,              -- computed
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    assigned_to UUID FK users(id),
    UNIQUE (workspace_id, asset_id, rule_id)   -- idempotent
);
CREATE INDEX ON findings (workspace_id, severity, status);

-- Change feed
CREATE TABLE asset_events (
    id BIGSERIAL PRIMARY KEY,
    workspace_id UUID FK,
    asset_id UUID FK,
    event_kind TEXT CHECK (event_kind IN
        ('asset_new','asset_removed','asset_mutated',
         'finding_new','finding_resolved','cert_expiring','tech_changed','banner_changed')),
    diff JSONB,
    occurred_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX ON asset_events (workspace_id, occurred_at DESC);

-- Jobs / scheduler
CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY,
    workspace_id UUID FK,
    name TEXT,
    cron TEXT,                    -- nullable for one-off
    spec JSONB,                   -- {modules:[…], seeds:[…], options:{…}}
    enabled BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ
);
CREATE TABLE scan_runs (
    id UUID PRIMARY KEY,
    job_id UUID FK,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    status TEXT,                  -- queued/running/success/partial/failed
    stats JSONB                   -- {assets_new, findings_new, errors, durations}
);

-- Threat feeds (cached locally)
CREATE TABLE cve_records (
    cve_id TEXT PRIMARY KEY,
    published_at TIMESTAMPTZ,
    cvss_v3 FLOAT,
    cvss_v4 FLOAT,
    epss FLOAT,
    kev BOOLEAN,
    cpes TEXT[],
    raw JSONB
);

-- Audit
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    workspace_id UUID,
    actor_user_id UUID,
    actor_token_id UUID,
    action TEXT,
    target_kind TEXT,
    target_id TEXT,
    payload JSONB,
    occurred_at TIMESTAMPTZ DEFAULT now()
);
```

**TimescaleDB hypertables** (optional, P1+):
- `port_observations(asset_id, port, open, observed_at)`
- `cert_observations(cert_id, issuer, valid_until, observed_at)`

**OpenSearch indices** (P1+):
- `findings_*` — full-text on title/description/evidence
- `js_paths_*` — secret/path search
- `audit_*` — audit log search

---

## 8. Tech-Stack Recommendations

Pick boring, proven tech. Everything below has an OSS license + a cloud-managed option.

| Concern | Choice | Why |
|---|---|---|
| Language | Python 3.12 (core), TypeScript (UI) | Current code is Python; team continuity |
| API framework | **FastAPI** | Pydantic v2 + native OpenAPI + async fits existing async modules |
| Queue / workers | **Celery 5** + **Redis** (or **Dramatiq** + Redis) | Mature, supports cron beat |
| DB | **PostgreSQL 16** + **TimescaleDB** ext. (optional) | JSONB, GIN indexes, time-series for observations |
| Search | **OpenSearch 2.x** (or **Postgres FTS** in P0) | Full-text on findings/JS |
| Object store | **MinIO** (S3-API) / AWS S3 | Raw artifacts (HTTP bodies, nuclei JSON, nmap XML, PDFs) |
| Cache / locks / rate-limit | **Redis** | Same instance as queue |
| Scheduler | **APScheduler** (P0) → **Celery beat** (P1) | Cron strings + workspace-scoped |
| Auth | **Authlib** + OIDC (Auth0/Okta/Azure AD/Google) | Off-the-shelf SSO |
| UI | **Next.js 15 (App Router) + TypeScript + Tailwind + shadcn/ui** | Modern, accessible, fast |
| Charts | **Recharts** or **Tremor** | Dashboards |
| Tests | `pytest` + `pytest-asyncio` + `httpx`-MockTransport + `testcontainers` | Already partial; add containers |
| Migrations | **Alembic** | Standard with SQLAlchemy 2.x |
| Lint / type | **ruff** + **mypy --strict** + **pre-commit** | Already needed |
| Observability | **OpenTelemetry** SDK → **OTLP** → Grafana/Tempo/Loki | Standard |
| Metrics | **Prometheus** client + `/metrics` endpoint | Standard |
| Container | **Docker** + **docker-compose** (dev), **Helm chart** (prod) | Standard |
| Deploy | Kubernetes (AKS/EKS/GKE) or single-node Compose | Both supported by Helm |
| Secrets | **HashiCorp Vault** OR cloud KMS | API keys (Shodan, Censys, etc.) |
| Notifications | Slack/Teams webhooks, SendGrid/SES, generic POST webhook | Off-the-shelf |
| Ticketing | Jira REST v3, ServiceNow Table API, Linear GraphQL | OSS clients exist |

---

## 9. Module-Level Implementation Plan

### 9.1 Core layer (`vaktscan/core/`)

```
vaktscan/
├── core/
│   ├── canonical.py        # canonical_key(asset_kind, attrs) -> str  (idempotent)
│   ├── confidence.py       # multi-source corroboration math
│   ├── diff_engine.py      # diff(prev_snapshot, new_snapshot) -> [events]
│   ├── risk_engine.py      # risk(asset, finding) -> float
│   ├── exposure.py         # exposure(asset) -> 0..1
│   ├── correlator.py       # tech + cve_db -> [findings]
│   ├── suppression.py      # apply suppression rules
│   ├── budget.py           # per-target token-bucket
│   ├── circuit_breaker.py  # module-level CB
│   ├── tenancy.py          # workspace/org guards
│   ├── models/             # SQLAlchemy 2.x models + Pydantic schemas
│   └── repositories/       # DB repositories (one per aggregate)
```

### 9.2 Modules layer (existing + new)

Existing modules stay where they are; each grows a thin **`Source` adapter** that yields
canonical asset/finding records into the queue. New modules listed in §5 above.

```
modules/
├── recon.py              ✅ keep
├── dns_recon.py          ✅ keep
├── domain_scan.py        ✅ keep
├── js_paths.py           ✅ keep
├── httpx_runner.py       ✅ keep
├── nuclei_runner.py      ✅ keep
├── nmap_runner.py        ✅ keep
├── dir_enum.py           ✅ keep
├── gau_runner.py         ✅ keep
├── waybackurls_runner.py ✅ keep
├── elastic.py            ✅ keep
├── kibana.py             ✅ keep
├── grafana.py            ✅ keep
├── prometheus.py         ✅ keep
├── react_to_shell.py     ✅ keep
├── aem.py                ✅ keep
├── cpanel.py             ✅ keep
├── ct_monitor.py         🆕 P1
├── rdap.py               🆕 P1
├── asn_expander.py       🆕 P1
├── tech_fingerprint.py   🆕 P1
├── cert_inventory.py     🆕 P1
├── internet_search.py    🆕 P1   (Shodan/Censys/FOFA pluggable)
├── favicon_hash.py       🆕 P2
├── jarm.py               🆕 P2
├── pdns.py               🆕 P2
├── dns_bruteforce.py     🆕 P2
├── typosquat.py          🆕 P2
├── cdn_attr.py           🆕 P2
├── secret_scanner.py     🆕 P2   (extracted from js_paths, generalized)
├── cloud/
│   ├── aws.py            🆕 P2
│   ├── azure.py          🆕 P2
│   ├── gcp.py            🆕 P2
│   └── exposure.py       🆕 P2
├── scm_dorks.py          🆕 P3
├── paste_monitor.py      🆕 P3
├── mobile_apps.py        🆕 P3
├── saas_detect.py        🆕 P3
├── cred_leak.py          🆕 P3
├── auth_scan.py          🆕 P3
├── api_discovery.py      🆕 P3
└── graphql_scan.py       🆕 P3
```

### 9.3 Service layer (`vaktscan/services/`)

```
services/
├── seeds_service.py
├── assets_service.py
├── findings_service.py
├── jobs_service.py
├── alerts_service.py
└── reports_service.py
```

### 9.4 API layer (`vaktscan/api/`)

```
api/
├── main.py              # FastAPI app
├── deps.py              # auth, db session, current_user, current_workspace
├── auth/                # OIDC, JWT, API tokens
├── rbac.py
├── audit.py
├── routers/
│   ├── seeds.py
│   ├── assets.py
│   ├── findings.py
│   ├── jobs.py
│   ├── reports.py
│   ├── integrations.py
│   ├── webhooks.py
│   └── admin.py
└── graphql.py           # P2, Strawberry
```

### 9.5 Workers (`vaktscan/workers/`)

```
workers/
├── celery_app.py
├── beat_schedule.py     # cron schedules from DB
├── tasks/
│   ├── discovery.py     # subdomain enum, CT, RDAP, ASN, cloud
│   ├── scanning.py      # port + service modules
│   ├── correlation.py   # tech → CVE
│   ├── feeds.py         # NVD/EPSS/KEV ingest
│   ├── diff.py          # snapshot diff
│   └── notify.py        # Slack/email/webhook
└── middleware.py        # tracing, rate-limit, retry
```

### 9.6 Web UI (`web/`)

```
web/
├── app/                 # Next.js App Router
│   ├── (auth)/          # login, oidc callback
│   ├── dashboard/
│   ├── inventory/       # asset browser w/ facets
│   ├── asset/[id]/      # detail view + graph + history
│   ├── findings/        # triage queue
│   ├── seeds/
│   ├── jobs/
│   ├── reports/
│   ├── integrations/    # Slack/Jira/SIEM connectors
│   └── settings/        # workspace, members, tokens
├── components/          # shadcn/ui-derived
└── lib/api-client/      # generated from OpenAPI
```

### 9.7 Integrations (`vaktscan/integrations/`)

```
integrations/
├── chatops.py           # Slack/Teams/Discord webhooks
├── email.py             # SendGrid/SES/SMTP
├── ticketing.py         # Jira/ServiceNow/Linear
├── siem.py              # Splunk HEC/Sentinel/XSOAR
└── webhook.py           # generic POST
```

### 9.8 Feeds (`vaktscan/feeds/`)

```
feeds/
├── nvd.py               # NVD JSON 2.0 daily delta
├── epss.py              # FIRST.org EPSS CSV daily
├── kev.py               # CISA-KEV JSON daily
├── ghsa.py              # GitHub Advisories (P2)
├── osv.py               # OSV.dev (P2)
└── vendors/             # cPanel TSR, AEM, Elastic, Grafana, …  (already in modules/data)
```

---

## 10. Cross-Cutting Concerns

### 10.1 Performance / Scalability

- **Workers stateless**: scale horizontally; CPU-bound jobs (nmap, dirsearch) get dedicated pool with `concurrency=1` and `prefetch=1`; I/O-bound (httpx, DNS) use `concurrency=50+`.
- **Sharding**: `workspace_id` is the natural shard key on every hot table.
- **Backpressure**: token-bucket per `(workspace, target_host)` and per `(workspace, ASN)` to avoid hammering customers' own infra.
- **Streaming preserved**: today's chunked scan of millions of IPs becomes a **fan-out** of small per-CIDR queue messages — same throughput, better observability.

### 10.2 Safety & Legal

- **Scope enforcement**: every job validates that targets ∈ workspace's in-scope seeds. Bail with `SCOPE_VIOLATION` otherwise. Suppression rules cannot widen scope.
- **No active exploit without consent**: existing aggressive checks (e.g. WHM default-creds, react-to-shell RCE) remain **opt-in per workspace** (env-var today → DB flag tomorrow).
- **Audit trail**: every scan run records `actor`, `seeds`, `modules`, `targets_resolved`, `start`, `end` — non-repudiable.
- **Robots/`humans.txt` respect**: configurable; off by default for owned assets, on for typosquat targets.
- **Rate-limit defaults**: conservative (1 RPS/target) until per-workspace override.

### 10.3 Security of the Platform Itself

- Secrets at rest in Vault / KMS. No keys in DB or code.
- All API auth = OIDC or short-lived signed JWT or hashed API token.
- All inter-service auth via mTLS in production.
- Webhook URLs go through SSRF-safe egress proxy.
- Worker containers run rootless, read-only FS, dropped capabilities.
- DB rows are `workspace_id`-scoped — RLS policy in Postgres for defense in depth.
- All admin actions audit-logged.

### 10.4 Testing Strategy

- **Unit**: every module retains today's unit tests; add tests for new modules using
  `httpx.MockTransport`, `aiosmtpd`, `respx`, `pytest-postgresql`, `fakeredis`.
- **Integration**: `testcontainers-python` to spin Postgres/Redis/MinIO/Mailhog per test class.
- **E2E**: Playwright against the Next.js UI hitting a seeded local stack.
- **Contract**: OpenAPI schema diff in CI prevents accidental breaking changes.
- **Load**: `locust` for API; `k6` for ingest paths.

### 10.5 Documentation

- `/docs` site (MkDocs Material). Sections: Concepts, CLI, API, Modules, Plugin SDK, Deploy, Operations, Compliance.
- Every module has a `MODULE.md` describing inputs, outputs, evidence schema, false-positive surface, and rate-limit footprint.
- Public OpenAPI + GraphQL schema published per release.

---

## 11. Migration Strategy (CLI → ASM, no break)

The CLI must keep working through every phase. Strategy:

1. **Phase 0** introduces a `--asm-write` flag (default off in v1.0.0, on in v1.1.0). When on, the CLI also writes findings to the API. When off, CLI behaves exactly like today.
2. The existing **CSV exporter remains the source-of-truth for CLI users** until v1.2.0; in v1.2.0 it becomes a thin wrapper around the API's CSV export.
3. The recon → scan pipeline (today: `python main.py -m recon --recon-domain target.com --scan-found`) becomes a one-shot **Job** in P0, schedulable in P1.
4. State files (`scan_state.py`) keep working in CLI; the API uses the DB. No double-state.
5. The 56 existing tests run unmodified in CI for every release.

---

## 12. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Scope creep — try to ship all of P1–P3 at once | High | High | Hard cap per phase. Each phase tagged release. Don't start phase N+1 until phase N is in users' hands. |
| Single-process Python perf wall | Med | High | Move CPU-heavy work to dedicated worker tier; consider Rust/Go shells for hot paths (massdns wrapper, JARM) in P2. |
| External API rate-limits (Shodan, Censys, GitHub) | High | Med | Per-key budgets, exponential backoff, cache-first reads, optional self-hosted alternatives. |
| Legal / scope violations | Med | Critical | Hard scope enforcement at job-dispatch time. Opt-in aggressive checks. Audit log. Per-workspace allow-list. |
| Data growth (raw HTTP bodies, nmap XMLs) | High | Med | Object store w/ TTL policies. Hot/cold tiering. Compress + dedup. |
| Schema lock-in | Med | High | Alembic from day one; expand-and-contract migrations; never drop columns in same release that adds the replacement. |
| Multi-tenant data leaks | Low | Critical | Postgres RLS + per-request `workspace_id` filter middleware + integration tests that try cross-tenant reads. |
| Open-source competitors (e.g. ProjectDiscovery Cloud, OWASP Amass intel) outpace us | Med | Med | Lean into VaktScan's deep service modules (cPanel/AEM/Elastic) as differentiators; expose plugin SDK so the community contributes breadth. |
| Worker fleet cost | Med | Med | Burstable scheduling; spot/preemptible workers for non-critical jobs; per-workspace quotas. |

---

## 13. Success Metrics

| Phase | KPI | Target |
|---|---|---|
| P0 | All existing CLI tests pass under new package layout | 100% |
| P0 | Findings written to Postgres via worker | 100% of scan output |
| P0 | API `p95` latency for `/findings?workspace_id=` (10k rows) | < 300 ms |
| P1 | Active workspaces using scheduled scans | ≥ 5 internal, ≥ 1 design partner |
| P1 | Time from new subdomain (CT log) → alert delivered | < 5 min |
| P1 | False-positive rate on `critical` findings (sampled) | < 5% |
| P2 | Cloud-asset coverage vs. AWS/Azure/GCP ground truth | ≥ 90% |
| P2 | Daily diff events generated per active workspace | tracked, not capped |
| P3 | Plugin SDK adoption (external modules contributed) | ≥ 5 |
| P3 | Categories of attack surface covered (vs. Gartner EASM 2025 taxonomy) | ≥ 90% |

---

## 14. Open Questions (to resolve before P1 kickoff)

1. **Deployment model**: SaaS-first vs. self-hosted-first vs. both from day one?
2. **Pricing axis** (if SaaS): per-asset, per-seed, per-workspace, per-scan-credit?
3. **Hard requirement on multi-tenancy in P0** or is single-tenant acceptable in P0 and multi-tenant in P1?
4. **OpenSearch vs. Postgres FTS** for P0 (Postgres FTS likely enough until P1).
5. **Authenticated scanning** — is this P2 or P3? Depends on design-partner ask.
6. **Compliance mapping** — which framework first? (PCI 4.0 likely highest ROI.)
7. **License** — keep MIT (today) or relicense (BSL / Elastic v2) to protect commercial play?

---

## 15. TL;DR — Where to Start Monday

1. Create `vaktscan/` Python package; move `main.py`, `modules/`, `utils.py`, etc. into it. Keep CLI entry-point.
2. Add `pyproject.toml`, `ruff`, `mypy`, `pre-commit`.
3. Add `alembic` + initial schema (`orgs`, `workspaces`, `seeds`, `assets`, `findings`, `scan_jobs`, `scan_runs`).
4. Add FastAPI skeleton with `/healthz` + read-only `/seeds`, `/assets`, `/findings`.
5. Add Celery + Redis; wrap **one** module (start with `dns_recon` — small, deterministic, no external binaries) as a Celery task that writes to DB.
6. Add `docker-compose.yml` with `postgres`, `redis`, `minio`, `api`, `worker`.
7. CI: container build, tests, schema-diff check.
8. Cut **`v1.0.0-asm`** when steps 1–7 are done. Iterate.

The rest of the plan (P1–P3) builds on top of that skeleton. Resist the urge to scope-creep
P0; the win is "VaktScan is now a service that the CLI talks to" — nothing more.
