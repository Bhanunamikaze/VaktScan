# VaktScan CLI Redesign — Design Spec

## Overview

This document specifies the full CLI redesign for VaktScan. The redesign introduces a
subcommand-based interface (replacing the current flat argparse), a unified 15-key finding
schema enforced across all modules, an extracted reporter module, a new `google-dork`
subcommand, and a clearly defined parallel pipeline for both domain and IP/CIDR targets.

The goals are:
- Composable CLI: each recon stage is independently invokable
- Schema consistency: every module returns the same 15 keys, enabling reliable CSV/JSON/SARIF output
- Maximum parallelism: independent stages run concurrently; sequential dependencies are explicit
- Incremental delivery: phased task list allows schema fixes to land before CLI surgery

---

## Subcommand Registry

### `scan` — Full attack surface scan (the primary command)

```
vaktscan scan <target> [options]
```

**Positional:**
- `target` — domain name, IP address, CIDR range, or path to a file containing one target per line

**Flags:**
```
--no-subdomain-enum          Skip subfinder/assetfinder/findomain/etc (domain targets only)
-m, --module MODULE          Run only this service module (elastic|kibana|grafana|prometheus|
                             aem|cpanel|jenkins|service_recon|react_to_shell)
                             Default: all modules run
--ports PORTS                Override default port list (e.g. "80,443,8080" or "1-1024")
--wordlist PATH              Wordlist for vhost fuzzing (ffuf) and dirsearch
--output-dir DIR             Override default output directory (default: reports/)
--no-nuclei                  Skip Nuclei template scanning
--no-dirsearch               Skip dirsearch directory brute-force
--no-js-paths                Skip JS path extraction
--no-passive                 Skip GAU, waybackurls, passive intel (Shodan/Censys)
--no-kev                     Skip CISA KEV enrichment
--no-epss                    Skip EPSS enrichment
--sarif                      Also write SARIF 2.1.0 output file
--json                       Also write JSON output file
--format csv|json|sarif|all  Output format(s) (csv always written regardless)
--concurrency N              Global concurrency cap (default: 50)
--timeout N                  Per-request timeout in seconds (default: 10)
--proxy URL                  HTTP proxy for all requests
--rate-limit N               Max requests per second across all modules
--shodan-key KEY             Shodan API key (overrides SHODAN_API_KEY env)
--censys-id ID               Censys API ID (overrides CENSYS_API_ID env)
--censys-secret SECRET       Censys API secret (overrides CENSYS_API_SECRET env)
```

---

### `enum` — Subdomain enumeration only

```
vaktscan enum <domain> [options]
```

**Positional:**
- `domain` — apex domain to enumerate

**Flags:**
```
--wordlist PATH              Wordlist for vhost fuzzing
--output-dir DIR             Output directory (default: reports/)
--concurrency N              Concurrency cap (default: 20)
--no-ct                      Skip certificate transparency (crt.sh)
--no-vhost-fuzz              Skip ffuf vhost fuzzing
```

**Output:** Writes `reports/<domain>/subdomains_<ts>.txt`. Prints count to stdout.

---

### `probe` — Port scan + httpx probe only

```
vaktscan probe <target> [options]
```

**Positional:**
- `target` — domain, IP, CIDR, or file

**Flags:**
```
--ports PORTS                Port list or range (default: VaktScan default port list)
--output-dir DIR             Output directory (default: reports/)
--concurrency N              Concurrency cap (default: 50)
--timeout N                  Timeout in seconds (default: 10)
```

**Output:** Writes `reports/<target>/portscan_<ts>.csv` and `reports/<target>/httpx_<ts>.json`.

---

### `dns` — DNS recon only

```
vaktscan dns <domain> [options]
```

**Positional:**
- `domain` — apex domain (or comma-separated list of domains)

**Flags:**
```
--resolver IP                DNS resolver to use (default: 1.1.1.1)
--concurrency N              Concurrency cap (default: 20)
--output-dir DIR             Output directory (default: reports/)
```

**Output:** Writes `reports/<domain>/dns_<ts>.csv`. Prints findings summary to stdout.

---

### `cloud` — Cloud asset enumeration only

```
vaktscan cloud <domain> [options]
```

**Positional:**
- `domain` — apex domain

**Flags:**
```
--concurrency N              Concurrency for bucket probing (default: 50)
--output-dir DIR             Output directory (default: reports/)
```

**Output:** Writes `reports/<domain>/cloud_<ts>.csv`.

---

### `js-paths` — JS path extraction only

```
vaktscan js-paths <url_or_file> [options]
```

**Positional:**
- `url_or_file` — single URL or file containing one URL per line

**Flags:**
```
--threads N                  Thread count for JS fetching (default: 20)
--timeout N                  Timeout in seconds (default: 10)
--output-dir DIR             Output directory (default: reports/)
```

**Output:** Writes `reports/<target>/js_paths_<ts>.csv`.

---

### `domain-scan` — Domain-level HTTP analysis only

```
vaktscan domain-scan <domain> [options]
```

**Positional:**
- `domain` — apex domain

**Flags:**
```
--httpx-data PATH            Path to existing httpx JSON output (skip re-probing)
--output-dir DIR             Output directory (default: reports/)
--concurrency N              Concurrency cap (default: 50)
```

**Output:** Writes `reports/<domain>/domain_scan_<ts>.csv`.

---

### `google-dork` — Google Dorking passive recon

```
vaktscan google-dork <domain> [options]
```

**Positional:**
- `domain` — target domain

**Flags:**
```
--google-api-key KEY         Google Custom Search API key (required; or GOOGLE_API_KEY env)
--google-cx CX               Google Custom Search Engine ID (required; or GOOGLE_CX env)
--dorks FILE                 Path to custom dorks file (one dork template per line)
--output-dir DIR             Output directory (default: reports/)
--delay N                    Delay between API requests in seconds (default: 1)
--max-results N              Max results per dork query (default: 10)
```

**Output:** Writes `reports/<domain>/google_dork_<ts>.csv`. Findings use the canonical schema.

---

## Full Scan Pipeline (Domain Target)

```
vaktscan scan example.com
```

### Stage 0 — Initialization (sequential, instant)
- Validate target type (domain detection)
- Create `reports/example.com_<timestamp>/` output directory
- Initialize SQLite inventory DB (`init_db()`, `start_scan_run()`)
- Resolve display_target, scan_address

### Stage 1 — Passive Recon (sequential start, parallel internals)

**Step 1.1 — Subdomain Enumeration** (skipped if `--no-subdomain-enum`)
- `ReconScanner.run_all()` — fans out subfinder/assetfinder/findomain/bbot/censys/crtsh concurrently via internal `asyncio.gather`
- Produces: `sorted_subdomains: list[str]`
- Must complete before Stage 2 (httpx needs the full subdomain list)

**Step 1.2 — DNS Recon** (runs concurrently with Step 1.1 on the apex domain)
- `dns_recon.run([domain])` — does not need subdomains, runs on apex only
- Produces: `dns_findings: list[dict]`
- Can finish independently; findings fed to final aggregation

**Step 1.3 — Cloud Enumeration** (runs concurrently with Steps 1.1 and 1.2)
- `cloud_enum.enumerate_cloud_assets(domain)` — only needs apex domain
- Produces: `cloud_findings: list[dict]`
- Can finish independently

**Step 1.4 — Google Dorking** (runs concurrently with Steps 1.1, 1.2, 1.3, if API keys present)
- `google_dork.run(domain)` — only needs apex domain + API credentials
- Produces: `dork_findings: list[dict]`
- Can finish independently

**Parallelism:** Steps 1.2, 1.3, 1.4 run concurrently with 1.1 via `asyncio.gather`. Stage 2 waits on 1.1 only.

### Stage 2 — Active Discovery (sequential after Stage 1.1)

**Step 2.1 — Port Scan**
- Runs masscan or nmap SYN scan across all discovered subdomains + apex
- Produces: `port_scan_results: list[dict]` with `(ip, hostname, open_ports)`
- Writes `portscan_<ts>.csv` via `save_port_scan_csv()`
- Must complete before Step 2.2 (httpx needs the port/host pairs)

**Step 2.2 — HTTPX Probe**
- `HTTPXRunner.run_httpx(targets)` where targets = subdomains with their discovered ports
- Produces: `httpx_data: list[dict]`, `alive_urls: list[str]`
- Must complete before Stages 3, 4, 5

### Stage 3 — Web-Level Analysis (all parallel after Stage 2.2)

All three run concurrently via `asyncio.gather` after httpx completes:

**Step 3.1 — Nuclei**
- `NucleiRunner.run_nuclei(alive_urls)`
- Produces: `nuclei_findings: list[dict]`

**Step 3.2 — Web Checks**
- `web_checks.run_checks(alive_urls)`
- Produces: `web_findings: list[dict]`

**Step 3.3 — Domain Scan**
- `DomainScanner.run(domains, httpx_data, alive_urls)`
- Produces: `domain_findings: list[dict]`

### Stage 4 — Service Vulnerability Scanning (parallel after Stage 2.2)

For each (host, port) pair from port scan results, dispatch the matching service module. All module coroutines run concurrently via a top-level `asyncio.gather` with a semaphore cap.

If `-m elastic` specified, only `elastic.run_scans()` is dispatched. Otherwise all applicable modules run.

**Step 4.1 — Fan out service module coroutines based on port-to-module mapping:**

```
Port mapping (defaults):
9200, 9243, 9300 → elastic
5601             → kibana
3000             → grafana
9090, 9091, 9100 → prometheus
4502, 4503, 4504 → aem
2082, 2083, 2086, 2087, 2095, 2096 → cpanel
8080, 8443, 50000 → jenkins
*                → service_recon (always runs on all open ports as fallback)
```

Produces: `service_findings: list[dict]`

### Stage 5 — Historical URL Analysis (parallel after Stage 1.1, independent of Stage 2)

**Step 5.1 — GAU** (runs concurrently with Stage 3/4)
- `GAURunner.run(subdomains)`
- Can start as soon as subdomain list is known (after Stage 1.1)
- Produces: `gau_urls: dict[str, list[str]]` (used for context, not directly as findings)

**Step 5.2 — WaybackURLs** (runs concurrently with GAU and Stage 3/4)
- `WaybackURLsRunner.run(subdomains)`
- Produces: `wayback_urls: dict[str, list[str]]`

**Step 5.3 — JS Paths** (runs concurrently with GAU/Wayback, depends on Stage 2.2)
- `JSPathsScanner(alive_urls).run()`
- Produces: `js_findings: dict` (findings, paths, hosts, etc.)

**Step 5.4 — Dirsearch** (concurrently with above, depends on Stage 2.2)
- `DirEnumerator.run_dirsearch(alive_urls)` (skipped if `--no-dirsearch`)
- Produces: output files in `dirsearch_reports/` subdirectory

### Stage 6 — Enrichment (sequential, all findings must be aggregated first)

Aggregate all findings from Stages 1.2, 1.3, 1.4, 3.x, 4.x, 5.3 into `all_findings: list[dict]`.

**Step 6.1 — CISA KEV** (skipped if `--no-kev`)
- `cisa_kev.enrich(all_findings)` — appends new CRITICAL sibling findings
- Sequential (must complete before 6.2)

**Step 6.2 — EPSS** (skipped if `--no-epss`)
- `epss.enrich(all_findings)` — mutates in-place
- Sequential (after 6.1 so KEV findings also get EPSS scored)

**Step 6.3 — Passive Intel** (skipped if `--no-passive` or no API keys)
- `passive_intel.enrich(all_findings)` — appends new INFO findings
- Can run concurrently with 6.1 and 6.2 since it only reads resolved_ip fields, but appending to the same list requires care; serialize for safety

### Stage 7 — Output & Persistence (sequential)

**Step 7.1 — Deduplication**
- `deduplicate_vulnerabilities(all_findings)` from `main.py`

**Step 7.2 — Inventory Persistence**
- `upsert_asset()` for each discovered asset
- `save_findings(run_id, all_findings)` — returns delta dict
- `complete_scan_run(run_id, len(all_findings))`

**Step 7.3 — Report Writing (always runs)**
- `save_results_to_csv(all_findings)` — writes `reports/<scan_dir>/scan_results_<ts>.csv`
- `save_port_scan_csv()` — already written in Step 2.1, no-op here
- If `--json`: `save_results_to_json(all_findings)`
- If `--sarif`: `write_sarif_output(all_findings, path)`

**Step 7.4 — Console Output**
- `print_final_results(all_findings, output_csv)`
- `print_delta_report(delta)`
- `print_executive_summary(run_id, len(all_findings))`

---

## Full Scan Pipeline (IP/CIDR Target)

```
vaktscan scan 192.168.1.0/24
vaktscan scan 10.0.0.1
```

Stages 1.1 (subdomain enum), 1.2 (DNS recon), 1.3 (cloud enum), 1.4 (Google Dork), and Stage 5.1/5.2 (GAU/wayback) are **all skipped** — these require a domain name.

### Stage 0 — Initialization
- Same as domain pipeline: create output dir, init DB, start scan run

### Stage 1 — Port Scan (sequential)
- Masscan/nmap across IP or expanded CIDR range
- Produces: `port_scan_results: list[dict]`
- Writes `portscan_<ts>.csv`

### Stage 2 — HTTPX Probe (sequential after Stage 1)
- `HTTPXRunner.run_httpx(ip_port_targets)`
- Produces: `httpx_data`, `alive_urls`

### Stage 3 — Web-Level Analysis (parallel after Stage 2)
- Step 3.1: Nuclei
- Step 3.2: Web Checks
- (Domain Scan skipped — requires domain/httpx metadata with domain context)

### Stage 4 — Service Vulnerability Scanning (parallel after Stage 2)
- Same port-to-module dispatch as domain pipeline
- `service_recon` runs on all unmatched ports

### Stage 5 — JS Paths (parallel with Stage 3/4, after Stage 2)
- `JSPathsScanner(alive_urls).run()`
- Dirsearch also runs if not `--no-dirsearch`

### Stage 6 — Enrichment (sequential after all findings aggregated)
- Same as domain pipeline: CISA KEV → EPSS → Passive Intel

### Stage 7 — Output & Persistence
- Same as domain pipeline

**File routing for `scan <file>`:** Each line is classified as domain (no `/`, contains `.`, not IP) or IP/CIDR. Domain lines run the full domain pipeline; IP/CIDR lines run the IP pipeline. Both pipelines run concurrently across lines (with a per-target semaphore to avoid overwhelming the host machine).

---

## Unified Finding Schema

Every module's `run_scans()` return value and every standalone module's output must contain exactly these 15 keys:

```python
{
    "status":          str,   # CRITICAL | VULNERABLE | POTENTIAL | INFO
    "severity":        str,   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    "vulnerability":   str,   # Human-readable finding name
    "target":          str,   # Display hostname or IP (not scan_address)
    "resolved_ip":     str,   # Resolved IPv4/IPv6, or "N/A"
    "port":            str,   # Port number as string, or "N/A"
    "url":             str,   # Full URL that triggered the finding
    "payload_url":     str,   # Specific payload/path URL, or same as url, or "N/A"
    "module":          str,   # Module name (e.g. "elastic", "kibana", "dns_recon")
    "service_version": str,   # Detected version string, or "N/A"
    "details":         str,   # Free-text description of the finding
    "http_status":     str,   # HTTP response code as string, or "N/A"
    "page_title":      str,   # Page <title> content, or "N/A"
    "content_length":  str,   # Response body size as string, or "N/A"
    "timestamp":       str,   # ISO 8601 UTC timestamp of when finding was generated
}
```

**Status vocabulary** (unified, all modules must use exactly these four values):
- `CRITICAL` — actively exploitable, known KEV, or EPSS >= 0.7
- `VULNERABLE` — confirmed vulnerability
- `POTENTIAL` — unconfirmed/version-based finding
- `INFO` — informational, no direct exploitability

**Notes on `server` key:** The `server` key present in `elastic`, `kibana`, `grafana`, `prometheus`, `aem`, `cpanel`, and `react_to_shell` is an internal implementation detail that holds `scan_address`. It must be stripped before findings leave `run_scans()` (or mapped: if `resolved_ip` is `"N/A"`, populate it from `server` before stripping). The `server` key must not appear in any returned finding dict.

**The `timestamp` key** is new — not currently in any module. The CSV writer already prepends a `Timestamp` column; making it explicit in the finding dict removes the implicit injection at write time.

---

## Reporting Architecture

### Directory Structure

```
reports/
└── example.com_20260601_143022/          # <target>_<YYYYMMDD>_<HHMMSS>/
    ├── scan_results_<ts>.csv             # Primary output — always written
    ├── scan_results_<ts>.json            # Written if --json
    ├── scan_results_<ts>.sarif           # Written if --sarif
    ├── portscan_<ts>.csv                 # Port scan raw results
    ├── dns_<ts>.csv                      # DNS findings
    ├── cloud_<ts>.csv                    # Cloud asset findings
    ├── google_dork_<ts>.csv              # Dork findings
    ├── js_paths_<ts>.csv                 # JS path findings
    ├── domain_scan_<ts>.csv              # Domain analysis findings
    ├── httpx_<ts>.json                   # Raw httpx output (kept as artifact)
    ├── nuclei_results_<ts>.json          # Raw nuclei output (kept as artifact)
    ├── subdomains_<ts>.txt               # Discovered subdomains list
    ├── dirsearch_reports/                # dirsearch per-target output files
    ├── nmap_scans/                       # nmap per-host .nmap files
    ├── gau/                              # GAU per-domain URL files
    └── waybackurls/                      # Wayback per-domain URL files
```

For standalone subcommands (`dns`, `cloud`, `js-paths`, etc.) the output dir is `reports/<target>/` without a timestamp suffix (since there is no scan run context).

### CSV Naming Convention

- Primary scan CSV: `scan_results_<YYYYMMDD_HHMMSS>.csv`
- Port scan CSV: `portscan_results_<YYYYMMDD_HHMMSS>.csv`
- Per-module standalone CSVs: `<module>_<YYYYMMDD_HHMMSS>.csv`

### CSV Always Written

The CSV is written unconditionally at the end of every `scan` run (Stage 7.3), regardless of flags. It is the canonical deliverable. A partial CSV is never written — only on clean completion (or on SIGINT, a partial write is attempted via a shutdown hook).

### Existing Reporting Functions — Reuse Plan

The five functions in `main.py` are extracted to `modules/reporter.py` as a standalone module. No logic changes; only relocation.

```python
# modules/reporter.py (new file, extracted from main.py)
def save_port_scan_csv(scan_results, output_path)       # sig changed: explicit path
def save_results_to_csv(vulnerabilities, output_path)   # sig changed: explicit path
def save_results_to_json(vulnerabilities, output_path)  # sig changed: explicit path
def write_sarif_output(vulnerabilities, output_path)    # unchanged
def print_final_results(all_vulnerabilities, output_csv) # unchanged
```

`main.py` is updated to import from `modules.reporter`. `tests/test_cpanel_reporting.py` is updated to import from `modules.reporter` instead of `main`.

The 15-column CSV contract is unchanged. `Timestamp` is sourced from the new `timestamp` finding key rather than being injected at write time.

---

## Module Output Gaps (what needs patching)

### `elastic.py`, `kibana.py`, `grafana.py`, `prometheus.py`

**Issues:**
- Non-standard `server` key present in all returned findings
- `severity` conditionally absent (present on CVE findings, absent on others)
- No `timestamp` key

**Patches needed:**
1. After the `asyncio.gather` in `run_scans`, iterate findings and: if `resolved_ip == "N/A"`, set `resolved_ip = finding.pop("server")`; else `finding.pop("server")`.
2. Add `finding.setdefault("severity", "INFO")` to guarantee severity is always present.
3. Add `finding["timestamp"] = datetime.utcnow().isoformat() + "Z"` in the stamp loop.

### `aem.py`, `cpanel.py`

**Issues:**
- Non-standard `server` key (same as above)
- `cpanel.py`: `_evidence_hash`, `_surface`, `_cve_id` are already stripped by `_strip_internals()` — no change needed there
- `cpanel.py`: `CRITICAL` status is already in the unified vocabulary — no change needed
- No `timestamp` key

**Patches needed:**
1. Same `server` key stripping as elastic/kibana/grafana/prometheus.
2. Add `timestamp` stamping in `run_scans` stamp loop.

### `jenkins.py`, `service_recon.py`

**Issues:**
- No `server` key (good, no removal needed)
- `http_status`, `page_title`, `content_length` hardcoded to `"N/A"` by `_finding()` — acceptable per spec
- No `timestamp` key

**Patches needed:**
1. Add `timestamp` to `_finding()` helper.

### `react_to_shell.py`

**Issues:**
- Missing `payload_url`, `http_status`, `page_title`, `content_length` entirely
- Non-standard `server` key present
- No `timestamp` key

**Patches needed:**
1. In `run_scans` stamp loop, add: `res.setdefault("payload_url", res.get("url", "N/A"))`, `res.setdefault("http_status", "N/A")`, `res.setdefault("page_title", "N/A")`, `res.setdefault("content_length", "N/A")`.
2. Strip `server` key (same as above).
3. Add `timestamp` stamping.

### `dns_recon.py`

**Issues:**
- Non-standard `server` key (always equals `target`; redundant)
- No `timestamp` key
- `resolved_ip` always `"N/A"` — acceptable

**Patches needed:**
1. Remove `server` key from all finding constructors.
2. Add `timestamp` to all finding constructors.

### `cloud_enum.py`

**Issues:**
- `resolved_ip` uses `""` (empty string) instead of `"N/A"` for unresolved
- No `timestamp` key

**Patches needed:**
1. Replace `""` with `"N/A"` for `resolved_ip` in all finding constructors.
2. Add `timestamp`.

### `web_checks.py`

**Issues:**
- `resolved_ip` uses `""` (empty string) instead of `"N/A"`
- No `timestamp` key

**Patches needed:**
1. Replace `resolved_ip = ""` with `resolved_ip = "N/A"` in finding constructors.
2. Add `timestamp`.

### `domain_scan.py`

**Issues:**
- No `payload_url` key anywhere in output
- No `timestamp` key

**Patches needed:**
1. Add `"payload_url": finding.get("url", "N/A")` in the finding constructor or stamp loop.
2. Add `timestamp`.

### `js_paths.py`

**Issues:**
- Output is a `dict` with `findings` as a sub-key, not a flat `list[dict]`
- The caller must extract `result["findings"]` — this is an API inconsistency vs all other modules

**Patches needed:**
1. No change to `JSPathsScanner.run()` signature (it returns richer data the JS subcommand needs).
2. The orchestrator in `main.py` (and new CLI) must extract `js_result["findings"]` when aggregating into `all_findings`.
3. Add `timestamp` to each finding in `js_paths.py`.

### `cisa_kev.py`, `epss.py`, `passive_intel.py`

**Issues:**
- `cisa_kev.py` and `passive_intel.py` append findings that hardcode `page_title = "N/A"` and `content_length = "N/A"` — acceptable
- None set `timestamp` on appended/mutated findings

**Patches needed:**
1. Each enrichment function adds `timestamp` to newly appended findings.
2. `epss.py` does not add new findings, only mutates — no timestamp needed there.

### `nuclei_runner.py`

**Issues:**
- Output schema has only 10 keys — missing `payload_url`, `http_status`, `page_title`, `content_length`, `timestamp`

**Patches needed:**
1. In `run_nuclei()` finding construction, add: `"payload_url": matched_url`, `"http_status": "N/A"`, `"page_title": "N/A"`, `"content_length": "N/A"`, `"timestamp": ...`

---

## Parallelism Map

```
Timeline →→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→

[Stage 0]  Init (instant, sequential)
           │
           ▼
[Stage 1]  ┌──────────────────────────────────────────┐
           │ 1.1 Subdomain Enum (blocks Stage 2)        │
           │ 1.2 DNS Recon       ◄── parallel ──►       │
           │ 1.3 Cloud Enum      ◄── parallel ──►       │
           │ 1.4 Google Dork     ◄── parallel ──►       │
           └──────────────────────────────────────────┘
                    │ (wait for 1.1 only)
                    ▼
[Stage 2]  2.1 Port Scan (sequential)
                    │
                    ▼
           2.2 HTTPX Probe (sequential after 2.1)
                    │
           ┌────────┴──────────────────────┐
           ▼                               ▼
[Stage 3]  3.1 Nuclei                [Stage 5]
           3.2 Web Checks     ◄──    5.1 GAU
           3.3 Domain Scan    par    5.2 WaybackURLs
                              ──►    5.3 JS Paths
[Stage 4]                            5.4 Dirsearch
           4.1 Service Modules  ◄────────────────────►
           (all module coroutines
            in one asyncio.gather
            with semaphore cap)

           └──────────────────────────────┘
                    │ (wait for all)
                    ▼
[Stage 6]  6.1 CISA KEV (sequential)
                    │
                    ▼
           6.2 EPSS (sequential)
                    │
                    ▼
           6.3 Passive Intel (sequential)
                    │
                    ▼
[Stage 7]  Dedup → Inventory → Write CSV → Console
```

**Key parallelism decisions:**

| Can run in parallel | Reason |
|---|---|
| DNS Recon + Cloud Enum + Google Dork + Subdomain Enum | All need only the apex domain |
| GAU + WaybackURLs | Need only subdomain list (available after Stage 1.1) |
| Nuclei + Web Checks + Domain Scan + JS Paths + Dirsearch + Service Modules | All need only alive_urls/httpx_data |
| Service module coroutines (elastic, kibana, etc.) with each other | Each operates on independent (host, port) pairs |

| Must be sequential | Reason |
|---|---|
| Port Scan → HTTPX | httpx needs discovered ports |
| HTTPX → Stages 3/4/5.3/5.4 | All need alive_urls |
| All findings → CISA KEV → EPSS | EPSS should score KEV findings too |
| EPSS → Passive Intel | Passive Intel appends; order matters for clean delta |
| All enrichment → Inventory | DB must see final enriched finding set |

---

## Implementation Task List

### Phase 0 — Schema Normalization (prerequisite for everything)

1. **Add `timestamp` field to all modules** — patch `_finding()` helpers in `jenkins.py`, `service_recon.py`; patch stamp loops in `elastic.py`, `kibana.py`, `grafana.py`, `prometheus.py`, `aem.py`, `cpanel.py`, `react_to_shell.py`; patch finding constructors in `dns_recon.py`, `cloud_enum.py`, `web_checks.py`, `domain_scan.py`, `js_paths.py`; patch appended findings in `cisa_kev.py`, `passive_intel.py`; patch `run_nuclei()` in `nuclei_runner.py`

2. **Strip `server` key from all modules** — `elastic.py`, `kibana.py`, `grafana.py`, `prometheus.py`, `aem.py`, `cpanel.py`, `react_to_shell.py`, `dns_recon.py` — pop before return, preserve data in `resolved_ip` if needed

3. **Normalize `resolved_ip` empty string → `"N/A"`** — `cloud_enum.py`, `web_checks.py`

4. **Add missing schema keys to `react_to_shell.py`** — `payload_url`, `http_status`, `page_title`, `content_length`

5. **Add missing schema keys to `domain_scan.py`** — `payload_url`

6. **Add missing schema keys to `nuclei_runner.py`** — `payload_url`, `http_status`, `page_title`, `content_length`

7. **Guarantee `severity` always present in `elastic.py`, `kibana.py`, `grafana.py`, `prometheus.py`** — `setdefault("severity", "INFO")`

8. **Write schema validation utility** — `modules/schema.py` with `validate_finding(d: dict) -> list[str]` that returns a list of violations; used in tests and optionally at runtime with `--debug`

### Phase 1 — Reporter Extraction

9. **Create `modules/reporter.py`** — extract `save_port_scan_csv`, `save_results_to_csv`, `save_results_to_json`, `write_sarif_output`, `print_final_results` from `main.py`; update function signatures to accept explicit output paths

10. **Update `main.py`** to import from `modules.reporter` instead of defining these functions

11. **Update `tests/test_cpanel_reporting.py`** to import from `modules.reporter`

12. **Add `modules/reporter.py` unit test** — verify 15-column CSV contract, verify `timestamp` column appears correctly

### Phase 2 — Google Dork Module

13. **Create `modules/google_dork.py`** — implement `run(domain, api_key, cx, dorks=None, delay=1, max_results=10) -> list[dict]`; return canonical 15-key findings; include a built-in dork template library (site:, inurl:, filetype:, intitle: patterns); handle API quota errors gracefully; set `module = "google_dork"`, `port = "443"`, `http_status = "N/A"`, `page_title` from snippet

### Phase 3 — CLI Subparser Redesign

14. **Redesign argument parsing in `main.py`** — replace current flat argparse with `subparsers` for `scan`, `enum`, `probe`, `dns`, `cloud`, `js-paths`, `domain-scan`, `google-dork`; preserve all existing flags under `scan` subcommand; route each subcommand to a dedicated async handler function

15. **Implement `cmd_scan(args)`** — the full pipeline orchestrator; reads `args.target`, classifies as domain/IP/CIDR/file; routes accordingly; all stages wired with proper `asyncio.gather` groupings per the parallelism map

16. **Implement `cmd_enum(args)`** — thin wrapper around `ReconScanner.run_all()` + output

17. **Implement `cmd_probe(args)`** — port scan + httpx; outputs portscan CSV and httpx JSON

18. **Implement `cmd_dns(args)`** — wraps `dns_recon.run()`; outputs DNS CSV

19. **Implement `cmd_cloud(args)`** — wraps `cloud_enum.enumerate_cloud_assets()`; outputs cloud CSV

20. **Implement `cmd_js_paths(args)`** — wraps `JSPathsScanner`; outputs js_paths CSV

21. **Implement `cmd_domain_scan(args)`** — wraps `DomainScanner`; accepts optional `--httpx-data` path

22. **Implement `cmd_google_dork(args)`** — wraps `google_dork.run()`; requires `--google-api-key` and `--google-cx` (or env vars); outputs google_dork CSV

### Phase 4 — Pipeline Orchestration

23. **Implement `output_dir` factory** — `make_output_dir(target, base="reports/") -> str` that creates `reports/<target>_<timestamp>/` for `scan` and `reports/<target>/` for standalone subcommands

24. **Implement `target_classifier(target: str) -> Literal["domain", "ip", "cidr", "file"]`** — used by `cmd_scan` to route pipelines

25. **Implement `domain_scan_pipeline(domain, args) -> list[dict]`** — full Stage 0–7 implementation for domain targets; uses `asyncio.gather` for Stage 1 and Stages 3/4/5 fan-out

26. **Implement `ip_scan_pipeline(ip_or_cidr, args) -> list[dict]`** — Stage 0–7 for IP/CIDR targets (no enum/DNS/cloud/GAU/wayback)

27. **Implement `file_scan_pipeline(filepath, args)`** — reads lines, classifies each, dispatches to `domain_scan_pipeline` or `ip_scan_pipeline` concurrently with per-target semaphore

28. **Implement `--no-subdomain-enum` flag handling** — when set, `subdomains = [domain]` (apex only) and Stage 1.1 is skipped; Stages 1.2/1.3/1.4 still run

29. **Implement `-m / --module` flag handling** — in Stage 4, filter the port-to-module dispatch table to only the specified module; if the port does not match that module's default ports, still run it on all open ports (user explicitly requested it)

### Phase 5 — Output Directory + CSV Auto-generation

30. **Implement auto CSV generation in every subcommand** — every `cmd_*` function calls `save_results_to_csv(findings, output_path)` before returning; path follows naming convention

31. **Implement SIGINT handler** — on `KeyboardInterrupt`, flush current `all_findings` to a partial CSV named `scan_results_<ts>_PARTIAL.csv` before exit

32. **Implement `--format` flag** — post-scan, in addition to the always-written CSV, write JSON and/or SARIF if requested

### Phase 6 — Tests

33. **Add integration test for `target_classifier`** — domain/IP/CIDR/file detection edge cases

34. **Add integration test for `schema.validate_finding`** — each module's sample output passes validation

35. **Add unit test for `google_dork.py`** — mock Google API responses, verify canonical schema output

36. **Add CLI invocation smoke tests** — verify each subcommand exits 0 with `--help` and that required args are enforced

37. **Update existing tests** that import directly from `main` to use new module locations
