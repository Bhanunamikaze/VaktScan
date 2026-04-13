# VaktScan — Domain-Scan Module
## Final Plan

---

## Architecture Decision

`domain-scan` is a **first-class module** (`modules/domain_scan.py`) with its own `DomainScanner` class — not a helper bolted onto existing code. It is activated in **three ways**:

| Trigger | How |
|---|---|
| `-m domain-scan` | New standalone mode in `main.py` (accepts a domain list file directly) |
| `--recon` flow | `run_recon_followups()` calls `DomainScanner` after httpx, same as nuclei |
| `--sub-domains` | Same code path as `--recon` — no duplication, already feeds `run_recon_followups()` |

---

## What Already Exists (Unchanged)

| Requirement | Existing Component |
|---|---|
| Load domain list | `load_subdomains_file()` + `--sub-domains` |
| HTTP validity check | `HTTPXRunner` → `httpx_runner.py` |
| Port scan | `scan_ports()` → `port_scanner.py` |
| CVE detection | `NucleiRunner` with `-tags cve` |
| Default/panel pages | `NucleiRunner` with `-tags panel,default-login,exposure` |
| Sensitive path enumeration | `DirEnumerator.run_dirsearch()` |
| Archive harvesting | `GAURunner`, `WaybackURLsRunner` |
| Reporting | `save_results_to_csv()` + `ScanStateManager.add_vulnerability()` |

---

## New File: `modules/domain_scan.py`

Single class that owns all new capabilities.

### 1 — Internal / External Classification

Zero-network. Runs before any probing.

```python
INTERNAL_KEYWORDS = [
    "builder-svcs", "uat", "qa", "staging",
    "dev", "internal", "local", "corp", "intranet",
    "preprod", "sandbox", "test", "sit", "int", "nonprod",
]

def classify_domains(domains: list, extra_keywords: list = None) -> dict:
    """Returns {'INTERNAL': [...], 'EXTERNAL': [...]}."""

def save_classification_csv(domains: list, output_dir: str) -> str:
    """Writes domain_classification_<ts>.csv."""
```

### 2 — Default / Parked Page Detection

Inspects titles/bodies **already in the httpx JSON** — zero extra requests.

```python
DEFAULT_PAGE_SIGNATURES = {
    "It works!":               "Apache default page",
    "Welcome to nginx":        "nginx default page",
    "IIS Windows Server":      "IIS default page",
    "Coming Soon":             "Placeholder / parked page",
    "domain for sale":         "Domain parking",
    "buy this domain":         "Domain parking",
}

def detect_default_pages(httpx_data: list) -> list[dict]:
    """Returns findings as standard VaktScan vuln dicts."""
```

### 3 — Broken Components Detection  ← NEW FIX

For each alive URL, fetches the HTML body (reuses httpx response bodies already collected), extracts all sub-resource URLs, and HEAD-probes each one.

```python
async def check_broken_components(httpx_data: list, concurrency: int = 50) -> list[dict]:
    """
    1. Parse HTML body in each httpx entry for asset URLs:
       - <script src="...">
       - <link href="..."> (stylesheets)
       - <img src="...">
       - fetch() / XHR patterns in inline JS (regex: ["'](/api/...) )
    2. Resolve relative URLs against the page origin.
    3. HEAD-probe each unique asset URL (semaphore-limited).
    4. Flag assets returning 4xx / 5xx as BROKEN_COMPONENT findings.
    5. Group by parent page — report once per broken asset.
    """
```

**Why this covers "broken components":**  
A broken SPA, partial deployment, or CDN misconfiguration all manifest as sub-resources (JS bundles, CSS, API calls, images) returning error codes while the shell page itself returns 200. This is invisible to nuclei and dirsearch.

**Finding shape** — same standard vuln dict as all other modules:

```python
{
    "target":        "app.example.com",
    "resolved_ip":   "1.2.3.4",
    "port":          "443",
    "vulnerability": "Broken Component: /static/main.abc123.js",
    "status":        "POTENTIAL",
    "severity":      "MEDIUM",
    "module":        "domain_scan",
    "service_version": "N/A",
    "url":           "https://app.example.com/static/main.abc123.js",
    "details":       "Sub-resource returned HTTP 404. Parent: https://app.example.com",
}
```

### 4 — Anomaly / Misconfiguration Checks

```python
async def run_anomaly_checks(alive_urls: list, concurrency: int = 50) -> list[dict]:
    """
    Per alive URL:
    - Missing security headers: HSTS, X-Frame-Options, CSP, X-Content-Type-Options
    - CORS misconfiguration: inject Origin: https://evil.com → inspect ACAO header
    - Open redirect: probe ?url=https://evil.com, ?redirect=https://evil.com
    - Directory listing: body contains "Index of /"
    - JSON/HTML mismatch: body starts with '{' but Content-Type is text/html
    - 5xx on base path
    - Response size anomaly: body < 50 bytes or > 2 MB
    """
```

### Main entry point

```python
class DomainScanner:
    def __init__(self, output_dir: str, extra_keywords: list = None):
        ...

    async def run(self, domains: list, httpx_data: list, alive_urls: list,
                  concurrency: int = 50) -> list[dict]:
        """
        Orchestrates all four checks. Returns combined list of vuln dicts.
        Called from run_recon_followups() and from the -m domain-scan standalone path.
        """
        classified = self.classify_domains(domains)
        self.save_classification_csv(domains)

        findings  = self.detect_default_pages(httpx_data)
        findings += await self.check_broken_components(httpx_data, concurrency)
        findings += await self.run_anomaly_checks(alive_urls, concurrency)
        return findings
```

---

## Integration Points

### A — `run_recon_followups()` in `main.py` (recon + --sub-domains flow)

After the existing httpx block, before dirsearch:

```python
from modules.domain_scan import DomainScanner

scanner = DomainScanner(output_dir=output_dir)
domain_scan_findings = await scanner.run(
    domains=unique_targets,
    httpx_data=httpx_data,      # already in memory
    alive_urls=alive_urls,       # already computed
    concurrency=concurrency,
)
for f in domain_scan_findings:
    print(f"  [domain_scan] {f['status']} | {f['vulnerability']} | {f['url']}")
    # findings returned to caller → flow into save_results_to_csv()
```

Classification CSV is written to the same `output_dir`. All findings use the existing vuln dict and reporting path.

### B — `-m domain-scan` standalone mode in `main.py`

New argument group:
```
python main.py -m domain-scan --ds-file domains.txt [--recon example.com] [--sub-domains subs.txt]
```

- Loads the domain list (or receives it from the recon output)
- Calls `HTTPXRunner` itself (same as the recon flow) then invokes `DomainScanner.run()`
- Outputs the same CSV + terminal report as all other modes

---

## Files Changed

```
modules/
  domain_scan.py     ← NEW  (DomainScanner class, ~280 lines)
main.py              ← MODIFY (2 integration points + new -m domain-scan arg)
modules/__init__.py  ← MODIFY (add: from . import domain_scan)
```

No new pip dependencies (uses `asyncio`, `httpx` Python lib already present, `html.parser` stdlib).
