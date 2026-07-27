# Adding a Module to VaktScan

VaktScan has **several kinds of modules**, and they don't all plug in the same way. Before writing any code, decide **which category** your module belongs to - that determines its entry-point signature, where it wires into the pipeline, and whether it runs by default or behind a flag.

> This guide avoids hard line numbers (they drift). It refers to **functions and landmarks** in `main.py`: `SERVICE_TO_MODULE`, `run_recon_followups()` (the `if alive_urls:` block), `_run_parallel_passive()`, `handle_domain()`, `_enrich_and_report()`, `cmd_scan()`, and the `extra_scans` frozenset. Search for those names.

---

## 0. Pick a category

| Category | Runs on | Wires into | Example modules | Default / flag |
|---|---|---|---|---|
| **A. Port-triggered service module** | one open port | `SERVICE_TO_MODULE` + `get_service_ports()` | elastic, kibana, grafana, jenkins, cpanel, testssl, service_recon | auto when the port is open; `-m <service>` isolates |
| **B. Alive-URL analysis module** | the alive HTTP URLs | `run_recon_followups()` → `if alive_urls:` block | web_checks, domain_scan, dirsearch, nuclei, js_paths, **archived_urls, param_discovery, favicon_jarm, tech_fingerprint, default_creds, screenshots** | some default; heavy/active ones **opt-in** via a flag (the `extra_scans` mechanism) |
| **C. Passive recon module** | a domain | `_run_parallel_passive()` | dns_recon, cloud_enum, ct_monitor | default for domain targets |
| **D. Pre-probe recon / expansion** | domain + enumerated subs | `handle_domain()` (before `run_recon_followups`) | horizontal_expand, dns_resolve | flag: default-on (`--no-dns-hygiene`) or opt-in (`--horizontal`) |
| **E. Enrichment module** | the final findings list | `_enrich_and_report()` | nvd, cisa_kev, epss, passive_intel | default |
| **F. Reporter / output** | findings → file | `reporter.py` + `_enrich_and_report()` | reporter (CSV/HTML/JSON/SARIF) | CSV+HTML always; JSON/SARIF opt-in |

Most **new** modules today are **Category B** (a check that runs over alive web URLs). Category A is the classic port-triggered service check.

---

## 1. The canonical finding schema (ALL categories)

Every finding is a dict with the **15 canonical keys** in `modules/schema.py` (`CANONICAL_KEYS`). The modern, preferred way to build one is `normalize_finding()` - it fills any missing keys with `"N/A"` and stamps the timestamp, so you only supply what you have:

```python
from modules.schema import normalize_finding

f = normalize_finding({
    "target": host,
    "resolved_ip": ip,
    "port": str(port),
    "vulnerability": "MyService Unauthenticated API Access",
    "status": "VULNERABLE",       # CRITICAL | VULNERABLE | POTENTIAL | INFO
    "severity": "HIGH",           # CRITICAL | HIGH | MEDIUM | LOW | INFO
    "module": "my_module",
    "url": f"https://{host}:{port}/api/status",
    "details": "…",
})
```

During development, assert cleanliness with `validate_finding(f)` (returns a list of violations; `[]` means good). The `server` key is forbidden - use `resolved_ip`.

> **Timestamps:** if you hand-roll a helper, use `datetime.now(timezone.utc)`, never the deprecated `datetime.utcnow()`. `normalize_finding` already does this for you.

### ⚠️ False-positive discipline (read this before emitting any VULNERABLE finding)

A weak oracle is the #1 way to generate hundreds of false findings. **Never** emit a vulnerability/exposure finding from a *weak signal* alone (HTTP status code, a path/name match, a single spoofable header). You must validate the response **content**, and for active checks add a **negative control**:

- Exposed-file checks (`.git`, `.env`, `.sql`, backups): require the body to actually be that artifact (`ref: refs/`, `KEY=VALUE`, SQL markers, a binary content-type) and reject HTML catch-all bodies. See `web_checks.check_sensitive_files` and `archived_urls._validate_exposure` (which also runs a per-host **soft-404 baseline** - probe a bogus path; if it 200s, the host is a catch-all and matching bodies are dropped).
- Default-credential / auth checks: confirm access with a positive oracle a login-page 200 can't satisfy, **and** run a deliberately-wrong credential as a negative control. See `default_creds.py`.
- EOL/version claims: require a concrete detected version mapped to a real past EOL date. See `tech_fingerprint.py`.
- Heuristic tags (e.g. `gf` patterns): emit **INFO "candidate"**, never a confirmed vuln. See `param_discovery.py`.

Your test suite **must** include a negative case proving the false positive does not fire (catch-all → no finding).

### Live progress + graceful tool skipping (Categories B/C/D)

If your module shells out to an external tool, detect it with `shutil.which` and **skip gracefully** when absent (print one info line, return `[]`/empty - never crash, never auto-install). For liveness on the dashboard, use `modules/progress.py`:

```python
from modules.progress import DashboardProgress, heartbeat

prog = DashboardProgress("my_module", total=len(items), noun="hosts")
results = await asyncio.gather(*(prog.wrap(_do(i)) for i in items), return_exceptions=True)
# or, for one opaque long op:
async with heartbeat("my_module", "Doing the thing"):
    await long_running()
```

Both no-op safely when the dashboard is inactive. See `modules/gau_runner.py` for the tool-wrap + `shutil.which` + graceful-skip pattern to copy.

---

## 2. Category A - port-triggered service module

Runs automatically when the scanner finds a matching open port (and via `-m <service>`).

### 2.1 Entry point

```python
async def run_scans(target_obj, port, **_):
    host = target_obj["scan_address"]
    resolved_ip = target_obj.get("resolved_ip", host)
    display = target_obj.get("display_target", host)
    findings = []
    # ... probe host:port, build findings via normalize_finding ...
    return findings   # list[dict]
```

`target_obj` keys: `scan_address` (what to connect to), `display_target` (report label), `resolved_ip`.

### 2.2 Register it (3 edits in `main.py` + `modules/__init__.py`)

1. `modules/__init__.py` - add `from . import my_module`.
2. `main.py` - add `my_module` to the `from modules import ( … )` block.
3. `main.py` - add to `SERVICE_TO_MODULE` (the single source of truth for dispatch; the key is the `-m` value):

   ```python
   SERVICE_TO_MODULE = {
       "elasticsearch": elastic, "kibana": kibana, "grafana": grafana,
       "prometheus": prometheus, "nextjs": react_to_shell, "aem": aem,
       "cpanel": cpanel, "service_recon": service_recon, "jenkins": jenkins,
       "testssl": testssl_runner,
       "my_service": my_module,      # <-- add; "my_service" is the -m value
   }
   ```

4. **Port mapping** - add your service + its default ports to `get_service_ports()` in `utils.py`, or the scan loop will never auto-route traffic to your module. (The `web` and `cpanel_adjacent` pseudo-services are handled specially and are not in `SERVICE_TO_MODULE`.)

### 2.3 Optional: fingerprint-gated dispatch via `service_recon.py`

If you want an nmap-discovered / shared port to auto-invoke your check without `-m`, add a `check_*` function to `service_recon.py`, map it in `PORT_DISPATCH`, and (for shared ports like 8080) add the port to `SHARED_PORTS`, add your check to `CHECK_REQUIRES_TAG`, and add a `('my_tag', ['keyword', …])` entry to the `_fingerprint()` markers list so a real service is confirmed before your check runs (anti-false-positive gate).

---

## 3. Category B - alive-URL analysis module (the common new pattern)

This is what `archived_urls`, `param_discovery`, `favicon_jarm`, `tech_fingerprint`, `default_creds`, and `screenshots` are. It runs over the list of alive HTTP URLs discovered by httpx.

### 3.1 Entry point (a plain async function - NOT `run_scans`)

```python
async def analyze(alive_urls: list[str], output_dir: str, concurrency: int = 20) -> list[dict]:
    if not alive_urls:
        return []
    findings = []
    # ... work concurrently; use normalize_finding; validate content (no FPs!) ...
    return findings
```

Return `[]` (never raise) on empty input or a missing tool.

### 3.2 Wire it into `run_recon_followups()`

Inside `run_recon_followups()`, find the **`if alive_urls:` block** (where `nuclei`, `web_checks`, `dirsearch`, `js_paths` already run). Add your call there. Then add its result to the module's `all_findings`. Two sub-cases:

**Default-on** (cheap, low-risk) - call it directly, or gate on a dedicated boolean param like `enable_archived`:

```python
if alive_urls:
    ...
    my_findings = await my_module.analyze(alive_urls, output_dir, concurrency)
    all_findings.extend(my_findings)
```

**Opt-in** (heavy at scale, active, or tool-dependent) - use the **`extra_scans`** mechanism (this is the standard for per-URL heavy modules; a recon run can hit 60k+ alive URLs, so default-on is dangerous):

```python
if "my_scan" in extra_scans:
    my_findings = await my_module.analyze(alive_urls, output_dir, concurrency)
    all_findings.extend(my_findings)
```

`run_recon_followups()` already takes `extra_scans=frozenset()`. See §5 for how the flag reaches it.

### 3.3 It also runs under `enum --probe` and `scan --posture`?

- `enum <domain> --probe` chains into the same `run_recon_followups()`, so a Category-B module wired there **automatically** runs under `enum --probe` too.
- `scan --posture` does **not** run `run_recon_followups` (it only runs `DomainScanner` + httpx), so posture triage will not include your module. That's intended - posture is deliberately lightweight.

---

## 4. Categories C, D, E - passive recon, pre-probe expansion, enrichment

**C. Passive recon (per domain)** - runs in `_run_parallel_passive()` alongside `dns_recon`, `cloud_enum`, `ct_monitor`, concurrently, for domain targets. Return a findings list; the caller buffers it into `recon_phase_findings` (which is flushed into the report later). Entry point shape: `async def run(domain, concurrency, ...) -> list[dict]`.

**D. Pre-probe recon / expansion** - runs in `handle_domain()` **before** `run_recon_followups()`, so it can clean or expand the subdomain set that gets probed (like `dns_resolve`, which feeds a wildcard-filtered list forward) or discover new scope (`horizontal_expand`). Entry point often returns a dict (`{"resolved": [...], "findings": [...]}`) so the caller can both feed hosts forward and collect findings. Gate with a flag (default-on `dns_hygiene` or opt-in `enable_horizontal`).

**E. Enrichment** - runs in `_enrich_and_report()` over the **deduplicated final findings list** (like `nvd`, `cisa_kev`, `epss`, `passive_intel`). It mutates/augments findings in place or returns additions. It does not probe targets; it decorates findings. Add your call into the enrichment `asyncio.gather` in `_enrich_and_report()`.

---

## 5. CLI flag mechanics - how a flag reaches your module

There are two flag styles. Both live in the `scan` subparser (search `sp_scan.add_argument`) and are read in `cmd_scan()`.

### 5.1 Opt-in scan (the `extra_scans` set) - for Category-B heavy/active modules

Four small edits:

1. **argparse** (`sp_scan`):
   ```python
   sp_scan.add_argument("--my-scan", action="store_true", dest="my_scan",
                        help="… (off by default; skips if tool absent)")
   ```
2. **`cmd_scan()`** - add your name to the `extra_scans` frozenset it builds and passes to `main()`:
   ```python
   extra_scans=frozenset(name for name, on in (
       ("params", getattr(args, 'params', False)),
       ...
       ("my_scan", getattr(args, 'my_scan', False)),
   ) if on),
   ```
3. **`main()`** already forwards `extra_scans` to its `run_recon_followups()` calls - no change needed there.
4. **`run_recon_followups()`** - check `if "my_scan" in extra_scans:` (see §3.2).

### 5.2 Default-on with an off-switch - for Categories B/D that reduce noise or are cheap

Use `--no-x` (store_false, default True), e.g. `--no-archived-scan`, `--no-dns-hygiene`:

```python
sp_scan.add_argument("--no-my-thing", action="store_false", dest="my_thing", default=True,
                     help="Disable … (on by default).")
```

Then thread it as an explicit `main()` parameter (like `archived_scan`, `dns_hygiene`) → into `run_recon_followups()` / `handle_domain()`, and pass `my_thing=getattr(args, 'my_thing', True)` from `cmd_scan()`.

> Rule of thumb: **default-on** for anything that improves quality or is cheap and passthrough-safe (wildcard filtering, archived-URL analysis). **Opt-in** for anything that is per-URL heavy (favicon/tech/params/screenshots), active (default-creds), or scope-expanding (horizontal).

---

## 6. Output / reporting - you don't write your own report

Findings returned from your entry point flow into the shared tail: dedup → enrichment (NVD/KEV/EPSS/passive-intel) → **CSV + HTML always**, JSON/SARIF opt-in (`--format`, `--sarif`) → SQLite inventory delta → alerts (`notify.py`). You only *return findings*; `_enrich_and_report()` handles persistence. (A standalone `-m` mode that returns early may write its own CSV/HTML via `reporter.save_results_to_csv`/`save_results_to_html` - see the `domain-scan`/posture branch.)

---

## 7. Tests - `tests/test_<your_module>.py`

Mock all subprocess/network so tests run with no tools/network. Cover:

- **Canonical schema**: every emitted finding passes `validate_finding` (`[]` violations).
- **Positive case**: a genuine hit produces the expected finding/severity.
- **Negative case (required for anything making a claim)**: a catch-all / always-200 / wrong-credential / supported-version input yields **no** finding.
- **Graceful skip**: with the tool absent (`shutil.which` → None), returns `[]` and spawns no subprocess.
- **Empty input** → `[]`.

```bash
python -m pytest tests/ -q     # the whole suite must stay green
```

(The suite currently has 300+ tests across ~36 files - all must continue to pass.)

---

## 8. Quick checklist

```
[ ] Category chosen (A port-service / B alive-URL / C passive / D pre-probe / E enrichment)
[ ] Findings built via schema.normalize_finding (15 canonical keys, no `server` key)
[ ] CONTENT/response oracle for any VULNERABLE claim (+ negative control for active checks)
[ ] External tool detected via shutil.which and skipped gracefully if absent
[ ] Live progress via modules/progress.py (DashboardProgress / heartbeat)
[ ] Wired into the right place:
      A -> modules/__init__.py + main.py import + SERVICE_TO_MODULE + get_service_ports()
      B -> run_recon_followups() `if alive_urls:` block (+ extra_scans gate if opt-in)
      C -> _run_parallel_passive()
      D -> handle_domain() before run_recon_followups()
      E -> _enrich_and_report() enrichment gather
[ ] Flag added if opt-in/default-off (extra_scans) or default-on off-switch (--no-x), threaded main()->cmd_scan
[ ] tests/test_<module>.py: schema + positive + NEGATIVE(no-FP) + graceful-skip + empty
[ ] python -m pytest tests/ -q passes
[ ] README.md + TODO.md updated
```

---

## Appendix - adding a check to an *existing* module

When the finding belongs inside an existing module (a new CVE for Grafana, a new sensitive path for `web_checks`, a new record type in `dns_recon`):

1. Add an `async def check_*` function that uses the module's `_finding()`/`normalize_finding`, **validates the response body (not just status)**, wraps everything in `try/except`, and returns `[]` when it does not fire.
2. Add it to the module's `run_scans()` (or its internal `asyncio.gather`).
3. Add a test with a **fires** case and a **does-not-fire** case.
4. Run the full suite. Don't refactor surrounding code unless required.

| Situation | Action |
|---|---|
| New CVE/technique for a service already in a module | Add a `check_*()` inside that module |
| New port/protocol, wholly different service | New Category-A module |
| New HTTP check for all alive URLs | Add to `web_checks.py` (or a new Category-B module) |
| New DNS record / validation rule | Add to `dns_recon.py` |
