# Adding a Scanner Module to VaktScan

This guide walks through every file that must be touched when adding a new first-class scanner module (one that is dispatched by `-m <service>` and participates in the automatic port-based scan loop).

For lightweight service checks that piggyback on existing port discovery without their own top-level `-m` flag, see the [service_recon.py section](#4-modulesservice_reconpy--port-triggered-checks) below.

---

## Overview of files to touch

| File | Change |
|------|--------|
| `modules/<your_module>.py` | New file — the module itself |
| `modules/__init__.py` | One-line import |
| `main.py` | Two edits: import block + `SERVICE_TO_MODULE` dict |
| `modules/service_recon.py` | Optional — if you want nmap-discovered ports to auto-invoke your checks |
| `tests/test_<your_module>.py` | New test file |
| `TODO.md` | Add to the relevant section for tracking |

---

## 1. Create `modules/<your_module>.py`

### Required entry point

Every module must expose a single coroutine with this exact signature:

```python
async def run_scans(target_obj, port, **_):
```

`target_obj` is a dict with three keys:

| Key | Type | Description |
|-----|------|-------------|
| `scan_address` | `str` | The address actually connected to (IP or hostname) |
| `display_target` | `str` | Human-readable label used in reports |
| `resolved_ip` | `str` | Resolved IPv4/IPv6, falls back to `scan_address` |

`run_scans` must return `list[dict]`, where every dict contains all 15 canonical keys (see schema section below).

### The `_finding()` helper

Every module defines a local `_finding()` helper that builds a schema-conformant dict. Copy this pattern:

```python
"""
VaktScan <ServiceName> Module

Checks: <brief list of what this module checks>
"""

import asyncio
from datetime import datetime, timezone

import httpx

MODULE_NAME = "<ServiceName>"

DEFAULT_PORTS = [<port1>, <port2>]


def _finding(status, severity, vulnerability, details, target, resolved_ip, port,
             url="", payload_url="", service_version="",
             http_status="N/A", page_title="N/A", content_length="N/A"):
    return {
        "status": status,
        "severity": severity,
        "vulnerability": vulnerability,
        "target": target,
        "resolved_ip": resolved_ip,
        "port": port,
        "url": url or f"http://{target}:{port}",
        "payload_url": payload_url or url or f"http://{target}:{port}",
        "module": MODULE_NAME,
        "service_version": service_version,
        "details": details,
        "http_status": str(http_status),
        "page_title": page_title,
        "content_length": str(content_length),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
```

**Timestamp note**: Use `datetime.now(timezone.utc)` rather than `datetime.utcnow()`. The `utcnow()` method is deprecated in Python 3.12 and five existing modules are already flagged for this migration. All new modules must use the timezone-aware form.

### Protocol detection helper

Most HTTP-based modules need to probe for HTTPS vs HTTP before issuing checks:

```python
async def _detect_protocol(host, port, timeout=5):
    for scheme in ("https", "http"):
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as c:
                r = await c.get(f"{scheme}://{host}:{port}/")
                if r.status_code < 600:
                    return scheme
        except Exception:
            continue
    return "http"
```

### Complete minimal module

```python
"""
VaktScan MyService Module

Checks: unauthenticated access, default credentials
"""

import asyncio
from datetime import datetime, timezone

import httpx

MODULE_NAME = "MyService"

DEFAULT_PORTS = [8765]


def _finding(status, severity, vulnerability, details, target, resolved_ip, port,
             url="", payload_url="", service_version="",
             http_status="N/A", page_title="N/A", content_length="N/A"):
    return {
        "status": status,
        "severity": severity,
        "vulnerability": vulnerability,
        "target": target,
        "resolved_ip": resolved_ip,
        "port": port,
        "url": url or f"http://{target}:{port}",
        "payload_url": payload_url or url or f"http://{target}:{port}",
        "module": MODULE_NAME,
        "service_version": service_version,
        "details": details,
        "http_status": str(http_status),
        "page_title": page_title,
        "content_length": str(content_length),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


async def _detect_protocol(host, port, timeout=5):
    for scheme in ("https", "http"):
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as c:
                r = await c.get(f"{scheme}://{host}:{port}/")
                if r.status_code < 600:
                    return scheme
        except Exception:
            continue
    return "http"


async def _check_unauthenticated_access(client, base_url, target, resolved_ip, port):
    findings = []
    try:
        r = await client.get(f"{base_url}/api/status")
        if r.status_code == 200 and "myservice" in r.text.lower():
            findings.append(_finding(
                status="VULNERABLE",
                severity="HIGH",
                vulnerability="MyService Unauthenticated API Access",
                details=f"API accessible without authentication at /api/status",
                target=target,
                resolved_ip=resolved_ip,
                port=port,
                url=f"{base_url}/api/status",
                http_status=r.status_code,
            ))
    except Exception:
        pass
    return findings


async def run_scans(target_obj, port, **_):
    host = target_obj["scan_address"]
    resolved_ip = target_obj.get("resolved_ip", host)
    display = target_obj.get("display_target", host)
    findings = []

    scheme = await _detect_protocol(host, port)
    base_url = f"{scheme}://{host}:{port}"

    async with httpx.AsyncClient(
        timeout=10, verify=False, follow_redirects=True
    ) as client:
        tasks = [
            _check_unauthenticated_access(client, base_url, display, resolved_ip, port),
            # add more check coroutines here
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, dict):
                findings.append(r)

    return findings
```

### Allowed field values

`status` must be one of: `CRITICAL`, `VULNERABLE`, `POTENTIAL`, `INFO`

`severity` must be one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

---

## 2. `modules/__init__.py`

Add one import line alongside the existing 19 module imports (line ~21):

```python
# modules/__init__.py  (current last line is line 20: `from . import cisa_kev`)
from . import my_module
```

The current file ends at line 21. Append your import after `from . import cisa_kev`.

---

## 3. `main.py` — two edits

### Edit 1: the explicit import block (lines 43–70)

The block starting at line 43 imports every module by name. Add your module to the list:

```python
from modules import (
    elastic,
    kibana,
    grafana,
    prometheus,
    react_to_shell,
    recon,
    httpx_runner,
    nuclei_runner,
    nmap_runner,
    dir_enum,
    gau_runner,
    waybackurls_runner,
    domain_scan,
    js_paths,
    aem,
    cpanel,
    dns_recon,
    service_recon,
    web_checks,
    cisa_kev,
    epss,
    jenkins,
    passive_intel,
    inventory,
    cloud_enum,
    nvd,
    my_module,      # <-- add here
)
```

### Edit 2: the `SERVICE_TO_MODULE` dict (lines 73–83)

This dict is the single source of truth for dispatch. It is consumed at lines 1157, 1162, 1164, 1436, 1440, and 1442 — all reads go through the same dict, so one new entry covers all call sites:

```python
SERVICE_TO_MODULE = {
    "elasticsearch": elastic,
    "kibana":        kibana,
    "grafana":       grafana,
    "prometheus":    prometheus,
    "nextjs":        react_to_shell,
    "aem":           aem,
    "cpanel":        cpanel,
    "service_recon": service_recon,
    "jenkins":       jenkins,
    "my_service":    my_module,   # <-- add here; key is the -m flag value
}
```

The key you choose here is exactly what users pass to `-m my_service` and what the scan loop matches against `service_ports` (the port-to-service mapping). Make sure the key also appears in the `service_ports` dict (defined nearby in `main.py`) with the correct port list, or the scan loop will never automatically route traffic to your module.

---

## 4. `modules/service_recon.py` — port-triggered checks

This section is only needed if you want nmap-discovered ports to automatically invoke your checks through the `service_recon` dispatcher, without requiring users to pass `-m my_service` explicitly.

### 4a. Define the check function

Check functions in `service_recon.py` follow this convention:

```python
async def check_my_service(host, port, target, resolved_ip):
    """Check MyService for unauthenticated access."""
    findings = []
    # ... probe logic ...
    return findings
```

Note the argument order: `host, port, target, resolved_ip` — this is what `run_scans()` at line 3054 passes to every check function.

### 4b. `PORT_DISPATCH` (line 2906)

Map the service's default TCP port to the check function:

```python
PORT_DISPATCH = {
    # ... existing entries ...
    8765: check_my_service,
}
```

If the port is already used by other services (i.e., it is a shared port), use a list:

```python
8765: [check_existing_service, check_my_service],
```

### 4c. `SHARED_PORTS` and `CHECK_REQUIRES_TAG` (lines 2998–3027)

If your service shares a port with others, add the port to `SHARED_PORTS` and add your check function to `CHECK_REQUIRES_TAG` so the fingerprinter gates it:

```python
SHARED_PORTS = {80, 443, 8080, ..., 8765}  # add your port

CHECK_REQUIRES_TAG = {
    # ... existing entries ...
    check_my_service: 'my_service_tag',
}
```

### 4d. `_fingerprint` markers list (line 2862)

Add a fingerprint entry inside the `_fingerprint()` coroutine so the dispatcher can identify the service by response body/header keywords. The list is inside a `for tag, markers in [...]` loop:

```python
('my_service_tag', ['myservice', 'my-service-keyword']),
```

The fingerprinter checks `Server` header + `X-Powered-By` header + the first 4096 bytes of the response body. Pick keywords that are reliably present in genuine responses but unlikely in other services.

---

## 5. Schema validation

Import `validate_finding` from `modules.schema` and call it on every finding before returning, especially during development:

```python
from modules.schema import validate_finding

async def run_scans(target_obj, port, **_):
    # ... build findings ...
    for f in findings:
        violations = validate_finding(f)
        if violations:
            # log or raise during development; remove in production
            print(f"[!] Schema violation in {MODULE_NAME}: {violations}")
    return findings
```

The 15 canonical keys are defined in `modules/schema.py:CANONICAL_KEYS` (lines 6–22). Missing any key will fail validation downstream in the reporter. The `server` key is explicitly forbidden (line 54 in schema.py) — use `resolved_ip` instead.

`normalize_finding()` in the same file can be used to fill missing keys with `"N/A"` defaults as a fallback, but it is better to emit complete findings from the start.

---

## 6. Tests — `tests/test_<your_module>.py`

Place tests in the `tests/` directory. The existing suite uses `unittest.TestCase` throughout. Follow this pattern:

```python
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from modules.schema import CANONICAL_KEYS, validate_finding
import modules.my_module as my_module


class TestMyModuleFinding(unittest.TestCase):
    """Unit tests for _finding() helper — no network required."""

    def test_finding_has_all_canonical_keys(self):
        f = my_module._finding(
            status="INFO",
            severity="INFO",
            vulnerability="Test",
            details="details",
            target="example.com",
            resolved_ip="1.2.3.4",
            port=8765,
        )
        for key in CANONICAL_KEYS:
            self.assertIn(key, f, f"Missing canonical key: {key}")

    def test_finding_passes_schema_validation(self):
        f = my_module._finding(
            status="VULNERABLE",
            severity="HIGH",
            vulnerability="Test",
            details="details",
            target="example.com",
            resolved_ip="1.2.3.4",
            port=8765,
        )
        violations = validate_finding(f)
        self.assertEqual(violations, [], f"Schema violations: {violations}")

    def test_finding_timestamp_format(self):
        f = my_module._finding(
            status="INFO", severity="INFO",
            vulnerability="T", details="d",
            target="h", resolved_ip="1.2.3.4", port=8765,
        )
        self.assertTrue(f["timestamp"].endswith("Z"))

    def test_finding_module_name(self):
        f = my_module._finding(
            status="INFO", severity="INFO",
            vulnerability="T", details="d",
            target="h", resolved_ip="1.2.3.4", port=8765,
        )
        self.assertEqual(f["module"], my_module.MODULE_NAME)


class TestRunScans(unittest.IsolatedAsyncioTestCase):
    """Integration-style tests with mocked HTTP."""

    async def test_run_scans_returns_list(self):
        target_obj = {
            "scan_address": "127.0.0.1",
            "display_target": "example.com",
            "resolved_ip": "127.0.0.1",
        }
        # Patch httpx to avoid real network calls
        with patch("modules.my_module.httpx.AsyncClient") as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.status_code = 403
            mock_resp.text = ""
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await my_module.run_scans(target_obj, 8765)
            self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
```

Run the full suite to confirm nothing is broken:

```
python -m pytest tests/ -q
```

The suite currently contains 94 tests across 15 test files. All must continue to pass after your addition.

---

## 7. `TODO.md` — tracking

Add your new service to the appropriate section in `TODO.md`. The file uses these sections:

- **Section 2: Missing Service Checks** — CI/CD, Cloud-Native, Infrastructure & Monitoring sub-tables. Add a row to the relevant sub-table:

```markdown
| **MyService** | 8765 | Unauthenticated access, default credentials, CVE-XXXX-YYYY |
```

- **Section 3: Missing Recon / Discovery** — for passive/recon-oriented modules rather than active service checks.

If the check is already fully implemented, mark the section header with `✅ DONE` (matching the existing convention for Sections 1 and 2).

---

## Quick checklist

```
[ ] modules/my_module.py created
      [ ] run_scans(target_obj, port, **_) defined
      [ ] _finding() returns all 15 canonical keys
      [ ] timestamp uses datetime.now(timezone.utc), not utcnow()
      [ ] status is one of CRITICAL/VULNERABLE/POTENTIAL/INFO
      [ ] severity is one of CRITICAL/HIGH/MEDIUM/LOW/INFO
[ ] modules/__init__.py — from . import my_module added
[ ] main.py edit 1 — my_module added to the from modules import (...) block
[ ] main.py edit 2 — "my_service": my_module added to SERVICE_TO_MODULE
[ ] modules/service_recon.py (if port-triggered)
      [ ] check_my_service() defined
      [ ] PORT_DISPATCH entry added
      [ ] SHARED_PORTS updated (if port is shared)
      [ ] CHECK_REQUIRES_TAG entry added (if port is shared)
      [ ] _fingerprint markers tuple added
[ ] tests/test_my_module.py created
      [ ] _finding() canonical key coverage test
      [ ] schema validation test
      [ ] run_scans() returns list test
[ ] python -m pytest tests/ -q passes (all 94+ tests green)
[ ] TODO.md updated
```
