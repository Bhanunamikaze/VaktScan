#!/usr/bin/env python3
"""
Coverage verifier for the cPanel module.

Asserts the invariants documented in cpanel_plan.md §4.4, §10.4, §12:

1. Every entry in OBSERVABLE_CVE_CHECKS has the oracle triple
   (positive + control + indicator).
2. The TSR archive is loaded and contains at least the seeded bulletins.
3. The bundled-component CVE table contains the must-call-out CVEs from
   §4.3.
4. Every primary cPanel port from §1a is registered in
   utils.get_service_ports().
5. Every check_* function in modules/cpanel.py is referenced from
   run_scans (no orphan checks).
6. Every finding emitted by the module's helper factory satisfies the
   §9c.2 schema (required keys, valid status vocabulary).

Run: python scripts/verify_cpanel_coverage.py
Exits 0 on success, non-zero with a human-readable failure list otherwise.
"""
import ast
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from modules import cpanel  # noqa: E402
from utils import get_service_ports  # noqa: E402

# Must-call-out CVEs (cpanel_plan.md §4.3 "never-miss" list).
MUST_CALL_OUT_CVES = {
    'CVE-2024-25602',
    'CVE-2024-37383',
    'CVE-2024-23184',
    'CVE-2024-4577',
    'CVE-2024-38476',
    'CVE-2023-25690',
    'CVE-2019-10149',
    'CVE-2020-28017',
    'CVE-2022-30287',
    'CVE-2024-6387',
    'CVE-2014-0160',
    'CVE-2015-3306',
    'CVE-2017-1000501',
    'CVE-2023-49103',
}

# Primary ports from cpanel_plan.md §1a.
PRIMARY_PORTS = {
    2077, 2078, 2079, 2080,
    2082, 2083,
    2086, 2087,
    2089,
    2095, 2096,
    9998, 9999,
    80, 443,
}


def main():
    failures = []

    # 1. Oracle completeness.
    for cve_id, meta in cpanel.OBSERVABLE_CVE_CHECKS.items():
        if 'oracle' not in meta:
            failures.append(f"[oracle] {cve_id} missing oracle key")
            continue
        for k in ('positive', 'control', 'indicator'):
            if k not in meta['oracle'] or not callable(meta['oracle'][k]):
                failures.append(f"[oracle] {cve_id} oracle missing/non-callable: {k}")
        if 'drop_if' not in meta['oracle']:
            failures.append(f"[oracle] {cve_id} oracle missing drop_if")
        for k in ('description', 'severity', 'status', 'surface', 'details'):
            if k not in meta:
                failures.append(f"[oracle] {cve_id} metadata missing: {k}")

    # 2. TSR archive non-empty.
    if not cpanel.CPANEL_SECURITY_BULLETINS:
        failures.append("[tsr] CPANEL_SECURITY_BULLETINS is empty — cpanel_tsr.json failed to load")

    # 3. Must-call-out CVEs in bundled table.
    all_bundled = set()
    for entries in cpanel.BUNDLED_COMPONENT_CVES.values():
        for entry in entries:
            all_bundled.add(entry['cve'])
    missing = MUST_CALL_OUT_CVES - all_bundled
    for cve in sorted(missing):
        failures.append(f"[bundled] must-call-out CVE missing: {cve}")

    # 4. Primary ports registered.
    registered = set(get_service_ports().get('cpanel', []))
    for p in sorted(PRIMARY_PORTS - registered):
        failures.append(f"[ports] primary port {p} not registered in utils.get_service_ports()['cpanel']")

    # 5. Every check_* function is wired into run_scans.
    cpanel_src = open(os.path.join(ROOT, 'modules', 'cpanel.py'), 'r', encoding='utf-8').read()
    tree = ast.parse(cpanel_src)
    check_funcs = set()
    run_scans_calls = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            if node.name.startswith('check_'):
                check_funcs.add(node.name)
            if node.name == 'run_scans':
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                        run_scans_calls.add(sub.func.id)
    for f in sorted(check_funcs - run_scans_calls):
        failures.append(f"[wiring] check_* function not invoked from run_scans: {f}")

    # 6. Finding-factory schema.
    sample = cpanel._finding(
        status='VULNERABLE', severity='HIGH', vulnerability='X',
        details='Y', payload_url='https://e/x',
    )
    for k in ('status', 'severity', 'vulnerability', 'details', 'payload_url'):
        if k not in sample:
            failures.append(f"[schema] _finding factory missing key: {k}")
    if sample['status'] not in cpanel.VALID_STATUSES:
        failures.append(f"[schema] _finding factory emitted invalid status: {sample['status']}")

    # 7. Status vocabulary matches main.py colour-coding.
    expected_statuses = {'CRITICAL', 'VULNERABLE', 'POTENTIAL', 'INFO'}
    if cpanel.VALID_STATUSES != expected_statuses:
        failures.append(f"[schema] VALID_STATUSES drifted from main.py vocab: {cpanel.VALID_STATUSES}")

    # 8. Domain-scan takeover signature table loaded.
    try:
        from modules import domain_scan
        sig_count = len(domain_scan.TAKEOVER_SIGNATURES)
        if sig_count < 30:
            failures.append(f"[takeover] TAKEOVER_SIGNATURES table too small ({sig_count} < 30)")
    except Exception as e:
        failures.append(f"[takeover] modules.domain_scan failed to load: {e}")
        sig_count = 0

    # 9. DNS recon module loads + has required functions.
    try:
        from modules import dns_recon
        for fn in ('scan_domain', 'run_dns_recon', '_spf_findings', 'check_dmarc'):
            if not hasattr(dns_recon, fn):
                failures.append(f"[dns_recon] missing function: {fn}")
        dns_loaded = True
    except Exception as e:
        failures.append(f"[dns_recon] modules.dns_recon failed to load: {e}")
        dns_loaded = False

    if failures:
        print("VERIFICATION FAILED")
        for fl in failures:
            print(f"  - {fl}")
        sys.exit(1)
    print("OK — cPanel + domain-scan + DNS coverage verified.")
    print(f"  TSR bulletins:        {len(cpanel.CPANEL_SECURITY_BULLETINS)}")
    print(f"  Bundled components:   {len(cpanel.BUNDLED_COMPONENT_CVES)}")
    print(f"  Bundled CVEs:         {len(all_bundled)}")
    print(f"  Observable CVEs:      {len(cpanel.OBSERVABLE_CVE_CHECKS)}")
    print(f"  check_* functions:    {len(check_funcs)}")
    print(f"  Registered ports:     {len(registered)}")
    print(f"  Takeover signatures:  {sig_count}")
    print(f"  DNS module loaded:    {dns_loaded}")


if __name__ == '__main__':
    main()
