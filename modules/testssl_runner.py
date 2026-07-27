"""
VaktScan testssl Module

Checks: SSL/TLS protocols, vulnerabilities, weak certs, misconfigurations
"""

import asyncio
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone

from modules import proc as proc_runner
from modules.schema import validate_finding

MODULE_NAME = "testssl"
DEFAULT_PORTS = [443, 8443, 465, 993, 995]

# Maps testssl.sh finding ``id`` -> human-readable VaktScan vulnerability title.
#
# Keys use the *real* testssl.sh JSON ids (case-sensitive, e.g. "ROBOT",
# "POODLE_SSL", "CRIME_TLS", "secure_client_renego"). A small number of legacy
# lowercase aliases are retained for backward compatibility, and the lookup in
# ``run_scans`` also falls back to a case-insensitive match. The oracle strings
# mined from runcommand.py (SWEET32, ROBOT, POODLE CVE-2014-3566, BEAST
# CVE-2011-3389, BREACH CVE-2013-3587, LOGJAM CVE-2015-4000, RC4, client-initiated
# renegotiation, Obsolete CBC, PFS) were used to cross-check these id mappings.
# Vulnerable-vs-safe is decided by testssl's own severity field (OK/INFO are
# skipped), which is exactly the "not vulnerable"/"not offered" safe-signal that
# runcommand.py greps for in the targeted-flag text output.
VULN_MAP = {
    # Protocols
    "SSLv2": "SSLv2 Protocol Support Enabled",
    "SSLv3": "SSLv3 Protocol Support Enabled",
    "TLS1": "TLSv1.0 Protocol Support Enabled",
    "TLS1_1": "TLSv1.1 Protocol Support Enabled",

    # Vulnerabilities (real testssl.sh ids)
    "heartbleed": "SSL/TLS Vulnerability: Heartbleed (CVE-2014-0160)",
    "CCS": "SSL/TLS Vulnerability: OpenSSL CCS Injection (CVE-2014-0224)",
    "ticketbleed": "SSL/TLS Vulnerability: Ticketbleed (CVE-2016-9244)",
    "ROBOT": "SSL/TLS Vulnerability: ROBOT Attack (CVE-2017-13098)",
    "CRIME_TLS": "SSL/TLS Vulnerability: CRIME (CVE-2012-4929)",
    "BREACH": "SSL/TLS Vulnerability: BREACH (CVE-2013-3587)",
    "POODLE_SSL": "SSL/TLS Vulnerability: POODLE (CVE-2014-3566)",
    "SWEET32": "SSL/TLS Vulnerability: SWEET32 (CVE-2016-2183)",
    "LOGJAM": "SSL/TLS Vulnerability: LOGJAM (CVE-2015-4000)",
    "LOGJAM-common_primes": "Weak Diffie-Hellman Common Primes (LOGJAM-related, CVE-2015-4000)",
    "FREAK": "SSL/TLS Vulnerability: FREAK (CVE-2015-0204)",
    "DROWN": "SSL/TLS Vulnerability: DROWN (CVE-2016-0800)",
    "BEAST": "SSL/TLS Vulnerability: BEAST (CVE-2011-3389)",
    "BEAST_CBC_TLS1": "SSL/TLS Vulnerability: BEAST (CVE-2011-3389)",
    "RC4": "SSL/TLS Vulnerability: Weak RC4 Ciphers Enabled (CVE-2013-2566)",
    "LUCKY13": "SSL/TLS Vulnerability: Lucky13 (CVE-2013-0169)",
    "winshock": "SSL/TLS Vulnerability: Winshock (CVE-2014-6321)",
    "raccoon": "SSL/TLS Vulnerability: Raccoon (CVE-2020-1967)",

    # Weak / obsolete cipher categories (testssl `run_cipher_categories` ids)
    "cipherlist_NULL": "NULL Cipher Suites Offered (No Encryption)",
    "cipherlist_aNULL": "Anonymous (aNULL) Cipher Suites Offered",
    "cipherlist_EXPORT": "Export-grade Cipher Suites Offered",
    "cipherlist_LOW": "Weak (LOW / 64-bit / DES) Cipher Suites Offered",
    "cipherlist_3DES_IDEA": "Weak 3DES / IDEA Cipher Suites Offered (SWEET32-related)",
    "cipherlist_OBSOLETED": "Obsolete CBC Cipher Suites Offered",

    # Forward secrecy
    "FS": "Missing Forward Secrecy (PFS) Support",

    # Certificate Quality
    "cert_signature": "Weak SSL/TLS Certificate Signature Algorithm",
    "cert_signatureAlgorithm": "Weak SSL/TLS Certificate Signature Algorithm",
    "cert_keySize": "Weak SSL/TLS Certificate Key Size",
    "cert_trust": "Untrusted SSL/TLS Certificate Chain",
    "cert_chain_of_trust": "Untrusted SSL/TLS Certificate Chain",
    "cert_expirationStatus": "SSL/TLS Certificate Expired or Nearing Expiry",
    "cert_expiration_status": "SSL/TLS Certificate Expired or Nearing Expiry",

    # Misconfigurations
    "HSTS": "Missing or Misconfigured Strict-Transport-Security (HSTS) Header",
    "HSTS_time": "Missing or Misconfigured Strict-Transport-Security (HSTS) Header",
    "secure_renego": "Insecure SSL/TLS Renegotiation Supported",
    "secure_client_renego": "Insecure Client-Initiated SSL/TLS Renegotiation Allowed",
    "fallback_SCSV": "Missing TLS Fallback Signaling Cipher Suite Value (SCSV) Support",

    # Legacy lowercase aliases (kept for backward compatibility)
    "robot": "SSL/TLS Vulnerability: ROBOT Attack (CVE-2017-13098)",
    "crime": "SSL/TLS Vulnerability: CRIME (CVE-2012-4929)",
    "breach": "SSL/TLS Vulnerability: BREACH (CVE-2013-3587)",
    "poodle": "SSL/TLS Vulnerability: POODLE (CVE-2014-3566)",
    "sweet32": "SSL/TLS Vulnerability: SWEET32 (CVE-2016-2183)",
    "logjam": "SSL/TLS Vulnerability: LOGJAM (CVE-2015-4000)",
    "freak": "SSL/TLS Vulnerability: FREAK (CVE-2015-0204)",
    "rc4": "SSL/TLS Vulnerability: Weak RC4 Ciphers Enabled",
    "lucky13": "SSL/TLS Vulnerability: Lucky13 (CVE-2013-0169)",
    "secure_reneg": "Insecure Client-Initiated SSL/TLS Renegotiation Allowed",
}

# Severities that indicate a safe / informational result - skipped entirely.
# testssl emits "OK" for the "not vulnerable" / "not offered" / "PFS is offered"
# safe-signals that runcommand.py greps for.
_SKIP_SEVERITIES = {"OK", "INFO", "FATAL", "DEBUG", ""}


def _iter_scan_findings(data):
    """Yield finding-shaped dicts from testssl JSON output.

    Supports both layouts testssl.sh can emit:

    * Flat ``--jsonfile`` layout - a top-level list, or a ``scanResult`` whose
      entries are themselves findings (``{"id", "severity", "finding"}``). This
      is the shape the legacy parser and existing unit test rely on.
    * Nested ``--jsonfile-pretty`` layout - ``scanResult`` is a list of per-host
      objects, each containing category arrays (``protocols``,
      ``vulnerabilities``, ``fs``, ``serverDefaults``, ``ciphers`` ...) whose
      items are the actual findings.
    """
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "id" in item:
                yield item
        return

    if not isinstance(data, dict):
        return

    for res in data.get("scanResult", []) or []:
        if not isinstance(res, dict):
            continue
        # Flat-per-host layout: the entry itself is a finding.
        if "id" in res and "severity" in res:
            yield res
            continue
        # Nested pretty layout: descend one level into category arrays.
        for value in res.values():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and "id" in item and "severity" in item:
                        yield item

def _finding(status, severity, vulnerability, details, target, resolved_ip, port,
             url="", payload_url="", service_version="",
             http_status="N/A", page_title="N/A", content_length="N/A"):
    return {
        "status": status,
        "severity": severity,
        "vulnerability": vulnerability,
        "target": target,
        "resolved_ip": resolved_ip,
        "port": str(port),
        "url": url or f"https://{target}:{port}",
        "payload_url": payload_url or url or f"https://{target}:{port}",
        "module": MODULE_NAME,
        "service_version": service_version,
        "details": details,
        "http_status": str(http_status),
        "page_title": page_title,
        "content_length": str(content_length),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

async def run_scans(target_obj, port, **_):
    host = target_obj["scan_address"]
    resolved_ip = target_obj.get("resolved_ip", host)
    display = target_obj.get("display_target", host)
    findings = []

    binary = shutil.which("testssl") or shutil.which("testssl.sh")
    if not binary:
        return findings

    # Create a temporary file for JSON output
    fd, temp_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)

    try:
        # Run testssl.sh: testssl --jsonfile-pretty <temp_path> --overwrite --severity LOW --nodns none <host>:<port>
        cmd = [
            binary,
            "--jsonfile-pretty", temp_path,
            "--overwrite",
            "--severity", "LOW",
            "--nodns", "none",
            f"{host}:{port}"
        ]

        # Run the scan (buffered) with a per-host timeout of 5 minutes
        result = await proc_runner.run_tool(cmd, timeout=300)
        stdout, stderr = result.stdout, result.stderr
        
        if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
            with open(temp_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
                
            for res in _iter_scan_findings(data):
                vuln_id = res.get("id")
                severity = res.get("severity")
                finding_desc = res.get("finding", "")

                # Skip safe/informational results. testssl marks "not vulnerable"
                # / "not offered" / "PFS is offered (OK)" as severity OK, which is
                # exactly the safe-signal runcommand.py checks for.
                if not vuln_id or severity in _SKIP_SEVERITIES:
                    continue
                    
                # Map severity
                vakt_severity = {
                    "CRITICAL": "CRITICAL",
                    "HIGH": "HIGH",
                    "MEDIUM": "MEDIUM",
                    "LOW": "LOW",
                    "WARN": "LOW",
                }.get(severity, "LOW")
                
                vakt_status = {
                    "CRITICAL": "CRITICAL",
                    "HIGH": "VULNERABLE",
                    "MEDIUM": "VULNERABLE",
                    "LOW": "POTENTIAL",
                    "WARN": "POTENTIAL",
                }.get(severity, "POTENTIAL")
                
                # Vulnerability title. Try exact id, then a case-insensitive
                # match (covers testssl id-casing drift), then a generic fallback.
                vuln_title = (
                    VULN_MAP.get(vuln_id)
                    or VULN_MAP.get(str(vuln_id).lower())
                    or f"SSL/TLS Issue: {vuln_id}"
                )
                    
                details = f"testssl.sh detected issue '{vuln_id}' with severity '{severity}'. Description: {finding_desc}"
                
                finding = _finding(
                    status=vakt_status,
                    severity=vakt_severity,
                    vulnerability=vuln_title,
                    details=details,
                    target=display,
                    resolved_ip=resolved_ip,
                    port=port,
                    url=f"https://{display}:{port}",
                )
                
                # Validate schema
                violations = validate_finding(finding)
                if not violations:
                    findings.append(finding)
                
    except Exception as e:
        pass
    finally:
        # Cleanup temp file
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
                
    return findings
