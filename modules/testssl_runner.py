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

from modules.schema import validate_finding

MODULE_NAME = "testssl"
DEFAULT_PORTS = [443, 8443, 465, 993, 995]

VULN_MAP = {
    # Protocols
    "SSLv2": "SSLv2 Protocol Support Enabled",
    "SSLv3": "SSLv3 Protocol Support Enabled",
    "TLS1": "TLSv1.0 Protocol Support Enabled",
    "TLS1_1": "TLSv1.1 Protocol Support Enabled",
    
    # Vulnerabilities
    "heartbleed": "SSL/TLS Vulnerability: Heartbleed (CVE-2014-0160)",
    "CCS": "SSL/TLS Vulnerability: OpenSSL CCS Injection (CVE-2014-0224)",
    "ticketbleed": "SSL/TLS Vulnerability: Ticketbleed (CVE-2016-9244)",
    "robot": "SSL/TLS Vulnerability: ROBOT Attack (CVE-2017-13098)",
    "crime": "SSL/TLS Vulnerability: CRIME (CVE-2012-4929)",
    "breach": "SSL/TLS Vulnerability: BREACH (CVE-2013-3587)",
    "poodle": "SSL/TLS Vulnerability: POODLE (CVE-2014-3566)",
    "sweet32": "SSL/TLS Vulnerability: SWEET32 (CVE-2016-2183)",
    "logjam": "SSL/TLS Vulnerability: LOGJAM (CVE-2015-4000)",
    "freak": "SSL/TLS Vulnerability: FREAK (CVE-2015-0204)",
    "rc4": "SSL/TLS Vulnerability: Weak RC4 Ciphers Enabled",
    "lucky13": "SSL/TLS Vulnerability: Lucky13 (CVE-2013-0169)",
    "raccoon": "SSL/TLS Vulnerability: Raccoon (CVE-2020-1967)",
    
    # Certificate Quality
    "cert_signature": "Weak SSL/TLS Certificate Signature Algorithm",
    "cert_keySize": "Weak SSL/TLS Certificate Key Size",
    "cert_trust": "Untrusted SSL/TLS Certificate Chain",
    
    # Misconfigurations
    "HSTS": "Missing or Misconfigured Strict-Transport-Security (HSTS) Header",
    "secure_reneg": "Insecure Client-Initiated SSL/TLS Renegotiation Allowed",
    "fallback_SCSV": "Missing TLS Fallback Signaling Cipher Suite Value (SCSV) Support",
}

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

        # Start the process asynchronously
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Await communication to let the scan finish (with timeout)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300) # 5 minutes timeout per host
        
        if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
            with open(temp_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
                
            scan_results = data.get("scanResult", [])
            for res in scan_results:
                vuln_id = res.get("id")
                severity = res.get("severity")
                finding_desc = res.get("finding", "")
                
                # We skip OK, INFO, or empty/FATAL severities to focus on real security warnings
                if severity in ("OK", "INFO", "FATAL"):
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
                
                # Vulnerability title
                vuln_title = VULN_MAP.get(vuln_id)
                if not vuln_title:
                    # Fallback to id if not in map
                    vuln_title = f"SSL/TLS Issue: {vuln_id}"
                    
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
