"""
reporter.py - VaktScan output / reporting layer.

Provides all file-output helpers (CSV, JSON, SARIF) and the final
results printer.  Kept separate from main.py so the reporting
contract can be imported and tested without pulling in the full
scan engine.
"""
import asyncio  # noqa: F401 - kept for async def print_final_results
import csv
import json
import time
import ipaddress
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

# Lazily-resolved module imports (same vendor path setup as main.py)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'vendor'))

from modules import cisa_kev, epss, passive_intel


# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------

class Colors:
    # Basic colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'

    # Bright colors
    BRIGHT_RED = '\033[1;91m'
    BRIGHT_GREEN = '\033[1;92m'
    BRIGHT_YELLOW = '\033[1;93m'
    BRIGHT_BLUE = '\033[1;94m'
    BRIGHT_MAGENTA = '\033[1;95m'
    BRIGHT_CYAN = '\033[1;96m'

    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

    @staticmethod
    def disable():
        """Disable colors for non-terminal environments."""
        Colors.RED = Colors.GREEN = Colors.YELLOW = Colors.BLUE = ''
        Colors.MAGENTA = Colors.CYAN = Colors.WHITE = Colors.GRAY = ''
        Colors.BRIGHT_RED = Colors.BRIGHT_GREEN = Colors.BRIGHT_YELLOW = ''
        Colors.BRIGHT_BLUE = Colors.BRIGHT_MAGENTA = Colors.BRIGHT_CYAN = ''
        Colors.BOLD = Colors.DIM = Colors.UNDERLINE = Colors.RESET = ''


# ---------------------------------------------------------------------------
# Deduplication utility
# ---------------------------------------------------------------------------

_DOMAIN_SCAN_DIAGNOSTICS = (
    "Broken Component:",
    "Anomalous Response Size",
    "5xx Server Error on Base Path",
    "Missing Security Headers",
    "Potential JSON Data Leak in HTML",
)

_ORACLE_GATED_WEB_FINDINGS = (
    "Git Repository Exposed",
    "Environment File Exposed",
    "PHP Info Page Exposed",
    "PHP Test Page Exposed",
    "WordPress Config Exposed",
    "Config File Exposed",
    "Database Credentials File Exposed",
    "Secrets File Exposed",
    "Credentials File Exposed",
    "Backup Archive Exposed",
    "Site Archive Exposed",
    "Adminer Database UI Exposed",
    "phpMyAdmin Exposed",
)


def normalize_finding_for_report(finding):
    """Return a copy with the actual tested/evidence URL as canonical URL."""
    normalized = dict(finding or {})
    current_url = str(normalized.get("url") or "").strip()
    payload_url = str(normalized.get("payload_url") or "").strip()

    def _is_http_url(value):
        try:
            parsed = urlparse(value)
            return parsed.scheme in ("http", "https") and bool(parsed.hostname)
        except ValueError:
            return False

    # Payload_URL is the exact request which generated the evidence.  Earlier
    # writers left URL at the parent origin, losing paths from the main column.
    if _is_http_url(payload_url):
        current_parsed = urlparse(current_url) if _is_http_url(current_url) else None
        payload_parsed = urlparse(payload_url)
        current_is_origin = bool(
            current_parsed
            and current_parsed.path in ("", "/")
            and not current_parsed.query
            and not current_parsed.fragment
        )
        if not current_parsed or (
            current_is_origin
            and payload_parsed.hostname == current_parsed.hostname
            and payload_parsed.path not in ("", "/")
        ):
            current_url = payload_url
    elif not _is_http_url(current_url):
        # Recover legacy broken-resource rows whose full URL only survived in
        # Details. These rows are filtered from vulnerability output, but the
        # normalization keeps exports and migration tools internally correct.
        match = re.search(r"Sub-resource\s+['\"](https?://[^'\"\s]+)", str(normalized.get("details") or ""), re.I)
        if match:
            current_url = payload_url = match.group(1)

    if not current_url or current_url.lower() in ("n/a", "unknown"):
        target = str(normalized.get("target") or "").strip()
        if target and target.lower() not in ("n/a", "unknown") and str(normalized.get("module") or "").lower() in {
            "dns", "dns_resolve", "dns_recon",
        }:
            normalized["url"] = f"dns://{target}"

    if _is_http_url(current_url):
        normalized["url"] = current_url
        if _is_http_url(payload_url):
            normalized["payload_url"] = payload_url
        parsed = urlparse(current_url)
        if str(normalized.get("target") or "").strip().lower() in ("", "n/a", "unknown"):
            normalized["target"] = parsed.hostname
        if str(normalized.get("port") or "").strip().lower() in ("", "n/a", "unknown"):
            normalized["port"] = str(parsed.port or (443 if parsed.scheme == "https" else 80))

    details = str(normalized.get("details") or "")
    if str(normalized.get("http_status") or "").strip().lower() in ("", "n/a", "unknown"):
        status_match = re.search(r"\bHTTP\s+(\d{3})\b", details, re.I)
        if status_match:
            normalized["http_status"] = status_match.group(1)
    if str(normalized.get("content_length") or "").strip().lower() in ("", "n/a", "unknown"):
        length_match = re.search(r"\b([0-9]+)\s+bytes\b", details, re.I)
        if length_match:
            normalized["content_length"] = length_match.group(1)
    return normalized


def finding_rejection_reason(finding):
    """Explain why a legacy/unsupported result is not report-quality evidence."""
    module = str(finding.get("module") or "")
    title = str(finding.get("vulnerability") or "")
    details = str(finding.get("details") or "")
    status = str(finding.get("status") or "").upper()

    if module == "domain_scan":
        if title.startswith(_DOMAIN_SCAN_DIAGNOSTICS):
            return "operational diagnostic, not a vulnerability"
        if title.startswith("Potential Open Redirect"):
            return "legacy substring-only redirect result lacks exact Location-host proof"
        if title.startswith("Confirmed Open Redirect") and "Confirmed external redirect host" not in details:
            return "open redirect lacks exact external Location-host proof"
        if title == "Permissive CORS Configuration":
            return "legacy CORS result lacks reflected-origin plus credential proof"
        if title.startswith("CORS:") and "arbitrary origin reflection with credentials" not in details.lower():
            return "CORS result lacks reflected-origin plus credential proof"
        if title.startswith("Subdomain takeover candidate:") and "DNS evidence: CNAME" not in details:
            return "takeover fingerprint lacks matching DNS/CNAME evidence"

    if module == "WebChecks":
        try:
            response_status = int(str(finding.get("http_status", "0")))
        except ValueError:
            response_status = 0
        if response_status >= 400 and title in {
            "Missing Strict-Transport-Security Header",
            "Missing Clickjacking Protection (X-Frame-Options / CSP)",
            "Weak Content-Security-Policy Directives",
            "Security Headers Missing",
            "Server Header Discloses Version",
            "X-Powered-By Header Discloses Technology",
            "Insecure Cookie Attributes",
        }:
            return "policy inferred from an error/block/rate-limit response"
        if title.startswith("Admin Path Accessible:"):
            return "HTTP 200 path without an admin authentication oracle"
        if title in ("Admin Panel Detected", "WordPress Admin Panel Detected"):
            return "legacy HTTP 200 admin-path result lacks a login/admin oracle"
        if title == "security.txt Accessible" and "Contact:" not in details:
            return "security.txt result lacks a valid Contact field"
        if title in ("robots.txt Accessible", "crossdomain.xml Accessible") and "Evidence:" not in details:
            return "legacy well-known-file result lacks a content oracle"
        if title.startswith(_ORACLE_GATED_WEB_FINDINGS) and "Evidence:" not in details:
            return "sensitive endpoint lacks a path-specific content oracle"
        if title == "WordPress Default Credentials" and "wordpress_logged_in_*" not in details:
            return "legacy login result lacks redirect plus authentication-cookie proof"
        if title == "Insecure Cookie Attributes" and any(
            name in details.lower() for name in ("'__cf_bm'", "'cf_clearance'", "'_cfuvid'", "'awsalb'")
        ):
            return "edge/infrastructure cookie is not an application authentication cookie"
        if title == "Insecure Cookie Attributes" and "application authentication/session cookie" not in details:
            return "legacy cookie result lacks evidence that the cookie carries authentication state"

    if module == "cPanel":
        if title.startswith("Service port reachable on"):
            return "port reachability belongs in service inventory, not vulnerability findings"
        if title in {
            "Host-header allow-list bypass possible",
            "cPHulk brute-force protection not directly observed",
            "HTTP request smuggling differential observed",
        }:
            return "heuristic differential/absence is not exploit proof"
        if title == "CRLF / response header injection" and "Evidence:" not in details:
            return "legacy CRLF result lacks a separately parsed injected response header"
        if title.startswith("CVE-2022-44762") and "exact external host" not in details:
            return "legacy open-redirect result lacks exact Location-host proof"
        if title.startswith("cPanel service identified") and not any(
            marker in details for marker in ("body:", "header:", "version:", "magic_revision:")
        ):
            return "legacy cPanel identity used weak reflected path markers"
        if "reachable over plaintext HTTP" in title and "independently verified" not in details:
            return "legacy plaintext finding lacks verified cPanel identity evidence"

    if module == "js_paths":
        if title.startswith("Hardcoded Secret:") and "Evidence:" not in details:
            return "legacy regex-only secret result lacks first-party/credential validation"
        if title.startswith("Sensitive Path Accessible:") and "Evidence:" not in details:
            return "legacy path result is based only on HTTP status"
        if title == "Unauthenticated JSON Endpoint":
            return "public JSON alone is not a vulnerability"
        if title == "Exposed JS Source Map" and "Evidence:" not in details:
            return "legacy source-map result lacks embedded-source impact evidence"

    if module == "js_cve":
        service_version = str(finding.get("service_version") or "")
        version = service_version.rsplit(" ", 1)[-1]
        if re.fullmatch(r"[a-f0-9]{7,}", version, re.I) and "." not in version:
            return "asset fingerprint/hash was misparsed as a library version"
        if not title.startswith(("CVE-", "GHSA-", "Advisory ")):
            return "non-CVE advisory identifier is ambiguous/malformed"

    return None


def prepare_findings_for_report(vulnerabilities, *, include_rejections=False):
    """Normalize report rows and remove known unsupported scanner output."""
    accepted = []
    rejected = []
    for finding in vulnerabilities or []:
        normalized = normalize_finding_for_report(finding)
        reason = finding_rejection_reason(normalized)
        if reason:
            rejected.append((normalized, reason))
        else:
            accepted.append(normalized)
    return (accepted, rejected) if include_rejections else accepted

def deduplicate_vulnerabilities(vulnerabilities):
    """
    Deduplicates a list of vulnerabilities.
    """
    unique_vulns = {}

    for vuln in prepare_findings_for_report(vulnerabilities):
        vuln_key = (
            vuln.get('resolved_ip', vuln.get('target')),
            vuln.get('port'),
            vuln.get('vulnerability')
        )

        if vuln_key not in unique_vulns:
            unique_vulns[vuln_key] = vuln
        else:
            existing_vuln = unique_vulns[vuln_key]
            try:
                import ipaddress
                ipaddress.ip_address(existing_vuln['target'])
                try:
                    ipaddress.ip_address(vuln['target'])
                except ValueError:
                    unique_vulns[vuln_key] = vuln
            except ValueError:
                pass

    return list(unique_vulns.values())


# ---------------------------------------------------------------------------
# File output helpers
# ---------------------------------------------------------------------------

def save_port_scan_csv(scan_results, domain, output_dir=None):
    """
    Save full port scan results to a CSV file.
    scan_results structure: list of tuples (target_obj, {'open_ports': []})
    If output_dir is provided the file is written there; otherwise cwd.
    """
    import os as _os
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename_only = f"portscan_results_{domain}_{timestamp}.csv"
    filename = _os.path.join(output_dir, filename_only) if output_dir else filename_only

    headers = ['Timestamp', 'Hostname', 'IP Address', 'Open Ports', 'Count']

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)

            scan_time = time.strftime("%Y-%m-%d %H:%M:%S")

            count = 0
            for target_obj, result in scan_results:
                open_ports = result.get('open_ports', [])
                if not open_ports:
                    continue

                hostname = target_obj.get('display_target', 'N/A')
                ip = target_obj.get('resolved_ip', 'N/A')
                ports_str = ", ".join(map(str, sorted(open_ports)))

                writer.writerow([
                    scan_time,
                    hostname,
                    ip,
                    ports_str,
                    len(open_ports)
                ])
                count += 1

        print(f"{Colors.GREEN}[+] Full port scan results saved to: {Colors.BOLD}{filename}{Colors.RESET}")
        return filename
    except Exception as e:
        print(f"{Colors.RED}[!] Error saving port scan CSV: {e}{Colors.RESET}")
        return None


def save_results_to_csv(vulnerabilities, filename=None):
    """Save vulnerability results to CSV format."""
    vulnerabilities = prepare_findings_for_report(vulnerabilities)
    if not filename:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.csv"

    csv_headers = ['Timestamp', 'Status', 'Vulnerability', 'Hostname', 'IP Address', 'Port', 'URL', 'Payload_URL', 'Module', 'Service_Version', 'Severity', 'Details', 'HTTP_Status', 'Page_Title', 'Content_Length']

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(csv_headers)

            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

            for vuln in vulnerabilities:
                hostname = vuln.get('target', 'N/A')
                try:
                    # If the target is a valid IP, it's not a hostname
                    ipaddress.ip_address(hostname)
                    hostname = ''
                except ValueError:
                    pass

                writer.writerow([
                    timestamp,
                    vuln.get('status', 'UNKNOWN'),
                    vuln.get('vulnerability', 'N/A'),
                    hostname,
                    vuln.get('resolved_ip', 'N/A'),
                    vuln.get('port', 'N/A'),
                    vuln.get('url', 'N/A'),
                    vuln.get('payload_url', 'N/A'),
                    vuln.get('module', 'N/A'),
                    vuln.get('service_version', 'N/A'),
                    vuln.get('severity', 'N/A'),
                    vuln.get('details', 'N/A'),
                    str(vuln.get('http_status', 'N/A')),
                    vuln.get('page_title', 'N/A'),
                    str(vuln.get('content_length', 'N/A'))
                ])

        print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.RESET}")
        return filename

    except Exception as e:
        print(f"{Colors.RED}[!] Error saving CSV file: {e}{Colors.RESET}")
        return None


def save_results_to_json(vulnerabilities, filename=None):
    """Save vulnerability results to JSON format."""
    vulnerabilities = prepare_findings_for_report(vulnerabilities)
    if not filename:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.json"

    fields = [
        'Timestamp', 'Status', 'Vulnerability', 'Hostname', 'IP Address',
        'Port', 'URL', 'Payload_URL', 'Module', 'Service_Version',
        'Severity', 'Details', 'HTTP_Status', 'Page_Title', 'Content_Length',
    ]

    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        records = []
        for vuln in vulnerabilities:
            hostname = vuln.get('target', 'N/A')
            try:
                ipaddress.ip_address(hostname)
                hostname = ''
            except ValueError:
                pass

            records.append({
                'Timestamp':       timestamp,
                'Status':          vuln.get('status', 'UNKNOWN'),
                'Vulnerability':   vuln.get('vulnerability', 'N/A'),
                'Hostname':        hostname,
                'IP Address':      vuln.get('resolved_ip', 'N/A'),
                'Port':            vuln.get('port', 'N/A'),
                'URL':             vuln.get('url', 'N/A'),
                'Payload_URL':     vuln.get('payload_url', 'N/A'),
                'Module':          vuln.get('module', 'N/A'),
                'Service_Version': vuln.get('service_version', 'N/A'),
                'Severity':        vuln.get('severity', 'N/A'),
                'Details':         vuln.get('details', 'N/A'),
                'HTTP_Status':     str(vuln.get('http_status', 'N/A')),
                'Page_Title':      vuln.get('page_title', 'N/A'),
                'Content_Length':  str(vuln.get('content_length', 'N/A')),
            })

        with open(filename, 'w', encoding='utf-8') as jf:
            json.dump(records, jf, indent=2)

        print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.RESET}")
        return filename

    except Exception as e:
        print(f"{Colors.RED}[!] Error saving JSON file: {e}{Colors.RESET}")
        return None


def save_results_to_html(vulnerabilities, filename=None, scan_label=None):
    """Save findings as a single self-contained, styled HTML report.

    No external assets (CSS/JS inlined) so the file is portable. All dynamic
    text is HTML-escaped. Findings are grouped by severity with a summary and a
    client-side text/severity filter.
    """
    import html as _html
    vulnerabilities = prepare_findings_for_report(vulnerabilities)

    if not filename:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.html"

    SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    SEV_COLOR = {
        "CRITICAL": "#b3123b", "HIGH": "#d9480f", "MEDIUM": "#b8860b",
        "LOW": "#1971c2", "INFO": "#5c6772",
    }

    try:
        counts = {s: 0 for s in SEV_ORDER}
        for v in vulnerabilities:
            sev = str(v.get("severity", "INFO")).upper()
            counts[sev] = counts.get(sev, 0) + 1

        def _rank(v):
            try:
                return SEV_ORDER.index(str(v.get("severity", "INFO")).upper())
            except ValueError:
                return len(SEV_ORDER)

        ordered = sorted(vulnerabilities, key=_rank)
        generated = time.strftime("%Y-%m-%d %H:%M:%S")
        label = _html.escape(str(scan_label)) if scan_label else "VaktScan"

        tiles = []
        for s in SEV_ORDER:
            tiles.append(
                f'<div class="tile" data-sev="{s}"><span class="tn" style="color:{SEV_COLOR[s]}">'
                f'{counts.get(s, 0)}</span><span class="tl">{s}</span></div>'
            )

        rows = []
        for v in ordered:
            sev = str(v.get("severity", "INFO")).upper()
            color = SEV_COLOR.get(sev, "#5c6772")
            url = str(v.get("url", "") or "")
            if url and url != "N/A":
                url_cell = (f'<a href="{_html.escape(url, quote=True)}" target="_blank" '
                            f'rel="noopener noreferrer">{_html.escape(url)}</a>')
            else:
                url_cell = _html.escape(url)
            rows.append(
                f'<tr data-sev="{sev}">'
                f'<td><span class="badge" style="background:{color}">{_html.escape(sev)}</span></td>'
                f'<td>{_html.escape(str(v.get("status", "")))}</td>'
                f'<td>{_html.escape(str(v.get("vulnerability", "")))}</td>'
                f'<td>{_html.escape(str(v.get("target", "")))}</td>'
                f'<td>{_html.escape(str(v.get("resolved_ip", "")))}</td>'
                f'<td>{_html.escape(str(v.get("port", "")))}</td>'
                f'<td class="u">{url_cell}</td>'
                f'<td>{_html.escape(str(v.get("module", "")))}</td>'
                f'<td class="d">{_html.escape(str(v.get("details", "")))}</td>'
                '</tr>'
            )
        if not rows:
            rows.append('<tr><td colspan="9" class="empty">No findings.</td></tr>')

        css = (
            "<style>"
            ":root{--bg:#f6f7f9;--card:#fff;--line:#e3e6ea;--fg:#1a1d21;--mut:#5c6772}"
            "*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;"
            "background:var(--bg);color:var(--fg)}"
            ".wrap{max-width:1280px;margin:0 auto;padding:24px}"
            "h1{font-size:20px;margin:0}.sub{color:var(--mut);font-size:13px;margin-top:4px}"
            ".tiles{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}"
            ".tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 18px;"
            "min-width:104px;cursor:pointer;user-select:none}.tile.off{opacity:.4}"
            ".tn{display:block;font-size:26px;font-weight:700}.tl{color:var(--mut);font-size:12px;letter-spacing:.04em}"
            "#q{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;margin-bottom:12px;font-size:14px}"
            ".tblwrap{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow-x:auto}"
            "table{width:100%;border-collapse:collapse;font-size:13px}"
            "th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}"
            "th{position:sticky;top:0;background:var(--card);font-weight:600;white-space:nowrap}"
            ".badge{color:#fff;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}"
            "td.d{max-width:420px;color:var(--mut)}td.u{max-width:260px;word-break:break-all}"
            "a{color:#1971c2;text-decoration:none}a:hover{text-decoration:underline}"
            ".empty{text-align:center;color:var(--mut);padding:28px}"
            "@media(prefers-color-scheme:dark){:root{--bg:#16181c;--card:#1e2227;--line:#2c313a;--fg:#e6e9ee;--mut:#9aa4b2}}"
            "</style>"
        )
        js = (
            "<script>"
            "const q=document.getElementById('q'),rows=[...document.querySelectorAll('tbody tr')],"
            "tiles=[...document.querySelectorAll('.tile')];let off=new Set();"
            "function apply(){const t=q.value.toLowerCase();rows.forEach(r=>{"
            "const sev=r.dataset.sev;const show=(!off.has(sev))&&r.textContent.toLowerCase().includes(t);"
            "r.style.display=show?'':'none';});}"
            "q.addEventListener('input',apply);"
            "tiles.forEach(el=>el.addEventListener('click',()=>{const s=el.dataset.sev;"
            "if(off.has(s)){off.delete(s);el.classList.remove('off');}else{off.add(s);el.classList.add('off');}apply();}));"
            "</script>"
        )
        doc = (
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>VaktScan Report - {label}</title>{css}</head><body><div class=\"wrap\">"
            f"<h1>VaktScan Report</h1><div class=\"sub\">{label} &middot; {len(vulnerabilities)} finding(s) &middot; generated {generated}</div>"
            f"<div class=\"tiles\">{''.join(tiles)}</div>"
            "<input id=\"q\" type=\"search\" placeholder=\"Filter findings… (click a severity tile to toggle it)\">"
            "<div class=\"tblwrap\"><table><thead><tr>"
            "<th>Severity</th><th>Status</th><th>Vulnerability</th><th>Target</th><th>IP</th>"
            "<th>Port</th><th>URL</th><th>Module</th><th>Details</th></tr></thead><tbody>"
            f"{''.join(rows)}</tbody></table></div></div>{js}</body></html>"
        )

        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(doc)
        print(f"{Colors.GREEN}[+] HTML report saved to {filename}{Colors.RESET}")
        return filename
    except Exception as e:
        print(f"{Colors.RED}[!] Error saving HTML report: {e}{Colors.RESET}")
        return None


def save_unified_html_report(vulnerabilities, filename, scan_label=None,
                             state=None, artifact_root=None):
    """Write a searchable, self-contained report for the complete scan.

    In addition to findings this combines checkpoint inventory, recon/httpx
    results, ports/services, directory discoveries, and the textual output of
    every tool beneath ``artifact_root``.  It is intentionally independent of
    third-party JS/CSS so it remains usable as a single portable file.
    """
    import html as _html

    state = state if isinstance(state, dict) else {}
    vulnerabilities = prepare_findings_for_report(vulnerabilities)
    root = Path(artifact_root) if artifact_root else None
    esc = lambda value: _html.escape(str(value if value is not None else ""))
    generated = time.strftime("%Y-%m-%d %H:%M:%S")
    label = str(scan_label or state.get("primary_target") or "VaktScan")

    assets = {}

    def add_asset(host, source=""):
        host = str(host or "").strip().lower()
        if not host or host in ("n/a", "unknown"):
            return
        item = assets.setdefault(host, {"host": host, "sources": set(), "urls": set(),
                                        "ips": set(), "ports": set(), "findings": 0})
        if source:
            item["sources"].add(source)

    for domain, payload in (state.get("recon_enumeration_results") or {}).items():
        for host in (payload or {}).get("subdomains", []):
            add_asset(host, f"recon:{domain}")
    for domain, hosts in (state.get("recon_results") or {}).items():
        for host in hosts or []:
            add_asset(host, f"recon:{domain}")

    http_rows = []
    for domain, payload in (state.get("recon_http_results") or {}).items():
        entries = (payload or {}).get("httpx_data", [])
        if not entries:
            entries = [{"url": u} for u in (payload or {}).get("alive_urls", [])]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            url = str(entry.get("url") or entry.get("input") or "")
            parsed = urlparse(url if "://" in url else "//" + url)
            host = parsed.hostname or str(entry.get("host") or "")
            add_asset(host, f"httpx:{domain}")
            if host:
                assets[host]["urls"].add(url)
                ip = entry.get("host") or entry.get("ip") or entry.get("a")
                if ip and str(ip) != host:
                    assets[host]["ips"].add(str(ip))
            http_rows.append({
                "host": host, "url": url, "status": entry.get("status-code", entry.get("status_code", "")),
                "title": entry.get("title", ""), "tech": entry.get("tech", entry.get("webserver", "")),
                "ip": entry.get("host", entry.get("ip", "")),
            })

    for ip, ports in (state.get("open_ports") or {}).items():
        add_asset(ip, "port-scan")
        assets[str(ip).lower()]["ports"].update(str(p) for p in (ports or []))
    for finding in vulnerabilities:
        host = finding.get("target") or urlparse(str(finding.get("url") or "")).hostname
        add_asset(host, finding.get("module", "finding"))
        key = str(host or "").lower()
        if key in assets:
            assets[key]["findings"] += 1
            if finding.get("resolved_ip") not in (None, "", "N/A"):
                assets[key]["ips"].add(str(finding["resolved_ip"]))
            if finding.get("port") not in (None, "", "N/A"):
                assets[key]["ports"].add(str(finding["port"]))
            if finding.get("url") not in (None, "", "N/A"):
                assets[key]["urls"].add(str(finding["url"]))

    def table_row(values, attrs=""):
        return f"<tr {attrs}>" + "".join(f"<td>{esc(v)}</td>" for v in values) + "</tr>"

    asset_rows = []
    for item in sorted(assets.values(), key=lambda x: x["host"]):
        urls = " · ".join(sorted(item["urls"]))
        asset_rows.append(table_row([
            item["host"], ", ".join(sorted(item["ips"])),
            ", ".join(sorted(item["ports"], key=lambda p: int(p) if p.isdigit() else 99999)),
            urls, ", ".join(sorted(item["sources"])), item["findings"],
        ], 'class="searchable"'))

    service_rows = [table_row([
        r["host"], r["ip"], r["url"], r["status"], r["title"],
        ", ".join(r["tech"]) if isinstance(r["tech"], list) else r["tech"],
    ], 'class="searchable"') for r in http_rows]

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    finding_rows = []
    severity_counts = {name: 0 for name in severity_order}
    for finding in sorted(vulnerabilities, key=lambda f: severity_order.get(str(f.get("severity", "INFO")).upper(), 9)):
        sev = str(finding.get("severity", "INFO")).upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        finding_rows.append(table_row([
            sev, finding.get("status", ""), finding.get("vulnerability", ""),
            finding.get("target", ""), finding.get("resolved_ip", ""), finding.get("port", ""),
            finding.get("url", ""), finding.get("module", ""), finding.get("details", ""),
        ], f'class="searchable" data-severity="{esc(sev)}"'))

    directory_rows = []
    artifacts = []
    if root and root.is_dir():
        output_abs = Path(filename).resolve()
        text_ext = {".txt", ".csv", ".json", ".jsonl", ".log", ".xml", ".yaml", ".yml"}
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            if path.resolve() == output_abs or path.suffix.lower() == ".html":
                continue
            rel = str(path.relative_to(root))
            size = path.stat().st_size
            preview = ""
            truncated = False
            if path.suffix.lower() in text_ext or path.name.startswith("dirsearch_report_"):
                try:
                    with path.open("r", encoding="utf-8", errors="replace") as handle:
                        preview = handle.read(2_000_001)
                    if len(preview) > 2_000_000:
                        preview = preview[:2_000_000]
                        truncated = True
                except OSError:
                    preview = ""
            tool = rel.split(os.sep, 1)[0]
            artifacts.append((rel, tool, size, preview, truncated))
            if "dirsearch" in rel.lower():
                for line in preview.splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith(("#", "[", "_")):
                        directory_rows.append(table_row([rel, stripped], 'class="searchable"'))

    artifact_blocks = []
    for rel, tool, size, preview, truncated in artifacts:
        suffix = "\n[preview truncated at 2 MB; original artifact retained on disk]" if truncated else ""
        body = esc(preview + suffix) if preview else "Binary or empty artifact; see the file on disk."
        artifact_blocks.append(
            f'<details class="artifact searchable"><summary>{esc(rel)} '
            f'<span>{esc(tool)} · {size:,} bytes</span></summary><pre>{body}</pre></details>'
        )

    def section(identifier, title, body, count):
        return (f'<section id="{identifier}"><h2>{esc(title)} '
                f'<span class="count">{count}</span></h2>{body}</section>')

    def table(headers, rows):
        head = "".join(f"<th>{esc(h)}</th>" for h in headers)
        empty = f'<tr><td colspan="{len(headers)}" class="empty">No data recorded.</td></tr>'
        return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{"".join(rows) or empty}</tbody></table></div>'

    nav = "".join(
        f'<a href="#{ident}">{esc(title)} <b>{count}</b></a>'
        for ident, title, count in [
            ("overview", "Overview", len(vulnerabilities)), ("assets", "Assets", len(asset_rows)),
            ("services", "Web services", len(service_rows)), ("findings", "Findings", len(finding_rows)),
            ("directories", "Directories", len(directory_rows)), ("artifacts", "Tool outputs", len(artifacts)),
        ]
    )
    cards = "".join(
        f'<div class="card"><strong>{value}</strong><span>{esc(name)}</span></div>'
        for name, value in [
            ("Assets", len(assets)), ("Live web services", len(http_rows)),
            ("Open ports", sum(len(v.get("ports", [])) for v in assets.values())),
            ("Findings", len(vulnerabilities)), ("Tool artifacts", len(artifacts)),
        ]
    )
    sev_cards = "".join(
        f'<span class="severity {name.lower()}">{name} {severity_counts.get(name, 0)}</span>'
        for name in severity_order
    )

    css = """<style>
:root{--bg:#0b1020;--panel:#121a2d;--panel2:#18233a;--line:#2a3856;--text:#e9eef8;--muted:#9eabc2;--accent:#50d5ff}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 Inter,ui-sans-serif,system-ui,sans-serif}
aside{position:fixed;inset:0 auto 0 0;width:230px;background:#0e1628;border-right:1px solid var(--line);padding:24px 16px;overflow:auto}aside h1{font-size:18px;margin:0 8px 4px}aside p{margin:0 8px 22px;color:var(--muted);word-break:break-word}nav a{display:flex;justify-content:space-between;color:var(--muted);text-decoration:none;padding:9px 10px;border-radius:7px}nav a:hover{background:var(--panel2);color:var(--text)}nav b{color:var(--accent)}main{margin-left:230px;padding:28px;max-width:1800px}.toolbar{position:sticky;top:0;z-index:5;background:linear-gradient(var(--bg) 75%,transparent);padding:0 0 18px}#global-search{width:100%;padding:12px 14px;border:1px solid var(--line);border-radius:9px;background:var(--panel);color:var(--text);font-size:15px}section{scroll-margin-top:72px;margin-bottom:34px}h2{font-size:18px;margin:0 0 12px}.count{font-size:12px;color:var(--accent);background:var(--panel2);padding:3px 8px;border-radius:12px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px}.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:16px}.card strong{display:block;font-size:27px;color:var(--accent)}.card span{color:var(--muted)}.severities{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.severity{padding:5px 9px;border-radius:6px;background:var(--panel2)}.critical{color:#ff5d8f}.high{color:#ff8a65}.medium{color:#ffd166}.low{color:#64b5f6}.info{color:#aab4c8}.table-wrap{border:1px solid var(--line);border-radius:10px;overflow:auto;max-height:650px}table{border-collapse:collapse;width:100%;background:var(--panel);font-size:12px}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}th{position:sticky;top:0;background:var(--panel2);z-index:2;color:#cbd6e8}.empty{text-align:center;color:var(--muted);padding:25px}.artifact{background:var(--panel);border:1px solid var(--line);border-radius:9px;margin:8px 0}.artifact summary{padding:11px 13px;cursor:pointer}.artifact summary span{float:right;color:var(--muted);font-size:12px}.artifact pre{margin:0;border-top:1px solid var(--line);padding:14px;max-height:540px;overflow:auto;white-space:pre-wrap;color:#cbd6e8}.hidden{display:none!important}.meta{color:var(--muted);margin-bottom:18px}@media(max-width:800px){aside{position:static;width:auto}main{margin:0;padding:18px}nav{display:flex;overflow:auto}nav a{min-width:max-content;gap:8px}}
</style>"""
    js = """<script>
const box=document.getElementById('global-search'),items=[...document.querySelectorAll('.searchable')];
box.addEventListener('input',()=>{const q=box.value.trim().toLowerCase();items.forEach(el=>el.classList.toggle('hidden',q&&!el.textContent.toLowerCase().includes(q)));});
</script>"""
    body = (
        section("overview", "Overview", f'<div class="meta">Generated {esc(generated)} · phase {esc(state.get("phase", "unknown"))}</div><div class="cards">{cards}</div><div class="severities">{sev_cards}</div>', len(vulnerabilities)) +
        section("assets", "Asset inventory", table(["Host", "IPs", "Ports", "URLs", "Sources", "Findings"], asset_rows), len(asset_rows)) +
        section("services", "Live web services", table(["Host", "IP", "URL", "Status", "Title", "Technology"], service_rows), len(service_rows)) +
        section("findings", "Vulnerabilities and observations", table(["Severity", "Status", "Finding", "Target", "IP", "Port", "URL", "Module", "Details"], finding_rows), len(finding_rows)) +
        section("directories", "Directory discoveries", table(["Source", "Result"], directory_rows), len(directory_rows)) +
        section("artifacts", "All tool outputs", "".join(artifact_blocks) or '<div class="panel empty">No artifacts recorded.</div>', len(artifacts))
    )
    doc = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<title>VaktScan unified report — {esc(label)}</title>{css}</head><body><aside><h1>VaktScan</h1><p>{esc(label)}</p><nav>{nav}</nav></aside>'
           f'<main><div class="toolbar"><input id="global-search" type="search" placeholder="Search all assets, services, findings, directories and tool output…"></div>{body}</main>{js}</body></html>')
    try:
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        with open(filename, "w", encoding="utf-8") as handle:
            handle.write(doc)
        print(f"{Colors.GREEN}[+] Unified HTML report saved to {filename}{Colors.RESET}")
        return filename
    except OSError as exc:
        print(f"{Colors.RED}[!] Error saving unified HTML report: {exc}{Colors.RESET}")
        return None


def write_sarif_output(vulnerabilities, output_path):
    """Write vulnerability findings to SARIF 2.1.0 format for GitHub/GitLab security tab integration."""
    vulnerabilities = prepare_findings_for_report(vulnerabilities)

    SEVERITY_MAP = {
        "CRITICAL": "error",
        "HIGH":     "error",
        "MEDIUM":   "warning",
        "LOW":      "note",
        "INFO":     "none",
    }

    # Build unique rules from finding titles
    rules_seen = {}
    for vuln in vulnerabilities:
        title = vuln.get('vulnerability', 'Unknown Finding')
        if title not in rules_seen:
            rule_id = f"VAKTSCAN-{len(rules_seen) + 1:03d}"
            severity = vuln.get('severity', 'INFO').upper()
            rules_seen[title] = {
                "id": rule_id,
                "name": title.replace(' ', ''),
                "shortDescription": {"text": title},
                "defaultConfiguration": {
                    "level": SEVERITY_MAP.get(severity, "none")
                },
            }

    rules = list(rules_seen.values())
    rule_index = {r["shortDescription"]["text"]: i for i, r in enumerate(rules)}

    results = []
    for vuln in vulnerabilities:
        title = vuln.get('vulnerability', 'Unknown Finding')
        severity = vuln.get('severity', 'INFO').upper()
        description = vuln.get('details', vuln.get('description', title))
        target = vuln.get('target', 'unknown')
        port = vuln.get('port', '')
        uri = f"{target}:{port}" if port and str(port) not in ('N/A', '') else target

        rule = rules_seen.get(title, {})
        result_entry = {
            "ruleId": rule.get("id", "VAKTSCAN-000"),
            "ruleIndex": rule_index.get(title, 0),
            "level": SEVERITY_MAP.get(severity, "none"),
            "message": {"text": description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri}
                }
            }],
        }
        results.append(result_entry)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "VaktScan",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/bhanunamikaze/VaktScan",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    }

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_doc, f, indent=2)
        print(f"{Colors.GREEN}[+] SARIF report saved to {output_path}{Colors.RESET}")
        return output_path
    except Exception as e:
        print(f"{Colors.RED}[!] Error saving SARIF file: {e}{Colors.RESET}")
        return None


# ---------------------------------------------------------------------------
# Final results printer (async - orchestrates enrichment + file output)
# ---------------------------------------------------------------------------

async def print_final_results(all_vulnerabilities):
    final_vulnerabilities = deduplicate_vulnerabilities(all_vulnerabilities)
    final_vulnerabilities = await cisa_kev.enrich_findings_with_kev(final_vulnerabilities)
    print(f"[*] CISA KEV cross-reference complete.")
    final_vulnerabilities = await epss.enrich_findings_with_epss(final_vulnerabilities)
    final_vulnerabilities = await passive_intel.enrich_findings_with_passive_intel(final_vulnerabilities)
    print(f"\n{Colors.BRIGHT_CYAN}=== Final Vulnerability Results ==={Colors.RESET}")
    if final_vulnerabilities:
        for result in final_vulnerabilities:
            print(f"[!] {result['status']}: {result['vulnerability']} on {result['target']}")
    else:
        print("[*] No vulnerabilities found.")
    if final_vulnerabilities:
        save_results_to_csv(final_vulnerabilities)
        save_results_to_json(final_vulnerabilities)
