"""
reporter.py — VaktScan output / reporting layer.

Provides all file-output helpers (CSV, JSON, SARIF) and the final
results printer.  Kept separate from main.py so the reporting
contract can be imported and tested without pulling in the full
scan engine.
"""
import asyncio  # noqa: F401 — kept for async def print_final_results
import csv
import json
import time
import ipaddress
import os
import sys

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

def deduplicate_vulnerabilities(vulnerabilities):
    """
    Deduplicates a list of vulnerabilities.
    """
    unique_vulns = {}

    for vuln in vulnerabilities:
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
            f"<title>VaktScan Report — {label}</title>{css}</head><body><div class=\"wrap\">"
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


def write_sarif_output(vulnerabilities, output_path):
    """Write vulnerability findings to SARIF 2.1.0 format for GitHub/GitLab security tab integration."""

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
# Final results printer (async — orchestrates enrichment + file output)
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
