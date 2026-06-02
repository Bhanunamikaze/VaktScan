"""
NVD API 2.0 CVE lookup utility.

Usage:
    findings = await lookup_cves(product="elasticsearch", version="7.9.0")
    # Returns list of canonical finding dicts (INFO/POTENTIAL severity)
"""

import asyncio
import os
import re
import httpx
from datetime import datetime

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_API_KEY = os.environ.get("NVD_API_KEY", "")

# Known product→CPE vendor mappings (expand as needed)
CPE_VENDOR_MAP = {
    "elasticsearch": "elastic",
    "kibana":        "elastic",
    "grafana":       "grafana",
    "prometheus":    "prometheus",
    "jenkins":       "jenkins",
    "gitlab":        "gitlab",
    "jira":          "atlassian",
    "confluence":    "atlassian",
    "sonarqube":     "sonarsource",
    "consul":        "hashicorp",
    "vault":         "hashicorp",
    "tomcat":        "apache",
    "spring":        "pivotal_software",
    "traefik":       "traefik",
    "portainer":     "portainer",
    "minio":         "minio",
    "redis":         "redis",
    "mongodb":       "mongodb",
    "postgresql":    "postgresql",
    "mysql":         "oracle",
    "docker":        "docker",
    "kubernetes":    "kubernetes",
    "openssh":       "openbsd",
    "dropbear":      "dropbear",
    "vsftpd":        "vsftpd",
    "proftpd":       "proftpd",
    "pure-ftpd":     "pureftpd",
    "http_server":   "apache",
    "nginx":         "nginx",
    "iis":           "microsoft",
}


async def lookup_cves(
    product: str,
    version: str,
    target: str = "N/A",
    resolved_ip: str = "N/A",
    port: str = "N/A",
    min_cvss: float = 7.0,
    timeout: float = 10.0,
) -> list[dict]:
    """
    Look up CVEs for a product+version via NVD API 2.0.
    Returns canonical finding dicts for CVEs with CVSS >= min_cvss.
    Returns [] if version is unknown/N/A or API is unreachable.
    """
    if not version or version in ("Unknown", "N/A", "unknown"):
        return []

    product_lower = product.lower()
    vendor = CPE_VENDOR_MAP.get(product_lower, product_lower)

    # Build CPE 2.3 string
    cpe = f"cpe:2.3:a:{vendor}:{product_lower}:{version}:*:*:*:*:*:*:*"

    headers = {}
    if _API_KEY:
        headers["apiKey"] = _API_KEY

    findings = []
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            # Try CPE lookup first
            resp = await client.get(NVD_BASE, params={
                "cpeName": cpe,
                "resultsPerPage": 20,
            })
            if resp.status_code != 200:
                # Fallback: keyword search
                resp = await client.get(NVD_BASE, params={
                    "keywordSearch": f"{product} {version}",
                    "resultsPerPage": 20,
                })
            if resp.status_code != 200:
                return []

            data = resp.json()
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")

                # Get CVSS score
                metrics = cve_data.get("metrics", {})
                cvss_score = 0.0
                severity = "INFO"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        entry = metrics[key][0]
                        cvss_data = entry.get("cvssData", {})
                        cvss_score = float(cvss_data.get("baseScore", 0))
                        severity = cvss_data.get("baseSeverity", "INFO").upper()
                        break

                if cvss_score < min_cvss:
                    continue

                # Get description
                descriptions = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                status = "CRITICAL" if cvss_score >= 9.0 else "VULNERABLE" if cvss_score >= 7.0 else "POTENTIAL"

                findings.append({
                    "status":          status,
                    "severity":        severity,
                    "vulnerability":   f"{cve_id} — {product} {version}",
                    "target":          target,
                    "resolved_ip":     resolved_ip,
                    "port":            str(port),
                    "url":             f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "payload_url":     f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "module":          "nvd",
                    "service_version": version,
                    "details":         f"CVSS {cvss_score:.1f} ({severity}). {desc[:300]}",
                    "http_status":     "N/A",
                    "page_title":      "N/A",
                    "content_length":  "N/A",
                    "timestamp":       datetime.utcnow().isoformat() + "Z",
                })

    except Exception as e:
        # NVD API is best-effort — never crash the scan if it's unreachable
        print(f"  [!] NVD lookup failed for {product} {version}: {e}")

    return findings


def extract_product_and_version(finding: dict) -> tuple[str, str]:
    """
    Extract product name and version from a finding.
    First checks if service_version is present. If not, parses details for banners.
    Returns (product, version) or ('', '').
    """
    version = finding.get("service_version", "")
    if version in ("Unknown", "N/A", "unknown"):
        version = ""

    module = finding.get("module", "").lower()
    vuln = finding.get("vulnerability", "").lower()
    details = finding.get("details", "")
    port = str(finding.get("port", ""))

    product = finding.get("product", "")
    if product:
        return product, version

    # Try to parse banners or names
    # 1. SSH
    if "ssh" in vuln or port == "22":
        match = re.search(r'openssh[_-]([0-9.a-z\-]+)', details, re.IGNORECASE)
        if match:
            return "openssh", match.group(1)
        match_db = re.search(r'dropbear[_-]([0-9.]+)', details, re.IGNORECASE)
        if match_db:
            return "dropbear", match_db.group(1)
        if not version:
            match_generic = re.search(r'ssh[-_](([0-9.]+)[^\s]*)', details, re.IGNORECASE)
            if match_generic:
                return "ssh", match_generic.group(1)
        return "ssh", version

    # 2. FTP
    if "ftp" in vuln or port == "21":
        match_vs = re.search(r'vsftpd\s*([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match_vs:
            return "vsftpd", match_vs.group(1)
        match_pro = re.search(r'proftpd\s*([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match_pro:
            return "proftpd", match_pro.group(1)
        match_pure = re.search(r'pure-ftpd\s*([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match_pure:
            return "pure-ftpd", match_pure.group(1)
        return "ftp", version

    # 3. MySQL
    if "mysql" in vuln or port == "3306":
        if not version:
            match = re.search(r'(\d+\.\d+\.\d+)', details)
            if match:
                version = match.group(1)
        return "mysql", version

    # 4. Redis
    if "redis" in vuln or port == "6379":
        if not version:
            match = re.search(r'(?:version|redis_version):(\S+)', details, re.IGNORECASE)
            if match:
                version = match.group(1)
        return "redis", version

    # 5. Tomcat
    if "tomcat" in vuln or port in ("8080", "8443"):
        match = re.search(r'tomcat/([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match:
            return "tomcat", match.group(1)

    # 6. Apache httpd
    if "apache" in details.lower() or "apache" in vuln:
        match = re.search(r'apache/([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match:
            return "http_server", match.group(1)

    # 7. Nginx
    if "nginx" in details.lower() or "nginx" in vuln:
        match = re.search(r'nginx/([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match:
            return "nginx", match.group(1)

    # 8. IIS
    if "microsoft-iis" in details.lower() or "iis" in vuln:
        match = re.search(r'microsoft-iis/([0-9a-zA-Z.-]+)', details, re.IGNORECASE)
        if match:
            return "iis", match.group(1)

    if module != "servicerecon":
        return module, version

    return "", version
