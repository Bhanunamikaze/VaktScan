"""Normalize bulk discovery-tool output into VaktScan findings.

The original raw files remain the authoritative, complete datasets embedded in
the unified HTML report.  These compact per-target summaries make the same data
visible to deduplication, inventory, JSON/CSV, and SARIF without creating one
finding for every one of potentially millions of archived URLs.
"""

from datetime import datetime, timezone
import glob
import os
from urllib.parse import urlparse

from modules.schema import normalize_finding


def _summary(tool, target, urls, artifact=""):
    unique = sorted({str(url).strip() for url in (urls or []) if str(url).strip()})
    if not unique:
        return None
    preview = "\n".join(unique[:25])
    suffix = f"\nRaw artifact: {artifact}" if artifact else ""
    return normalize_finding({
        "status": "INFO",
        "severity": "INFO",
        "vulnerability": f"{tool} URL Discovery",
        "target": target or "N/A",
        "resolved_ip": "N/A",
        "port": "N/A",
        "url": unique[0],
        "payload_url": unique[0],
        "module": tool.lower().replace(" ", "_"),
        "service_version": "N/A",
        "details": (
            f"{tool} discovered {len(unique)} unique URL(s) for {target}. "
            f"First {min(25, len(unique))}:\n{preview}{suffix}"
        ),
        "http_status": "N/A",
        "page_title": "N/A",
        "content_length": "N/A",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


def archive_findings(tool, results):
    """Create one normalized discovery finding per GAU/Wayback target."""
    if not isinstance(results, dict):
        return []
    findings = []
    for target, urls in sorted(results.items()):
        finding = _summary(tool, target, urls)
        if finding:
            findings.append(finding)
    return findings


def dirsearch_findings(reports_dir):
    """Create one normalized discovery finding per Dirsearch simple report."""
    if not reports_dir or not os.path.isdir(reports_dir):
        return []
    findings = []
    for path in sorted(glob.glob(os.path.join(reports_dir, "*.txt"))):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                urls = [line.strip() for line in handle if line.strip().startswith(("http://", "https://"))]
        except OSError:
            continue
        target = "N/A"
        if urls:
            target = urlparse(urls[0]).hostname or "N/A"
        finding = _summary("Dirsearch", target, urls, artifact=path)
        if finding:
            findings.append(finding)
    return findings
