"""
web_tech_cve.py - Map web-layer technology versions to NVD CVEs (VaktScan).

Motivation
----------
Historically the version->CVE path (modules/nvd.py) was fed almost entirely by
nmap/service_recon banners. Concrete versions detected at the WEB layer - the
HTTP ``Server`` / ``X-Powered-By`` response headers httpx/web_checks already
fetched, and the product/version pairs the ``--tech`` webanalyze fingerprint
detects - never reached NVD reliably (PHP, OpenSSL, Tomcat, jetty, webanalyze
detections in particular). This module closes that gap.

Two entry points
----------------
* ``cves_from_headers(host_headers, ...)``  - DEFAULT-ON lightweight path. Parses
  (product, version) out of the ``Server`` / ``X-Powered-By`` header strings that
  were ALREADY fetched for each alive host (no new HTTP requests) and looks up
  CVEs via ``modules.nvd.lookup_cves``.
* ``cves_from_tech_detections(detections, ...)`` - the fuller ``--tech`` path.
  Feeds webanalyze product/version detections into the same NVD lookup on top of
  the header path.

Both emit canonical findings whose ``vulnerability`` field carries the CVE id
(e.g. ``"CVE-2021-23017 - nginx 1.18.0"``) - exactly the convention modules/js_cve
uses - so the shared ``_enrich_and_report`` tail runs CISA-KEV / EPSS / CVSS
enrichment over them automatically. This module NEVER calls KEV/EPSS itself.

False-positive discipline (the maintainer cares deeply here)
-----------------------------------------------------------
* A CONCRETE version (>= major.minor, e.g. ``1.18.0``) is REQUIRED. A bare
  product name with no version NEVER fires.
* Findings are marked version-INFERRED / ``POTENTIAL`` - never ``CRITICAL`` /
  ``VULNERABLE`` - and the ``details`` state plainly that the CVE is inferred from
  a detected version banner (which can be spoofed, backported, or vendor-patched
  without a version bump), not confirmed exploitation. The CVE's real CVSS-derived
  severity is preserved so triage still sees HIGH/CRITICAL, but the POTENTIAL
  status signals "verify first".
* Scope is SERVER / FRAMEWORK products ONLY (nginx, apache/httpd, php, openssl,
  iis, tomcat, ...). JavaScript libraries are deliberately excluded - js_cve /
  Retire.js owns those (see ``JS_LIB_NAMES`` and the ``SERVER_PRODUCTS`` allow-list).
* Callers pass ``existing_cve_keys`` (a set of ``(target, CVE-ID)``) so a CVE
  already reported for the same host by nuclei / nmap / service_recon / js_cve is
  not duplicated. nvd's existing CVSS>=7 filter is kept.

Fail-open: every lookup is best-effort; an NVD failure or a malformed header
never raises - it just yields no finding.
"""

from __future__ import annotations

import asyncio
import re

from modules import nvd
from modules.schema import normalize_finding

MODULE_NAME = "web_tech_cve"

# ── Product scope ──────────────────────────────────────────────────────────────
# Detected/header product name (lowercased) -> the NVD product key understood by
# modules.nvd.lookup_cves / CPE_VENDOR_MAP. SERVER / FRAMEWORK products ONLY.
# JavaScript libraries are intentionally absent - js_cve owns those.
SERVER_PRODUCTS: dict[str, str] = {
    "nginx":               "nginx",
    "openresty":           "nginx",       # OpenResty embeds nginx; version tracks nginx
    "apache":              "http_server",
    "httpd":               "http_server",
    "apache httpd":        "http_server",
    "apache http server":  "http_server",
    "php":                 "php",
    "openssl":             "openssl",
    "iis":                 "iis",
    "microsoft-iis":       "iis",
    "microsoft iis":       "iis",
    "tomcat":              "tomcat",
    "apache tomcat":       "tomcat",
    "apache-coyote":       "tomcat",       # Tomcat's HTTP connector Server token
    "coyote":              "tomcat",
    "lighttpd":            "lighttpd",
    "jetty":               "jetty",
}

# Explicit deny-list of client-side JavaScript libraries. Defense-in-depth on top
# of the SERVER_PRODUCTS allow-list: these belong to js_cve / Retire.js and must
# never be mapped to a server CVE here.
JS_LIB_NAMES: frozenset[str] = frozenset({
    "jquery", "jquery-ui", "jquery ui", "react", "react-dom", "angular",
    "angularjs", "angular.js", "vue", "vue.js", "vuejs", "bootstrap", "lodash",
    "underscore", "underscore.js", "moment", "moment.js", "backbone",
    "backbone.js", "ember", "ember.js", "handlebars", "handlebars.js",
    "knockout", "knockout.js", "d3", "d3.js", "dojo", "mootools", "prototype",
    "ext js", "extjs", "swiper", "axios", "next.js", "nuxt.js", "gsap",
    "select2", "modernizr", "requirejs", "require.js",
})

# "name/version" tokens inside a Server / X-Powered-By header value, e.g.
# "nginx/1.18.0", "Apache/2.4.7", "PHP/7.4.3", "OpenSSL/1.0.2k".
_TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z0-9_+.\-]*?)/([0-9][0-9A-Za-z.\-]*)")

# A concrete version needs at least major.minor (e.g. "1.18.0", "2.4", "1.0.2k").
# A bare product name, a single "1", or empty string is NOT concrete.
_CONCRETE_VERSION_RE = re.compile(r"^\d+\.\d+(?:[.\-][0-9A-Za-z.\-]*)?$")

# CVE id matcher (shared for extraction + dedup key building).
CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)


# ── Pure helpers (unit-testable, no I/O) ───────────────────────────────────────

def is_concrete_version(version: str) -> bool:
    """True only for a concrete >= major.minor version. Guards against firing on
    a bare product name or a partial/absent version."""
    v = (version or "").strip()
    if not v or v.lower() in ("unknown", "n/a"):
        return False
    return bool(_CONCRETE_VERSION_RE.match(v))


def map_product(name: str) -> str | None:
    """Map a detected tech / header product name to a scoped NVD product key, or
    None if it is not a server/framework product (e.g. a JS library)."""
    key = (name or "").strip().lower()
    if not key or key in JS_LIB_NAMES:
        return None
    if key in SERVER_PRODUCTS:
        return SERVER_PRODUCTS[key]
    first = key.split()[0] if key.split() else ""
    if not first or first in JS_LIB_NAMES:
        return None
    return SERVER_PRODUCTS.get(first)


def parse_header_products(header_value: str) -> list[tuple[str, str]]:
    """Parse a Server / X-Powered-By header string into scoped (nvd_product,
    version) pairs. Only concrete versions of server/framework products survive;
    a bare "nginx" (no version) yields nothing."""
    out: list[tuple[str, str]] = []
    if not header_value:
        return out
    for m in _TOKEN_RE.finditer(header_value):
        product = map_product(m.group(1))
        version = m.group(2)
        if product and is_concrete_version(version):
            out.append((product, version))
    return out


def collect_existing_cve_keys(findings) -> set[tuple[str, str]]:
    """Build the dedup set ``{(target, CVE-ID), ...}`` from findings already
    reported (nuclei / nmap / service_recon / js_cve / ...). A CVE named in a
    finding's ``vulnerability`` field for a host suppresses a duplicate here."""
    keys: set[tuple[str, str]] = set()
    for f in findings or []:
        target = f.get("target", "N/A")
        for m in CVE_RE.finditer(f.get("vulnerability", "") or ""):
            keys.add((target, m.group(0).upper()))
    return keys


def _inferred_finding(nvd_finding: dict, *, product: str, version: str,
                      target: str, resolved_ip: str, port, url: str,
                      source: str) -> dict:
    """Downgrade an ``nvd.lookup_cves`` result to a version-INFERRED POTENTIAL
    finding pinned to the detected host/URL, with an honest disclaimer."""
    m = CVE_RE.search(nvd_finding.get("vulnerability", "") or "")
    cve_id = m.group(0).upper() if m else ""
    base_details = nvd_finding.get("details", "") or ""
    details = (
        f"VERSION-INFERRED (not confirmed): {source} reported {product} {version} "
        f"on this host, and {cve_id or 'a CVE'} affects that version per NVD "
        f"(CVSS>=7). This is inferred from a detected version banner - which can be "
        f"spoofed, back-ported, or vendor-patched without a version bump - NOT from "
        f"confirmed exploitation. Verify before acting. {base_details}"
    ).strip()
    use_url = url if url and url != "N/A" else nvd_finding.get("url", "N/A")
    return normalize_finding({
        "status":          "POTENTIAL",
        "severity":        nvd_finding.get("severity", "MEDIUM"),
        "vulnerability":   nvd_finding.get("vulnerability",
                                           f"{cve_id} - {product} {version}".strip()),
        "target":          target,
        "resolved_ip":     resolved_ip,
        "port":            str(port),
        "url":             use_url,
        "payload_url":     use_url,
        "module":          MODULE_NAME,
        "service_version": version,
        "details":         details,
        "http_status":     "N/A",
        "page_title":      "N/A",
        "content_length":  "N/A",
    })


# ── Async lookup core ──────────────────────────────────────────────────────────

async def _lookup_batch(candidates: list[tuple[dict, str, str, str]],
                        existing_cve_keys: set[tuple[str, str]] | None,
                        min_cvss: float) -> list[dict]:
    """Shared lookup + assembly for both paths.

    ``candidates`` is a list of ``(entry, product, version, source)`` where
    ``entry`` carries target/resolved_ip/port/url. Runs the NVD lookups
    concurrently, dedups against ``existing_cve_keys`` (and internally), and
    returns version-inferred POTENTIAL findings. Never raises.
    """
    if not candidates:
        return []

    existing = set(existing_cve_keys or set())
    seen: set[tuple[str, str]] = set()

    tasks = [
        nvd.lookup_cves(
            product=product, version=version,
            target=entry.get("target", "N/A"),
            resolved_ip=entry.get("resolved_ip", "N/A"),
            port=entry.get("port", "N/A"),
            min_cvss=min_cvss,
        )
        for (entry, product, version, _src) in candidates
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[dict] = []
    for res, (entry, product, version, source) in zip(results, candidates):
        if not isinstance(res, list):
            continue  # NVD failure for this pair -> fail-open, skip
        target = entry.get("target", "N/A")
        for nvd_f in res:
            m = CVE_RE.search(nvd_f.get("vulnerability", "") or "")
            if not m:
                continue
            cve_id = m.group(0).upper()
            key = (target, cve_id)
            if key in existing or key in seen:
                continue
            seen.add(key)
            findings.append(_inferred_finding(
                nvd_f, product=product, version=version,
                target=target,
                resolved_ip=entry.get("resolved_ip", "N/A"),
                port=entry.get("port", "N/A"),
                url=entry.get("url", "N/A"),
                source=source,
            ))
    return findings


async def cves_from_headers(host_headers: list[dict], *,
                            existing_cve_keys: set[tuple[str, str]] | None = None,
                            min_cvss: float = 7.0) -> list[dict]:
    """DEFAULT-ON header path. ``host_headers`` is a list of dicts, each with a
    ``header`` string (a raw Server / X-Powered-By value) plus target /
    resolved_ip / port / url context. Returns version-inferred CVE findings."""
    candidates: list[tuple[dict, str, str, str]] = []
    for entry in host_headers or []:
        for product, version in parse_header_products(entry.get("header", "")):
            candidates.append((entry, product, version,
                               "The Server/X-Powered-By response header"))
    return await _lookup_batch(candidates, existing_cve_keys, min_cvss)


async def cves_from_tech_detections(detections: list[dict], *,
                                    existing_cve_keys: set[tuple[str, str]] | None = None,
                                    min_cvss: float = 7.0) -> list[dict]:
    """``--tech`` path. ``detections`` is a list of dicts with a ``name`` (the
    detected product, e.g. "Apache Tomcat") and ``version`` plus target /
    resolved_ip / port / url context. JS libraries and version-less detections
    are skipped. Returns version-inferred CVE findings."""
    candidates: list[tuple[dict, str, str, str]] = []
    for det in detections or []:
        product = map_product(det.get("name") or "")
        version = (det.get("version") or "").strip()
        if product and is_concrete_version(version):
            candidates.append((det, product, version,
                               "The webanalyze technology fingerprint"))
    return await _lookup_batch(candidates, existing_cve_keys, min_cvss)
