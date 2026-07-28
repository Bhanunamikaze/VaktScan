"""
Tests for modules/web_tech_cve.py - web-layer technology version -> NVD CVE mapping.

Fully offline: modules.nvd.lookup_cves is mocked, no network or headers are
fetched. Uses unittest.IsolatedAsyncioTestCase so it runs regardless of any
pytest-asyncio mode configuration (matching tests/test_js_cve.py convention).

Coverage:
  * Server-header parse:  "nginx/1.18.0" -> (nginx, 1.18.0)
  * concrete version present -> a version-inferred CVE finding (POTENTIAL)
  * bare "nginx" (no version) -> NO finding, NVD never queried
  * dedupe against a CVE already reported for the same host
  * the --tech detection path feeds NVD (product mapped, lookup called)
  * a JavaScript library (header OR detection) is NOT mapped here (js_cve owns it)
"""

import unittest
from unittest.mock import patch

from modules import web_tech_cve
from modules.schema import validate_finding


def _fake_nvd_finding(cve_id, product, version, target="host.example.com",
                      port="443", severity="HIGH", cvss=7.5):
    """Shape a dict the way modules.nvd.lookup_cves returns them."""
    return {
        "status":          "CRITICAL" if cvss >= 9.0 else "VULNERABLE",
        "severity":        severity,
        "vulnerability":   f"{cve_id} - {product} {version}",
        "target":          target,
        "resolved_ip":     "N/A",
        "port":            str(port),
        "url":             f"nvd://{target}:{port}/{cve_id}",
        "payload_url":     f"nvd://{target}:{port}/{cve_id}",
        "module":          "nvd",
        "service_version": version,
        "details":         f"CVSS {cvss:.1f} ({severity}). Example description. "
                           f"Reference: https://nvd.nist.gov/vuln/detail/{cve_id}",
        "http_status":     "N/A",
        "page_title":      "N/A",
        "content_length":  "N/A",
        "timestamp":       "2026-01-01T00:00:00Z",
    }


class _NvdRecorder:
    """Async stand-in for nvd.lookup_cves that records calls and returns a
    scripted response keyed by (product, version)."""

    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    async def __call__(self, *, product, version, target="N/A", resolved_ip="N/A",
                       port="N/A", min_cvss=7.0, **kwargs):
        self.calls.append({"product": product, "version": version,
                           "target": target, "port": port, "min_cvss": min_cvss})
        out = self.responses.get((product, version), [])
        # Return copies so callers mutating findings can't corrupt the fixture.
        return [dict(f) for f in out]


# ── Pure-helper tests (no async / no mock needed) ───────────────────────────────

class HeaderParseTests(unittest.TestCase):

    def test_server_header_parse(self):
        self.assertEqual(
            web_tech_cve.parse_header_products("nginx/1.18.0"),
            [("nginx", "1.18.0")],
        )

    def test_server_header_with_os_suffix(self):
        # "Apache/2.4.7 (Ubuntu)" -> http_server 2.4.7 (OS suffix ignored)
        self.assertEqual(
            web_tech_cve.parse_header_products("Apache/2.4.7 (Ubuntu)"),
            [("http_server", "2.4.7")],
        )

    def test_x_powered_by_php_parse(self):
        self.assertEqual(
            web_tech_cve.parse_header_products("PHP/7.4.3"),
            [("php", "7.4.3")],
        )

    def test_bare_product_no_version_not_parsed(self):
        # No concrete version -> nothing, even for a scoped product.
        self.assertEqual(web_tech_cve.parse_header_products("nginx"), [])
        self.assertEqual(web_tech_cve.parse_header_products("cloudflare"), [])
        self.assertFalse(web_tech_cve.is_concrete_version(""))
        self.assertFalse(web_tech_cve.is_concrete_version("1"))
        self.assertTrue(web_tech_cve.is_concrete_version("1.18.0"))

    def test_js_library_not_mapped(self):
        # JavaScript libraries belong to js_cve / Retire.js, never mapped here.
        self.assertIsNone(web_tech_cve.map_product("jQuery"))
        self.assertIsNone(web_tech_cve.map_product("react"))
        self.assertIsNone(web_tech_cve.map_product("bootstrap"))
        # Even a "jquery/1.7"-style token must not map to a server CVE product.
        self.assertEqual(web_tech_cve.parse_header_products("jquery/1.7.2"), [])
        # ... while a real server product still maps.
        self.assertEqual(web_tech_cve.map_product("nginx"), "nginx")
        self.assertEqual(web_tech_cve.map_product("Apache Tomcat"), "tomcat")


# ── Async lookup tests (nvd mocked) ─────────────────────────────────────────────

class WebTechCveLookupTests(unittest.IsolatedAsyncioTestCase):

    async def test_header_version_yields_inferred_cve_finding(self):
        rec = _NvdRecorder({
            ("nginx", "1.18.0"): [_fake_nvd_finding("CVE-2021-23017", "nginx", "1.18.0")],
        })
        host_headers = [{
            "target": "host.example.com", "resolved_ip": "1.2.3.4",
            "port": "443", "url": "https://host.example.com/", "header": "nginx/1.18.0",
        }]
        with patch.object(web_tech_cve.nvd, "lookup_cves", new=rec):
            findings = await web_tech_cve.cves_from_headers(host_headers)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertIn("CVE-2021-23017", f["vulnerability"])
        self.assertEqual(f["status"], "POTENTIAL")          # conservative, not VULNERABLE
        self.assertEqual(f["module"], "web_tech_cve")
        self.assertEqual(f["target"], "host.example.com")
        self.assertEqual(f["service_version"], "1.18.0")
        self.assertEqual(f["url"], "https://host.example.com/")  # pinned to service URL
        self.assertIn("INFERRED", f["details"].upper())     # clearly labeled inferred
        self.assertEqual(validate_finding(f), [], f"schema violation: {f}")
        # NVD was queried once for the concrete pair.
        self.assertEqual(rec.calls, [{
            "product": "nginx", "version": "1.18.0",
            "target": "host.example.com", "port": "443", "min_cvss": 7.0,
        }])

    async def test_bare_product_no_version_no_finding_and_no_lookup(self):
        rec = _NvdRecorder({("nginx", ""): [_fake_nvd_finding("CVE-9999-0001", "nginx", "")]})
        host_headers = [{
            "target": "host.example.com", "port": "80",
            "url": "http://host.example.com/", "header": "nginx",  # no version
        }]
        with patch.object(web_tech_cve.nvd, "lookup_cves", new=rec):
            findings = await web_tech_cve.cves_from_headers(host_headers)

        self.assertEqual(findings, [])
        self.assertEqual(rec.calls, [], "NVD must not be queried without a concrete version")

    async def test_dedupe_against_existing_cve_for_same_host(self):
        rec = _NvdRecorder({
            ("nginx", "1.18.0"): [_fake_nvd_finding("CVE-2021-23017", "nginx", "1.18.0")],
        })
        host_headers = [{
            "target": "host.example.com", "port": "443",
            "url": "https://host.example.com/", "header": "nginx/1.18.0",
        }]
        existing = {("host.example.com", "CVE-2021-23017")}  # already reported by e.g. nuclei
        with patch.object(web_tech_cve.nvd, "lookup_cves", new=rec):
            findings = await web_tech_cve.cves_from_headers(
                host_headers, existing_cve_keys=existing)

        self.assertEqual(findings, [], "duplicate CVE for the same host must be suppressed")

    async def test_collect_existing_cve_keys(self):
        prior = [
            {"target": "host.example.com", "vulnerability": "CVE-2021-23017 - nginx 1.18.0"},
            {"target": "other.example.com", "vulnerability": "Missing HSTS Header"},
        ]
        keys = web_tech_cve.collect_existing_cve_keys(prior)
        self.assertIn(("host.example.com", "CVE-2021-23017"), keys)
        self.assertEqual(len(keys), 1)

    async def test_tech_detection_path_feeds_nvd(self):
        rec = _NvdRecorder({
            ("tomcat", "9.0.1"): [_fake_nvd_finding("CVE-2020-1938", "tomcat", "9.0.1",
                                                    target="app.example.com", port="8080")],
        })
        detections = [{
            "name": "Apache Tomcat", "version": "9.0.1",
            "target": "app.example.com", "resolved_ip": "N/A",
            "port": "8080", "url": "http://app.example.com:8080/",
        }]
        with patch.object(web_tech_cve.nvd, "lookup_cves", new=rec):
            findings = await web_tech_cve.cves_from_tech_detections(detections)

        self.assertEqual(len(findings), 1)
        self.assertIn("CVE-2020-1938", findings[0]["vulnerability"])
        self.assertEqual(findings[0]["module"], "web_tech_cve")
        self.assertEqual(findings[0]["status"], "POTENTIAL")
        self.assertEqual(validate_finding(findings[0]), [])
        # The --tech path mapped "Apache Tomcat" -> tomcat and queried NVD for it.
        self.assertEqual(len(rec.calls), 1)
        self.assertEqual(rec.calls[0]["product"], "tomcat")
        self.assertEqual(rec.calls[0]["version"], "9.0.1")

    async def test_tech_detection_js_library_not_fed_to_nvd(self):
        rec = _NvdRecorder({("jquery", "1.7.2"): [_fake_nvd_finding("CVE-0000-0000",
                                                                     "jquery", "1.7.2")]})
        detections = [{
            "name": "jQuery", "version": "1.7.2",
            "target": "app.example.com", "port": "443",
            "url": "https://app.example.com/",
        }]
        with patch.object(web_tech_cve.nvd, "lookup_cves", new=rec):
            findings = await web_tech_cve.cves_from_tech_detections(detections)

        self.assertEqual(findings, [], "JS library must not produce a server CVE finding")
        self.assertEqual(rec.calls, [], "NVD must not be queried for a JS library")


if __name__ == "__main__":
    unittest.main()
