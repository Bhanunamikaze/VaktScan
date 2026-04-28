import unittest
from unittest.mock import Mock

from modules.js_paths import JSRecon


class JSPathsTests(unittest.TestCase):
    def test_extract_hosts_paths_and_absolute_urls_from_full_urls(self):
        recon = JSRecon([])
        content = """
        aiBuilderBaseUrl:"https://gateway.bluehost-agents.newfold.com/bluehost/agents/website-builder",
        payuReturnURL:"https://www.bluehost.com/checkout/cart/process-payment?payuPaymentAction=success",
        paymentRedirect:"/?paypalPayment=true",
        """

        recon._extract_hosts_and_paths_from_urls(content)
        recon.paths.update(recon._extract_paths(content))

        self.assertIn(
            "https://gateway.bluehost-agents.newfold.com/bluehost/agents/website-builder",
            recon.absolute_urls,
        )
        self.assertIn(
            "https://www.bluehost.com/checkout/cart/process-payment?payuPaymentAction=success",
            recon.absolute_urls,
        )
        self.assertIn("https://gateway.bluehost-agents.newfold.com", recon.hosts)
        self.assertIn("https://www.bluehost.com", recon.hosts)
        self.assertIn("/bluehost/agents/website-builder", recon.paths)
        self.assertIn("/checkout/cart/process-payment", recon.paths)
        self.assertIn("/?paypalPayment=true", recon.paths)
        self.assertIn(
            "/checkout/cart/process-payment?payuPaymentAction=success",
            recon.paths,
        )

    def test_extracts_template_based_absolute_urls_without_adding_template_hosts(self):
        recon = JSRecon([])
        content = """
        pricingUrl:`https://${C.hostname}/api/v1.0/prices/summary?productCode=${r}&siteId=${i}`
        """

        recon._extract_hosts_and_paths_from_urls(content)

        self.assertIn(
            "https://${C.hostname}/api/v1.0/prices/summary?productCode=${r}&siteId=${i}",
            recon.absolute_urls,
        )
        self.assertNotIn("https://${C.hostname}", recon.hosts)
        self.assertIn("/api/v1.0/prices/summary", recon.paths)

    def test_probe_endpoint_does_not_create_sensitive_path_finding_for_403(self):
        recon = JSRecon([])
        recon.session.get = Mock(return_value=Mock(
            status_code=403,
            headers={"Server": "cloudflare", "Content-Type": "text/html"},
            text="",
        ))

        recon.probe_endpoint(("https://securepay.svcs.endurance.com", "/api/v1.0/cart"))

        self.assertEqual(recon.findings, [])
        self.assertEqual(len(recon.probe_results), 1)
        self.assertEqual(recon.probe_results[0]["Status Code"], 403)

    def test_probe_endpoint_does_not_create_sensitive_path_finding_for_401(self):
        recon = JSRecon([])
        recon.session.get = Mock(return_value=Mock(
            status_code=401,
            headers={"Server": "nginx", "Content-Type": "text/html"},
            text="",
        ))

        recon.probe_endpoint(("https://api.example.com", "/api/v1/users"))

        self.assertEqual(recon.findings, [])
        self.assertEqual(len(recon.probe_results), 1)
        self.assertEqual(recon.probe_results[0]["Status Code"], 401)

    def test_probe_endpoint_keeps_sensitive_path_finding_for_302(self):
        recon = JSRecon([])
        recon.session.get = Mock(return_value=Mock(
            status_code=302,
            headers={"Server": "nginx", "Content-Type": "text/html"},
            text="",
        ))

        recon.probe_endpoint(("https://api.example.com", "/api/v1/users"))

        self.assertEqual(len(recon.findings), 1)
        self.assertEqual(recon.findings[0]["status"], "POTENTIAL")
        self.assertEqual(recon.findings[0]["http_status"], "302")


if __name__ == "__main__":
    unittest.main()
