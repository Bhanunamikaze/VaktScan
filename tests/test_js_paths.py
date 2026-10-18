import unittest
import threading
import time
from unittest.mock import Mock

from modules.js_paths import JSPathsScanner, JSRecon


class JSPathsTests(unittest.TestCase):
    def test_scanner_allows_global_default_concurrency(self):
        self.assertEqual(JSPathsScanner([], threads=300).threads, 300)

    def test_probes_only_paths_associated_with_each_origin(self):
        recon = JSRecon([], threads=2)
        recon.origin_paths = {
            "https://a.example.com": {"/a", "/shared"},
            "https://b.example.com": {"/b", "/shared"},
        }
        seen = []
        recon.probe_endpoint = seen.append

        recon.execute_probing()

        self.assertEqual(
            set(seen),
            {
                ("https://a.example.com", "/a"),
                ("https://a.example.com", "/shared"),
                ("https://b.example.com", "/b"),
                ("https://b.example.com", "/shared"),
            },
        )
        self.assertNotIn(("https://a.example.com", "/b"), seen)

    def test_embedded_third_party_hosts_are_inventory_only_not_probe_targets(self):
        recon = JSRecon(["https://app.onit.com/login"])
        content = '''
        const localApi = "https://app.onit.com/api/v1/users";
        const webhook = "https://hooks.slack.com/services/T000/B000/secret";
        '''

        recon._extract_hosts_and_paths_from_urls(content)

        self.assertIn("https://app.onit.com", recon.hosts)
        self.assertNotIn("https://hooks.slack.com", recon.hosts)
        self.assertIn(
            "https://hooks.slack.com/services/T000/B000/secret",
            recon.absolute_urls,
        )

    def test_bounded_runner_does_not_submit_the_entire_input(self):
        recon = JSRecon([], threads=2)
        gate = threading.Event()
        worker_started = threading.Event()
        yielded = []
        processed = []

        def items():
            for item in range(100):
                yielded.append(item)
                yield item

        def worker(item):
            worker_started.set()
            gate.wait(timeout=2)
            processed.append(item)

        runner = threading.Thread(target=recon._run_bounded, args=(items(), worker))
        runner.start()
        self.assertTrue(worker_started.wait(timeout=1))
        time.sleep(0.05)

        # Two workers with a 2x pending window must consume only four items
        # while both worker threads are blocked, not all 100.
        self.assertLessEqual(len(yielded), 4)

        gate.set()
        runner.join(timeout=3)
        self.assertFalse(runner.is_alive())
        self.assertEqual(len(processed), 100)

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
