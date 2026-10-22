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

    def test_probe_endpoint_records_302_as_inventory_not_vulnerability(self):
        recon = JSRecon([])
        recon.session.get = Mock(return_value=Mock(
            status_code=302,
            headers={"Server": "nginx", "Content-Type": "text/html"},
            text="",
        ))

        recon.probe_endpoint(("https://api.example.com", "/api/v1/users"))

        self.assertEqual(recon.findings, [])
        self.assertEqual(len(recon.probe_results), 1)
        self.assertEqual(recon.probe_results[0]["Status Code"], 302)

    def test_css_module_identifier_is_not_a_generic_secret(self):
        recon = JSRecon(["https://app.example.com/"])
        recon._check_secrets(
            "https://app.example.com/main.js",
            'requestToken:"ConnectModal_requestToken__bm0S9"',
        )
        self.assertEqual(recon.findings, [])

    def test_invalid_private_ip_shape_is_not_reported(self):
        recon = JSRecon(["https://app.example.com/"])
        recon._check_internal_ips(
            "https://app.example.com/main.js",
            'const artifact = "10.934.661.508";',
        )
        self.assertEqual(recon.findings, [])

    def test_valid_private_ip_is_reported(self):
        recon = JSRecon(["https://app.example.com/"])
        recon._check_internal_ips(
            "https://app.example.com/main.js",
            'const backend = "10.23.42.7";',
        )
        self.assertEqual(len(recon.findings), 1)

    def test_json_schema_password_property_is_not_sensitive_data(self):
        body = '{"routes":{"args":{"password":{"type":"string","required":false}}}}'
        self.assertEqual(JSRecon._sensitive_json_values(body), [])

    def test_json_secret_scalar_is_detected_without_returning_value(self):
        body = '{"user":{"access_token":"sl_live_example_123"}}'
        self.assertEqual(JSRecon._sensitive_json_values(body), ["access_token"])


def _fake_secret(prefix, suffix):
    """Build a test secret at runtime so the literal never appears in source."""
    return prefix + suffix


class NewSecretPatternTests(unittest.TestCase):
    """Tests for cloud-provider secret patterns added to SECRET_PATTERNS."""

    def _detect(self, content: str) -> list[dict]:
        recon = JSRecon(["https://app.example.com/"])
        recon._check_secrets("https://app.example.com/main.js", content)
        return recon.findings

    def _vuln_names(self, content: str) -> set[str]:
        return {f["vulnerability"] for f in self._detect(content)}

    # -- Stripe ----------------------------------------------------------------

    def test_stripe_secret_key_detected(self):
        key = _fake_secret("sk" + "_live_", "X" * 24)
        names = self._vuln_names(f'const key = "{key}";')
        self.assertIn("Hardcoded Secret: Stripe Secret Key", names)

    def test_stripe_restricted_key_detected(self):
        key = _fake_secret("rk" + "_live_", "X" * 24)
        names = self._vuln_names(f'const key = "{key}";')
        self.assertIn("Hardcoded Secret: Stripe Restricted Key", names)

    def test_stripe_test_key_not_detected(self):
        key = _fake_secret("sk" + "_test_", "X" * 24)
        findings = self._detect(f'const key = "{key}";')
        stripe_findings = [f for f in findings if "Stripe" in f["vulnerability"]]
        self.assertEqual(stripe_findings, [])

    # -- GitLab ----------------------------------------------------------------

    def test_gitlab_pat_detected(self):
        key = _fake_secret("glpat-", "X" * 20)
        names = self._vuln_names(f'token = "{key}";')
        self.assertIn("Hardcoded Secret: GitLab PAT", names)

    # -- SendGrid --------------------------------------------------------------

    def test_sendgrid_key_detected(self):
        key = _fake_secret("SG.", "X" * 22 + "." + "Y" * 43)
        names = self._vuln_names(f'apiKey = "{key}";')
        self.assertIn("Hardcoded Secret: SendGrid Key", names)

    # -- Azure -----------------------------------------------------------------

    def test_azure_storage_key_detected(self):
        key = "A" * 88
        content = f'conn = "DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey={key};";'
        names = self._vuln_names(content)
        self.assertIn("Hardcoded Secret: Azure Storage Key", names)

    # -- Twilio ----------------------------------------------------------------

    def test_twilio_api_key_detected(self):
        key = _fake_secret("SK", "a1" * 16)
        names = self._vuln_names(f'const sid = "{key}";')
        self.assertIn("Hardcoded Secret: Twilio API Key", names)

    def test_twilio_key_is_potential_not_critical(self):
        key = _fake_secret("SK", "a1" * 16)
        findings = self._detect(f'const sid = "{key}";')
        twilio = [f for f in findings if "Twilio" in f["vulnerability"]]
        self.assertEqual(len(twilio), 1)
        self.assertEqual(twilio[0]["status"], "POTENTIAL")
        self.assertEqual(twilio[0]["severity"], "HIGH")

    # -- Mailgun ---------------------------------------------------------------

    def test_mailgun_key_detected(self):
        key = _fake_secret("key-", "a1" * 16)
        names = self._vuln_names(f'mg_key = "{key}";')
        self.assertIn("Hardcoded Secret: Mailgun Key", names)

    # -- Shopify ---------------------------------------------------------------

    def test_shopify_token_detected(self):
        key = _fake_secret("shp" + "at_", "a1" * 16)
        names = self._vuln_names(f'const token = "{key}";')
        self.assertIn("Hardcoded Secret: Shopify Token", names)

    def test_shopify_private_app_token_detected(self):
        key = _fake_secret("shp" + "pa_", "a1" * 16)
        names = self._vuln_names(f'const token = "{key}";')
        self.assertIn("Hardcoded Secret: Shopify Token", names)

    # -- Square ----------------------------------------------------------------

    def test_square_token_detected(self):
        key = _fake_secret("sq0" + "atp-", "X" * 22)
        names = self._vuln_names(f'sq_token = "{key}";')
        self.assertIn("Hardcoded Secret: Square Token", names)

    # -- GCP Service Account ---------------------------------------------------

    def test_gcp_service_account_detected(self):
        findings = self._detect('{"type": "service_account", "project_id": "my-project"}')
        gcp = [f for f in findings if "GCP" in f["vulnerability"]]
        self.assertEqual(len(gcp), 1)
        self.assertEqual(gcp[0]["status"], "POTENTIAL")
        self.assertEqual(gcp[0]["severity"], "HIGH")

    # -- Credential URL --------------------------------------------------------

    def test_credential_url_detected(self):
        findings = self._detect('redirect = "https://api.example.com/callback?access_token=abc12345longtoken";')
        cred = [f for f in findings if "Credential URL" in f["vulnerability"]]
        self.assertEqual(len(cred), 1)
        self.assertEqual(cred[0]["status"], "POTENTIAL")

    # -- False-positive skip list in _credible_generic_secret ------------------

    def test_test_token_skip_value_not_flagged(self):
        findings = self._detect('secret: "test_token_xx"')
        generic = [f for f in findings if "Generic Secret" in f["vulnerability"]]
        self.assertEqual(generic, [])

    def test_fake_secret_skip_value_not_flagged(self):
        findings = self._detect('secret: "fake_secret_xx"')
        generic = [f for f in findings if "Generic Secret" in f["vulnerability"]]
        self.assertEqual(generic, [])

    # -- Schema validation for new findings ------------------------------------

    def test_new_pattern_findings_pass_schema_validation(self):
        from modules.schema import validate_finding
        stripe = _fake_secret("sk" + "_live_", "X" * 24)
        gitlab = _fake_secret("glpat-", "X" * 20)
        mailgun = _fake_secret("key-", "a1" * 16)
        content = f'{stripe} {gitlab} {mailgun} '
        findings = self._detect(content)
        self.assertGreaterEqual(len(findings), 3)
        for f in findings:
            violations = validate_finding(f)
            errors = [v for v in violations if not v.startswith("WARN:")]
            self.assertEqual(errors, [], f"Schema violations in {f['vulnerability']}: {errors}")


class PostMessageAndDomXssTests(unittest.TestCase):
    """Tests for postMessage listener and DOM XSS source-sink detection."""

    def _pm_detect(self, content: str) -> list[dict]:
        recon = JSRecon(["https://app.example.com/"])
        recon._check_postmessage("https://app.example.com/main.js", content)
        return recon.findings

    def _dom_detect(self, content: str) -> list[dict]:
        recon = JSRecon(["https://app.example.com/"])
        recon._check_dom_xss_sinks("https://app.example.com/main.js", content)
        return recon.findings

    # -- postMessage tests -------------------------------------------------------

    def test_postmessage_no_origin_check_detected(self):
        js = 'window.addEventListener("message", function(e) { div.innerHTML = e.data; });'
        findings = self._pm_detect(js)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"],
                         "postMessage Listener Without Origin Validation")
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_postmessage_with_origin_check_no_high_finding(self):
        js = '''
        window.addEventListener("message", function(event) {
            if (event.origin === "https://safe.example.com") {
                console.log(event.data);
            }
        });
        '''
        findings = self._pm_detect(js)
        high = [f for f in findings if f["severity"] == "HIGH"]
        self.assertEqual(high, [])

    def test_postmessage_with_origin_and_html_sink_detected(self):
        js = '''
        window.addEventListener("message", function(event) {
            if (event.origin === "https://safe.example.com") {
                document.getElementById("out").innerHTML = event.data;
            }
        });
        '''
        findings = self._pm_detect(js)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"],
                         "postMessage Handler With HTML Sink")
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_postmessage_single_finding_per_file(self):
        js = '''
        window.addEventListener("message", function(e) { x.innerHTML = e.data; });
        window.addEventListener("message", function(e) { y.innerHTML = e.data; });
        '''
        findings = self._pm_detect(js)
        self.assertEqual(len(findings), 1)

    # -- DOM XSS tests -----------------------------------------------------------

    def test_dom_xss_source_sink_detected(self):
        js = '''
        var hash = location.hash.substring(1);
        document.getElementById("content").innerHTML = hash;
        '''
        findings = self._dom_detect(js)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"],
                         "Potential DOM XSS Source-Sink Chain")

    def test_dom_xss_source_only_no_finding(self):
        js = 'var q = new URLSearchParams(location.search).get("q"); console.log(q);'
        findings = self._dom_detect(js)
        self.assertEqual(findings, [])

    def test_dom_xss_sink_only_no_finding(self):
        js = 'document.getElementById("x").innerHTML = "<b>static</b>";'
        findings = self._dom_detect(js)
        self.assertEqual(findings, [])

    def test_schema_validation_postmessage_and_dom_xss(self):
        from modules.schema import validate_finding
        pm_js = 'window.addEventListener("message", function(e) { x.innerHTML = e.data; });'
        dom_js = 'var h = location.hash; document.getElementById("x").innerHTML = h;'
        recon = JSRecon(["https://app.example.com/"])
        recon._check_postmessage("https://app.example.com/a.js", pm_js)
        recon._check_dom_xss_sinks("https://app.example.com/b.js", dom_js)
        self.assertGreaterEqual(len(recon.findings), 2)
        for f in recon.findings:
            violations = validate_finding(f)
            errors = [v for v in violations if not v.startswith("WARN:")]
            self.assertEqual(errors, [], f"Schema violations in {f['vulnerability']}: {errors}")


if __name__ == "__main__":
    unittest.main()
