"""Regression test for the recon-phase `state_manager` scope bug.

`main.main()` assigns its local `state_manager` only after the reconnaissance
block runs. The recon block (and the nested `handle_domain` closure) previously
referenced `state_manager` directly, which raised:

    cannot access free variable 'state_manager' where it is not associated
    with a value in enclosing scope

The exception was swallowed by the `return_exceptions=True` gather and surfaced
as "Recon error ... / Recon finished with no usable targets", so recon never
produced targets. This test drives `main()` through the `-m recon` domain path
and asserts that recon-phase findings are buffered and flushed into the
state manager once it exists.
"""

import asyncio
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main  # noqa: E402


class _StopAfterFlush(Exception):
    """Raised to halt main() right after the recon-findings flush point."""


class _FakeReconScanner:
    def __init__(self, domain, wordlist=None, detailed_dashboard=True):
        self.domain = domain

    async def run_all(self):
        # (results_file, subdomains)
        return (os.path.join("reports", self.domain, "subs.txt"), [f"a.{self.domain}"])


class ReconStateScopeTest(unittest.TestCase):
    def test_recon_findings_flushed_to_state_manager(self):
        dns_finding = {"type": "dns", "severity": "LOW", "id": "recon-scope-test"}

        async def fake_passive(domain, concurrency, detailed_dashboard=True):
            # (dns_findings, cloud_findings, ct_findings) — dns non-empty triggers
            # the recon-phase add_vulnerability call that used to crash.
            return ([dns_finding], [], [])

        state_mgr = mock.MagicMock()

        def raise_stop(*args, **kwargs):
            raise _StopAfterFlush()

        fake_dashboard = mock.MagicMock()
        fake_dashboard.active = False

        with mock.patch.object(main.nuclei_runner, "sync_nuclei_templates", return_value=None), \
             mock.patch("modules.dashboard.LiveDashboard", return_value=fake_dashboard), \
             mock.patch.object(main.recon, "ReconScanner", _FakeReconScanner), \
             mock.patch.object(main, "_run_parallel_passive", fake_passive), \
             mock.patch.object(main, "ScanStateManager", return_value=state_mgr), \
             mock.patch.object(main, "inventory", mock.MagicMock()), \
             mock.patch.object(main, "parse_targets_file", side_effect=raise_stop):

            # Reaching parse_targets_file (raise_stop) proves recon completed and
            # main() advanced past state_manager creation + the findings flush.
            # `no_dork=True` is a real main() parameter now (no module-global
            # `args` dependency), so no injection hack is needed.
            with self.assertRaises(_StopAfterFlush):
                asyncio.run(
                    main.main(
                        None,   # targets_file
                        1,      # concurrency
                        recon_domains=["example.com"],
                        scan_found=False,
                        no_dork=True,
                    )
                )

        # The DNS finding gathered during recon must have been flushed.
        state_mgr.add_vulnerability.assert_any_call(dns_finding)


if __name__ == "__main__":
    unittest.main()
