"""Phase-4 stable state-key tests (doc T6).

Asserts the resumable-state identity behaves as designed:

* the same target string yields the same ``scan_id`` across independent runs;
* flipping a scope-affecting flag (e.g. ``-m``) yields a DIFFERENT id (so the
  narrower/wider scan gets its own independent state);
* renaming a targets file with identical contents keeps the resume identity
  (its digest) stable;
* changing ``concurrency`` (a NON-scope field) keeps the id stable, so resume is
  still allowed with a different ``-c``;
* ip / domain / cidr targets each produce a stable, canonicalized id.

Pure/offline: no network, no subprocess, no state files written.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from state_key import (  # noqa: E402
    canonical_targets,
    scope_signature,
    compute_scan_id,
)
from utils import parse_targets_file  # noqa: E402


# A representative "default scan" scope config; individual tests tweak one key.
def _base_scope_cfg(**overrides):
    cfg = {
        "module_filter": None,
        "ports": None,
        "no_subdomain_enum": False,
        "dns_permute": False,
        "dns_hygiene": True,
        "dns_takeover": True,
        "company_only": False,
        "shared_ip_threshold": 10,
        "horizontal": False,
        "archived_scan": True,
        "stream_web_probe": False,
        "extra_scans": [],
        "nmap": False,
        "no_dork": False,
        "exclude": None,
        "include_only": None,
    }
    cfg.update(overrides)
    return cfg


def _scan_id_for(target_type, raw, primary_label, scope_cfg):
    targets = canonical_targets(target_type, raw, parse_targets_file)
    sig = scope_signature(scope_cfg)
    return compute_scan_id(primary_label, targets, sig)


def _digest_of(scan_id):
    """The 16-hex digest is the resume identity; the leading slug is cosmetic."""
    return scan_id.rsplit("-", 1)[-1]


class SameTargetSameIdTest(unittest.TestCase):
    def test_same_domain_string_same_id_across_runs(self):
        a = _scan_id_for("domain", "example.com", "example.com", _base_scope_cfg())
        b = _scan_id_for("domain", "example.com", "example.com", _base_scope_cfg())
        self.assertEqual(a, b)

    def test_domain_normalization_is_stable(self):
        # Case, trailing dot, and bracket noise must not change the id.
        a = _scan_id_for("domain", "example.com", "example.com", _base_scope_cfg())
        b_targets = canonical_targets("domain", "Example.COM.", parse_targets_file)
        self.assertEqual(b_targets, ["example.com"])
        b = compute_scan_id("example.com", b_targets, scope_signature(_base_scope_cfg()))
        self.assertEqual(a, b)


class ScopeFlagFlipChangesIdTest(unittest.TestCase):
    def test_module_filter_flip_changes_id(self):
        default = _scan_id_for("domain", "example.com", "example.com", _base_scope_cfg())
        with_mod = _scan_id_for("domain", "example.com", "example.com",
                                _base_scope_cfg(module_filter="elasticsearch"))
        self.assertNotEqual(default, with_mod)

    def test_ports_flip_changes_id(self):
        default = _scan_id_for("ip", "192.168.1.1", "192.168.1.1", _base_scope_cfg())
        custom = _scan_id_for("ip", "192.168.1.1", "192.168.1.1",
                              _base_scope_cfg(ports="8080,9200"))
        self.assertNotEqual(default, custom)

    def test_collection_order_does_not_change_scope(self):
        # extra_scans / exclude are order-insensitive.
        a = scope_signature(_base_scope_cfg(extra_scans=["tech", "favicon"],
                                            exclude=["b", "a"]))
        b = scope_signature(_base_scope_cfg(extra_scans=["favicon", "tech"],
                                            exclude=["a", "b"]))
        self.assertEqual(a, b)


class FileRenameSameContentsSameIdTest(unittest.TestCase):
    def test_rename_same_contents_keeps_resume_digest(self):
        contents = "Example.COM\n1.2.3.4\n"
        d = tempfile.mkdtemp(prefix="vaktscan_state_key_")
        try:
            p1 = os.path.join(d, "targets.txt")
            p2 = os.path.join(d, "hosts.txt")
            for p in (p1, p2):
                with open(p, "w") as f:
                    f.write(contents)

            t1 = canonical_targets("file", p1, parse_targets_file)
            t2 = canonical_targets("file", p2, parse_targets_file)
            # Same contents => same canonicalized, sorted target set.
            self.assertEqual(t1, t2)
            self.assertEqual(t1, ["1.2.3.4", "example.com"])

            sig = scope_signature(_base_scope_cfg())
            id1 = compute_scan_id(os.path.splitext(os.path.basename(p1))[0], t1, sig)
            id2 = compute_scan_id(os.path.splitext(os.path.basename(p2))[0], t2, sig)
            # The resume identity (digest of targets+scope) is stable across the
            # rename even though the cosmetic slug follows the filename.
            self.assertEqual(_digest_of(id1), _digest_of(id2))
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)


class ConcurrencyChangeSameIdTest(unittest.TestCase):
    def test_concurrency_is_not_in_the_key(self):
        # concurrency is deliberately NOT a scope field: two cfgs that differ
        # only by a (spurious) concurrency entry must hash identically, so a
        # resume with a different -c is allowed.
        sig_a = scope_signature(_base_scope_cfg())
        cfg_b = _base_scope_cfg()
        cfg_b["concurrency"] = 500  # ignored by scope_signature
        sig_b = scope_signature(cfg_b)
        self.assertEqual(sig_a, sig_b)

        id_a = compute_scan_id("example.com", ["example.com"], sig_a)
        id_b = compute_scan_id("example.com", ["example.com"], sig_b)
        self.assertEqual(id_a, id_b)


class TargetTypeStableIdsTest(unittest.TestCase):
    def test_ip_stable_and_canonical(self):
        a = _scan_id_for("ip", "192.168.1.1", "192.168.1.1", _base_scope_cfg())
        b = _scan_id_for("ip", "192.168.1.1", "192.168.1.1", _base_scope_cfg())
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("192.168.1.1-"))

    def test_domain_stable(self):
        a = _scan_id_for("domain", "example.com", "example.com", _base_scope_cfg())
        b = _scan_id_for("domain", "example.com", "example.com", _base_scope_cfg())
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("example.com-"))

    def test_cidr_stable_and_canonical(self):
        # Dotted-mask and prefix-length forms canonicalize to one entry, so both
        # spellings resume the same scan.
        dotted = canonical_targets("cidr", "10.0.0.0/255.255.255.0", parse_targets_file)
        prefix = canonical_targets("cidr", "10.0.0.0/24", parse_targets_file)
        self.assertEqual(dotted, prefix)
        self.assertEqual(prefix, ["10.0.0.0/24"])

        sig = scope_signature(_base_scope_cfg())
        a = compute_scan_id("10.0.0.0/24", prefix, sig)
        b = compute_scan_id("10.0.0.0/24", dotted, sig)
        self.assertEqual(a, b)
        # slug sanitization: '/' -> '_'
        self.assertTrue(a.startswith("10.0.0.0_24-"))


if __name__ == "__main__":
    unittest.main()
