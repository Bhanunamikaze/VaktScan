"""Stable scan-state identity (Phase 4).

The resumable-state key is derived from the *normalized target set* plus the
*scope-affecting configuration* - never from a temporary targets-file path or
from ``concurrency``. This is what makes ad-hoc ``scan <ip|domain|cidr>`` runs
resumable (they previously wrote a random temp file every run, so the old
path-derived key never matched), and it keeps a file rename (same contents) or
a ``-c`` change from breaking resume, while a scope change (e.g. ``-m``,
``--ports``) yields a different id and its own independent state.

See ``scan_lifecycle_architecture.md`` section 2.3 for the design rationale and
the worked examples.
"""

import hashlib
import ipaddress
import json
import re


def canonical_targets(target_type, raw, parse_targets_file) -> list:
    """Return the sorted, normalized set of targets for a scan.

    ``target_type`` is the classifier result (``file`` / ``ip`` / ``cidr`` /
    ``domain``); ``raw`` is the CLI target (a file path when ``target_type`` is
    ``file``, otherwise the literal target); ``parse_targets_file`` is injected so
    this module stays free of a ``utils`` import cycle.

    IPs/CIDRs are canonicalized via :mod:`ipaddress` (so ``10.0.0.0/24`` and
    ``10.0.0.0/255.255.255.0`` collapse to one form); domains are lowercased and
    stripped of a trailing dot and bracket notation.
    """
    def norm_one(s):
        s = s.strip().strip('[]')
        try:
            if '/' in s:
                return str(ipaddress.ip_network(s, strict=False))
            return str(ipaddress.ip_address(s))
        except ValueError:
            return s.lower().rstrip('.')  # domain

    if target_type == 'file':
        entries = {norm_one(l) for l in parse_targets_file(raw) if l.strip()}
    else:
        entries = {norm_one(raw)}
    return sorted(entries)


SCOPE_FIELDS = (        # only fields that change WHAT/HOW-MUCH is scanned
    "module_filter", "ports", "no_subdomain_enum", "dns_permute",
    "dns_hygiene", "dns_takeover", "company_only", "shared_ip_threshold",
    "horizontal", "archived_scan", "stream_web_probe", "extra_scans",
    "nmap", "no_dork", "exclude", "include_only",
)


def scope_signature(cfg: dict) -> str:
    """Hash the scope-affecting config so two runs with the same scope share a key.

    Fields NOT included (safe to change on resume): ``concurrency``,
    ``connect_timeout``, ``port_retries``, ``recon_concurrency``, ``dork_method``,
    output format flags, ``no_dashboard``, ``js_timeout``, ``chunk_size``.
    """
    scope = {k: cfg.get(k) for k in SCOPE_FIELDS}
    # normalize collections so ordering never affects the signature
    for k in ("ports", "extra_scans", "exclude", "include_only"):
        if scope.get(k):
            scope[k] = sorted(scope[k])
    return hashlib.sha256(json.dumps(scope, sort_keys=True).encode()).hexdigest()


def compute_scan_id(primary_label, targets, scope_sig) -> str:
    """Build a stable, human-readable state id: ``<slug>-<16-hex-digest>``.

    ``primary_label`` supplies the readable slug (the target, or a file's stem);
    the digest mixes the canonical target set with the scope signature.
    """
    tsig = hashlib.sha256("\n".join(targets).encode()).hexdigest()
    digest = hashlib.sha256(f"{tsig}\x00{scope_sig}".encode()).hexdigest()[:16]
    slug = re.sub(r"[^\w.-]", "_", primary_label)[:32]
    return f"{slug}-{digest}"
