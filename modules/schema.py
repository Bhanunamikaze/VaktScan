"""Schema validation and normalization utilities for VaktScan findings."""

from datetime import datetime

# The 15 canonical keys for all findings
CANONICAL_KEYS = [
    "status",
    "severity",
    "vulnerability",
    "target",
    "resolved_ip",
    "port",
    "url",
    "payload_url",
    "module",
    "service_version",
    "details",
    "http_status",
    "page_title",
    "content_length",
    "timestamp",
]

# Allowed status values
STATUS_VALUES = {"CRITICAL", "VULNERABLE", "POTENTIAL", "INFO"}

# Allowed severity values
SEVERITY_VALUES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def validate_finding(d: dict) -> list[str]:
    """
    Validate a finding dictionary against the canonical schema.

    Returns:
        A list of violation strings. Empty list means the finding is valid.
        Violations are prefixed with:
        - "MISSING" for missing required keys
        - "INVALID" for invalid field values
        - "FORBIDDEN" for disallowed keys
        - "WARN:" for unexpected extra keys (warnings, not errors)
    """
    violations = []

    # Check for missing canonical keys
    for key in CANONICAL_KEYS:
        if key not in d:
            violations.append(f"MISSING key: {key}")

    # Check for extra keys (warnings only, not errors)
    for key in d.keys():
        if key not in CANONICAL_KEYS:
            if key == "server":
                # server is forbidden, not just unexpected
                violations.append(f"FORBIDDEN key '{key}' present")
            else:
                # Other extra keys are warnings
                violations.append(f"WARN: unexpected key '{key}'")

    # Validate status field
    if "status" in d:
        status = d["status"]
        if status not in STATUS_VALUES:
            allowed = "|".join(sorted(STATUS_VALUES))
            violations.append(
                f"INVALID status: '{status}' (expected one of {allowed})"
            )

    # Validate severity field
    if "severity" in d:
        severity = d["severity"]
        if severity not in SEVERITY_VALUES:
            allowed = "|".join(sorted(SEVERITY_VALUES))
            violations.append(
                f"INVALID severity: '{severity}' (expected one of {allowed})"
            )

    return violations


def normalize_finding(d: dict) -> dict:
    """
    Normalize a finding dictionary to match the canonical schema.

    Returns:
        A new dictionary with:
        - All 15 canonical keys guaranteed present (missing ones filled with "N/A")
        - "server" key removed (promoted to resolved_ip if resolved_ip is "N/A")
        - Timestamp set to current UTC if absent or "N/A"
    """
    out = dict(d)

    # Handle server key: promote to resolved_ip if needed, then remove
    if "server" in out:
        if out.get("resolved_ip", "N/A") == "N/A":
            out["resolved_ip"] = out.pop("server")
        else:
            out.pop("server")

    # Fill missing canonical keys
    for key in CANONICAL_KEYS:
        if key not in out or out[key] is None:
            if key == "timestamp":
                # Set timestamp to current UTC in ISO format
                out[key] = datetime.utcnow().isoformat() + "Z"
            else:
                out[key] = "N/A"

    return out
