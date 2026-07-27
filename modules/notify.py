"""
modules/notify.py - Alert delivery for NEW findings (continuous monitoring).

Continuous monitoring (inventory delta in ``modules.inventory`` +
new-certificate detection in ``modules.ct_monitor``) discovers NEW findings but
currently only prints them to stdout / persists them to SQLite. This module
fans those NEW findings out to a human via one or more channels:

  - Webhooks (Slack / Discord / generic) via the async ``httpx`` library.
  - Email via ``smtplib`` (the blocking send runs in a thread executor so it
    never blocks the event loop).

Every channel is configured purely through environment variables and is used
**only if configured** - otherwise it is skipped silently. Alerts are only
delivered when there are NEW findings at or above a configurable minimum
severity (default: HIGH / CRITICAL / VULNERABLE).

Design contract: ``send_alerts`` **NEVER raises**. A delivery failure logs a
single warning and is recorded in the returned report; the caller can safely
``await`` it as a terminal step without a try/except.

Environment variables
----------------------
Webhooks (any/all, used only if set):
    SLACK_WEBHOOK_URL       Slack incoming webhook  -> POST {"text": ...}
    DISCORD_WEBHOOK_URL     Discord webhook         -> POST {"content": ...}
    VAKT_WEBHOOK_URL        Generic webhook         -> POST rich JSON

Email (used only if SMTP_HOST and ALERT_EMAIL_TO are both set):
    SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASS
    ALERT_EMAIL_TO          Comma-separated recipient list
    ALERT_EMAIL_FROM        Optional From address (defaults to SMTP_USER)

Tuning:
    VAKT_ALERT_MIN_SEVERITY  Minimum severity to alert on (default "HIGH")
    VAKT_ALERT_TOP_N         Number of findings to list in the message (default 10)

Entry point
-----------
    async def send_alerts(new_findings, summary, scan_label="") -> dict
        returns {"channels_sent": [...], "skipped": [...], "errors": [...]}
"""

import asyncio
import logging
import os
import smtplib
from email.message import EmailMessage

import httpx

MODULE_NAME = "notify"

_log = logging.getLogger("vaktscan.notify")

# Webhooks POST to third-party endpoints; be patient but bounded.
_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# Ordered severity ranking (matches modules.schema.SEVERITY_VALUES).
_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Statuses that always qualify for an alert regardless of the severity gate.
_ALERT_STATUSES = {"VULNERABLE", "CRITICAL"}

_DEFAULT_MIN_SEVERITY = "HIGH"
_DEFAULT_TOP_N = 10


# ─── Configuration helpers ──────────────────────────────────────────────────────

def _env(name: str) -> str:
    """Return a stripped environment value ('' if unset)."""
    return (os.environ.get(name) or "").strip()


def _min_severity() -> str:
    """Configured minimum severity; falls back to the default if invalid."""
    raw = _env("VAKT_ALERT_MIN_SEVERITY").upper()
    return raw if raw in _SEVERITY_RANK else _DEFAULT_MIN_SEVERITY


def _top_n() -> int:
    """How many findings to enumerate in the message body."""
    raw = _env("VAKT_ALERT_TOP_N")
    try:
        n = int(raw)
        return n if n > 0 else _DEFAULT_TOP_N
    except (TypeError, ValueError):
        return _DEFAULT_TOP_N


def _webhook_targets() -> list[tuple[str, str]]:
    """Return configured ``(channel_name, url)`` webhook pairs."""
    targets: list[tuple[str, str]] = []
    slack = _env("SLACK_WEBHOOK_URL")
    if slack:
        targets.append(("slack", slack))
    discord = _env("DISCORD_WEBHOOK_URL")
    if discord:
        targets.append(("discord", discord))
    generic = _env("VAKT_WEBHOOK_URL")
    if generic:
        targets.append(("webhook", generic))
    return targets


def _email_configured() -> bool:
    """Email is usable only when a host and at least one recipient are set."""
    return bool(_env("SMTP_HOST") and _env("ALERT_EMAIL_TO"))


# ─── Finding severity / gating ──────────────────────────────────────────────────

def _rank(severity) -> int:
    return _SEVERITY_RANK.get(str(severity or "").upper(), 0)


def _is_alertable(finding: dict, min_sev: str) -> bool:
    """A finding alerts if its status is severe, or its severity meets the gate."""
    status = str(finding.get("status", "") or "").upper()
    if status in _ALERT_STATUSES:
        return True
    return _rank(finding.get("severity")) >= _rank(min_sev)


def _severity_counts(findings: list[dict]) -> dict:
    """Count findings by severity bucket (unknown severities -> INFO)."""
    counts = {k: 0 for k in _SEVERITY_ORDER}
    for f in findings:
        sev = str(f.get("severity", "") or "INFO").upper()
        if sev not in counts:
            sev = "INFO"
        counts[sev] += 1
    return counts


def _ensure_summary(summary, findings: list[dict]) -> dict:
    """Use the caller's summary if present; otherwise build it from findings."""
    if isinstance(summary, dict) and summary:
        return {str(k).upper(): v for k, v in summary.items()}
    return _severity_counts(findings)


def _top_findings(findings: list[dict], top_n: int) -> list[dict]:
    """Return the ``top_n`` findings sorted by severity (highest first, stable)."""
    return sorted(findings, key=lambda f: _rank(f.get("severity")), reverse=True)[:top_n]


def _target_of(finding: dict) -> str:
    return (
        finding.get("target")
        or finding.get("resolved_ip")
        or finding.get("url")
        or "N/A"
    )


# ─── Message construction ───────────────────────────────────────────────────────

def _build_text(alertable: list[dict], summary: dict, scan_label: str, top_n: int) -> str:
    """Build a compact plain-text alert body shared by every channel."""
    lines: list[str] = []
    header = "VaktScan alert"
    if scan_label:
        header += f" - {scan_label}"
    lines.append(header)
    lines.append(f"{len(alertable)} new finding(s) at/above alert threshold")

    parts = [f"{sev} {summary.get(sev, 0)}" for sev in _SEVERITY_ORDER if summary.get(sev, 0)]
    if parts:
        lines.append("Severity: " + ", ".join(parts))

    lines.append("")
    for f in _top_findings(alertable, top_n):
        sev = str(f.get("severity", "") or "N/A").upper()
        vuln = str(f.get("vulnerability", "") or "N/A")
        lines.append(f"[{sev}] {vuln} - {_target_of(f)}")

    remaining = len(alertable) - min(len(alertable), top_n)
    if remaining > 0:
        lines.append(f"... and {remaining} more")

    return "\n".join(lines)


def _payload_for(name: str, text: str, alertable: list[dict],
                 summary: dict, scan_label: str, top_n: int) -> dict:
    """Return the JSON body appropriate for the given channel."""
    if name == "slack":
        # Slack incoming webhooks accept a top-level "text" field.
        return {"text": text}
    if name == "discord":
        # Discord webhooks accept "content"; hard cap is 2000 chars.
        return {"content": text[:1900]}
    # Generic webhook: send a structured, machine-readable body.
    return {
        "source": "vaktscan",
        "scan_label": scan_label,
        "count": len(alertable),
        "summary": summary,
        "text": text,
        "findings": [
            {
                "target": _target_of(f),
                "vulnerability": f.get("vulnerability", "N/A"),
                "severity": f.get("severity", "N/A"),
            }
            for f in _top_findings(alertable, top_n)
        ],
    }


def _subject(alertable: list[dict], scan_label: str) -> str:
    base = f"[VaktScan] {len(alertable)} new finding(s)"
    if scan_label:
        base += f" - {scan_label}"
    return base


# ─── Delivery: webhooks ─────────────────────────────────────────────────────────

async def _deliver_webhooks(webhooks, alertable, summary, scan_label, text, top_n, report):
    """POST the alert to each configured webhook, recording per-channel outcome."""
    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT,
            verify=False,
            headers={"User-Agent": "VaktScan/1.0 notify"},
        ) as client:
            for name, url in webhooks:
                try:
                    payload = _payload_for(name, text, alertable, summary, scan_label, top_n)
                    resp = await client.post(url, json=payload)
                    resp.raise_for_status()
                    report["channels_sent"].append(name)
                except Exception as exc:  # noqa: BLE001 - never propagate
                    _log.warning("notify: %s webhook delivery failed: %s", name, exc)
                    report["errors"].append(f"{name}: {exc}")
    except Exception as exc:  # noqa: BLE001 - client construction failure
        _log.warning("notify: webhook client error: %s", exc)
        report["errors"].append(f"webhook: {exc}")


# ─── Delivery: email ────────────────────────────────────────────────────────────

def _send_email_blocking(subject: str, body: str) -> None:
    """Synchronous SMTP send - invoked inside a thread executor."""
    host = _env("SMTP_HOST")
    try:
        port = int(_env("SMTP_PORT") or "587")
    except ValueError:
        port = 587
    user = _env("SMTP_USER")
    password = os.environ.get("SMTP_PASS") or ""
    to_raw = _env("ALERT_EMAIL_TO")
    from_addr = _env("ALERT_EMAIL_FROM") or user or to_raw
    recipients = [addr.strip() for addr in to_raw.split(",") if addr.strip()]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)

    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=15)
    else:
        server = smtplib.SMTP(host, port, timeout=15)
    try:
        if port != 465:
            try:
                server.starttls()
            except Exception:  # noqa: BLE001 - server may not offer STARTTLS
                pass
        if user:
            server.login(user, password)
        server.send_message(msg, from_addr=from_addr, to_addrs=recipients)
    finally:
        try:
            server.quit()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass


async def _deliver_email(subject: str, body: str, report: dict) -> None:
    """Run the blocking SMTP send in a thread so the event loop stays free."""
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _send_email_blocking, subject, body)
        report["channels_sent"].append("email")
    except Exception as exc:  # noqa: BLE001 - never propagate
        _log.warning("notify: email delivery failed: %s", exc)
        report["errors"].append(f"email: {exc}")


# ─── Public entry point ─────────────────────────────────────────────────────────

async def send_alerts(new_findings: list[dict], summary: dict, scan_label: str = "") -> dict:
    """
    Deliver an alert for NEW findings to every configured channel.

    Args:
        new_findings: The delta's NEW findings (canonical finding dicts). This
            is typically ``delta['new']`` from ``inventory.save_findings`` and/or
            the findings returned by ``ct_monitor.check_new_certificates``.
        summary: A dict of severity counts. If empty/None it is rebuilt
            defensively from ``new_findings``.
        scan_label: Optional human-readable label for this scan (e.g. targets
            file name or a timestamp) included in the message.

    Returns:
        {"channels_sent": [...], "skipped": [...], "errors": [...]}

    Never raises: any failure is logged once and recorded in the report.
    """
    report: dict = {"channels_sent": [], "skipped": [], "errors": []}

    try:
        findings = list(new_findings or [])
        summary = _ensure_summary(summary, findings)
        min_sev = _min_severity()

        alertable = [f for f in findings if _is_alertable(f, min_sev)]
        if not alertable:
            report["skipped"].append(
                f"no NEW findings at/above {min_sev} (or VULNERABLE) - "
                f"{len(findings)} new total"
            )
            return report

        webhooks = _webhook_targets()
        email_on = _email_configured()
        if not webhooks and not email_on:
            report["skipped"].append("no alert channels configured")
            return report

        top_n = _top_n()
        text = _build_text(alertable, summary, scan_label, top_n)

        if webhooks:
            await _deliver_webhooks(
                webhooks, alertable, summary, scan_label, text, top_n, report
            )
        else:
            report["skipped"].append("webhooks: not configured")

        if email_on:
            await _deliver_email(_subject(alertable, scan_label), text, report)
        else:
            report["skipped"].append("email: not configured")

    except Exception as exc:  # noqa: BLE001 - send_alerts must never raise
        _log.warning("notify: unexpected error while sending alerts: %s", exc)
        report["errors"].append(f"notify: {exc}")

    return report
