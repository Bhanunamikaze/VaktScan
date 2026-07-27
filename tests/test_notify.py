"""Tests for modules/notify.py - alert delivery for NEW findings.

Everything runs WITHOUT network: httpx.AsyncClient and smtplib are mocked.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from modules import notify


# ── helpers ─────────────────────────────────────────────────────────────────────

def _run(coro):
    return asyncio.run(coro)


def _finding(severity="HIGH", status="VULNERABLE", vuln="Test Vuln", target="example.com"):
    """Build a minimal canonical-ish finding dict."""
    return {
        "status": status,
        "severity": severity,
        "vulnerability": vuln,
        "target": target,
        "resolved_ip": "1.2.3.4",
        "port": 443,
        "url": f"https://{target}",
        "module": "unit_test",
    }


# All env vars notify.py consults. Cleared before every test so the host
# environment can never leak in.
_NOTIFY_ENV = [
    "SLACK_WEBHOOK_URL", "DISCORD_WEBHOOK_URL", "VAKT_WEBHOOK_URL",
    "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS",
    "ALERT_EMAIL_TO", "ALERT_EMAIL_FROM",
    "VAKT_ALERT_MIN_SEVERITY", "VAKT_ALERT_TOP_N",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in _NOTIFY_ENV:
        monkeypatch.delenv(name, raising=False)
    yield


def _mock_async_client(post_return=None, post_side_effect=None):
    """A context-manager-style AsyncClient mock exposing an awaitable .post."""
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    if post_side_effect is not None:
        client.post = AsyncMock(side_effect=post_side_effect)
    else:
        resp = post_return if post_return is not None else MagicMock(status_code=200)
        client.post = AsyncMock(return_value=resp)
    return client


def _patch_client(client):
    return patch("modules.notify.httpx.AsyncClient", return_value=client)


# ── no configuration ─────────────────────────────────────────────────────────────

class TestNoConfig:
    def test_no_channels_configured_sends_nothing(self):
        client = _mock_async_client()
        with _patch_client(client):
            report = _run(notify.send_alerts([_finding()], {"HIGH": 1}))
        assert report["channels_sent"] == []
        assert report["errors"] == []
        assert any("no alert channels configured" in s for s in report["skipped"])
        client.post.assert_not_called()

    def test_no_findings_at_all(self):
        report = _run(notify.send_alerts([], {}))
        assert report["channels_sent"] == []
        assert report["errors"] == []
        assert report["skipped"]  # gate closed


# ── severity gate ────────────────────────────────────────────────────────────────

class TestSeverityGate:
    def test_info_only_findings_are_filtered(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/slack")
        client = _mock_async_client()
        findings = [
            _finding(severity="INFO", status="INFO", vuln="Info A"),
            _finding(severity="LOW", status="POTENTIAL", vuln="Low B"),
            _finding(severity="MEDIUM", status="POTENTIAL", vuln="Med C"),
        ]
        with _patch_client(client):
            report = _run(notify.send_alerts(findings, {}))
        assert report["channels_sent"] == []
        client.post.assert_not_called()
        assert any("at/above HIGH" in s for s in report["skipped"])

    def test_vulnerable_status_low_severity_still_alerts(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/slack")
        client = _mock_async_client()
        # LOW severity but VULNERABLE status must pass the gate.
        findings = [_finding(severity="LOW", status="VULNERABLE")]
        with _patch_client(client):
            report = _run(notify.send_alerts(findings, {}))
        assert report["channels_sent"] == ["slack"]
        client.post.assert_called_once()

    def test_min_severity_override_via_env(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/slack")
        monkeypatch.setenv("VAKT_ALERT_MIN_SEVERITY", "MEDIUM")
        client = _mock_async_client()
        findings = [_finding(severity="MEDIUM", status="POTENTIAL")]
        with _patch_client(client):
            report = _run(notify.send_alerts(findings, {}))
        assert report["channels_sent"] == ["slack"]


# ── webhook delivery ─────────────────────────────────────────────────────────────

class TestWebhookDelivery:
    def test_slack_post_called_with_sensible_payload(self, monkeypatch):
        url = "https://hooks.example/slack"
        monkeypatch.setenv("SLACK_WEBHOOK_URL", url)
        client = _mock_async_client()
        findings = [_finding(vuln="RCE in nginx", target="host.example.com")]
        with _patch_client(client):
            report = _run(notify.send_alerts(findings, {"HIGH": 1}, scan_label="nightly"))

        assert report["channels_sent"] == ["slack"]
        assert report["errors"] == []
        client.post.assert_called_once()
        call = client.post.call_args
        assert call.args[0] == url
        payload = call.kwargs["json"]
        assert "text" in payload
        assert "RCE in nginx" in payload["text"]
        assert "host.example.com" in payload["text"]
        assert "nightly" in payload["text"]

    def test_discord_uses_content_field(self, monkeypatch):
        monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.example/hook")
        client = _mock_async_client()
        with _patch_client(client):
            report = _run(notify.send_alerts([_finding()], {"HIGH": 1}))
        assert report["channels_sent"] == ["discord"]
        payload = client.post.call_args.kwargs["json"]
        assert "content" in payload
        assert len(payload["content"]) <= 2000

    def test_generic_webhook_structured_payload(self, monkeypatch):
        monkeypatch.setenv("VAKT_WEBHOOK_URL", "https://internal.example/vakt")
        client = _mock_async_client()
        findings = [_finding(vuln="Open S3 bucket", target="acme.com")]
        with _patch_client(client):
            report = _run(notify.send_alerts(findings, {"HIGH": 1}, scan_label="acme"))
        assert report["channels_sent"] == ["webhook"]
        payload = client.post.call_args.kwargs["json"]
        assert payload["source"] == "vaktscan"
        assert payload["count"] == 1
        assert payload["scan_label"] == "acme"
        assert isinstance(payload["findings"], list)
        assert payload["findings"][0]["vulnerability"] == "Open S3 bucket"
        assert payload["findings"][0]["target"] == "acme.com"
        assert payload["findings"][0]["severity"] == "HIGH"

    def test_multiple_webhooks_all_delivered(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/slack")
        monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.example/hook")
        monkeypatch.setenv("VAKT_WEBHOOK_URL", "https://internal.example/vakt")
        client = _mock_async_client()
        with _patch_client(client):
            report = _run(notify.send_alerts([_finding()], {"HIGH": 1}))
        assert set(report["channels_sent"]) == {"slack", "discord", "webhook"}
        assert client.post.call_count == 3

    def test_summary_built_defensively_when_empty(self, monkeypatch):
        monkeypatch.setenv("VAKT_WEBHOOK_URL", "https://internal.example/vakt")
        client = _mock_async_client()
        findings = [
            _finding(severity="HIGH", vuln="A"),
            _finding(severity="CRITICAL", vuln="B"),
        ]
        with _patch_client(client):
            report = _run(notify.send_alerts(findings, {}))  # empty summary
        assert report["channels_sent"] == ["webhook"]
        summary = client.post.call_args.kwargs["json"]["summary"]
        assert summary["HIGH"] == 1
        assert summary["CRITICAL"] == 1


# ── failure handling ─────────────────────────────────────────────────────────────

class TestFailureHandling:
    def test_post_failure_is_caught_and_recorded(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/slack")
        client = _mock_async_client(post_side_effect=httpx_error())
        with _patch_client(client):
            # Must not raise.
            report = _run(notify.send_alerts([_finding()], {"HIGH": 1}))
        assert report["channels_sent"] == []
        assert report["errors"]
        assert any("slack" in e for e in report["errors"])

    def test_one_channel_fails_other_succeeds(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/slack")
        monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.example/hook")

        async def _post(url, json=None):
            if "slack" in url:
                raise RuntimeError("boom")
            return MagicMock(status_code=200)

        client = _mock_async_client()
        client.post = AsyncMock(side_effect=_post)
        with _patch_client(client):
            report = _run(notify.send_alerts([_finding()], {"HIGH": 1}))
        assert report["channels_sent"] == ["discord"]
        assert any("slack" in e for e in report["errors"])

    def test_http_error_status_recorded(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/slack")
        bad_resp = MagicMock(status_code=500)
        bad_resp.raise_for_status.side_effect = RuntimeError("500 Server Error")
        client = _mock_async_client(post_return=bad_resp)
        with _patch_client(client):
            report = _run(notify.send_alerts([_finding()], {"HIGH": 1}))
        assert report["channels_sent"] == []
        assert report["errors"]


# ── email delivery ───────────────────────────────────────────────────────────────

class TestEmailDelivery:
    def test_email_sent_when_configured(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_USER", "alerts@example.com")
        monkeypatch.setenv("SMTP_PASS", "secret")
        monkeypatch.setenv("ALERT_EMAIL_TO", "soc@example.com")

        smtp_instance = MagicMock()
        with patch("modules.notify.smtplib.SMTP", return_value=smtp_instance) as smtp_cls:
            report = _run(notify.send_alerts([_finding()], {"HIGH": 1}, scan_label="lbl"))

        assert report["channels_sent"] == ["email"]
        assert report["errors"] == []
        smtp_cls.assert_called_once()
        smtp_instance.login.assert_called_once_with("alerts@example.com", "secret")
        smtp_instance.send_message.assert_called_once()

    def test_email_not_sent_without_recipient(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")  # no ALERT_EMAIL_TO
        with patch("modules.notify.smtplib.SMTP") as smtp_cls:
            report = _run(notify.send_alerts([_finding()], {"HIGH": 1}))
        assert report["channels_sent"] == []
        smtp_cls.assert_not_called()
        assert any("no alert channels configured" in s for s in report["skipped"])

    def test_email_failure_is_caught(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("ALERT_EMAIL_TO", "soc@example.com")
        with patch("modules.notify.smtplib.SMTP", side_effect=OSError("connect refused")):
            report = _run(notify.send_alerts([_finding()], {"HIGH": 1}))
        assert report["channels_sent"] == []
        assert any("email" in e for e in report["errors"])


def httpx_error():
    """A network-style error instance for post side_effect."""
    import httpx
    return httpx.ConnectError("connection refused")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
