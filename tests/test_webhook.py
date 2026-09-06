"""
Unit tests for _send_webhook URL validation + the urllib → curl → powershell
fallback chain. urllib and subprocess are mocked — no real network traffic.

These tests verify the LOGIC: that the right errors are raised on bad inputs,
that 403s trigger the fallback chain, and that the chain stops on first success.
They CANNOT verify that the live Cloudflare response actually accepts our UA —
that's a network-dependent observation only the user can confirm.
"""

from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import patch, MagicMock

import pytest

import gui_bridge


# ----------------------------------------------------------------------
# URL validation
# ----------------------------------------------------------------------

VALID_URL = (
    "https://discord.com/api/webhooks/1234567890123456789/"
    "AbCdEf-12345_xyz67890fakebutwellformedtokenstringaaaaaaaaaaaaa"
)


def test_empty_url_rejected():
    with pytest.raises(ValueError, match="No webhook URL"):
        gui_bridge._send_webhook("", {})


def test_whitespace_only_rejected():
    with pytest.raises(ValueError, match="empty after stripping"):
        gui_bridge._send_webhook("   \n  ", {})


def test_non_discord_domain_rejected():
    with pytest.raises(ValueError, match="must be a Discord webhook"):
        gui_bridge._send_webhook("https://example.com/api/webhooks/1/x", {})


@pytest.mark.parametrize(
    "domain",
    [
        "https://discord.com/api/webhooks/",
        "https://discordapp.com/api/webhooks/",
        "https://canary.discord.com/api/webhooks/",
        "https://ptb.discord.com/api/webhooks/",
    ],
)
def test_all_discord_domains_accepted(domain):
    """All four Discord domains pass the prefix check."""
    url = f"{domain}1234567890123456789/" + ("A" * 60)
    # Mock urllib to return success — we only care about prefix acceptance.
    mock_resp = MagicMock()
    mock_resp.status = 204
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_resp):
        # No exception means URL was accepted and "sent"
        gui_bridge._send_webhook(url, {"engine": "test"})


def test_truncated_paste_caught_by_non_numeric_id():
    """If the user's paste cut the ID, the leading segment won't be numeric."""
    url = "https://discord.com/api/webhooks/abc/" + ("A" * 60)
    with pytest.raises(ValueError, match="ID looks malformed"):
        gui_bridge._send_webhook(url, {})


def test_missing_token_rejected():
    url = "https://discord.com/api/webhooks/1234567890123456789/"
    with pytest.raises(ValueError, match="Incomplete URL"):
        gui_bridge._send_webhook(url, {})


def test_leading_trailing_whitespace_stripped():
    """Pasted URL with surrounding whitespace must reach urllib clean."""
    sent_url = []
    def fake_urlopen(req, timeout):
        sent_url.append(req.full_url)
        resp = MagicMock()
        resp.status = 204
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        gui_bridge._send_webhook(f"   {VALID_URL}\n  ", {"engine": "test"})

    assert sent_url[0] == VALID_URL, "URL was not stripped before send"


# ----------------------------------------------------------------------
# User-Agent
# ----------------------------------------------------------------------


def test_user_agent_is_discord_bot_format():
    """Cloudflare whitelist requires 'DiscordBot (url, version)' UA."""
    captured = {}

    def fake_urlopen(req, timeout):
        captured["headers"] = dict(req.header_items())
        resp = MagicMock()
        resp.status = 204
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        gui_bridge._send_webhook(VALID_URL, {"engine": "test"})

    ua = captured["headers"].get("User-agent") or captured["headers"].get("User-Agent")
    assert ua is not None, "User-Agent header missing"
    assert ua.startswith("DiscordBot ("), f"Wrong UA format: {ua!r}"


# ----------------------------------------------------------------------
# 403 fallback chain
# ----------------------------------------------------------------------


def _http_error(code: int, body: bytes = b""):
    """Build a urllib.error.HTTPError with a fake body for testing."""
    return urllib.error.HTTPError(
        url=VALID_URL, code=code, msg="Forbidden",
        hdrs=None, fp=io.BytesIO(body),
    )


def test_403_triggers_curl_fallback_and_returns_on_success():
    """urllib gets 403 → curl is tried → curl returns 204 → no exception."""
    with patch("urllib.request.urlopen", side_effect=_http_error(403)), \
         patch.object(gui_bridge, "_curl_send", return_value=None) as mock_curl, \
         patch.object(gui_bridge, "_powershell_send") as mock_ps:
        gui_bridge._send_webhook(VALID_URL, {"engine": "test"})
        mock_curl.assert_called_once()
        # PowerShell should NOT be tried if curl succeeded
        mock_ps.assert_not_called()


def test_403_falls_through_to_powershell_when_curl_fails():
    """urllib 403 → curl raises → powershell tried → succeeds → no exception."""
    with patch("urllib.request.urlopen", side_effect=_http_error(403)), \
         patch.object(gui_bridge, "_curl_send",
                      side_effect=RuntimeError("curl got HTTP 403")), \
         patch.object(gui_bridge, "_powershell_send", return_value=None) as mock_ps:
        gui_bridge._send_webhook(VALID_URL, {"engine": "test"})
        mock_ps.assert_called_once()


def test_all_three_tiers_failing_raises_friendly_message():
    """urllib 403 → curl fails → powershell fails → custom RuntimeError."""
    with patch("urllib.request.urlopen", side_effect=_http_error(403)), \
         patch.object(gui_bridge, "_curl_send",
                      side_effect=RuntimeError("curl 403")), \
         patch.object(gui_bridge, "_powershell_send",
                      side_effect=RuntimeError("ps 403")):
        with pytest.raises(RuntimeError, match="all.+three fingerprints"):
            gui_bridge._send_webhook(VALID_URL, {"engine": "test"})


# ----------------------------------------------------------------------
# 404 / 401 / 429 — non-fallback paths
# ----------------------------------------------------------------------


def test_404_does_not_trigger_fallback():
    """404 means resource gone; no point retrying with curl."""
    with patch("urllib.request.urlopen", side_effect=_http_error(404)), \
         patch.object(gui_bridge, "_curl_send") as mock_curl, \
         patch.object(gui_bridge, "_powershell_send") as mock_ps:
        with pytest.raises(RuntimeError, match="404"):
            gui_bridge._send_webhook(VALID_URL, {})
        mock_curl.assert_not_called()
        mock_ps.assert_not_called()


def test_401_diagnostic_mentions_token():
    with patch("urllib.request.urlopen", side_effect=_http_error(401)):
        with pytest.raises(RuntimeError, match="token is invalid"):
            gui_bridge._send_webhook(VALID_URL, {})


def test_429_diagnostic_mentions_rate_limit():
    with patch("urllib.request.urlopen", side_effect=_http_error(429)):
        with pytest.raises(RuntimeError, match="rate-limited"):
            gui_bridge._send_webhook(VALID_URL, {})


# ----------------------------------------------------------------------
# URL redaction for logging
# ----------------------------------------------------------------------


def test_redact_webhook_hides_token():
    out = gui_bridge._redact_webhook(VALID_URL)
    assert "<redacted-token>" in out
    assert "AbCdEf" not in out, "Token leaked into redacted output"
    assert "1234567890123456789" in out, "ID should be visible for diagnostics"


def test_redact_unparseable_url_doesnt_crash():
    out = gui_bridge._redact_webhook("not a url at all")
    assert isinstance(out, str)
    assert "AbCdEf" not in out
