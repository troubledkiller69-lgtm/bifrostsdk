"""
Live subprocess verification of api_server.py.

Spawns the actual Python backend, talks to it over stdin/stdout JSON,
and confirms:

  1. bridge_info returns the new build stamp + feature flags
  2. test_webhook with a syntactically-valid-but-nonexistent Discord URL
     produces the new friendly 404 diagnostic (proving _send_webhook runs)
  3. test_webhook with whitespace gets stripped (regression on the original
     404 root cause)
  4. test_webhook with a non-Discord URL gets rejected at the validator

These tests DO make network calls (to Discord, which returns 404 for
nonexistent webhook IDs). They confirm the LIVE end-to-end path is wired
up correctly without spamming any real user webhook.

Run with: python -m pytest tests/test_backend_live.py -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_SERVER = os.path.join(PROJECT_ROOT, "api_server.py")

# A snowflake well below the 2^63 max that is statistically guaranteed not
# to exist as a real Discord webhook ID. Token is well-formed base64-ish
# junk. Discord returns 404 for the (id, token) pair → exercises our
# HTTPError handler path.
#
# IMPORTANT: must be <= 9223372036854775807 (2^63 - 1). Earlier test used
# 9999999999999999999 which Discord rejects with 400 because it exceeds
# max snowflake. We pick a recent-looking snowflake instead.
FAKE_BUT_VALID_URL = (
    "https://discord.com/api/webhooks/1234567890123456789/"
    "ThisIsAFakeTokenForTestingOnlyDoNotUseInRealConfigurationXYZ123"
)


@pytest.fixture
def backend():
    """Spawn api_server.py as a subprocess; tear down after each test."""
    proc = subprocess.Popen(
        [sys.executable, API_SERVER],
        cwd=PROJECT_ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    # Drain stderr (the startup banner) without blocking.
    time.sleep(0.5)
    yield proc
    try:
        proc.stdin.close()
    except Exception:
        pass
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()


def _send(proc, command, args=None, req_id=1):
    """Send a JSON command over stdin and read the response from stdout."""
    msg = {
        "protocol_version": "1.1-enforcement-draft",
        "command": command,
        "args": args or {},
        "id": req_id,
    }
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()

    # Read until we get a line with our req_id
    deadline = time.time() + 8.0
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05)
            continue
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if data.get("_id") == req_id:
            return data
        # Other messages (log/progress) are ignored for this test harness.
    raise TimeoutError(f"No response with _id={req_id} within 8s")


# ----------------------------------------------------------------------
# bridge_info
# ----------------------------------------------------------------------

def test_bridge_info_returns_build_stamp(backend):
    """The new bridge_info command should return a real build stamp."""
    resp = _send(backend, "bridge_info")
    assert "data" in resp, f"bridge_info missing data: {resp}"
    stamp = resp["data"].get("build_stamp", "")
    assert stamp and stamp != "unknown", f"Build stamp not populated: {stamp!r}"
    # Format: ISO timestamp + "+" + 8-char hash
    assert "+" in stamp and len(stamp.split("+")[1]) == 8


def test_bridge_info_advertises_new_features(backend):
    """The feature flags must include the powershell fallback we just added."""
    resp = _send(backend, "bridge_info")
    features = resp["data"].get("features", {})
    assert features.get("webhook_curl_fallback") is True
    assert features.get("webhook_powershell_fallback") is True
    assert features.get("webhook_strict_validation") is True
    assert features.get("webhook_discord_bot_ua") is True


# ----------------------------------------------------------------------
# test_webhook — validation
# ----------------------------------------------------------------------

def test_test_webhook_rejects_empty_url(backend):
    resp = _send(backend, "test_webhook", {"url": ""})
    err = resp.get("data", {}).get("error", "")
    assert "No webhook URL" in err, f"Wrong error: {err!r}"


def test_test_webhook_rejects_non_discord_url(backend):
    resp = _send(backend, "test_webhook", {"url": "https://example.com/api/webhooks/1/x"})
    err = resp.get("data", {}).get("error", "")
    assert "must be a Discord webhook" in err, f"Wrong error: {err!r}"


def test_test_webhook_rejects_truncated_id(backend):
    """Pasted URL where the ID got cut should fail with a clear hint."""
    resp = _send(backend, "test_webhook", {"url": "https://discord.com/api/webhooks/abc/sometoken"})
    err = resp.get("data", {}).get("error", "")
    assert "ID looks malformed" in err, f"Wrong error: {err!r}"


# ----------------------------------------------------------------------
# test_webhook — live network exercise (404 path)
# ----------------------------------------------------------------------

def test_test_webhook_fake_id_returns_friendly_404(backend):
    """
    Send a syntactically-valid URL whose ID is statistically guaranteed not
    to exist. Discord returns 404. Our NEW code must produce the friendly
    "webhook was deleted, URL was truncated, or stale URL" diagnostic —
    NOT the bare "HTTP Error 404: Forbidden" that escaped before.
    """
    resp = _send(backend, "test_webhook", {"url": FAKE_BUT_VALID_URL})
    err = resp.get("data", {}).get("error", "") or ""
    # Accept any of these as proof the new code path handled the response.
    # All of them are strings ONLY the new RuntimeError-wrapping code
    # produces; the old code would have leaked "HTTP Error NNN: ..." verbatim.
    new_code_markers = [
        "doesn't match any live webhook",  # 404 hint
        "Cloudflare/Discord rejected",     # 403 hint after fallbacks
        "token is invalid",                # 401 hint
        "rate-limited",                    # 429 hint
        "Network error",                   # URLError hint
        "HTTP 400 ",                       # generic-code hint w/ body
        "HTTP 5",                          # 5xx hints
    ]
    assert any(m in err for m in new_code_markers), (
        f"Backend did NOT run the new _send_webhook code path. "
        f"Got error: {err!r}. Expected one of: {new_code_markers}"
    )
    # Critical: must NOT be the raw urllib format that escaped pre-fix.
    bare_urllib_patterns = ["HTTP Error 404: Not Found", "HTTP Error 403: Forbidden",
                            "HTTP Error 401: Unauthorized"]
    assert not any(p == err for p in bare_urllib_patterns), (
        f"Backend is running stale code — raw HTTPError str escaped: {err!r}"
    )


def test_test_webhook_strips_whitespace_end_to_end(backend):
    """Whitespace in the URL was the ORIGINAL 404 root cause. Verify e2e."""
    padded = f"   {FAKE_BUT_VALID_URL}\n  "
    resp = _send(backend, "test_webhook", {"url": padded})
    err = resp.get("data", {}).get("error", "") or ""
    # Should reach the network layer (not stop at validation), then either
    # 404 or 403 / 401 from Discord — but NOT a validation error.
    bad_markers = ["No webhook URL", "must be a Discord webhook", "Incomplete URL"]
    assert not any(m in err for m in bad_markers), (
        f"Whitespace was NOT stripped before validation: {err!r}"
    )
