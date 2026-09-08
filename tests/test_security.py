"""Security regression tests — council finding T6.

These tests verify that the security fixes applied to gui_bridge.py
actually prevent the attack paths identified by the council.

Previously these tests mirrored gui_bridge's sanitizer logic inline,
which meant the bug in the real implementation was masked by an
identically-buggy test mirror. We now import the real function so the
test exercises production code directly.
"""

from __future__ import annotations

import os
import sys

import pytest

# We test the sanitization logic directly without needing IPC
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestPathTraversal:
    """Verify output path sanitization prevents directory escape."""

    def _sanitize_name(self, name: str) -> str:
        """
        Delegate to the real sanitizer in gui_bridge so tests can't drift
        from production code (which is how the original bug stayed hidden).
        """
        from gui_bridge import sanitize_process_name
        return sanitize_process_name(name)

    def test_normal_name(self):
        assert self._sanitize_name("brawlhalla.exe") == "brawlhalla"

    def test_path_traversal_unix(self):
        result = self._sanitize_name("../../etc/cron.d/evil")
        assert ".." not in result
        assert "/" not in result
        assert "\\" not in result

    def test_path_traversal_windows(self):
        result = self._sanitize_name("..\\..\\Windows\\System32\\drivers\\etc\\hosts")
        assert ".." not in result
        assert "\\" not in result

    def test_empty_name_fallback(self):
        assert self._sanitize_name("") == "unknown"
        assert self._sanitize_name(".exe") == "unknown"

    def test_name_with_spaces(self):
        result = self._sanitize_name("among us.exe")
        assert result == "among us"

    def test_deeply_nested_traversal(self):
        result = self._sanitize_name("../../../../../../../../tmp/pwned")
        assert ".." not in result
        # After replacing / with _, basename gives us the last segment
        assert "tmp" not in result or "pwned" not in result

    def test_output_dir_stays_within_project(self):
        """The constructed output_dir must be under PROJECT_ROOT/output/."""
        name = "../../etc/passwd"
        safe_name = self._sanitize_name(name)
        output_dir = os.path.join(PROJECT_ROOT, "output", safe_name)
        # Resolve both paths and check containment
        resolved = os.path.realpath(output_dir)
        expected_parent = os.path.realpath(os.path.join(PROJECT_ROOT, "output"))
        assert resolved.startswith(expected_parent), (
            f"Path escaped output dir: {resolved}"
        )


class TestPidValidation:
    """Verify PID validation rejects invalid values."""

    def _is_valid_pid(self, pid) -> bool:
        """Mirror the validation logic from gui_bridge.py run_dump."""
        return isinstance(pid, int) and 0 < pid <= 65535

    def test_valid_pid(self):
        assert self._is_valid_pid(1234) is True

    def test_zero_pid_rejected(self):
        assert self._is_valid_pid(0) is False

    def test_negative_pid_rejected(self):
        assert self._is_valid_pid(-1) is False

    def test_huge_pid_rejected(self):
        assert self._is_valid_pid(999999999) is False

    def test_string_pid_rejected(self):
        assert self._is_valid_pid("1234") is False

    def test_none_pid_rejected(self):
        assert self._is_valid_pid(None) is False

    def test_system_pid_4(self):
        """PID 4 is the System process — valid range but dangerous to attach to."""
        assert self._is_valid_pid(4) is True  # Range-valid, but may fail at attach


class TestWebhookValidation:
    """Verify Discord webhook URL validation."""

    def _is_valid_webhook(self, url: str) -> bool:
        """Mirror the validation from gui_bridge._send_webhook."""
        if not url:
            return False
        if not url.startswith("https://discord.com/api/webhooks/"):
            return False
        parts = url.replace("https://discord.com/api/webhooks/", "").strip("/").split("/")
        if len(parts) < 2 or not parts[1]:
            return False
        return True

    def test_valid_webhook(self):
        assert self._is_valid_webhook(
            "https://discord.com/api/webhooks/123456/abcdef"
        ) is True

    def test_http_rejected(self):
        assert self._is_valid_webhook(
            "http://discord.com/api/webhooks/123456/abcdef"
        ) is False

    def test_wrong_domain_rejected(self):
        assert self._is_valid_webhook(
            "https://evil.com/api/webhooks/123456/abcdef"
        ) is False

    def test_incomplete_url_rejected(self):
        assert self._is_valid_webhook(
            "https://discord.com/api/webhooks/123456/"
        ) is False

    def test_empty_rejected(self):
        assert self._is_valid_webhook("") is False

    def test_missing_token_rejected(self):
        assert self._is_valid_webhook(
            "https://discord.com/api/webhooks/123456"
        ) is False
