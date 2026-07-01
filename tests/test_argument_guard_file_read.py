"""Tests for file-read ArgumentGuard rules."""

from __future__ import annotations

from pathlib import Path

from agent_reliability_harness.argument_guard import ArgumentGuard
from agent_reliability_harness.spec import GuardAction


class TestArgumentGuardFileRead:
    def test_safe_read_file_allow(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "read_file",
            {"path": "docs/example.md"},
        )

        assert decision.action == GuardAction.allow

    def test_path_traversal_deny(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "read_file",
            {"path": "../../../../etc/passwd"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "path_traversal"
        assert decision.check_type == "path_traversal"
        assert decision.reason_zh == "检测到路径穿越读取尝试"
        assert decision.reason_en == "Path traversal read attempt detected"

    def test_linux_sensitive_path_deny(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "read_file",
            {"path": "/etc/passwd"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "linux_sensitive_path"
        assert decision.check_type == "sensitive_path"

    def test_windows_sensitive_path_deny(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "read_file",
            {"path": "C:\\Windows\\System32\\config\\SAM"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "windows_sensitive_path"
        assert decision.check_type == "windows_sensitive_path"

    def test_outside_workspace_read_deny(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "read_file",
            {"path": "..\\..\\..\\secret.env"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "path_traversal"
        assert decision.check_type == "path_traversal"
        assert decision.reason_zh == "检测到项目目录外读取尝试"

    def test_does_not_read_real_files(self, tmp_path: Path) -> None:
        marker = tmp_path / "secret.env"
        marker.write_text("do-not-read", encoding="utf-8")

        decision = ArgumentGuard().check_tool_call(
            "read_file",
            {"path": str(marker)},
        )

        assert decision.action == GuardAction.allow

    def test_does_not_execute_shell(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "read_file",
            {"path": "echo should-not-run"},
        )

        assert decision.action == GuardAction.allow
