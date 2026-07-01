"""Unit tests for ArgumentGuard file write checks."""

from __future__ import annotations

from agent_reliability_harness.argument_guard import ArgumentGuard
from agent_reliability_harness.spec import GuardAction


class TestArgumentGuardFileWrite:
    def test_safe_workspace_write_is_allowed(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "write_file",
            {"path": "workspace/notes.txt", "content": "demo"},
        )

        assert decision.action == GuardAction.allow
        assert decision.reason == "allow"

    def test_blocks_windows_system_path_write(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "write_file",
            {"path": r"C:\Windows\System32\drivers\etc\hosts", "content": "demo"},
        )

        assert decision.action == GuardAction.deny
        assert decision.check_type == "windows_system_write"
        assert decision.reason == "windows_system_write"
        assert decision.reason_zh == "检测到 Windows 系统路径写入尝试"
        assert decision.reason_en == "Windows system path write attempt detected"

    def test_blocks_linux_system_path_write(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "write_file",
            {"path": "/etc/hosts", "content": "demo"},
        )

        assert decision.action == GuardAction.deny
        assert decision.check_type == "linux_system_write"
        assert decision.reason == "linux_system_write"
        assert decision.reason_zh == "检测到 Linux 系统路径写入尝试"
        assert decision.reason_en == "Linux system path write attempt detected"

    def test_blocks_script_file_write(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "write_file",
            {"path": "workspace/startup.ps1", "content": "demo"},
        )

        assert decision.action == GuardAction.deny
        assert decision.check_type == "script_file_write"
        assert decision.reason == "script_file_write"
        assert decision.reason_zh == "检测到脚本文件写入尝试"
        assert decision.reason_en == "Script file write attempt detected"

    def test_blocks_path_traversal_write(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "write_file",
            {"path": "../../authorized_keys", "content": "demo"},
        )

        assert decision.action == GuardAction.deny
        assert decision.check_type == "path_traversal"
        assert decision.reason == "path_traversal"
        assert decision.reason_zh == "检测到目录穿越写文件尝试"
        assert decision.reason_en == "Directory traversal write attempt detected"
