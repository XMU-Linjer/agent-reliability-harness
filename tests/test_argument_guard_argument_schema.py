"""Tests for malformed tool argument structures."""

from __future__ import annotations

from agent_reliability_harness.argument_guard import ArgumentGuard
from agent_reliability_harness.spec import GuardAction


class TestArgumentGuardArgumentSchema:
    def test_missing_required_path_is_denied(self) -> None:
        decision = ArgumentGuard().check_tool_call("read_file", {})

        assert decision.action == GuardAction.deny
        assert decision.check_type == "missing_required_field"
        assert decision.reason == "missing_required_field"
        assert decision.reason_zh == "检测到缺失必需参数 path，已阻止 read_file 执行"
        assert decision.reason_en == (
            "Missing required path argument detected; read_file execution was blocked"
        )
        assert decision.evidence["attack_payload"] == "{}"

    def test_null_path_is_denied(self) -> None:
        decision = ArgumentGuard().check_tool_call("read_file", {"path": None})

        assert decision.action == GuardAction.deny
        assert decision.check_type == "null_argument"
        assert decision.reason == "null_argument"
        assert decision.reason_zh == "检测到 path 为 null，已阻止 read_file 执行"
        assert decision.reason_en == (
            "Null path argument detected; read_file execution was blocked"
        )
        assert decision.evidence["attack_payload"] == '{"path": null}'

    def test_arguments_not_object_is_denied_before_path_checks(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "read_file",
            "../../../../etc/passwd",
        )

        assert decision.action == GuardAction.deny
        assert decision.check_type == "arguments_not_object"
        assert decision.reason == "arguments_not_object"
        assert decision.reason != "path_traversal"
        assert decision.evidence["attack_payload"] == '"../../../../etc/passwd"'

    def test_oversized_path_is_denied_with_summary_evidence(self) -> None:
        decision = ArgumentGuard().check_tool_call("read_file", {"path": "A" * 100000})

        assert decision.action == GuardAction.deny
        assert decision.check_type == "argument_too_long"
        assert decision.reason == "argument_too_long"
        assert decision.evidence["attack_payload"] == "A repeated 100000 times"
        assert decision.evidence["payload_length"] == 100000
        assert decision.evidence["payload_preview"] == "AAAAAAAAAA..."
