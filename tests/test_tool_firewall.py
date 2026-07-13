"""Tests for ToolFirewall — Day 3."""

from __future__ import annotations

from agent_guard.guards.runtime_guard import GuardDecision
from benchmark.spec import GuardAction, PolicySpec, ToolRiskLevel
from agent_guard.guards.tool_firewall import ToolFirewall, _risk_exceeds


def _make_policy(**overrides) -> PolicySpec:
    """Create a PolicySpec with sensible defaults, allowing field overrides."""
    defaults = {
        "allowed_models": ["gpt-4o"],
        "max_token_budget": 10000,
        "max_tool_risk_level": ToolRiskLevel.low,
    }
    defaults.update(overrides)
    return PolicySpec(**defaults)


class TestSafeToolAllowed:
    """Safe tools should be allowed when policy permits."""

    def test_read_file_allowed_with_low_risk(self) -> None:
        fw = ToolFirewall()
        policy = _make_policy(max_tool_risk_level=ToolRiskLevel.low)
        decision = fw.check_tool_call("read_file", {"path": "test.txt"}, policy)
        assert decision.action == GuardAction.allow
        assert isinstance(decision, GuardDecision)

    def test_search_web_allowed_with_safe_risk(self) -> None:
        fw = ToolFirewall()
        policy = _make_policy(max_tool_risk_level=ToolRiskLevel.safe)
        decision = fw.check_tool_call("search_web", {"query": "test"}, policy)
        assert decision.action == GuardAction.allow


class TestUnknownToolDenied:
    """Unknown tools should always be denied."""

    def test_unknown_tool_denied(self) -> None:
        fw = ToolFirewall()
        policy = _make_policy(max_tool_risk_level=ToolRiskLevel.critical)
        decision = fw.check_tool_call("nonexistent_tool", {}, policy)
        assert decision.action == GuardAction.deny
        assert "nonexistent_tool" in decision.reason

    def test_unknown_tool_check_type(self) -> None:
        fw = ToolFirewall()
        policy = _make_policy()
        decision = fw.check_tool_call("fake_unknown", {}, policy)
        assert decision.check_type == "firewall_unknown_tool"


class TestDeniedToolsList:
    """Tools in denied_tools list should be denied."""

    def test_denied_tool_blocked(self) -> None:
        fw = ToolFirewall()
        policy = _make_policy(
            max_tool_risk_level=ToolRiskLevel.critical,
            denied_tools=["write_file", "execute_shell"],
        )
        decision = fw.check_tool_call("write_file", {"path": "x", "content": "y"}, policy)
        assert decision.action == GuardAction.deny
        assert "denied" in decision.reason.lower()

    def test_non_denied_tool_allowed(self) -> None:
        fw = ToolFirewall()
        policy = _make_policy(
            max_tool_risk_level=ToolRiskLevel.critical,
            denied_tools=["execute_shell"],
        )
        decision = fw.check_tool_call("read_file", {"path": "test.txt"}, policy)
        assert decision.action == GuardAction.allow


class TestAllowedToolsList:
    """Tools not in allowed_tools list should be denied."""

    def test_tool_not_in_allowed_list_denied(self) -> None:
        fw = ToolFirewall()
        policy = _make_policy(
            max_tool_risk_level=ToolRiskLevel.high,
            allowed_tools=["read_file", "search_web"],
        )
        decision = fw.check_tool_call("write_file", {"path": "x", "content": "y"}, policy)
        assert decision.action == GuardAction.deny
        assert "allowed" in decision.reason.lower()

    def test_tool_in_allowed_list_allowed(self) -> None:
        fw = ToolFirewall()
        policy = _make_policy(
            max_tool_risk_level=ToolRiskLevel.low,
            allowed_tools=["read_file", "search_web"],
        )
        decision = fw.check_tool_call("read_file", {"path": "test.txt"}, policy)
        assert decision.action == GuardAction.allow


class TestRiskLevelEnforcement:
    """Risk level checks should enforce the maximum allowed level."""

    def test_high_risk_denied_when_max_is_low(self) -> None:
        fw = ToolFirewall()
        policy = _make_policy(max_tool_risk_level=ToolRiskLevel.low)
        # write_file is risk_level=high
        decision = fw.check_tool_call("write_file", {"path": "x", "content": "y"}, policy)
        assert decision.action == GuardAction.deny
        assert "risk" in decision.reason.lower()
        assert "high" in decision.reason.lower()

    def test_critical_tool_denied_when_max_is_low(self) -> None:
        fw = ToolFirewall()
        policy = _make_policy(max_tool_risk_level=ToolRiskLevel.low)
        decision = fw.check_tool_call("execute_shell", {"command": "ls"}, policy)
        assert decision.action == GuardAction.deny

    def test_critical_tool_denied_when_max_is_high(self) -> None:
        fw = ToolFirewall()
        policy = _make_policy(max_tool_risk_level=ToolRiskLevel.high)
        decision = fw.check_tool_call("execute_shell", {"command": "ls"}, policy)
        assert decision.action == GuardAction.deny

    def test_critical_tool_allowed_when_max_is_critical(self) -> None:
        fw = ToolFirewall()
        policy = _make_policy(max_tool_risk_level=ToolRiskLevel.critical)
        decision = fw.check_tool_call("execute_shell", {"command": "ls"}, policy)
        assert decision.action == GuardAction.allow

    def test_high_risk_allowed_when_max_is_high(self) -> None:
        fw = ToolFirewall()
        policy = _make_policy(max_tool_risk_level=ToolRiskLevel.high)
        decision = fw.check_tool_call("write_file", {"path": "x", "content": "y"}, policy)
        assert decision.action == GuardAction.allow


class TestRiskLevelOrder:
    """Validate the risk level ordering: safe < low < high < critical."""

    def test_safe_less_than_low(self) -> None:
        assert not _risk_exceeds(ToolRiskLevel.safe, ToolRiskLevel.low)

    def test_low_less_than_high(self) -> None:
        assert not _risk_exceeds(ToolRiskLevel.low, ToolRiskLevel.high)

    def test_high_less_than_critical(self) -> None:
        assert not _risk_exceeds(ToolRiskLevel.high, ToolRiskLevel.critical)

    def test_critical_exceeds_high(self) -> None:
        assert _risk_exceeds(ToolRiskLevel.critical, ToolRiskLevel.high)

    def test_high_exceeds_low(self) -> None:
        assert _risk_exceeds(ToolRiskLevel.high, ToolRiskLevel.low)

    def test_low_exceeds_safe(self) -> None:
        assert _risk_exceeds(ToolRiskLevel.low, ToolRiskLevel.safe)

    def test_same_level_does_not_exceed(self) -> None:
        for level in ToolRiskLevel:
            assert not _risk_exceeds(level, level)
