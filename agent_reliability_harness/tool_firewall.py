"""
ToolFirewall for AgentReliabilityHarness.

Validates individual tool calls against a PolicySpec before execution:
- Unknown tool rejection
- Allowed/denied tool list enforcement
- Risk level threshold checks

No real execution. No prompt injection detection (Day 4/5).
"""

from __future__ import annotations

from typing import Any

from agent_reliability_harness.runtime_guard import GuardDecision
from agent_reliability_harness.spec import GuardAction, PolicySpec, ToolRiskLevel
from agent_reliability_harness.tools import ToolNotFoundError, get_tool

# Ordered risk levels for comparison (lower index = lower risk)
_RISK_LEVEL_ORDER: dict[ToolRiskLevel, int] = {
    ToolRiskLevel.safe: 0,
    ToolRiskLevel.low: 1,
    ToolRiskLevel.high: 2,
    ToolRiskLevel.critical: 3,
}


def _risk_exceeds(
    tool_risk: ToolRiskLevel, max_risk: ToolRiskLevel
) -> bool:
    """Return True if tool_risk is strictly greater than max_risk."""
    return _RISK_LEVEL_ORDER[tool_risk] > _RISK_LEVEL_ORDER[max_risk]


class ToolFirewall:
    """Evaluates tool calls against policy constraints.

    Usage::

        firewall = ToolFirewall()
        decision = firewall.check_tool_call("execute_shell", {"command": "ls"}, policy)
        if decision.action == GuardAction.deny:
            # block the tool call
    """

    def check_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        policy: PolicySpec,
    ) -> GuardDecision:
        """Check whether a tool call is permitted by policy.

        Checks are applied in order:
        1. Unknown tool → deny
        2. allowed_tools list (if set) → tool must be in it
        3. denied_tools list (if set) → tool must not be in it
        4. Risk level → tool risk must not exceed max_tool_risk_level

        Args:
            tool_name: Name of the tool being called.
            arguments: Arguments passed to the tool.
            policy: The active PolicySpec.

        Returns:
            GuardDecision with action and reason.
        """
        # 1. Unknown tool check
        try:
            fake_tool = get_tool(tool_name)
        except ToolNotFoundError:
            return GuardDecision(
                action=GuardAction.deny,
                reason=f"Unknown tool '{tool_name}' is not registered in the tool registry.",
                check_type="firewall_unknown_tool",
            )

        # 2. Allowed tools list
        if policy.allowed_tools is not None and tool_name not in policy.allowed_tools:
            return GuardDecision(
                action=GuardAction.deny,
                reason=(
                    f"Tool '{tool_name}' is not in the allowed tools list. "
                    f"Allowed tools: {policy.allowed_tools}"
                ),
                check_type="firewall_allowed_tools",
            )

        # 3. Denied tools list
        if policy.denied_tools is not None and tool_name in policy.denied_tools:
            return GuardDecision(
                action=GuardAction.deny,
                reason=f"Tool '{tool_name}' is explicitly denied by policy.",
                check_type="firewall_denied_tools",
            )

        # 4. Risk level check
        tool_risk = fake_tool.metadata.risk_level
        if _risk_exceeds(tool_risk, policy.max_tool_risk_level):
            return GuardDecision(
                action=GuardAction.deny,
                reason=(
                    f"Tool '{tool_name}' has risk level '{tool_risk.value}' which exceeds "
                    f"the maximum allowed risk level '{policy.max_tool_risk_level.value}'."
                ),
                check_type="firewall_risk_level",
            )

        # All checks passed
        return GuardDecision(
            action=GuardAction.allow,
            reason=f"Tool '{tool_name}' is permitted by policy.",
            check_type="firewall",
        )
