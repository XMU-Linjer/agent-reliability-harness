"""
ToolFirewall for AgentGuard SDK.

Validates individual tool calls against a PolicySpec before execution:
- Unknown tool rejection
- Allowed/denied tool list enforcement
- Risk level threshold checks

No real execution. No prompt injection detection.
"""

from __future__ import annotations

from typing import Any

from agent_guard.guards.runtime_guard import GuardDecision
from agent_guard.spec import GuardAction, PolicySpec, ToolRiskLevel

# Ordered risk levels for comparison (lower index = lower risk)
_RISK_LEVEL_ORDER: dict[ToolRiskLevel, int] = {
    ToolRiskLevel.safe: 0,
    ToolRiskLevel.low: 1,
    ToolRiskLevel.high: 2,
    ToolRiskLevel.critical: 3,
}

# Default risk levels for built-in tools
DEFAULT_TOOL_RISKS: dict[str, ToolRiskLevel] = {
    "read_file": ToolRiskLevel.safe,
    "search_web": ToolRiskLevel.safe,
    "list_files": ToolRiskLevel.safe,
    "write_file": ToolRiskLevel.high,
    "send_email": ToolRiskLevel.high,
    "execute_shell": ToolRiskLevel.critical,
}


def _risk_exceeds(tool_risk: ToolRiskLevel, max_risk: ToolRiskLevel) -> bool:
    """Return True if tool_risk is strictly greater than max_risk."""
    return _RISK_LEVEL_ORDER[tool_risk] > _RISK_LEVEL_ORDER[max_risk]


class ToolFirewall:
    """Evaluates tool calls against policy constraints.

    Args:
        tool_risks: Optional mapping of tool_name → ToolRiskLevel.
            If not provided, uses DEFAULT_TOOL_RISKS.

    Usage::

        firewall = ToolFirewall()
        decision = firewall.check_tool_call("execute_shell", {"command": "ls"}, policy)
        if decision.action == GuardAction.deny:
            # block the tool call
    """

    def __init__(
        self,
        tool_risks: dict[str, ToolRiskLevel] | None = None,
    ) -> None:
        self._tool_risks = tool_risks or dict(DEFAULT_TOOL_RISKS)

    def register_tool(self, tool_name: str, risk_level: ToolRiskLevel) -> None:
        """Register a custom tool with its risk level.

        Args:
            tool_name: Name of the tool.
            risk_level: Risk level of the tool.
        """
        self._tool_risks[tool_name] = risk_level

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
        tool_risk = self._tool_risks.get(tool_name)
        if tool_risk is None:
            return GuardDecision(
                action=GuardAction.deny,
                reason=f"Unknown tool '{tool_name}' is not registered.",
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