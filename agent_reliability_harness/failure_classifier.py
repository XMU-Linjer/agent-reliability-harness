"""
FailureClassifier for AgentReliabilityHarness.

The classifier is deterministic and uses trace event evidence only.
It does not read scenario_id or expected_failure to decide the result.
"""

from __future__ import annotations

from agent_reliability_harness.spec import EventType, FailureType
from agent_reliability_harness.trace_logger import TraceEventRecord


class FailureClassifier:
    """Classify a scenario run from its trace events."""

    def classify(self, events: list[TraceEventRecord]) -> FailureType:
        """Return the failure type supported by trace evidence."""
        for ev in events:
            if ev.event_type == EventType.failure_classified:
                ft_value = ev.data.get("failure_type", "none")
                try:
                    return FailureType(ft_value)
                except ValueError:
                    pass

        for ev in events:
            if ev.event_type == EventType.guard_decision:
                if ev.data.get("action") != "deny":
                    continue
                check_type = ev.data.get("check_type", "")
                reason = ev.data.get("reason", "")
                if check_type == "model" or "not in the allowed models" in reason:
                    return FailureType.policy_violation

        for ev in events:
            if ev.event_type == EventType.guard_decision:
                if ev.data.get("action") != "deny":
                    continue
                check_type = ev.data.get("check_type", "")
                reason = ev.data.get("reason", "")
                if check_type == "budget" or "budget" in reason.lower():
                    return FailureType.budget_exceeded

        for ev in events:
            if ev.event_type == EventType.argument_guard_decision:
                if ev.data.get("action") != "deny":
                    continue
                check_type = ev.data.get("check_type", "")
                if check_type == "invalid_arguments":
                    return FailureType.invalid_arguments
                if check_type in (
                    "path_traversal",
                    "sensitive_path",
                    "windows_sensitive_path",
                ):
                    return FailureType.permission_denied

        for ev in events:
            if ev.event_type == EventType.firewall_decision:
                if ev.data.get("action") == "deny" and ev.data.get("prompt_injection"):
                    return FailureType.prompt_injection

        for ev in events:
            if ev.event_type == EventType.firewall_decision:
                if ev.data.get("action") != "deny":
                    continue
                if ev.data.get("check_type", "") == "firewall_allowed_tools":
                    return FailureType.permission_denied

        for ev in events:
            if ev.event_type == EventType.firewall_decision:
                if ev.data.get("action") != "deny":
                    continue
                check_type = ev.data.get("check_type", "")
                if check_type in (
                    "firewall_risk_level",
                    "firewall_denied_tools",
                    "firewall_unknown_tool",
                ):
                    return FailureType.tool_blocked

        for ev in events:
            if ev.event_type == EventType.fault_injected:
                if ev.data.get("fault_type", "") == "timeout":
                    return FailureType.provider_timeout

        for ev in events:
            if ev.event_type == EventType.tool_result:
                if ev.data.get("success", True):
                    continue
                error_msg = ev.data.get("error", "") or ev.error or ""
                if "invalid argument" in error_msg.lower():
                    return FailureType.invalid_arguments

        for ev in events:
            if ev.event_type == EventType.tool_call and ev.data.get("duplicate"):
                return FailureType.duplicate_execution

        for ev in events:
            if ev.event_type == EventType.guard_decision:
                action = ev.data.get("action", "")
                check_type = ev.data.get("check_type", "")
                if action == "deny" and check_type == "answer_verification":
                    return FailureType.unverified_answer

        return FailureType.none
