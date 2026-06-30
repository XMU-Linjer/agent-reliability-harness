"""
FailureClassifier for AgentReliabilityHarness.

Rule-based classifier that examines a list of TraceEventRecords
and determines the most appropriate FailureType.

No LLM, no NLP, no external API — purely deterministic.
"""

from __future__ import annotations

from agent_reliability_harness.spec import EventType, FailureType
from agent_reliability_harness.trace_logger import TraceEventRecord


class FailureClassifier:
    """Classify the failure type of a scenario run from its trace events.

    Classification is rule-based and checks events in priority order:

    1. Explicit ``failure_classified`` event → read its ``failure_type``.
    2. ``guard_decision`` deny with model-not-allowed evidence → ``policy_violation``.
    3. ``guard_decision`` deny with budget evidence → ``budget_exceeded``.
    4. ``firewall_decision`` deny with prompt-injection evidence → ``prompt_injection``.
    5. ``firewall_decision`` deny with permission evidence → ``permission_denied``.
    6. ``firewall_decision`` deny with tool-risk evidence → ``tool_blocked``.
    7. ``fault_injected`` timeout → ``provider_timeout``.
    8. ``tool_result`` failure with invalid-argument evidence → ``invalid_arguments``.
    9. Duplicate tool-call evidence → ``duplicate_execution``.
    10. Final-answer verification denied → ``unverified_answer``.
    11. No failure evidence → ``none``.
    """

    def classify(self, events: list[TraceEventRecord]) -> FailureType:
        """Classify the failure type from trace events.

        Args:
            events: Ordered list of TraceEventRecords from a single run.

        Returns:
            The determined FailureType.
        """
        # 1. Explicit failure_classified event
        for ev in events:
            if ev.event_type == EventType.failure_classified:
                ft_value = ev.data.get("failure_type", "none")
                try:
                    return FailureType(ft_value)
                except ValueError:
                    pass

        # 2. guard_decision deny — policy_violation (model not allowed)
        for ev in events:
            if ev.event_type == EventType.guard_decision:
                action = ev.data.get("action", "")
                if action == "deny":
                    check_type = ev.data.get("check_type", "")
                    reason = ev.data.get("reason", "")
                    if check_type == "model" or "not in the allowed models" in reason:
                        return FailureType.policy_violation

        # 3. guard_decision deny — budget_exceeded
        for ev in events:
            if ev.event_type == EventType.guard_decision:
                action = ev.data.get("action", "")
                if action == "deny":
                    check_type = ev.data.get("check_type", "")
                    reason = ev.data.get("reason", "")
                    if check_type == "budget" or "budget" in reason.lower():
                        return FailureType.budget_exceeded

        # 4. firewall_decision deny — prompt_injection
        for ev in events:
            if ev.event_type == EventType.firewall_decision:
                action = ev.data.get("action", "")
                if action == "deny":
                    if ev.data.get("prompt_injection"):
                        return FailureType.prompt_injection

        # 5. firewall_decision deny — permission_denied
        for ev in events:
            if ev.event_type == EventType.firewall_decision:
                action = ev.data.get("action", "")
                if action == "deny":
                    check_type = ev.data.get("check_type", "")
                    if check_type == "firewall_allowed_tools":
                        return FailureType.permission_denied

        # 6. firewall_decision deny — tool_blocked (risk level or denied list)
        for ev in events:
            if ev.event_type == EventType.firewall_decision:
                action = ev.data.get("action", "")
                if action == "deny":
                    check_type = ev.data.get("check_type", "")
                    if check_type in (
                        "firewall_risk_level",
                        "firewall_denied_tools",
                        "firewall_unknown_tool",
                    ):
                        return FailureType.tool_blocked

        # 7. fault_injected timeout
        for ev in events:
            if ev.event_type == EventType.fault_injected:
                fault_type = ev.data.get("fault_type", "")
                if fault_type == "timeout":
                    return FailureType.provider_timeout

        # 8. tool_result with invalid arguments
        for ev in events:
            if ev.event_type == EventType.tool_result:
                if not ev.data.get("success", True):
                    error_msg = ev.data.get("error", "") or ev.error or ""
                    if "invalid argument" in error_msg.lower():
                        return FailureType.invalid_arguments

        # 9. Duplicate tool-call evidence
        for ev in events:
            if ev.event_type == EventType.tool_call:
                if ev.data.get("duplicate"):
                    return FailureType.duplicate_execution

        # 10. Unverified final answer
        for ev in events:
            if ev.event_type == EventType.guard_decision:
                action = ev.data.get("action", "")
                check_type = ev.data.get("check_type", "")
                if action == "deny" and check_type == "answer_verification":
                    return FailureType.unverified_answer

        # 11. No failure evidence
        return FailureType.none
