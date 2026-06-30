"""Tests for FailureClassifier — Day 5 coverage."""

from __future__ import annotations

from agent_reliability_harness.failure_classifier import FailureClassifier
from agent_reliability_harness.spec import EventType, FailureType
from agent_reliability_harness.trace_logger import TraceEventRecord


def _evt(
    event_type: EventType,
    data: dict | None = None,
    error: str | None = None,
    step: int = 0,
    scenario_id: str = "test_scenario",
) -> TraceEventRecord:
    """Helper to build a minimal TraceEventRecord."""
    return TraceEventRecord(
        run_id="test",
        scenario_id=scenario_id,
        step=step,
        event_type=event_type,
        module="test",
        data=data or {},
        error=error,
    )


class TestFailureClassifierNone:
    """No failure evidence → FailureType.none."""

    def test_empty_events(self) -> None:
        c = FailureClassifier()
        assert c.classify([]) == FailureType.none

    def test_only_start_and_end(self) -> None:
        events = [
            _evt(EventType.agent_start),
            _evt(EventType.agent_end),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.none

    def test_normal_run_events(self) -> None:
        events = [
            _evt(EventType.agent_start),
            _evt(EventType.llm_request),
            _evt(EventType.llm_response),
            _evt(EventType.guard_decision, {"action": "allow", "check_type": "model", "reason": "ok"}),
            _evt(EventType.guard_decision, {"action": "allow", "check_type": "budget", "reason": "ok"}),
            _evt(EventType.agent_end),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.none

    def test_scenario_id_does_not_drive_classification(self) -> None:
        events = [
            _evt(EventType.agent_start, scenario_id="model_not_allowed"),
            _evt(EventType.agent_end, scenario_id="model_not_allowed"),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.none


class TestFailureClassifierPolicyViolation:
    """guard_decision deny with model evidence → policy_violation."""

    def test_model_denied(self) -> None:
        events = [
            _evt(EventType.agent_start),
            _evt(EventType.guard_decision, {
                "action": "deny",
                "check_type": "model",
                "reason": "Model 'gpt-5' is not in the allowed models list.",
            }),
            _evt(EventType.agent_end),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.policy_violation


class TestFailureClassifierBudgetExceeded:
    """guard_decision deny with budget evidence → budget_exceeded."""

    def test_budget_denied(self) -> None:
        events = [
            _evt(EventType.agent_start),
            _evt(EventType.guard_decision, {
                "action": "allow",
                "check_type": "model",
                "reason": "ok",
            }),
            _evt(EventType.guard_decision, {
                "action": "deny",
                "check_type": "budget",
                "reason": "Token budget exceeded: used 20000 tokens, budget is 10000.",
            }),
            _evt(EventType.agent_end),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.budget_exceeded


class TestFailureClassifierProviderTimeout:
    """fault_injected timeout → provider_timeout."""

    def test_timeout_injected(self) -> None:
        events = [
            _evt(EventType.agent_start),
            _evt(EventType.fault_injected, {
                "fault_type": "timeout",
                "applied": True,
            }),
            _evt(EventType.agent_end),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.provider_timeout


class TestFailureClassifierToolBlocked:
    """firewall_decision deny with risk_level → tool_blocked."""

    def test_risk_level_blocked(self) -> None:
        events = [
            _evt(EventType.agent_start),
            _evt(EventType.firewall_decision, {
                "action": "deny",
                "check_type": "firewall_risk_level",
                "reason": "Tool risk too high.",
            }),
            _evt(EventType.agent_end),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.tool_blocked

    def test_denied_tools_list(self) -> None:
        events = [
            _evt(EventType.agent_start),
            _evt(EventType.firewall_decision, {
                "action": "deny",
                "check_type": "firewall_denied_tools",
                "reason": "Tool is denied.",
            }),
            _evt(EventType.agent_end),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.tool_blocked


class TestFailureClassifierPermissionDenied:
    """firewall_decision deny with allowed_tools → permission_denied."""

    def test_not_in_allowed_tools(self) -> None:
        events = [
            _evt(EventType.agent_start),
            _evt(EventType.firewall_decision, {
                "action": "deny",
                "check_type": "firewall_allowed_tools",
                "reason": "Tool not in allowed list.",
            }),
            _evt(EventType.agent_end),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.permission_denied


class TestFailureClassifierPromptInjection:
    """firewall_decision deny with prompt_injection flag → prompt_injection."""

    def test_prompt_injection_flag(self) -> None:
        events = [
            _evt(EventType.agent_start),
            _evt(EventType.firewall_decision, {
                "action": "deny",
                "check_type": "firewall_risk_level",
                "reason": "Tool risk too high.",
                "prompt_injection": True,
            }),
            _evt(EventType.agent_end),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.prompt_injection


class TestFailureClassifierInvalidArguments:
    """tool_result with success=false and invalid argument error → invalid_arguments."""

    def test_invalid_arguments_from_tool_result(self) -> None:
        events = [
            _evt(EventType.agent_start),
            _evt(EventType.tool_result, {
                "tool": "read_file",
                "success": False,
                "error": "Invalid arguments: 'path' must be a non-empty string, got None",
            }),
            _evt(EventType.agent_end),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.invalid_arguments


class TestFailureClassifierDuplicateExecution:
    """tool_call with duplicate=True → duplicate_execution."""

    def test_duplicate_tool_call(self) -> None:
        events = [
            _evt(EventType.agent_start),
            _evt(EventType.tool_call, {
                "tool": "read_file",
                "arguments": {"path": "config.yaml"},
                "duplicate": True,
            }),
            _evt(EventType.agent_end),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.duplicate_execution


class TestFailureClassifierUnverifiedAnswer:
    """guard_decision deny with answer_verification → unverified_answer."""

    def test_unverified_answer(self) -> None:
        events = [
            _evt(EventType.agent_start),
            _evt(EventType.guard_decision, {
                "action": "deny",
                "check_type": "answer_verification",
                "reason": "Answer verification required but not done.",
            }),
            _evt(EventType.agent_end),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.unverified_answer


class TestFailureClassifierExplicitEvent:
    """failure_classified event directly determines failure_type."""

    def test_explicit_failure_classified(self) -> None:
        events = [
            _evt(EventType.agent_start),
            _evt(EventType.failure_classified, {
                "failure_type": "budget_exceeded",
            }),
            _evt(EventType.agent_end),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.budget_exceeded

    def test_explicit_none(self) -> None:
        events = [
            _evt(EventType.failure_classified, {"failure_type": "none"}),
        ]
        c = FailureClassifier()
        assert c.classify(events) == FailureType.none
