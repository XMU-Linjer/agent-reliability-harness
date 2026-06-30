"""Tests for agent_reliability_harness.spec — Day 1 coverage."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_reliability_harness.spec import (
    AgentRunSpec,
    EventType,
    FailureType,
    GuardAction,
    PolicySpec,
    ScenarioSpec,
    ToolRiskLevel,
    load_scenario,
    load_scenarios,
)

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"


# ---------------------------------------------------------------------------
# Import smoke tests
# ---------------------------------------------------------------------------


class TestImports:
    """Verify that all public types can be imported."""

    def test_import_scenario_spec(self) -> None:
        assert ScenarioSpec is not None

    def test_import_agent_run_spec(self) -> None:
        assert AgentRunSpec is not None

    def test_import_policy_spec(self) -> None:
        assert PolicySpec is not None

    def test_import_failure_type(self) -> None:
        assert FailureType.none == "none"

    def test_import_event_type(self) -> None:
        assert EventType.agent_start == "agent_start"

    def test_import_tool_risk_level(self) -> None:
        assert ToolRiskLevel.safe == "safe"

    def test_import_guard_action(self) -> None:
        assert GuardAction.allow == "allow"


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


class TestLoadScenario:
    """Test loading individual YAML scenario files."""

    def test_load_normal_agent_run(self) -> None:
        s = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        assert s.id == "normal_agent_run"
        assert s.expected_failure == FailureType.none
        assert s.agent_run.model == "gpt-4o"
        assert s.agent_run.provider == "mock"
        assert "read_file" in s.agent_run.tools

    def test_load_model_not_allowed(self) -> None:
        s = load_scenario(SCENARIOS_DIR / "model_not_allowed.yaml")
        assert s.id == "model_not_allowed"
        assert s.expected_failure == FailureType.policy_violation

    def test_load_high_risk_tool_blocked(self) -> None:
        s = load_scenario(SCENARIOS_DIR / "high_risk_tool_blocked.yaml")
        assert s.id == "high_risk_tool_blocked"
        assert s.expected_failure == FailureType.tool_blocked

    def test_load_all_three_scenarios(self) -> None:
        for name in (
            "normal_agent_run.yaml",
            "model_not_allowed.yaml",
            "high_risk_tool_blocked.yaml",
        ):
            s = load_scenario(SCENARIOS_DIR / name)
            assert isinstance(s, ScenarioSpec)


class TestLoadScenarios:
    """Test batch loading from directory."""

    def test_load_scenarios_returns_all(self) -> None:
        scenarios = load_scenarios(SCENARIOS_DIR)
        assert len(scenarios) == 5

    def test_load_scenarios_deterministic_order(self) -> None:
        """load_scenarios sorts by filename, so order must be stable."""
        scenarios = load_scenarios(SCENARIOS_DIR)
        ids = [s.id for s in scenarios]
        # Filenames sorted alphabetically:
        #   budget_exceeded.yaml
        #   high_risk_tool_blocked.yaml
        #   model_not_allowed.yaml
        #   normal_agent_run.yaml
        #   write_file_without_permission.yaml
        assert ids == [
            "budget_exceeded",
            "high_risk_tool_blocked",
            "model_not_allowed",
            "normal_agent_run",
            "write_file_without_permission",
        ]

    def test_load_scenarios_nonexistent_dir(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_scenarios("/nonexistent/path")


# ---------------------------------------------------------------------------
# FailureType & EventType parsing
# ---------------------------------------------------------------------------


class TestEnumParsing:
    """Verify that YAML string values map to correct enum members."""

    def test_expected_failure_parsed_as_failure_type(self) -> None:
        s = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        assert isinstance(s.expected_failure, FailureType)
        assert s.expected_failure is FailureType.none

    def test_expected_events_parsed_as_event_type(self) -> None:
        s = load_scenario(SCENARIOS_DIR / "high_risk_tool_blocked.yaml")
        assert all(isinstance(e, EventType) for e in s.expected_events)
        assert EventType.firewall_check in s.expected_events
        assert EventType.firewall_decision in s.expected_events

    def test_tool_risk_level_parsed(self) -> None:
        s = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        assert s.policy.max_tool_risk_level is ToolRiskLevel.low

    def test_all_failure_types_are_snake_case(self) -> None:
        for member in FailureType:
            assert member.value == member.value.lower()
            assert " " not in member.value


# ---------------------------------------------------------------------------
# Validation rules
# ---------------------------------------------------------------------------


class TestValidation:
    """Test Pydantic validation rules on spec models."""

    def _minimal_policy(self, **overrides: object) -> dict:
        base = {
            "allowed_models": ["gpt-4o"],
            "max_token_budget": 1000,
            "max_tool_risk_level": "low",
        }
        base.update(overrides)
        return base

    def _minimal_agent_run(self, **overrides: object) -> dict:
        base = {
            "model": "gpt-4o",
            "tools": ["read_file"],
            "max_steps": 3,
            "task": "test task",
        }
        base.update(overrides)
        return base

    def test_max_steps_zero_fails(self) -> None:
        with pytest.raises(ValidationError, match="max_steps must be > 0"):
            AgentRunSpec(**self._minimal_agent_run(max_steps=0))

    def test_max_steps_negative_fails(self) -> None:
        with pytest.raises(ValidationError, match="max_steps must be > 0"):
            AgentRunSpec(**self._minimal_agent_run(max_steps=-1))

    def test_max_steps_positive_passes(self) -> None:
        spec = AgentRunSpec(**self._minimal_agent_run(max_steps=1))
        assert spec.max_steps == 1

    def test_max_token_budget_zero_fails(self) -> None:
        with pytest.raises(ValidationError, match="max_token_budget must be > 0"):
            PolicySpec(**self._minimal_policy(max_token_budget=0))

    def test_max_token_budget_negative_fails(self) -> None:
        with pytest.raises(ValidationError, match="max_token_budget must be > 0"):
            PolicySpec(**self._minimal_policy(max_token_budget=-100))

    def test_max_token_budget_positive_passes(self) -> None:
        spec = PolicySpec(**self._minimal_policy(max_token_budget=1))
        assert spec.max_token_budget == 1

    def test_allowed_models_empty_fails(self) -> None:
        with pytest.raises(ValidationError, match="allowed_models must not be empty"):
            PolicySpec(**self._minimal_policy(allowed_models=[]))

    def test_allowed_tools_and_denied_tools_both_set_fails(self) -> None:
        with pytest.raises(
            ValidationError, match="allowed_tools and denied_tools must not be configured simultaneously"
        ):
            PolicySpec(
                **self._minimal_policy(
                    allowed_tools=["read_file"],
                    denied_tools=["write_file"],
                )
            )

    def test_allowed_tools_only_passes(self) -> None:
        spec = PolicySpec(**self._minimal_policy(allowed_tools=["read_file"]))
        assert spec.allowed_tools == ["read_file"]
        assert spec.denied_tools is None

    def test_denied_tools_only_passes(self) -> None:
        spec = PolicySpec(**self._minimal_policy(denied_tools=["execute_shell"]))
        assert spec.denied_tools == ["execute_shell"]
        assert spec.allowed_tools is None


# ---------------------------------------------------------------------------
# MockResponse / MockToolCall
# ---------------------------------------------------------------------------


class TestMockModels:
    """Test MockResponse and MockToolCall defaults."""

    def test_mock_response_defaults(self) -> None:
        s = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        # Second response has finish_reason=stop
        last = s.agent_run.mock_responses[-1]
        assert last.finish_reason == "stop"
        assert last.tool_calls == []
        assert last.total_tokens == 80

    def test_mock_tool_call_in_response(self) -> None:
        s = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        first = s.agent_run.mock_responses[0]
        assert len(first.tool_calls) == 1
        assert first.tool_calls[0].tool == "read_file"
        assert first.tool_calls[0].arguments == {"path": "config.yaml"}
