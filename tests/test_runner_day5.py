"""Tests for Day 5 scenario runner — TraceLogger + FailureClassifier integration."""

from __future__ import annotations

import json
from pathlib import Path

from agent_reliability_harness.runner import (
    run_scenario_day2,
    run_scenario_day3,
    run_scenario_day4,
    run_scenario_day5,
)
from agent_reliability_harness.spec import load_scenario

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(name: str, tmp_path: Path) -> dict:
    scenario = load_scenario(SCENARIOS_DIR / name)
    return run_scenario_day5(scenario, output_dir=tmp_path)


def _assert_trace_basics(result: dict, tmp_path: Path) -> None:
    """Every scenario must produce a trace file with agent_start + agent_end."""
    assert result["trace_file"] is not None
    trace_path = Path(result["trace_file"])
    assert trace_path.exists()
    with trace_path.open("r", encoding="utf-8") as f:
        lines = f.readlines()
    assert len(lines) >= 2
    events = [json.loads(line) for line in lines]
    event_types = [e["event_type"] for e in events]
    assert "agent_start" in event_types
    assert "agent_end" in event_types


# ---------------------------------------------------------------------------
# normal_agent_run
# ---------------------------------------------------------------------------


class TestNormalAgentRun:
    """normal_agent_run: passed=True, failure_type=none."""

    def test_passed(self, tmp_path: Path) -> None:
        result = _run("normal_agent_run.yaml", tmp_path)
        assert result["passed"] is True

    def test_failure_type_none(self, tmp_path: Path) -> None:
        result = _run("normal_agent_run.yaml", tmp_path)
        assert result["failure_type"] == "none"

    def test_expected_failure(self, tmp_path: Path) -> None:
        result = _run("normal_agent_run.yaml", tmp_path)
        assert result["expected_failure"] == "none"

    def test_trace_file_created(self, tmp_path: Path) -> None:
        result = _run("normal_agent_run.yaml", tmp_path)
        _assert_trace_basics(result, tmp_path)

    def test_events_count_positive(self, tmp_path: Path) -> None:
        result = _run("normal_agent_run.yaml", tmp_path)
        assert result["events_count"] > 0


# ---------------------------------------------------------------------------
# model_not_allowed
# ---------------------------------------------------------------------------


class TestModelNotAllowed:
    """model_not_allowed: passed=True, failure_type=policy_violation."""

    def test_passed(self, tmp_path: Path) -> None:
        result = _run("model_not_allowed.yaml", tmp_path)
        assert result["passed"] is True

    def test_failure_type(self, tmp_path: Path) -> None:
        result = _run("model_not_allowed.yaml", tmp_path)
        assert result["failure_type"] == "policy_violation"

    def test_trace_file_created(self, tmp_path: Path) -> None:
        result = _run("model_not_allowed.yaml", tmp_path)
        _assert_trace_basics(result, tmp_path)


# ---------------------------------------------------------------------------
# budget_exceeded
# ---------------------------------------------------------------------------


class TestBudgetExceeded:
    """budget_exceeded: passed=True, failure_type=budget_exceeded."""

    def test_passed(self, tmp_path: Path) -> None:
        result = _run("budget_exceeded.yaml", tmp_path)
        assert result["passed"] is True

    def test_failure_type(self, tmp_path: Path) -> None:
        result = _run("budget_exceeded.yaml", tmp_path)
        assert result["failure_type"] == "budget_exceeded"

    def test_trace_file_created(self, tmp_path: Path) -> None:
        result = _run("budget_exceeded.yaml", tmp_path)
        _assert_trace_basics(result, tmp_path)


# ---------------------------------------------------------------------------
# provider_timeout_fallback
# ---------------------------------------------------------------------------


class TestProviderTimeoutFallback:
    """provider_timeout_fallback: passed=True, failure_type=provider_timeout."""

    def test_passed(self, tmp_path: Path) -> None:
        result = _run("provider_timeout_fallback.yaml", tmp_path)
        assert result["passed"] is True

    def test_failure_type(self, tmp_path: Path) -> None:
        result = _run("provider_timeout_fallback.yaml", tmp_path)
        assert result["failure_type"] == "provider_timeout"

    def test_status_recovered(self, tmp_path: Path) -> None:
        result = _run("provider_timeout_fallback.yaml", tmp_path)
        assert result["status"] == "recovered"

    def test_trace_file_created(self, tmp_path: Path) -> None:
        result = _run("provider_timeout_fallback.yaml", tmp_path)
        _assert_trace_basics(result, tmp_path)


# ---------------------------------------------------------------------------
# high_risk_tool_blocked
# ---------------------------------------------------------------------------


class TestHighRiskToolBlocked:
    """high_risk_tool_blocked: passed=True, failure_type=tool_blocked."""

    def test_passed(self, tmp_path: Path) -> None:
        result = _run("high_risk_tool_blocked.yaml", tmp_path)
        assert result["passed"] is True

    def test_failure_type(self, tmp_path: Path) -> None:
        result = _run("high_risk_tool_blocked.yaml", tmp_path)
        assert result["failure_type"] == "tool_blocked"

    def test_trace_file_created(self, tmp_path: Path) -> None:
        result = _run("high_risk_tool_blocked.yaml", tmp_path)
        _assert_trace_basics(result, tmp_path)


# ---------------------------------------------------------------------------
# write_file_without_permission
# ---------------------------------------------------------------------------


class TestWriteFileWithoutPermission:
    """write_file_without_permission: passed=True, failure_type=permission_denied."""

    def test_passed(self, tmp_path: Path) -> None:
        result = _run("write_file_without_permission.yaml", tmp_path)
        assert result["passed"] is True

    def test_failure_type(self, tmp_path: Path) -> None:
        result = _run("write_file_without_permission.yaml", tmp_path)
        assert result["failure_type"] == "permission_denied"

    def test_trace_file_created(self, tmp_path: Path) -> None:
        result = _run("write_file_without_permission.yaml", tmp_path)
        _assert_trace_basics(result, tmp_path)


# ---------------------------------------------------------------------------
# prompt_injection_tool_escalation
# ---------------------------------------------------------------------------


class TestPromptInjectionToolEscalation:
    """prompt_injection_tool_escalation: passed=True, failure_type=prompt_injection."""

    def test_passed(self, tmp_path: Path) -> None:
        result = _run("prompt_injection_tool_escalation.yaml", tmp_path)
        assert result["passed"] is True

    def test_failure_type(self, tmp_path: Path) -> None:
        result = _run("prompt_injection_tool_escalation.yaml", tmp_path)
        assert result["failure_type"] == "prompt_injection"

    def test_trace_file_created(self, tmp_path: Path) -> None:
        result = _run("prompt_injection_tool_escalation.yaml", tmp_path)
        _assert_trace_basics(result, tmp_path)


# ---------------------------------------------------------------------------
# bad_tool_arguments
# ---------------------------------------------------------------------------


class TestBadToolArguments:
    """bad_tool_arguments: passed=True, failure_type=invalid_arguments."""

    def test_passed(self, tmp_path: Path) -> None:
        result = _run("bad_tool_arguments.yaml", tmp_path)
        assert result["passed"] is True

    def test_failure_type(self, tmp_path: Path) -> None:
        result = _run("bad_tool_arguments.yaml", tmp_path)
        assert result["failure_type"] == "invalid_arguments"

    def test_trace_file_created(self, tmp_path: Path) -> None:
        result = _run("bad_tool_arguments.yaml", tmp_path)
        _assert_trace_basics(result, tmp_path)


# ---------------------------------------------------------------------------
# duplicate_tool_execution
# ---------------------------------------------------------------------------


class TestDuplicateToolExecution:
    """duplicate_tool_execution: passed=True, failure_type=duplicate_execution."""

    def test_passed(self, tmp_path: Path) -> None:
        result = _run("duplicate_tool_execution.yaml", tmp_path)
        assert result["passed"] is True

    def test_failure_type(self, tmp_path: Path) -> None:
        result = _run("duplicate_tool_execution.yaml", tmp_path)
        assert result["failure_type"] == "duplicate_execution"

    def test_trace_file_created(self, tmp_path: Path) -> None:
        result = _run("duplicate_tool_execution.yaml", tmp_path)
        _assert_trace_basics(result, tmp_path)


# ---------------------------------------------------------------------------
# unverified_final_answer
# ---------------------------------------------------------------------------


class TestUnverifiedFinalAnswer:
    """unverified_final_answer: passed=True, failure_type=unverified_answer."""

    def test_passed(self, tmp_path: Path) -> None:
        result = _run("unverified_final_answer.yaml", tmp_path)
        assert result["passed"] is True

    def test_failure_type(self, tmp_path: Path) -> None:
        result = _run("unverified_final_answer.yaml", tmp_path)
        assert result["failure_type"] == "unverified_answer"

    def test_trace_file_created(self, tmp_path: Path) -> None:
        result = _run("unverified_final_answer.yaml", tmp_path)
        _assert_trace_basics(result, tmp_path)


# ---------------------------------------------------------------------------
# Trace content validation
# ---------------------------------------------------------------------------


class TestTraceContent:
    """Validate trace JSONL content across scenarios."""

    def test_all_lines_parseable(self, tmp_path: Path) -> None:
        """Every line in every scenario trace must be valid JSON."""
        scenario_files = [
            "normal_agent_run.yaml",
            "model_not_allowed.yaml",
            "budget_exceeded.yaml",
            "provider_timeout_fallback.yaml",
            "high_risk_tool_blocked.yaml",
            "write_file_without_permission.yaml",
            "prompt_injection_tool_escalation.yaml",
            "bad_tool_arguments.yaml",
            "duplicate_tool_execution.yaml",
            "unverified_final_answer.yaml",
        ]
        for sf in scenario_files:
            result = _run(sf, tmp_path)
            trace_path = Path(result["trace_file"])
            with trace_path.open("r", encoding="utf-8") as f:
                for line in f:
                    parsed = json.loads(line)
                    assert "event_type" in parsed

    def test_normal_run_has_llm_events(self, tmp_path: Path) -> None:
        result = _run("normal_agent_run.yaml", tmp_path)
        trace_path = Path(result["trace_file"])
        with trace_path.open("r", encoding="utf-8") as f:
            event_types = [json.loads(line)["event_type"] for line in f]
        assert "llm_request" in event_types
        assert "llm_response" in event_types


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Day 2 / Day 3 / Day 4 runners must remain functional."""

    def test_day2_normal_run(self) -> None:
        scenario = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        result = run_scenario_day2(scenario)
        assert result["status"] == "passed"

    def test_day3_normal_run(self) -> None:
        scenario = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        result = run_scenario_day3(scenario)
        assert result["status"] == "passed"

    def test_day3_model_not_allowed(self) -> None:
        scenario = load_scenario(SCENARIOS_DIR / "model_not_allowed.yaml")
        result = run_scenario_day3(scenario)
        assert result["failure_type"] == "policy_violation"

    def test_day4_normal_run(self) -> None:
        scenario = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        result = run_scenario_day4(scenario)
        assert result["status"] == "passed"
        assert result["failure_type"] == "none"

    def test_day4_timeout(self) -> None:
        scenario = load_scenario(SCENARIOS_DIR / "provider_timeout_fallback.yaml")
        result = run_scenario_day4(scenario)
        assert result["failure_type"] == "provider_timeout"


# ---------------------------------------------------------------------------
# Safety assertions
# ---------------------------------------------------------------------------


class TestNoRealSideEffects:
    """No real file writes or shell executions."""

    def test_no_real_file_writes(self, tmp_path: Path) -> None:
        _run("bad_tool_arguments.yaml", tmp_path)
        assert not Path("config.yaml.broken").exists()

    def test_no_real_shell_execution(self, tmp_path: Path) -> None:
        result = _run("prompt_injection_tool_escalation.yaml", tmp_path)
        # execute_shell should have been blocked
        assert result["failure_type"] == "prompt_injection"

    def test_trace_only_in_output_dir(self, tmp_path: Path) -> None:
        """Trace files should only appear under the specified output_dir."""
        result = _run("normal_agent_run.yaml", tmp_path)
        trace_path = Path(result["trace_file"])
        assert str(trace_path).startswith(str(tmp_path))
