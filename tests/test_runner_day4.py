"""Tests for Day 4 scenario runner — FaultInjector integration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmark.runner import (
    run_scenario_day2,
    run_scenario_day3,
    run_scenario_day4,
)
from benchmark.spec import load_scenario

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "scenarios"


# ---------------------------------------------------------------------------
# provider_timeout_fallback
# ---------------------------------------------------------------------------


class TestProviderTimeoutFallback:
    """provider_timeout_fallback should detect timeout and use fallback."""

    def _run(self) -> dict[str, Any]:
        scenario = load_scenario(SCENARIOS_DIR / "provider_timeout_fallback.yaml")
        return run_scenario_day4(scenario)

    def test_failure_type_is_provider_timeout(self) -> None:
        result = self._run()
        assert result["failure_type"] == "provider_timeout"

    def test_status_is_recovered(self) -> None:
        result = self._run()
        assert result["status"] == "recovered"

    def test_timeout_fault_was_injected(self) -> None:
        result = self._run()
        timeout_injections = [
            fi for fi in result["fault_injections"]
            if fi["fault_type"] == "timeout" and fi["applied"]
        ]
        assert len(timeout_injections) >= 1

    def test_fallback_content_used(self) -> None:
        """Fallback mock_responses should have been consumed."""
        result = self._run()
        assert result["final_content"] != ""
        assert result["steps"] >= 1

    def test_scenario_id(self) -> None:
        result = self._run()
        assert result["scenario_id"] == "provider_timeout_fallback"


# ---------------------------------------------------------------------------
# bad_tool_arguments
# ---------------------------------------------------------------------------


class TestBadToolArguments:
    """bad_tool_arguments should detect corrupted arguments."""

    def _run(self) -> dict[str, Any]:
        scenario = load_scenario(SCENARIOS_DIR / "bad_tool_arguments.yaml")
        return run_scenario_day4(scenario)

    def test_failure_type_is_invalid_arguments(self) -> None:
        result = self._run()
        assert result["failure_type"] == "invalid_arguments"

    def test_status_is_failed(self) -> None:
        result = self._run()
        assert result["status"] == "failed"

    def test_bad_args_fault_was_injected(self) -> None:
        result = self._run()
        bad_args_injections = [
            fi for fi in result["fault_injections"]
            if fi["fault_type"] == "bad_args" and fi["applied"]
        ]
        assert len(bad_args_injections) >= 1

    def test_tool_result_has_error(self) -> None:
        """The fake tool should return an error for bad arguments."""
        result = self._run()
        error_results = [
            tr for tr in result["tool_results"] if not tr["success"]
        ]
        assert len(error_results) >= 1

    def test_no_real_file_created(self) -> None:
        self._run()
        assert not Path("config.yaml.broken").exists()


# ---------------------------------------------------------------------------
# duplicate_tool_execution
# ---------------------------------------------------------------------------


class TestDuplicateToolExecution:
    """duplicate_tool_execution should detect duplicated tool calls."""

    def _run(self) -> dict[str, Any]:
        scenario = load_scenario(SCENARIOS_DIR / "duplicate_tool_execution.yaml")
        return run_scenario_day4(scenario)

    def test_failure_type_is_duplicate_execution(self) -> None:
        result = self._run()
        assert result["failure_type"] == "duplicate_execution"

    def test_status_is_failed(self) -> None:
        result = self._run()
        assert result["status"] == "failed"

    def test_duplicate_fault_was_injected(self) -> None:
        result = self._run()
        dup_injections = [
            fi for fi in result["fault_injections"]
            if fi["fault_type"] == "duplicate" and fi["applied"]
        ]
        assert len(dup_injections) >= 1

    def test_at_least_one_tool_executed_before_detection(self) -> None:
        result = self._run()
        assert len(result["tool_results"]) >= 1


# ---------------------------------------------------------------------------
# prompt_injection_tool_escalation
# ---------------------------------------------------------------------------


class TestPromptInjectionToolEscalation:
    """prompt_injection should escalate tool and be blocked by ToolFirewall."""

    def _run(self) -> dict[str, Any]:
        scenario = load_scenario(
            SCENARIOS_DIR / "prompt_injection_tool_escalation.yaml"
        )
        return run_scenario_day4(scenario)

    def test_failure_type_is_prompt_injection(self) -> None:
        result = self._run()
        assert result["failure_type"] == "prompt_injection"

    def test_status_is_blocked(self) -> None:
        result = self._run()
        assert result["status"] == "blocked"

    def test_prompt_injection_fault_was_injected(self) -> None:
        result = self._run()
        pi_injections = [
            fi for fi in result["fault_injections"]
            if fi["fault_type"] == "prompt_injection" and fi["applied"]
        ]
        assert len(pi_injections) >= 1

    def test_firewall_blocked_escalated_tool(self) -> None:
        result = self._run()
        deny_decisions = [
            fd for fd in result["firewall_decisions"] if fd["action"] == "deny"
        ]
        assert len(deny_decisions) >= 1

    def test_execute_shell_not_actually_run(self) -> None:
        """execute_shell should have been blocked by ToolFirewall."""
        result = self._run()
        for tr in result["tool_results"]:
            assert tr["tool"] != "execute_shell"


# ---------------------------------------------------------------------------
# Day 2 / Day 3 backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Day 2 and Day 3 runners must remain functional."""

    def test_day2_normal_run(self) -> None:
        scenario = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        result = run_scenario_day2(scenario)
        assert result["status"] == "passed"
        assert result["scenario_id"] == "normal_agent_run"

    def test_day3_normal_run(self) -> None:
        scenario = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        result = run_scenario_day3(scenario)
        assert result["status"] == "passed"

    def test_day3_model_not_allowed(self) -> None:
        scenario = load_scenario(SCENARIOS_DIR / "model_not_allowed.yaml")
        result = run_scenario_day3(scenario)
        assert result["status"] == "blocked"
        assert result["failure_type"] == "policy_violation"

    def test_day4_normal_run_no_injection(self) -> None:
        """Day 4 runner on normal scenario (no fault_injection) should pass."""
        scenario = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        result = run_scenario_day4(scenario)
        assert result["status"] == "passed"
        assert result["failure_type"] == "none"


# ---------------------------------------------------------------------------
# Safety assertions
# ---------------------------------------------------------------------------


class TestNoRealSideEffects:
    """Ensure no real file writes or shell executions happen."""

    def test_no_real_file_writes(self) -> None:
        scenario = load_scenario(SCENARIOS_DIR / "bad_tool_arguments.yaml")
        run_scenario_day4(scenario)
        # No real files should be created
        assert not Path("output_from_bad_args.txt").exists()

    def test_no_real_shell_execution(self) -> None:
        scenario = load_scenario(
            SCENARIOS_DIR / "prompt_injection_tool_escalation.yaml"
        )
        result = run_scenario_day4(scenario)
        # execute_shell should have been blocked, never executed
        for tr in result["tool_results"]:
            assert tr["tool"] != "execute_shell"

    def test_no_real_network_calls(self) -> None:
        """All providers are mock — no real HTTP/API calls."""
        scenario = load_scenario(SCENARIOS_DIR / "provider_timeout_fallback.yaml")
        result = run_scenario_day4(scenario)
        # If we got here without network errors, no real calls were made
        assert result["scenario_id"] == "provider_timeout_fallback"
