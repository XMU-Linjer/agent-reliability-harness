"""Tests for Day 3 scenario runner — RuntimeGuard + ToolFirewall integration."""

from __future__ import annotations

from pathlib import Path

from agent_reliability_harness.runner import run_scenario_day2, run_scenario_day3
from agent_reliability_harness.spec import load_scenario

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"


# ---------------------------------------------------------------------------
# normal_agent_run — should pass through all guards
# ---------------------------------------------------------------------------


class TestNormalAgentRunDay3:
    """normal_agent_run should complete successfully with Day 3 runner."""

    def _run(self) -> dict:
        scenario = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        return run_scenario_day3(scenario)

    def test_status_is_passed(self) -> None:
        result = self._run()
        assert result["status"] == "passed"

    def test_failure_type_is_none(self) -> None:
        result = self._run()
        assert result["failure_type"] == "none"

    def test_has_guard_decisions_all_allow(self) -> None:
        result = self._run()
        assert len(result["guard_decisions"]) >= 1
        for gd in result["guard_decisions"]:
            assert gd["action"] == "allow"

    def test_has_tool_results(self) -> None:
        result = self._run()
        assert len(result["tool_results"]) >= 1

    def test_scenario_id(self) -> None:
        result = self._run()
        assert result["scenario_id"] == "normal_agent_run"


# ---------------------------------------------------------------------------
# model_not_allowed — RuntimeGuard blocks before any LLM call
# ---------------------------------------------------------------------------


class TestModelNotAllowedDay3:
    """model_not_allowed should be blocked by RuntimeGuard.check_model."""

    def _run(self) -> dict:
        scenario = load_scenario(SCENARIOS_DIR / "model_not_allowed.yaml")
        return run_scenario_day3(scenario)

    def test_status_is_blocked(self) -> None:
        result = self._run()
        assert result["status"] == "blocked"

    def test_failure_type_is_policy_violation(self) -> None:
        result = self._run()
        assert result["failure_type"] == "policy_violation"

    def test_guard_decision_is_deny(self) -> None:
        result = self._run()
        deny_decisions = [
            gd for gd in result["guard_decisions"] if gd["action"] == "deny"
        ]
        assert len(deny_decisions) >= 1

    def test_no_tool_results(self) -> None:
        """Model blocked at pre-flight — no tools should have executed."""
        result = self._run()
        assert result["tool_results"] == []

    def test_zero_steps(self) -> None:
        result = self._run()
        assert result["steps"] == 0


# ---------------------------------------------------------------------------
# budget_exceeded — RuntimeGuard blocks when tokens exceed budget
# ---------------------------------------------------------------------------


class TestBudgetExceededDay3:
    """budget_exceeded should be blocked by RuntimeGuard.check_budget."""

    def _run(self) -> dict:
        scenario = load_scenario(SCENARIOS_DIR / "budget_exceeded.yaml")
        return run_scenario_day3(scenario)

    def test_status_is_blocked(self) -> None:
        result = self._run()
        assert result["status"] == "blocked"

    def test_failure_type_is_budget_exceeded(self) -> None:
        result = self._run()
        assert result["failure_type"] == "budget_exceeded"

    def test_guard_has_deny_decision(self) -> None:
        result = self._run()
        deny_decisions = [
            gd for gd in result["guard_decisions"]
            if gd["action"] == "deny" and gd["check_type"] == "budget"
        ]
        assert len(deny_decisions) >= 1

    def test_at_least_one_step_before_block(self) -> None:
        """Budget is checked after each LLM call, so at least 1 step runs."""
        result = self._run()
        assert result["steps"] >= 1


# ---------------------------------------------------------------------------
# high_risk_tool_blocked — ToolFirewall blocks execute_shell
# ---------------------------------------------------------------------------


class TestHighRiskToolBlockedDay3:
    """high_risk_tool_blocked should be blocked by ToolFirewall risk check."""

    def _run(self) -> dict:
        scenario = load_scenario(SCENARIOS_DIR / "high_risk_tool_blocked.yaml")
        return run_scenario_day3(scenario)

    def test_status_is_blocked(self) -> None:
        result = self._run()
        assert result["status"] == "blocked"

    def test_failure_type_is_tool_blocked(self) -> None:
        result = self._run()
        assert result["failure_type"] == "tool_blocked"

    def test_firewall_has_deny_decision(self) -> None:
        result = self._run()
        deny_decisions = [
            fd for fd in result["firewall_decisions"] if fd["action"] == "deny"
        ]
        assert len(deny_decisions) >= 1

    def test_execute_shell_not_actually_run(self) -> None:
        """execute_shell should not appear in tool_results."""
        result = self._run()
        for tr in result["tool_results"]:
            assert tr["tool"] != "execute_shell"


# ---------------------------------------------------------------------------
# write_file_without_permission — ToolFirewall blocks write_file
# ---------------------------------------------------------------------------


class TestWriteFileWithoutPermissionDay3:
    """write_file_without_permission should be blocked by ToolFirewall allowed_tools."""

    def _run(self) -> dict:
        scenario = load_scenario(SCENARIOS_DIR / "write_file_without_permission.yaml")
        return run_scenario_day3(scenario)

    def test_status_is_blocked(self) -> None:
        result = self._run()
        assert result["status"] == "blocked"

    def test_failure_type_is_permission_denied(self) -> None:
        result = self._run()
        assert result["failure_type"] == "permission_denied"

    def test_firewall_has_deny_decision(self) -> None:
        result = self._run()
        deny_decisions = [
            fd for fd in result["firewall_decisions"] if fd["action"] == "deny"
        ]
        assert len(deny_decisions) >= 1

    def test_write_file_not_actually_run(self) -> None:
        """write_file should not appear in tool_results."""
        result = self._run()
        for tr in result["tool_results"]:
            assert tr["tool"] != "write_file"

    def test_read_file_was_executed(self) -> None:
        """read_file IS in allowed_tools, so step 1 should have run it."""
        result = self._run()
        read_results = [tr for tr in result["tool_results"] if tr["tool"] == "read_file"]
        assert len(read_results) >= 1


# ---------------------------------------------------------------------------
# Day 2 backward compatibility
# ---------------------------------------------------------------------------


class TestDay2RunnerStillWorks:
    """run_scenario_day2 must remain functional."""

    def test_day2_normal_run(self) -> None:
        scenario = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        result = run_scenario_day2(scenario)
        assert result["status"] == "passed"
        assert result["scenario_id"] == "normal_agent_run"

    def test_day2_has_no_guard_keys(self) -> None:
        """Day 2 runner should not return guard/firewall keys."""
        scenario = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        result = run_scenario_day2(scenario)
        assert "guard_decisions" not in result
        assert "firewall_decisions" not in result


# ---------------------------------------------------------------------------
# Safety assertions
# ---------------------------------------------------------------------------


class TestNoRealSideEffects:
    """Ensure no real file writes or shell executions happen."""

    def test_no_real_file_created_by_write_scenario(self) -> None:
        scenario = load_scenario(SCENARIOS_DIR / "write_file_without_permission.yaml")
        run_scenario_day3(scenario)
        # output.txt should NOT be created
        assert not Path("output.txt").exists()

    def test_no_real_shell_execution(self) -> None:
        scenario = load_scenario(SCENARIOS_DIR / "high_risk_tool_blocked.yaml")
        result = run_scenario_day3(scenario)
        # execute_shell should have been blocked
        for tr in result["tool_results"]:
            assert tr["tool"] != "execute_shell"
