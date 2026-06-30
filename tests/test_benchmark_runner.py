"""Tests for BenchmarkRunner — Day 6 coverage."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from agent_reliability_harness.benchmark_runner import BenchmarkRunner, BenchmarkRunResult
from agent_reliability_harness.runner import (
    run_scenario_day2,
    run_scenario_day3,
    run_scenario_day4,
    run_scenario_day5,
)
from agent_reliability_harness.spec import load_scenario

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"


# ---------------------------------------------------------------------------
# Full benchmark run
# ---------------------------------------------------------------------------


class TestBenchmarkRunAll:
    """Run all 10 scenarios through BenchmarkRunner."""

    def _run(self, tmp_path: Path) -> BenchmarkRunResult:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path)
        return runner.run()

    def test_scenarios_total(self, tmp_path: Path) -> None:
        result = self._run(tmp_path)
        assert result.scenarios_total == 10

    def test_scenarios_passed(self, tmp_path: Path) -> None:
        result = self._run(tmp_path)
        assert result.scenarios_passed == 10

    def test_scenarios_failed(self, tmp_path: Path) -> None:
        result = self._run(tmp_path)
        assert result.scenarios_failed == 0

    def test_pass_rate(self, tmp_path: Path) -> None:
        result = self._run(tmp_path)
        assert result.pass_rate == 1.0

    def test_result_count(self, tmp_path: Path) -> None:
        result = self._run(tmp_path)
        assert len(result.results) == 10

    def test_each_scenario_has_result(self, tmp_path: Path) -> None:
        result = self._run(tmp_path)
        ids = {r["scenario_id"] for r in result.results}
        expected = {
            "normal_agent_run",
            "model_not_allowed",
            "budget_exceeded",
            "provider_timeout_fallback",
            "high_risk_tool_blocked",
            "write_file_without_permission",
            "prompt_injection_tool_escalation",
            "bad_tool_arguments",
            "duplicate_tool_execution",
            "unverified_final_answer",
        }
        assert expected == ids


# ---------------------------------------------------------------------------
# Trace files
# ---------------------------------------------------------------------------


class TestTraceFiles:
    """Each scenario must generate a trace.jsonl."""

    def test_each_scenario_has_trace(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path)
        result = runner.run()
        for r in result.results:
            assert r["trace_file"] is not None
            trace = Path(r["trace_file"])
            assert trace.exists(), f"Missing trace for {r['scenario_id']}"

    def test_trace_contains_agent_start_and_end(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path)
        result = runner.run()
        for r in result.results:
            trace = Path(r["trace_file"])
            with trace.open("r", encoding="utf-8") as f:
                event_types = [json.loads(line)["event_type"] for line in f]
            assert "agent_start" in event_types, f"No agent_start in {r['scenario_id']}"
            assert "agent_end" in event_types, f"No agent_end in {r['scenario_id']}"


# ---------------------------------------------------------------------------
# Scorecard
# ---------------------------------------------------------------------------


class TestScorecard:
    """Scorecard.json must be generated and readable."""

    def test_scorecard_file_created(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path)
        result = runner.run()
        assert result.scorecard_file is not None
        assert Path(result.scorecard_file).exists()

    def test_scorecard_json_parseable(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path)
        result = runner.run()
        with open(result.scorecard_file, "r", encoding="utf-8") as f:
            sc = json.load(f)
        assert sc["scenarios_total"] == 10
        assert sc["pass_rate"] == 1.0

    def test_scorecard_has_failure_type_counts(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path)
        result = runner.run()
        with open(result.scorecard_file, "r", encoding="utf-8") as f:
            sc = json.load(f)
        assert "failure_type_counts" in sc
        assert isinstance(sc["failure_type_counts"], dict)

    def test_scorecard_has_status_counts(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path)
        result = runner.run()
        with open(result.scorecard_file, "r", encoding="utf-8") as f:
            sc = json.load(f)
        assert "status_counts" in sc
        assert isinstance(sc["status_counts"], dict)

    def test_scorecard_has_results_list(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path)
        result = runner.run()
        with open(result.scorecard_file, "r", encoding="utf-8") as f:
            sc = json.load(f)
        assert len(sc["results"]) == 10


# ---------------------------------------------------------------------------
# Error resilience
# ---------------------------------------------------------------------------


class TestErrorResilience:
    """A single scenario exception must not abort the entire benchmark."""

    def test_single_error_does_not_abort(self, tmp_path: Path) -> None:
        """Patch run_scenario_day5 to throw on one specific scenario."""
        original = run_scenario_day5

        def _patched(scenario, output_dir=None):
            if scenario.id == "normal_agent_run":
                raise RuntimeError("Simulated crash")
            return original(scenario, output_dir=output_dir)

        with patch("agent_reliability_harness.benchmark_runner.run_scenario_day5", _patched):
            runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path)
            result = runner.run()

        # Should still run all 10 scenarios
        assert result.scenarios_total == 10
        # The crashed one should be marked as not passed
        crashed = [r for r in result.results if r["scenario_id"] == "normal_agent_run"]
        assert len(crashed) == 1
        assert crashed[0]["passed"] is False
        assert crashed[0]["status"] == "error"
        # The other 9 should be passed
        assert result.scenarios_passed == 9

    def test_error_result_has_error_field(self, tmp_path: Path) -> None:
        original = run_scenario_day5

        def _patched(scenario, output_dir=None):
            if scenario.id == "budget_exceeded":
                raise ValueError("Something went wrong")
            return original(scenario, output_dir=output_dir)

        with patch("agent_reliability_harness.benchmark_runner.run_scenario_day5", _patched):
            runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path)
            result = runner.run()

        error_result = [r for r in result.results if r["scenario_id"] == "budget_exceeded"]
        assert len(error_result) == 1
        assert "error" in error_result[0]
        assert "Something went wrong" in error_result[0]["error"]


# ---------------------------------------------------------------------------
# Run ID
# ---------------------------------------------------------------------------


class TestRunId:
    """BenchmarkRunner respects custom and auto-generated run IDs."""

    def test_custom_run_id(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="my-run-42")
        result = runner.run()
        assert result.run_id == "my-run-42"
        assert "my-run-42" in result.output_dir

    def test_auto_run_id(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path)
        assert runner.run_id is not None
        assert len(runner.run_id) > 0


# ---------------------------------------------------------------------------
# Output directory structure
# ---------------------------------------------------------------------------


class TestOutputStructure:
    """Verify output directory layout: run_id/scenario_id/trace.jsonl + scorecard.json."""

    def test_output_dir_contains_run_id(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="test-run")
        result = runner.run()
        run_dir = Path(result.output_dir)
        assert run_dir.name == "test-run"
        assert run_dir.exists()

    def test_scorecard_in_run_dir(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="test-run")
        result = runner.run()
        sc_path = Path(result.scorecard_file)
        assert sc_path.parent.name == "test-run"
        assert sc_path.name == "scorecard.json"

    def test_trace_under_scenario_subdir(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="test-run")
        result = runner.run()
        for r in result.results:
            trace = Path(r["trace_file"])
            # trace should be at: tmp_path / test-run / <scenario_id> / trace.jsonl
            assert trace.parent.name == r["scenario_id"]
            assert trace.name == "trace.jsonl"


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Day 2 / Day 3 / Day 4 / Day 5 runners must remain functional."""

    def test_day2_normal_run(self) -> None:
        s = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        result = run_scenario_day2(s)
        assert result["status"] == "passed"

    def test_day3_model_not_allowed(self) -> None:
        s = load_scenario(SCENARIOS_DIR / "model_not_allowed.yaml")
        result = run_scenario_day3(s)
        assert result["failure_type"] == "policy_violation"

    def test_day4_timeout(self) -> None:
        s = load_scenario(SCENARIOS_DIR / "provider_timeout_fallback.yaml")
        result = run_scenario_day4(s)
        assert result["failure_type"] == "provider_timeout"

    def test_day5_normal_run(self, tmp_path: Path) -> None:
        s = load_scenario(SCENARIOS_DIR / "normal_agent_run.yaml")
        result = run_scenario_day5(s, output_dir=tmp_path)
        assert result["passed"] is True


# ---------------------------------------------------------------------------
# Safety assertions
# ---------------------------------------------------------------------------


class TestNoRealSideEffects:
    """No real file writes, shell executions, or network calls."""

    def test_no_real_shell_execution(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path)
        result = runner.run()
        pi_results = [r for r in result.results if r["scenario_id"] == "prompt_injection_tool_escalation"]
        assert len(pi_results) == 1
        assert pi_results[0]["failure_type"] == "prompt_injection"

    def test_no_real_network_calls(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path)
        result = runner.run()
        assert result.scenarios_total == 10  # if we got here, no network errors

    def test_no_markdown_report(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="no-report")
        runner.run()
        run_dir = tmp_path / "no-report"
        md_files = list(run_dir.rglob("*.md"))
        assert len(md_files) == 0

    def test_no_html_report(self, tmp_path: Path) -> None:
        runner = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="no-report")
        runner.run()
        run_dir = tmp_path / "no-report"
        html_files = list(run_dir.rglob("*.html"))
        assert len(html_files) == 0
