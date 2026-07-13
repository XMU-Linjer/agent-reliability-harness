"""End-to-end tests for file write attack scenarios."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmark.benchmark_runner import BenchmarkRunner
from benchmark.spec import load_scenarios

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "benchmark/scenarios/file_write_attack"


def _trace_events(result: dict[str, Any]) -> list[dict[str, Any]]:
    trace_file = result["trace_file"]
    assert isinstance(trace_file, str)
    trace_path = Path(trace_file)
    assert trace_path.exists()
    return [
        json.loads(line)
        for line in trace_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


class TestFileWriteAttackScenarios:
    def test_loads_four_yaml_files(self) -> None:
        scenarios = load_scenarios(SCENARIOS_DIR)

        assert [scenario.id for scenario in scenarios] == [
            "ad_05_windows_system_path_write_attempt",
            "ad_06_linux_system_path_write_attempt",
            "ad_07_script_file_write_attempt",
            "ad_08_path_traversal_write_attempt",
        ]

        for scenario in scenarios:
            assert scenario.policy.allowed_tools == ["write_file"]

    def test_benchmark_runs_all_four_cases(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(
            SCENARIOS_DIR,
            tmp_path,
            run_id="file-write-test",
        ).run()

        assert result.scenarios_total == 4
        assert result.scenarios_passed == 4
        assert result.pass_rate == 1.0

        expected_case_ids = ["AD-05", "AD-06", "AD-07", "AD-08"]
        assert [item["case_id"] for item in result.results] == expected_case_ids

        for scenario_result in result.results:
            assert scenario_result["status"] == "blocked"
            assert scenario_result["failure_type"] == "permission_denied"
            assert scenario_result["blocked_by"] == "argument_guard"
            assert scenario_result["attack_payload"]
            assert scenario_result["tool"] == "write_file"
            trace_file = scenario_result["trace_file"]
            assert isinstance(trace_file, str)
            assert Path(trace_file).exists()

    def test_each_trace_contains_required_security_events(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(
            SCENARIOS_DIR,
            tmp_path,
            run_id="trace-write-test",
        ).run()

        for scenario_result in result.results:
            events = _trace_events(scenario_result)
            event_types = [event["event_type"] for event in events]
            assert "tool_call" in event_types
            assert "argument_guard_check" in event_types
            assert "argument_guard_decision" in event_types
            assert "tool_execution_skipped" in event_types
            assert "failure_classified" in event_types

            decision = next(
                event
                for event in events
                if event["event_type"] == "argument_guard_decision"
            )
            assert decision["data"]["action"] == "deny"
            assert decision["data"]["attack_payload"]

            classified = next(
                event
                for event in events
                if event["event_type"] == "failure_classified"
            )
            assert classified["data"]["failure_type"] == "permission_denied"

    def test_dangerous_fake_tool_is_not_executed(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(
            SCENARIOS_DIR,
            tmp_path,
            run_id="no-write-tool-result-test",
        ).run()

        for scenario_result in result.results:
            events = _trace_events(scenario_result)
            tool_results = [
                event
                for event in events
                if event["event_type"] == "tool_result"
                and event["data"].get("success") is True
            ]
            assert tool_results == []

        assert not (tmp_path / "authorized_keys").exists()
        assert not (tmp_path / "workspace" / "startup.ps1").exists()
