"""End-to-end tests for data exfiltration attack scenarios."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmark.benchmark_runner import BenchmarkRunner
from benchmark.spec import load_scenarios

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "benchmark/scenarios/data_exfiltration_attack"


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


class TestDataExfiltrationAttackScenarios:
    def test_loads_four_yaml_files(self) -> None:
        scenarios = load_scenarios(SCENARIOS_DIR)

        assert [scenario.id for scenario in scenarios] == [
            "ad_13_email_api_key_exfiltration_attempt",
            "ad_14_email_password_exfiltration_attempt",
            "ad_15_untrusted_email_recipient_attempt",
            "ad_16_url_query_secret_exfiltration_attempt",
        ]

        assert scenarios[0].policy.allowed_tools == ["send_email"]
        assert scenarios[1].policy.allowed_tools == ["send_email"]
        assert scenarios[2].policy.allowed_tools == ["send_email"]
        assert scenarios[3].policy.allowed_tools == ["search_web"]

    def test_benchmark_runs_all_four_cases(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="data-test").run()

        assert result.scenarios_total == 4
        assert result.scenarios_passed == 4
        assert result.pass_rate == 1.0
        assert [item["case_id"] for item in result.results] == [
            "AD-13",
            "AD-14",
            "AD-15",
            "AD-16",
        ]

        for scenario_result in result.results:
            assert scenario_result["category"] == "data-exfiltration"
            assert scenario_result["status"] == "blocked"
            assert scenario_result["failure_type"] == "permission_denied"
            assert scenario_result["blocked_by"] == "argument_guard"
            assert scenario_result["tool"] in ("send_email", "search_web")
            assert scenario_result["attack_payload"]
            assert scenario_result["passed"] is True
            trace_file = scenario_result["trace_file"]
            assert isinstance(trace_file, str)
            assert Path(trace_file).exists()

    def test_each_trace_contains_exfiltration_evidence(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="data-trace-test").run()

        for scenario_result in result.results:
            events = _trace_events(scenario_result)
            event_types = [event["event_type"] for event in events]
            assert "tool_call" in event_types
            assert "firewall_check" in event_types
            assert "firewall_decision" in event_types
            assert "argument_guard_check" in event_types
            assert "argument_guard_decision" in event_types
            assert "tool_execution_skipped" in event_types
            assert "failure_classified" in event_types

            payload = scenario_result["attack_payload"]
            serialized = "\n".join(json.dumps(event, ensure_ascii=False) for event in events)
            assert payload in serialized
            assert "argument_guard" in serialized
            assert scenario_result["reason"] in serialized

            decision = next(
                event
                for event in events
                if event["event_type"] == "argument_guard_decision"
            )
            assert decision["data"]["action"] == "deny"
            assert decision["data"]["blocked_by"] == "argument_guard"

            classified = next(
                event
                for event in events
                if event["event_type"] == "failure_classified"
            )
            assert classified["data"]["failure_type"] == "permission_denied"

    def test_exfiltration_fake_tool_is_not_executed(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="no-data-tool-result").run()

        for scenario_result in result.results:
            events = _trace_events(scenario_result)
            successful_tool_results = [
                event
                for event in events
                if event["event_type"] == "tool_result"
                and event["data"].get("success") is True
            ]
            assert successful_tool_results == []
