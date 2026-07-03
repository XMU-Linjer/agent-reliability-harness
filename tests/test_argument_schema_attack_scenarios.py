"""End-to-end tests for argument schema attack scenarios."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_reliability_harness.benchmark_runner import BenchmarkRunner
from agent_reliability_harness.spec import load_scenarios

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "argument_schema_attack_scenarios"


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


class TestArgumentSchemaAttackScenarios:
    def test_loads_four_yaml_files(self) -> None:
        scenarios = load_scenarios(SCENARIOS_DIR)

        assert [scenario.id for scenario in scenarios] == [
            "ad_23_missing_required_field_attempt",
            "ad_24_null_argument_attempt",
            "ad_25_arguments_not_object_attempt",
            "ad_26_oversized_argument_attempt",
        ]
        assert all(scenario.policy.allowed_tools == ["read_file"] for scenario in scenarios)

    def test_benchmark_runs_all_four_cases(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(
            SCENARIOS_DIR,
            tmp_path,
            run_id="argument-schema-test",
        ).run()

        assert result.scenarios_total == 4
        assert result.scenarios_passed == 4
        assert result.pass_rate == 1.0

        expected_reasons = {
            "AD-23": "missing_required_field",
            "AD-24": "null_argument",
            "AD-25": "arguments_not_object",
            "AD-26": "argument_too_long",
        }
        for scenario_result in result.results:
            case_id = str(scenario_result["case_id"])
            assert scenario_result["category"] == "argument-schema"
            assert scenario_result["status"] == "blocked"
            assert scenario_result["failure_type"] == "invalid_arguments"
            assert scenario_result["blocked_by"] == "argument_guard"
            assert scenario_result["tool"] == "read_file"
            assert scenario_result["reason"] == expected_reasons[case_id]
            assert scenario_result["passed"] is True

        by_case = {item["case_id"]: item for item in result.results}
        assert by_case["AD-23"]["attack_payload"] == "{}"
        assert by_case["AD-24"]["attack_payload"] == '{"path": null}'
        assert by_case["AD-25"]["attack_payload"] == '"../../../../etc/passwd"'
        assert by_case["AD-26"]["attack_payload"] == "A repeated 100000 times"
        assert by_case["AD-26"]["payload_length"] == 100000
        assert by_case["AD-26"]["payload_preview"] == "AAAAAAAAAA..."

    def test_each_trace_contains_schema_evidence(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(
            SCENARIOS_DIR,
            tmp_path,
            run_id="argument-schema-trace-test",
        ).run()

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
            assert "agent_end" in event_types

            decision = next(
                event
                for event in events
                if event["event_type"] == "argument_guard_decision"
            )
            assert decision["data"]["action"] == "deny"
            assert decision["data"]["reason"] == scenario_result["reason"]

            classified = next(
                event
                for event in events
                if event["event_type"] == "failure_classified"
            )
            assert classified["data"]["failure_type"] == "invalid_arguments"

    def test_arguments_not_object_is_not_classified_as_path_traversal(
        self,
        tmp_path: Path,
    ) -> None:
        result = BenchmarkRunner(
            SCENARIOS_DIR,
            tmp_path,
            run_id="argument-schema-priority-test",
        ).run()
        ad25 = next(item for item in result.results if item["case_id"] == "AD-25")

        assert ad25["reason"] == "arguments_not_object"
        assert ad25["reason"] != "path_traversal"

    def test_oversized_payload_is_not_written_in_full(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(
            SCENARIOS_DIR,
            tmp_path,
            run_id="argument-schema-oversized-test",
        ).run()
        ad26 = next(item for item in result.results if item["case_id"] == "AD-26")
        events = _trace_events(ad26)
        serialized = "\n".join(json.dumps(event, ensure_ascii=False) for event in events)

        assert "A repeated 100000 times" in serialized
        assert "payload_length" in serialized
        assert "100000" in serialized
        assert "A" * 100000 not in serialized

    def test_malformed_fake_tool_is_not_executed(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(
            SCENARIOS_DIR,
            tmp_path,
            run_id="argument-schema-no-tool-result",
        ).run()

        for scenario_result in result.results:
            events = _trace_events(scenario_result)
            successful_tool_results = [
                event
                for event in events
                if event["event_type"] == "tool_result"
                and event["data"].get("success") is True
            ]
            assert successful_tool_results == []
