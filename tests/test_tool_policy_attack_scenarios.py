"""End-to-end tests for tool policy bypass attack scenarios."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmark.benchmark_runner import BenchmarkRunner
from benchmark.spec import load_scenarios

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "benchmark/scenarios/tool_policy_attack"


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


class TestToolPolicyAttackScenarios:
    def test_loads_three_yaml_files(self) -> None:
        scenarios = load_scenarios(SCENARIOS_DIR)

        assert [scenario.id for scenario in scenarios] == [
            "ad_20_allowed_tools_bypass_attempt",
            "ad_21_denied_tools_bypass_attempt",
            "ad_22_prompt_ignore_policy_tool_escalation_attempt",
        ]
        assert scenarios[0].policy.allowed_tools == ["read_file"]
        assert scenarios[1].policy.denied_tools == ["send_email"]
        assert scenarios[2].policy.allowed_tools == ["read_file"]

    def test_benchmark_runs_all_three_cases(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="policy-test").run()

        assert result.scenarios_total == 3
        assert result.scenarios_passed == 3
        assert result.pass_rate == 1.0

        by_case = {item["case_id"]: item for item in result.results}
        ad20 = by_case["AD-20"]
        assert ad20["category"] == "tool-policy"
        assert ad20["status"] == "blocked"
        assert ad20["failure_type"] == "tool_blocked"
        assert ad20["blocked_by"] == "tool_firewall"
        assert ad20["tool"] == "execute_shell"
        assert ad20["reason"] == "tool_not_allowed"
        assert ad20["passed"] is True

        ad21 = by_case["AD-21"]
        assert ad21["category"] == "tool-policy"
        assert ad21["status"] == "blocked"
        assert ad21["failure_type"] == "tool_blocked"
        assert ad21["blocked_by"] == "tool_firewall"
        assert ad21["tool"] == "send_email"
        assert ad21["reason"] == "denied_tool"
        assert ad21["passed"] is True

        ad22 = by_case["AD-22"]
        assert ad22["category"] == "tool-policy"
        assert ad22["status"] == "blocked"
        assert ad22["failure_type"] == "prompt_injection"
        assert ad22["blocked_by"] == "tool_firewall"
        assert ad22["tool"] == "execute_shell"
        assert ad22["reason"] == "prompt_injection_tool_escalation"
        assert ad22["passed"] is True

    def test_each_trace_contains_policy_evidence(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="policy-trace-test").run()

        for scenario_result in result.results:
            events = _trace_events(scenario_result)
            event_types = [event["event_type"] for event in events]
            assert "tool_call" in event_types
            assert "firewall_check" in event_types
            assert "firewall_decision" in event_types
            assert "tool_execution_skipped" in event_types
            assert "failure_classified" in event_types
            assert "agent_end" in event_types

            payload = scenario_result["attack_payload"]
            serialized = "\n".join(json.dumps(event, ensure_ascii=False) for event in events)
            assert payload in serialized
            assert "tool_firewall" in serialized
            assert scenario_result["reason"] in serialized

            decision = next(
                event
                for event in events
                if event["event_type"] == "firewall_decision"
            )
            assert decision["data"]["action"] == "deny"
            assert decision["data"]["blocked_by"] == "tool_firewall"

            classified = next(
                event
                for event in events
                if event["event_type"] == "failure_classified"
            )
            assert classified["data"]["failure_type"] == scenario_result["failure_type"]

    def test_policy_blocked_fake_tool_is_not_executed(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="no-policy-tool-result").run()

        for scenario_result in result.results:
            events = _trace_events(scenario_result)
            successful_tool_results = [
                event
                for event in events
                if event["event_type"] == "tool_result"
                and event["data"].get("success") is True
            ]
            assert successful_tool_results == []
