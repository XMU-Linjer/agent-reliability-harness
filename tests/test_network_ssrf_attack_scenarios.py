"""End-to-end tests for network / SSRF attack scenarios."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_reliability_harness.benchmark_runner import BenchmarkRunner
from agent_reliability_harness.spec import load_scenarios

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "network_ssrf_attack_scenarios"


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


class TestNetworkSsrfAttackScenarios:
    def test_loads_three_yaml_files(self) -> None:
        scenarios = load_scenarios(SCENARIOS_DIR)

        assert [scenario.id for scenario in scenarios] == [
            "ad_17_cloud_metadata_ssrf_attempt",
            "ad_18_localhost_probe_attempt",
            "ad_19_private_ip_probe_attempt",
        ]
        assert all(scenario.policy.allowed_tools == ["search_web"] for scenario in scenarios)

    def test_benchmark_runs_all_three_cases(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="network-test").run()

        assert result.scenarios_total == 3
        assert result.scenarios_passed == 3
        assert result.pass_rate == 1.0
        assert [item["case_id"] for item in result.results] == [
            "AD-17",
            "AD-18",
            "AD-19",
        ]

        for scenario_result in result.results:
            assert scenario_result["category"] == "network"
            assert scenario_result["status"] == "blocked"
            assert scenario_result["failure_type"] == "permission_denied"
            assert scenario_result["blocked_by"] == "argument_guard"
            assert scenario_result["tool"] == "search_web"
            assert scenario_result["attack_payload"]
            assert scenario_result["passed"] is True
            trace_file = scenario_result["trace_file"]
            assert isinstance(trace_file, str)
            assert Path(trace_file).exists()

    def test_each_trace_contains_ssrf_evidence(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="network-trace-test").run()

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

            payload = scenario_result["attack_payload"]
            serialized = "\n".join(json.dumps(event, ensure_ascii=False) for event in events)
            assert payload in serialized
            assert "search_web" in serialized
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

    def test_network_fake_tool_is_not_executed(self, tmp_path: Path) -> None:
        result = BenchmarkRunner(SCENARIOS_DIR, tmp_path, run_id="no-network-tool-result").run()

        for scenario_result in result.results:
            events = _trace_events(scenario_result)
            successful_tool_results = [
                event
                for event in events
                if event["event_type"] == "tool_result"
                and event["data"].get("success") is True
            ]
            assert successful_tool_results == []
