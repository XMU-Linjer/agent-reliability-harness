"""Tests for the minimal Day 7 CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_reliability_harness.cli import main

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"


class TestCliRun:
    def test_run_generates_scorecard_and_report(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        exit_code = main([
            "run",
            "--scenarios-dir",
            str(SCENARIOS_DIR),
            "--output-dir",
            str(tmp_path),
            "--run-id",
            "cli-test",
        ])

        assert exit_code == 0
        run_dir = tmp_path / "cli-test"
        scorecard_path = run_dir / "scorecard.json"
        report_path = run_dir / "report.md"

        assert scorecard_path.exists()
        assert report_path.exists()
        assert list(run_dir.rglob("*.html")) == []

        with scorecard_path.open("r", encoding="utf-8") as f:
            scorecard: dict[str, Any] = json.load(f)
        assert scorecard["scenarios_total"] == 10
        assert scorecard["scenarios_passed"] == 10
        assert scorecard["pass_rate"] == 1.0

        report = report_path.read_text(encoding="utf-8")
        assert "Agent Reliability Benchmark Report" in report
        assert "Scenario Results" in report

        output = capsys.readouterr().out
        assert "run_id: cli-test" in output
        assert "scenarios_total: 10" in output
        assert "scorecard:" in output
        assert "report:" in output

    def test_run_does_not_execute_shell_or_network(self, tmp_path: Path) -> None:
        exit_code = main([
            "run",
            "--scenarios-dir",
            str(SCENARIOS_DIR),
            "--output-dir",
            str(tmp_path),
            "--run-id",
            "safety-test",
        ])

        assert exit_code == 0
        scorecard_path = tmp_path / "safety-test" / "scorecard.json"
        with scorecard_path.open("r", encoding="utf-8") as f:
            scorecard: dict[str, Any] = json.load(f)
        assert scorecard["scenarios_total"] == 10
        results = scorecard["results"]
        assert isinstance(results, list)
        prompt_injection_results = [
            result
            for result in results
            if isinstance(result, dict)
            if result["scenario_id"] == "prompt_injection_tool_escalation"
        ]
        assert len(prompt_injection_results) == 1
        assert prompt_injection_results[0]["failure_type"] == "prompt_injection"
