"""Tests for Day 7 Markdown report rendering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_reliability_harness.report_renderer import ReportRenderer


def _scorecard() -> dict[str, Any]:
    return {
        "run_id": "example-run",
        "scenarios_total": 2,
        "scenarios_passed": 2,
        "scenarios_failed": 0,
        "pass_rate": 1.0,
        "failure_type_counts": {
            "none": 1,
            "policy_violation": 1,
        },
        "status_counts": {
            "blocked": 1,
            "passed": 1,
        },
        "results": [
            {
                "scenario_id": "normal_agent_run",
                "status": "passed",
                "expected_failure": "none",
                "failure_type": "none",
                "passed": True,
                "trace_file": "runs/example/normal_agent_run/trace.jsonl",
            },
            {
                "scenario_id": "model_not_allowed",
                "status": "blocked",
                "expected_failure": "policy_violation",
                "failure_type": "policy_violation",
                "passed": True,
                "trace_file": "runs/example/model_not_allowed/trace.jsonl",
            },
        ],
    }


class TestRenderMarkdown:
    def test_contains_summary(self) -> None:
        markdown = ReportRenderer().render_markdown(_scorecard())
        assert "# Agent Reliability Benchmark Report" in markdown
        assert "## Summary" in markdown
        assert "| run_id | example-run |" in markdown
        assert "| scenarios_total | 2 |" in markdown
        assert "| pass_rate | 1.0000 |" in markdown

    def test_contains_failure_type_counts(self) -> None:
        markdown = ReportRenderer().render_markdown(_scorecard())
        assert "## Failure Type Counts" in markdown
        assert "| none | 1 |" in markdown
        assert "| policy_violation | 1 |" in markdown

    def test_contains_scenario_results(self) -> None:
        markdown = ReportRenderer().render_markdown(_scorecard())
        assert "## Scenario Results" in markdown
        assert "normal_agent_run" in markdown
        assert "model_not_allowed" in markdown
        assert "runs/example/model_not_allowed/trace.jsonl" in markdown

    def test_contains_project_boundaries(self) -> None:
        markdown = ReportRenderer().render_markdown(_scorecard())
        assert "- offline" in markdown
        assert "- deterministic" in markdown
        assert "- no real LLM API" in markdown
        assert "- no real shell execution" in markdown
        assert "- no real network calls" in markdown


class TestWriteMarkdown:
    def test_write_markdown_creates_report(self, tmp_path: Path) -> None:
        report_path = tmp_path / "report.md"
        result = ReportRenderer().write_markdown(_scorecard(), report_path)
        assert result == report_path
        assert report_path.exists()
        assert "Agent Reliability Benchmark Report" in report_path.read_text(encoding="utf-8")

    def test_render_from_file(self, tmp_path: Path) -> None:
        scorecard_path = tmp_path / "scorecard.json"
        scorecard_path.write_text(json.dumps(_scorecard()), encoding="utf-8")
        report_path = tmp_path / "report.md"
        ReportRenderer().render_from_file(scorecard_path, report_path)
        assert report_path.exists()
        assert "Scenario Results" in report_path.read_text(encoding="utf-8")

    def test_does_not_generate_html(self, tmp_path: Path) -> None:
        ReportRenderer().write_markdown(_scorecard(), tmp_path / "report.md")
        assert list(tmp_path.rglob("*.html")) == []
