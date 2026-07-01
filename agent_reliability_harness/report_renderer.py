"""
Markdown report renderer for AgentReliabilityHarness.

Generates a stable, human-readable Markdown report from a scorecard dict.
No HTML, templates, charts, dashboards, network calls, or external services.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ReportRenderer:
    """Render benchmark scorecards as Markdown."""

    def render_markdown(self, scorecard: dict[str, Any]) -> str:
        """Render a scorecard dict to a stable Markdown string."""
        lines: list[str] = [
            "# Agent Reliability Benchmark Report",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|---|---:|",
            f"| run_id | {self._cell(scorecard.get('run_id', 'unknown'))} |",
            f"| scenarios_total | {self._cell(scorecard.get('scenarios_total', 0))} |",
            f"| scenarios_passed | {self._cell(scorecard.get('scenarios_passed', 0))} |",
            f"| scenarios_failed | {self._cell(scorecard.get('scenarios_failed', 0))} |",
            f"| pass_rate | {self._format_pass_rate(scorecard.get('pass_rate', 0.0))} |",
            "",
            "## Failure Type Counts",
            "",
            "| failure_type | count |",
            "|---|---:|",
        ]

        failure_type_counts = self._as_count_dict(scorecard.get("failure_type_counts", {}))
        lines.extend(self._count_rows(failure_type_counts, "failure_type"))

        lines.extend([
            "",
            "## Status Counts",
            "",
            "| status | count |",
            "|---|---:|",
        ])
        status_counts = self._as_count_dict(scorecard.get("status_counts", {}))
        lines.extend(self._count_rows(status_counts, "status"))

        lines.extend([
            "",
            "## Scenario Results",
            "",
            "| scenario_id | status | expected_failure | failure_type | passed | trace_file |",
            "|---|---|---|---|---:|---|",
        ])
        for result in self._as_results(scorecard.get("results", [])):
            lines.append(
                "| "
                f"{self._cell(result.get('scenario_id', 'unknown'))} | "
                f"{self._cell(result.get('status', 'unknown'))} | "
                f"{self._cell(result.get('expected_failure', 'unknown'))} | "
                f"{self._cell(result.get('failure_type', 'unknown'))} | "
                f"{self._cell(result.get('passed', False))} | "
                f"{self._cell(result.get('trace_file', ''))} |"
            )

        lines.extend([
            "",
            "## Project Boundaries",
            "",
            "- offline",
            "- deterministic",
            "- no real LLM API",
            "- no real shell execution",
            "- no real network calls",
            "",
        ])
        return "\n".join(lines)

    def write_markdown(self, scorecard: dict[str, Any], output_path: str | Path) -> Path:
        """Write a Markdown report and return the written path."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render_markdown(scorecard), encoding="utf-8")
        return path

    def render_from_file(self, scorecard_file: str | Path, output_path: str | Path) -> Path:
        """Read scorecard JSON from disk and write a Markdown report."""
        with Path(scorecard_file).open("r", encoding="utf-8") as f:
            scorecard = json.load(f)
        if not isinstance(scorecard, dict):
            raise ValueError("scorecard JSON must contain an object")
        return self.write_markdown(scorecard, output_path)

    def _count_rows(self, counts: dict[str, int], empty_label: str) -> list[str]:
        if not counts:
            return [f"| {empty_label}:none | 0 |"]
        return [f"| {self._cell(key)} | {value} |" for key, value in sorted(counts.items())]

    def _as_count_dict(self, value: Any) -> dict[str, int]:
        if not isinstance(value, dict):
            return {}
        counts: dict[str, int] = {}
        for key, count in value.items():
            if isinstance(count, int):
                counts[str(key)] = count
        return counts

    def _as_results(self, value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    def _format_pass_rate(self, value: Any) -> str:
        if isinstance(value, int | float):
            return f"{float(value):.4f}"
        return self._cell(value)

    def _cell(self, value: Any) -> str:
        text = "" if value is None else str(value)
        return text.replace("|", "\\|").replace("\n", " ")
