"""
ScorecardGenerator for AgentReliabilityHarness.

Produces a structured scorecard (dict / JSON) from benchmark results.
No rich-text reports, no ReportRenderer — just JSON.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


class ScorecardGenerator:
    """Generate a scorecard summary from a list of scenario run results.

    Usage::

        gen = ScorecardGenerator()
        scorecard = gen.generate(results, run_id="abc123", output_dir="runs/abc123")
        gen.write_json(scorecard, "runs/abc123/scorecard.json")
    """

    def generate(
        self,
        results: list[dict[str, Any]],
        run_id: str,
        output_dir: str | Path,
    ) -> dict[str, Any]:
        """Build a scorecard dict from scenario results.

        Args:
            results: List of result dicts from run_scenario_day5.
            run_id: Unique identifier for this benchmark run.
            output_dir: Directory where outputs were written.

        Returns:
            Scorecard dict with summary statistics and per-scenario results.
        """
        total = len(results)
        passed = sum(1 for r in results if r.get("passed"))
        failed = total - passed
        pass_rate = passed / total if total > 0 else 0.0

        failure_type_counts: dict[str, int] = dict(
            Counter(r.get("failure_type", "unknown") for r in results)
        )
        status_counts: dict[str, int] = dict(
            Counter(r.get("status", "unknown") for r in results)
        )

        return {
            "run_id": run_id,
            "scenarios_total": total,
            "scenarios_passed": passed,
            "scenarios_failed": failed,
            "pass_rate": pass_rate,
            "failure_type_counts": failure_type_counts,
            "status_counts": status_counts,
            "results": results,
            "output_dir": str(output_dir),
        }

    def write_json(self, scorecard: dict[str, Any], output_path: str | Path) -> Path:
        """Write the scorecard to a JSON file.

        Creates parent directories as needed.

        Args:
            scorecard: The scorecard dict to serialise.
            output_path: Destination file path.

        Returns:
            The Path to the written file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(scorecard, f, indent=2, ensure_ascii=False)
        return path
