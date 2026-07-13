"""Tests for ScorecardGenerator — Day 6 coverage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmark.scorecard import ScorecardGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_results() -> list[dict[str, Any]]:
    """Build a representative set of scenario results."""
    return [
        {"scenario_id": "normal_agent_run", "status": "passed", "failure_type": "none",
         "expected_failure": "none", "passed": True, "trace_file": "t.jsonl", "events_count": 10},
        {"scenario_id": "model_not_allowed", "status": "blocked", "failure_type": "policy_violation",
         "expected_failure": "policy_violation", "passed": True, "trace_file": "t.jsonl", "events_count": 5},
        {"scenario_id": "budget_exceeded", "status": "blocked", "failure_type": "budget_exceeded",
         "expected_failure": "budget_exceeded", "passed": True, "trace_file": "t.jsonl", "events_count": 8},
        {"scenario_id": "provider_timeout", "status": "recovered", "failure_type": "provider_timeout",
         "expected_failure": "provider_timeout", "passed": True, "trace_file": "t.jsonl", "events_count": 7},
        {"scenario_id": "tool_blocked", "status": "blocked", "failure_type": "tool_blocked",
         "expected_failure": "tool_blocked", "passed": True, "trace_file": "t.jsonl", "events_count": 6},
    ]


def _make_mixed_results() -> list[dict[str, Any]]:
    """Results with some failures (passed=False)."""
    return [
        {"scenario_id": "s1", "status": "passed", "failure_type": "none",
         "expected_failure": "none", "passed": True, "trace_file": None, "events_count": 5},
        {"scenario_id": "s2", "status": "blocked", "failure_type": "policy_violation",
         "expected_failure": "none", "passed": False, "trace_file": None, "events_count": 3},
        {"scenario_id": "s3", "status": "error", "failure_type": "error",
         "expected_failure": "none", "passed": False, "trace_file": None, "events_count": 0},
    ]


# ---------------------------------------------------------------------------
# pass_rate
# ---------------------------------------------------------------------------


class TestPassRate:
    """Verify pass_rate calculation."""

    def test_all_passed(self) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate(_make_results(), "r1", "out")
        assert sc["pass_rate"] == 1.0

    def test_mixed_results(self) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate(_make_mixed_results(), "r1", "out")
        # 1 of 3 passed
        assert abs(sc["pass_rate"] - 1 / 3) < 1e-9

    def test_empty_results(self) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate([], "r1", "out")
        assert sc["pass_rate"] == 0.0

    def test_scenarios_total(self) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate(_make_results(), "r1", "out")
        assert sc["scenarios_total"] == 5

    def test_scenarios_passed_and_failed(self) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate(_make_mixed_results(), "r1", "out")
        assert sc["scenarios_passed"] == 1
        assert sc["scenarios_failed"] == 2


# ---------------------------------------------------------------------------
# failure_type_counts
# ---------------------------------------------------------------------------


class TestFailureTypeCounts:
    """Verify failure type distribution."""

    def test_all_unique(self) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate(_make_results(), "r1", "out")
        counts = sc["failure_type_counts"]
        assert counts["none"] == 1
        assert counts["policy_violation"] == 1
        assert counts["budget_exceeded"] == 1

    def test_mixed_has_error(self) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate(_make_mixed_results(), "r1", "out")
        counts = sc["failure_type_counts"]
        assert counts.get("error") == 1


# ---------------------------------------------------------------------------
# status_counts
# ---------------------------------------------------------------------------


class TestStatusCounts:
    """Verify status distribution."""

    def test_status_counts(self) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate(_make_results(), "r1", "out")
        counts = sc["status_counts"]
        assert counts["passed"] == 1
        assert counts["blocked"] == 3
        assert counts["recovered"] == 1

    def test_mixed_status_counts(self) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate(_make_mixed_results(), "r1", "out")
        counts = sc["status_counts"]
        assert counts["passed"] == 1
        assert counts["blocked"] == 1
        assert counts["error"] == 1


# ---------------------------------------------------------------------------
# JSON write / read
# ---------------------------------------------------------------------------


class TestWriteJson:
    """Verify scorecard JSON serialisation."""

    def test_write_creates_file(self, tmp_path: Path) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate(_make_results(), "r1", str(tmp_path))
        out = tmp_path / "scorecard.json"
        gen.write_json(sc, out)
        assert out.exists()

    def test_json_is_parseable(self, tmp_path: Path) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate(_make_results(), "r1", str(tmp_path))
        out = tmp_path / "scorecard.json"
        gen.write_json(sc, out)
        with out.open("r", encoding="utf-8") as f:
            parsed = json.load(f)
        assert parsed["run_id"] == "r1"
        assert parsed["scenarios_total"] == 5

    def test_write_creates_parent_dirs(self, tmp_path: Path) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate([], "r1", str(tmp_path))
        deep = tmp_path / "a" / "b" / "scorecard.json"
        gen.write_json(sc, deep)
        assert deep.exists()

    def test_roundtrip_fields(self, tmp_path: Path) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate(_make_results(), "r1", str(tmp_path))
        out = tmp_path / "scorecard.json"
        gen.write_json(sc, out)
        with out.open("r", encoding="utf-8") as f:
            parsed = json.load(f)
        assert parsed["pass_rate"] == sc["pass_rate"]
        assert parsed["failure_type_counts"] == sc["failure_type_counts"]
        assert parsed["status_counts"] == sc["status_counts"]
        assert len(parsed["results"]) == len(sc["results"])


# ---------------------------------------------------------------------------
# No report generation
# ---------------------------------------------------------------------------


class TestNoReportGeneration:
    """ScorecardGenerator must not generate Markdown/HTML reports."""

    def test_no_markdown_output(self, tmp_path: Path) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate(_make_results(), "r1", str(tmp_path))
        gen.write_json(sc, tmp_path / "scorecard.json")
        assert list(tmp_path.rglob("*.md")) == []

    def test_no_html_output(self, tmp_path: Path) -> None:
        gen = ScorecardGenerator()
        sc = gen.generate(_make_results(), "r1", str(tmp_path))
        gen.write_json(sc, tmp_path / "scorecard.json")
        assert list(tmp_path.rglob("*.html")) == []
