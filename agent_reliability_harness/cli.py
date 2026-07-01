"""Minimal CLI for AgentReliabilityHarness."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from agent_reliability_harness.benchmark_runner import BenchmarkRunner
from agent_reliability_harness.report_renderer import ReportRenderer


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="arh",
        description="Run the offline AgentReliabilityHarness benchmark.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run",
        help="Run all scenario YAML files and generate scorecard.json + report.md.",
    )
    run_parser.add_argument("--scenarios-dir", default="scenarios")
    run_parser.add_argument("--output-dir", default="runs/local-demo")
    run_parser.add_argument("--run-id", default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point used by both `arh` and `python -m`."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        result = BenchmarkRunner(
            scenarios_dir=args.scenarios_dir,
            output_dir=args.output_dir,
            run_id=args.run_id,
        ).run()

        scorecard_file = result.scorecard_file
        if scorecard_file is None:
            raise RuntimeError("BenchmarkRunner did not produce a scorecard file")

        report_path = Path(result.output_dir) / "report.md"
        ReportRenderer().render_from_file(scorecard_file, report_path)

        print(f"run_id: {result.run_id}")
        print(f"scenarios_total: {result.scenarios_total}")
        print(f"scenarios_passed: {result.scenarios_passed}")
        print(f"pass_rate: {result.pass_rate:.4f}")
        print(f"scorecard: {scorecard_file}")
        print(f"report: {report_path}")
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
