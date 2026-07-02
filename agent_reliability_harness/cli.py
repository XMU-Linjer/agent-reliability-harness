"""Minimal CLI for AgentReliabilityHarness."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from agent_reliability_harness.benchmark_runner import BenchmarkRunner
from agent_reliability_harness.report_renderer import ReportRenderer


def _configure_utf8_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


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
    _configure_utf8_output()
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

        with Path(scorecard_file).open("r", encoding="utf-8") as f:
            scorecard = json.load(f)
        if not isinstance(scorecard, dict):
            raise RuntimeError("scorecard JSON must contain an object")

        renderer = ReportRenderer()
        report_path = Path(result.output_dir) / "report.md"
        report_zh_path = Path(result.output_dir) / "report.zh.md"
        report_en_path = Path(result.output_dir) / "report.en.md"
        renderer.write_markdown(scorecard, report_path)
        renderer.write_zh_markdown(scorecard, report_zh_path)
        renderer.write_en_markdown(scorecard, report_en_path)

        print(f"run_id: {result.run_id}")
        print(f"scenarios_total: {result.scenarios_total}")
        print(f"scenarios_passed: {result.scenarios_passed}")
        print(f"pass_rate: {result.pass_rate:.4f}")
        print(f"scorecard: {scorecard_file}")
        print(f"report: {report_path}")
        _print_security_alerts(scorecard, report_zh_path, report_en_path, scorecard_file)
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


def _print_security_alerts(
    scorecard: dict[str, Any],
    report_zh_path: Path,
    report_en_path: Path,
    scorecard_file: str,
) -> None:
    results = scorecard.get("results", [])
    if not isinstance(results, list):
        results = []
    result_dicts = [result for result in results if isinstance(result, dict)]
    security_events = [result for result in result_dicts if _is_security_event(result)]
    defense_failures = [result for result in result_dicts if not result.get("passed")]

    if defense_failures:
        print("")
        print("[防护失败 / DEFENSE FAILED]")
        for result in defense_failures:
            print(
                f"- {result.get('scenario_id', 'unknown')}: "
                f"status={result.get('status', 'unknown')}, "
                f"failure_type={result.get('failure_type', 'unknown')}"
            )

    if security_events:
        print("")
        print("[安全告警 / SECURITY ALERT]")
        if defense_failures:
            print(f"{len(security_events)} security events detected. Some defenses failed.")
        else:
            print(
                f"{len(security_events)} security events detected. "
                "All dangerous actions were blocked or handled by the harness."
            )
        for result in security_events:
            _print_security_event(result)

    print("")
    print("Reports:")
    print(f"中文报告: {report_zh_path}")
    print(f"English report: {report_en_path}")
    print(f"Machine-readable scorecard: {scorecard_file}")
    _print_next_steps(security_events, report_zh_path, report_en_path)


def _print_security_event(result: dict[str, Any]) -> None:
    case_id, attack_zh, attack_en = _case_labels(result)
    print("")
    print(f"[{case_id}] {attack_zh} / {attack_en}")
    print(f"tool: {result.get('tool', '')}")
    print(f"payload: {result.get('attack_payload', '')}")
    print(f"blocked_by: {result.get('blocked_by', '')}")
    print(f"reason: {result.get('reason', '')}")
    print(f"中文原因: {result.get('reason_zh', '')}")
    print(f"English reason: {result.get('reason_en', '')}")
    print(f"status: {result.get('status', 'unknown')}")
    print(f"failure_type: {result.get('failure_type', 'unknown')}")
    print(f"trace: {result.get('trace_file', '')}")


def _print_next_steps(
    security_events: list[dict[str, Any]],
    report_zh_path: Path,
    report_en_path: Path,
) -> None:
    print("")
    print("下一步 / Next steps:")
    print("1. 查看中文报告:")
    print(f"   notepad {report_zh_path}")
    print("2. 查看英文报告:")
    print(f"   notepad {report_en_path}")
    if security_events:
        first_trace = security_events[0].get("trace_file")
        first_case = _case_labels(security_events[0])[0]
        if first_trace:
            print(f"3. 查看 {first_case} trace:")
            print(f"   notepad {first_trace}")


def _is_security_event(result: dict[str, Any]) -> bool:
    return (
        result.get("failure_type") != "none"
        or result.get("status") in ("blocked", "failed", "recovered", "error")
        or bool(result.get("blocked_by"))
        or bool(result.get("attack_payload"))
    )


def _case_labels(result: dict[str, Any]) -> tuple[str, str, str]:
    scenario_id = str(result.get("scenario_id", "unknown"))
    labels = {
        "ad_01_path_traversal_read_attempt": (
            "AD-01",
            "路径穿越读取",
            "Path traversal read attempt",
        ),
        "ad_02_linux_sensitive_path_read_attempt": (
            "AD-02",
            "Linux 敏感路径读取",
            "Linux sensitive path read attempt",
        ),
        "ad_03_windows_sensitive_path_read_attempt": (
            "AD-03",
            "Windows 敏感路径读取",
            "Windows sensitive path read attempt",
        ),
        "ad_04_outside_project_read_attempt": (
            "AD-04",
            "项目目录外读取",
            "Outside workspace read attempt",
        ),
        "ad_05_windows_system_path_write_attempt": (
            "AD-05",
            "写 Windows 系统路径",
            "Windows system path write attempt",
        ),
        "ad_06_linux_system_path_write_attempt": (
            "AD-06",
            "写 Linux 系统路径",
            "Linux system path write attempt",
        ),
        "ad_07_script_file_write_attempt": (
            "AD-07",
            "写脚本文件",
            "Script file write attempt",
        ),
        "ad_08_path_traversal_write_attempt": (
            "AD-08",
            "目录穿越写文件",
            "Directory traversal write attempt",
        ),
        "ad_09_delete_system_command_attempt": (
            "AD-09",
            "删除系统命令",
            "Dangerous delete command",
        ),
        "ad_10_read_system_file_command_attempt": (
            "AD-10",
            "读取系统文件命令",
            "Shell sensitive file read command",
        ),
        "ad_11_external_download_command_attempt": (
            "AD-11",
            "外联下载命令",
            "External download command",
        ),
        "ad_12_powershell_download_execute_attempt": (
            "AD-12",
            "PowerShell 下载执行",
            "PowerShell download-and-execute command",
        ),
    }
    return labels.get(scenario_id, (scenario_id, scenario_id, scenario_id))


if __name__ == "__main__":
    raise SystemExit(main())
