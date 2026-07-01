"""Tests for the interview attack_lab.py script."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "attack_lab.py"
SOURCE_AD01 = ROOT / "file_read_attack_scenarios" / "ad_01_path_traversal_read_attempt.yaml"


def _run_script(args: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=False,
    )


class TestAttackLabScript:
    def test_list_cases(self) -> None:
        result = _run_script(["list"])

        assert result.returncode == 0
        assert "AD-01" in result.stdout
        assert "AD-02" in result.stdout
        assert "AD-03" in result.stdout
        assert "AD-04" in result.stdout
        assert "../../../../etc/passwd" in result.stdout

    def test_run_ad01_default_payload(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "attack-lab-test"
        result = _run_script([
            "file-read",
            "AD-01",
            "--output-dir",
            str(output_dir),
            "--run-id",
            "ad-01-test",
        ])

        assert result.returncode == 0
        stdout = result.stdout
        assert "安全告警" in stdout
        assert "SECURITY ALERT" in stdout
        assert "AD-01" in stdout
        assert "../../../../etc/passwd" in stdout
        assert "argument_guard" in stdout
        assert "path_traversal" in stdout
        assert "report.zh.md" in stdout
        assert "report.en.md" in stdout
        assert "trace.jsonl" in stdout
        assert "靶场演示完成" in stdout

        run_dir = output_dir / "ad-01-test"
        report_zh = run_dir / "report.zh.md"
        report_en = run_dir / "report.en.md"
        trace = run_dir / "ad_01_path_traversal_read_attempt" / "trace.jsonl"
        assert report_zh.exists()
        assert report_en.exists()
        assert trace.exists()

        events = [
            json.loads(line)
            for line in trace.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        decision = next(
            event
            for event in events
            if event["event_type"] == "argument_guard_decision"
        )
        assert decision["data"]["action"] == "deny"

        successful_tool_results = [
            event
            for event in events
            if event["event_type"] == "tool_result"
            and event["data"].get("success") is True
        ]
        assert successful_tool_results == []

    def test_custom_payload_uses_temp_yaml_without_changing_source(
        self,
        tmp_path: Path,
    ) -> None:
        original_source = SOURCE_AD01.read_text(encoding="utf-8")
        custom_payload = r"..\..\..\secret.env"
        output_dir = tmp_path / "attack-lab-custom"

        result = _run_script([
            "file-read",
            "AD-01",
            "--payload",
            custom_payload,
            "--output-dir",
            str(output_dir),
            "--run-id",
            "ad-01-custom",
        ])

        assert result.returncode == 0
        assert custom_payload in result.stdout

        trace = output_dir / "ad-01-custom" / "ad_01_path_traversal_read_attempt" / "trace.jsonl"
        events = [
            json.loads(line)
            for line in trace.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        decision = next(
            event
            for event in events
            if event["event_type"] == "argument_guard_decision"
        )
        assert decision["data"]["attack_payload"] == custom_payload

        temp_yaml = ROOT / ".tmp" / "attack_lab" / "ad-01" / "ad_01_path_traversal_read_attempt.yaml"
        with temp_yaml.open("r", encoding="utf-8") as f:
            temp_data = yaml.safe_load(f)
        path_value = (
            temp_data["agent_run"]["mock_responses"][0]
            ["tool_calls"][0]["arguments"]["path"]
        )
        assert path_value == custom_payload

        assert SOURCE_AD01.read_text(encoding="utf-8") == original_source
        assert "../../../../etc/passwd" in original_source

    def test_script_uses_no_shell_true(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")

        assert "shell=True" not in source
        assert "os.system" not in source
