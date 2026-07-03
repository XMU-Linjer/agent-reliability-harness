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
SOURCE_AD05 = ROOT / "file_write_attack_scenarios" / "ad_05_windows_system_path_write_attempt.yaml"
SOURCE_AD10 = ROOT / "shell_attack_scenarios" / "ad_10_read_system_file_command_attempt.yaml"
SOURCE_AD16 = ROOT / "data_exfiltration_attack_scenarios" / "ad_16_url_query_secret_exfiltration_attempt.yaml"
SOURCE_AD18 = ROOT / "network_ssrf_attack_scenarios" / "ad_18_localhost_probe_attempt.yaml"


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
        assert "文件读取类 / File Read Attack Lab" in result.stdout
        assert "文件写入类 / File Write Attack Lab" in result.stdout
        assert "Shell / 命令执行类 / Shell Command Attack Lab" in result.stdout
        assert "数据外传类 / Data Exfiltration Attack Lab" in result.stdout
        assert "网络 / SSRF 类 / Network SSRF Attack Lab" in result.stdout
        for case_id in (
            "AD-01",
            "AD-02",
            "AD-03",
            "AD-04",
            "AD-05",
            "AD-06",
            "AD-07",
            "AD-08",
            "AD-09",
            "AD-10",
            "AD-11",
            "AD-12",
            "AD-13",
            "AD-14",
            "AD-15",
            "AD-16",
            "AD-17",
            "AD-18",
            "AD-19",
        ):
            assert case_id in result.stdout
        assert "rm -rf /" in result.stdout
        assert "api_key=sk-demo-secret" in result.stdout
        assert "https://example.com/search?q=test&secret=demo-secret" in result.stdout
        assert "http://169.254.169.254/latest/meta-data/" in result.stdout
        assert "http://127.0.0.1:8080/admin" in result.stdout
        assert "http://10.0.0.1/" in result.stdout

    def test_run_ad01_default_payload(self, tmp_path: Path) -> None:
        result = _run_script([
            "file-read",
            "AD-01",
            "--output-dir",
            str(tmp_path / "attack-lab-test"),
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

    def test_run_ad05_default_payload(self, tmp_path: Path) -> None:
        result = _run_script([
            "file-write",
            "AD-05",
            "--output-dir",
            str(tmp_path / "attack-lab-write-test"),
            "--run-id",
            "ad-05-test",
        ])

        assert result.returncode == 0
        stdout = result.stdout
        assert "安全告警" in stdout
        assert "AD-05" in stdout
        assert r"C:\Windows\System32\drivers\etc\hosts" in stdout
        assert "write_file" in stdout
        assert "windows_system_write" in stdout

    def test_run_ad09_default_payload(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "attack-lab-shell-test"
        result = _run_script([
            "shell",
            "AD-09",
            "--output-dir",
            str(output_dir),
            "--run-id",
            "ad-09-test",
        ])

        assert result.returncode == 0
        stdout = result.stdout
        assert "安全告警" in stdout
        assert "AD-09" in stdout
        assert "删除系统命令" in stdout
        assert "rm -rf /" in stdout
        assert "execute_shell" in stdout
        assert "tool_blocked" in stdout
        assert "dangerous_delete_command" in stdout

        trace = output_dir / "ad-09-test" / "ad_09_delete_system_command_attempt" / "trace.jsonl"
        events = _load_trace(trace)
        _assert_no_successful_tool_result(events)

    def test_run_ad13_default_payload(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "attack-lab-data-test"
        result = _run_script([
            "data-exfiltration",
            "AD-13",
            "--output-dir",
            str(output_dir),
            "--run-id",
            "ad-13-test",
        ])

        assert result.returncode == 0
        stdout = result.stdout
        assert "安全告警" in stdout
        assert "SECURITY ALERT" in stdout
        assert "AD-13" in stdout
        assert "Email 外传 API key" in stdout
        assert "api_key=sk-demo-secret" in stdout
        assert "send_email" in stdout
        assert "permission_denied" in stdout
        assert "data_exfiltration_api_key" in stdout
        assert "report.zh.md" in stdout
        assert "report.en.md" in stdout
        assert "trace.jsonl" in stdout
        assert "靶场演示完成" in stdout

        trace = output_dir / "ad-13-test" / "ad_13_email_api_key_exfiltration_attempt" / "trace.jsonl"
        events = _load_trace(trace)
        _assert_no_successful_tool_result(events)

    def test_data_alias_runs_ad13(self, tmp_path: Path) -> None:
        result = _run_script([
            "data",
            "AD-13",
            "--output-dir",
            str(tmp_path / "attack-lab-data-alias"),
            "--run-id",
            "ad-13-alias",
        ])

        assert result.returncode == 0
        assert "AD-13" in result.stdout
        assert "api_key=sk-demo-secret" in result.stdout

    def test_run_ad17_default_payload(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "attack-lab-network-test"
        result = _run_script([
            "network",
            "AD-17",
            "--output-dir",
            str(output_dir),
            "--run-id",
            "ad-17-test",
        ])

        assert result.returncode == 0
        stdout = result.stdout
        assert "安全告警" in stdout
        assert "SECURITY ALERT" in stdout
        assert "AD-17" in stdout
        assert "云元数据 SSRF" in stdout
        assert "http://169.254.169.254/latest/meta-data/" in stdout
        assert "search_web" in stdout
        assert "permission_denied" in stdout
        assert "ssrf_cloud_metadata" in stdout
        assert "report.zh.md" in stdout
        assert "report.en.md" in stdout
        assert "trace.jsonl" in stdout
        assert "靶场演示完成" in stdout

        trace = output_dir / "ad-17-test" / "ad_17_cloud_metadata_ssrf_attempt" / "trace.jsonl"
        events = _load_trace(trace)
        _assert_no_successful_tool_result(events)

    def test_ssrf_alias_runs_ad17(self, tmp_path: Path) -> None:
        result = _run_script([
            "ssrf",
            "AD-17",
            "--output-dir",
            str(tmp_path / "attack-lab-ssrf-alias"),
            "--run-id",
            "ad-17-alias",
        ])

        assert result.returncode == 0
        assert "AD-17" in result.stdout
        assert "http://169.254.169.254/latest/meta-data/" in result.stdout

    def test_custom_file_read_payload_uses_temp_yaml_without_changing_source(
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
        decision = _first_event(_load_trace(trace), "argument_guard_decision")
        assert decision["data"]["attack_payload"] == custom_payload

        temp_yaml = ROOT / ".tmp" / "attack_lab" / "ad-01" / "ad_01_path_traversal_read_attempt.yaml"
        assert _tool_argument(temp_yaml, "path") == custom_payload
        assert SOURCE_AD01.read_text(encoding="utf-8") == original_source

    def test_custom_file_write_payload_uses_temp_yaml_without_changing_source(
        self,
        tmp_path: Path,
    ) -> None:
        original_source = SOURCE_AD05.read_text(encoding="utf-8")
        custom_payload = "../../authorized_keys"
        output_dir = tmp_path / "attack-lab-write-custom"

        result = _run_script([
            "file-write",
            "AD-05",
            "--payload",
            custom_payload,
            "--output-dir",
            str(output_dir),
            "--run-id",
            "ad-05-custom",
        ])

        assert result.returncode == 0
        assert custom_payload in result.stdout
        trace = output_dir / "ad-05-custom" / "ad_05_windows_system_path_write_attempt" / "trace.jsonl"
        decision = _first_event(_load_trace(trace), "argument_guard_decision")
        assert decision["data"]["attack_payload"] == custom_payload
        assert decision["data"]["reason"] == "path_traversal"
        temp_yaml = ROOT / ".tmp" / "attack_lab" / "ad-05" / "ad_05_windows_system_path_write_attempt.yaml"
        assert _tool_argument(temp_yaml, "path") == custom_payload
        assert SOURCE_AD05.read_text(encoding="utf-8") == original_source

    def test_custom_shell_command_uses_temp_yaml_without_changing_source(
        self,
        tmp_path: Path,
    ) -> None:
        original_source = SOURCE_AD10.read_text(encoding="utf-8")
        custom_command = "cat /etc/passwd"
        output_dir = tmp_path / "attack-lab-shell-custom"

        result = _run_script([
            "shell",
            "AD-10",
            "--command",
            custom_command,
            "--output-dir",
            str(output_dir),
            "--run-id",
            "ad-10-custom",
        ])

        assert result.returncode == 0
        assert custom_command in result.stdout
        assert "shell_sensitive_file_read" in result.stdout
        trace = output_dir / "ad-10-custom" / "ad_10_read_system_file_command_attempt" / "trace.jsonl"
        decision = _first_event(_load_trace(trace), "argument_guard_decision")
        assert decision["data"]["attack_payload"] == custom_command
        assert _tool_argument(
            ROOT / ".tmp" / "attack_lab" / "ad-10" / "ad_10_read_system_file_command_attempt.yaml",
            "command",
        ) == custom_command
        assert SOURCE_AD10.read_text(encoding="utf-8") == original_source

    def test_custom_data_url_uses_temp_yaml_without_changing_source(
        self,
        tmp_path: Path,
    ) -> None:
        original_source = SOURCE_AD16.read_text(encoding="utf-8")
        custom_url = "https://example.com/search?q=test&secret=demo-secret"
        output_dir = tmp_path / "attack-lab-data-custom"

        result = _run_script([
            "data-exfiltration",
            "AD-16",
            "--url",
            custom_url,
            "--output-dir",
            str(output_dir),
            "--run-id",
            "ad-16-custom",
        ])

        assert result.returncode == 0
        assert custom_url in result.stdout
        assert "url_secret_exfiltration" in result.stdout
        trace = output_dir / "ad-16-custom" / "ad_16_url_query_secret_exfiltration_attempt" / "trace.jsonl"
        decision = _first_event(_load_trace(trace), "argument_guard_decision")
        assert decision["data"]["attack_payload"] == custom_url
        assert decision["data"]["reason"] == "url_secret_exfiltration"
        temp_yaml = ROOT / ".tmp" / "attack_lab" / "ad-16" / "ad_16_url_query_secret_exfiltration_attempt.yaml"
        assert _tool_argument(temp_yaml, "query") == custom_url
        assert SOURCE_AD16.read_text(encoding="utf-8") == original_source

    def test_custom_network_url_uses_temp_yaml_without_changing_source(
        self,
        tmp_path: Path,
    ) -> None:
        original_source = SOURCE_AD18.read_text(encoding="utf-8")
        custom_url = "http://127.0.0.1:8080/admin"
        output_dir = tmp_path / "attack-lab-network-custom"

        result = _run_script([
            "network",
            "AD-18",
            "--url",
            custom_url,
            "--output-dir",
            str(output_dir),
            "--run-id",
            "ad-18-custom",
        ])

        assert result.returncode == 0
        assert custom_url in result.stdout
        assert "ssrf_localhost" in result.stdout
        trace = output_dir / "ad-18-custom" / "ad_18_localhost_probe_attempt" / "trace.jsonl"
        decision = _first_event(_load_trace(trace), "argument_guard_decision")
        assert decision["data"]["attack_payload"] == custom_url
        assert decision["data"]["reason"] == "ssrf_localhost"
        temp_yaml = ROOT / ".tmp" / "attack_lab" / "ad-18" / "ad_18_localhost_probe_attempt.yaml"
        assert _tool_argument(temp_yaml, "query") == custom_url
        assert SOURCE_AD18.read_text(encoding="utf-8") == original_source

    def test_script_uses_no_shell_true(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")

        assert "shell=True" not in source
        assert "os.system" not in source


def _load_trace(trace: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in trace.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _first_event(events: list[dict[str, object]], event_type: str) -> dict[str, object]:
    return next(event for event in events if event["event_type"] == event_type)


def _assert_no_successful_tool_result(events: list[dict[str, object]]) -> None:
    successful_tool_results = [
        event
        for event in events
        if event["event_type"] == "tool_result"
        and isinstance(event.get("data"), dict)
        and event["data"].get("success") is True
    ]
    assert successful_tool_results == []


def _tool_argument(path: Path, argument_name: str) -> object:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return (
        data["agent_run"]["mock_responses"][0]
        ["tool_calls"][0]["arguments"][argument_name]
    )
