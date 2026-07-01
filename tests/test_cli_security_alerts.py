"""Tests for CLI security alert output."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_reliability_harness.cli import main

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "file_read_attack_scenarios"


class TestCliSecurityAlerts:
    def test_file_read_attack_run_prints_security_alerts(
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
