"""
Markdown report renderer for AgentReliabilityHarness.

Generates stable Markdown reports from scorecard dicts.
No HTML, templates, charts, dashboards, network calls, or external services.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ReportRenderer:
    """Render benchmark scorecards as Markdown."""

    def render_markdown(self, scorecard: dict[str, Any]) -> str:
        """Render the original English benchmark report."""
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

        lines.extend(["", "## Status Counts", "", "| status | count |", "|---|---:|"])
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

    def render_zh_markdown(self, scorecard: dict[str, Any]) -> str:
        """Render a Chinese attack-defense report."""
        lines = [
            "# Agent 可靠性攻防模拟报告",
            "",
            "## 汇总",
            "",
            "| 指标 | 值 |",
            "|---|---:|",
            f"| run_id | {self._cell(scorecard.get('run_id', 'unknown'))} |",
            f"| 场景总数 | {self._cell(scorecard.get('scenarios_total', 0))} |",
            f"| 验收通过 | {self._cell(scorecard.get('scenarios_passed', 0))} |",
            f"| 验收失败 | {self._cell(scorecard.get('scenarios_failed', 0))} |",
            f"| 通过率 | {self._format_pass_rate(scorecard.get('pass_rate', 0.0))} |",
            "",
            "## 安全告警",
            "",
            "| case_id | 攻击模拟 | 工具 | payload | 防护模块 | 拦截原因 | failure_type | trace_file |",
            "|---|---|---|---|---|---|---|---|",
        ]
        alert_results = [
            result
            for result in self._as_results(scorecard.get("results", []))
            if self._is_security_event(result)
        ]
        if not alert_results:
            lines.append("| none | 无安全告警 |  |  |  |  | none |  |")
        for result in alert_results:
            case_id, attack_zh, _attack_en = self._case_labels(result)
            reason = self._reason_with_detail(result.get("reason"), result.get("reason_zh"))
            lines.append(
                "| "
                f"{self._cell(case_id)} | "
                f"{self._cell(attack_zh)} | "
                f"{self._cell(result.get('tool', ''))} | "
                f"{self._cell(result.get('attack_payload', ''))} | "
                f"{self._cell(result.get('blocked_by', ''))} | "
                f"{self._cell(reason)} | "
                f"{self._cell(result.get('failure_type', 'unknown'))} | "
                f"{self._cell(result.get('trace_file', ''))} |"
            )
        lines.extend(self._boundaries_zh())
        return "\n".join(lines)

    def render_en_markdown(self, scorecard: dict[str, Any]) -> str:
        """Render an English attack-defense report."""
        lines = [
            "# Agent Reliability Attack-Defense Report",
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
            "## Security Alerts",
            "",
            "| case_id | attack_simulation | tool | payload | blocked_by | reason | failure_type | trace_file |",
            "|---|---|---|---|---|---|---|---|",
        ]
        alert_results = [
            result
            for result in self._as_results(scorecard.get("results", []))
            if self._is_security_event(result)
        ]
        if not alert_results:
            lines.append("| none | no security alerts |  |  |  |  | none |  |")
        for result in alert_results:
            case_id, _attack_zh, attack_en = self._case_labels(result)
            reason = self._reason_with_detail(result.get("reason"), result.get("reason_en"))
            lines.append(
                "| "
                f"{self._cell(case_id)} | "
                f"{self._cell(attack_en)} | "
                f"{self._cell(result.get('tool', ''))} | "
                f"{self._cell(result.get('attack_payload', ''))} | "
                f"{self._cell(result.get('blocked_by', ''))} | "
                f"{self._cell(reason)} | "
                f"{self._cell(result.get('failure_type', 'unknown'))} | "
                f"{self._cell(result.get('trace_file', ''))} |"
            )
        lines.extend(self._boundaries_en())
        return "\n".join(lines)

    def write_markdown(self, scorecard: dict[str, Any], output_path: str | Path) -> Path:
        """Write the original English benchmark report and return the path."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render_markdown(scorecard), encoding="utf-8")
        return path

    def write_zh_markdown(self, scorecard: dict[str, Any], output_path: str | Path) -> Path:
        """Write the Chinese report and return the path."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render_zh_markdown(scorecard), encoding="utf-8")
        return path

    def write_en_markdown(self, scorecard: dict[str, Any], output_path: str | Path) -> Path:
        """Write the English attack-defense report and return the path."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render_en_markdown(scorecard), encoding="utf-8")
        return path

    def render_from_file(self, scorecard_file: str | Path, output_path: str | Path) -> Path:
        """Read scorecard JSON from disk and write the original report."""
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
        return {str(key): count for key, count in value.items() if isinstance(count, int)}

    def _as_results(self, value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    def _format_pass_rate(self, value: Any) -> str:
        if isinstance(value, int | float):
            return f"{float(value):.4f}"
        return self._cell(value)

    def _is_security_event(self, result: dict[str, Any]) -> bool:
        return (
            result.get("failure_type") != "none"
            or result.get("status") in ("blocked", "failed", "recovered", "error")
            or bool(result.get("blocked_by"))
            or bool(result.get("attack_payload"))
        )

    def _case_labels(self, result: dict[str, Any]) -> tuple[str, str, str]:
        scenario_id = str(result.get("scenario_id", "unknown"))
        labels = {
            "ad_01_path_traversal_read_attempt": ("AD-01", "路径穿越读取", "Path traversal read attempt"),
            "ad_02_linux_sensitive_path_read_attempt": ("AD-02", "Linux 敏感路径读取", "Linux sensitive path read attempt"),
            "ad_03_windows_sensitive_path_read_attempt": ("AD-03", "Windows 敏感路径读取", "Windows sensitive path read attempt"),
            "ad_04_outside_project_read_attempt": ("AD-04", "项目目录外读取", "Outside workspace read attempt"),
            "ad_05_windows_system_path_write_attempt": ("AD-05", "写 Windows 系统路径", "Windows system path write attempt"),
            "ad_06_linux_system_path_write_attempt": ("AD-06", "写 Linux 系统路径", "Linux system path write attempt"),
            "ad_07_script_file_write_attempt": ("AD-07", "写脚本文件", "Script file write attempt"),
            "ad_08_path_traversal_write_attempt": ("AD-08", "目录穿越写文件", "Directory traversal write attempt"),
            "ad_09_delete_system_command_attempt": ("AD-09", "删除系统命令", "Dangerous delete command"),
            "ad_10_read_system_file_command_attempt": ("AD-10", "读取系统文件命令", "Shell sensitive file read command"),
            "ad_11_external_download_command_attempt": ("AD-11", "外联下载命令", "External download command"),
            "ad_12_powershell_download_execute_attempt": ("AD-12", "PowerShell 下载执行", "PowerShell download-and-execute command"),
            "ad_13_email_api_key_exfiltration_attempt": ("AD-13", "Email 外传 API key", "Email API key exfiltration attempt"),
            "ad_14_email_password_exfiltration_attempt": ("AD-14", "Email 外传 password", "Email password exfiltration attempt"),
            "ad_15_untrusted_email_recipient_attempt": ("AD-15", "发往不可信域名", "Untrusted email recipient attempt"),
            "ad_16_url_query_secret_exfiltration_attempt": ("AD-16", "搜索/网络请求外传", "URL query secret exfiltration attempt"),
            "ad_17_cloud_metadata_ssrf_attempt": ("AD-17", "云元数据 SSRF", "Cloud metadata SSRF attempt"),
            "ad_18_localhost_probe_attempt": ("AD-18", "localhost 探测", "Localhost probe attempt"),
            "ad_19_private_ip_probe_attempt": ("AD-19", "内网网段探测", "Private IP probe attempt"),
        }
        return labels.get(scenario_id, (scenario_id, scenario_id, scenario_id))

    def _reason_with_detail(self, reason: Any, detail: Any) -> str:
        reason_text = "" if reason is None else str(reason)
        detail_text = "" if detail is None else str(detail)
        if reason_text and detail_text and reason_text != detail_text:
            return f"{reason_text} - {detail_text}"
        return reason_text or detail_text

    def _boundaries_zh(self) -> list[str]:
        return [
            "",
            "## 安全边界",
            "",
            "- payload 是惰性字符串",
            "- 不真实读取系统文件",
            "- 不真实写入系统文件",
            "- 不真实执行 shell",
            "- 不真实发送邮件",
            "- 不真实联网",
            "- 危险路径、危险命令、外传 payload 和 SSRF URL 会在 FakeTool 执行前被拦截",
            "",
        ]

    def _boundaries_en(self) -> list[str]:
        return [
            "",
            "## Safety Boundaries",
            "",
            "- Payloads are inert strings",
            "- No real system file reads",
            "- No real system file writes",
            "- No real shell execution",
            "- No real email sending",
            "- No real network calls",
            "- Dangerous paths, commands, exfiltration payloads, and SSRF URLs are blocked before FakeTool execution",
            "",
        ]

    def _cell(self, value: Any) -> str:
        text = "" if value is None else str(value)
        return text.replace("|", "\\|").replace("\n", " ")
