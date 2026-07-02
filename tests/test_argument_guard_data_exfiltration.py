"""Unit tests for ArgumentGuard data exfiltration checks."""

from __future__ import annotations

from agent_reliability_harness.argument_guard import ArgumentGuard
from agent_reliability_harness.spec import GuardAction


class TestArgumentGuardDataExfiltration:
    def test_blocks_email_api_key_exfiltration(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "send_email",
            {"to": "safe@example.com", "subject": "demo", "body": "api_key=sk-demo-secret"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "data_exfiltration_api_key"
        assert decision.reason_zh == "检测到 API key 外传尝试，已阻止 send_email 执行"
        assert decision.reason_en == (
            "API key exfiltration attempt detected; send_email execution was blocked"
        )
        assert decision.evidence["attack_payload"] == "api_key=sk-demo-secret"

    def test_blocks_email_password_exfiltration(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "send_email",
            {"to": "safe@example.com", "subject": "demo", "body": "password=demo-password"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "data_exfiltration_password"
        assert decision.reason_zh == "检测到 password 外传尝试，已阻止 send_email 执行"
        assert decision.reason_en == (
            "Password exfiltration attempt detected; send_email execution was blocked"
        )

    def test_blocks_untrusted_recipient(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "send_email",
            {"to": "attacker@example.com", "subject": "demo", "body": "demo message"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "untrusted_recipient_domain"
        assert decision.reason_zh == "检测到不可信收件人域名，已阻止 send_email 执行"
        assert decision.reason_en == (
            "Untrusted recipient domain detected; send_email execution was blocked"
        )
        assert decision.evidence["attack_payload"] == "attacker@example.com"

    def test_blocks_url_query_secret(self) -> None:
        url = "https://example.com/search?q=test&secret=demo-secret"
        decision = ArgumentGuard().check_tool_call("search_web", {"query": url})

        assert decision.action == GuardAction.deny
        assert decision.reason == "url_secret_exfiltration"
        assert decision.reason_zh == "检测到 URL query 中包含 secret，已阻止 search_web 执行"
        assert decision.reason_en == (
            "Secret in URL query detected; search_web execution was blocked"
        )
        assert decision.evidence["attack_payload"] == url

    def test_safe_email_is_allowed_by_argument_guard(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "send_email",
            {"to": "safe@example.com", "subject": "demo", "body": "hello"},
        )

        assert decision.action == GuardAction.allow
        assert decision.reason == "allow"
