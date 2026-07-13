"""Tests for network / SSRF argument guard checks."""

from __future__ import annotations

from agent_guard.guards.argument_guard import ArgumentGuard
from benchmark.spec import GuardAction


class TestArgumentGuardNetworkSsrf:
    def test_blocks_cloud_metadata_url(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "search_web",
            {"query": "http://169.254.169.254/latest/meta-data/"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "ssrf_cloud_metadata"
        assert decision.check_type == "ssrf_cloud_metadata"
        assert decision.evidence["attack_payload"] == "http://169.254.169.254/latest/meta-data/"

    def test_blocks_localhost_url(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "search_web",
            {"query": "http://127.0.0.1:8080/admin"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "ssrf_localhost"
        assert decision.check_type == "ssrf_localhost"

    def test_blocks_private_ip_url(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "search_web",
            {"query": "http://10.0.0.1/"},
        )

        assert decision.action == GuardAction.deny
        assert decision.reason == "ssrf_private_ip"
        assert decision.check_type == "ssrf_private_ip"

    def test_safe_search_url_is_allowed(self) -> None:
        decision = ArgumentGuard().check_tool_call(
            "search_web",
            {"query": "https://example.com/search?q=hello"},
        )

        assert decision.action == GuardAction.allow
        assert decision.reason == "allow"
