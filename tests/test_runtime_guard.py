"""Tests for RuntimeGuard — Day 3."""

from __future__ import annotations

from agent_reliability_harness.runtime_guard import GuardDecision, RuntimeGuard
from agent_reliability_harness.spec import GuardAction, PolicySpec, ToolRiskLevel


def _make_policy(**overrides) -> PolicySpec:
    """Create a PolicySpec with sensible defaults, allowing field overrides."""
    defaults = {
        "allowed_models": ["gpt-4o", "claude-3-sonnet"],
        "max_token_budget": 10000,
        "max_tool_risk_level": ToolRiskLevel.low,
        "require_answer_verification": False,
    }
    defaults.update(overrides)
    return PolicySpec(**defaults)


class TestCheckModel:
    """RuntimeGuard.check_model tests."""

    def test_allowed_model_returns_allow(self) -> None:
        guard = RuntimeGuard()
        decision = guard.check_model("gpt-4o", _make_policy())
        assert decision.action == GuardAction.allow
        assert isinstance(decision, GuardDecision)

    def test_disallowed_model_returns_deny(self) -> None:
        guard = RuntimeGuard()
        decision = guard.check_model("gpt-4o-mini", _make_policy())
        assert decision.action == GuardAction.deny
        assert "gpt-4o-mini" in decision.reason

    def test_deny_reason_mentions_allowed_list(self) -> None:
        guard = RuntimeGuard()
        decision = guard.check_model("unknown-model", _make_policy())
        assert decision.action == GuardAction.deny
        assert "gpt-4o" in decision.reason  # mentions allowed models

    def test_check_type_is_model(self) -> None:
        guard = RuntimeGuard()
        decision = guard.check_model("gpt-4o", _make_policy())
        assert decision.check_type == "model"


class TestCheckBudget:
    """RuntimeGuard.check_budget tests."""

    def test_within_budget_returns_allow(self) -> None:
        guard = RuntimeGuard()
        policy = _make_policy(max_token_budget=1000)
        decision = guard.check_budget(500, policy)
        assert decision.action == GuardAction.allow

    def test_exactly_at_budget_returns_allow(self) -> None:
        guard = RuntimeGuard()
        policy = _make_policy(max_token_budget=1000)
        decision = guard.check_budget(1000, policy)
        assert decision.action == GuardAction.allow

    def test_exceeded_budget_returns_deny(self) -> None:
        guard = RuntimeGuard()
        policy = _make_policy(max_token_budget=1000)
        decision = guard.check_budget(1001, policy)
        assert decision.action == GuardAction.deny

    def test_deny_reason_contains_token_counts(self) -> None:
        guard = RuntimeGuard()
        policy = _make_policy(max_token_budget=500)
        decision = guard.check_budget(800, policy)
        assert "800" in decision.reason
        assert "500" in decision.reason

    def test_check_type_is_budget(self) -> None:
        guard = RuntimeGuard()
        decision = guard.check_budget(100, _make_policy())
        assert decision.check_type == "budget"


class TestCheckFinalAnswerVerified:
    """RuntimeGuard.check_final_answer_verified tests."""

    def test_verification_not_required_allows_unverified(self) -> None:
        guard = RuntimeGuard()
        policy = _make_policy(require_answer_verification=False)
        decision = guard.check_final_answer_verified(False, policy)
        assert decision.action == GuardAction.allow

    def test_verification_not_required_allows_verified(self) -> None:
        guard = RuntimeGuard()
        policy = _make_policy(require_answer_verification=False)
        decision = guard.check_final_answer_verified(True, policy)
        assert decision.action == GuardAction.allow

    def test_verification_required_and_verified_allows(self) -> None:
        guard = RuntimeGuard()
        policy = _make_policy(require_answer_verification=True)
        decision = guard.check_final_answer_verified(True, policy)
        assert decision.action == GuardAction.allow

    def test_verification_required_and_not_verified_denies(self) -> None:
        guard = RuntimeGuard()
        policy = _make_policy(require_answer_verification=True)
        decision = guard.check_final_answer_verified(False, policy)
        assert decision.action == GuardAction.deny

    def test_deny_reason_mentions_verification(self) -> None:
        guard = RuntimeGuard()
        policy = _make_policy(require_answer_verification=True)
        decision = guard.check_final_answer_verified(False, policy)
        assert "verification" in decision.reason.lower()

    def test_check_type_is_answer_verification(self) -> None:
        guard = RuntimeGuard()
        decision = guard.check_final_answer_verified(True, _make_policy())
        assert decision.check_type == "answer_verification"
