"""
RuntimeGuard for AgentReliabilityHarness.

Performs pre-execution policy checks:
- Model allowlist validation
- Token budget enforcement
- Answer verification requirement

All checks return a GuardDecision with an action (allow/deny) and a reason.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_reliability_harness.spec import GuardAction, PolicySpec


@dataclass(frozen=True)
class GuardDecision:
    """Result of a RuntimeGuard policy check.

    Attributes:
        action: The guard action — allow, deny, or warn.
        reason: Human-readable explanation including evidence.
        check_type: Which check produced this decision (model, budget, answer_verification).
    """

    action: GuardAction
    reason: str
    check_type: str


class RuntimeGuard:
    """Evaluates agent runtime parameters against a PolicySpec.

    Usage::

        guard = RuntimeGuard()
        decision = guard.check_model("gpt-4o-mini", policy)
        if decision.action == GuardAction.deny:
            # block the run
    """

    def check_model(self, model: str, policy: PolicySpec) -> GuardDecision:
        """Check whether the requested model is permitted by policy.

        Args:
            model: The model identifier the agent wants to use.
            policy: The active PolicySpec.

        Returns:
            GuardDecision with allow if model is in allowed_models, deny otherwise.
        """
        if model not in policy.allowed_models:
            return GuardDecision(
                action=GuardAction.deny,
                reason=(
                    f"Model '{model}' is not in the allowed models list. "
                    f"Allowed models: {policy.allowed_models}"
                ),
                check_type="model",
            )
        return GuardDecision(
            action=GuardAction.allow,
            reason=f"Model '{model}' is permitted by policy.",
            check_type="model",
        )

    def check_budget(self, used_tokens: int, policy: PolicySpec) -> GuardDecision:
        """Check whether token usage is within the budget limit.

        Args:
            used_tokens: Cumulative tokens consumed so far.
            policy: The active PolicySpec.

        Returns:
            GuardDecision with allow if within budget, deny if exceeded.
        """
        if used_tokens > policy.max_token_budget:
            return GuardDecision(
                action=GuardAction.deny,
                reason=(
                    f"Token budget exceeded: used {used_tokens} tokens, "
                    f"budget is {policy.max_token_budget}."
                ),
                check_type="budget",
            )
        return GuardDecision(
            action=GuardAction.allow,
            reason=(
                f"Token usage {used_tokens}/{policy.max_token_budget} is within budget."
            ),
            check_type="budget",
        )

    def check_final_answer_verified(
        self, verified: bool, policy: PolicySpec
    ) -> GuardDecision:
        """Check whether the final answer verification requirement is met.

        Args:
            verified: Whether the final answer has been verified.
            policy: The active PolicySpec.

        Returns:
            GuardDecision with deny if verification is required but not done.
        """
        if policy.require_answer_verification and not verified:
            return GuardDecision(
                action=GuardAction.deny,
                reason=(
                    "Answer verification is required by policy but the final "
                    "answer has not been verified."
                ),
                check_type="answer_verification",
            )
        return GuardDecision(
            action=GuardAction.allow,
            reason="Answer verification check passed.",
            check_type="answer_verification",
        )
