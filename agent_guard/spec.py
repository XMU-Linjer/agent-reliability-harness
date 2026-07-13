"""
Core data structures for AgentGuard SDK.

Minimal spec — only what the SDK needs at runtime.
Benchmark-specific types (MockResponse, FaultInjectionSpec, etc.) live in benchmark/spec.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FailureType(str, Enum):
    """Agent runtime failure classification."""

    none = "none"
    policy_violation = "policy_violation"
    budget_exceeded = "budget_exceeded"
    provider_timeout = "provider_timeout"
    tool_blocked = "tool_blocked"
    permission_denied = "permission_denied"
    prompt_injection = "prompt_injection"
    invalid_arguments = "invalid_arguments"
    duplicate_execution = "duplicate_execution"
    unverified_answer = "unverified_answer"


class EventType(str, Enum):
    """Trace event type."""

    agent_start = "agent_start"
    agent_end = "agent_end"
    llm_request = "llm_request"
    llm_response = "llm_response"
    final_answer = "final_answer"
    tool_call = "tool_call"
    tool_result = "tool_result"
    guard_check = "guard_check"
    guard_decision = "guard_decision"
    runtime_guard_check = "runtime_guard_check"
    runtime_guard_decision = "runtime_guard_decision"
    firewall_check = "firewall_check"
    firewall_decision = "firewall_decision"
    argument_guard_check = "argument_guard_check"
    argument_guard_decision = "argument_guard_decision"
    tool_execution_skipped = "tool_execution_skipped"
    fault_injected = "fault_injected"
    failure_classified = "failure_classified"


class ToolRiskLevel(str, Enum):
    """Tool risk level for ToolFirewall decisions."""

    safe = "safe"
    low = "low"
    high = "high"
    critical = "critical"


class GuardAction(str, Enum):
    """Guard / Firewall / ArgumentGuard decision action."""

    allow = "allow"
    deny = "deny"
    warn = "warn"


# ---------------------------------------------------------------------------
# Pydantic models (SDK-essential only)
# ---------------------------------------------------------------------------


class PolicySpec(BaseModel):
    """Runtime policy rules for Guard and Firewall."""

    allowed_models: list[str]
    max_token_budget: int
    max_tool_risk_level: ToolRiskLevel
    allowed_tools: list[str] | None = None
    denied_tools: list[str] | None = None
    require_answer_verification: bool = False

    @field_validator("max_token_budget")
    @classmethod
    def max_token_budget_must_be_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("max_token_budget must be > 0")
        return v

    @field_validator("allowed_models")
    @classmethod
    def allowed_models_must_not_be_empty(cls, v: list[str]) -> list[str]:
        if len(v) == 0:
            raise ValueError("allowed_models must not be empty")
        return v

    @model_validator(mode="after")
    def check_tools_mutual_exclusion(self) -> "PolicySpec":
        if self.allowed_tools is not None and self.denied_tools is not None:
            raise ValueError(
                "allowed_tools and denied_tools must not be configured simultaneously"
            )
        return self