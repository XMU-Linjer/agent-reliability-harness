"""
Spec definitions for AgentReliabilityHarness.

This module defines all core data structures used across the framework:
- Enums: FailureType, EventType, ToolRiskLevel, GuardAction
- Pydantic models: ScenarioSpec, AgentRunSpec, PolicySpec, etc.
- Loaders: load_scenario(), load_scenarios()
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

import yaml
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
    tool_call = "tool_call"
    tool_result = "tool_result"
    guard_check = "guard_check"
    guard_decision = "guard_decision"
    firewall_check = "firewall_check"
    firewall_decision = "firewall_decision"
    fault_injected = "fault_injected"
    failure_classified = "failure_classified"


class ToolRiskLevel(str, Enum):
    """Tool risk level for ToolFirewall decisions."""

    safe = "safe"
    low = "low"
    high = "high"
    critical = "critical"


class GuardAction(str, Enum):
    """Guard / Firewall decision action."""

    allow = "allow"
    deny = "deny"
    warn = "warn"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class MockToolCall(BaseModel):
    """A single mock tool call within a MockResponse."""

    tool: str
    arguments: dict[str, Any] = {}


class MockResponse(BaseModel):
    """A pre-configured LLM response for mock execution."""

    content: str
    tool_calls: list[MockToolCall] = []
    finish_reason: str | None = None
    total_tokens: int = 0


class FaultInjectionSpec(BaseModel):
    """Configuration for a single fault injection point."""

    type: str
    target: str | None = None
    payload: dict[str, Any] = {}


class AgentRunSpec(BaseModel):
    """Agent execution parameters."""

    model: str
    provider: str = "mock"
    tools: list[str]
    max_steps: int
    task: str
    mock_responses: list[MockResponse] = []

    @field_validator("max_steps")
    @classmethod
    def max_steps_must_be_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("max_steps must be > 0")
        return v


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
    def check_tools_mutual_exclusion(self) -> PolicySpec:
        if self.allowed_tools is not None and self.denied_tools is not None:
            raise ValueError(
                "allowed_tools and denied_tools must not be configured simultaneously"
            )
        return self


class ScenarioSpec(BaseModel):
    """Top-level scenario definition — the primary input unit for ARH."""

    id: str
    name: str
    description: str
    agent_run: AgentRunSpec
    policy: PolicySpec
    fault_injection: FaultInjectionSpec | None = None
    expected_failure: FailureType
    expected_events: list[EventType] = []
    pass_criteria: str


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def load_scenario(path: str | Path) -> ScenarioSpec:
    """Load a single scenario from a YAML file.

    Args:
        path: Path to the YAML scenario file.

    Returns:
        Parsed and validated ScenarioSpec.

    Raises:
        FileNotFoundError: If the file does not exist.
        yaml.YAMLError: If the file is not valid YAML.
        pydantic.ValidationError: If the data does not match ScenarioSpec.
    """
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return ScenarioSpec(**data)


def load_scenarios(directory: str | Path) -> list[ScenarioSpec]:
    """Load all scenarios from a directory, sorted by filename for deterministic order.

    Args:
        directory: Path to the directory containing YAML scenario files.

    Returns:
        List of parsed ScenarioSpec objects, sorted by source filename.

    Raises:
        FileNotFoundError: If the directory does not exist.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        raise FileNotFoundError(f"Directory not found: {dir_path}")

    yaml_files = sorted(
        p for p in dir_path.iterdir() if p.suffix in (".yaml", ".yml") and p.is_file()
    )

    return [load_scenario(f) for f in yaml_files]
