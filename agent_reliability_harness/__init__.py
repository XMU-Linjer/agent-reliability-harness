# Agent Reliability Harness - Python Package
"""
AgentReliabilityHarness: offline-first Agent Runtime reliability benchmark framework.

Spec + Guard + Fault Injection + Trace + Scorecard for reproducing
and classifying multi-agent runtime failures.
"""

__version__ = "0.1.0"

from agent_reliability_harness.mock_llm import MockLLMProvider, MockLLMResponseExhausted
from agent_reliability_harness.runner import run_scenario_day2
from agent_reliability_harness.spec import (
    AgentRunSpec,
    EventType,
    FailureType,
    FaultInjectionSpec,
    GuardAction,
    MockResponse,
    MockToolCall,
    PolicySpec,
    ScenarioSpec,
    ToolRiskLevel,
    load_scenario,
    load_scenarios,
)
from agent_reliability_harness.tools import (
    FakeTool,
    ToolMetadata,
    ToolNotFoundError,
    ToolResult,
    get_tool,
    list_tools,
)

__all__ = [
    # Spec (Day 1)
    "AgentRunSpec",
    "EventType",
    "FailureType",
    "FaultInjectionSpec",
    "GuardAction",
    "MockResponse",
    "MockToolCall",
    "PolicySpec",
    "ScenarioSpec",
    "ToolRiskLevel",
    "load_scenario",
    "load_scenarios",
    # Mock LLM (Day 2)
    "MockLLMProvider",
    "MockLLMResponseExhausted",
    # Tools (Day 2)
    "FakeTool",
    "ToolMetadata",
    "ToolNotFoundError",
    "ToolResult",
    "get_tool",
    "list_tools",
    # Runner (Day 2)
    "run_scenario_day2",
]
