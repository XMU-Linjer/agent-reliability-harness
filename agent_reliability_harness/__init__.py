# Agent Reliability Harness - Python Package
"""
AgentReliabilityHarness: offline-first Agent Runtime reliability benchmark framework.

Spec + Guard + Fault Injection + Trace + Scorecard for reproducing
and classifying multi-agent runtime failures.
"""

__version__ = "0.1.0"

from agent_reliability_harness.benchmark_runner import BenchmarkRunner, BenchmarkRunResult
from agent_reliability_harness.failure_classifier import FailureClassifier
from agent_reliability_harness.fault_injector import (
    FaultInjectionResult,
    FaultInjector,
    ProviderTimeoutInjected,
)
from agent_reliability_harness.mock_llm import MockLLMProvider, MockLLMResponseExhausted
from agent_reliability_harness.runner import (
    run_scenario_day2,
    run_scenario_day3,
    run_scenario_day4,
    run_scenario_day5,
)
from agent_reliability_harness.runtime_guard import GuardDecision, RuntimeGuard
from agent_reliability_harness.scorecard import ScorecardGenerator
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
from agent_reliability_harness.tool_firewall import ToolFirewall
from agent_reliability_harness.tools import (
    FakeTool,
    ToolMetadata,
    ToolNotFoundError,
    ToolResult,
    get_tool,
    list_tools,
)
from agent_reliability_harness.trace_logger import TraceEventRecord, TraceLogger

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
    # Runner (Day 2 + Day 3 + Day 4 + Day 5)
    "run_scenario_day2",
    "run_scenario_day3",
    "run_scenario_day4",
    "run_scenario_day5",
    # RuntimeGuard (Day 3)
    "GuardDecision",
    "RuntimeGuard",
    # ToolFirewall (Day 3)
    "ToolFirewall",
    # FaultInjector (Day 4)
    "FaultInjectionResult",
    "FaultInjector",
    "ProviderTimeoutInjected",
    # TraceLogger + FailureClassifier (Day 5)
    "TraceEventRecord",
    "TraceLogger",
    "FailureClassifier",
    # BenchmarkRunner + ScorecardGenerator (Day 6)
    "BenchmarkRunner",
    "BenchmarkRunResult",
    "ScorecardGenerator",
]
