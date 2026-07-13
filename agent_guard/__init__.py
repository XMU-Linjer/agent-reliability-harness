"""
AgentGuard SDK — Runtime safety guard library for AI Agents.

Provides a non-invasive guard pipeline that intercepts tool calls
before execution, checking model permissions, tool policies, and
argument safety.

Usage::

    from agent_guard import GuardPipeline

    pipeline = GuardPipeline(policy=my_policy)
    result = pipeline.check("execute_shell", {"command": "rm -rf /"})
    if result.denied:
        raise PermissionError(result.reason_zh)
"""

from agent_guard.pipeline import GuardPipeline, GuardResult
from agent_guard.spec import (
    EventType,
    FailureType,
    GuardAction,
    PolicySpec,
    ToolRiskLevel,
)
from agent_guard.guards import (
    ArgumentGuard,
    ArgumentGuardDecision,
    GuardDecision,
    RuntimeGuard,
    ToolFirewall,
)
from agent_guard.trace import FailureClassifier, TraceEventRecord, TraceLogger
from agent_guard.sandbox import LocalSandboxToolExecutor

__version__ = "0.2.0"

__all__ = [
    # Pipeline
    "GuardPipeline",
    "GuardResult",
    # Spec
    "EventType",
    "FailureType",
    "GuardAction",
    "PolicySpec",
    "ToolRiskLevel",
    # Guards
    "ArgumentGuard",
    "ArgumentGuardDecision",
    "GuardDecision",
    "RuntimeGuard",
    "ToolFirewall",
    # Trace
    "FailureClassifier",
    "TraceEventRecord",
    "TraceLogger",
    # Sandbox
    "LocalSandboxToolExecutor",
]
