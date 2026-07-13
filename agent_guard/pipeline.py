"""
GuardPipeline — the main entry point for AgentGuard SDK.

Wires together all three guard layers, trace logging, and optional
sandbox execution into a single call interface for embedding into
any Agent application.

Usage::

    from agent_guard import GuardPipeline

    pipeline = GuardPipeline(policy=my_policy)
    result = pipeline.check("execute_shell", {"command": "rm -rf /"})
    if result.denied:
        raise PermissionError(result.reason_zh)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_guard.guards.argument_guard import ArgumentGuard, ArgumentGuardDecision
from agent_guard.guards.runtime_guard import GuardDecision, RuntimeGuard
from agent_guard.guards.tool_firewall import ToolFirewall
from agent_guard.spec import EventType, FailureType, GuardAction, PolicySpec
from agent_guard.trace.failure_classifier import FailureClassifier
from agent_guard.trace.trace_logger import TraceEventRecord, TraceLogger


@dataclass
class GuardResult:
    """Result of a GuardPipeline check.

    Attributes:
        allowed: Whether the tool call is permitted.
        decision_type: Which guard made the final decision (runtime_guard, tool_firewall, argument_guard).
        reason: Machine-readable reason code.
        reason_zh: Human-readable reason in Chinese.
        reason_en: Human-readable reason in English.
        evidence: Additional evidence about the decision.
    """

    allowed: bool
    decision_type: str
    reason: str
    reason_zh: str = ""
    reason_en: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def denied(self) -> bool:
        """True if the check was denied."""
        return not self.allowed


class GuardPipeline:
    """One-stop guard pipeline: check → trace → (optional) execute.

    Args:
        policy: Runtime policy configuration.
        tool_risks: Optional custom tool risk level mapping.
        trace_dir: Optional directory for trace output. If provided,
            each check writes to a trace.jsonl file.
        sandbox: Optional sandbox executor for safe tool execution.
    """

    def __init__(
        self,
        policy: PolicySpec,
        tool_risks: dict[str, Any] | None = None,
        trace_dir: str | Path | None = None,
        sandbox: Any | None = None,
    ) -> None:
        self.policy = policy
        self._runtime_guard = RuntimeGuard()
        self._firewall = ToolFirewall(tool_risks=tool_risks)
        self._argument_guard = ArgumentGuard()
        self._classifier = FailureClassifier()
        self._sandbox = sandbox

        self._trace_logger: TraceLogger | None = None
        self._run_id: str = ""
        if trace_dir is not None:
            trace_path = Path(trace_dir) / "trace.jsonl"
            self._trace_logger = TraceLogger(trace_path)
            self._run_id = uuid.uuid4().hex[:12]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        used_tokens: int = 0,
        model: str | None = None,
    ) -> GuardResult:
        """Run all three guard layers against a proposed tool call.

        This is the primary method you should call before executing
        any tool in your Agent.

        Args:
            tool_name: Name of the tool being called (e.g. "execute_shell").
            arguments: Tool arguments.
            used_tokens: Cumulative token usage so far (for budget check).
            model: Model identifier (for model allowlist check).

        Returns:
            GuardResult with allowed=True if all guards pass.
        """
        step = 0

        def _trace(
            event_type: EventType,
            module: str,
            data: dict[str, Any] | None = None,
            error: str | None = None,
        ) -> None:
            if self._trace_logger is not None:
                self._trace_logger.log(TraceEventRecord(
                    run_id=self._run_id,
                    scenario_id="pipeline",
                    step=step,
                    event_type=event_type,
                    module=module,
                    data=data or {},
                    error=error,
                ))

        # Layer 1: RuntimeGuard — model check (if model provided)
        if model is not None:
            decision = self._runtime_guard.check_model(model, self.policy)
            _trace(EventType.runtime_guard_decision, "runtime_guard", {
                "action": decision.action.value,
                "reason": decision.reason,
                "check_type": decision.check_type,
            })
            if decision.action == GuardAction.deny:
                return GuardResult(
                    allowed=False,
                    decision_type="runtime_guard",
                    reason=decision.reason,
                    reason_zh=decision.reason,
                    reason_en=decision.reason,
                )

        # Layer 1b: RuntimeGuard — budget check
        if used_tokens > 0:
            decision = self._runtime_guard.check_budget(used_tokens, self.policy)
            _trace(EventType.runtime_guard_decision, "runtime_guard", {
                "action": decision.action.value,
                "reason": decision.reason,
                "check_type": decision.check_type,
            })
            if decision.action == GuardAction.deny:
                return GuardResult(
                    allowed=False,
                    decision_type="runtime_guard",
                    reason=decision.reason,
                    reason_zh=decision.reason,
                    reason_en=decision.reason,
                )

        # Layer 2: ToolFirewall
        fw_decision = self._firewall.check_tool_call(tool_name, arguments, self.policy)
        _trace(EventType.firewall_decision, "tool_firewall", {
            "action": fw_decision.action.value,
            "reason": fw_decision.reason,
            "check_type": fw_decision.check_type,
            "tool": tool_name,
        })
        if fw_decision.action == GuardAction.deny:
            return GuardResult(
                allowed=False,
                decision_type="tool_firewall",
                reason=fw_decision.reason,
                reason_zh=fw_decision.reason,
                reason_en=fw_decision.reason,
            )

        # Layer 3: ArgumentGuard
        arg_decision = self._argument_guard.check_tool_call(tool_name, arguments)
        _trace(EventType.argument_guard_decision, "argument_guard", {
            "action": arg_decision.action.value,
            "reason": arg_decision.reason,
            "check_type": arg_decision.check_type,
            "tool": tool_name,
        })
        if arg_decision.action == GuardAction.deny:
            return GuardResult(
                allowed=False,
                decision_type="argument_guard",
                reason=arg_decision.reason,
                reason_zh=arg_decision.reason_zh,
                reason_en=arg_decision.reason_en,
                evidence=arg_decision.evidence,
            )

        return GuardResult(
            allowed=True,
            decision_type="all",
            reason="allow",
            reason_zh="所有检查通过",
            reason_en="All checks passed",
        )

    def check_and_execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        used_tokens: int = 0,
        model: str | None = None,
    ) -> Any:
        """Check and (if allowed) execute a tool call through the sandbox.

        Args:
            tool_name: Name of the tool to execute.
            arguments: Tool arguments.
            used_tokens: Cumulative token usage (for budget check).
            model: Model identifier.

        Returns:
            Tool execution result, or GuardResult if denied.
        """
        result = self.check(tool_name, arguments, used_tokens=used_tokens, model=model)
        if result.denied:
            return result

        if self._sandbox is not None:
            return self._sandbox.execute(tool_name, arguments)

        return result

    def flush_trace(self) -> str | None:
        """Write accumulated trace events to disk.

        Returns:
            Path to the trace file, or None if tracing is disabled.
        """
        if self._trace_logger is not None:
            return str(self._trace_logger.flush())
        return None

    def classify_failure(self) -> FailureType:
        """Classify the current run based on trace evidence.

        Returns:
            FailureType from the trace event evidence.
        """
        if self._trace_logger is None:
            return FailureType.none
        return self._classifier.classify(self._trace_logger.events)