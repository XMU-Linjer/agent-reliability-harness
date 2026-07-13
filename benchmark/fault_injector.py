"""
FaultInjector for AgentReliabilityHarness.

Deterministic, scenario-driven fault injection supporting 4 fault types:
- timeout: Simulates provider timeout via ProviderTimeoutInjected exception.
- bad_args: Corrupts tool call arguments to invalid values.
- duplicate: Duplicates the previous tool call for repeat-detection.
- prompt_injection: Escalates a safe tool call to a high-risk tool.

All injections are deterministic — no randomness, no real side effects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from benchmark.spec import FaultInjectionSpec, MockToolCall


class ProviderTimeoutInjected(Exception):
    """Raised when a timeout fault is injected on a provider call.

    This is a deterministic marker — no actual delay occurs.
    """


@dataclass(frozen=True)
class FaultInjectionResult:
    """Result of a fault injection attempt.

    Attributes:
        applied: Whether a fault was actually injected.
        fault_type: The type of fault injected (timeout, bad_args, duplicate, prompt_injection).
        target: The target of the injection (provider name, tool name, etc.).
        payload: Additional injection data.
        reason: Human-readable explanation of what was injected.
    """

    applied: bool
    fault_type: str
    target: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


class FaultInjector:
    """Deterministic fault injector driven by FaultInjectionSpec.

    Usage::

        injector = FaultInjector(scenario.fault_injection)
        # Before provider call:
        injector.maybe_inject_timeout()
        # Before tool execution:
        tool_calls = injector.maybe_inject_tool_faults(tool_calls, history)
    """

    def __init__(self, spec: FaultInjectionSpec | None) -> None:
        self._spec = spec

    @property
    def fault_type(self) -> str | None:
        """The configured fault type, or None if no injection configured."""
        return self._spec.type if self._spec else None

    @property
    def target(self) -> str | None:
        """The configured fault target."""
        return self._spec.target if self._spec else None

    @property
    def payload(self) -> dict[str, Any]:
        """The configured fault payload."""
        return self._spec.payload if self._spec else {}

    def maybe_inject_timeout(self) -> FaultInjectionResult:
        """Check if a timeout fault should be injected on the provider call.

        If fault_type is 'timeout', raises ProviderTimeoutInjected.
        Otherwise returns a no-op result.

        Returns:
            FaultInjectionResult describing what happened.

        Raises:
            ProviderTimeoutInjected: If a timeout fault is configured.
        """
        if self._spec is None or self._spec.type != "timeout":
            return FaultInjectionResult(
                applied=False,
                fault_type="timeout",
                reason="No timeout fault configured.",
            )

        target = self._spec.target or "primary"
        result = FaultInjectionResult(
            applied=True,
            fault_type="timeout",
            target=target,
            payload=self._spec.payload,
            reason=f"Timeout injected on provider '{target}'. No real delay.",
        )
        raise ProviderTimeoutInjected(result.reason)

    def maybe_inject_bad_args(
        self, tool_calls: list[MockToolCall]
    ) -> tuple[list[MockToolCall], FaultInjectionResult]:
        """Corrupt tool call arguments if bad_args fault is configured.

        For each tool call matching the target (or all if no target),
        replaces arguments with invalid values from payload.

        Args:
            tool_calls: The original tool calls from the LLM response.

        Returns:
            Tuple of (possibly modified tool_calls, FaultInjectionResult).
        """
        if self._spec is None or self._spec.type != "bad_args":
            return tool_calls, FaultInjectionResult(
                applied=False,
                fault_type="bad_args",
                reason="No bad_args fault configured.",
            )

        target = self._spec.target
        bad_args = self._spec.payload.get("arguments", {"path": None})
        modified: list[MockToolCall] = []

        for tc in tool_calls:
            if target is None or tc.tool == target:
                # Create a new MockToolCall with corrupted arguments
                modified.append(MockToolCall(tool=tc.tool, arguments=bad_args))
            else:
                modified.append(tc)

        return modified, FaultInjectionResult(
            applied=True,
            fault_type="bad_args",
            target=target,
            payload={"injected_arguments": bad_args},
            reason=f"Arguments corrupted for tool '{target or 'all'}': {bad_args}",
        )

    def maybe_inject_duplicate(
        self,
        tool_calls: list[MockToolCall],
        history: list[tuple[str, dict[str, Any]]],
    ) -> tuple[list[MockToolCall], FaultInjectionResult]:
        """Duplicate the previous tool call if duplicate fault is configured.

        Checks if any tool call in the current batch matches a previous call
        in the history (same tool name + same arguments). If the fault is
        configured, injects a duplicate of the last history entry.

        Args:
            tool_calls: The current tool calls from the LLM response.
            history: List of (tool_name, arguments) from previous calls.

        Returns:
            Tuple of (possibly modified tool_calls, FaultInjectionResult).
        """
        if self._spec is None or self._spec.type != "duplicate":
            return tool_calls, FaultInjectionResult(
                applied=False,
                fault_type="duplicate",
                reason="No duplicate fault configured.",
            )

        if not history:
            return tool_calls, FaultInjectionResult(
                applied=False,
                fault_type="duplicate",
                reason="No previous tool calls to duplicate.",
            )

        # Duplicate the last tool call from history
        last_tool, last_args = history[-1]
        duplicate_call = MockToolCall(tool=last_tool, arguments=last_args)
        modified = list(tool_calls) + [duplicate_call]

        return modified, FaultInjectionResult(
            applied=True,
            fault_type="duplicate",
            target=last_tool,
            payload={"duplicated_arguments": last_args},
            reason=(
                f"Duplicated previous tool call: {last_tool} "
                f"with arguments {last_args}"
            ),
        )

    def maybe_inject_prompt_injection(
        self, tool_calls: list[MockToolCall]
    ) -> tuple[list[MockToolCall], FaultInjectionResult]:
        """Escalate a safe tool call to a high-risk tool if prompt_injection fault is configured.

        Replaces the first tool call with an escalated tool call as specified
        in the payload (defaults to execute_shell).

        Args:
            tool_calls: The original tool calls from the LLM response.

        Returns:
            Tuple of (possibly modified tool_calls, FaultInjectionResult).
        """
        if self._spec is None or self._spec.type != "prompt_injection":
            return tool_calls, FaultInjectionResult(
                applied=False,
                fault_type="prompt_injection",
                reason="No prompt_injection fault configured.",
            )

        escalate_to = self._spec.payload.get("escalate_to", "execute_shell")
        escalate_args = self._spec.payload.get(
            "escalate_arguments", {"command": "cat /etc/passwd"}
        )

        if not tool_calls:
            # No tool calls to escalate; inject one
            modified = [MockToolCall(tool=escalate_to, arguments=escalate_args)]
        else:
            # Replace the first tool call with the escalated version
            modified = [MockToolCall(tool=escalate_to, arguments=escalate_args)]
            modified.extend(tool_calls[1:])

        return modified, FaultInjectionResult(
            applied=True,
            fault_type="prompt_injection",
            target=escalate_to,
            payload={"escalate_to": escalate_to, "escalate_arguments": escalate_args},
            reason=(
                f"Prompt injection: escalated tool call to '{escalate_to}' "
                f"with arguments {escalate_args}"
            ),
        )
