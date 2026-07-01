"""
Scenario runners for AgentReliabilityHarness.

- run_scenario_day2: Minimal mock execution loop (Day 2).
- run_scenario_day3: Adds RuntimeGuard + ToolFirewall checks (Day 3).
- run_scenario_day4: Adds FaultInjector for fault injection scenarios (Day 4).
- run_scenario_day5: Adds TraceLogger + FailureClassifier (Day 5).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from agent_reliability_harness.argument_guard import ArgumentGuard
from agent_reliability_harness.failure_classifier import FailureClassifier
from agent_reliability_harness.fault_injector import (
    FaultInjectionResult,
    FaultInjector,
    ProviderTimeoutInjected,
)
from agent_reliability_harness.mock_llm import MockLLMProvider
from agent_reliability_harness.runtime_guard import RuntimeGuard
from agent_reliability_harness.spec import (
    EventType,
    GuardAction,
    MockToolCall,
    ScenarioSpec,
)
from agent_reliability_harness.tool_firewall import ToolFirewall
from agent_reliability_harness.tools import ToolResult, get_tool
from agent_reliability_harness.trace_logger import TraceEventRecord, TraceLogger


def run_scenario_day2(scenario: ScenarioSpec) -> dict[str, Any]:
    """Run a scenario through the minimal Day 2 mock execution loop.

    Flow:
        1. Create MockLLMProvider from scenario's mock_responses.
        2. Loop: call provider.chat(), execute any tool_calls via fake tools.
        3. Stop when finish_reason == "stop", responses exhausted, or max_steps reached.
        4. Return a summary dict.

    Args:
        scenario: A fully loaded ScenarioSpec.

    Returns:
        Dict with keys: scenario_id, status, final_content, tool_results, steps.
    """
    provider = MockLLMProvider(scenario.agent_run.mock_responses)
    tool_results: list[dict[str, Any]] = []
    final_content: str = ""
    steps = 0

    for _ in range(scenario.agent_run.max_steps):
        if provider.remaining == 0:
            break

        response = provider.chat()
        steps += 1
        final_content = response.content

        # Execute any tool calls in the response
        for tc in response.tool_calls:
            tool = get_tool(tc.tool)
            result: ToolResult = tool.execute(tc.arguments)
            tool_results.append({
                "tool": result.tool,
                "success": result.success,
                "output": result.output,
                "error": result.error,
            })

        # Stop if the model signals completion
        if response.finish_reason == "stop":
            break

    return {
        "scenario_id": scenario.id,
        "status": "passed",
        "final_content": final_content,
        "tool_results": tool_results,
        "steps": steps,
    }


def run_scenario_day3(scenario: ScenarioSpec) -> dict[str, Any]:
    """Run a scenario with RuntimeGuard and ToolFirewall enforcement.

    Flow:
        1. RuntimeGuard.check_model — block if model is not allowed.
        2. Loop through MockLLMProvider responses:
           a. Accumulate total_tokens, check budget via RuntimeGuard.
           b. For each tool_call, check via ToolFirewall before execution.
           c. If any check denies, return immediately with blocked/failed status.
        3. If all checks pass, return status="passed".

    Args:
        scenario: A fully loaded ScenarioSpec.

    Returns:
        Dict with keys: scenario_id, status, failure_type, guard_decisions,
        firewall_decisions, tool_results, final_content, steps.
    """
    guard = RuntimeGuard()
    firewall = ToolFirewall()
    policy = scenario.policy

    guard_decisions: list[dict[str, Any]] = []
    firewall_decisions: list[dict[str, Any]] = []
    tool_results: list[dict[str, Any]] = []
    final_content: str = ""
    steps = 0
    used_tokens = 0

    def _decision_dict(decision: Any) -> dict[str, Any]:
        return {
            "action": decision.action.value,
            "reason": decision.reason,
            "check_type": decision.check_type,
        }

    # --- Pre-flight: model check ---
    model_decision = guard.check_model(scenario.agent_run.model, policy)
    guard_decisions.append(_decision_dict(model_decision))
    if model_decision.action == GuardAction.deny:
        return {
            "scenario_id": scenario.id,
            "status": "blocked",
            "failure_type": "policy_violation",
            "guard_decisions": guard_decisions,
            "firewall_decisions": firewall_decisions,
            "tool_results": tool_results,
            "final_content": final_content,
            "steps": steps,
        }

    # --- Main loop ---
    provider = MockLLMProvider(scenario.agent_run.mock_responses)

    for _ in range(scenario.agent_run.max_steps):
        if provider.remaining == 0:
            break

        response = provider.chat()
        steps += 1
        final_content = response.content
        used_tokens += response.total_tokens

        # Budget check after each LLM response
        budget_decision = guard.check_budget(used_tokens, policy)
        guard_decisions.append(_decision_dict(budget_decision))
        if budget_decision.action == GuardAction.deny:
            return {
                "scenario_id": scenario.id,
                "status": "blocked",
                "failure_type": "budget_exceeded",
                "guard_decisions": guard_decisions,
                "firewall_decisions": firewall_decisions,
                "tool_results": tool_results,
                "final_content": final_content,
                "steps": steps,
            }

        # Tool call checks
        for tc in response.tool_calls:
            fw_decision = firewall.check_tool_call(tc.tool, tc.arguments, policy)
            firewall_decisions.append(_decision_dict(fw_decision))

            if fw_decision.action == GuardAction.deny:
                # Determine failure_type based on check_type
                if fw_decision.check_type == "firewall_allowed_tools":
                    failure_type = "permission_denied"
                elif fw_decision.check_type == "firewall_risk_level":
                    failure_type = "tool_blocked"
                elif fw_decision.check_type == "firewall_denied_tools":
                    failure_type = "tool_blocked"
                else:
                    failure_type = "tool_blocked"

                return {
                    "scenario_id": scenario.id,
                    "status": "blocked",
                    "failure_type": failure_type,
                    "guard_decisions": guard_decisions,
                    "firewall_decisions": firewall_decisions,
                    "tool_results": tool_results,
                    "final_content": final_content,
                    "steps": steps,
                }

            # Firewall allowed — execute the fake tool
            tool = get_tool(tc.tool)
            result: ToolResult = tool.execute(tc.arguments)
            tool_results.append({
                "tool": result.tool,
                "success": result.success,
                "output": result.output,
                "error": result.error,
            })

        # Stop if the model signals completion
        if response.finish_reason == "stop":
            break

    return {
        "scenario_id": scenario.id,
        "status": "passed",
        "failure_type": "none",
        "guard_decisions": guard_decisions,
        "firewall_decisions": firewall_decisions,
        "tool_results": tool_results,
        "final_content": final_content,
        "steps": steps,
    }


def run_scenario_day4(scenario: ScenarioSpec) -> dict[str, Any]:
    """Run a scenario with RuntimeGuard, ToolFirewall, and FaultInjector.

    Flow:
        1. RuntimeGuard.check_model — block if model is not allowed.
        2. FaultInjector.maybe_inject_timeout — if timeout fault, catch
           ProviderTimeoutInjected and fall back to mock_responses.
        3. Loop through MockLLMProvider responses:
           a. Accumulate total_tokens, check budget via RuntimeGuard.
           b. Apply fault injections to tool_calls (bad_args, duplicate,
              prompt_injection).
           c. For each tool_call, check via ToolFirewall before execution.
           d. Detect duplicate tool calls.
           e. Execute fake tools; detect argument errors.
        4. Return result with appropriate failure_type.

    Args:
        scenario: A fully loaded ScenarioSpec.

    Returns:
        Dict with keys: scenario_id, status, failure_type, guard_decisions,
        firewall_decisions, fault_injections, tool_results, final_content, steps.
    """
    guard = RuntimeGuard()
    firewall = ToolFirewall()
    injector = FaultInjector(scenario.fault_injection)
    policy = scenario.policy

    guard_decisions: list[dict[str, Any]] = []
    firewall_decisions: list[dict[str, Any]] = []
    fault_injections: list[dict[str, Any]] = []
    tool_results: list[dict[str, Any]] = []
    tool_call_history: list[tuple[str, dict[str, Any]]] = []
    final_content: str = ""
    steps = 0
    used_tokens = 0
    timeout_recovered = False

    def _decision_dict(decision: Any) -> dict[str, Any]:
        return {
            "action": decision.action.value,
            "reason": decision.reason,
            "check_type": decision.check_type,
        }

    def _injection_dict(result: FaultInjectionResult) -> dict[str, Any]:
        return {
            "applied": result.applied,
            "fault_type": result.fault_type,
            "target": result.target,
            "payload": result.payload,
            "reason": result.reason,
        }

    # --- Pre-flight: model check ---
    model_decision = guard.check_model(scenario.agent_run.model, policy)
    guard_decisions.append(_decision_dict(model_decision))
    if model_decision.action == GuardAction.deny:
        return {
            "scenario_id": scenario.id,
            "status": "blocked",
            "failure_type": "policy_violation",
            "guard_decisions": guard_decisions,
            "firewall_decisions": firewall_decisions,
            "fault_injections": fault_injections,
            "tool_results": tool_results,
            "final_content": final_content,
            "steps": steps,
        }

    # --- Timeout injection (pre-provider) ---
    try:
        inj_result = injector.maybe_inject_timeout()
        if inj_result.applied:
            fault_injections.append(_injection_dict(inj_result))
    except ProviderTimeoutInjected as exc:
        timeout_recovered = True
        fault_injections.append(_injection_dict(FaultInjectionResult(
            applied=True,
            fault_type="timeout",
            target=injector.target or "primary",
            payload=injector.payload,
            reason=str(exc),
        )))
        # Fall through to use mock_responses as fallback

    # --- Main loop ---
    provider = MockLLMProvider(scenario.agent_run.mock_responses)

    for _ in range(scenario.agent_run.max_steps):
        if provider.remaining == 0:
            break

        response = provider.chat()
        steps += 1
        final_content = response.content
        used_tokens += response.total_tokens

        # Budget check after each LLM response
        budget_decision = guard.check_budget(used_tokens, policy)
        guard_decisions.append(_decision_dict(budget_decision))
        if budget_decision.action == GuardAction.deny:
            return {
                "scenario_id": scenario.id,
                "status": "blocked",
                "failure_type": "budget_exceeded",
                "guard_decisions": guard_decisions,
                "firewall_decisions": firewall_decisions,
                "fault_injections": fault_injections,
                "tool_results": tool_results,
                "final_content": final_content,
                "steps": steps,
            }

        # --- Apply fault injections to tool calls ---
        current_tool_calls: list[MockToolCall] = list(response.tool_calls)

        # bad_args injection
        current_tool_calls, bad_args_inj = injector.maybe_inject_bad_args(
            current_tool_calls
        )
        if bad_args_inj.applied:
            fault_injections.append(_injection_dict(bad_args_inj))

        # prompt_injection injection
        current_tool_calls, pi_inj = injector.maybe_inject_prompt_injection(
            current_tool_calls
        )
        if pi_inj.applied:
            fault_injections.append(_injection_dict(pi_inj))

        # duplicate injection
        current_tool_calls, dup_inj = injector.maybe_inject_duplicate(
            current_tool_calls, tool_call_history
        )
        if dup_inj.applied:
            fault_injections.append(_injection_dict(dup_inj))

        # --- Process tool calls ---
        for tc in current_tool_calls:
            # Duplicate detection
            call_signature = (tc.tool, dict(tc.arguments))
            if call_signature in [
                (h_tool, h_args) for h_tool, h_args in tool_call_history
            ]:
                return {
                    "scenario_id": scenario.id,
                    "status": "failed",
                    "failure_type": "duplicate_execution",
                    "guard_decisions": guard_decisions,
                    "firewall_decisions": firewall_decisions,
                    "fault_injections": fault_injections,
                    "tool_results": tool_results,
                    "final_content": final_content,
                    "steps": steps,
                }

            # Firewall check
            fw_decision = firewall.check_tool_call(tc.tool, tc.arguments, policy)
            firewall_decisions.append(_decision_dict(fw_decision))

            if fw_decision.action == GuardAction.deny:
                # If prompt_injection fault was applied, classify as prompt_injection
                has_pi_injection = any(
                    fi["fault_type"] == "prompt_injection" and fi["applied"]
                    for fi in fault_injections
                )
                if has_pi_injection:
                    failure_type = "prompt_injection"
                elif fw_decision.check_type == "firewall_allowed_tools":
                    failure_type = "permission_denied"
                elif fw_decision.check_type == "firewall_risk_level":
                    failure_type = "tool_blocked"
                elif fw_decision.check_type == "firewall_denied_tools":
                    failure_type = "tool_blocked"
                else:
                    failure_type = "tool_blocked"

                return {
                    "scenario_id": scenario.id,
                    "status": "blocked",
                    "failure_type": failure_type,
                    "guard_decisions": guard_decisions,
                    "firewall_decisions": firewall_decisions,
                    "fault_injections": fault_injections,
                    "tool_results": tool_results,
                    "final_content": final_content,
                    "steps": steps,
                }

            # Execute the fake tool
            tool = get_tool(tc.tool)
            result: ToolResult = tool.execute(tc.arguments)
            tool_results.append({
                "tool": result.tool,
                "success": result.success,
                "output": result.output,
                "error": result.error,
            })

            # Record in history for duplicate detection
            tool_call_history.append((tc.tool, dict(tc.arguments)))

            # Check for argument validation errors from fake tools
            if not result.success:
                # bad_args injection caused tool failure
                has_bad_args = any(
                    fi["fault_type"] == "bad_args" and fi["applied"]
                    for fi in fault_injections
                )
                if has_bad_args:
                    return {
                        "scenario_id": scenario.id,
                        "status": "failed",
                        "failure_type": "invalid_arguments",
                        "guard_decisions": guard_decisions,
                        "firewall_decisions": firewall_decisions,
                        "fault_injections": fault_injections,
                        "tool_results": tool_results,
                        "final_content": final_content,
                        "steps": steps,
                    }

        # Stop if the model signals completion
        if response.finish_reason == "stop":
            break

    # Determine final status
    if timeout_recovered:
        return {
            "scenario_id": scenario.id,
            "status": "recovered",
            "failure_type": "provider_timeout",
            "guard_decisions": guard_decisions,
            "firewall_decisions": firewall_decisions,
            "fault_injections": fault_injections,
            "tool_results": tool_results,
            "final_content": final_content,
            "steps": steps,
        }

    return {
        "scenario_id": scenario.id,
        "status": "passed",
        "failure_type": "none",
        "guard_decisions": guard_decisions,
        "firewall_decisions": firewall_decisions,
        "fault_injections": fault_injections,
        "tool_results": tool_results,
        "final_content": final_content,
        "steps": steps,
    }


# ---------------------------------------------------------------------------
# Day 5: TraceLogger + FailureClassifier
# ---------------------------------------------------------------------------


def run_scenario_day5(
    scenario: ScenarioSpec,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Run a scenario with full trace logging and failure classification.

    Reuses the Day 4 execution chain and instruments every key step
    with TraceEventRecords.  After execution, the FailureClassifier
    derives the failure_type from trace evidence alone.

    Args:
        scenario: A fully loaded ScenarioSpec.
        output_dir: Optional directory for trace output.  If provided,
            the trace JSONL is written to ``output_dir / scenario.id / trace.jsonl``.

    Returns:
        Dict with keys: scenario_id, status, expected_failure, failure_type,
        passed, trace_file, events_count.
    """
    run_id = uuid.uuid4().hex[:12]
    trace_path: Path | None = None
    if output_dir is not None:
        trace_path = Path(output_dir) / scenario.id / "trace.jsonl"

    logger = TraceLogger(trace_path or Path("trace.jsonl"))

    guard = RuntimeGuard()
    firewall = ToolFirewall()
    argument_guard = ArgumentGuard()
    injector = FaultInjector(scenario.fault_injection)
    policy = scenario.policy

    step = 0
    used_tokens = 0
    timeout_recovered = False
    tool_call_history: list[tuple[str, dict[str, Any]]] = []

    def _emit(
        event_type: EventType,
        module: str,
        data: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> TraceEventRecord:
        nonlocal step
        ev = TraceEventRecord(
            run_id=run_id,
            scenario_id=scenario.id,
            step=step,
            event_type=event_type,
            module=module,
            data=data or {},
            error=error,
        )
        logger.log(ev)
        return ev

    # ---- agent_start ----
    _emit(EventType.agent_start, "runner", {
        "model": scenario.agent_run.model,
        "task": scenario.agent_run.task,
        "max_steps": scenario.agent_run.max_steps,
    })

    # ---- guard_check: model ----
    _emit(EventType.guard_check, "guard", {
        "check_type": "model",
        "model": scenario.agent_run.model,
    })
    model_decision = guard.check_model(scenario.agent_run.model, policy)
    _emit(EventType.guard_decision, "guard", {
        "action": model_decision.action.value,
        "reason": model_decision.reason,
        "check_type": model_decision.check_type,
    })

    if model_decision.action == GuardAction.deny:
        _emit(EventType.agent_end, "runner", {"status": "blocked"})
        return _finalise(logger, scenario, run_id, "blocked", trace_path)

    # ---- timeout injection (pre-provider) ----
    try:
        injector.maybe_inject_timeout()
    except ProviderTimeoutInjected as exc:
        timeout_recovered = True
        _emit(EventType.fault_injected, "fault_injector", {
            "fault_type": "timeout",
            "target": injector.target or "primary",
            "applied": True,
            "reason": str(exc),
        })
        # fall through to use mock_responses as fallback

    # ---- main loop ----
    provider = MockLLMProvider(scenario.agent_run.mock_responses)

    for _ in range(scenario.agent_run.max_steps):
        if provider.remaining == 0:
            break

        step += 1

        # llm_request
        _emit(EventType.llm_request, "mock_llm", {"step": step})

        response = provider.chat()
        used_tokens += response.total_tokens

        # llm_response
        _emit(EventType.llm_response, "mock_llm", {
            "content": response.content,
            "finish_reason": response.finish_reason,
            "total_tokens": response.total_tokens,
            "tool_calls_count": len(response.tool_calls),
        })

        # guard_check: budget
        _emit(EventType.guard_check, "guard", {
            "check_type": "budget",
            "used_tokens": used_tokens,
        })
        budget_decision = guard.check_budget(used_tokens, policy)
        _emit(EventType.guard_decision, "guard", {
            "action": budget_decision.action.value,
            "reason": budget_decision.reason,
            "check_type": budget_decision.check_type,
        })

        if budget_decision.action == GuardAction.deny:
            _emit(EventType.agent_end, "runner", {"status": "blocked"})
            return _finalise(logger, scenario, run_id, "blocked", trace_path)

        # ---- apply fault injections to tool calls ----
        current_tool_calls: list[MockToolCall] = list(response.tool_calls)

        # bad_args
        current_tool_calls, bad_args_inj = injector.maybe_inject_bad_args(
            current_tool_calls
        )
        if bad_args_inj.applied:
            _emit(EventType.fault_injected, "fault_injector", {
                "fault_type": "bad_args",
                "target": bad_args_inj.target,
                "applied": True,
                "reason": bad_args_inj.reason,
            })

        # prompt_injection
        current_tool_calls, pi_inj = injector.maybe_inject_prompt_injection(
            current_tool_calls
        )
        if pi_inj.applied:
            _emit(EventType.fault_injected, "fault_injector", {
                "fault_type": "prompt_injection",
                "target": pi_inj.target,
                "applied": True,
                "reason": pi_inj.reason,
            })

        # duplicate
        current_tool_calls, dup_inj = injector.maybe_inject_duplicate(
            current_tool_calls, tool_call_history
        )
        if dup_inj.applied:
            _emit(EventType.fault_injected, "fault_injector", {
                "fault_type": "duplicate",
                "target": dup_inj.target,
                "applied": True,
                "reason": dup_inj.reason,
            })

        # ---- process tool calls ----
        for tc in current_tool_calls:
            # duplicate detection
            call_signature = (tc.tool, dict(tc.arguments))
            is_duplicate = call_signature in [
                (h_tool, h_args) for h_tool, h_args in tool_call_history
            ]

            _emit(EventType.tool_call, "runner", {
                "tool": tc.tool,
                "arguments": tc.arguments,
                "duplicate": is_duplicate,
            })

            if is_duplicate:
                _emit(EventType.agent_end, "runner", {"status": "failed"})
                return _finalise(logger, scenario, run_id, "failed", trace_path)

            # firewall_check
            _emit(EventType.firewall_check, "firewall", {
                "tool": tc.tool,
                "arguments": tc.arguments,
            })

            fw_decision = firewall.check_tool_call(tc.tool, tc.arguments, policy)

            # Did a prompt_injection fault cause this call?
            has_pi = pi_inj.applied

            _emit(EventType.firewall_decision, "firewall", {
                "action": fw_decision.action.value,
                "reason": fw_decision.reason,
                "check_type": fw_decision.check_type,
                "prompt_injection": has_pi,
            })

            if fw_decision.action == GuardAction.deny:
                _emit(EventType.agent_end, "runner", {"status": "blocked"})
                return _finalise(logger, scenario, run_id, "blocked", trace_path)

            _emit(EventType.argument_guard_check, "argument_guard", {
                "tool": tc.tool,
                "arguments": tc.arguments,
                "attack_payload": tc.arguments.get("path"),
            })

            arg_decision = argument_guard.check_tool_call(tc.tool, tc.arguments)
            _emit(EventType.argument_guard_decision, "argument_guard", {
                "action": arg_decision.action.value,
                "tool": arg_decision.tool_name,
                "check_type": arg_decision.check_type,
                "reason": arg_decision.reason,
                "reason_zh": arg_decision.reason_zh,
                "reason_en": arg_decision.reason_en,
                "attack_payload": arg_decision.evidence.get("attack_payload"),
                "evidence": arg_decision.evidence,
            })

            if arg_decision.action == GuardAction.deny:
                _emit(EventType.tool_execution_skipped, "runner", {
                    "tool": tc.tool,
                    "reason": arg_decision.reason,
                    "reason_zh": arg_decision.reason_zh,
                    "reason_en": arg_decision.reason_en,
                    "attack_payload": arg_decision.evidence.get("attack_payload"),
                })
                _emit(EventType.agent_end, "runner", {"status": "blocked"})
                return _finalise(logger, scenario, run_id, "blocked", trace_path)

            # execute fake tool
            tool_impl = get_tool(tc.tool)
            result: ToolResult = tool_impl.execute(tc.arguments)

            _emit(EventType.tool_result, "tools", {
                "tool": result.tool,
                "success": result.success,
                "output": result.output,
                "error": result.error,
            }, error=result.error)

            tool_call_history.append((tc.tool, dict(tc.arguments)))

            if not result.success:
                has_bad_args = bad_args_inj.applied
                if has_bad_args:
                    _emit(EventType.agent_end, "runner", {"status": "failed"})
                    return _finalise(logger, scenario, run_id, "failed", trace_path)

        # stop if model signals completion
        if response.finish_reason == "stop":
            # ---- answer verification check ----
            if policy.require_answer_verification:
                has_tool_calls_in_run = len(tool_call_history) > 0
                verified = has_tool_calls_in_run

                _emit(EventType.guard_check, "guard", {
                    "check_type": "answer_verification",
                    "verified": verified,
                })
                av_decision = guard.check_final_answer_verified(verified, policy)
                _emit(EventType.guard_decision, "guard", {
                    "action": av_decision.action.value,
                    "reason": av_decision.reason,
                    "check_type": av_decision.check_type,
                })

                if av_decision.action == GuardAction.deny:
                    _emit(EventType.agent_end, "runner", {"status": "blocked"})
                    return _finalise(logger, scenario, run_id, "blocked", trace_path)

            break

    # ---- determine final status ----
    if timeout_recovered:
        _emit(EventType.agent_end, "runner", {"status": "recovered"})
        return _finalise(logger, scenario, run_id, "recovered", trace_path)

    _emit(EventType.agent_end, "runner", {"status": "passed"})
    return _finalise(logger, scenario, run_id, "passed", trace_path)


def _finalise(
    logger: TraceLogger,
    scenario: ScenarioSpec,
    run_id: str,
    status: str,
    trace_path: Path | None,
) -> dict[str, Any]:
    """Flush trace and build the result dict for run_scenario_day5."""
    classifier = FailureClassifier()
    events = logger.events
    failure_type = classifier.classify(events)

    last_step = events[-1].step if events else 0
    logger.log(TraceEventRecord(
        run_id=run_id,
        scenario_id=scenario.id,
        step=last_step,
        event_type=EventType.failure_classified,
        module="classifier",
        data={"failure_type": failure_type.value},
    ))
    events = logger.events

    trace_file: str | None = None
    if trace_path is not None:
        logger._output_path = trace_path
        logger.flush()
        trace_file = str(trace_path)

    passed = failure_type.value == scenario.expected_failure.value

    result = {
        "scenario_id": scenario.id,
        "case_id": _case_id_from_scenario_id(scenario.id),
        "status": status,
        "expected_failure": scenario.expected_failure.value,
        "failure_type": failure_type.value,
        "passed": passed,
        "trace_file": trace_file,
        "events_count": len(events),
    }
    result.update(_extract_security_evidence(events))
    return result


def _case_id_from_scenario_id(scenario_id: str) -> str:
    prefix = scenario_id.split("_", 2)[:2]
    if len(prefix) == 2 and prefix[0] == "ad" and prefix[1].isdigit():
        return f"AD-{prefix[1]}"
    return scenario_id


def _extract_security_evidence(events: list[TraceEventRecord]) -> dict[str, Any]:
    """Extract denial evidence for terminal alerts and reports."""
    for ev in events:
        if ev.event_type == EventType.argument_guard_decision:
            if ev.data.get("action") == GuardAction.deny.value:
                return {
                    "blocked_by": "argument_guard",
                    "reason": ev.data.get("reason", ""),
                    "reason_zh": ev.data.get("reason_zh", ""),
                    "reason_en": ev.data.get("reason_en", ""),
                    "attack_payload": ev.data.get("attack_payload", ""),
                    "tool": ev.data.get("tool", ""),
                }

    for ev in events:
        if ev.event_type == EventType.firewall_decision:
            if ev.data.get("action") == GuardAction.deny.value:
                return {
                    "blocked_by": "tool_firewall",
                    "reason": ev.data.get("check_type", ""),
                    "reason_zh": ev.data.get("reason", ""),
                    "reason_en": ev.data.get("reason", ""),
                    "attack_payload": "",
                    "tool": ev.data.get("tool", ""),
                }

    for ev in events:
        if ev.event_type == EventType.guard_decision:
            if ev.data.get("action") == GuardAction.deny.value:
                return {
                    "blocked_by": "runtime_guard",
                    "reason": ev.data.get("check_type", ""),
                    "reason_zh": ev.data.get("reason", ""),
                    "reason_en": ev.data.get("reason", ""),
                    "attack_payload": "",
                    "tool": "",
                }

    return {}
