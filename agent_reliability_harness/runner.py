"""
Scenario runners for AgentReliabilityHarness.

- run_scenario_day2: Minimal mock execution loop (Day 2).
- run_scenario_day3: Adds RuntimeGuard + ToolFirewall checks (Day 3).
- run_scenario_day4: Adds FaultInjector for fault injection scenarios (Day 4).
"""

from __future__ import annotations

from typing import Any

from agent_reliability_harness.fault_injector import (
    FaultInjectionResult,
    FaultInjector,
    ProviderTimeoutInjected,
)
from agent_reliability_harness.mock_llm import MockLLMProvider
from agent_reliability_harness.runtime_guard import RuntimeGuard
from agent_reliability_harness.spec import GuardAction, MockToolCall, ScenarioSpec
from agent_reliability_harness.tool_firewall import ToolFirewall
from agent_reliability_harness.tools import ToolResult, get_tool


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

