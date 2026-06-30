"""
Scenario runners for AgentReliabilityHarness.

- run_scenario_day2: Minimal mock execution loop (Day 2).
- run_scenario_day3: Adds RuntimeGuard + ToolFirewall checks (Day 3).
"""

from __future__ import annotations

from typing import Any

from agent_reliability_harness.mock_llm import MockLLMProvider
from agent_reliability_harness.runtime_guard import RuntimeGuard
from agent_reliability_harness.spec import GuardAction, ScenarioSpec
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
