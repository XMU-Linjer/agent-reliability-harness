"""
Minimal scenario runner for Day 2.

Runs a single ScenarioSpec through MockLLMProvider + fake tools
without Guard, Firewall, Trace, or Scorecard logic.
"""

from __future__ import annotations

from typing import Any

from agent_reliability_harness.mock_llm import MockLLMProvider
from agent_reliability_harness.spec import ScenarioSpec
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
