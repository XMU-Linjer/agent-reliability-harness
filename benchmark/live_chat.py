"""Interactive DeepSeek chat demo with guarded tool execution."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, TextIO

from agent_guard.guards.argument_guard import ArgumentGuard
from benchmark.providers.deepseek_provider import DeepSeekProvider
from benchmark.providers.tool_schema import get_tool_schemas
from agent_guard.guards.runtime_guard import RuntimeGuard
from benchmark.spec import (
    EventType,
    GuardAction,
    PolicySpec,
    ToolRiskLevel,
)
from agent_guard.sandbox.local_sandbox_executor import LocalSandboxToolExecutor
from agent_guard.guards.tool_firewall import ToolFirewall
from benchmark.fake_tools import ToolResult
from agent_guard.trace.trace_logger import TraceEventRecord, TraceLogger


DEFAULT_CHAT_TOOLS = ["read_file", "execute_shell", "search_web"]


def run_live_chat(
    *,
    model: str = "deepseek-v4-flash",
    sandbox_root: str | Path = ".tmp/live-chat-sandbox",
    output_dir: str | Path = "runs/live-chat",
    tools: list[str] | None = None,
    max_steps: int = 4,
    max_token_budget: int = 20_000,
    network_allowlist: list[str] | None = None,
    command_allowlist: list[str] | None = None,
    single_prompt: str | None = None,
    stdout: TextIO | None = None,
) -> int:
    """Run an interactive DeepSeek chat session with guarded tools.

    Args:
        model: DeepSeek model name.
        sandbox_root: Directory used by real local sandbox tools.
        output_dir: Root directory for trace output.
        tools: Tool names exposed to the model.
        max_steps: Maximum LLM/tool loop steps per user message.
        max_token_budget: Per-turn token budget.
        network_allowlist: Domains allowed for search_web URL fetches.
        command_allowlist: Command names allowed for execute_shell.
        single_prompt: If set, run exactly one prompt and exit.
        stdout: Output stream for tests.

    Returns:
        Process-style exit code.
    """
    out = stdout
    if out is None:
        import sys
        out = sys.stdout

    tool_names = tools or list(DEFAULT_CHAT_TOOLS)
    run_id = uuid.uuid4().hex[:12]
    trace_dir = Path(output_dir) / run_id
    trace_path = trace_dir / "trace.jsonl"
    logger = TraceLogger(trace_path)

    provider = DeepSeekProvider.from_env(model=model)
    executor = LocalSandboxToolExecutor(
        sandbox_root=sandbox_root,
        timeout_seconds=20,
        max_output_bytes=20_000,
        network_allowlist=network_allowlist or ["example.com"],
        command_allowlist=command_allowlist or ["python"],
    )
    guard = RuntimeGuard()
    firewall = ToolFirewall()
    argument_guard = ArgumentGuard()
    policy = PolicySpec(
        allowed_models=[model],
        max_token_budget=max_token_budget,
        max_tool_risk_level=ToolRiskLevel.critical,
        allowed_tools=tool_names,
    )
    tool_schemas = get_tool_schemas(tool_names)

    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                "You are an interview demo agent running inside AgentReliabilityHarness. "
                "Use provided tools when needed. Keep answers concise and explain which tool evidence you used."
            ),
        },
    ]
    step = 0

    def emit(
        event_type: EventType,
        module: str,
        data: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        nonlocal step
        logger.log(TraceEventRecord(
            run_id=run_id,
            scenario_id="live_chat",
            step=step,
            event_type=event_type,
            module=module,
            data=data or {},
            error=error,
        ))

    print("AgentReliabilityHarness Live Chat", file=out)
    print(f"provider=deepseek model={model} executor=local_sandbox", file=out)
    print(f"sandbox_root={Path(sandbox_root)}", file=out)
    print(f"trace={trace_path}", file=out)
    print(f"tools={', '.join(tool_names)}", file=out)
    print("type 'exit' to quit", file=out)

    emit(EventType.agent_start, "live_chat", {
        "model": model,
        "provider": "deepseek",
        "tool_executor": "local_sandbox",
        "tools": tool_names,
    })

    prompts = [single_prompt] if single_prompt is not None else None
    prompt_index = 0
    while True:
        if prompts is None:
            try:
                prompt = input("\nYou> ").strip()
            except EOFError:
                break
        else:
            if prompt_index >= len(prompts):
                break
            prompt = prompts[prompt_index] or ""
            prompt_index += 1
            print(f"\nYou> {prompt}", file=out)

        if prompt.lower() in {"exit", "quit", "q"}:
            break
        if not prompt:
            continue

        messages.append({"role": "user", "content": prompt})
        status, step = _run_one_turn(
            messages=messages,
            provider=provider,
            tool_schemas=tool_schemas,
            executor=executor,
            guard=guard,
            firewall=firewall,
            argument_guard=argument_guard,
            policy=policy,
            logger=logger,
            run_id=run_id,
            max_steps=max_steps,
            out=out,
            start_step=step,
        )
        if status == "blocked":
            print("[blocked] Tool execution was stopped by the harness.", file=out)

    emit(EventType.agent_end, "live_chat", {"status": "ended"})
    logger.flush()
    print(f"\ntrace saved: {trace_path}", file=out)
    return 0


def _run_one_turn(
    *,
    messages: list[dict[str, Any]],
    provider: DeepSeekProvider,
    tool_schemas: list[dict[str, Any]],
    executor: LocalSandboxToolExecutor,
    guard: RuntimeGuard,
    firewall: ToolFirewall,
    argument_guard: ArgumentGuard,
    policy: PolicySpec,
    logger: TraceLogger,
    run_id: str,
    max_steps: int,
    out: TextIO,
    start_step: int,
) -> tuple[str, int]:
    used_tokens = 0
    turn_tool_calls: set[tuple[str, str]] = set()
    step = start_step

    def emit(
        event_type: EventType,
        module: str,
        data: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        logger.log(TraceEventRecord(
            run_id=run_id,
            scenario_id="live_chat",
            step=step,
            event_type=event_type,
            module=module,
            data=data or {},
            error=error,
        ))

    model_decision = guard.check_model(provider.model, policy)
    print(f"[runtime_guard] model {model_decision.action.value}: {model_decision.reason}", file=out)
    emit(EventType.guard_decision, "runtime_guard", {
        "check_type": "model",
        "action": model_decision.action.value,
        "reason": model_decision.reason,
        "model": provider.model,
    })
    if model_decision.action == GuardAction.deny:
        return "blocked", step

    for _ in range(max_steps):
        step += 1
        print("[llm_request] DeepSeek", file=out)
        emit(EventType.llm_request, "deepseek", {
            "model": provider.model,
            "messages_count": len(messages),
            "tools_count": len(tool_schemas),
        })

        try:
            response = provider.chat(messages, tools=tool_schemas)
        except Exception as exc:
            print(f"[llm_error] {exc}", file=out)
            emit(EventType.llm_response, "deepseek", {"error": str(exc)}, error=str(exc))
            return "error", step

        used_tokens += response.total_tokens
        print(
            f"[llm_response] finish_reason={response.finish_reason} "
            f"tool_calls={len(response.tool_calls)} tokens={response.total_tokens}",
            file=out,
        )
        emit(EventType.llm_response, "deepseek", {
            "finish_reason": response.finish_reason,
            "tool_calls_count": len(response.tool_calls),
            "total_tokens": response.total_tokens,
            "content_preview": response.content[:200],
        })

        budget_decision = guard.check_budget(used_tokens, policy)
        print(f"[runtime_guard] budget {budget_decision.action.value}: {budget_decision.reason}", file=out)
        emit(EventType.guard_decision, "runtime_guard", {
            "check_type": "budget",
            "action": budget_decision.action.value,
            "reason": budget_decision.reason,
        })
        if budget_decision.action == GuardAction.deny:
            return "blocked", step

        if response.content:
            print(f"Agent> {response.content}", file=out)
            emit(EventType.final_answer, "live_chat", {
                "final_answer": response.content[:500],
            })

        if not response.tool_calls:
            return "passed", step

        for tool_call_index, tool_call in enumerate(response.tool_calls):
            call_id = tool_call.call_id or f"call_{step}_{tool_call_index}_{tool_call.tool}"
            args_json = json.dumps(tool_call.arguments, ensure_ascii=False, sort_keys=True)
            signature = (tool_call.tool, args_json)
            duplicate = signature in turn_tool_calls
            print(f"[tool_call] {tool_call.tool} {args_json}", file=out)
            emit(EventType.tool_call, "live_chat", {
                "tool_call_id": call_id,
                "tool": tool_call.tool,
                "arguments": tool_call.arguments,
                "duplicate": duplicate,
            })

            if duplicate:
                print("[runner] duplicate deny: duplicate_tool_execution", file=out)
                emit(EventType.tool_execution_skipped, "live_chat", {
                    "tool": tool_call.tool,
                    "blocked_by": "runner",
                    "reason": "duplicate_tool_execution",
                })
                return "blocked", step
            turn_tool_calls.add(signature)

            fw_decision = firewall.check_tool_call(tool_call.tool, tool_call.arguments, policy)
            print(f"[tool_firewall] {fw_decision.action.value}: {fw_decision.reason}", file=out)
            emit(EventType.firewall_decision, "tool_firewall", {
                "action": fw_decision.action.value,
                "reason": fw_decision.reason,
                "check_type": fw_decision.check_type,
                "tool": tool_call.tool,
            })
            if fw_decision.action == GuardAction.deny:
                emit(EventType.tool_execution_skipped, "live_chat", {
                    "tool": tool_call.tool,
                    "blocked_by": "tool_firewall",
                    "reason": fw_decision.reason,
                })
                return "blocked", step

            arg_decision = argument_guard.check_tool_call(tool_call.tool, tool_call.arguments)
            print(f"[argument_guard] {arg_decision.action.value}: {arg_decision.reason}", file=out)
            emit(EventType.argument_guard_decision, "argument_guard", {
                "action": arg_decision.action.value,
                "reason": arg_decision.reason,
                "check_type": arg_decision.check_type,
                "tool": tool_call.tool,
            })
            if arg_decision.action == GuardAction.deny:
                emit(EventType.tool_execution_skipped, "live_chat", {
                    "tool": tool_call.tool,
                    "blocked_by": "argument_guard",
                    "reason": arg_decision.reason,
                })
                return "blocked", step

            result = executor.execute(tool_call.tool, tool_call.arguments)
            _print_tool_result(result, out)
            emit(EventType.tool_result, "tools", {
                "tool": result.tool,
                "success": result.success,
                "output_preview": str(result.output)[:500] if result.output is not None else "",
            }, error=result.error)

            tool_output = str(result.output) if result.output is not None else ""
            if result.error:
                tool_output = f"Error: {result.error}"
            messages.append({
                "role": "assistant",
                "content": None,
                "tool_calls": [{
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": tool_call.tool,
                        "arguments": json.dumps(tool_call.arguments, ensure_ascii=False),
                    },
                }],
            })
            messages.append({
                "role": "tool",
                "tool_call_id": call_id,
                "content": tool_output[:4000],
            })

    return "max_steps", step


def _print_tool_result(result: ToolResult, out: TextIO) -> None:
    if isinstance(result.output, dict):
        if "status_code" in result.output:
            body_preview = str(result.output.get("body", ""))[:200]
            print(
                f"[tool_result] {result.tool} success={result.success} "
                f"status_code={result.output.get('status_code')} "
                f"content_type={result.output.get('content_type', '')!r} "
                f"body_preview={body_preview!r}",
                file=out,
            )
            return
        stdout = str(result.output.get("stdout", ""))[:200]
        stderr = str(result.output.get("stderr", ""))[:200]
        print(
            f"[tool_result] {result.tool} success={result.success} "
            f"exit_code={result.output.get('exit_code')} stdout={stdout!r} stderr={stderr!r}",
            file=out,
        )
        return
    preview = str(result.output)[:300] if result.output is not None else ""
    print(f"[tool_result] {result.tool} success={result.success} output={preview!r} error={result.error!r}", file=out)
