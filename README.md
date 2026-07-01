# AgentReliabilityHarness

AgentReliabilityHarness 是一个离线、确定性的 Agent 运行时可靠性评测框架。

它用 YAML 场景驱动 mock Agent 运行，模拟常见运行时故障，记录 trace，分类 failure type，并生成 `scorecard.json` 与 `report.md`。项目不接真实 LLM API，不执行真实 shell，不联网，适合展示 Agent Runtime / AI Infra 方向的工程能力。

## 核心能力

- YAML ScenarioSpec
- Mock LLM Provider
- Fake Tools
- RuntimeGuard
- ToolFirewall
- FaultInjector
- TraceLogger
- FailureClassifier
- BenchmarkRunner
- ScorecardGenerator
- ReportRenderer

## Benchmark 场景

| # | scenario_id | expected failure |
|---|---|---|
| 1 | `normal_agent_run` | `none` |
| 2 | `model_not_allowed` | `policy_violation` |
| 3 | `budget_exceeded` | `budget_exceeded` |
| 4 | `provider_timeout_fallback` | `provider_timeout` |
| 5 | `high_risk_tool_blocked` | `tool_blocked` |
| 6 | `write_file_without_permission` | `permission_denied` |
| 7 | `prompt_injection_tool_escalation` | `prompt_injection` |
| 8 | `bad_tool_arguments` | `invalid_arguments` |
| 9 | `duplicate_tool_execution` | `duplicate_execution` |
| 10 | `unverified_final_answer` | `unverified_answer` |

## 安装

```bash
python -m pip install -e ".[dev]"
```

## 运行测试

```bash
pytest -v
```

## 运行 Benchmark

如果安装了项目脚本：

```bash
arh run --scenarios-dir scenarios --output-dir runs/local-demo --run-id local-demo
```

也可以直接用 Python 模块方式运行：

```bash
python -m agent_reliability_harness.cli run --scenarios-dir scenarios --output-dir runs/local-demo --run-id local-demo
```

命令会批量运行 `scenarios/` 下的 YAML 场景，并生成 scorecard 与 Markdown 报告。

## 输出结构

`BenchmarkRunner` 会在 `output_dir / run_id` 下写出结果。例如上面的命令会生成：

```text
runs/local-demo/local-demo/
  scorecard.json
  report.md
  normal_agent_run/trace.jsonl
  model_not_allowed/trace.jsonl
  ...
```

主要文件：

- `scorecard.json`：机器可读的汇总结果，包含通过率、failure type 统计、status 统计和每个场景结果。
- `report.md`：人类可读的 Markdown 报告，包含 summary、统计表、场景结果表和项目边界说明。
- `<scenario_id>/trace.jsonl`：每个场景独立的事件 trace，每行一个 JSON 事件。

小型示例见：

- [examples/scorecard.example.json](examples/scorecard.example.json)
- [examples/report.example.md](examples/report.example.md)

## 项目边界

AgentReliabilityHarness 是一个 MVP 级别的离线评测 harness：

- offline-first
- deterministic
- no real LLM API
- no real shell/network side effects
- not a LangChain wrapper
- not a prompt engineering demo
- not a production security platform
- not a full LLMOps observability product

它关注“如何复现、记录、分类和汇总 Agent 运行时故障”，不承诺防御所有 prompt injection，也不连接真实 OpenAI、Anthropic、LangChain、AutoGen 或外部服务。

## 架构链路

```text
ScenarioSpec
  -> MockLLMProvider
  -> RuntimeGuard
  -> ToolFirewall
  -> FaultInjector
  -> TraceLogger
  -> FailureClassifier
  -> BenchmarkRunner
  -> ScorecardGenerator
  -> ReportRenderer
```

## 简历 bullet 草案

- 设计并实现离线 Agent 运行时可靠性评测框架，通过 YAML ScenarioSpec + PolicySpec 驱动 mock Agent 运行，覆盖 model / tool / budget 等运行时策略校验。
- 实现 RuntimeGuard 与 ToolFirewall，对模型白名单、token budget、工具 allow/deny list 和工具风险等级进行确定性拦截。
- 构建 FaultInjector，覆盖 provider timeout、bad arguments、duplicate execution、prompt injection escalation 等故障注入场景。
- 设计 TraceLogger + FailureClassifier，将运行时事件写入 JSONL trace，并基于 trace evidence 自动分类为 10 种 failure type。
- 实现 BenchmarkRunner、ScorecardGenerator 与 ReportRenderer，批量运行 10 个标准场景，输出 `scorecard.json` 和 `report.md`。

## 文档

- [架构设计](docs/architecture.md)
- [Spec 数据结构设计](docs/spec-design.md)
- [Benchmark 场景设计](docs/benchmark-design.md)
- [MVP 计划](docs/mvp-plan.md)
- [Non-Goals](docs/non-goals.md)
- [简历定位](docs/resume-positioning.md)

## License

MIT
