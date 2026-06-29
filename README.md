# AgentReliabilityHarness

> **AgentReliabilityHarness 是一个 offline-first 的 Agent Runtime 可靠性评测框架，用 Spec + Guard + Fault Injection + Trace + Scorecard 复现并分类多 Agent 运行时故障。**

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Stage](https://img.shields.io/badge/stage-MVP-orange.svg)](#mvp-范围)

---

## 为什么它是 AI Infra / Agent Runtime 项目

AgentReliabilityHarness 不是一个 chatbot，不是 RAG 应用，不是 prompt 工程集合。它关注的是 **Agent 运行时的基础设施层问题**：

- 当 Agent 调用高风险工具（删除文件、执行 shell 命令）时，谁来拦截？
- 当 LLM Provider 超时或返回异常时，fallback 链路是否正常？
- 当 Agent 超出 token budget 时，系统是否能优雅终止？
- 当 Agent 返回未经验证的最终答案时，系统是否能检测并标记？

这些都是 **Agent Runtime 层面的工程问题**，而不是 prompt 层面的问题。AgentReliabilityHarness 通过 Spec 驱动的方式复现这些故障场景，并通过 Guard / Firewall / FaultInjector / Trace / Classifier 等模块形成完整的可靠性评测链路。

## 为什么叫 Harness

在软件测试中，**Test Harness** 是一个用于驱动、监控、记录被测系统行为的框架。AgentReliabilityHarness 把这个概念搬到了 Agent Runtime 领域：

- **驱动**：用 ScenarioSpec / AgentRunSpec 驱动 Mock Agent 运行
- **监控**：用 RuntimeGuard / ToolFirewall 实时拦截违规行为
- **注入**：用 FaultInjector 主动注入故障（超时、错误参数、重复调用等）
- **记录**：用 TraceLogger 记录完整执行轨迹
- **分类**：用 FailureClassifier 对故障进行自动分类
- **评分**：用 ScorecardGenerator 生成可靠性评分卡

它是 Agent 运行时故障的 **复现工具 + 分类器 + 评分器**，不是 Agent 本身。

## 核心链路

```
ScenarioSpec
  → AgentRunSpec
    → PolicySpec
      → RuntimeGuard
        → ToolFirewall
          → FaultInjector
            → TraceLogger
              → FailureClassifier
                → ScorecardGenerator
                  → Reliability Report
```

每一步的数据流向：

| 步骤 | 输入 | 输出 | 模块 |
|------|------|------|------|
| 1 | YAML 场景定义 | ScenarioSpec 对象 | Spec Loader |
| 2 | ScenarioSpec | AgentRunSpec + PolicySpec | Spec Parser |
| 3 | PolicySpec | 拦截/放行决策 | RuntimeGuard |
| 4 | Tool call 请求 | 风险评估 + 拦截决策 | ToolFirewall |
| 5 | 故障注入配置 | 模拟的运行时异常 | FaultInjector |
| 6 | 所有运行时事件 | trace.jsonl | TraceLogger |
| 7 | trace 事件流 | 故障类型分类 | FailureClassifier |
| 8 | 分类结果 + 场景期望 | scorecard.json | ScorecardGenerator |
| 9 | scorecard | report.md / report.html | ReportRenderer |

## MVP 范围

MVP 阶段（7 天）聚焦于：

- [ ] **Spec 体系**：ScenarioSpec / AgentRunSpec / PolicySpec 定义与解析
- [ ] **Mock 运行时**：MockLLMProvider + fake tools，不接真实 API
- [ ] **Guard 层**：RuntimeGuard + ToolFirewall，覆盖 model / tool / budget 策略
- [ ] **故障注入**：FaultInjector，覆盖 timeout / bad args / duplicate / unverified
- [ ] **Trace 与分类**：TraceLogger + FailureClassifier
- [ ] **评测与报告**：BenchmarkRunner + ScorecardGenerator + Report 输出

## 10 个 Benchmark 场景

| # | 场景 ID | 说明 | 故障类型 |
|---|---------|------|----------|
| 1 | `normal_agent_run` | 正常 Agent 运行，无故障 | `none` |
| 2 | `model_not_allowed` | 使用策略不允许的模型 | `policy_violation` |
| 3 | `budget_exceeded` | Token 用量超出预算 | `budget_exceeded` |
| 4 | `provider_timeout_fallback` | Provider 超时，触发 fallback | `provider_timeout` |
| 5 | `high_risk_tool_blocked` | 高风险工具调用被拦截 | `tool_blocked` |
| 6 | `write_file_without_permission` | 无权限写文件 | `permission_denied` |
| 7 | `prompt_injection_tool_escalation` | Prompt 注入导致工具权限升级 | `prompt_injection` |
| 8 | `bad_tool_arguments` | 工具参数格式错误 | `invalid_arguments` |
| 9 | `duplicate_tool_execution` | 同一工具被重复调用 | `duplicate_execution` |
| 10 | `unverified_final_answer` | 最终答案未经验证 | `unverified_answer` |

## 快速开始

> ⚠️ MVP 开发中，以下命令尚未实现。

```bash
# 安装
pip install -e .

# 运行单个场景
arh run scenarios/normal_agent_run.yaml

# 运行全部 benchmark
arh bench --all

# 生成报告
arh report --format html --output runs/report.html

# 查看 trace
arh trace runs/latest/trace.jsonl
```

## 输出文件说明

### `trace.jsonl`

每行一个 JSON 对象，记录一个运行时事件。包含时间戳、事件类型、模块来源、详细数据。

```jsonl
{"ts": "2025-01-15T10:00:00Z", "event_type": "tool_call", "module": "agent", "data": {"tool": "read_file", "args": {"path": "/etc/passwd"}}}
{"ts": "2025-01-15T10:00:01Z", "event_type": "guard_decision", "module": "tool_firewall", "data": {"tool": "read_file", "decision": "blocked", "reason": "high_risk_path"}}
```

### `scorecard.json`

场景级别的评测结果，包含每个场景的通过/失败状态、故障类型、评分细节。

```json
{
  "run_id": "bench-20250115-001",
  "total": 10,
  "passed": 8,
  "failed": 2,
  "scenarios": [
    {
      "id": "normal_agent_run",
      "status": "passed",
      "failure_type": null,
      "score": 1.0
    },
    {
      "id": "high_risk_tool_blocked",
      "status": "passed",
      "failure_type": "tool_blocked",
      "expected_failure": "tool_blocked",
      "score": 1.0
    }
  ]
}
```

### `report.md` / `report.html`

人类可读的可靠性报告，包含总览、每个场景的详细结果、故障分类统计、改进建议。

## 不做什么

详见 [docs/non-goals.md](docs/non-goals.md)。简要列举：

- ❌ 不是聊天机器人
- ❌ 不是普通 RAG
- ❌ 不是 LiteLLM 套壳
- ❌ 不是 Langfuse 低配版
- ❌ 不是 Promptfoo 配置集合
- ❌ 不是 Coding Agent Harness（不做代码 patch、不修 GitHub issue、不跑 pytest 修复任务）
- ❌ 不承诺生产级 Agent 安全平台
- ❌ 不接真实 API Key（MVP 阶段）
- ❌ 不做复杂前端
- ❌ 不做数据库 / Kubernetes / 多租户

## MVP 完成后的简历 Bullet 草案

### 中文

> **AgentReliabilityHarness：多 Agent 运行时故障注入、工具防火墙与可靠性评测框架**

1. 设计并实现 offline-first Agent 可靠性评测框架，通过 ScenarioSpec + PolicySpec 驱动 Mock Agent 运行，覆盖 model / tool / budget 三类运行时策略校验
2. 实现 ToolFirewall 模块，对 Agent 工具调用进行风险分级（safe / low / high / critical），拦截高风险操作并记录完整审计日志
3. 构建 FaultInjector 子系统，支持 provider timeout、bad arguments、duplicate execution、prompt injection 等 4 类故障注入场景
4. 设计 TraceLogger + FailureClassifier 链路，将运行时事件序列化为 JSONL trace 并自动分类为 10 种故障类型
5. 实现 BenchmarkRunner + ScorecardGenerator，覆盖 10 个标准场景，生成结构化 scorecard 和 HTML/Markdown 可靠性报告

### English

> **AgentReliabilityHarness: Multi-Agent Runtime Fault Injection, Tool Firewall & Reliability Benchmark Framework**

1. Designed and implemented an offline-first Agent reliability benchmark framework, driving Mock Agent execution via ScenarioSpec + PolicySpec with model / tool / budget runtime policy enforcement
2. Built a ToolFirewall module with 4-tier risk classification (safe / low / high / critical) for Agent tool calls, blocking high-risk operations with full audit logging
3. Developed a FaultInjector subsystem supporting 4 fault injection categories: provider timeout, bad arguments, duplicate execution, and prompt injection escalation
4. Engineered TraceLogger + FailureClassifier pipeline, serializing runtime events to JSONL traces with automatic classification into 10 failure types
5. Implemented BenchmarkRunner + ScorecardGenerator covering 10 standard scenarios, producing structured scorecards and HTML/Markdown reliability reports

---

## 项目文档

- [架构设计](docs/architecture.md)
- [Spec 数据结构设计](docs/spec-design.md)
- [Benchmark 场景设计](docs/benchmark-design.md)
- [MVP 计划](docs/mvp-plan.md)
- [Non-Goals](docs/non-goals.md)
- [简历定位](docs/resume-positioning.md)

## License

MIT
