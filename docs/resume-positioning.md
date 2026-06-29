# 简历定位

---

## 中文简历标题

> **AgentReliabilityHarness：多 Agent 运行时故障注入、工具防火墙与可靠性评测框架**

## 英文 GitHub Description

> Offline-first Agent Runtime reliability benchmark framework — Spec + Guard + Fault Injection + Trace + Scorecard for reproducing and classifying multi-agent runtime failures.

---

## MVP 完成后的 5 条中文简历 Bullet

1. **设计并实现 offline-first Agent 可靠性评测框架**，通过 ScenarioSpec + PolicySpec 驱动 Mock Agent 运行，覆盖 model / tool / budget 三类运行时策略校验，10 个标准场景全部通过

2. **实现 ToolFirewall 模块**，对 Agent 工具调用进行四级风险分级（safe / low / high / critical），拦截高风险操作并记录完整审计日志，阻止 prompt injection 导致的权限升级

3. **构建 FaultInjector 子系统**，支持 provider timeout、bad arguments、duplicate execution、prompt injection 等 4 类故障注入，复现 Agent Runtime 常见失败模式

4. **设计 TraceLogger + FailureClassifier 链路**，将运行时事件序列化为 JSONL trace 并自动分类为 10 种故障类型，实现故障的可追溯和可复现

5. **实现 BenchmarkRunner + ScorecardGenerator**，覆盖 10 个标准可靠性场景，生成结构化 scorecard（JSON）和 HTML/Markdown 可靠性报告

## MVP 完成后的 5 条英文简历 Bullet

1. **Designed and implemented an offline-first Agent reliability benchmark framework**, driving Mock Agent execution via ScenarioSpec + PolicySpec with model / tool / budget runtime policy enforcement across 10 standard scenarios

2. **Built a ToolFirewall module** with 4-tier risk classification (safe / low / high / critical) for Agent tool calls, blocking high-risk operations with full audit logging and preventing prompt injection escalation

3. **Developed a FaultInjector subsystem** supporting 4 fault injection categories — provider timeout, bad arguments, duplicate execution, and prompt injection — to reproduce common Agent Runtime failure modes

4. **Engineered TraceLogger + FailureClassifier pipeline**, serializing runtime events to JSONL traces with automatic classification into 10 failure types for traceable and reproducible fault analysis

5. **Implemented BenchmarkRunner + ScorecardGenerator** covering 10 standard reliability scenarios, producing structured JSON scorecards and HTML/Markdown reliability reports

---

## 面试时怎么解释这个项目

### 30 秒版本

> "我做了一个 Agent 运行时的可靠性评测框架。现在很多公司都在用 LLM Agent，但 Agent 在运行时会遇到各种问题——调用了不该调的工具、超了 token 预算、provider 超时了怎么 fallback。我的框架用 mock 的方式复现这些故障场景，然后通过 Guard 和 Firewall 来验证防护机制是否有效，最后生成一份可靠性报告。"

### 2 分钟版本

> "这个项目叫 AgentReliabilityHarness，定位是 AI Infra 层面的工具。它解决的问题是：当你的 Agent 在生产环境中运行时，你怎么知道它的运行时防护和容错机制是靠谱的？
>
> 我设计了一套 Spec 驱动的评测方法：用 YAML 定义场景（比如高风险工具调用、provider 超时、token 超预算），然后框架会用 MockLLMProvider 和 Fake Tools 模拟 Agent 运行，RuntimeGuard 和 ToolFirewall 会实时检查策略，FaultInjector 会主动注入故障。
>
> 所有运行时事件都会被记录到 trace.jsonl，FailureClassifier 会自动分类故障类型，最后 ScorecardGenerator 生成评分卡和 HTML 报告。
>
> 整个框架 offline-first，不需要 API Key，跑一次 10 个场景不到 1 秒，可以直接集成到 CI。
>
> 核心价值不在于任何单一模块，而在于从 Spec 到 Report 的完整链路。目前市面上有做 Agent Gateway 的、有做 trace 可视化的、有做 prompt 评测的，但没有一个工具把故障注入、Guard、Trace、分类、评分串成完整的可靠性评测链路。"

---

## 面试官可能追问的问题和回答

### Q1: 为什么不直接用真实的 LLM API？

> "Offline-first 是有意的设计决策。真实 API 的响应不可控，无法精确复现同一故障。Mock 保证了测试的确定性和可复现性。而且零成本、毫秒级执行、不需要 API Key，非常 CI 友好。后续可以通过 LiteLLMAdapter 接入真实 API 做 online 验证，但 mock 始终是默认模式。"

### Q2: 这个项目和 Langfuse / LangSmith 有什么区别？

> "Langfuse 和 LangSmith 是 observability 平台，关注的是 **线上 Agent 执行的可视化和追踪**。AgentReliabilityHarness 关注的是 **离线场景下的故障复现和可靠性评测**。打个比方：Langfuse 像是生产环境的 APM 监控，AgentReliabilityHarness 像是发布前的混沌工程测试。两者互补，不是竞争关系。我的 trace 也可以通过 LangfuseExporter 导出到 Langfuse。"

### Q3: ToolFirewall 和生产级的 Agent 安全方案有什么区别？

> "ToolFirewall 是评测框架中的一个模块，目的是验证'如果你有一个防火墙，它能不能正确拦截'。它不是一个生产级的安全产品。生产级方案需要考虑性能、高可用、审计合规等，ToolFirewall 只关注策略逻辑的正确性验证。"

### Q4: 10 个场景够用吗？为什么不做更多？

> "10 个场景是 MVP 的标准集，覆盖了 Guard、Firewall、FaultInjector、Classifier 四大模块和 10 种故障类型。框架是 Spec-Driven 的，添加新场景只需要写一个 YAML 文件，不需要改代码。后续可以扩展到 50+ 场景，覆盖更多 Agent Runtime 故障模式。"

### Q5: 这个项目的技术难点在哪？

> "主要有三个：一是 Spec 体系设计，要让 YAML 定义足够灵活又不过度复杂；二是 FaultInjector 的实现，要在不修改被测模块代码的前提下注入故障；三是 FailureClassifier 的分类逻辑，比如要区分 prompt injection 和普通的 tool blocked，需要分析 trace 事件的上下文，不能只看单个事件。"

### Q6: 你一个人做的吗？花了多久？

> "核心是我一个人设计和实现的，7 天 MVP。架构设计（Spec-Driven + 4 层分层）是我自己定的，10 个 benchmark 场景是我根据 Agent 运行时的常见故障模式设计的。代码实现部分有用 AI 辅助编码，但架构决策、场景设计、边界控制都是我自己做的。"

---

## 如何解释它和同类工具的区别

### vs LiteLLM

| 维度 | LiteLLM | AgentReliabilityHarness |
|------|---------|------------------------|
| 定位 | LLM API 统一代理 | Agent Runtime 可靠性评测 |
| 核心功能 | 100+ provider 路由 | 故障注入 + Guard + 评分 |
| 关注层 | API 调用层 | 运行时行为层 |
| 关系 | 可作为 ARH 的 adapter | 独立框架 |

### vs MCPGuard

| 维度 | MCPGuard | AgentReliabilityHarness |
|------|---------|------------------------|
| 定位 | MCP 协议安全中间件 | 运行时可靠性评测框架 |
| 协议依赖 | 依赖 MCP | 不依赖任何协议 |
| 核心功能 | tool call 权限控制 | Spec 驱动的故障复现与评分 |
| ToolFirewall | 生产级组件 | 评测模块之一 |

### vs Langfuse

| 维度 | Langfuse | AgentReliabilityHarness |
|------|---------|------------------------|
| 定位 | LLM Observability 平台 | 离线可靠性评测框架 |
| 运行模式 | 线上 | 离线 |
| 核心功能 | trace 可视化 + 评估 | 故障注入 + 分类 + 评分 |
| 关系 | 可作为 ARH 的 trace 导出目标 | 独立框架 |

### vs Promptfoo

| 维度 | Promptfoo | AgentReliabilityHarness |
|------|-----------|------------------------|
| 定位 | Prompt 评测工具 | Agent Runtime 评测框架 |
| 评测对象 | Prompt 质量 | 运行时防护与容错 |
| 故障类型 | Prompt 输出质量 | 运行时故障（超时/权限/注入等） |
| 关系 | 可导入场景定义 | 独立框架 |

---

## 如何解释它和 Coding Agent Harness 的区别

> "Coding Agent Harness（比如 SWE-bench）评测的是 **Agent 写代码 / 修 bug 的能力**。它给 Agent 一个 GitHub issue 和一个代码仓库，看 Agent 能不能生成正确的 patch 让 pytest 通过。
>
> AgentReliabilityHarness 评测的是 **Agent 运行时基础设施的可靠性**。它不关心 Agent 修出来的代码对不对，它关心的是：当 Agent 尝试调用高风险工具时系统有没有拦截？当 provider 超时时 fallback 有没有生效？当 token 超预算时运行有没有正确终止？
>
> 一个评测 Agent 的输出质量，一个评测 Agent 的运行时安全性和容错性。两者完全不在同一个维度上。"
