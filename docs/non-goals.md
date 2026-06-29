# Non-Goals

本文档明确 AgentReliabilityHarness **不做** 的事项，避免项目范围失控。

---

## MVP 阶段不做

### 真实 API Key

不配置、不使用、不要求任何真实的 LLM API Key。所有 LLM 交互通过 MockLLMProvider 完成。

**原因**：offline-first 是核心设计原则，接入真实 API 会破坏可复现性、增加成本、引入安全风险。

### LiteLLM 接入

不依赖 LiteLLM，不使用 LiteLLM 的统一 API 调用。

**原因**：MVP 阶段只需要 mock，不需要真实多 provider 路由。LiteLLMAdapter 作为后续可选扩展预留。

### Langfuse 接入

不接入 Langfuse，不导出 trace 到 Langfuse。

**原因**：MVP 阶段 trace 输出为本地 JSONL 文件，足够满足评测需求。LangfuseExporter 作为后续可选扩展预留。

### Promptfoo 接入

不接入 Promptfoo，不导入 Promptfoo 评测配置。

**原因**：AgentReliabilityHarness 有独立的 ScenarioSpec 体系，不需要依赖 Promptfoo 的配置格式。

### 复杂前端

不做 Web UI、不做 Dashboard、不做可视化界面。

**原因**：MVP 阶段通过 CLI + HTML 报告 + JSON 输出已足够。前端是后续独立项目。

### FastAPI 后台（第一阶段）

不做 REST API、不做后台服务、不做 HTTP 接口。

**原因**：MVP 是 CLI 工具，不需要 HTTP 服务层。

### 数据库

不使用 SQLite / PostgreSQL / MongoDB 等数据库。所有数据存储为本地文件（YAML / JSON / JSONL）。

**原因**：文件系统存储对 MVP 足够，且便于 git 版本管理和 CI 集成。

### Kubernetes

不做 K8s 部署、不写 Helm chart、不做容器编排。

**原因**：MVP 是本地 CLI 工具，不需要分布式部署。

### 多租户

不做用户管理、不做权限隔离、不做多租户数据分离。

**原因**：MVP 是单用户本地工具。

### Coding Agent Patch

不做代码修复、不做 GitHub issue 修复、不跑 pytest 修复任务。

**原因**：AgentReliabilityHarness 评测的是 Agent Runtime 的可靠性，不是 Agent 写代码的能力。详见 [architecture.md](architecture.md) 中的区别说明。

### 真实 MCP Server

不启动真实 MCP server、不通过 MCP 协议调用外部工具。

**原因**：MVP 使用 fake tools，不需要 MCP 协议栈。MCPToolAdapter 作为后续可选扩展预留。

### 云平台部署

不部署到 AWS / GCP / Azure，不做 CI/CD pipeline，不做生产环境配置。

**原因**：MVP 是本地开发工具。

### 企业级安全平台

不承诺生产级安全防护、不做 SOC2 合规、不做审计日志归档。

**原因**：AgentReliabilityHarness 是评测框架，不是安全产品。ToolFirewall 只是评测链路中的一个模块，不是生产级防火墙。

### 通用 LangGraph / CrewAI Workflow Builder

不做通用的 Agent workflow 编排工具、不集成 LangGraph / CrewAI / AutoGen。

**原因**：AgentReliabilityHarness 评测 Agent Runtime，不编排 Agent workflow。

---

## 总结

AgentReliabilityHarness 的边界是：

> **一个 offline-first 的、CLI 驱动的、用 mock 运行的 Agent Runtime 可靠性评测框架。**

任何超出这个边界的功能都应该被推迟到后续阶段，或作为独立项目/adapter 实现。
