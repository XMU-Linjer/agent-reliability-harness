# MVP 7 天施工计划

---

## Day 1：Spec 定义与场景样例

### 施工目标

- 定义 `ScenarioSpec`, `AgentRunSpec`, `PolicySpec` 的 Pydantic model
- 定义所有枚举类型：`FailureType`, `EventType`, `ToolRiskLevel`, `GuardAction`
- 编写 3 个场景 YAML 样例：`normal_agent_run`, `model_not_allowed`, `high_risk_tool_blocked`
- 实现 YAML spec loader

### 验收命令

```bash
# Pydantic model 可以正常导入
python -c "from agent_reliability_harness.spec import ScenarioSpec, AgentRunSpec, PolicySpec"

# YAML 场景可以正常加载和校验
python -c "from agent_reliability_harness.spec import load_scenario; s = load_scenario('scenarios/normal_agent_run.yaml'); print(s.id)"

# 类型检查通过
mypy agent_reliability_harness/spec.py

# 单元测试通过
pytest tests/test_spec.py -v
```

### 不能做的越界事项

- ❌ 不要实现 MockLLMProvider
- ❌ 不要实现 RuntimeGuard / ToolFirewall
- ❌ 不要写 CLI
- ❌ 不要做 trace / report

### 建议 commit message

```
feat(spec): define ScenarioSpec/AgentRunSpec/PolicySpec models and load 3 scenario YAMLs
```

---

## Day 2：MockLLMProvider 和 Fake Tools

### 施工目标

- 实现 `MockLLMProvider`，支持预设响应序列
- 实现 5 个 fake tools：`read_file`, `write_file`, `execute_shell`, `search_web`, `send_email`
- 每个 fake tool 有元数据（name, description, risk_level, parameters）
- 跑通 `normal_agent_run` 场景的完整 mock 执行

### 验收命令

```bash
# MockLLMProvider 可以返回预设响应
python -c "from agent_reliability_harness.runtime import MockLLMProvider; p = MockLLMProvider([...]); print(p.chat(...))"

# Fake tools 可以执行
python -c "from agent_reliability_harness.tools import get_tool; t = get_tool('read_file'); print(t.execute(path='test.txt'))"

# normal_agent_run 场景端到端跑通
python -m agent_reliability_harness.runner scenarios/normal_agent_run.yaml

# 单元测试通过
pytest tests/test_runtime.py tests/test_tools.py -v
```

### 不能做的越界事项

- ❌ 不要接真实 LLM API
- ❌ 不要实现 Guard / Firewall
- ❌ 不要实现 trace 持久化
- ❌ 不要做 CLI 美化

### 建议 commit message

```
feat(runtime): implement MockLLMProvider + 5 fake tools, pass normal_agent_run
```

---

## Day 3：RuntimeGuard + ToolFirewall

### 施工目标

- 实现 `RuntimeGuard`，覆盖 3 类检查：model 白名单、token budget、answer verification
- 实现 `ToolFirewall`，覆盖 2 类检查：risk level、tool 白名单/黑名单
- 返回 `GuardDecision` 对象
- 跑通 `model_not_allowed`, `budget_exceeded`, `high_risk_tool_blocked`, `write_file_without_permission` 4 个场景

### 验收命令

```bash
# Guard 拦截不允许的模型
pytest tests/test_guard.py::test_model_not_allowed -v

# Guard 拦截超预算
pytest tests/test_guard.py::test_budget_exceeded -v

# Firewall 拦截高风险工具
pytest tests/test_firewall.py::test_high_risk_blocked -v

# Firewall 拦截不在白名单的工具
pytest tests/test_firewall.py::test_permission_denied -v

# 全部通过
pytest tests/test_guard.py tests/test_firewall.py -v
```

### 不能做的越界事项

- ❌ 不要实现 FaultInjector
- ❌ 不要实现 trace 输出
- ❌ 不要做复杂的策略表达式引擎
- ❌ 不要做动态策略更新

### 建议 commit message

```
feat(guard): implement RuntimeGuard + ToolFirewall, cover model/tool/budget policies
```

---

## Day 4：FaultInjector

### 施工目标

- 实现 `FaultInjector`，支持 4 类故障注入：
  - `timeout`：模拟 provider 超时
  - `bad_args`：修改 tool call 参数为无效值
  - `duplicate`：复制上一次 tool call
  - `prompt_injection`：在 LLM 响应中注入恶意 tool call
- 跑通 `provider_timeout_fallback`, `bad_tool_arguments`, `duplicate_tool_execution`, `prompt_injection_tool_escalation` 4 个场景

### 验收命令

```bash
# Timeout 注入
pytest tests/test_fault_injector.py::test_timeout -v

# Bad args 注入
pytest tests/test_fault_injector.py::test_bad_args -v

# Duplicate 检测
pytest tests/test_fault_injector.py::test_duplicate -v

# Prompt injection 检测
pytest tests/test_fault_injector.py::test_prompt_injection -v

# 全部通过
pytest tests/test_fault_injector.py -v
```

### 不能做的越界事项

- ❌ 不要实现 trace 持久化
- ❌ 不要实现 scorecard
- ❌ 不要做复杂的故障组合
- ❌ 不要做概率性故障注入

### 建议 commit message

```
feat(fault): implement FaultInjector with timeout/bad_args/duplicate/injection
```

---

## Day 5：TraceLogger + FailureClassifier

### 施工目标

- 实现 `TraceLogger`，将运行时事件序列化为 JSONL 写入 trace.jsonl
- 实现 `FailureClassifier`，分析 trace 事件流并输出 `FailureType`
- 所有模块接入 TraceLogger（Guard, Firewall, FaultInjector, Provider, Tools）
- 验证 10 个场景的 trace 输出和故障分类

### 验收命令

```bash
# trace.jsonl 格式正确
python -c "import json; [json.loads(l) for l in open('runs/test/trace.jsonl')]"

# FailureClassifier 分类正确
pytest tests/test_classifier.py -v

# TraceLogger 记录完整
pytest tests/test_trace.py -v

# 全部通过
pytest tests/test_trace.py tests/test_classifier.py -v
```

### 不能做的越界事项

- ❌ 不要实现 scorecard
- ❌ 不要实现 report 渲染
- ❌ 不要做 trace 可视化
- ❌ 不要接 Langfuse

### 建议 commit message

```
feat(trace): implement TraceLogger + FailureClassifier, output JSONL traces
```

---

## Day 6：BenchmarkRunner + ScorecardGenerator

### 施工目标

- 实现 `BenchmarkRunner`，批量加载并运行所有 10 个场景
- 实现 `ScorecardGenerator`，汇总结果生成 scorecard.json
- 实现 `arh bench --all` CLI 命令
- 10 个场景全部跑通并生成 scorecard

### 验收命令

```bash
# CLI 跑全部场景
arh bench --all

# scorecard.json 格式正确
python -c "import json; s = json.load(open('runs/latest/scorecard.json')); print(f'{s[\"passed\"]}/{s[\"total\"]} passed')"

# 10/10 通过
arh bench --all && python -c "import json; s = json.load(open('runs/latest/scorecard.json')); assert s['passed'] == 10"

# 单元测试通过
pytest tests/test_runner.py tests/test_scorecard.py -v
```

### 不能做的越界事项

- ❌ 不要实现 HTML report
- ❌ 不要做并行执行
- ❌ 不要做结果持久化到数据库
- ❌ 不要做 CI 集成

### 建议 commit message

```
feat(bench): implement BenchmarkRunner + ScorecardGenerator, pass 10/10 scenarios
```

---

## Day 7：Report + 收尾

### 施工目标

- 实现 `ReportRenderer`，从 scorecard.json 生成 report.md 和 report.html
- HTML 报告使用 Jinja2 模板
- 完善 README：加入真实输出示例和截图
- 补齐所有 pytest 测试
- 确保 `arh run / bench / report / trace` 四个 CLI 子命令可用
- 准备简历截图素材

### 验收命令

```bash
# 生成 HTML 报告
arh report --format html --output runs/latest/report.html

# 生成 Markdown 报告
arh report --format md --output runs/latest/report.md

# 全量测试通过
pytest --cov=agent_reliability_harness -v

# CLI 帮助信息正常
arh --help
arh run --help
arh bench --help
arh report --help
```

### 不能做的越界事项

- ❌ 不要做复杂前端
- ❌ 不要做 FastAPI
- ❌ 不要接真实 API
- ❌ 不要做 Docker / K8s 部署
- ❌ 不要做新功能

### 建议 commit message

```
feat(report): generate HTML/Markdown reliability report, finalize MVP

docs: update README with real output examples and screenshots
```

---

## 总览

| Day | 模块 | 产出 | 场景覆盖 |
|-----|------|------|----------|
| 1 | Spec | Pydantic models + 3 YAML | 0 |
| 2 | Runtime | MockLLMProvider + 5 tools | 1 |
| 3 | Guard | RuntimeGuard + ToolFirewall | 5 |
| 4 | Fault | FaultInjector | 9 |
| 5 | Trace | TraceLogger + FailureClassifier | 10（分类） |
| 6 | Bench | BenchmarkRunner + Scorecard | 10（评分） |
| 7 | Report | ReportRenderer + 收尾 | 10（完整） |
