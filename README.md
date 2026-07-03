# AgentReliabilityHarness

AgentReliabilityHarness is an offline, deterministic Agent Runtime reliability benchmark and attack-defense lab.

AgentReliabilityHarness 是一个离线、确定性、可复现的 Agent Runtime 可靠性评测与攻防靶场。
它通过 YAML 场景模拟 Agent 可能产生的危险 tool call，在 FakeTool 执行前由 RuntimeGuard / ToolFirewall / ArgumentGuard 拦截，并生成终端告警、trace、scorecard 和中英文报告。

## 核心能力

- ScenarioSpec / YAML loader
- MockLLMProvider
- Fake Tools
- RuntimeGuard
- ToolFirewall
- ArgumentGuard
- FaultInjector
- TraceLogger
- FailureClassifier
- BenchmarkRunner
- ScorecardGenerator
- ReportRenderer
- scripts/attack_lab.py

## 快速演示

列出 30 个受控攻防场景：

```powershell
python scripts\attack_lab.py list
```

运行代表性场景：

```powershell
python scripts\attack_lab.py file-read AD-01
python scripts\attack_lab.py shell AD-09
python scripts\attack_lab.py data-exfiltration AD-13
python scripts\attack_lab.py network AD-17
```

运行后终端会出现安全告警：

```text
[安全告警 / SECURITY ALERT]
```

并生成：

```text
report.zh.md
report.en.md
scorecard.json
trace.jsonl
```

## Benchmark 场景

`scenarios/` 中保留 10 个标准 benchmark 场景，用于验证 Day 1 ~ Day 7 的运行时可靠性链路。

## 30 个攻防 case 覆盖范围

| 分类 | Case 范围 | 示例 |
|---|---|---|
| 文件读取 | AD-01 ~ AD-04 | 路径穿越、敏感路径 |
| 文件写入 | AD-05 ~ AD-08 | 系统路径写入、脚本写入 |
| 命令执行 | AD-09 ~ AD-12 | rm -rf /、curl 下载 |
| 数据外传 | AD-13 ~ AD-16 | API key、password、URL secret |
| 网络 SSRF | AD-17 ~ AD-19 | 云元数据、localhost、内网 IP |
| 工具权限绕过 | AD-20 ~ AD-22 | allowed_tools、denied_tools、prompt injection |
| 参数结构 | AD-23 ~ AD-26 | missing/null/non-object/oversized |
| Agent 行为异常 | AD-27 ~ AD-30 | 重复调用、隐藏 trace、模型切换 |

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

也可以直接运行某一类攻防靶场：

```powershell
python -m agent_reliability_harness.cli run `
  --scenarios-dir file_read_attack_scenarios `
  --output-dir runs/local-file-read `
  --run-id local-file-read
```

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

This project does not perform real attacks. All payloads are inert strings inside YAML scenarios, mock tool calls, traces, reports, and terminal output.

本项目不执行真实攻击。所有 payload 都只是 YAML、mock tool call、trace、report 和终端输出中的惰性字符串。
项目不会真实执行 shell、不会联网、不会读取系统文件、不会写系统路径、不会发送邮件、不会调用真实模型 API。

它关注“如何复现、记录、分类和汇总 Agent 运行时故障”，不承诺防御所有 prompt injection，也不连接真实 OpenAI、Anthropic、LangChain、AutoGen 或外部服务。

## 证据链

```text
tool_call
  -> firewall_decision / argument_guard_decision / runtime_guard_decision
  -> tool_execution_skipped
  -> failure_classified
  -> report.zh.md / report.en.md / scorecard.json
```

## 文档

- [架构设计](docs/architecture.md)
- [Spec 数据结构设计](docs/spec-design.md)
- [Benchmark 场景设计](docs/benchmark-design.md)
- [MVP 计划](docs/mvp-plan.md)
- [Non-Goals](docs/non-goals.md)

## License

MIT
