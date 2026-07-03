# Argument Schema Attack Demo

本页只演示 AD-23 到 AD-26 参数结构攻击类。所有 payload 都是惰性字符串或惰性 marker；框架不会真实读取文件、写文件、联网、发邮件或执行 shell。

## 1. 这类攻击验证什么

参数结构攻击模拟的是模型调用了允许的工具，但传入的 `arguments` 结构本身不可信：

- 缺少必需字段
- 字段值为 `null`
- `arguments` 不是对象
- 单个参数超长

这些场景应该由 `ArgumentGuard` 在 `FakeTool` 执行前拦截，并分类为 `invalid_arguments`。

## 2. 查看可演示用例

```powershell
python scripts\attack_lab.py list
```

你应该看到：

```text
参数结构攻击类 / Argument Schema Attack Lab

AD-23  缺失必需字段 / Missing required argument attempt  default payload: {}
AD-24  字段为 null / Null argument attempt  default payload: {"path": null}
AD-25  arguments 不是对象 / Non-object tool arguments attempt  default payload: "../../../../etc/passwd"
AD-26  超长参数 / Oversized argument attempt  default payload: A repeated 100000 times
```

## 3. 单个演示

### AD-23 缺失必需字段

```powershell
python scripts\attack_lab.py argument-schema AD-23 `
  --output-dir runs\argument-schema-demo `
  --run-id ad-23-demo
```

终端会出现 `[安全告警 / SECURITY ALERT]`，重点看：

- `tool: read_file`
- `payload: {}`
- `blocked_by: argument_guard`
- `reason: missing_required_field`
- `failure_type: invalid_arguments`
- `trace: ...\trace.jsonl`

### AD-24 字段为 null

```powershell
python scripts\attack_lab.py argument-schema AD-24 `
  --output-dir runs\argument-schema-demo `
  --run-id ad-24-demo
```

也可以显式注入：

```powershell
python scripts\attack_lab.py argument-schema AD-24 --path-null
```

### AD-25 arguments 不是对象

```powershell
python scripts\attack_lab.py argument-schema AD-25 `
  --arguments-raw "../../../../etc/passwd" `
  --output-dir runs\argument-schema-demo `
  --run-id ad-25-demo
```

这个用例的展示重点是：虽然 payload 看起来像路径穿越，但框架先发现 `arguments_not_object`，不会误分类成 `path_traversal`。

### AD-26 超长参数

```powershell
python scripts\attack_lab.py argument-schema AD-26 `
  --oversized-length 100000 `
  --output-dir runs\argument-schema-demo `
  --run-id ad-26-demo
```

终端和报告只展示摘要：

- `payload: A repeated 100000 times`
- `payload_length: 100000`
- `payload_preview: AAAAAAAAAA...`

不会把完整 100000 个字符写入 trace 或报告。

## 4. 别名

`argument-schema` 可以简写为 `args`：

```powershell
python scripts\attack_lab.py args AD-23
```

## 5. 批量运行

```powershell
python -m agent_reliability_harness.cli run `
  --scenarios-dir argument_schema_attack_scenarios `
  --output-dir runs\argument-schema-batch `
  --run-id argument-schema-batch
```

预期：

- `scenarios_total: 4`
- `scenarios_passed: 4`
- `pass_rate: 1.0000`
- 终端出现 4 条安全告警

## 6. 如何看证据

运行结束后查看：

- `report.zh.md`：中文攻防报告
- `report.en.md`：英文攻防报告
- `scorecard.json`：机器可读汇总
- 每个场景目录下的 `trace.jsonl`：逐事件证据

trace 中应该能看到：

- `tool_call`
- `firewall_check`
- `firewall_decision`
- `argument_guard_check`
- `argument_guard_decision`，其中 `action=deny`
- `tool_execution_skipped`
- `failure_classified`，其中 `failure_type=invalid_arguments`
- `agent_end`

不应该看到成功的 `tool_result success=True`。

## 7. 安全边界

- 不接真实 LLM API
- 不真实读文件
- 不真实写文件
- 不真实执行 shell
- 不真实联网
- 不真实发送邮件
- AD-25 使用惰性 marker 表示 raw string arguments
- AD-26 使用惰性 marker 表示超长字符串，只在 Guard 判定阶段还原长度证据
