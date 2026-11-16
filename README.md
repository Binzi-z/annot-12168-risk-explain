# 风控规则命中回溯与误报压降

风控误杀了正常大额用户，需要能解释每条告警为什么触发，并把误报压下来。

```
data/events.jsonl   3014 条交易事件（含 2 类欺诈，只读，引擎不会改写）
labels.json         欺诈事件标注
rules/rulebook.json 规则书（窗口/阈值外置，改规则不发版，带版本号）
engine.py           规则引擎 + 告警回溯 CLI
tests/              全量测试（21 项）
```

## Run

```bash
python -m pytest tests -q
python engine.py data/events.jsonl alerts.json
# 也可指定规则书：
python engine.py data/events.jsonl alerts.json --rulebook rules/rulebook.json
```

## 回溯某条告警的全部依据

```bash
# 按账号回溯该账号的全部告警（含每条证据事件及源文件行号）
python engine.py trace alerts.json u9002

# 按告警 id 查看完整解释（规则版本、窗口快照、证据事件）
python engine.py explain alerts.json 'burst_small_pay:u9001:2026-10-02T03:31:11'
```

库形式：`engine.trace_alerts(doc, account)`、`engine.explain_alert(doc, alert_id)`、
`engine.verify_evidence(alert, source_path)`（回读源文件逐行核对证据是否仍一致）。

## 两类欺诈规则（参数全部在 rules/rulebook.json）

| 规则 | 窗口与阈值 | 快照中的聚合值 |
|---|---|---|
| `burst_small_pay` | 同一账号、该账号**从未出现过的 IP 地区**，`< 60s` 滑动窗口内 `>= 12` 笔且每笔 `<= 500` 的支付 | `pay_count` / `amount_sum` / `amount_max` / `regions` |
| `new_device_big_withdraw` | 账号在**首见设备**上 login 后 `<= 300s` 内，于同一设备发起 `>= 10000` 的提现 | `withdraw_amount` / `login_withdraw_gap_seconds` |

设计取舍（基于全量 3014 条事件实测）：

- 正常流水金额上限 199、60 秒内同账号最多 2 笔支付、没有任何 withdraw；
  欺诈段是 12 笔 / 35 秒 / 地区 999999，以及新机 40 秒后提现 48000。阈值留有安全余量。
- “unseen region / new device” 都按**该账号的历史事件**判定，不依赖设备命名特征
  （正常账号本来就有 25–29 台设备、多个地区）。
- 窗口边界为严格小于：跨度恰好等于 `window_seconds` 不命中。
- 同一账号同一条规则只在越过阈值的瞬间告警一次（边沿触发），不会对后续每笔事件重复告警。

## 告警长什么样

每条告警都自解释，不依赖当前磁盘上的规则书：

```json
{
  "alert_id": "burst_small_pay:u9001:2026-10-02T03:31:11",
  "rule": "burst_small_pay",
  "rule_version": "1.0.0",
  "rulebook_version": "2026.10.02-r1",
  "account": "u9001",
  "description": "…中文规则描述…",
  "trigger_event_line": 3012,
  "trigger_ts": "2026-10-02T03:31:11",
  "rule_snapshot": { "...": "命中时的完整规则参数（含窗口与阈值）" },
  "window_snapshot": {
    "event_count": 12,
    "from_ts": "2026-10-02T03:30:36",
    "to_ts": "2026-10-02T03:31:11",
    "span_seconds": 35.0,
    "window_seconds": 60.0,
    "aggregations": { "pay_count": 12, "amount_sum": 118.8, "amount_max": 9.9 }
  },
  "evidence_events": [ { "line": 3001, "event": { "...": "原始事件全文" } } ]
}
```

## 规则版本与可解释性

- 规则书有 `rulebook_version`，每条规则有独立 `rule_version`；
- 告警固化命中时刻的 `rule_snapshot` 与两个版本号。规则书后续怎么改，
  旧告警仍按旧参数解释，证据行号还能用 `verify_evidence` 回源核对；
- 调参只改 `rules/rulebook.json`（引擎启动时校验必填字段与未知规则名），无需改代码发版。

## 对事件文件零侵入

引擎只以只读方式打开 jsonl；`tests/test_engine.py::test_event_file_unchanged`
会在完整跑批前后做字节级比对，并校验每行仍是原始 6 字段 schema。
