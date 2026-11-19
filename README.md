# 风控规则命中回溯与误报压降

风控误杀了正常大额用户，需要能解释每条告警为什么触发，并把误报压下来。

```
data/events.jsonl   3014 条交易事件（含 2 类欺诈，只读，格式不变）
labels.json         欺诈事件标注
rules/rules.json    规则配置（窗口、阈值、版本），改规则改这里并升版本
engine.py           可解释引擎：滑动窗口评估 + 窗口快照 + 规则版本快照
traceback.py        告警回溯：按账号/告警 ID 还原全部依据事件
tests/              测试（零误报、全命中、窗口边界、版本固化、回溯、格式不变）
```

## Run

```bash
python engine.py data/events.jsonl alerts.json
python traceback.py --account u9001 --verify-with data/events.jsonl alerts.json
python -m pytest tests -q
```

## 规则（rules/rules.json，配置化、带版本）

| 规则 | 形态 | 窗口 | 阈值 |
|---|---|---|---|
| `burst_small_pay@v1` | 账号在**未见过的地区**高频小额支付 | 60s 严格滑动窗口（首末跨度 <60s） | 窗口内 pay ≥ 12 笔 |
| `new_device_big_withdraw@v1` | 新设备登录后同设备大额提现 | 登录后 1800s 关联窗口 | withdraw 金额 ≥ 10000 |

为什么正常大额用户不再被误杀：旧引擎只看单笔金额 ≥10000；新引擎要求
行为组合命中。实测正常流水的安全边际很宽——正常账号 60s 内最多 2 笔 pay
（欺诈是 12 笔/35s）、正常账号从未在地区 `999999` 出现、282 次正常新设备
登录后没有任何一次在同设备发生 ≥1000 的资金动作、全流水中仅 1 笔 withdraw。

## 五项要求如何落地

1. **规则描述窗口与阈值 + 窗口快照**：窗口/阈值全部在 `rules/rules.json`
   声明；命中时告警写入 `window_snapshot`：`event_count`（事件条数）、
   `time_range`（时间范围）、`aggregation`（聚合值，count/max）、实际跨度。
2. **零误报、两类欺诈全命中**：`tests/test_engine.py` 中
   `test_zero_false_positives_and_full_recall` 与
   `test_benign_stream_alone_produces_no_alerts` 强校验；当前全量结果恰为
   2 条告警，分别对应 u9001、u9002。
3. **按账号回溯依据事件**：每条告警内嵌 `evidence_events`（含事件文件
   行号 `line_no`）；`traceback.py --account/--alert-id` 可还原，
   `--verify-with` 还能按行号回到事件文件原文逐条复核。
4. **规则改动后旧告警仍可解释**：告警落库时固化完整 `rule_snapshot`
   （描述、参数、阈值、`rule_version`）。改配置必须升 `version`，旧告警
   自包含、不依赖当前 rules.json，永远按命中时的版本解释。
5. **不改事件文件格式**：引擎只读 `data/events.jsonl`；
   `test_event_file_format_unchanged` 用 git diff 与字段集合双重校验。

## 告警文件结构（alerts.json 摘要）

```json
{
  "engine_version": "2.0.0",
  "active_rule_versions": ["burst_small_pay@v1", "new_device_big_withdraw@v1"],
  "alerts": [
    {
      "alert_id": "ALERT-0001",
      "rule_id": "burst_small_pay",
      "rule_version": 1,
      "rule_versioned_id": "burst_small_pay@v1",
      "rule_snapshot": { "...": "命中时生效的完整规则（不可变）" },
      "account": "u9001",
      "window_snapshot": {
        "event_count": 12,
        "time_range": {"from": "...", "to": "..."},
        "aggregation": {"function": "count", "field": null, "value": 12}
      },
      "evidence_events": [ {"line_no": 3001, "...": "可回原文的依据事件"} ]
    }
  ]
}
```

## 调规则流程（不再需要发版改代码）

1. 编辑 `rules/rules.json` 中对应规则的 `params` / `threshold`；
2. 把该规则的 `version` 加 1；
3. 重跑 `engine.py`。新告警带新版本快照，历史告警保持旧版本快照、解释不变。
