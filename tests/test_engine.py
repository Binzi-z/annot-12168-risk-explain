import json
import os
import subprocess
import sys
from datetime import datetime, timedelta

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine  # noqa: E402

# 文件名 traceback.py 与标准库同名，用 importlib 按路径显式加载，避免 import 冲突
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("risk_traceback", os.path.join(ROOT, "traceback.py"))
tb_tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tb_tool)

EVENTS = os.path.join(ROOT, "data", "events.jsonl")
LABELS = os.path.join(ROOT, "labels.json")
RULES = os.path.join(ROOT, "rules", "rules.json")


# --------------------------------------------------------------------------- #
# 夹具 / 辅助
# --------------------------------------------------------------------------- #
def run_cli(tmp_path):
    out = tmp_path / "alerts.json"
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "engine.py"), EVENTS, str(out), "--rules", RULES],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )
    return r, out


@pytest.fixture(scope="module")
def store():
    rules = engine.load_rules(RULES)
    alerts = engine.serialize_alerts(engine.evaluate(engine.read_events(EVENTS), rules))
    return {"alerts": alerts, "rules": rules}


def write_store(path, store):
    """落盘时只写可 JSON 序列化的告警部分（Rule 实例不进告警文件）。"""
    path.write_text(json.dumps({"alerts": store["alerts"]}, ensure_ascii=False), encoding="utf-8")


def make_event(account, ts, action="pay", amount=9.9, device=None, region="110000", line=1):
    return {
        "_line": line,
        "_dt": datetime.fromisoformat(ts) if isinstance(ts, str) else ts,
        "ts": ts if isinstance(ts, str) else ts.isoformat(),
        "account": account,
        "device": device or f"{account}-d1",
        "action": action,
        "amount": amount,
        "ip_region": region,
    }


def burst_events(account, n, start, gap_seconds, region):
    t = datetime.fromisoformat(start)
    return [
        make_event(account, t + timedelta(seconds=i * gap_seconds), region=region, line=i + 1)
        for i in range(n)
    ]


# --------------------------------------------------------------------------- #
# 基线骨架测试（保留原有用例语义）
# --------------------------------------------------------------------------- #
def test_events_present():
    with open(EVENTS, encoding="utf-8") as fh:
        assert sum(1 for _ in fh) > 1000


def test_labels_present():
    with open(LABELS, encoding="utf-8") as fh:
        assert len(json.load(fh)["fraud"]) >= 2


def test_engine_runs(tmp_path):
    r, out = run_cli(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "alerts" in json.loads(out.read_text(encoding="utf-8"))


def test_alerts_have_account(tmp_path):
    _, out = run_cli(tmp_path)
    for a in json.loads(out.read_text(encoding="utf-8"))["alerts"]:
        assert a.get("account")


# --------------------------------------------------------------------------- #
# ② 对正常流水零误报，两类欺诈全部命中
# --------------------------------------------------------------------------- #
def test_zero_false_positives_and_full_recall(store):
    labels = json.load(open(LABELS, encoding="utf-8"))
    fraud_accounts = {f["account"] for f in labels["fraud"]}
    expected_rules = {f["rule"] for f in labels["fraud"]}

    alerts = store["alerts"]
    assert alerts, "应当至少产出两条欺诈告警"
    # 零误报：告警账号全部属于标注欺诈账号
    assert all(a["account"] in fraud_accounts for a in alerts)
    # 两类欺诈全部命中
    assert {a["rule_id"] for a in alerts} == expected_rules
    assert {a["account"] for a in alerts} == fraud_accounts


def test_benign_stream_alone_produces_no_alerts():
    rules = engine.load_rules(RULES)
    benign = [e for e in engine.read_events(EVENTS) if e["account"] not in ("u9001", "u9002")]
    assert engine.evaluate(benign, rules) == []


# --------------------------------------------------------------------------- #
# ① 规则描述滑动窗口与阈值；命中必须留下窗口快照
# --------------------------------------------------------------------------- #
def test_alert_contains_window_snapshot(store):
    for a in store["alerts"]:
        ws = a["window_snapshot"]
        # 三要素：事件条数、时间范围、聚合值
        assert isinstance(ws["event_count"], int) and ws["event_count"] >= 1
        assert ws["time_range"]["from"] < ws["time_range"]["to"] or ws["event_count"] == 1
        agg = ws["aggregation"]
        assert agg["function"] in ("count", "max") and "value" in agg
        # 快照与依据事件互相印证
        assert len(a["evidence_events"]) == ws["event_count"]
        for e in a["evidence_events"]:
            assert ws["time_range"]["from"] <= e["ts"] <= ws["time_range"]["to"]


def test_rule_config_declares_window_and_threshold():
    cfg = json.load(open(RULES, encoding="utf-8"))
    for rule in cfg["rules"]:
        assert rule["id"] and isinstance(rule["version"], int)
        assert "window_seconds" in rule["params"] or "link_max_gap_seconds" in rule["params"]
        assert rule["threshold"]["operator"] == ">="
        assert "value" in rule["threshold"]


def test_burst_snapshot_matches_labels(store):
    labels = {f["account"]: f for f in json.load(open(LABELS, encoding="utf-8"))["fraud"]}
    a = next(a for a in store["alerts"] if a["rule_id"] == "burst_small_pay")
    ws = a["window_snapshot"]
    want = labels["u9001"]
    assert ws["event_count"] == 12
    # labels.json 的时间是人工描述的约数，以事件文件首/末条依据事件为准，
    # 同时要求与标注时间同分钟级、且落在标注区间附近
    first_ev, last_ev = a["evidence_events"][0], a["evidence_events"][-1]
    assert ws["time_range"] == {"from": first_ev["ts"], "to": last_ev["ts"]}
    assert first_ev["ts"][:16] == want["from"][:16]
    assert last_ev["ts"][:16] == want["to"][:16]
    assert ws["aggregation"] == {"function": "count", "field": None, "value": 12}
    assert ws["span_seconds"] < 60


def test_withdraw_snapshot_matches_labels(store):
    labels = {f["account"]: f for f in json.load(open(LABELS, encoding="utf-8"))["fraud"]}
    a = next(a for a in store["alerts"] if a["rule_id"] == "new_device_big_withdraw")
    ws = a["window_snapshot"]
    want = labels["u9002"]
    assert ws["event_count"] == 2
    first_ev, last_ev = a["evidence_events"][0], a["evidence_events"][-1]
    assert ws["time_range"] == {"from": first_ev["ts"], "to": last_ev["ts"]}
    assert first_ev["ts"] == want["from"] and last_ev["ts"] == want["to"]
    assert ws["aggregation"]["value"] == 48000.0


# --------------------------------------------------------------------------- #
# 滑动窗口边界行为（合成事件，不碰事件文件）
# --------------------------------------------------------------------------- #
def _burst_rule(**overrides):
    rule = engine.Rule(
        id="burst_small_pay",
        version=1,
        description="t",
        params={
            "action": "pay",
            "window_seconds": 60,
            "min_events": 12,
            "window_bounds": "span_lt_window_seconds",
            "unseen_region_scope": "account_history",
            **overrides,
        },
        aggregation={"field": None, "function": "count"},
        threshold={"metric": "event_count", "operator": ">=", "value": 12},
        raw={},
    )
    return engine.BurstSmallPayRule(rule)


def test_window_fires_when_twelve_pay_inside_60s():
    ev = burst_events("uX", 12, "2026-10-01T00:00:00", 5, "999999")  # 跨度 55s
    rule = _burst_rule()
    alerts = [out for e in ev if (out := rule.on_event(e))]
    assert len(alerts) == 1
    assert alerts[0]["window_snapshot"]["event_count"] == 12


def test_window_excludes_events_at_exact_60s_boundary():
    # 12 笔、每笔间隔 6s => 首末跨度 66s；严格 <60s 窗口永远凑不齐 12 笔
    ev = burst_events("uX", 12, "2026-10-01T00:00:00", 6, "999999")
    rule = _burst_rule()
    assert [out for e in ev if (out := rule.on_event(e))] == []


def test_known_region_burst_does_not_fire():
    # 先在常见地区建立历史，再在同一地区高频支付 -> 不命中（正常频繁小额）
    history = [make_event("uX", "2026-09-30T00:00:00", region="110000", line=1)]
    burst = burst_events("uX", 12, "2026-10-01T00:00:00", 5, "110000")
    for e in burst:
        e["_line"] += 1
    rule = _burst_rule()
    out = []
    for e in history + burst:
        r = rule.on_event(e)
        if r:
            out.append(r)
    assert out == []


def test_burst_fires_only_once_per_account():
    ev = burst_events("uX", 20, "2026-10-01T00:00:00", 1, "999999")
    rule = _burst_rule()
    alerts = [out for e in ev if (out := rule.on_event(e))]
    assert len(alerts) == 1


def test_new_device_withdraw_rule_synthetic():
    rule_def = engine.Rule(
        id="new_device_big_withdraw",
        version=1,
        description="t",
        params={
            "login_action": "login",
            "money_action": "withdraw",
            "withdraw_min_amount": 10000.0,
            "link_max_gap_seconds": 1800,
            "new_device_scope": "account_history",
            "require_same_device": True,
        },
        aggregation={"field": "amount", "function": "max"},
        threshold={"metric": "withdraw_amount", "operator": ">=", "value": 10000.0},
        raw={},
    )
    rule = engine.NewDeviceBigWithdrawRule(rule_def)
    login = make_event("uY", "2026-10-01T00:00:00", action="login", amount=0, device="uY-new", region="999999")
    withdraw = make_event("uY", "2026-10-01T00:10:00", action="withdraw", amount=48000, device="uY-new", region="999999", line=2)
    assert rule.on_event(login) is None
    alert = rule.on_event(withdraw)
    assert alert and alert["window_snapshot"]["aggregation"]["value"] == 48000.0

    # 超过关联窗口 / 不同设备 / 金额不足 均不命中
    rule2 = engine.NewDeviceBigWithdrawRule(rule_def)
    rule2.on_event(login)
    late = make_event("uY", "2026-10-01T00:31:00", action="withdraw", amount=48000, device="uY-new", line=3)
    assert rule2.on_event(late) is None

    rule3 = engine.NewDeviceBigWithdrawRule(rule_def)
    rule3.on_event(login)
    other_dev = make_event("uY", "2026-10-01T00:05:00", action="withdraw", amount=48000, device="uY-other", line=4)
    assert rule3.on_event(other_dev) is None

    rule4 = engine.NewDeviceBigWithdrawRule(rule_def)
    rule4.on_event(login)
    small = make_event("uY", "2026-10-01T00:05:00", action="withdraw", amount=999, device="uY-new", line=5)
    assert rule4.on_event(small) is None


# --------------------------------------------------------------------------- #
# ③ 按账号回溯某条告警的全部依据事件
# --------------------------------------------------------------------------- #
def test_traceback_by_account_and_alert_id(store, tmp_path):
    path = tmp_path / "alerts.json"
    write_store(path, store)
    loaded = tb_tool.load_alert_store(str(path))

    for account in ("u9001", "u9002"):
        recs = tb_tool.find_alerts(loaded, account, None)
        assert len(recs) == 1
        rendered = tb_tool.render(recs[0])
        assert rendered["account"] == account
        assert rendered["evidence_event_count"] >= 1
        assert all({"line_no", "ts", "action", "amount"} <= set(e) for e in rendered["evidence_events"])

    first_id = loaded["alerts"][0]["alert_id"]
    assert len(tb_tool.find_alerts(loaded, None, first_id)) == 1
    assert tb_tool.find_alerts(loaded, "nobody", None) == []


def test_traceback_verifies_against_source_file(store, tmp_path):
    path = tmp_path / "alerts.json"
    write_store(path, store)
    loaded = tb_tool.load_alert_store(str(path))
    for alert in loaded["alerts"]:
        v = tb_tool.verify_against_events(alert, EVENTS)
        assert v["all_consistent"] is True
        assert v["missing_lines"] == []


def test_traceback_cli(tmp_path):
    r, out = run_cli(tmp_path)
    assert r.returncode == 0
    p = subprocess.run(
        [sys.executable, os.path.join(ROOT, "traceback.py"), "--account", "u9001", str(out)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=dict(os.environ, PYTHONIOENCODING="utf-8"),
    )
    assert p.returncode == 0
    assert "ALERT-0001" in p.stdout and "L3001" in p.stdout


# --------------------------------------------------------------------------- #
# ④ 规则改动后旧告警仍可解释（规则版本快照）
# --------------------------------------------------------------------------- #
def test_rule_version_snapshot_is_embedded_and_immutable(store):
    for a in store["alerts"]:
        snap = a["rule_snapshot"]
        assert snap["id"] == a["rule_id"]
        assert snap["version"] == a["rule_version"]
        assert "params" in snap and "threshold" in snap and "description" in snap


def test_old_alert_survives_rule_change(tmp_path):
    # 用当前规则固化一份告警
    v1_path = tmp_path / "alerts_v1.json"
    engine.run(EVENTS, str(v1_path), RULES)
    old = json.load(open(v1_path, encoding="utf-8"))
    old_burst = next(a for a in old["alerts"] if a["rule_id"] == "burst_small_pay")
    assert old_burst["rule_version"] == 1

    # 改规则：阈值 12 -> 8 并升 v2
    cfg = json.load(open(RULES, encoding="utf-8"))
    for r in cfg["rules"]:
        if r["id"] == "burst_small_pay":
            r["version"] = 2
            r["params"]["min_events"] = 8
            r["threshold"]["value"] = 8
    v2_rules = tmp_path / "rules_v2.json"
    v2_rules.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")

    v2_path = tmp_path / "alerts_v2.json"
    engine.run(EVENTS, str(v2_path), str(v2_rules))
    new = json.load(open(v2_path, encoding="utf-8"))
    new_burst = next(a for a in new["alerts"] if a["rule_id"] == "burst_small_pay")
    assert new_burst["rule_version"] == 2

    # 旧告警仍是 v1 语义：快照参数、窗口、解释、依据事件全部不变
    assert old_burst["rule_snapshot"]["params"]["min_events"] == 12
    assert old_burst["window_snapshot"]["event_count"] == 12
    rendered = tb_tool.render(old_burst)
    assert rendered["rule_params_at_fire_time"]["min_events"] == 12
    assert rendered["rule_version"] == 1
    assert len(rendered["evidence_events"]) == 12


# --------------------------------------------------------------------------- #
# ⑤ 不改事件文件格式
# --------------------------------------------------------------------------- #
def test_event_file_format_unchanged():
    import subprocess as sp

    diff = sp.run(["git", "diff", "--stat", "data/events.jsonl"], cwd=ROOT, capture_output=True, text=True)
    assert diff.stdout.strip() == "", "事件文件不允许被修改"
    with open(EVENTS, encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            e = json.loads(line)
            assert set(e) == {"ts", "account", "device", "amount", "action", "ip_region"}
    assert i == 3014
