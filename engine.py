"""可解释风控引擎（规则配置化 + 版本快照 + 窗口取证）。

设计要点
--------
1. 规则全部描述在 rules/rules.json 中：每条规则带语义化 version，
   调阈值/窗口只改配置并升版本，不需要改代码发版。
2. 每条告警落库时写入当时生效的完整规则快照（rule_snapshot），
   规则后续改动不影响旧告警的可解释性。
3. 命中时写入窗口快照 window_snapshot：事件条数、时间范围、聚合值，
   以及全部依据事件 evidence_events（含事件文件行号，可回溯原文件）。
4. 事件文件 data/events.jsonl 的格式不做任何改动，只读不写。

CLI:
    python engine.py [events.jsonl] [alerts.json] [--rules rules/rules.json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Deque, Dict, List, Optional

# Windows 控制台默认 GBK，统一改为 UTF-8，保证中文解释不乱码
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

ENGINE_VERSION = "2.0.0"
DEFAULT_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "rules.json")
DEFAULT_EVENTS_PATH = "data/events.jsonl"
DEFAULT_ALERTS_PATH = "alerts.json"


# --------------------------------------------------------------------------- #
# 规则加载与版本注册
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Rule:
    id: str
    version: int
    description: str
    params: Dict[str, Any]
    aggregation: Dict[str, Any]
    threshold: Dict[str, Any]
    raw: Dict[str, Any]

    @property
    def versioned_id(self) -> str:
        return f"{self.id}@v{self.version}"

    def snapshot(self) -> Dict[str, Any]:
        """告警落库时使用的不可变规则快照（深拷贝，避免后续被改写）。"""
        return json.loads(json.dumps(self.raw, ensure_ascii=False))


def load_rules(path: str = DEFAULT_RULES_PATH) -> List[Rule]:
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    rules: List[Rule] = []
    for item in cfg["rules"]:
        if not item.get("enabled", True):
            continue
        rules.append(
            Rule(
                id=item["id"],
                version=int(item["version"]),
                description=item.get("description", ""),
                params=item.get("params", {}),
                aggregation=item.get("aggregation", {}),
                threshold=item.get("threshold", {}),
                raw=item,
            )
        )
    return rules


# --------------------------------------------------------------------------- #
# 事件流读取（不修改事件文件格式）
# --------------------------------------------------------------------------- #
def read_events(path: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            event["_line"] = line_no
            event["_dt"] = datetime.fromisoformat(event["ts"])
            events.append(event)
    return events


def public_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """剥离内部字段后的依据事件，保留事件文件行号 line_no 用于回溯原文。"""
    return {
        "line_no": event["_line"],
        "ts": event["ts"],
        "account": event["account"],
        "device": event["device"],
        "action": event["action"],
        "amount": event["amount"],
        "ip_region": event["ip_region"],
    }


def serialize_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """告警已只含 JSON 原生类型；此函数做一次深拷贝兜底，剥离任何内部字段。"""
    return json.loads(json.dumps(alerts, ensure_ascii=False, default=str))


# --------------------------------------------------------------------------- #
# 规则一：burst_small_pay
# 账号在未见过的地区，于 <window_seconds> 秒滑动窗口内发生 >= min_events 笔 pay
# --------------------------------------------------------------------------- #
class BurstSmallPayRule:
    def __init__(self, rule: Rule):
        p = rule.params
        self.rule = rule
        self.action = p["action"]
        self.window_seconds = int(p["window_seconds"])
        self.min_events = int(p["min_events"])
        # 每个账号的滑动窗口（仅保留目标 action 的事件）
        self._windows: Dict[str, Deque[Dict[str, Any]]] = {}
        # 账号历史上出现过的地区（按到达顺序累积，含当前事件）
        self._known_regions: Dict[str, set] = {}
        self._fired: set = set()  # 每账号每规则版本只告警一次，避免窗口重复命中

    def on_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        account = event["account"]
        known = self._known_regions.setdefault(account, set())
        # “未见地区”：该账号在此前的历史事件中从未出现过该 ip_region。
        # 先判定再登记；以突发首笔事件到达时的地区状态作为整段突发的判定依据。
        is_unseen_region = event["ip_region"] not in known

        if event["action"] == self.action:
            window = self._windows.setdefault(account, deque())
            event["_region_unseen_at_arrival"] = is_unseen_region
            window.append(event)
            # 严格滑动窗口：保留 (now - t) < window_seconds 的事件，
            # 即窗口内首末事件时间跨度严格小于窗口时长
            cutoff = event["_dt"].timestamp() - self.window_seconds
            while window and window[0]["_dt"].timestamp() <= cutoff:
                window.popleft()
        else:
            window = self._windows.get(account)

        known.add(event["ip_region"])

        if event["action"] != self.action:
            return None
        if account in self._fired:
            return None
        if len(window) < self.min_events:
            return None
        members = list(window)
        first = members[0]
        # 突发开始时该地区对账号是未见地区，且窗口内事件全部来自该地区
        if not first.get("_region_unseen_at_arrival"):
            return None
        if any(e["ip_region"] != first["ip_region"] for e in members):
            return None

        self._fired.add(account)
        return self._build_alert(event, members)

    def _build_alert(self, trigger: Dict[str, Any], members: List[Dict[str, Any]]) -> Dict[str, Any]:
        first, last = members[0], members[-1]
        span_seconds = (last["_dt"] - first["_dt"]).total_seconds()
        amounts = [float(e["amount"]) for e in members]
        snapshot = {
            "window_seconds": self.window_seconds,
            "span_seconds": span_seconds,
            "event_count": len(members),
            "time_range": {"from": first["ts"], "to": last["ts"]},
            "aggregation": {
                "function": "count",
                "field": None,
                "value": len(members),
            },
            "extra": {
                "total_amount": round(sum(amounts), 2),
                "ip_region": trigger["ip_region"],
                "unseen_region_scope": self.rule.params["unseen_region_scope"],
            },
        }
        return {
            "rule_id": self.rule.id,
            "rule_version": self.rule.version,
            "rule_versioned_id": self.rule.versioned_id,
            "rule_snapshot": self.rule.snapshot(),
            "account": trigger["account"],
            "trigger_ts": trigger["ts"],
            "trigger_line_no": trigger["_line"],
            "window_snapshot": snapshot,
            "evidence_events": [public_event(e) for e in members],
            "explanation": (
                f"账号 {trigger['account']} 在未见过的地区 {trigger['ip_region']}，"
                f"{self.window_seconds} 秒滑动窗口内出现 {len(members)} 笔 {self.action} 事件"
                f"（{first['ts']} ~ {last['ts']}，跨度 {span_seconds:g}s），"
                f"达到阈值 {self.rule.threshold['operator']} {self.min_events}。"
            ),
        }


# --------------------------------------------------------------------------- #
# 规则二：new_device_big_withdraw
# 新设备 login 后，link_max_gap_seconds 秒内同设备发生 >= 阈值金额的 withdraw
# --------------------------------------------------------------------------- #
class NewDeviceBigWithdrawRule:
    def __init__(self, rule: Rule):
        p = rule.params
        self.rule = rule
        self.login_action = p["login_action"]
        self.money_action = p["money_action"]
        self.min_amount = float(p["withdraw_min_amount"])
        self.max_gap_seconds = int(p["link_max_gap_seconds"])
        self.require_same_device = bool(p["require_same_device"])
        self._known_devices: Dict[str, set] = {}
        # (account, device) -> 该设备最近一次“新设备登录”事件
        self._anchors: Dict[tuple, Dict[str, Any]] = {}
        self._fired: set = set()

    def on_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        account = event["account"]
        known = self._known_devices.setdefault(account, set())
        is_new_device = event["device"] not in known
        known.add(event["device"])

        if is_new_device and event["action"] == self.login_action:
            # 记录该账号这台新设备的登录锚点，供后续资金事件关联
            self._anchors[(account, event["device"])] = event
            return None

        if event["action"] != self.money_action:
            return None
        if float(event["amount"]) < self.min_amount:
            return None
        if account in self._fired:
            return None

        login = self._find_anchor(account, event)
        if login is None:
            return None

        self._fired.add(account)
        return self._build_alert(event, login)

    # 每个账号保留每台设备最近一次“新设备登录”锚点
    def _find_anchor(self, account: str, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self.require_same_device:
            login = self._anchors.get((account, event["device"]))
        else:
            login = None
            for (acct, _dev), evt in self._anchors.items():
                if acct == account:
                    login = evt
        if login is None:
            return None
        gap = (event["_dt"] - login["_dt"]).total_seconds()
        if gap < 0 or gap > self.max_gap_seconds:
            return None
        return login

    def _build_alert(self, trigger: Dict[str, Any], login: Dict[str, Any]) -> Dict[str, Any]:
        gap_seconds = (trigger["_dt"] - login["_dt"]).total_seconds()
        members = [login, trigger]
        snapshot = {
            "window_seconds": self.max_gap_seconds,
            "span_seconds": gap_seconds,
            "event_count": len(members),
            "time_range": {"from": login["ts"], "to": trigger["ts"]},
            "aggregation": {
                "function": "max",
                "field": "amount",
                "value": float(trigger["amount"]),
            },
            "extra": {
                "device": trigger["device"],
                "new_device_scope": self.rule.params["new_device_scope"],
                "login_line_no": login["_line"],
            },
        }
        return {
            "rule_id": self.rule.id,
            "rule_version": self.rule.version,
            "rule_versioned_id": self.rule.versioned_id,
            "rule_snapshot": self.rule.snapshot(),
            "account": trigger["account"],
            "trigger_ts": trigger["ts"],
            "trigger_line_no": trigger["_line"],
            "window_snapshot": snapshot,
            "evidence_events": [public_event(e) for e in members],
            "explanation": (
                f"账号 {trigger['account']} 于 {login['ts']} 在新设备 {login['device']} 登录，"
                f"{gap_seconds:g}s 后在同一设备发起 {self.money_action} {trigger['amount']}，"
                f"不低于阈值 {self.min_amount:g}（关联窗口 {self.max_gap_seconds}s）。"
            ),
        }


RULE_EVALUATORS: Dict[str, Callable[[Rule], Any]] = {
    "burst_small_pay": BurstSmallPayRule,
    "new_device_big_withdraw": NewDeviceBigWithdrawRule,
}


# --------------------------------------------------------------------------- #
# 引擎主流程
# --------------------------------------------------------------------------- #
def evaluate(events: List[Dict[str, Any]], rules: List[Rule]) -> List[Dict[str, Any]]:
    evaluators = []
    for r in rules:
        if r.id not in RULE_EVALUATORS:
            raise ValueError(f"未知规则 id: {r.id}（请在 RULE_EVALUATORS 注册评估器）")
        evaluators.append(RULE_EVALUATORS[r.id](r))
    alerts: List[Dict[str, Any]] = []
    for event in events:  # 事件已按 ts 升序；按到达顺序逐条喂给规则
        for evaluator in evaluators:
            alert = evaluator.on_event(event)
            if alert is not None:
                alerts.append(alert)
    alerts.sort(key=lambda a: (a["trigger_ts"], a["rule_id"]))
    for idx, alert in enumerate(alerts, start=1):
        alert["alert_id"] = f"ALERT-{idx:04d}"
    return alerts


def run(events_path: str, alerts_path: str, rules_path: str = DEFAULT_RULES_PATH) -> Dict[str, Any]:
    rules = load_rules(rules_path)
    events = read_events(events_path)
    alerts = evaluate(events, rules)
    result = {
        "engine_version": ENGINE_VERSION,
        "rules_path": os.path.abspath(rules_path),
        "events_file": os.path.abspath(events_path),
        "event_count": len(events),
        "active_rule_versions": [r.versioned_id for r in rules],
        "alerts": alerts,
    }
    with open(alerts_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="可解释风控引擎")
    parser.add_argument("events", nargs="?", default=DEFAULT_EVENTS_PATH)
    parser.add_argument("out", nargs="?", default=DEFAULT_ALERTS_PATH)
    parser.add_argument("--rules", default=DEFAULT_RULES_PATH)
    args = parser.parse_args(argv)

    result = run(args.events, args.out, args.rules)
    print(f"{len(result['alerts'])} alerts -> {args.out}")
    for alert in result["alerts"]:
        snap = alert["window_snapshot"]
        print(
            f"  {alert['alert_id']} {alert['rule_versioned_id']} "
            f"account={alert['account']} events={snap['event_count']} "
            f"range={snap['time_range']['from']}~{snap['time_range']['to']} "
            f"agg={snap['aggregation']['function']}={snap['aggregation']['value']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
