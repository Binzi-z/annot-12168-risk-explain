"""告警回溯工具：按账号/告警 ID 还原某条告警的全部依据事件。

用法：
    python traceback.py --account u9001 [alerts.json]
    python traceback.py --alert-id ALERT-0001 [alerts.json]
    python traceback.py --account u9002 --verify-with data/events.jsonl [alerts.json]

告警文件中已固化：规则版本快照、窗口快照、依据事件（含事件文件行号）。
因此即使 rules/rules.json 后续改动，旧告警仍可凭 rule_snapshot 完整解释。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

# Windows 控制台默认 GBK，统一改为 UTF-8，保证中文解释不乱码
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_ALERTS_PATH = "alerts.json"


def load_alert_store(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def find_alerts(store: Dict[str, Any], account: Optional[str], alert_id: Optional[str]) -> List[Dict[str, Any]]:
    alerts = store.get("alerts", [])
    if alert_id is not None:
        return [a for a in alerts if a.get("alert_id") == alert_id]
    if account is not None:
        return [a for a in alerts if a.get("account") == account]
    return alerts


def verify_against_events(alert: Dict[str, Any], events_path: str) -> Dict[str, Any]:
    """用事件文件原文复核告警里固化的依据事件（按行号比对，证明可回溯）。"""
    wanted = {e["line_no"]: e for e in alert["evidence_events"]}
    matched: List[Dict[str, Any]] = []
    with open(events_path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            if line_no in wanted:
                raw = json.loads(line)
                ref = wanted[line_no]
                ok = all(raw.get(k) == ref.get(k) for k in ("ts", "account", "device", "action", "amount", "ip_region"))
                matched.append({"line_no": line_no, "consistent": ok, "raw": raw})
    missing = sorted(set(wanted) - {m["line_no"] for m in matched})
    return {
        "all_consistent": all(m["consistent"] for m in matched) and not missing,
        "checked_lines": sorted(wanted),
        "missing_lines": missing,
        "matched": matched,
    }


def render(alert: Dict[str, Any], events_path: Optional[str] = None) -> Dict[str, Any]:
    snap = alert["window_snapshot"]
    rule = alert.get("rule_snapshot", {})
    record = {
        "alert_id": alert.get("alert_id"),
        "account": alert["account"],
        "rule": alert["rule_id"],
        "rule_version": alert["rule_version"],
        "rule_versioned_id": alert["rule_versioned_id"],
        "rule_description_at_fire_time": rule.get("description"),
        "rule_params_at_fire_time": rule.get("params"),
        "threshold_at_fire_time": rule.get("threshold"),
        "trigger": {"ts": alert["trigger_ts"], "event_file_line_no": alert["trigger_line_no"]},
        "window_snapshot": {
            "window_seconds": snap["window_seconds"],
            "span_seconds": snap["span_seconds"],
            "event_count": snap["event_count"],
            "time_range": snap["time_range"],
            "aggregation": snap["aggregation"],
            "extra": snap.get("extra", {}),
        },
        "evidence_event_count": len(alert["evidence_events"]),
        "evidence_events": alert["evidence_events"],
        "explanation": alert.get("explanation"),
    }
    if events_path:
        record["source_file_verification"] = verify_against_events(alert, events_path)
    return record


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="按账号/告警 ID 回溯告警依据")
    parser.add_argument("alerts", nargs="?", default=DEFAULT_ALERTS_PATH)
    parser.add_argument("--account", help="账号，如 u9001")
    parser.add_argument("--alert-id", help="告警 ID，如 ALERT-0001")
    parser.add_argument("--verify-with", dest="events_path", help="事件文件路径，用于按行号复核原文")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出（默认人类可读）")
    args = parser.parse_args(argv)

    if not args.account and not args.alert_id:
        parser.error("必须指定 --account 或 --alert-id")

    store = load_alert_store(args.alerts)
    alerts = find_alerts(store, args.account, args.alert_id)
    records = [render(a, args.events_path) for a in alerts]

    if args.json:
        print(json.dumps({"account": args.account, "alerts": records}, ensure_ascii=False, indent=2))
        return 0 if records else 2

    if not records:
        print(f"未找到匹配告警（account={args.account}, alert_id={args.alert_id}）")
        return 2

    for rec in records:
        ws = rec["window_snapshot"]
        print("=" * 72)
        print(f"告警 {rec['alert_id']} | {rec['rule_versioned_id']} | 账号 {rec['account']}")
        print(f"规则（命中时版本快照）: {rec['rule_description_at_fire_time']}")
        print(f"参数: {json.dumps(rec['rule_params_at_fire_time'], ensure_ascii=False)}")
        print(f"阈值: {json.dumps(rec['threshold_at_fire_time'], ensure_ascii=False)}")
        print(
            f"窗口快照: {ws['event_count']} 个事件, 时间 {ws['time_range']['from']} ~ {ws['time_range']['to']}, "
            f"跨度 {ws['span_seconds']:g}s / 窗口 {ws['window_seconds']}s, "
            f"聚合 {ws['aggregation']['function']}({ws['aggregation']['field']})={ws['aggregation']['value']}"
        )
        print(f"依据事件（共 {rec['evidence_event_count']} 条，可凭 line_no 回到事件文件原文）:")
        for ev in rec["evidence_events"]:
            print(
                f"  L{ev['line_no']:<5} {ev['ts']} {ev['action']:<8} amount={ev['amount']:<8} "
                f"device={ev['device']:<10} region={ev['ip_region']}"
            )
        print(f"解释: {rec['explanation']}")
        if "source_file_verification" in rec:
            v = rec["source_file_verification"]
            print(f"原文复核: {'全部一致' if v['all_consistent'] else '存在不一致'}，行号 {v['checked_lines']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
