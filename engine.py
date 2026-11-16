"""Config-driven risk engine with explainable, versioned alerts.

Replaces the old hardcoded ``amount >= 10000`` rule. Rules live in an
external rulebook (``rules/rulebook.json``): tuning a window or threshold no
longer needs a code release. Every alert carries:

* the full rule snapshot (rule version + rulebook version + parameters), so
  alerts stay explainable after the rulebook is edited;
* a window snapshot (event count, time range, aggregated values);
* every evidence event with its source-file line number, so an alert can be
  traced back to the exact events that justified it.

The event file is only read, never rewritten.

CLI:
    python engine.py [run] [events.jsonl] [alerts.json] [--rulebook path]
    python engine.py trace  <alerts.json> <account>
    python engine.py explain <alerts.json> <alert_id>
"""

from __future__ import annotations

import json
import sys
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

DEFAULT_RULEBOOK = Path(__file__).with_name("rules") / "rulebook.json"
DEFAULT_SOURCE = "data/events.jsonl"
DEFAULT_OUTPUT = "alerts.json"


class RulebookError(ValueError):
    """Raised when the rulebook is missing required fields or unknown rules."""


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def load_rulebook(path: str | Path = DEFAULT_RULEBOOK) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc.get("rulebook_version"), str) or not doc["rulebook_version"]:
        raise RulebookError("rulebook.rulebook_version is required")
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        raise RulebookError("rulebook.rules must be a non-empty list")
    seen: set[str] = set()
    for rule in rules:
        name = rule.get("rule")
        if not isinstance(name, str) or not name:
            raise RulebookError(f"rule entry missing name: {rule!r}")
        if name in seen:
            raise RulebookError(f"duplicate rule in rulebook: {name}")
        seen.add(name)
        if not isinstance(rule.get("rule_version"), str) or not rule["rule_version"]:
            raise RulebookError(f"rule {name} requires a rule_version")
        if not isinstance(rule.get("window_seconds"), (int, float)):
            raise RulebookError(f"rule {name} requires numeric window_seconds")
        if not isinstance(rule.get("thresholds"), dict):
            raise RulebookError(f"rule {name} requires a thresholds object")
        if name not in RULE_EVALUATORS:
            raise RulebookError(f"no evaluator implemented for rule {name}")
    return doc


def read_events(path: str | Path) -> list[tuple[int, dict[str, Any]]]:
    """Read the jsonl event file. Format is untouched (read-only)."""
    out: list[tuple[int, dict[str, Any]]] = []
    with open(path, encoding="utf-8") as fh:
        for line, raw in enumerate(fh, start=1):
            raw = raw.strip()
            if raw:
                out.append((line, json.loads(raw)))
    return out


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


# --------------------------------------------------------------------------- #
# Alert construction
# --------------------------------------------------------------------------- #
def _make_alert(
    *,
    rulebook_version: str,
    rule: dict[str, Any],
    account: str,
    trigger_line: int,
    trigger_ts: str,
    window: dict[str, Any],
    evidence: list[tuple[int, dict[str, Any]]],
) -> dict[str, Any]:
    return {
        "alert_id": f"{rule['rule']}:{account}:{trigger_ts}",
        "rule": rule["rule"],
        "rule_version": rule["rule_version"],
        "rulebook_version": rulebook_version,
        "account": account,
        "description": rule.get("description", ""),
        "trigger_event_line": trigger_line,
        "trigger_ts": trigger_ts,
        # Full parameter snapshot: the alert explains itself even after the
        # rulebook is edited and this version no longer exists on disk.
        "rule_snapshot": rule,
        "window_snapshot": window,
        "evidence_events": [
            {"line": line, "event": event} for line, event in evidence
        ],
    }


# --------------------------------------------------------------------------- #
# Rule 1: burst_small_pay
# 12 payments (each <= max_amount) inside a <window_seconds sliding window,
# from a region the account had never been seen in before the window opened.
# --------------------------------------------------------------------------- #
def eval_burst_small_pay(
    rule: dict[str, Any],
    rulebook_version: str,
    account_events: list[tuple[int, dict[str, Any]]],
) -> list[dict[str, Any]]:
    th = rule["thresholds"]
    window_seconds = float(rule["window_seconds"])
    min_count = int(th["min_pay_count"])
    max_amount = float(th["max_amount"])
    require_unseen = bool(th.get("require_unseen_region", True))

    alerts: list[dict[str, Any]] = []
    window: deque[tuple[int, dict[str, Any], datetime, bool]] = deque()
    known_regions: set[str] = set()
    armed = False  # edge-trigger: one alert until the window drains below count

    for line, event in account_events:
        ts = _parse_ts(event["ts"])
        region = str(event.get("ip_region", ""))
        unseen_at_arrival = region not in known_regions

        if event.get("action") == "pay" and float(event.get("amount", 0)) <= max_amount:
            window.append((line, event, ts, unseen_at_arrival))
            # Sliding window: drop payments at or beyond window_seconds old.
            while window and (ts - window[0][2]).total_seconds() >= window_seconds:
                window.popleft()
                armed = False

            if len(window) >= min_count and not armed:
                oldest_line, oldest_event, oldest_ts, oldest_unseen = window[0]
                region_ok = (not require_unseen) or oldest_unseen
                if region_ok:
                    span = (ts - oldest_ts).total_seconds()
                    amounts = [float(item[1]["amount"]) for item in window]
                    regions = sorted({str(item[1].get("ip_region", "")) for item in window})
                    snapshot = {
                        "event_count": len(window),
                        "window_seconds": window_seconds,
                        "window_compare": f"span_seconds < {window_seconds}",
                        "from_ts": oldest_event["ts"],
                        "to_ts": event["ts"],
                        "span_seconds": span,
                        "unseen_region": oldest_event.get("ip_region"),
                        "aggregations": {
                            "pay_count": len(window),
                            "amount_sum": round(sum(amounts), 2),
                            "amount_max": max(amounts),
                            "regions": regions,
                        },
                    }
                    alerts.append(
                        _make_alert(
                            rulebook_version=rulebook_version,
                            rule=rule,
                            account=event["account"],
                            trigger_line=line,
                            trigger_ts=event["ts"],
                            window=snapshot,
                            evidence=[(item[0], item[1]) for item in window],
                        )
                    )
                    armed = True
        known_regions.add(region)
    return alerts


# --------------------------------------------------------------------------- #
# Rule 2: new_device_big_withdraw
# login on a device never used by the account before, then a large withdraw on
# that same device within window_seconds.
# --------------------------------------------------------------------------- #
@dataclass
class _Login:
    line: int
    event: dict[str, Any]
    ts: datetime


def eval_new_device_big_withdraw(
    rule: dict[str, Any],
    rulebook_version: str,
    account_events: list[tuple[int, dict[str, Any]]],
) -> list[dict[str, Any]]:
    th = rule["thresholds"]
    window_seconds = float(rule["window_seconds"])
    min_amount = float(th["min_withdraw_amount"])
    same_device = bool(th.get("require_same_device", True))

    alerts: list[dict[str, Any]] = []
    seen_devices: set[str] = set()
    # Only devices whose FIRST appearance for this account was a login are
    # eligible. A device first seen on a non-login event (or one already
    # established before this stream started) never enters this map.
    new_logins: dict[str, _Login] = {}

    for line, event in account_events:
        ts = _parse_ts(event["ts"])
        device = str(event.get("device", ""))
        action = event.get("action")
        is_new_device = device not in seen_devices

        if action == "login" and is_new_device:
            new_logins[device] = _Login(line, event, ts)
        elif action == "withdraw" and float(event.get("amount", 0)) >= min_amount:
            # No entry for long-known devices -> benign withdrawals never alert.
            # The u9002 pattern (same new device, login then withdraw 40s later)
            # matches because the login created the entry above.
            login = new_logins.get(device) if same_device else _latest_login(new_logins)
            if login is not None:
                gap = (ts - login.ts).total_seconds()
                if 0 <= gap <= window_seconds:
                    snapshot = {
                        "event_count": 2,
                        "window_seconds": window_seconds,
                        "window_compare": f"withdraw_ts - login_ts <= {window_seconds}",
                        "from_ts": login.event["ts"],
                        "to_ts": event["ts"],
                        "span_seconds": gap,
                        "new_device": device,
                        "aggregations": {
                            "withdraw_amount": float(event["amount"]),
                            "login_withdraw_gap_seconds": gap,
                        },
                    }
                    alerts.append(
                        _make_alert(
                            rulebook_version=rulebook_version,
                            rule=rule,
                            account=event["account"],
                            trigger_line=line,
                            trigger_ts=event["ts"],
                            window=snapshot,
                            evidence=[(login.line, login.event), (line, event)],
                        )
                    )
        seen_devices.add(device)
    return alerts


def _latest_login(logins: dict[str, _Login]) -> _Login | None:
    return max(logins.values(), key=lambda item: item.ts, default=None)


RULE_EVALUATORS: dict[str, Callable[..., list[dict[str, Any]]]] = {
    "burst_small_pay": eval_burst_small_pay,
    "new_device_big_withdraw": eval_new_device_big_withdraw,
}


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
def evaluate_events(
    events: list[tuple[int, dict[str, Any]]],
    rulebook: dict[str, Any],
) -> list[dict[str, Any]]:
    by_account: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for line, event in events:
        by_account.setdefault(event["account"], []).append((line, event))

    alerts: list[dict[str, Any]] = []
    for rule in rulebook["rules"]:
        evaluator = RULE_EVALUATORS[rule["rule"]]
        for account in sorted(by_account):
            alerts.extend(
                evaluator(rule, rulebook["rulebook_version"], by_account[account])
            )

    alerts.sort(key=lambda a: (a["trigger_ts"], a["rule"]))
    # Guarantee unique alert_ids even if two rules share a trigger timestamp.
    used: set[str] = set()
    for alert in alerts:
        base = alert["alert_id"]
        candidate, n = base, 2
        while candidate in used:
            candidate = f"{base}#{n}"
            n += 1
        alert["alert_id"] = candidate
        used.add(candidate)
    return alerts


def run(source: str | Path, output: str | Path, rulebook_path: str | Path = DEFAULT_RULEBOOK) -> dict[str, Any]:
    rulebook = load_rulebook(rulebook_path)
    events = read_events(source)
    alerts = evaluate_events(events, rulebook)
    doc = {
        "rulebook_version": rulebook["rulebook_version"],
        "source": str(source),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alerts": alerts,
    }
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
    return doc


# --------------------------------------------------------------------------- #
# Tracing / explanation
# --------------------------------------------------------------------------- #
def load_alerts(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def trace_alerts(doc: dict[str, Any], account: str) -> list[dict[str, Any]]:
    """All alerts for one account, each carrying its full evidence events."""
    return [a for a in doc.get("alerts", []) if a.get("account") == account]


def explain_alert(doc: dict[str, Any], alert_id: str) -> dict[str, Any]:
    for alert in doc.get("alerts", []):
        if alert.get("alert_id") == alert_id:
            return alert
    raise KeyError(f"alert_id not found: {alert_id}")


def verify_evidence(alert: dict[str, Any], source: str | Path) -> bool:
    """Re-read the source file and prove every evidence line still matches."""
    wanted = {item["line"]: item["event"] for item in alert["evidence_events"]}
    found: dict[int, dict[str, Any]] = {}
    with open(source, encoding="utf-8") as fh:
        for line, raw in enumerate(fh, start=1):
            if line in wanted:
                found[line] = json.loads(raw)
    return found == wanted


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _print_alert(alert: dict[str, Any]) -> None:
    snap = alert["window_snapshot"]
    print(f"[{alert['alert_id']}]")
    print(f"  rule        : {alert['rule']} v{alert['rule_version']} "
          f"(rulebook {alert['rulebook_version']})")
    print(f"  account     : {alert['account']}")
    print(f"  description : {alert['description']}")
    print(f"  triggered at: {alert['trigger_ts']} (source line {alert['trigger_event_line']})")
    print(f"  window      : {snap['from_ts']} -> {snap['to_ts']} "
          f"({snap['span_seconds']}s, {snap['event_count']} events, limit {snap['window_seconds']}s)")
    print(f"  aggregation : {json.dumps(snap['aggregations'], ensure_ascii=False)}")
    print("  evidence    :")
    for item in alert["evidence_events"]:
        print(f"    line {item['line']}: {json.dumps(item['event'], ensure_ascii=False)}")


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to a non-UTF-8 code page (e.g. GBK); make
    # Chinese rule descriptions print without crashing. errors="replace"
    # keeps output working even on streams that refuse reconfiguration.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv[0] if argv and argv[0] in ("run", "trace", "explain") else "run"

    if command == "run":
        args = argv[1:] if argv and argv[0] == "run" else list(argv)
        rulebook_path = DEFAULT_RULEBOOK
        if "--rulebook" in args:
            i = args.index("--rulebook")
            rulebook_path = args[i + 1]
            del args[i:i + 2]
        src = args[0] if len(args) > 0 else DEFAULT_SOURCE
        out = args[1] if len(args) > 1 else DEFAULT_OUTPUT
        doc = run(src, out, rulebook_path)
        print(f"{len(doc['alerts'])} alerts -> {out} (rulebook {doc['rulebook_version']})")
        return 0

    if command == "trace":
        alerts_path, account = argv[1], argv[2]
        doc = load_alerts(alerts_path)
        hits = trace_alerts(doc, account)
        if not hits:
            print(f"no alerts for account {account}")
            return 1
        for alert in hits:
            _print_alert(alert)
        return 0

    if command == "explain":
        alerts_path, alert_id = argv[1], argv[2]
        doc = load_alerts(alerts_path)
        try:
            _print_alert(explain_alert(doc, alert_id))
        except KeyError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0

    print(f"unknown command: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
