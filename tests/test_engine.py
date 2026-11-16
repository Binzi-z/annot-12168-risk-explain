import json
import os
import subprocess
import sys
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine

EVENTS = os.path.join(ROOT, "data", "events.jsonl")
LABELS = os.path.join(ROOT, "labels.json")
RULEBOOK = os.path.join(ROOT, "rules", "rulebook.json")


# --------------------------------------------------------------------------- #
# fixtures / helpers
# --------------------------------------------------------------------------- #
def run_cli(tmp_path, rulebook=RULEBOOK, out_name="alerts.json"):
    out = tmp_path / out_name
    cmd = [sys.executable, "-I", os.path.join(ROOT, "engine.py"),
           EVENTS, str(out), "--rulebook", rulebook]
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", env=env)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text(encoding="utf-8"))


def write_jsonl(path, events):
    with open(path, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")


def pay(ts, account, amount=9.9, region="110000", device="d1", action="pay"):
    return {"ts": ts, "account": account, "device": device,
            "amount": amount, "action": action, "ip_region": region}


def full_run(tmp_path):
    doc = run_cli(tmp_path)
    return doc, doc["alerts"]


# --------------------------------------------------------------------------- #
# original skeleton tests (kept)
# --------------------------------------------------------------------------- #
def test_events_present():
    with open(EVENTS, encoding="utf-8") as fh:
        assert sum(1 for _ in fh) > 1000


def test_labels_present():
    with open(LABELS, encoding="utf-8") as fh:
        assert len(json.load(fh)["fraud"]) >= 2


def test_engine_runs(tmp_path):
    doc = run_cli(tmp_path)
    assert "alerts" in doc


def test_alerts_have_account(tmp_path):
    _, alerts = full_run(tmp_path)
    assert alerts  # see below: exactly two
    for a in alerts:
        assert a.get("account")


# --------------------------------------------------------------------------- #
# requirement 2: zero false positives on benign traffic, both frauds caught
# --------------------------------------------------------------------------- #
def test_exactly_two_alerts_matching_labels(tmp_path):
    labels = json.load(open(LABELS, encoding="utf-8"))["fraud"]
    doc, alerts = full_run(tmp_path)

    # zero false positives: every alerted account is a labelled fraud account
    fraud_accounts = {f["account"] for f in labels}
    assert {a["account"] for a in alerts} == fraud_accounts

    # both fraud patterns caught, one alert each
    by_rule = {a["rule"]: a for a in alerts}
    assert set(by_rule) == {f["rule"] for f in labels}
    for f in labels:
        a = by_rule[f["rule"]]
        assert a["account"] == f["account"]
        # label gives the fraud window; alert evidence must fall inside it
        assert f["from"] <= a["window_snapshot"]["from_ts"]
        assert a["window_snapshot"]["to_ts"] <= f["to"]
        assert len(a["evidence_events"]) == a["window_snapshot"]["event_count"]


def test_no_alert_on_benign_accounts(tmp_path):
    _, alerts = full_run(tmp_path)
    assert all(a["account"] in {"u9001", "u9002"} for a in alerts)


# --------------------------------------------------------------------------- #
# requirement 1: sliding window + threshold description + window snapshot
# --------------------------------------------------------------------------- #
def test_burst_alert_snapshot_contents(tmp_path):
    _, alerts = full_run(tmp_path)
    a = next(a for a in alerts if a["rule"] == "burst_small_pay")
    snap = a["window_snapshot"]

    # snapshot must carry event count, time range, aggregated value
    assert snap["event_count"] == 12
    assert snap["from_ts"] == "2026-10-02T03:30:36"
    assert snap["to_ts"] == "2026-10-02T03:31:11"
    assert snap["span_seconds"] == 35.0
    assert snap["span_seconds"] < snap["window_seconds"] == 60.0
    assert snap["aggregations"]["pay_count"] == 12
    assert snap["aggregations"]["amount_sum"] == 118.8
    assert snap["aggregations"]["amount_max"] == 9.9
    assert snap["unseen_region"] == "999999"
    # rule parameters described alongside the alert
    assert a["rule_snapshot"]["thresholds"]["min_pay_count"] == 12
    assert a["rule_snapshot"]["window_seconds"] == 60


def test_withdraw_alert_snapshot_contents(tmp_path):
    _, alerts = full_run(tmp_path)
    a = next(a for a in alerts if a["rule"] == "new_device_big_withdraw")
    snap = a["window_snapshot"]
    assert snap["event_count"] == 2
    assert snap["span_seconds"] == 40.0
    assert snap["aggregations"]["withdraw_amount"] == 48000.0
    assert snap["aggregations"]["login_withdraw_gap_seconds"] == 40.0
    assert snap["new_device"] == "d777-new"


def test_sliding_window_boundary_exclusive(tmp_path):
    # 12 payments spread over exactly 60s (span == window) must NOT alert:
    # the rule fires only when span < window_seconds.
    base = datetime(2026, 10, 1, 0, 0, 0)
    events = [pay((base + timedelta(seconds=i * 60 / 11)).isoformat(),
                  "u1", region="110000") for i in range(12)]
    src = tmp_path / "boundary.jsonl"
    write_jsonl(src, events)
    out = tmp_path / "out.json"
    engine.run(src, out)
    assert json.loads(out.read_text(encoding="utf-8"))["alerts"] == []


def test_known_region_burst_does_not_alert(tmp_path):
    # 12 fast payments, but the account already used that region earlier ->
    # not an "unseen region", no alert.
    events = [pay("2026-10-01T00:00:00", "u1", region="110000")]
    events += [pay(f"2026-10-01T01:00:{i:02d}", "u1", region="110000") for i in range(12)]
    src = tmp_path / "known.jsonl"
    write_jsonl(src, events)
    out = tmp_path / "out.json"
    engine.run(src, out)
    assert json.loads(out.read_text(encoding="utf-8"))["alerts"] == []


def test_unseen_region_burst_alert_and_edge_trigger(tmp_path):
    events = [pay("2026-10-01T00:00:00", "u1", region="110000")]
    events += [pay(f"2026-10-01T01:00:{i:02d}", "u1", region="999999") for i in range(14)]
    src = tmp_path / "burst.jsonl"
    write_jsonl(src, events)
    out = tmp_path / "out.json"
    doc = engine.run(src, out)
    # edge trigger: one alert for the whole burst, not one per extra event
    assert len(doc["alerts"]) == 1
    a = doc["alerts"][0]
    assert a["rule"] == "burst_small_pay"
    assert a["window_snapshot"]["event_count"] == 12


def test_known_device_withdraw_does_not_alert(tmp_path):
    # Device d1 is established earlier through ordinary activity; a later
    # login + large withdraw on it is normal, not a new-device takeover.
    events = [
        pay("2026-09-30T00:00:00", "u1", device="d1", action="view", amount=0),
        pay("2026-10-01T00:00:00", "u1", device="d1", action="login", amount=0),
        pay("2026-10-01T00:05:00", "u1", device="d1", action="withdraw", amount=48000.0),
    ]
    src = tmp_path / "known_dev.jsonl"
    write_jsonl(src, events)
    out = tmp_path / "out.json"
    engine.run(src, out)
    assert json.loads(out.read_text(encoding="utf-8"))["alerts"] == []


def test_withdraw_outside_window_does_not_alert(tmp_path):
    events = [
        pay("2026-10-01T00:00:00", "u1", device="d1", action="login", amount=0),
        pay("2026-10-01T00:06:00", "u1", device="d1", action="withdraw", amount=48000.0),
    ]
    src = tmp_path / "late.jsonl"
    write_jsonl(src, events)
    out = tmp_path / "out.json"
    engine.run(src, out)
    assert json.loads(out.read_text(encoding="utf-8"))["alerts"] == []


# --------------------------------------------------------------------------- #
# requirement 3: trace an account's alert back to all evidence events
# --------------------------------------------------------------------------- #
def test_trace_by_account(tmp_path):
    doc, _ = full_run(tmp_path)
    hits = engine.trace_alerts(doc, "u9001")
    assert len(hits) == 1
    a = hits[0]
    lines = [e["line"] for e in a["evidence_events"]]
    assert lines == list(range(3001, 3013))
    # evidence events are complete records, not just ids
    for item in a["evidence_events"]:
        assert set(item["event"]) == {"ts", "account", "device", "amount", "action", "ip_region"}
        assert item["event"]["account"] == "u9001"


def test_evidence_verifies_against_source(tmp_path):
    doc, alerts = full_run(tmp_path)
    for a in alerts:
        assert engine.verify_evidence(a, EVENTS) is True


def test_trace_cli(tmp_path):
    out = tmp_path / "alerts.json"
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    subprocess.run([sys.executable, "-I", os.path.join(ROOT, "engine.py"),
                    EVENTS, str(out)], check=True, env=env,
                   capture_output=True, text=True, encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "engine.py"),
                        "trace", str(out), "u9002"],
                       capture_output=True, text=True, encoding="utf-8", env=env)
    assert r.returncode == 0, r.stderr
    assert "new_device_big_withdraw" in r.stdout
    assert "line 3013" in r.stdout and "line 3014" in r.stdout


# --------------------------------------------------------------------------- #
# requirement 4: rule versioning - old alerts stay explainable after changes
# --------------------------------------------------------------------------- #
def _edited_rulebook(tmp_path, **overrides):
    book = json.load(open(RULEBOOK, encoding="utf-8"))
    book["rulebook_version"] = "2026.11.17-r2"
    for rule in book["rules"]:
        if rule["rule"] == "burst_small_pay":
            rule["rule_version"] = "1.1.0"
            rule["window_seconds"] = overrides.get("window_seconds", 90)
            rule["thresholds"]["min_pay_count"] = overrides.get("min_pay_count", 15)
    path = tmp_path / "rulebook-v2.json"
    path.write_text(json.dumps(book, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def test_old_alert_keeps_rule_version_and_snapshot(tmp_path):
    # v1 run with the shipped rulebook
    old_doc = run_cli(tmp_path, out_name="alerts-v1.json")
    old_alert = next(a for a in old_doc["alerts"] if a["rule"] == "burst_small_pay")
    assert old_alert["rule_version"] == "1.0.0"
    assert old_alert["rulebook_version"] == "2026.10.02-r1"

    # rulebook changes: burst window 60->90s and threshold 12->15.
    # u9001 only has 12 pays, so under v2 that pattern no longer alerts.
    v2 = _edited_rulebook(tmp_path)
    new_doc = run_cli(tmp_path, rulebook=v2, out_name="alerts-v2.json")
    assert all(a["rule"] != "burst_small_pay" for a in new_doc["alerts"])
    # untouched rules keep their old version; the output records the new book
    assert new_doc["rulebook_version"] == "2026.11.17-r2"
    withdraw = next(a for a in new_doc["alerts"]
                    if a["rule"] == "new_device_big_withdraw")
    assert withdraw["rule_version"] == "1.0.0"

    # the OLD alert still explains itself under the OLD parameters even
    # though the rulebook on disk no longer contains them
    assert old_alert["rule_snapshot"]["window_seconds"] == 60
    assert old_alert["rule_snapshot"]["thresholds"]["min_pay_count"] == 12
    assert old_alert["window_snapshot"]["event_count"] == 12
    # and still traces to the same evidence
    assert engine.verify_evidence(old_alert, EVENTS) is True
    # explain_alert reconstructs the full rationale from the stored file
    explained = engine.explain_alert(old_doc, old_alert["alert_id"])
    assert explained["rule_snapshot"]["rule_version"] == "1.0.0"


def test_threshold_change_removes_false_negative_fires_in_synthetic(tmp_path):
    # tuned-down rulebook: threshold 3 -> benign-looking fast burst now fires,
    # proving rule edits take effect via config without touching engine code
    v2 = _edited_rulebook(tmp_path, min_pay_count=3, window_seconds=60)
    events = [pay(f"2026-10-01T00:00:{i:02d}", "u1", region="110000") for i in range(3)]
    src = tmp_path / "small.jsonl"
    write_jsonl(src, events)
    out = tmp_path / "out.json"
    doc = engine.run(src, out, rulebook_path=v2)
    assert len(doc["alerts"]) == 1
    assert doc["alerts"][0]["rule_version"] == "1.1.0"


def test_invalid_rulebook_rejected(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"rulebook_version": "x", "rules": [{"rule": "nope"}]}),
                   encoding="utf-8")
    import pytest
    with pytest.raises(engine.RulebookError):
        engine.load_rulebook(bad)


# --------------------------------------------------------------------------- #
# requirement 5: event file format untouched
# --------------------------------------------------------------------------- #
def test_event_file_unchanged(tmp_path):
    before = open(EVENTS, "rb").read()
    run_cli(tmp_path)
    after = open(EVENTS, "rb").read()
    assert before == after
    # every parsed line still has exactly the original schema
    with open(EVENTS, encoding="utf-8") as fh:
        for line in fh:
            assert set(json.loads(line)) == {
                "ts", "account", "device", "amount", "action", "ip_region"}


def test_alert_id_stable_and_unique(tmp_path):
    doc, alerts = full_run(tmp_path)
    ids = [a["alert_id"] for a in alerts]
    assert len(ids) == len(set(ids))
    # re-running produces identical ids (deterministic, based on rule+account+ts)
    doc2, alerts2 = full_run(tmp_path)
    assert [a["alert_id"] for a in alerts2] == ids
