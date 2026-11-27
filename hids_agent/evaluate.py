"""Precision / recall report.

    python -m hids_agent.evaluate --out out/dev --labels data/dev_labels.json
    python -m hids_agent.evaluate --out out/dev --stream data/dev_stream.jsonl   # labels embedded in events

Scoring is per attack sequence:
  * a sequence is detected (TP) if at least one alert matches it;
  * an alert is a false alarm only if it matches no labeled sequence
    (several alerts on the same sequence are not false alarms).
Matching prefers shared event ids; without ids it falls back to host + time overlap.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .normalize import LABEL_FIELDS, flatten, normalize, parse_ts

BENIGN = {"", "0", "false", "none", "benign", "normal", "no", "null"}
TYPE_TO_RULE = {
    "bruteforce": "bruteforce", "brute_force": "bruteforce", "brute-force": "bruteforce",
    "password_spray": "bruteforce", "spray": "bruteforce", "credential_access": "bruteforce",
    "temp_service": "temp_service", "service": "temp_service", "persistence": "temp_service",
    "new_service": "temp_service",
    "office_shell": "office_shell", "office": "office_shell", "macro": "office_shell",
    "phishing": "office_shell",
    "fim": "fim", "file_integrity": "fim", "tamper": "fim", "file_tamper": "fim",
}


def _ref(x) -> str:
    s = str(x)
    return s if s.startswith(("id:", "line:")) else f"id:{s}"


def load_label_file(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        data = data.get("sequences") or data.get("attacks") or data.get("labels") or []
    seqs = []
    for i, s in enumerate(data):
        ids = s.get("event_ids") or s.get("events") or s.get("ids") or []
        seqs.append({
            "id": str(s.get("attack_id") or s.get("id") or f"S{i + 1}"),
            "type": str(s.get("type") or s.get("technique") or s.get("attack_type") or "").lower(),
            "host": (str(s["host"]).lower() if s.get("host") else None),
            "start": parse_ts(s.get("start")), "end": parse_ts(s.get("end")),
            "refs": {_ref(x) for x in ids},
            "description": s.get("description", ""),
        })
    return seqs


def labels_from_stream(path: str) -> list[dict]:
    seqs: dict[str, dict] = {}
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        n = 0
        for line in f:
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            n += 1
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(raw, dict):
                continue
            flat = flatten(raw)
            lab = None
            for k in ("attack_id", "sequence_id", "label", "attack", "is_attack", "ground_truth", "attack_type"):
                if k in flat and str(flat[k]).strip().lower() not in BENIGN:
                    lab = flat[k]
                    break
            if lab is None:
                continue
            sid = str(flat.get("attack_id") or flat.get("sequence_id") or lab)
            ev = normalize(raw, n)
            s = seqs.setdefault(sid, {"id": sid, "type": str(flat.get("attack_type") or flat.get("label") or "").lower(),
                                      "host": ev.host, "start": ev.ts, "end": ev.ts, "refs": set(),
                                      "description": ""})
            s["refs"].add(ev.ref)
            if ev.ts is not None:
                s["start"] = ev.ts if s["start"] is None else min(s["start"], ev.ts)
                s["end"] = ev.ts if s["end"] is None else max(s["end"], ev.ts)
    return list(seqs.values())


def _overlaps(alert: dict, s: dict, slack: float) -> bool:
    if s["host"] and alert["host"] != s["host"]:
        return False
    if s["start"] is None:
        return False
    end = s["end"] if s["end"] is not None else s["start"]
    return alert["first_seen"] <= end + slack and alert["last_seen"] >= s["start"] - slack


def evaluate(alerts: list[dict], blocks: list[dict], seqs: list[dict], slack: float = 60.0) -> dict:
    alert_match: dict[str, list[str]] = {}
    seq_hits: dict[str, list[str]] = {s["id"]: [] for s in seqs}
    for a in alerts:
        ev = set(a["evidence"])
        m = [s["id"] for s in seqs if s["refs"] and ev & s["refs"]]
        if not m:
            m = [s["id"] for s in seqs if not s["refs"] and _overlaps(a, s, slack)]
        alert_match[a["id"]] = m
        for sid in m:
            seq_hits[sid].append(a["id"])
    by_id = {a["id"]: a for a in alerts}
    tp_alerts = [aid for aid, m in alert_match.items() if m]
    fp_alerts = [aid for aid, m in alert_match.items() if not m]
    detected = [sid for sid, h in seq_hits.items() if h]
    missed = [sid for sid, h in seq_hits.items() if not h]
    n_alerts = len(alerts)
    precision = len(tp_alerts) / n_alerts if n_alerts else (1.0 if not seqs else 0.0)
    recall = len(detected) / len(seqs) if seqs else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    seq_by_id = {s["id"]: s for s in seqs}
    latency = {}
    for sid, h in seq_hits.items():
        s = seq_by_id[sid]
        if h and s["start"] is not None:
            latency[sid] = round(min(by_id[a]["first_seen"] for a in h) - s["start"], 3)

    per_rule: dict[str, dict] = {}
    for a in alerts:
        r = per_rule.setdefault(a["rule"], {"alerts": 0, "tp_alerts": 0, "fp_alerts": 0})
        r["alerts"] += 1
        r["tp_alerts" if alert_match[a["id"]] else "fp_alerts"] += 1
    per_type: dict[str, dict] = {}
    for s in seqs:
        t = TYPE_TO_RULE.get(s["type"], s["type"] or "unknown")
        r = per_type.setdefault(t, {"sequences": 0, "detected": 0})
        r["sequences"] += 1
        r["detected"] += 1 if seq_hits[s["id"]] else 0
    for r in per_type.values():
        r["recall"] = round(r["detected"] / r["sequences"], 4) if r["sequences"] else None

    tp_set = set(tp_alerts)
    active = [b for b in blocks if b.get("status") == "active"]
    blocks_on_attacks = [b["id"] for b in active
                         if set(b.get("alert_ids", [])) & tp_set
                         or any(set(b.get("evidence", [])) & s["refs"] for s in seqs)]
    fp_detail = [{"id": aid, "rule": by_id[aid]["rule"], "host": by_id[aid]["host"],
                  "title": by_id[aid]["title"], "score": by_id[aid]["score"]} for aid in fp_alerts]
    miss_detail = [{"id": sid, "type": seq_by_id[sid]["type"], "host": seq_by_id[sid]["host"],
                    "description": seq_by_id[sid].get("description", "")} for sid in missed]
    core = {
        "all_sequences_detected": not missed,
        "false_alarms_le_2": len(fp_alerts) <= 2,
        "at_least_one_block": len(blocks_on_attacks) >= 1,
    }
    core["pass"] = all(core.values())
    return {
        "sequences": len(seqs), "detected": len(detected), "missed": len(missed),
        "alerts": n_alerts, "true_positive_alerts": len(tp_alerts), "false_alarms": len(fp_alerts),
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "mean_latency_s": round(sum(latency.values()) / len(latency), 3) if latency else None,
        "latency_s": latency, "per_rule": per_rule, "per_attack_type": per_type,
        "blocks_total": len(blocks), "blocks_active": len(active),
        "blocks_on_attacks": len(blocks_on_attacks),
        "false_alarm_detail": fp_detail, "missed_detail": miss_detail,
        "alert_to_sequences": alert_match, "core_target": core,
    }


def to_markdown(r: dict, title: str) -> str:
    c = r["core_target"]
    yes = lambda b: "PASS" if b else "FAIL"
    lines = [f"# Detection report: {title}", "",
             f"**Core target: {yes(c['pass'])}**", "",
             "| Check | Result |", "|---|---|",
             f"| All attack sequences detected | {yes(c['all_sequences_detected'])} ({r['detected']}/{r['sequences']}) |",
             f"| At most 2 false alarms | {yes(c['false_alarms_le_2'])} ({r['false_alarms']}) |",
             f"| At least one block on an attack | {yes(c['at_least_one_block'])} ({r['blocks_on_attacks']}) |",
             "", "| Metric | Value |", "|---|---|",
             f"| Precision (alert level) | {r['precision']:.3f} |",
             f"| Recall (sequence level) | {r['recall']:.3f} |",
             f"| F1 | {r['f1']:.3f} |",
             f"| Alerts | {r['alerts']} |",
             f"| Mean detection latency | {r['mean_latency_s']} s |",
             "", "## Recall per attack type", "", "| Type | Detected | Recall |", "|---|---|---|"]
    for t, v in r["per_attack_type"].items():
        lines.append(f"| {t} | {v['detected']}/{v['sequences']} | {v['recall']} |")
    lines += ["", "## Alerts per rule", "", "| Rule | Alerts | True | False |", "|---|---|---|---|"]
    for t, v in r["per_rule"].items():
        lines.append(f"| {t} | {v['alerts']} | {v['tp_alerts']} | {v['fp_alerts']} |")
    if r["false_alarm_detail"]:
        lines += ["", "## False alarms", ""] + [f"- {x['id']} ({x['rule']}, {x['host']}): {x['title']}"
                                                 for x in r["false_alarm_detail"]]
    if r["missed_detail"]:
        lines += ["", "## Missed sequences", ""] + [f"- {x['id']} ({x['type']}, {x['host']}) {x['description']}"
                                                     for x in r["missed_detail"]]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", required=True, help="agent output directory (alerts.json, blocklist.jsonl)")
    p.add_argument("--labels", help="labels JSON (sequence list)")
    p.add_argument("--stream", help="stream with labels embedded in events")
    p.add_argument("--slack", type=float, default=60.0, help="time-overlap slack when labels have no ids")
    a = p.parse_args(argv)
    if not a.labels and not a.stream:
        p.error("need --labels or --stream")
    out = Path(a.out)
    alerts = json.loads((out / "alerts.json").read_text(encoding="utf-8"))
    blocks = [json.loads(l) for l in (out / "blocklist.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    seqs = load_label_file(a.labels) if a.labels else labels_from_stream(a.stream)
    r = evaluate(alerts, blocks, seqs, a.slack)
    (out / "report.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
    md = to_markdown(r, out.name)
    (out / "report.md").write_text(md, encoding="utf-8")
    sys.stdout.write(md)
    return 0 if r["core_target"]["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
