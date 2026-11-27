"""Score final alerts against independent, sequence-level truth."""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from statistics import mean
from math import isfinite

from .label_input import TYPE_TO_RULE, labels_from_stream
from .normalize import parse_ts

from .contract import BASE, evidence_ids, object_record, read_json, stamp, text


def labels_from_events(events):
    """Explicit offline import of tagged events with attack_id and attack_type."""
    groups = {}
    for event in events:
        if not event.get("attack_id"):
            continue
        key = text(event["attack_id"], "attack_id")
        host, rule = text(event.get("host"), "host"), text(event.get("attack_type"), "attack_type")
        moment = stamp(event.get("ts"))
        group = groups.setdefault(key, dict(attack_id=key, host=host, type=rule,
                                            start=moment, end=moment, event_ids=[]))
        if (host, rule) != (group["host"], group["type"]):
            raise ValueError(f"inconsistent host or type for attack {key}")
        group["start"], group["end"] = min(group["start"], moment), max(group["end"], moment)
        group["event_ids"].append(text(event.get("id"), "id"))
    return list(groups.values())


def labels_by_id(rows):
    if isinstance(rows, dict):
        rows = next((rows[k] for k in ("sequences", "attacks", "labels") if k in rows), None)
    if not isinstance(rows, list):
        raise ValueError("labels must be a sequence array or an object containing one")
    result = {}
    for i, row in enumerate(rows, 1):
        object_record(row)
        key = str(row.get("attack_id") or row.get("id") or f"S{i}")
        if key in result:
            raise ValueError(f"duplicate attack ID: {key}")
        name = str(row.get("type") or row.get("attack_type") or row.get("technique") or "").lower()
        rule = TYPE_TO_RULE.get(name, name)
        refs = row.get("event_ids", row.get("events", row.get("ids", [])))
        if not isinstance(refs, (list, set)) or any(type(x) not in (int, str) for x in refs):
            raise ValueError(f"invalid event_ids for {key}")
        start, end = parse_ts(row.get("start")), parse_ts(row.get("end", row.get("start")))
        if start is not None and end is not None and end < start:
            raise ValueError(f"end precedes start in {key}")
        host = str(row.get("host") or "").strip().lower()
        if not refs and (not host or rule not in BASE or None in (start, end)):
            raise ValueError(f"time-only label {key} requires a host, rule, start and end")
        result[key] = dict(attack_id=key, type=rule, host=host, start=start, end=end,
                           event_ids=evidence_ids([str(x) for x in refs]) if refs else [],
                           variant=row.get("variant") or name or "unspecified")
    return result


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def evaluate(alerts, blocks, labels, *, slack_s=60):
    if labels is None:
        return {"status": "UNSCORED", "reason": "No labels supplied", "precision": None, "recall": None}
    if not isfinite(slack_s) or slack_s < 0:
        raise ValueError("time matching slack must be finite and nonnegative")
    truth = labels_by_id(labels)
    # Legacy ID-only labels can be scoped when their evidence identifies a single host and rule.
    partial = [l for l in truth.values() if not l["host"] or l["type"] not in BASE]
    if partial:
        scopes = defaultdict(set)
        for a in alerts:
            for hit in a.get("observations", [a]):
                for ref in hit["evidence"]:
                    scopes[ref].add((a["host"].lower(), TYPE_TO_RULE.get(a["rule"], a["rule"])))
        for label in partial:
            possible = {(h, r) for ref in label["event_ids"] for h,r in scopes[ref]
                        if (not label["host"] or label["host"] == h) and
                        (label["type"] not in BASE or label["type"] == r)}
            if len(possible) == 1:
                label["host"], label["type"] = possible.pop()
    refs, windows = defaultdict(set), defaultdict(list)
    for key, label in truth.items():
        scope = (label["host"], label["type"])
        if label["event_ids"]:
            for ref in label["event_ids"]:
                refs[(*scope, ref)].add(key)
        else:
            windows[scope].append(key)
    active = {b["id"]: b for b in blocks if b["status"] == "active" and b["simulated"] is True}
    found, matches, ambiguous, false_ids, credited = {}, {}, {}, [], set()
    per_rule = {rule: {"alerts": 0, "matched_alerts": 0, "false_alarms": 0,
                       "sequences": 0, "detected": 0} for rule in sorted(set(BASE).union(l["type"] or "unspecified" for l in truth.values()))}
    for alert in alerts:
        aid = alert["id"]
        scope = (alert["host"].lower(), TYPE_TO_RULE.get(alert["rule"], alert["rule"]))
        counts = per_rule[scope[1]]
        counts["alerts"] += 1
        observations = alert.get("observations")
        grouped_only = observations is None
        if observations is None:
            observations = [{"timestamp": alert["first_seen"], "evidence": alert["evidence"],
                             "blocks": alert.get("blocks", [])}]
        exact, by_time = defaultdict(list), defaultdict(list)
        conflicts = set()
        for hit in observations:
            ids = set()
            for ref in hit["evidence"]:
                ids.update(refs.get((*scope, ref), ()))
            if len(ids) == 1:
                exact[ids.pop()].append(hit)
            elif ids:
                conflicts.update(ids)
            else:
                possible = [key for key in windows[scope]
                            if truth[key]["start"] - slack_s <= hit["timestamp"] <= truth[key]["end"] + slack_s]
                if len(possible) == 1:
                    by_time[possible[0]].append(hit)
                elif possible:
                    conflicts.update(possible)
        options = exact or by_time
        if conflicts:
            ambiguous[aid] = sorted(conflicts)
        if not options:
            false_ids.append(aid)
            counts["false_alarms"] += 1
            continue
        matches[aid] = {"attack_id": next(iter(options)), "attack_ids": sorted(options),
                        "method": "evidence" if exact else "time"}
        counts["matched_alerts"] += 1
        for key, hits in options.items():
            first = min(h["timestamp"] for h in hits)
            found[key] = min(found.get(key, first), first)
            for hit in hits:
                for bid in hit["blocks"]:
                    b = active.get(bid)
                    if not b or b["host"] != alert["host"] or aid not in b["alert_ids"]:
                        continue
                    if grouped_only and exact and not set(b.get("evidence", ())).intersection(truth[key]["event_ids"]):
                        continue
                    credited.add(bid)
    variants = {}
    latency = {k: t - truth[k]["start"] for k, t in found.items() if truth[k]["start"] is not None}
    for key, label in truth.items():
        counts = per_rule[label["type"] or "unspecified"]
        counts["sequences"] += 1
        counts["detected"] += int(key in found)
        v = variants.setdefault(label["variant"], {"detected": 0, "sequences": 0})
        v["sequences"] += 1
        v["detected"] += int(key in found)
    for row in per_rule.values():
        row["precision"] = ratio(row["matched_alerts"], row["alerts"])
        row["recall"] = ratio(row["detected"], row["sequences"])
    precision, recall = ratio(len(matches), len(alerts)), ratio(len(found), len(truth))
    f1 = None if None in (precision, recall) else (ratio(2 * precision * recall, precision + recall) or 0.0)
    passed = bool(truth) and len(found) == len(truth) and len(false_ids) <= 2 and bool(credited)
    return {"status": "PASS" if passed else "FAIL", "core_target": {"pass": passed,
            "all_sequences_detected": bool(truth) and len(found) == len(truth), "false_alarms_le_2": len(false_ids) <= 2,
            "at_least_one_block": bool(credited)}, "precision": precision, "recall": recall, "f1": f1,
            "alerts": len(alerts), "matched_alerts": len(matches), "detected": len(found), "sequences": len(truth),
            "false_alarms": len(false_ids), "false_alert_ids": false_ids, "missed": sorted(truth.keys() - found.keys()),
            "matches": matches, "ambiguous": ambiguous,
            "duplicate_matches": sum(len(m["attack_ids"]) for m in matches.values()) - len(found),
            "blocks_on_attacks": sorted(credited), "latency_s": latency,
            "mean_latency_s": mean(latency.values()) if latency else None,
            "per_rule": per_rule, "per_attack_type": variants}


def score_run(run, labels, slack_s=60):
    summary = run["summary"]
    if summary.get("input_error") or summary.get("processing_errors") or summary.get("interrupted"):
        return {"status": "INCOMPLETE", "reason": "Replay interrupted or input/detection failed; see summary.json",
                "precision": None, "recall": None}
    return evaluate(run["alerts"], run["blocks"], labels, slack_s=slack_s)


def main(argv=None):
    from .outputs import load_run, publish_report
    from .contract import lines
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--out", type=Path, required=True, help="existing run folder")
    group = cli.add_mutually_exclusive_group(required=True)
    group.add_argument("--labels", type=Path)
    group.add_argument("--embedded-labels", type=Path, help="tagged raw events as JSONL")
    group.add_argument("--stream", type=Path, help="organizer stream with embedded labels")
    cli.add_argument("--slack", type=float, default=60)
    args = cli.parse_args(argv)
    try:
        if args.labels:
            labels = read_json(args.labels)
        elif args.stream:
            labels = labels_from_stream(args.stream) or None
        else:
            with args.embedded_labels.open(encoding="utf-8-sig") as stream:
                labels = labels_from_events(row for _, row in lines(stream)) or None
        run = load_run(args.out)
        report = score_run(run, labels, args.slack)
        publish_report(args.out, run, report)
        print(f"{report['status']}  {args.out / 'report.md'}")
        return int(report["status"] in {"FAIL", "INCOMPLETE"})
    except (OSError, ValueError, KeyError) as exc:
        cli.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
