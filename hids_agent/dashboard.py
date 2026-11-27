"""Offline dashboard. Untrusted telemetry is rendered as escaped text only."""

from collections import defaultdict
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from string import Template


def percent(value):
    return "—" if value is None else f"{value:.1%}"


def esc(value):
    return escape(str(value), quote=True)


def utc(value):
    try:
        return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return str(value)


def table(headings, rows, empty):
    if not rows:
        return f'<p class="empty">{esc(empty)}</p>'
    head = "".join(f"<th scope=col>{esc(h)}</th>" for h in headings)
    body = "".join("<tr>" + "".join(f"<td>{esc(v)}</td>" for v in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def chart(volume, alerts):
    counts = {int(k): [v, 0] for k, v in volume.items()}
    for alert in alerts:
        counts.setdefault(int(alert["first_seen"] // 60), [0, 0])[1] += 1
    if not counts:
        return '<p class="empty">No event or alert counts supplied.</p>'
    start, end = min(counts), max(counts)
    width = max(1, (end - start + 48) // 48)
    buckets = [[0, 0] for _ in range((end - start) // width + 1)]
    for minute, (events, hits) in counts.items():
        bucket = buckets[(minute - start) // width]
        bucket[0] += events
        bucket[1] += hits
    max_events = max(1, max(b[0] for b in buckets))
    max_hits = max(1, max(b[1] for b in buckets))
    bars = "".join(f'<div title="{esc(utc((start+i*width)*60))} UTC: {n} events, {a} alerts">'
                   f'<span style="--bar:{round(100*n/max_events)}%"></span>'
                   f'<span style="--bar:{round(100*a/max_hits)}%"></span></div>' for i, (n, a) in enumerate(buckets))
    return (f'<div class="chart" aria-label="Event and alert counts by time">{bars}</div>'
            f'<p class="axis">{esc(utc(start*60))} UTC, {width} min per pair. '
            'Events in teal, alerts in amber. Each uses its own scale.</p>')


def render(run, report):
    summary = run["summary"]
    status = report["status"]
    cards = [("Precision", percent(report["precision"])), ("Sequence recall", percent(report["recall"])),
             ("False alarms", str(report.get("false_alarms", "—"))),
             ("Blocks on attacks", str(len(report["blocks_on_attacks"])) if "blocks_on_attacks" in report else "—")]
    metrics = "".join(f"<div><span>{esc(label)}</span><strong>{esc(value)}</strong></div>" for label, value in cards)
    alerts = defaultdict(list)
    for a in sorted(run["alerts"], key=lambda row: row["first_seen"]):
        details = {"Signals": a["signals"], "Context": a["context"], "Evidence": a["evidence"],
                   "Requested blocks": a.get("requested_blocks", []), "Block IDs": a["blocks"],
                   "Techniques": a.get("mitre", []), "Label match": report.get("matches", {}).get(a["id"])}
        alerts[a["host"]].append(f'<details data-severity="{esc(a["severity"])}"><summary><small>{esc(a["id"])}</small>'
                      f'<b>{esc(a["title"])}</b><span class="sev {esc(a["severity"])}">'
                      f'{esc(a["severity"])} · {esc(a["score"])}</span></summary>'
                      f'<p>{esc(a["host"])} · {esc(a["entity"])} · {esc(utc(a["first_seen"]))} UTC'
                      f' · {esc(a["hits"])} observation(s)</p><pre>{esc(json.dumps(details, indent=2))}</pre></details>')
    rules = table(["Rule", "Precision", "False alarms", "Sequence recall", "Sequences found"],
                  [[k, percent(r["precision"]), r["false_alarms"], percent(r["recall"]), f'{r["detected"]}/{r["sequences"]}']
                   for k, r in report.get("per_rule", {}).items()], "Supply labels to score this run.")
    decisions = table(["ID", "Host", "Action", "Target", "Status", "Alerts"],
                      [[b["id"], b["host"], b["action"], b["target"], b["status"], ", ".join(b["alert_ids"])]
                       for b in run["blocks"]], "No simulated block decisions.")
    notes = table(["Record", "Host", "Reason", "Approval", "Evidence"],
                  [[kind, n["host"], n["reason"], n.get("entry", "—"), ", ".join(n["evidence"])]
                   for kind in ("audit", "watch") for n in run[kind]], "No audit or watch records.")
    incidents = table(["Incident", "Host", "First seen (UTC)", "Alerts"],
                      [[i["id"], i["host"], utc(i["first_seen"]), ", ".join(i["alert_ids"])]
                       for i in run["incidents"]], "No incidents.")
    match_info = ""
    if status in ("PASS", "FAIL"):
        lag = report['mean_latency_s']
        delay = "—" if lag is None else f"{lag:.1f} s"
        match_info = (f'<p>F1 {percent(report["f1"])} · Mean detection latency {delay} · '
                      f'Missed sequences {esc(", ".join(report["missed"]) or "none")} · '
                      f'False alerts {esc(", ".join(report["false_alert_ids"]) or "none")}</p>')
        match_info += table(["Labeled sequence", "Detection latency (s)"],
                            [[key, f"{value:g}"] for key, value in report["latency_s"].items()],
                            "No matched sequences.")
        match_info += table(["Attack type", "Sequences found", "Recall"],
                            [[key, f'{row["detected"]}/{row["sequences"]}', percent(row["detected"]/row["sequences"])]
                             for key, row in report["per_attack_type"].items()], "No labeled attack types.")
    sweep = run.get("sweep", {})
    trials = sweep.get("trials", []) if isinstance(sweep, dict) else []
    sweep_table = ""
    if trials:
        sweep_table = '<section><h2>Development threshold sweep</h2>' + table(
            ["Parameters", "Precision", "Recall", "False alarms", "Target"],
            [[json.dumps(t["config"]), percent(t["precision"]), percent(t["recall"]), t["false_alarms"], t["status"]]
             for t in trials], "No trial results.") + "</section>"
    levels = {"critical": 0, "high": 0, "medium": 0}
    for alert in run["alerts"]:
        levels[alert["severity"]] = levels.get(alert["severity"], 0) + 1
    severity = " · ".join(f"{n} {name}" for name, n in levels.items())
    rate = summary.get("events_per_second")
    throughput = f" · {rate:,.0f} event receipts/s" if rate is not None else ""
    template = (Path(__file__).with_name("dashboard.html")).read_text(encoding="utf-8")
    return Template(template).substitute(source=esc(summary["source"]), mode=esc(summary["mode"]),
        status=esc(status), events=esc(summary["events"] if summary["events"] else "—"), throughput=throughput, severity=severity,
        alert_count=len(run["alerts"]), metrics=metrics, volume=chart(summary["events_per_minute"], run["alerts"]),
        alerts="".join(f'<div class="host"><h3>{esc(host)}</h3>{"".join(rows)}</div>' for host, rows in alerts.items()) or '<p class="empty">No confirmed detections.</p>', rules=rules,
        decisions=decisions, notes=notes, incidents=incidents, match_info=match_info, sweep=sweep_table)
