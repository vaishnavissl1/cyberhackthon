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


TEAL, AMBER, ALARM, MUTED = "#0e8a73", "#b96e12", "#d03b3b", "#9aa9a7"


def hbars(title, rows, legend=None, unit=""):
    """Horizontal bar chart as inline SVG. rows: (label, [(value, color, series)], value_text).
    Every bar has a hover title and a value label, so color never carries meaning alone."""
    if not rows:
        return ""
    top = max((sum(v for v, _, _ in segs) for _, segs, _ in rows), default=0) or 1
    width, left, right, row_h = 760, 210, 175, 28
    plot = width - left - right
    height = len(rows) * row_h + 8
    parts = []
    for i, (label, segs, text) in enumerate(rows):
        y = 4 + i * row_h
        parts.append(f'<text x="{left - 10}" y="{y + 17}" text-anchor="end" class="lbl">{esc(label)}</text>')
        x = left
        for value, color, series in segs:
            w = plot * value / top
            if w <= 0:
                continue
            seg = max(w - 2, 1.5)   # 2px surface gap between stacked segments
            parts.append(f'<rect x="{x:.1f}" y="{y + 5}" width="{seg:.1f}" height="16" rx="3" fill="{color}">'
                         f'<title>{esc(label)}: {esc(series)} {value:g}{esc(unit)}</title></rect>')
            x += w
        parts.append(f'<text x="{x + 6:.1f}" y="{y + 17}" class="val">{esc(text)}</text>')
    key = ""
    if legend:
        key = '<p class="key">' + "".join(
            f'<span><i style="background:{c}"></i>{esc(n)}</span>' for n, c in legend) + "</p>"
    return (f'<figure class="bars"><figcaption>{esc(title)}</figcaption>{key}'
            f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{esc(title)}">{"".join(parts)}</svg></figure>')


def charts(run, report):
    """Charts for every scored result; each has a matching table on the page."""
    out = []
    sev_order = ["critical", "high", "medium", "low", "info"]
    counts = {s: 0 for s in sev_order}
    for a in run["alerts"]:
        counts[a["severity"]] = counts.get(a["severity"], 0) + 1
    out.append(hbars("Alerts by severity", [(s, [(n, TEAL, "alerts")], str(n))
                                            for s, n in counts.items() if n or s in ("critical", "high", "medium")]))
    if report.get("status") in ("PASS", "FAIL"):
        out.append(hbars("Recall by rule: labeled attacks found",
                         [(rule, [(r["detected"], TEAL, "found"), (r["sequences"] - r["detected"], MUTED, "missed")],
                           f'{r["detected"]} of {r["sequences"]}' + ("" if r["detected"] == r["sequences"] else " (missed shown gray)"))
                          for rule, r in report.get("per_rule", {}).items() if r["sequences"]],
                         legend=[("found", TEAL), ("missed", MUTED)]))
        per_rule = {}
        for a in run["alerts"]:
            row = per_rule.setdefault(a["rule"], [0, 0])
            row[0 if report.get("matches", {}).get(a["id"]) else 1] += 1
        out.append(hbars("Alerts by rule: true detections and false alarms",
                         [(rule, [(t, TEAL, "true"), (f, ALARM, "false alarm")],
                           f"{t} true" + (f", {f} false alarm{'s' if f > 1 else ''}" if f else ", 0 false"))
                          for rule, (t, f) in sorted(per_rule.items())],
                         legend=[("true detection", TEAL), ("false alarm", ALARM)]))
        lat = sorted(report.get("latency_s", {}).items(), key=lambda kv: -kv[1])
        out.append(hbars("Detection latency per attack (seconds from first attack event to alert)",
                         [(k, [(max(v, 0), TEAL, "latency")], f"{v:g} s") for k, v in lat], unit=" s"))
    trials = (run.get("sweep") or {}).get("trials", []) if isinstance(run.get("sweep"), dict) else []
    if trials:
        outcomes: dict = {}
        for t in trials:
            key = (t.get("recall") or 0, t.get("false_alarms") or 0)
            outcomes[key] = outcomes.get(key, 0) + 1
        rows = [(f"recall {percent(r)}, {fa} false alarm{'s' if fa != 1 else ''}",
                 [(n, TEAL if r >= 1 and fa <= 2 else MUTED, "trials")],
                 f"{n} trial{'s' if n != 1 else ''}" + (" (meets target)" if r >= 1 and fa <= 2 else ""))
                for (r, fa), n in sorted(outcomes.items(), key=lambda kv: (-kv[0][0], kv[0][1]))]
        out.append(hbars(f"Tuning on development: outcome of {len(trials)} threshold settings", rows,
                         legend=[("meets core target", TEAL), ("misses an attack or too many false alarms", MUTED)]))
    return "".join(c for c in out if c)


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
        decisions=decisions, notes=notes, incidents=incidents, match_info=match_info, sweep=sweep_table,
        charts=charts(run, report))
