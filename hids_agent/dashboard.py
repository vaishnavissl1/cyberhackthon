"""Offline dashboard. Untrusted telemetry is rendered as escaped text only."""

from collections import defaultdict
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from string import Template

THEME = Path(__file__).with_name("dashboard.css").read_text(encoding="utf-8")


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


PAGES = {
    "overview": "Overview",
    "alerts": "Alerts",
    "incidents": "Incidents",
    "evaluation": "Evaluation",
    "response": "Response",
    "audit": "Audit trail",
}


def report_filename(view):
    return "dashboard.html" if view == "overview" else f"dashboard-{view}.html"


def report_href(view, case_url=None):
    if not case_url:
        return report_filename(view)
    return case_url if view == "overview" else f"{case_url}/{view}"


def overview(run, report):
    summary = run["summary"]
    cards = [
        ("Precision", percent(report["precision"])),
        ("Sequence recall", percent(report["recall"])),
        ("False alarms / limit", f'{report["false_alarms"]} / 2' if "false_alarms" in report else "\u2014"),
        ("Blocks on attacks", len(report["blocks_on_attacks"]) if "blocks_on_attacks" in report else "\u2014"),
    ]
    return {
        "metrics": "".join(f'<div class="metric"><span>{esc(label)}</span><strong>{esc(value)}</strong></div>'
                           for label, value in cards),
        "events": esc(summary["events"]),
        "throughput": (f" \u00b7 {rate:,.0f} events/s"
                       if (rate := summary.get("events_per_second")) is not None else ""),
        "alert_count": len(run["alerts"]),
        "volume": chart(summary["events_per_minute"], run["alerts"]),
        "evaluation_note": evaluation_note(report),
    }


def evaluation_note(report):
    return f'<p class="summary-note">{esc(report["reason"])}</p>' if "reason" in report else ""


def alerts_page(run, report):
    alerts = defaultdict(list)
    levels = {"critical": 0, "high": 0, "medium": 0}
    for alert in sorted(run["alerts"], key=lambda row: row["first_seen"]):
        details = {
            "Signals": alert["signals"], "Context": alert["context"], "Evidence": alert["evidence"],
            "Requested blocks": alert.get("requested_blocks", alert.get("would_block", [])),
            "Block IDs": alert["blocks"], "Techniques": alert.get("mitre", []),
            "Label match": report.get("matches", {}).get(alert["id"]),
        }
        severity = alert["severity"]
        levels[severity] = levels.get(severity, 0) + 1
        alerts[alert["host"]].append(
            f'<details class="alert" data-severity="{esc(severity)}"><summary><small>{esc(alert["id"])}</small>'
            f'<b>{esc(alert["title"])}</b><span class="badge {esc(severity)}">'
            f'{esc(severity)} \u00b7 {esc(alert["score"])}</span></summary>'
            f'<div class="alert-content"><p>{esc(alert["host"])} \u00b7 {esc(alert["entity"])} \u00b7 '
            f'{esc(utc(alert["first_seen"]))} UTC \u00b7 {esc(alert["hits"])} observation(s)</p>'
            f'<pre>{esc(json.dumps(details, indent=2))}</pre></div></details>')
    groups = "".join(f'<div class="host" data-host="{esc(host)}"><h3>{esc(host)}</h3>{"".join(rows)}</div>'
                     for host, rows in alerts.items())
    return {
        "alerts": groups or '<p class="empty">No confirmed detections.</p>',
        "host_options": "".join(f'<option value="{esc(host)}">{esc(host)}</option>' for host in sorted(alerts)),
        "severity": " \u00b7 ".join(f"{count} {esc(level)}" for level, count in levels.items()),
    }


def evaluation(run, report):
    rules = table(
        ["Rule", "Precision", "False alarms", "Sequence recall", "Sequences found"],
        [[k, percent(r["precision"]), r["false_alarms"], percent(r["recall"]), f'{r["detected"]}/{r["sequences"]}']
         for k, r in report.get("per_rule", {}).items()], "Supply labels to score this run.")
    match_info = evaluation_note(report)
    if report["status"] in ("PASS", "FAIL"):
        lag = report["mean_latency_s"]
        delay = "\u2014" if lag is None else f"{lag:.1f} s"
        match_info = (f'<p class="summary-note">F1 {percent(report["f1"])} \u00b7 Mean detection latency {delay} \u00b7 '
                      f'Missed sequences {esc(", ".join(report["missed"]) or "none")} \u00b7 '
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
        sweep_table = '<div class="panel section"><h3>Development threshold sweep</h3>' + table(
            ["Parameters", "Precision", "Recall", "False alarms", "Target"],
            [[json.dumps(t["config"]), percent(t["precision"]), percent(t["recall"]), t["false_alarms"], t["status"]]
             for t in trials], "No trial results.") + "</div>"
    return {"rules": rules, "match_info": match_info, "sweep": sweep_table}


def incidents_page(run, report):
    return {"incidents": table(
        ["Incident", "Host", "First seen (UTC)", "Alerts"],
        [[i["id"], i["host"], utc(i["first_seen"]), ", ".join(i["alert_ids"])] for i in run["incidents"]],
        "No incidents.")}


def response_page(run, report):
    return {"decisions": table(
        ["ID", "Host", "Action", "Target", "Status", "Alerts"],
        [[b["id"], b["host"], b["action"], b["target"], b["status"], ", ".join(b["alert_ids"])] for b in run["blocks"]],
        "No simulated block decisions.")}


def audit_page(run, report):
    return {"notes": table(
        ["Record", "Host", "Reason", "Approval", "Evidence"],
        [[kind, n["host"], n["reason"], n.get("entry", "\u2014"), ", ".join(n["evidence"])]
         for kind in ("audit", "watch") for n in run[kind]], "No audit or watch records.")}


RENDERERS = {"overview": overview, "alerts": alerts_page, "incidents": incidents_page,
             "evaluation": evaluation, "response": response_page, "audit": audit_page}


def case_navigation(view, case_url):
    links = []
    for key, label in PAGES.items():
        current = ' aria-current="page"' if key == view else ""
        links.append(f'<a href="{esc(report_href(key, case_url))}"{current}>{label}</a>')
    return "".join(links)


def render(run, report, *, view="overview", case_url=None):
    summary = run["summary"]
    status = report["status"]
    if case_url:
        home = "/"
        top_links = '<a href="/">Home</a><a href="/replay">New replay</a><a href="/cases">Cases</a>'
        artifact_base = case_url + "/files/"
    else:
        home = report_filename("overview")
        top_links = f'<a href="{home}">Case overview</a>'
        artifact_base = ""
    template_root = Path(__file__).parent
    section = RENDERERS[view](run, report)
    template = (template_root / "dashboard.html").read_text(encoding="utf-8")
    part = (template_root / "report_pages" / f"{view}.html").read_text(encoding="utf-8")
    body = Template(part).substitute(section)
    return Template(template).substitute(
        theme=THEME, home=esc(home), top_links=top_links,
        title=PAGES[view], heading="Replay findings" if view == "overview" else PAGES[view],
        report_link=esc(artifact_base + "report.md"), blocks_link=esc(artifact_base + "blocklist.jsonl"),
        source=esc(summary["source"]), mode=esc(summary["mode"]), status_class=esc(status.lower()), status=esc(status),
        case_navigation=case_navigation(view, case_url), body=body)
