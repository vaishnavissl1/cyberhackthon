"""Publish complete case folders and refresh an existing case after labels arrive."""

import os
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from .contract import lines, read_json, write_json, write_lines
from .dashboard import percent, render


@contextmanager
def new_folder(destination):
    """Only expose completed runs. Each invocation owns its staging directory."""
    dest = Path(destination).absolute()
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise FileExistsError(f"choose a new output directory: {dest}")
    with TemporaryDirectory(prefix=".replay-", dir=dest.parent) as tmp:
        stage = Path(tmp) / "case"
        stage.mkdir()
        yield stage
        stage.rename(dest)


def load_run(folder):
    def journal(name):
        with (folder / name).open(encoding="utf-8") as stream:
            return [row for _, row in lines(stream)]
    run = {"alerts": read_json(folder / "alerts.json"), "blocks": journal("blocklist.jsonl"),
            "incidents": read_json(folder / "incidents.json"), "summary": read_json(folder / "summary.json"),
            "watch": journal("watch.jsonl"), "audit": journal("audit.jsonl")}


    # Folders written by the original detector lack the later dashboard field names.
    summary = run["summary"]
    summary.setdefault("source", "Saved raw event replay")
    summary.setdefault("events", summary.get("events_processed", 0))
    summary.setdefault("events_per_minute", {})
    for i in run["incidents"]:
        i.setdefault("first_seen", i.get("start"))
        i.setdefault("alert_ids", i.get("alerts", []))
    for n in run["watch"]:
        n.setdefault("reason", n.get("note", "Watch observation"))
    for n in run["audit"]:
        n.setdefault("entry", n.get("allowlist_entry", {}))
    if (folder / "sweep.json").is_file():
        run["sweep"] = read_json(folder / "sweep.json")
    return run


def publish_report(folder, run, report):
    summary = run["summary"]
    md = [f"# Replay evaluation Ã‚Â· {report['status']}", "",
          f"Source: {summary['source']}  ", f"Mode: {summary['mode']}  ",
          f"Alerts: {len(run['alerts'])}  ", f"Simulated decisions: {len(run['blocks'])}", ""]
    if report["status"] in ("UNSCORED", "INCOMPLETE"):
        md.append(report["reason"])
    else:
        md += [f"Precision: {percent(report['precision'])}  ", f"Sequence recall: {percent(report['recall'])}  ",
               f"F1: {percent(report['f1'])}  ", f"False alarms: {report['false_alarms']} (limit 2)  ",
               f"Active simulated blocks linked to attacks: {len(report['blocks_on_attacks'])}", "",
               "| Rule | Matched alerts | False alarms | Sequences found |",
               "| --- | ---: | ---: | ---: |"]
        for rule, row in report["per_rule"].items():
            md.append(f"| {rule} | {row['matched_alerts']} | {row['false_alarms']} | {row['detected']}/{row['sequences']} |")
        md += ["", "Missed sequences: " + (", ".join(report["missed"]) or "none"),
               "","False alerts: " + (", ".join(report["false_alert_ids"]) or "none")]
    with TemporaryDirectory(dir=folder) as tmp:
        stage = Path(tmp)
        write_json(stage / "report.json", report)
        (stage / "report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
        (stage / "dashboard.html").write_text(render(run, report), encoding="utf-8")
        for name in ("report.json", "report.md", "dashboard.html"):
            os.replace(stage / name, folder / name)


def save_run(folder, run, report):
    for key in ("summary", "alerts", "incidents"):
        write_json(folder / f"{key}.json", run[key])
    for key, name in (("alerts", "alerts"), ("blocks", "blocklist"), ("audit", "audit"), ("watch", "watch")):
        write_lines(folder / f"{name}.jsonl", run[key])
    publish_report(folder, run, report)
