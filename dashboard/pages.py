"""Render the workspace and case library from completed runs."""

from html import escape
from pathlib import Path
import re
from string import Template
from urllib.parse import quote

from hids_agent.contract import read_json
from hids_agent.dashboard import THEME


def case_folder(root, name):
    if not re.fullmatch(r"[\w-]+", name):
        return None
    folder = (root / name).resolve()
    if folder.parent != root or not (folder / "dashboard.html").is_file():
        return None
    return folder


def status_label(report):
    status = report.get("status")
    if status in {"PASS", "FAIL", "INCOMPLETE", "UNSCORED"}:
        return status
    return "UNSCORED"


def case_cards(root, folders):
    rows = []
    for folder in folders:
        try:
            summary_path = (folder / "summary.json").resolve()
            report_path = (folder / "report.json").resolve()
            if not all(p.is_relative_to(root) for p in (summary_path, report_path)):
                continue
            summary = read_json(summary_path)
            status = status_label(read_json(report_path)) if report_path.is_file() else "UNSCORED"
            source = escape(str(summary.get("source") or "Saved event replay"))
            mode = escape(str(summary.get("mode") or ""))
            alerts = summary.get("alerts")
            count = f"{alerts} {'alert' if alerts == 1 else 'alerts'}" if isinstance(alerts, int) else ""
            meta = " · ".join(value for value in (escape(folder.name), mode, count) if value)
        except (OSError, ValueError, AttributeError, TypeError):
            continue
        rows.append(
            f'<a class="case-row" href="/case/{quote(folder.name)}"><span class="case-meta">'
            f'<strong>{source}</strong><small>{meta}</small></span>'
            f'<span class="badge badge--{status.lower()}">{status}</span></a>'
        )
    if rows:
        return '<div class="case-list">' + "".join(rows) + "</div>"
    return '<div class="case-list"><p class="empty">No replays here yet. Run a case to start the library.</p></div>'


def workspace(root: Path, *, library=False):
    folders = [folder for entry in root.iterdir() if (folder := case_folder(root, entry.name))]
    folders.sort(key=lambda folder: folder.stat().st_mtime, reverse=True)
    name = "cases.html" if library else "index.html"
    cases = case_cards(root, folders if library else folders[:4])
    count = len(folders)
    return Template(Path(__file__).with_name(name).read_text(encoding="utf-8")).substitute(
        theme=THEME, recent=cases, cases=cases, case_count=f"{count} {'case' if count == 1 else 'cases'}")
