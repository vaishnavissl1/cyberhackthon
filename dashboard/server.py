"""Browse completed cases and run candidate fixtures on this computer."""

import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
import json
from pathlib import Path
import re
from urllib.parse import quote, unquote, urlsplit
from uuid import uuid4

from hids_agent.handoff import process
from hids_agent.contract import lines, object_record, read_json, write_json
from hids_agent.dashboard import PAGES, render
from hids_agent.evaluate import evaluate, score_run
from hids_agent.replay import demo, replay_files
from hids_agent.outputs import load_run, new_folder, save_run
from .pages import case_folder, status_label, workspace

ARTIFACTS = {"report.md", "report.json", "blocklist.jsonl", "alerts.json", "summary.json", "audit.jsonl"}
CASE_INPUTS = ARTIFACTS | {"incidents.json", "watch.jsonl", "sweep.json"}
WORKSPACE = {"/": "overview", "/replay": "replay", "/cases": "cases"}


class Cases(BaseHTTPRequestHandler):
    def reply(self, code, content, mime="text/html; charset=utf-8", *, filename=None):
        data = content.encode("utf-8") if isinstance(content, str) else content
        self.send_response(code)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

    def local(self):
        port = self.server.server_port
        return self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")

    def do_GET(self):
        if not self.local():
            return self.reply(403, "Loopback requests only.")
        path = unquote(urlsplit(self.path).path)
        root = self.server.output
        try:
            if path in WORKSPACE:
                return self.reply(200, workspace(root, WORKSPACE[path]))
            if path == "/assets/replay-campus.jpg":
                return self.reply(200, Path(__file__).with_name("replay-campus.jpg").read_bytes(), "image/jpeg")
            match = re.fullmatch(r"/case/([\w-]+)(?:/([\w-]+)|/files/([\w.-]+))?/?", path)
            if match and (folder := case_folder(root, match[1])):
                if match[3]:
                    filename = match[3]
                    file = (folder / filename).resolve()
                    if filename in ARTIFACTS and file.parent == folder and file.is_file():
                        return self.reply(200, file.read_bytes(), "application/octet-stream", filename=filename)
                elif (view := match[2] or "overview") in PAGES:
                    return self.case_page(folder, match[1], view)
        except (OSError, ValueError, KeyError, TypeError):
            return self.reply(422, "This replay could not be loaded.", "text/plain; charset=utf-8")
        self.reply(404, "Case or file not found.", "text/plain; charset=utf-8")

    def case_page(self, folder, name, view):
        if any((folder / filename).resolve().parent != folder for filename in CASE_INPUTS):
            raise ValueError("case files need to stay inside the case directory")
        report_file = folder / "report.json"
        run = load_run(folder)
        report = read_json(report_file) if report_file.is_file() else None
        if report is None or "status" not in report:
            report = score_run(run, None)
        if report["status"] != status_label(report):
            raise ValueError("unknown report status")
        return self.reply(200, render(run, report, view=view, case_url="/case/" + quote(name)))

    def do_POST(self):
        if (not self.local() or self.path != "/run" or
                self.headers.get("Origin") != "http://" + self.headers.get("Host", "")):
            return self.reply(403, "Open the runner on this computer.", "text/plain")
        try:
            if self.headers.get_content_type() != "application/json":
                raise ValueError("expected JSON")
            size = int(self.headers.get("Content-Length", -1))
            if not 0 < size <= 8 * 1024 * 1024:
                return self.reply(413, "Select files under 8 MiB total.", "text/plain")
            request = object_record(json.loads(self.rfile.read(size)))
            split, mode = request.get("split"), request.get("mode")
            if mode not in ("detect", "prevent"):
                raise ValueError("select detect or prevent mode")
            name = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + uuid4().hex[:8]
            with new_folder(self.server.output / name) as folder:
                if split == "import":
                    handoff = request.get("handoff")
                    if not isinstance(handoff, str):
                        raise ValueError("choose a candidate JSONL file")
                    run = process(lines(StringIO(handoff)), mode=mode, source="Imported candidate handoff",
                                  never_block=request.get("never_block"))
                    report = evaluate(run["alerts"], run["blocks"], request.get("labels"))
                    save_run(folder, run, report)
                elif split == "raw":
                    raw = request.get("events")
                    if not isinstance(raw, str):
                        raise ValueError("choose a raw events file")
                    inputs = folder / "inputs"
                    inputs.mkdir()
                    (inputs / "events.jsonl").write_text(raw, encoding="utf-8")
                    for key in ("baseline", "allowlist", "labels"):
                        if key in request:
                            write_json(inputs / f"{key}.json", request[key])
                    replay_files(folder, inputs, mode, "Uploaded raw event replay")
                else:
                    demo(folder, split, mode)
            return self.reply(201, json.dumps({"url": "/case/" + name}), "application/json")
        except (OSError, ValueError, TypeError, OverflowError) as exc:
            self.reply(400, str(exc), "text/plain; charset=utf-8")


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--root", type=Path, default=Path("runs"))
    cli.add_argument("--port", type=int, default=8765)
    args = cli.parse_args()
    args.root.mkdir(parents=True, exist_ok=True)
    with ThreadingHTTPServer(("127.0.0.1", args.port), Cases) as server:
        server.output = args.root.resolve()
        print(f"Open http://127.0.0.1:{server.server_port}/", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
