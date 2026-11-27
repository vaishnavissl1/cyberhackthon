"""Browse completed cases and run candidate fixtures on this computer."""

import argparse
from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
import json
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit
from uuid import uuid4

from hids_agent.handoff import process
from hids_agent.contract import lines, object_record
from hids_agent.evaluate import evaluate
from hids_agent.replay import demo, replay_files
from hids_agent.contract import write_json
from hids_agent.outputs import new_folder, save_run


class Cases(BaseHTTPRequestHandler):
    def reply(self, code, content, mime="text/html; charset=utf-8"):
        data = content.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
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
        if path == "/":
            items = [p for p in root.iterdir() if re.fullmatch(r"[\w-]+", p.name)
                     and (p / "dashboard.html").is_file() and (p / "dashboard.html").resolve().is_relative_to(root)]
            links = "".join(f'<li><a href="/case/{escape(p.name)}">{escape(p.name)}</a></li>'
                            for p in sorted(items, key=lambda p: p.stat().st_mtime, reverse=True))
            page = Path(__file__).with_name("index.html").read_text(encoding="utf-8")
            return self.reply(200, page.replace("<!-- cases -->", links or "<li>No completed runs yet.</li>"))
        match = re.fullmatch(r"/case/([\w-]+)", path)
        if match:
            page = (root / match[1] / "dashboard.html").resolve()
            if page.is_relative_to(root) and page.is_file():
                return self.reply(200, page.read_text(encoding="utf-8"))
        self.reply(404, "Case not found.")

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
