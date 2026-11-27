"""HIDS/HIPS event-replay agent.

    python provided_replay.py | python -m hids_agent.agent --out out/
    python -m hids_agent.agent --input data/dev_stream.jsonl --out out/dev

Reads JSON events (JSON Lines, a JSON array, or {"events": [...]}) from a pipe,
a file (optionally followed), a TCP socket or HTTP POSTs. Never executes anything:
"blocking" means writing a decision to blocklist.jsonl.
"""
from __future__ import annotations

import argparse
import heapq
import json
import queue
import socketserver
import sys
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .allowlist import load_allowlist
from .config import load_config, load_structured
from .engine import Engine, load_baseline
from .normalize import normalize
from .evaluate import score_run
from .outputs import publish_report
from .contract import write_lines

EOF = object()
_SEQ_LOCK = threading.Lock()


def _put(q: queue.Queue, counter: list, obj: dict) -> None:
    """Queue one event under a unique sequence number (network inputs are multi-threaded)."""
    with _SEQ_LOCK:
        counter[0] += 1
        seq = counter[0]
    q.put((seq, obj))


# ------------------------------------------------------------------ adapters
def _emit_text(text: str, q: queue.Queue, counter: list) -> None:
    """Push every JSON object found in `text` (JSONL, array or wrapper)."""
    s = text.lstrip("﻿").strip()
    if not s:
        return
    if s[0] == "[" or (s[0] == "{" and "\n" in s and s.rstrip()[-1] == "}" and _is_single_json(s)):
        try:
            obj = json.loads(s)
            for o in _expand(obj):
                _put(q, counter, o)
            return
        except json.JSONDecodeError:
            pass
    for line in s.splitlines():
        _emit_line(line, q, counter)


def _is_single_json(s: str) -> bool:
    try:
        json.loads(s)
        return True
    except json.JSONDecodeError:
        return False


def _expand(obj):
    if isinstance(obj, list):
        for o in obj:
            yield from _expand(o)
    elif isinstance(obj, dict) and isinstance(obj.get("events"), list) and len(obj) <= 3:
        yield from _expand(obj["events"])
    elif isinstance(obj, dict):
        yield obj


def _emit_line(line: str, q: queue.Queue, counter: list) -> None:
    line = line.strip().lstrip("﻿").rstrip(",")
    if not line or line in ("[", "]", "{", "}"):
        return
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as e:
        _put(q, counter, {"__error__": f"bad json: {e.msg}", "__raw__": line[:500]})
        return
    expanded = list(_expand(obj))
    if not expanded:
        _put(q, counter, {"__error__": "not an object", "__raw__": line[:500]})
    for o in expanded:
        _put(q, counter, o)


def _decode_incremental(stream, buf: str, q: queue.Queue, counter: list) -> None:
    """Arrays and multi-line objects: emit each value as soon as it is complete,
    so a live pipe is processed before the document is closed."""
    dec = json.JSONDecoder()
    in_array = buf.startswith("[")
    if in_array:
        buf = buf[1:]
    while True:
        buf = buf.lstrip(" \t\r\n,\ufeff")
        if in_array and buf.startswith("]"):
            in_array, buf = False, buf[1:]
            continue
        if not in_array and buf.startswith("["):
            in_array, buf = True, buf[1:]
            continue
        if buf:
            try:
                obj, end = dec.raw_decode(buf)
            except json.JSONDecodeError:
                pass
            else:
                for o in _expand(obj):
                    _put(q, counter, o)
                buf = buf[end:]
                continue
            nxt = buf.find("\n{", 1)
            if len(buf) > 1_000_000 and nxt > 0:      # unrecoverable element: skip it
                _put(q, counter, {"__error__": "bad json element", "__raw__": buf[:500]})
                buf = buf[nxt:]
                continue
        line = stream.readline()
        if not line:
            break
        buf += line
    if buf.strip():
        for line in buf.splitlines():
            _emit_line(line, q, counter)


def stream_reader(stream, q: queue.Queue, counter: list) -> None:
    first = stream.read(1)
    while first and (first.isspace() or first == "\ufeff"):
        first = stream.read(1)
    if first == "[":
        _decode_incremental(stream, first, q, counter)
    elif first:
        line = first + stream.readline()
        if line.rstrip().endswith(("{", "[", ",", ":")) and not _is_single_json(line.strip().rstrip(",")):
            _decode_incremental(stream, line, q, counter)   # pretty-printed document
        else:
            _emit_line(line, q, counter)
            for line in stream:
                _emit_line(line, q, counter)
    q.put(EOF)


def file_reader(path: str, q: queue.Queue, counter: list, follow: bool) -> None:
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        if not follow:
            stream_reader(f, q, counter)
            return
        pos = 0
        while True:
            line = f.readline()
            if line:
                if line.endswith("\n"):
                    _emit_line(line, q, counter)
                    pos = f.tell()
                else:
                    f.seek(pos)            # partial line still being written
                    time.sleep(0.05)
                continue
            try:
                if Path(path).stat().st_size < pos:   # truncated / rotated
                    f.seek(0)
                    pos = 0
            except FileNotFoundError:
                pass
            time.sleep(0.1)


def tcp_reader(addr: str, q: queue.Queue, counter: list) -> None:
    host, port = addr.rsplit(":", 1)

    class H(socketserver.StreamRequestHandler):
        def handle(self):
            for raw in self.rfile:
                _emit_line(raw.decode("utf-8", "replace"), q, counter)

    with socketserver.ThreadingTCPServer((host, int(port)), H) as srv:
        print(f"[agent] listening on tcp {addr}", file=sys.stderr)
        srv.serve_forever()


def http_reader(addr: str, q: queue.Queue, counter: list) -> None:
    host, port = addr.rsplit(":", 1)

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            length = self.headers.get("Content-Length", "")
            if not length.isdigit():
                self.send_error(411, "Content-Length required")
                return
            n = int(length)
            _emit_text(self.rfile.read(n).decode("utf-8", "replace"), q, counter)
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer((host, int(port)), H)
    print(f"[agent] listening on http {addr}", file=sys.stderr)
    srv.serve_forever()


def _guarded(target, q: queue.Queue, *args) -> None:
    """A reader that dies must end the run with an error, not hang the agent."""
    try:
        target(*args)
    except Exception as ex:
        q.put(("__fatal__", f"{type(ex).__name__}: {ex}"))


# ------------------------------------------------------------------ writers
class Outputs:
    def __init__(self, out: Path | None, quiet: bool):
        self.out = out
        self.quiet = quiet
        self.fh = {}
        if out:
            out.mkdir(parents=True, exist_ok=True)
            for name in ("alerts.jsonl", "blocklist.jsonl", "audit.jsonl", "watch.jsonl", "errors.log"):
                self.fh[name] = open(out / name, "w", encoding="utf-8", buffering=1)

    def write(self, name: str, rec: dict) -> None:
        f = self.fh.get(name)
        if f:
            f.write(json.dumps(rec, default=str) + "\n")

    def sink(self, kind: str, rec: dict) -> None:
        if kind in ("alert", "alert_update"):
            self.write("alerts.jsonl", {"type": kind, **rec})
            if kind == "alert" and not self.quiet:
                print(f"[ALERT {rec['severity'].upper():8}] {rec['id']} {rec['host']}: {rec['title']} "
                      f"(score {rec['score']})", file=sys.stderr)
        elif kind == "block":
            self.write("blocklist.jsonl", rec)
            if not self.quiet:
                print(f"[BLOCK] {rec['id']} {rec['action']} {rec['target']} ({rec['status']})", file=sys.stderr)
        elif kind == "audit":
            self.write("audit.jsonl", rec)
        elif kind == "watch":
            self.write("watch.jsonl", rec)

    def close(self) -> None:
        for f in self.fh.values():
            f.close()


# ------------------------------------------------------------------ pipeline
class Pipeline:
    """Reorders events by event time (watermark) and drops replayed duplicates
    by explicit (host, id). Events without an explicit id are never de-duplicated:
    identical failed logons in the same second are real and must be counted."""

    def __init__(self, engine: Engine, cfg: dict, outputs: Outputs):
        self.e = engine
        self.slack = float(cfg["reorder_slack_s"])
        self.cap = int(cfg["dedup_window"])
        self.seen: OrderedDict = OrderedDict()
        self.heap: list = []
        self.max_ts = None
        self.last_ts = 0.0
        self.o = outputs
        self.stats = {"read": 0, "malformed": 0, "duplicates": 0, "late": 0, "errors": 0}

    def push(self, seq: int, raw: dict) -> None:
        self.stats["read"] += 1
        if "__error__" in raw:
            self.stats["malformed"] += 1
            self.o.write("errors.log", {"line": seq, **raw})
            return
        try:
            ev = normalize(raw, seq)
        except Exception as ex:   # never let one odd event stop the agent
            self.stats["malformed"] += 1
            self.o.write("errors.log", {"line": seq, "__error__": f"normalize: {ex!r}"})
            return
        if ev.has_explicit_id:
            k = (ev.host, ev.ref)
            if k in self.seen:
                self.stats["duplicates"] += 1
                return
            self.seen[k] = None
            if len(self.seen) > self.cap:
                self.seen.popitem(last=False)
        if ev.ts is None:
            ev.ts = self.max_ts if self.max_ts is not None else self.last_ts
        if self.max_ts is not None and ev.ts < self.max_ts - self.slack:
            self.stats["late"] += 1
        self.max_ts = ev.ts if self.max_ts is None else max(self.max_ts, ev.ts)
        heapq.heappush(self.heap, (ev.ts, seq, ev))
        wm = self.max_ts - self.slack
        while self.heap and self.heap[0][0] <= wm:
            self._emit(heapq.heappop(self.heap)[2])

    def _emit(self, ev) -> None:
        self.last_ts = ev.ts
        try:
            self.e.process(ev)
        except Exception as ex:   # report it, keep monitoring
            self.stats["errors"] += 1
            self.o.write("errors.log", {"ref": ev.ref, "__error__": f"detect: {ex!r}"})
            print(f"[agent] error processing {ev.ref}: {ex!r}", file=sys.stderr)

    def flush(self) -> None:
        while self.heap:
            self._emit(heapq.heappop(self.heap)[2])


def run(args, *, overrides=None, source=None) -> dict:
    settings = dict(overrides or {})
    if args.mode:
        settings["mode"] = args.mode
    cfg = load_config(args.config, settings)
    allow = load_allowlist(load_structured(args.allowlist) if args.allowlist else None)
    baseline = load_baseline(load_structured(args.baseline) if args.baseline else None)
    labels = load_structured(args.labels) if getattr(args, "labels", None) else None
    sweep = load_structured(args.sweep) if getattr(args, "sweep", None) else None
    if args.learn_baseline:
        cfg["fim"]["learn_baseline"] = True
    out = Path(args.out) if args.out else None
    outputs = Outputs(out, args.quiet)
    engine = Engine(cfg, allow, baseline, outputs.sink)
    pipe = Pipeline(engine, cfg, outputs)

    q: queue.Queue = queue.Queue(maxsize=100000)
    counter = [0]
    if args.listen_tcp:
        reader = (tcp_reader, args.listen_tcp, q, counter)
    elif args.listen_http:
        reader = (http_reader, args.listen_http, q, counter)
    elif args.input and args.input != "-":
        reader = (file_reader, args.input, q, counter, args.follow)
    else:
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        reader = (stream_reader, sys.stdin, q, counter)
    threading.Thread(target=_guarded, args=(reader[0], q, *reader[1:]), daemon=True).start()
    fatal = None
    interrupted = False

    t0 = time.perf_counter()
    idle = float(cfg["idle_flush_s"])
    try:
        while True:
            try:
                item = q.get(timeout=idle)
            except queue.Empty:
                pipe.flush()          # quiet stream: process everything buffered
                continue
            if item is EOF:
                break
            if item[0] == "__fatal__":
                fatal = item[1]
                print(f"[agent] input failed: {fatal}", file=sys.stderr)
                break
            pipe.push(*item)
    except KeyboardInterrupt:
        interrupted = True
        print("[agent] interrupted, flushing", file=sys.stderr)
    pipe.flush()
    elapsed = time.perf_counter() - t0

    summary = {
        "mode": cfg["mode"],
        "events_read": pipe.stats["read"], "events_processed": engine.stats["events"],
        "malformed": pipe.stats["malformed"], "duplicates_dropped": pipe.stats["duplicates"],
        "late_events": pipe.stats["late"], "processing_errors": pipe.stats["errors"],
        "input_error": fatal, "interrupted": interrupted, "ts_missing": engine.stats["ts_missing"],
        "by_category": engine.stats["by_category"],
        "alerts": len(engine.alerts), "blocks": len(engine.blocks),
        "active_blocks": sum(1 for b in engine.blocks if b["status"] == "active"),
        "suppressed_by_allowlist": len(engine.audit), "watch": len(engine.watch),
        "events_after_ip_block": engine.stats["dropped_after_block"],
        "elapsed_s": round(elapsed, 3),
        "events_per_s": round(engine.stats["events"] / elapsed) if elapsed > 0 else None,
    }
    summary.update(source=source or f"Raw event replay · {args.input or 'stdin'}",
                   events=summary["events_processed"], events_per_second=summary["events_per_s"],
                   events_per_minute=dict(sorted(engine.volume.items())))
    case = {"summary": summary, "alerts": list(engine.alerts.values()), "blocks": engine.blocks,
            "incidents": engine.incidents(), "audit": engine.audit, "watch": engine.watch}
    if sweep is not None:
        case["sweep"] = sweep
    report = score_run(case, labels)
    outputs.close()
    if out:
        # Replace the live decision journal with final reverse links and merged evidence.
        write_lines(out / "blocklist.jsonl", case["blocks"])
        (out / "alerts.json").write_text(json.dumps(case["alerts"], indent=2, default=str), encoding="utf-8")
        (out / "incidents.json").write_text(json.dumps(case["incidents"], indent=2), encoding="utf-8")
        (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        (out / "config_used.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        if sweep is not None:
            (out / "sweep.json").write_text(json.dumps(sweep, indent=2), encoding="utf-8")
        publish_report(out, case, report)
    if args.save_baseline:
        target = Path(args.save_baseline)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(engine.rules[3].export_baseline(), indent=2), encoding="utf-8")
    if not args.quiet:
        print(json.dumps(summary, indent=2), file=sys.stderr)
    return {**case, "engine": engine, "report": report}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hids_agent", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--input", "-i", default="-", help="file path, or - for stdin (default)")
    p.add_argument("--follow", action="store_true", help="keep reading a growing file (tail -f)")
    p.add_argument("--listen-tcp", metavar="HOST:PORT")
    p.add_argument("--listen-http", metavar="HOST:PORT")
    p.add_argument("--mode", choices=["detect", "prevent"], help="default: prevent (from config)")
    p.add_argument("--config", help="JSON/YAML overrides of hids_agent/config.py defaults")
    p.add_argument("--baseline", help="hash baseline JSON")
    p.add_argument("--learn-baseline", action="store_true", help="first-seen hash becomes baseline")
    p.add_argument("--save-baseline", metavar="PATH",
                   help="write the baseline (including learned hashes) after the run")
    p.add_argument("--allowlist", help="allow-list JSON/YAML")
    p.add_argument("--labels", help="sequence labels for offline evaluation after detection")
    p.add_argument("--sweep", help="optional tuning sweep JSON for the dashboard")
    p.add_argument("--out", "-o", default="out", help="output directory")
    p.add_argument("--quiet", "-q", action="store_true")
    return p


def main(argv=None) -> int:
    result = run(build_parser().parse_args(argv))
    return 2 if result["report"]["status"] == "INCOMPLETE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
