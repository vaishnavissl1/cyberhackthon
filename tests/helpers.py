"""Small helpers to drive the agent in-process from Python dicts."""
from __future__ import annotations

import datetime as dt
import io
import queue

from hids_agent.agent import EOF, Outputs, Pipeline, stream_reader
from hids_agent.allowlist import load_allowlist
from hids_agent.config import load_config
from hids_agent.engine import Engine, load_baseline

T0 = dt.datetime(2026, 11, 20, 8, 0, tzinfo=dt.timezone.utc).timestamp()
_n = [0]


def iso(sec: float) -> str:
    return dt.datetime.fromtimestamp(T0 + sec, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def ev(sec: float, **kw) -> dict:
    """Flat-schema event at T0+sec with a unique id unless id=None is passed."""
    _n[0] += 1
    d = {"id": f"t{_n[0]}", "timestamp": iso(sec), "host": "h1"}
    d.update(kw)
    if d.get("id") is None:
        d.pop("id")
    return d


def auth(sec, outcome, user="alice", ip="203.0.113.9", **kw):
    return ev(sec, type="auth", outcome=outcome, user=user, src_ip=ip, **kw)


def proc(sec, image, pid, ppid, parent=None, cmd=None, **kw):
    d = ev(sec, type="process", action="start", image=image, pid=str(pid), ppid=str(ppid), **kw)
    if parent:
        d["parent_image"] = parent
    if cmd:
        d["cmdline"] = cmd
    return d


def fevt(sec, path, action="modify", sha256=None, **kw):
    d = ev(sec, type="file", action=action, path=path, **kw)
    if sha256:
        d["sha256"] = sha256
    return d


def run(events, cfg=None, allow=None, baseline=None, mode="prevent"):
    c = load_config(None, {"mode": mode, **(cfg or {})})
    eng = Engine(c, load_allowlist(allow), load_baseline(baseline))
    pipe = Pipeline(eng, c, Outputs(None, quiet=True))
    for i, e in enumerate(events, 1):
        pipe.push(i, e)
    pipe.flush()
    return eng, pipe


def run_text(text, **kw):
    """Feed raw text through the real stream reader (JSONL / arrays / bad lines)."""
    q: queue.Queue = queue.Queue()
    stream_reader(io.StringIO(text), q, [0])
    items = []
    while True:
        it = q.get_nowait()
        if it is EOF:
            break
        items.append(it)
    c = load_config(None, {"mode": kw.get("mode", "prevent")})
    eng = Engine(c, load_allowlist(None), load_baseline(None))
    pipe = Pipeline(eng, c, Outputs(None, quiet=True))
    for seq, raw in items:
        pipe.push(seq, raw)
    pipe.flush()
    return eng, pipe


def alerts(eng, rule=None):
    return [a for a in eng.alerts.values() if rule is None or a["rule"] == rule]
