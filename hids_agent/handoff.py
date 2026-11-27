"""Deterministic response to confirmed detections. All response actions are data."""

import json
from collections import Counter
from time import perf_counter
from ipaddress import ip_address

from .allowlist import AllowList
from .config import load_config
from .engine import Engine as DetectionEngine
from .rules import Candidate

from .contract import BASE, POINTS, candidate, evidence_ids, object_record, stamp, strings, text


class Engine:
    """Feed records with add(). finish() returns final, event-time ordered records."""

    def __init__(self, mode="prevent", cooldown_s=900, never_block=None):
        if mode not in ("detect", "prevent") or type(cooldown_s) is not int or cooldown_s < 0:
            raise ValueError("expected detect/prevent mode and a nonnegative integer cooldown")
        policy = object_record({} if never_block is None else never_block)
        if policy.keys() - {"ips", "users", "paths"}:
            raise ValueError("never_block supports ips, users and paths")
        self.allow = AllowList({"never_block": {k: strings(v, k) for k, v in policy.items()}})
        self.mode = mode
        self.cooldown_s = cooldown_s
        self.candidates = []
        self.audit = []
        self.watch = []
        self.event_count = 0
        self.volume = Counter()

    def add(self, record):
        row = object_record(record)
        kind = row.get("kind", "candidate")
        if kind == "event":
            minute = int(stamp(row.get("timestamp")) // 60)
            self.volume[minute] += 1
            self.event_count += 1
        elif kind in ("audit", "watch"):
            note = {k: text(row.get(k), k) for k in ("host", "reason")}
            note.update(timestamp=stamp(row.get("timestamp")), evidence=evidence_ids(row.get("evidence")))
            if kind == "audit":
                note["entry"] = text(row.get("entry"), "entry")
            (self.audit if kind == "audit" else self.watch).append(note)
        elif kind == "candidate":
            item = candidate(row)
            for request in item["requested_blocks"]:
                if request["action"] == "block_ip":
                    request["target"] = str(ip_address(request["target"]))
            if item["rule"] == "file_integrity" and "unverified" in item["signals"]:
                self.watch.append({**item, "reason": "No comparable file hash"})
            else:
                self.candidates.append(item)
        else:
            raise ValueError(f"unknown handoff kind {kind!r}")

    def finish(self):
        cfg = load_config(None, {"mode": self.mode, "cooldown_s": self.cooldown_s,
                                "scoring": {"base": BASE}, "response": {"block_rules": list(BASE)}})
        engine = DetectionEngine(cfg, self.allow, {"*": {}})
        for item in sorted(self.candidates, key=lambda x: x["timestamp"]):
            engine.accept(Candidate(
                rule=item["rule"], host=item["host"], entity=item["entity"], ts=item["timestamp"],
                title=item["title"], mitre=item["mitre"], evidence=item["evidence"], context=item["context"],
                signals=[(name, POINTS[name]) for name in item["signals"]],
                blocks=[(b["action"], b["target"]) for b in item["requested_blocks"]]))
        return {"alerts": list(engine.alerts.values()), "blocks": engine.blocks, "incidents": engine.incidents(),
                "audit": self.audit, "watch": self.watch, "summary": {"mode": self.mode,
                "source": "Imported candidate handoff", "events": self.event_count, "candidates": len(self.candidates),
                "alerts": len(engine.alerts), "block_decisions": len(engine.blocks),
                "events_per_minute": dict(sorted(self.volume.items()))}}


def process(records, *, mode, source, cooldown_s=900, never_block=None, live=False):
    engine = Engine(mode, cooldown_s, never_block)
    started = perf_counter()
    first_record = True
    for number, record in records:
        try:
            is_header = first_record and record.get("kind") == "source"
            first_record = False
            if is_header:
                source = text(record.get("name"), "source name")
                continue
            engine.add(record)
            if live and record.get("kind", "candidate") == "candidate":
                print(json.dumps({"received": record["rule"], "host": record["host"],
                                  "evidence": record["evidence"]}), flush=True)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"handoff line {number}: {exc}") from exc
    run = engine.finish()
    elapsed = perf_counter() - started
    run["summary"].update(source=source, cooldown_s=cooldown_s, processing_seconds=elapsed,
                          events_per_second=engine.event_count / elapsed if elapsed and engine.event_count else None)
    return run
