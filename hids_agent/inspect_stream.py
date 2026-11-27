"""Check how well the agent understands a stream before trusting its results.

    python -m hids_agent.inspect_stream dev_stream.jsonl
    python provided_replay.py | python -m hids_agent.inspect_stream - --config schema.json

Reports how events were classified, which raw fields the agent does not read,
which required fields are missing per category, and which raw event types ended
up unclassified. Fix gaps with the "schema" section of a --config file.
"""
from __future__ import annotations

import argparse
import io
import json
import queue
import sys
from collections import Counter, defaultdict

from .agent import EOF, stream_reader
from .config import load_config
from .normalize import ALIASES, LABEL_FIELDS, configure, flatten, normalize

NEEDED = {
    "auth": ("user", "outcome"),
    "process": ("image", "pid", "ppid"),
    "file": ("path", "hashes"),
    "service": ("service_path",),
}
USEFUL = {
    "auth": ("src_ip",),
    "process": ("parent_image", "cmdline"),
    "file": ("action",),
    "service": ("service_name",),
}
TYPE_KEYS = ("category", "event_type", "eventtype", "type", "event.category", "event.type", "kind",
             "action", "event.action", "eventid", "event_id", "event.code")


def inspect(items, schema: dict | None = None) -> dict:
    configure(schema)
    known = {name for names in ALIASES.items() for name in names[1]}
    known |= {f.lower() for f in (schema or {}).get("field_aliases", {}).get("_", [])}
    extra = {n.lower() for v in ((schema or {}).get("field_aliases") or {}).values() for n in v}
    known |= extra | LABEL_FIELDS | {"provider", "channel", "approved_by", "approver", "expires",
                                     "ticket", "md5", "sha1", "sha256", "new_path"}
    total = bad = 0
    cats: Counter = Counter()
    unread: Counter = Counter()
    other_types: Counter = Counter()
    missing: dict[str, Counter] = defaultdict(Counter)
    weak: dict[str, Counter] = defaultdict(Counter)
    samples: list = []
    hosts: Counter = Counter()
    with_ids = 0
    for seq, raw in items:
        total += 1
        if "__error__" in raw:
            bad += 1
            continue
        ev = normalize(raw, seq)
        cats[ev.category] += 1
        hosts[ev.host] += 1
        with_ids += ev.has_explicit_id
        flat = flatten(raw)
        for k, v in flat.items():
            leaf = k.rsplit(".", 1)[-1]
            if not isinstance(v, dict) and k not in known and leaf not in known:
                unread[k] += 1
        if ev.category == "other":
            sig = tuple(f"{k}={flat[k]}" for k in TYPE_KEYS if k in flat and not isinstance(flat[k], (dict, list)))
            if not sig:   # unknown type field: show short raw values so it can be mapped
                sig = tuple(f"{k}={v}" for k, v in raw.items()
                            if k.lower() not in ALIASES["id"] + ALIASES["ts"] + ALIASES["host"]
                            and isinstance(v, (str, int)) and len(str(v)) <= 30)[:4]
            other_types[" ".join(sig) or "(no fields)"] += 1
            if len(samples) < 5:
                samples.append(raw)
            continue
        for f in NEEDED.get(ev.category, ()):
            if not getattr(ev, f):
                missing[ev.category][f] += 1
        for f in USEFUL.get(ev.category, ()):
            if not getattr(ev, f):
                weak[ev.category][f] += 1
    good = total - bad
    return {
        "events": total, "malformed": bad, "with_ids": with_ids, "hosts": len(hosts),
        "by_category": dict(cats.most_common()),
        "unclassified_share": round(cats.get("other", 0) / good, 4) if good else None,
        "unclassified_types": dict(other_types.most_common(15)),
        "unread_fields": dict(unread.most_common(25)),
        "missing_required": {c: dict(v) for c, v in missing.items()},
        "missing_useful": {c: dict(v) for c, v in weak.items()},
        "unclassified_samples": samples,
    }


def to_text(r: dict) -> str:
    out = [f"events {r['events']} | malformed {r['malformed']} | with ids {r['with_ids']} | hosts {r['hosts']}",
           "classified as: " + ", ".join(f"{k} {v}" for k, v in r["by_category"].items())]
    problems = 0
    if r["unclassified_share"]:
        problems += 1
        out.append(f"\nUNCLASSIFIED {r['unclassified_share']:.1%} of events. Raw types seen:")
        out += [f"  {n:>7}  {t}" for t, n in r["unclassified_types"].items()]
        out.append('  Fix: map them in config {"schema": {"category_map": {"<type>": "auth|process|file|service"}}}')
    for kind, label in (("missing_required", "MISSING REQUIRED"), ("missing_useful", "missing (optional)")):
        for cat, fields in r[kind].items():
            problems += kind == "missing_required"
            out.append(f"\n{label} in {cat} events: " + ", ".join(f"{f} ({n})" for f, n in fields.items()))
    if r["missing_required"]:
        out.append('  Fix: name the field in config {"schema": {"field_aliases": {"<field>": ["<raw name>"]}}}')
    if r["unread_fields"]:
        out.append("\nRaw fields the agent does not read (check none of them hold the data above):")
        out += [f"  {n:>7}  {k}" for k, n in r["unread_fields"].items()]
    out.append("\nRESULT: " + ("OK, every event was classified with its required fields" if not problems
                                else f"{problems} problem(s) to fix before trusting detection results"))
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", help="stream file, or - for stdin")
    p.add_argument("--config", help="config with a schema section to test")
    p.add_argument("--json", help="also write the full report as JSON here")
    a = p.parse_args(argv)
    cfg = load_config(a.config)
    q: queue.Queue = queue.Queue()
    if a.input == "-":
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        stream_reader(sys.stdin, q, [0])
    else:
        with open(a.input, encoding="utf-8-sig", errors="replace") as f:
            stream_reader(f, q, [0])
    items = []
    while (item := q.get()) is not EOF:
        items.append(item)
    r = inspect(items, cfg.get("schema"))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=2, default=str)
    out = to_text(r)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stdout.write(out)
    return 0 if "RESULT: OK" in out else 1


if __name__ == "__main__":
    raise SystemExit(main())
