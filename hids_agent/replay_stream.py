"""Replay a JSONL event file to stdout, the way a provided replay script would.

    python -m hids_agent.replay_stream data/hidden/events.jsonl --speed 600 | python -m hids_agent.agent --out runs/live

Lines are written unchanged (including any malformed ones) and flushed one by one.
--speed N plays N seconds of event time per real second; 0 (default) sends as fast
as possible. Gaps are capped by --max-gap so a quiet hour does not stall a demo.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from .normalize import ALIASES, flatten, parse_ts


def event_time(line: str):
    try:
        flat = flatten(json.loads(line))
    except (json.JSONDecodeError, AttributeError, TypeError):
        return None
    for key in ALIASES["ts"]:
        if key in flat:
            return parse_ts(flat[key])
    return None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input")
    p.add_argument("--speed", type=float, default=0.0, help="event seconds per real second; 0 = no delay")
    p.add_argument("--max-gap", type=float, default=2.0, help="longest real pause between lines, seconds")
    a = p.parse_args(argv)
    out = sys.stdout
    last = None
    try:
        with open(a.input, encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                if a.speed > 0:
                    t = event_time(line)
                    if t is not None:
                        if last is not None and t > last:
                            time.sleep(min((t - last) / a.speed, a.max_gap))
                        last = t if last is None else max(last, t)
                out.write(line if line.endswith("\n") else line + "\n")
                out.flush()
    except BrokenPipeError:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
