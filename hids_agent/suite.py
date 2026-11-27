"""Reproduce the headline result in one command.

    python -m hids_agent.suite --hidden 30 --out runs/suite

1. Build the development stream (seed 1) and tune on it only.
2. Build N hidden streams (seeds 101 onward), never used for tuning.
3. Replay each hidden stream into the agent with the frozen config and score it.
4. Write summary.json and print totals: PASS count, attacks found, false alarms,
   blocks, and detection latency.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

PY = sys.executable


def sh(*args, **kw):
    return subprocess.run([PY, "-m", *args], capture_output=True, text=True, **kw)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--hidden", type=int, default=30, help="number of hidden streams")
    p.add_argument("--out", default="runs/suite")
    a = p.parse_args(argv)
    root = Path(a.out)
    root.mkdir(parents=True, exist_ok=True)
    dev = root / "dev-1"
    sh("hids_agent.build_dataset", "--split", "dev", "--seed", "1", "--out", str(dev), check=True)
    t = sh("hids_agent.tune", "--events", str(dev / "events.jsonl"), "--labels", str(dev / "labels.json"),
           "--baseline", str(dev / "baseline.json"), "--allowlist", str(dev / "allowlist.json"),
           "--failures", "4", "5", "6", "8", "--windows", "120", "300", "600", "--success-delays", "300", "600",
           "--spray-users", "4", "5", "6", "--cooldowns", "900", "--min-severities", "medium", "high",
           "--config-out", str(root / "frozen.json"), "--report-out", str(root / "sweep.json"))
    if t.returncode != 0:
        print(t.stderr[-2000:], file=sys.stderr)
        return 1
    chosen = json.loads((root / "frozen.json").read_text())
    rows, lat = [], []
    for seed in range(101, 101 + a.hidden):
        d = root / f"hidden-{seed}"
        sh("hids_agent.build_dataset", "--split", "hidden", "--seed", str(seed), "--out", str(d), check=True)
        replay = subprocess.Popen([PY, "-m", "hids_agent.replay_stream", str(d / "events.jsonl")],
                                  stdout=subprocess.PIPE)
        subprocess.run([PY, "-m", "hids_agent.agent", "--config", str(root / "frozen.json"),
                        "--baseline", str(d / "baseline.json"), "--allowlist", str(d / "allowlist.json"),
                        "--labels", str(d / "labels.json"), "--sweep", str(root / "sweep.json"),
                        "--out", str(d / "out"), "-q"], stdin=replay.stdout, capture_output=True)
        replay.wait()
        r = json.loads((d / "out" / "report.json").read_text())
        lat += [max(v, 0) for v in r.get("latency_s", {}).values()]
        rows.append({"seed": seed, "status": r["status"], "found": r["detected"], "attacks": r["sequences"],
                     "false_alarms": r["false_alarms"], "blocks_on_attacks": len(r.get("blocks_on_attacks", [])),
                     "missed": r.get("missed", [])})
        print(f"hidden {seed}: {r['status']} {r['detected']}/{r['sequences']} FA {r['false_alarms']}", flush=True)
    lat.sort()
    summary = {
        "tuned_on": "dev seed 1 only",
        "chosen": {**{k: chosen["bruteforce"][k] for k in ("n_fail", "window_s", "success_within_s", "spray_users")},
                   "cooldown_s": chosen["cooldown_s"], "alert_min_severity": chosen["alert_min_severity"]},
        "hidden_streams": len(rows),
        "pass": sum(r["status"] == "PASS" for r in rows),
        "attacks_found": sum(r["found"] for r in rows), "attacks": sum(r["attacks"] for r in rows),
        "false_alarms": sum(r["false_alarms"] for r in rows),
        "max_false_alarms_in_a_stream": max((r["false_alarms"] for r in rows), default=0),
        "streams_with_a_block": sum(1 for r in rows if r["blocks_on_attacks"]),
        "latency_s": {"median": round(lat[len(lat) // 2], 1), "p95": round(lat[int(len(lat) * .95)], 1),
                      "max": round(lat[-1], 1)} if lat else None,
        "streams": rows,
    }
    (root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "streams"}, indent=2))
    return 0 if summary["pass"] == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
