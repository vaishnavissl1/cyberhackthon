"""Run the Person B handoff from JSONL or replay a scripted demonstration."""

import argparse
import sys
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path

from .contract import lines, read_json
from .handoff import process
from .evaluate import evaluate
from . import agent
from .replay import demo as run_demo
from .outputs import new_folder, save_run


def main():
    if sys.argv[1:2] == ["replay"]:
        raise SystemExit(agent.main(sys.argv[2:]))
    cli = argparse.ArgumentParser(description=__doc__)
    commands = cli.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--out", type=Path, help="new directory; default is a timestamped folder under runs/")
    common.add_argument("--mode", choices=("detect", "prevent"), default="prevent")
    common.add_argument("--cooldown", type=int, default=900, help="alert grouping window in seconds")
    common.add_argument("--never-block", type=Path, help='JSON object with "ips" and/or "users" arrays')
    common.add_argument("--live", action="store_true", help="print candidate receipts while reading")
    commands.add_parser("replay", help="detect on raw events (see replay --help)")
    demo = commands.add_parser("demo", parents=[common], help="run the detector on labeled synthetic raw events")
    demo.add_argument("--split", choices=("dev", "holdout"), default="dev")
    run_cli = commands.add_parser("run", parents=[common], help="consume Person A handoff records")
    run_cli.add_argument("--input", type=Path, help="candidate JSONL; omit for stdin")
    run_cli.add_argument("--labels", type=Path, help="independent sequence labels JSON")
    args = cli.parse_args()
    dest = args.out or Path("runs") / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    try:
        with new_folder(dest) as folder:
            protected = read_json(args.never_block) if args.never_block else None
            if args.command == "demo":
                run = run_demo(folder, args.split, args.mode, cooldown=args.cooldown, live=args.live, never_block=protected)
                report = run["report"]
            else:
                input_path, label_path = args.input, args.labels
                reader = input_path.open(encoding="utf-8-sig") if input_path else nullcontext(sys.stdin)
                with reader as stream:
                    run = process(lines(stream), mode=args.mode, cooldown_s=args.cooldown, live=args.live,
                                  source="Imported candidate handoff", never_block=protected)
                report = evaluate(run["alerts"], run["blocks"], read_json(label_path) if label_path else None)
                save_run(folder, run, report)
        print(f"{report['status']} | {run['summary']['source']} | {len(run['alerts'])} alerts | {dest.absolute()}")
    except (OSError, ValueError, OverflowError) as exc:
        cli.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    main()
