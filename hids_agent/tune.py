"""Compare grouping cooldowns across saved detector trials using development labels."""

import argparse
import json
from itertools import product
from pathlib import Path

from .handoff import process
from .contract import lines, object_record, read_json
from .evaluate import score_run
from . import agent
from .config import SEV_ORDER
from .contract import write_json


def search(grid, replay, labels):
    """replay(config) must rerun the detector and return a Person B run for that config."""
    if not grid or any(not isinstance(v, list) or not v for v in grid.values()):
        raise ValueError("supply at least one value for each grid parameter")
    trials = []
    for values in product(*grid.values()):
        config = dict(zip(grid, values))
        run = replay(config)
        report = score_run(run, labels)
        if report["recall"] is None:
            raise ValueError("tuning requires labeled attack sequences")
        trials.append(dict(config=config, status=report["status"], recall=report["recall"],
                           false_alarms=report["false_alarms"], precision=report["precision"]))
    # Prefer meeting the whole target, then recall, then fewer false alarms.
    # Grid order breaks ties, allowing the caller to put the preferred setting first.
    best = max(trials, key=lambda t: (t["status"] == "PASS", t["recall"], -t["false_alarms"]))
    return {"best": best, "trials": trials}


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--labels", required=True, type=Path)
    source = cli.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path, help="one development candidate handoff")
    source.add_argument("--events", type=Path, help="development raw events; reruns the full detector")
    cli.add_argument("--baseline", type=Path)
    cli.add_argument("--allowlist", type=Path)
    cli.add_argument("--config", type=Path)
    cli.add_argument("--failures", nargs="+", type=int, default=[5], help="raw detector failure-count grid")
    cli.add_argument("--windows", nargs="+", type=int, default=[300])
    cli.add_argument("--success-delays", nargs="+", type=int, default=[600])
    cli.add_argument("--spray-users", nargs="+", type=int, default=[5])
    cli.add_argument("--min-severities", nargs="+", choices=SEV_ORDER, default=["medium"])
    cli.add_argument("--config-out", type=Path, help="write the selected raw detector config")
    cli.add_argument("--report-out", type=Path, help="write the parameter sweep JSON")
    source.add_argument("--trials", type=Path, help="JSON list of {input, parameters} detector trials")
    cli.add_argument("--cooldowns", nargs="+", type=int, default=[900, 300, 60])
    args = cli.parse_args()
    try:
        labels = read_json(args.labels)
        if args.events:
            if min(*args.failures, *args.windows, *args.success_delays, *args.spray_users) < 1 or min(args.cooldowns) < 0:
                raise ValueError("thresholds and windows must be positive and cooldowns nonnegative")
            raw = agent.build_parser().parse_args([])
            raw.input, raw.out, raw.quiet = str(args.events), None, True
            raw.baseline, raw.allowlist, raw.config = args.baseline, args.allowlist, args.config

            def overrides(config):
                return {"cooldown_s": config["cooldown_s"], "alert_min_severity": config["alert_min_severity"],
                        "bruteforce": {k: config[k] for k in ("n_fail", "window_s", "success_within_s", "spray_users")}}

            def raw_trial(config):
                return agent.run(raw, overrides=overrides(config))

            grid = {"n_fail": sorted(set(args.failures)), "window_s": sorted(set(args.windows), reverse=True),
                    "success_within_s": sorted(set(args.success_delays), reverse=True),
                    "spray_users": sorted(set(args.spray_users)), "cooldown_s": sorted(set(args.cooldowns)),
                    "alert_min_severity": sorted(set(args.min_severities), key=SEV_ORDER.index)}
            results = search(grid, raw_trial, labels)
            kept = [t for t in results["trials"] if t["recall"] == 1.0]
            results["best"] = min(kept, key=lambda t: t["false_alarms"], default=None)
            if args.report_out:
                write_json(args.report_out, results)
            print(json.dumps(results, indent=2))
            if not results["best"]:
                cli.exit(1, "No setting achieved full sequence recall.\n")
            if args.config_out:
                from .config import load_config
                write_json(args.config_out, load_config(args.config, overrides(results["best"]["config"])))
            return
        entries = read_json(args.trials) if args.trials else [{"input": str(args.input.absolute()), "parameters": {}}]
        if not isinstance(entries, list) or not entries:
            raise ValueError("trials requires a nonempty array")
        root = args.trials.parent if args.trials else Path.cwd()
        def replay(config):
            entry = entries[config["trial"]]
            with (root / entry["input"]).open(encoding="utf-8-sig") as stream:
                return process(lines(stream), mode="prevent", source="development trial", cooldown_s=config["cooldown_s"])
        results = search({"trial": list(range(len(entries))), "cooldown_s": args.cooldowns}, replay, labels)
        for trial in results["trials"]:
            index = trial["config"]["trial"]
            trial["detector_parameters"] = object_record(entries[index]["parameters"])
        print(json.dumps(results, indent=2))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        cli.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    main()
