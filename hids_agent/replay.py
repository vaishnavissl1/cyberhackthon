"""Use the detector CLI pipeline for dashboard uploads and generated demos."""

from .agent import build_parser, run
from .contract import write_json
from .gen_synthetic import export


def replay_files(folder, inputs, mode, source, *, cooldown=900, live=False):
    args = build_parser().parse_args([])
    args.input, args.out, args.mode, args.quiet = str(inputs / "events.jsonl"), str(folder), mode, not live
    for field in ("labels", "baseline", "allowlist"):
        path = inputs / f"{field}.json"
        setattr(args, field, str(path) if path.is_file() else None)
    result = run(args, overrides={"cooldown_s": cooldown}, source=source)
    if result["report"]["status"] == "INCOMPLETE":
        raise ValueError(result["summary"]["input_error"] or "raw replay interrupted or processing failed")
    return result


def demo(folder, split, mode="prevent", *, cooldown=900, live=False, never_block=None):
    from .contract import read_json
    inputs = folder / "inputs"
    export(inputs, split)
    if never_block is not None:
        policy = read_json(inputs / "allowlist.json")
        write_json(inputs / "allowlist.json", {**policy, "never_block": never_block})
    return replay_files(folder, inputs, mode, f"Synthetic {split} · raw events",
                        cooldown=cooldown, live=live)
