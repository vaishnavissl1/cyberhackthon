"""Measure Person B processing of a finite JSONL handoff dominated by ordinary events."""

import argparse
import json
import tracemalloc
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from .contract import lines
from .handoff import Engine
from .evaluate import evaluate
from .gen_synthetic import dataset


def peak_rss_bytes():
    """Read the OS high-water mark for the current process."""
    import sys
    if sys.platform != "win32":
        from resource import getrusage, RUSAGE_SELF
        rss = getrusage(RUSAGE_SELF).ru_maxrss
        return rss if sys.platform == "darwin" else rss * 1024
    import ctypes
    from ctypes import wintypes

    class MemoryCounters(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
            (key, ctypes.c_size_t) for key in ("peak_working_set", "working_set", "peak_pool_paged",
            "pool_paged", "peak_pool_nonpaged", "pool_nonpaged", "pagefile", "peak_pagefile")]

    process = ctypes.windll.kernel32.GetCurrentProcess
    process.restype = wintypes.HANDLE
    get_counters = ctypes.windll.psapi.GetProcessMemoryInfo
    get_counters.argtypes = (wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD)
    counters = MemoryCounters()
    counters.size = ctypes.sizeof(counters)
    if not get_counters(process(), ctypes.byref(counters), counters.size):
        raise ctypes.WinError()
    return counters.peak_working_set


def raw_benchmark(count):
    """Measure a complete file replay including final report publication."""
    from .gen_synthetic import export
    from .replay import replay_files
    if count < 100:
        raise ValueError("use at least 100 raw events")
    with TemporaryDirectory() as temp:
        folder = Path(temp)
        inputs = folder / "inputs"
        export(inputs, "dev")
        data = dataset("dev")
        origin = max(e["ts"] for e in data["events"]) + 1
        with (inputs / "events.jsonl").open("a", encoding="utf-8") as stream:
            for i in range(count - len(data["events"])):
                stream.write(f'{{"id":"bg-{i}","ts":{origin + i // 200},"host":"desk-03",'
                             '"type":"process","image":"notepad.exe","parent_image":"explorer.exe"}\n')
        start = perf_counter()
        run = replay_files(folder, inputs, "prevent", "Raw detector benchmark")
        elapsed = perf_counter() - start
        report, summary = run["report"], run["summary"]
        if summary["events_processed"] != count or report["status"] != "PASS":
            raise ValueError("raw benchmark accounting or evaluation failed")
        return {"workload": "raw JSONL, detector, simulated response, evaluation and dashboard publication",
                "events": count, "seconds": round(elapsed, 3), "events_per_second": round(count / elapsed),
                "detected": report["detected"], "sequences": report["sequences"],
                "false_alarms": report["false_alarms"], "blocks_on_attacks": len(report["blocks_on_attacks"]),
                "processing_errors": summary["processing_errors"], "peak_rss_bytes": peak_rss_bytes()}


def benchmark(count):
    if count < 100:
        raise ValueError("use at least 100 observations")
    data = dataset()
    extra = [r for r in data["handoff"] if r.get("kind") not in ("source", "event")]
    origin = min(e["ts"] for e in data["events"])
    # Represent an hour of ordinary event receipts with the fixture detections interleaved.
    def stream():
        position = 0
        for i in range(count):
            ts = origin + i * 3600 // count
            yield f'{{"kind":"event","timestamp":{ts}}}\n'
            while position < len(extra) and extra[position]["timestamp"] <= ts:
                yield json.dumps(extra[position]) + "\n"
                position += 1
    engine = Engine()
    checkpoints = {count // 10, count // 2, count}
    samples = {}
    tracemalloc.start()
    start = perf_counter()
    try:
        for _, record in lines(stream()):
            engine.add(record)
            if record.get("kind") == "event" and engine.event_count in checkpoints:
                samples[engine.event_count] = tracemalloc.get_traced_memory()[0]
        run = engine.finish()
        report = evaluate(run["alerts"], run["blocks"], data["labels"])
        elapsed = perf_counter() - start
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    if engine.event_count != count or report["status"] != "PASS":
        raise ValueError("benchmark accounting check failed")
    return {"workload": "JSONL event receipts and scripted candidate handoff; Python allocations traced",
            "events": count, "candidates": len(engine.candidates), "alerts": len(run["alerts"]),
            "elapsed_s": round(elapsed, 3), "events_per_second": round(count/elapsed),
            "peak_traced_bytes": peak, "current_traced_bytes_by_event": samples}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=1_000_000)
    parser.add_argument("--raw", action="store_true", help="run the full raw-event detector")
    args = parser.parse_args()
    print(json.dumps((raw_benchmark if args.raw else benchmark)(args.events), indent=2))
