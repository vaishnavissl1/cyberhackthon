"""Person A supplies confirmed, allow-list-filtered candidates with these fields."""

from __future__ import annotations

import json
import math
from datetime import datetime
from pathlib import Path


BASE = {"bruteforce": 55, "temp_service": 60, "office_shell": 55, "file_integrity": 50}
POINTS = {"critical_file": 25, "privileged": 15, "suspicious_cmdline": 15,
          "external_source": 10, "fast_failures": 10, "high_volume": 5,
          "temp_binary": 10, "recent_drop": 10, "unsigned": 10,
          "indirect_chain": 5, "new_unit": 5, "unverified": -10}
ACTIONS = {
    "bruteforce": {"block_ip", "lock_account"},
    "temp_service": {"disable_service", "quarantine_file", "block_hash"},
    "office_shell": {"terminate_process", "block_hash"},
    "file_integrity": {"deny_file_change", "quarantine_file", "block_hash"},
}


def text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} requires a nonempty string")
    return value.strip()


def strings(value, field):
    if not isinstance(value, list):
        raise ValueError(f"{field} requires an array")
    return list(dict.fromkeys(text(item, field) for item in value))


def stamp(value):
    """UTC epoch seconds or an ISO timestamp with an explicit offset."""
    if isinstance(value, str):
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            raise ValueError("timestamp requires a timezone")
        value = dt.timestamp()
    if type(value) not in (float, int) or not math.isfinite(value):
        raise ValueError("timestamp requires finite epoch seconds or ISO time with offset")
    return float(value)


def object_record(value):
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def evidence_ids(value):
    refs = strings(value, "evidence")
    if not refs:
        raise ValueError("at least one evidence reference is required")
    return [e if e.startswith(("id:", "line:")) else f"id:{e}" for e in refs]


def candidate(record):
    row = object_record(record)
    result = {key: text(row.get(key), key) for key in ("rule", "host", "entity", "title")}
    rule = result["rule"]
    if rule not in BASE:
        raise ValueError(f"unknown rule {rule!r}")
    result["timestamp"] = stamp(row.get("timestamp"))
    result["evidence"] = list(dict.fromkeys(evidence_ids(row.get("evidence"))))
    result["signals"] = strings(row.get("signals", []), "signals")
    if set(result["signals"]) - POINTS.keys():
        raise ValueError("unknown score signal")
    result["context"] = object_record(row.get("context", {}))
    result["mitre"] = strings(row.get("mitre", []), "mitre")
    blocks = row.get("requested_blocks", [])
    if not isinstance(blocks, list):
        raise ValueError("requested_blocks requires an array")
    result["requested_blocks"] = []
    for block in blocks:
        action = text(object_record(block).get("action"), "action")
        if action not in ACTIONS[rule]:
            raise ValueError(f"{action!r} is not a block action for {rule}")
        request = {"action": action, "target": text(block.get("target"), "target")}
        if request not in result["requested_blocks"]:
            result["requested_blocks"].append(request)
    return result


def lines(stream):
    for number, line in enumerate(stream, 1):
        if line.strip():
            try:
                yield number, object_record(json.loads(line.lstrip("\ufeff")))
            except ValueError as exc:
                raise ValueError(f"line {number}: {exc}") from exc


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def write_lines(path, rows):
    with Path(path).open("w", encoding="utf-8") as out:
        for row in rows:
            out.write(json.dumps(row, separators=(",", ":"), allow_nan=False) + "\n")
