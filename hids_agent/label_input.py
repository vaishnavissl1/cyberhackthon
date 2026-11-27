"""Load organizer label files and embedded event annotations."""

from pathlib import Path

from .normalize import flatten, normalize

BENIGN = {"", "0", "false", "none", "benign", "normal", "no", "null"}
TYPE_TO_RULE = {
    "bruteforce": "bruteforce", "brute_force": "bruteforce", "brute-force": "bruteforce",
    "password_spray": "bruteforce", "spray": "bruteforce", "credential_access": "bruteforce",
    "temp_service": "temp_service", "service": "temp_service", "persistence": "temp_service",
    "new_service": "temp_service",
    "office_shell": "office_shell", "office": "office_shell", "macro": "office_shell",
    "phishing": "office_shell",
    "fim": "file_integrity", "file_integrity": "file_integrity", "tamper": "file_integrity", "file_tamper": "file_integrity",
}


def labels_from_stream(path) -> list[dict]:
    # Use the detector's input framing so line:<n> refers to the same record in both phases.
    from .agent import EOF, stream_reader
    groups = {}

    class Collect:
        def put(self, item):
            if item is EOF:
                return
            n, raw = item
            flat = flatten(raw)
            key = next((flat[k] for k in ("attack_id", "sequence_id", "label", "attack", "ground_truth",
                                          "is_attack", "attack_type")
                        if k in flat and str(flat[k]).strip().lower() not in BENIGN), None)
            if key is None:
                return
            if isinstance(key, bool) or str(key).lower() in ("true", "yes"):
                raise ValueError("boolean attack annotations require a sequence ID")
            key = str(key)
            ev = normalize(raw, n)
            rule = str(flat.get("attack_type") or "").lower()
            group = groups.setdefault(key, {"attack_id": key, "host": ev.host, "type": rule,
                                            "start": None, "end": None, "event_ids": []})
            if ev.host != group["host"] or (rule and group["type"] and group["type"] != rule):
                raise ValueError(f"inconsistent host or attack type for sequence {key}")
            group["type"] = group["type"] or rule
            group["event_ids"].append(ev.ref)
            if ev.ts is not None:
                group["start"] = ev.ts if group["start"] is None else min(group["start"], ev.ts)
                group["end"] = ev.ts if group["end"] is None else max(group["end"], ev.ts)

    with Path(path).open(encoding="utf-8-sig") as reader:
        stream_reader(reader, Collect(), [0])
    return list(groups.values())
