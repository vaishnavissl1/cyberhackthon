"""Generate inert development and holdout telemetry and separate sequence labels."""

import argparse
import json
from hashlib import sha256
from pathlib import Path
from random import Random

from .contract import write_json, write_lines


def dataset(split="dev", seed=None):
    if split not in ("dev", "holdout"):
        raise ValueError("split must be dev or holdout")
    holdout = split == "holdout"
    rng = Random((92 if holdout else 31) if seed is None else seed)
    origin = 1795680000 + 86400 * holdout
    desk, server = ("desk-07", "web-02") if holdout else ("desk-03", "web-01")
    ip, user = "192.0.2.19", "riley"
    path = "/etc/example/service.conf"
    hashes = [sha256(v.encode()).hexdigest() for v in ("baseline", "approved revision", "unexpected revision")]
    parent = "EXCEL.EXE" if holdout else "WINWORD.EXE"
    child = "powershell.exe" if holdout else "cmd.exe"
    binary = r"C:\Users\demo\AppData\Local\Temp\helper.exe" if holdout else r"C:\Windows\Temp\helper.exe"
    service = "DemoHelper"
    events, labels, handoff = [], [], []

    def event(name, seconds, host, category, action, **fields):
        row = dict(id=f"{split}-{name}", ts=origin + seconds, host=host, category=category, action=action, **fields)
        events.append(row)
        return row

    def label(rule, variant, group, suffix=""):
        labels.append(dict(attack_id=f"{split}-{rule}{suffix}", type="fim" if rule == "file_integrity" else rule,
                           variant=variant, host=group[0]["host"],
                           start=group[0]["ts"], end=group[-1]["ts"], event_ids=[e["id"] for e in group]))

    def fixture(rule, entity, title, group, signals, action, target, **context):
        last = group[-1]
        techniques = {"bruteforce": ["T1110"], "office_shell": ["T1059"],
                      "temp_service": ["T1543.002" if entity.startswith("/") else "T1543.003"]}
        handoff.append(dict(rule=rule, host=last["host"], entity=entity, timestamp=last["ts"], title=title,
                            evidence=["id:" + e["id"] for e in group], signals=signals, context=context,
                            mitre=techniques.get(rule, []),
                            requested_blocks=[dict(action=action, target=target)]))

    for i in range(48):
        second, machine = rng.randrange(350), rng.choice([desk, server])
        image, launcher = ("notepad.exe", "explorer.exe") if machine == desk else ("/usr/bin/date", "/bin/sh")
        event(f"ordinary-{i}", second, machine, "process", "start", pid=10000+i, image=image, parent_image=launcher)
    for i in range(5):
        event(f"typo-{i}", 2 + i, server, "auth", "logon", outcome="failure" if i < 4 else "success",
              user="sam", src_ip="192.0.2.8")
    for i in range(10):
        event(f"no-success-{i}", 10 + i, desk, "auth", "logon", outcome="failure",
              user="test", src_ip="192.0.2.33")
    auth = []
    for i in range(6):
        source = f"198.51.100.{i % 3 + 1}" if holdout else ip
        auth.append(event(f"auth-{i}", 28 + i * (42 if holdout else 2), server, "auth", "logon",
                          src_ip=source, user=user, outcome="success" if i == 5 else "failure"))
    label("bruteforce", "distributed" if holdout else "same_source", auth)
    fixture("bruteforce", auth[-1]["src_ip"], "Repeated failures followed by a logon", auth, [],
            "block_ip", auth[-1]["src_ip"], user=user, failures=5)
    browser = event("browser", 55, desk, "process", "start", pid=71, image="browser.exe", parent_image=parent)
    office = event("office", 77, desk, "process", "start", pid=80, image=parent, parent_image="explorer.exe")
    shell = event("shell", 79, desk, "process", "start", pid=81, ppid=80, image=child,
                  **({} if holdout else {"parent_image": parent}))
    grandchild = event("grandchild", 81, desk, "process", "start", pid=82, ppid=81, image="pwsh.exe")
    label("office_shell", "pid_parent" if holdout else "direct_parent", [office, shell, grandchild])
    fixture("office_shell", "pid:80", "Office application started a shell", [office, shell], [],
            "terminate_process", "pid:81", process_tree=[parent, child])
    fixture("office_shell", "pid:80", "Office shell started a child shell", [shell, grandchild],
            ["indirect_chain"], "terminate_process", "pid:82", process_tree=[parent, child, "pwsh.exe"])
    event("normal-service", 90, desk, "process", "start", parent_image="services.exe",
          image=r"C:\Program Files\Example\service.exe", pid=93)
    drop = event("drop", 115, desk, "file", "create", path=binary)
    install = event("install", 118, desk, "process", "service_install", image="sc.exe",
                    service_name=service, service_path=binary, cmdline=f'sc.exe create {service} binPath= "{binary}"')
    start = event("start", 120, desk, "process", "start", image=binary, parent_image="services.exe", pid=94)
    label("temp_service", "install_and_start", [drop, install, start])
    fixture("temp_service", binary, "Service installed from a temporary directory", [drop, install],
            ["temp_binary", "recent_drop"], "disable_service", service, service_path=binary)
    event("baseline", 130, server, "file", "modify", path=path, hashes={"sha256": hashes[0]})
    approved = event("approved", 135, server, "file", "modify", path=path, hashes={"sha256": hashes[1]})
    handoff.append(dict(kind="audit", host=server, timestamp=approved["ts"], evidence=[approved["id"]],
                        entry="CHG-101", reason="Approved file revision"))
    change = event("change", 151, server, "file", "delete" if holdout else "modify", path=path,
                   **({} if holdout else {"hashes": {"sha256": hashes[2]}}))
    label("file_integrity", "delete" if holdout else "changed_hash", [change])
    fixture("file_integrity", path, "Baselined configuration changed", [change], [], "deny_file_change", path,
            expected_sha256=hashes[1], observed_sha256=None if holdout else hashes[2])
    policy = {"fim": [{"host": server, "path": path, "hash": hashes[1], "ticket": "CHG-101"}]}
    if holdout:
        spray = [event(f"spray-{i}", 380+i, server, "auth", "logon", outcome="failure" if i < 5 else "success",
                       src_ip="203.0.113.9", user=f"test{i % 5}") for i in range(6)]
        label("bruteforce", "password_spray", spray, "-spray")
        fixture("bruteforce", "203.0.113.9", "Failures across accounts followed by a logon", spray, [],
                "block_ip", "203.0.113.9", distinct_users=5)
        unit = event("unit", 403, server, "file", "create", path="/etc/systemd/system/example.service",
                     service_name="example.service", service_path="/tmp/example-worker")
        worker = event("worker", 406, server, "process", "start", image="/tmp/example-worker",
                       parent_image="/usr/lib/systemd/systemd", pid=288)
        label("temp_service", "systemd_unit_and_start", [unit, worker], "-systemd")
        fixture("temp_service", worker["image"], "New unit starts a temporary executable", [unit, worker],
                ["new_unit", "temp_binary"], "disable_service", "example.service")
        event("reuse-1", 420, desk, "process", "start", pid=180, image="winword.exe", parent_image="explorer.exe")
        event("reuse-2", 430, desk, "process", "start", pid=180, image="notepad.exe", parent_image="explorer.exe")
        event("reuse-child", 431, desk, "process", "start", pid=181, ppid=180, image="cmd.exe")
        patch = event("patch", 440, desk, "process", "service_install", service_name="PatchSvc",
                      service_path=r"C:\Windows\Temp\approved\patch.exe", image="sc.exe")
        policy["services"] = [{"host": desk, "name": patch["service_name"], "path": patch["service_path"]}]
        macro = event("macro", 448, desk, "process", "start", parent_image="excel.exe", image="cmd.exe",
                      cmdline=r"cmd /c C:\Approved\report.bat", pid=188)
        policy["process"] = [{"host": desk, "parent": "excel.exe", "child": "cmd.exe",
                              "cmdline_regex": r"^cmd /c C:\\Approved\\report\.bat$"}]
        for row, entry in [(patch, "Approved patch service"), (macro, "Approved reporting macro")]:
            handoff.append(dict(kind="audit", host=desk, timestamp=row["ts"], entry=entry,
                                reason="Matched scoped change approval", evidence=[row["id"]]))
        slow = [event(f"ssh-{i}", 530 + i * 54, server, "auth", "logon",
                      message=("Failed password" if i < 5 else "Accepted password") +
                              " for operator from 192.0.2.51 port 45678 ssh2") for i in range(6)]
        label("bruteforce", "slow_ssh", slow, "-slow")
        fixture("bruteforce", "192.0.2.51", "Slow burst of SSH failures followed by success", slow, [],
                "block_ip", "192.0.2.51")
        outlook = event("outlook", 850, desk, "process", "start", pid=394, image="OUTLOOK.EXE",
                        parent_image="explorer.exe")
        script = event("script-child", 853, desk, "process", "start", pid=395, ppid=394,
                       image="wscript.exe", parent_image="OUTLOOK.EXE")
        label("office_shell", "outlook_script_host", [outlook, script], "-outlook")
        fixture("office_shell", "pid:394", "Outlook starts a script host", [outlook, script], [],
                "terminate_process", "pid:395", process_tree=["OUTLOOK.EXE", "wscript.exe"])
        event("tmp-note", 865, server, "file", "create", path="/tmp/notes.txt")
        event("rewrite", 870, server, "file", "modify", path="/etc/example/unchanged.conf",
              hashes={"sha256": hashes[0]})
    events.sort(key=lambda r: r["ts"])
    if holdout:
        # Duplicate a benign observation and deliver two observations out of order.
        events.append(dict(browser))
        events[4], events[5] = events[5], events[4]
    handoff.extend(dict(kind="event", timestamp=e["ts"]) for e in events)
    handoff.sort(key=lambda r: r["timestamp"])
    handoff.insert(0, {"kind": "source", "name": f"Synthetic {split} · scripted predictions"})
    return dict(events=events, labels=labels, handoff=handoff,
                baseline={"hosts": {server: {path: {"sha256": hashes[0]},
                                              "/etc/example/unchanged.conf": {"sha256": hashes[0]}}}},
                allowlist=policy)


def stress_input(folder, events):
    """Exercise the normalizer with stable event IDs, aliases, and one malformed line."""
    with (folder / "events-mixed.jsonl").open("w", encoding="utf-8-sig") as stream:
        for i, event in enumerate(events):
            row = dict(event)
            if i % 3 == 1:
                row["Computer"] = row.pop("host")
                row["TimeCreated"] = row.pop("ts") * 1000
                category = row.pop("category")
                if category == "process" and row.get("action") == "start":
                    row.update(Provider="Microsoft-Windows-Sysmon", EventID=1)
                elif category == "auth" and "outcome" in row:
                    row["EventID"] = 4624 if row.pop("outcome") == "success" else 4625
                elif category == "process" and row.get("action") == "service_install":
                    row["EventID"] = 4697
                else:
                    row["type"] = category
                for original, alternate in (("pid", "ProcessId"), ("ppid", "ParentProcessId"),
                                            ("parent_image", "ParentImage"), ("src_ip", "IpAddress"),
                                            ("user", "TargetUserName"), ("service_path", "ServiceFileName")):
                    if original in row:
                        row[alternate] = row.pop(original)
            if i % 3 == 2:
                row["host"] = {"name": row["host"]}
                row["@timestamp"] = row.pop("ts")
                row["event"] = {"category": [row.pop("category")], "action": row.pop("action")}
                if "src_ip" in row:
                    row["source"] = {"ip": row.pop("src_ip")}
            stream.write(json.dumps(row) + "\n")
            if i == 0:
                stream.write("{incomplete record\n")
                stream.write(json.dumps(row) + "\n")


def export(folder, split, seed=None, *, mixed=False):
    data = dataset(split, seed)
    folder.mkdir(parents=True, exist_ok=False)
    for key in ("events", "handoff"):
        write_lines(folder / f"{key}.jsonl", data[key])
    for key in ("labels", "baseline", "allowlist"):
        write_json(folder / f"{key}.json", data[key])
    if mixed:
        stress_input(folder, data["events"])


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--out", type=Path, required=True, help="new directory")
    cli.add_argument("--split", choices=("dev", "holdout"), default="dev")
    cli.add_argument("--seed", type=int)
    cli.add_argument("--mixed", action="store_true", help="also write an alias/duplicate/malformed raw stream")
    args = cli.parse_args()
    try:
        export(args.out, args.split, args.seed, mixed=args.mixed)
    except (OSError, ValueError) as exc:
        cli.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    main()
