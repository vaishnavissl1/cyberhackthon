"""Detection rules. Each rule consumes normalized Events and returns Candidates.

A Candidate is a confirmed detection; the engine scores it, de-duplicates it into
an alert and applies the response (block) policy.
"""
from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field

from .allowlist import AllowList
from .normalize import Event, base, exe_from_cmd, is_private_ip, parse_ts, path_tokens

_SUSP_CMD = re.compile(
    r"(-enc(odedcommand)?\b|-e\s+[a-z0-9+/=]{20,}|frombase64string|downloadstring|downloadfile|"
    r"invoke-webrequest|\biwr\b|\biex\b|invoke-expression|bitsadmin\s+/transfer|certutil\s+-urlcache|"
    r"https?://|-w(indowstyle)?\s+hidden|-nop\b|curl\s|wget\s|/dev/tcp/|nc\s+-e|bash\s+-i)",
    re.I,
)


@dataclass
class Candidate:
    rule: str
    host: str
    entity: str
    ts: float
    title: str
    mitre: list[str]
    evidence: list[str]
    signals: list[tuple[str, int]] = field(default_factory=list)
    context: dict = field(default_factory=dict)
    blocks: list[tuple[str, str]] = field(default_factory=list)
    user: str | None = None
    src_ip: str | None = None
    base_override: int | None = None
    escalates: bool = False   # replaces the title/context of the alert it merges into


@dataclass
class Watch:
    rule: str
    host: str
    ts: float
    note: str
    evidence: list[str]
    context: dict = field(default_factory=dict)


@dataclass
class PreBlock:
    action: str
    target: str
    reason: str
    ts: float
    host: str
    evidence: list[str]


@dataclass
class Suppressed:
    rule: str
    host: str
    ts: float
    reason: str
    allow_entry: dict
    evidence: list[str]
    context: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# approval events carried in the stream (optional, off by default)
# ---------------------------------------------------------------------------
class Approvals:
    name = "approval"

    def __init__(self, cfg: dict, allow: AllowList):
        c = cfg["approvals"]
        self.enabled = bool(c["from_stream"])
        self.trusted = {str(x).strip().lower() for x in c["trusted_approvers"]}
        self.ttl = float(c["default_ttl_s"])
        self.max_ttl = float(c["max_ttl_s"])
        self.allow = allow

    @staticmethod
    def _entry(ev: Event) -> tuple[str, dict] | None:
        """The narrowest allow-list entry the event describes, or None if too broad."""
        wild = lambda s: any(ch in s for ch in "*?[")
        if ev.service_path:
            return None if wild(ev.service_path) else \
                ("services", {"name": ev.service_name, "path": ev.service_path})
        if ev.parent_image:
            if not (ev.image and ev.cmdline):
                return None
            return "process", {"parent": ev.parent_image, "child": ev.image,
                               "cmdline_regex": re.escape(ev.cmdline.strip())}
        if ev.path:
            digest = ev.hashes.get("sha256") or next(iter(ev.hashes.values()), None)
            if not digest or wild(ev.path):
                return None
            return "fim", {"path": ev.path, "hash": digest}
        if ev.src_ip:
            try:
                ipaddress.ip_address(ev.src_ip)      # a single address, not a network
            except ValueError:
                return None
            return "auth", {"src_ip": ev.src_ip}
        return None

    def on_event(self, ev: Event) -> list:
        if ev.category != "approval":
            return []
        info = ev.approval or {}
        who = str(info.get("approver") or "").strip().lower()

        def note(text: str) -> list:
            return [Watch(self.name, ev.host, ev.ts, text, [ev.ref],
                          {"approver": who or None, "ticket": info.get("ticket")})]

        if not self.enabled:
            return note("approval event ignored: approvals.from_stream is off")
        if not ("*" in self.trusted or (who and who in self.trusted)):
            return note("approval rejected: approver is not trusted")
        made = self._entry(ev)
        if made is None:
            return note("approval rejected: too broad or missing fields")
        kind, entry = made
        expires = parse_ts(info.get("expires"))
        expires = ev.ts + self.ttl if expires is None else min(expires, ev.ts + self.max_ttl)
        entry.update(expires=expires, ticket=info.get("ticket"), approved_by=who or None,
                     source=ev.ref)
        if ev.host != "unknown":
            entry["host"] = ev.host
        if not self.allow.add(kind, entry, starts=ev.ts):
            return note("approval rejected: too broad or missing fields")
        return note(f"approval accepted: {kind}")


# ---------------------------------------------------------------------------
# R1 brute force -> success
# ---------------------------------------------------------------------------
class BruteForce:
    name = "bruteforce"
    MAX_KEEP = 2000

    def __init__(self, cfg: dict, allow: AllowList, prevent: bool):
        c = cfg["bruteforce"]
        self.n = int(c["n_fail"])
        self.w = float(c["window_s"])
        self.after = float(c["success_within_s"])
        self.spray = int(c["spray_users"])
        self.dist = int(c["dist_sources"])
        self.skip_machine = bool(c["skip_machine_accounts"])
        self.preempt = int(c["preempt_block_factor"]) * self.n if c.get("preempt_block_factor") else 0
        self.allow = allow
        self.prevent = prevent
        self.pair: dict[tuple, deque] = defaultdict(deque)   # (host, ip, user) -> (ts, ref)
        self.by_src: dict[tuple, deque] = defaultdict(deque)  # (host, ip) -> (ts, ref, user)
        self.by_user: dict[tuple, deque] = defaultdict(deque)  # (host, user) -> (ts, ref, ip)
        self.preblocked: set[str] = set()
        self.watched: set[tuple] = set()
        self.fail_only = bool(c["alert_without_success"])
        self.fail_n = int(c["failures_without_success"])
        self.failed: dict[tuple, dict] = {}      # (host, source) -> failed-only alert state
        self.src_users: dict[tuple, dict] = {}   # (host, source) -> {user: last failure ts}

    def _trim(self, dq: deque, now: float) -> None:
        horizon = self.w + self.after
        while dq and now - dq[0][0] > horizon:
            dq.popleft()
        while len(dq) > self.MAX_KEEP:
            dq.popleft()

    @staticmethod
    def _add(dq: deque, item: tuple) -> None:
        """Append keeping time order even when an event arrives late."""
        i = len(dq)
        while i and dq[i - 1][0] > item[0]:
            i -= 1
        if i == len(dq):
            dq.append(item)
        else:
            dq.insert(i, item)

    def sweep(self, now: float) -> None:
        horizon = self.w + self.after
        for d in (self.pair, self.by_src, self.by_user):
            dead = [k for k, dq in d.items() if not dq or now - dq[-1][0] > horizon]
            for k in dead:
                del d[k]
        self.watched &= set(self.pair)
        for k in [k for k, st in self.failed.items() if now - st["last"] > horizon]:
            del self.failed[k]
            self.src_users.pop(k, None)

    def _burst(self, dq: deque, now: float) -> list:
        """Failures inside the window ending at the last failure, provided the last
        failure is recent enough relative to `now` (the success)."""
        before = [x for x in dq if x[0] <= now + 1]
        if not before:
            return []
        last = before[-1][0]
        if now - last > self.after:
            return []
        return [x for x in before if last - x[0] <= self.w]

    def _failed_only(self, ev: Event, pair_key: tuple, allowed: dict | None):
        """Alert on failures alone: once per source at the threshold, then a
        continuation every n_fail failures so a long flood stays one alert."""
        host, ts = ev.host, ev.ts
        key = (host, ev.src_ip or f"user:{ev.user}")
        st = self.failed.get(key)
        if st is None or ts - st["last"] > self.w:
            st = self.failed[key] = {"reported": False, "pending": [], "last": ts}
            self.src_users.pop(key, None)
        st["last"] = max(st["last"], ts)
        users = self.src_users.setdefault(key, {})
        users[ev.user] = max(ts, users.get(ev.user, ts))
        spray = False
        if st["reported"]:
            if allowed:
                return None
            st["pending"].append(ev.ref)
            if len(st["pending"]) < self.n:
                return None
            refs, st["pending"] = st["pending"], []
        else:
            burst: list = []
            if len(self.pair[pair_key]) >= self.fail_n:
                burst = [x for x in self.pair[pair_key] if ts - x[0] <= self.w]
            if len(burst) < self.fail_n:
                if not ev.src_ip or len(users) < self.spray:
                    return None
                for name in [n for n, t in users.items() if ts - t > self.w]:
                    del users[name]
                if len(users) < self.spray:
                    return None
                spray = True
                burst = [x for x in self.by_src[(host, ev.src_ip)] if ts - x[0] <= self.w]
            st["reported"] = True
            refs = [x[1] for x in burst]
        who = ev.src_ip or f"user {ev.user}"
        many = len(users) > 1
        title = (f"password spray with no success yet: {len(users)} users failed from {who}" if spray
                 else f"{len(refs)} failed logons from {who} with no success yet")
        if allowed:
            return Suppressed(self.name, host, ts, "approved authentication source", allowed, refs,
                              {"title": title, "src_ip": ev.src_ip})
        user = None if many else ev.user
        sig = [("variant:failed_only", 0)]
        if ev.src_ip and not is_private_ip(ev.src_ip):
            sig.append(("external source IP", 10))
        return Candidate(self.name, host, ev.src_ip or f"user:{ev.user}", ts, title,
                         ["T1110 Brute Force"], refs, sig,
                         {"variant": "failed_only", "failures": len(refs), "user": user,
                          "src_ip": ev.src_ip},
                         [("block_ip", ev.src_ip)] if ev.src_ip else [],
                         user=user, src_ip=ev.src_ip)

    def on_event(self, ev: Event) -> list:
        if ev.category != "auth" or ev.outcome not in ("success", "failure"):
            return []
        user = ev.user
        if user and self.skip_machine and user.endswith("$"):
            return []
        allowed = self.allow.auth_match(ev.src_ip, user, ev.ts, ev.host)
        ts, host, ip = ev.ts, ev.host, ev.src_ip or "unknown-src"
        out: list = []
        if ev.outcome == "failure":
            k = (host, ip, user)
            for d, key, item in ((self.pair, k, (ts, ev.ref)),
                                 (self.by_src, (host, ip), (ts, ev.ref, user)),
                                 (self.by_user, (host, user), (ts, ev.ref, ip))):
                dq = d[key]
                self._add(dq, item)
                self._trim(dq, dq[-1][0])
            if self.fail_only:
                item = self._failed_only(ev, k, allowed)
                if item is not None:
                    out.append(item)
            if allowed or len(self.pair[k]) < self.n:
                return out
            need_watch = k not in self.watched
            need_block = self.prevent and self.preempt and ip != "unknown-src" and ip not in self.preblocked
            if not (need_watch or need_block):
                return out
            burst = [x for x in self.pair[k] if ts - x[0] <= self.w]
            if len(burst) >= self.n and need_watch:
                self.watched.add(k)
                out.append(Watch(self.name, host, ts,
                                 f"{len(burst)} failed logons for {user} from {ip} (no success yet)",
                                 [x[1] for x in burst], {"user": user, "src_ip": ip}))
            if need_block and len(burst) >= self.preempt:
                self.preblocked.add(ip)
                out.append(PreBlock("block_ip", ip, f"pre-emptive: {len(burst)} failed logons in "
                                    f"{int(self.w)}s", ts, host, [x[1] for x in burst][-20:]))
            return out

        # ---- success: check the three variants ------------------------------
        variants = []
        b = self._burst(self.pair.get((host, ip, user), deque()), ts)
        if len(b) >= self.n:
            variants.append(("classic", b, f"{len(b)} failed logons then success for {user} from {ip}"))
        # spraying needs a real source: local logons without an IP must not be pooled
        sb = self._burst(self.by_src.get((host, ip), deque()), ts) if ev.src_ip else []
        su = {x[2] for x in sb}
        if len(su) >= self.spray:
            variants.append(("spray", sb, f"password spray: {len(su)} users failed from {ip}, then success as {user}"))
        ub = self._burst(self.by_user.get((host, user), deque()), ts)
        us = {x[2] for x in ub}
        if len(ub) >= self.n and len(us) >= self.dist:
            variants.append(("distributed", ub, f"distributed: {len(ub)} failures for {user} from {len(us)} sources, then success"))
        if not variants:
            return []
        kind, fails, title = variants[0]
        all_refs = sorted({x[1] for _, f, _ in variants for x in f}) + [ev.ref]
        span = max(1.0, fails[-1][0] - fails[0][0])
        rate = len(fails) / (span / 60.0)
        sig = [(f"variant:{kind}", 0)]
        if rate >= 10:
            sig.append((f"fast: {rate:.0f} failures/min", 10))
        elif rate >= 3:
            sig.append((f"rate: {rate:.1f} failures/min", 5))
        if len(fails) >= 20:
            sig.append((f"volume: {len(fails)} failures", 5))
        if ev.src_ip and not is_private_ip(ev.src_ip):
            sig.append(("external source IP", 10))
        cand = Candidate(
            self.name, host, ev.src_ip or f"user:{user}", ts, title,
            ["T1110 Brute Force"] + (["T1110.003 Password Spraying"] if kind == "spray" else []),
            all_refs, sig,
            {"variant": kind, "failures": len(fails), "user": user, "src_ip": ev.src_ip,
             "first_failure_ts": fails[0][0], "logon_type": ev.logon_type},
            [("block_ip", ev.src_ip)] if ev.src_ip else [],
            user=user, src_ip=ev.src_ip, escalates=True,
        )
        if user:
            cand.blocks.append(("lock_account", user))
        # reset state so the same burst cannot alert twice
        self.pair.pop((host, ip, user), None)
        self.by_src.pop((host, ip), None)
        self.by_user.pop((host, user), None)
        self.watched.discard((host, ip, user))
        source = (host, ev.src_ip or f"user:{user}")
        self.failed.pop(source, None)
        self.src_users.pop(source, None)
        if allowed:
            return [Suppressed(self.name, host, ts, "approved authentication source", allowed,
                               all_refs, {"title": title, "user": user, "src_ip": ev.src_ip})]
        return [cand]


# ---------------------------------------------------------------------------
# Process table (shared)
# ---------------------------------------------------------------------------
class ProcessTable:
    def __init__(self, cap: int = 200000):
        self.cap = cap
        self.t: OrderedDict[tuple, dict] = OrderedDict()

    def add(self, ev: Event) -> None:
        if ev.pid is None:
            return
        k = (ev.host, ev.pid)
        self.t[k] = {"image": ev.image, "base": base(ev.image), "ppid": ev.ppid, "ts": ev.ts,
                     "cmd": ev.cmdline, "pid": ev.pid, "ref": ev.ref,
                     "parent_image": ev.parent_image}
        self.t.move_to_end(k)
        if len(self.t) > self.cap:
            self.t.popitem(last=False)

    def remove(self, ev: Event) -> None:
        r = self.t.get((ev.host, ev.pid))
        if r and (ev.image is None or base(ev.image) == r["base"]):
            del self.t[(ev.host, ev.pid)]

    def get(self, host: str, pid: str | None, before: float | None) -> dict | None:
        if pid is None:
            return None
        r = self.t.get((host, pid))
        if r is None:
            return None
        if before is not None and r["ts"] is not None and r["ts"] > before + 1:
            return None   # PID reused by a process that started after the child
        return r

    def _parent_of(self, host: str, ppid: str | None, child_ts: float | None,
                   stated: str | None) -> dict | None:
        """Table record for ppid, rejected if it contradicts the stated parent image
        (the PID was reused and we missed one of the start events)."""
        r = self.get(host, ppid, child_ts)
        if r and stated and r["base"] and r["base"] != base(stated):
            return None
        return r

    def ancestors(self, ev: Event, depth: int) -> list[dict]:
        """Nearest-first list of {base, image, pid, cmd}."""
        chain: list[dict] = []
        pid, ts, stated = ev.ppid, ev.ts, ev.parent_image
        seen = {ev.pid}
        while len(chain) < depth:
            rec = self._parent_of(ev.host, pid, ts, stated)
            if rec is None:
                if stated:   # parent known only by name: use it, nothing further to walk
                    chain.append({"base": base(stated), "image": stated, "pid": pid, "cmd": None})
                break
            if rec["pid"] in seen:
                break
            seen.add(rec["pid"])
            chain.append({"base": rec["base"], "image": rec["image"], "pid": rec["pid"], "cmd": rec["cmd"]})
            pid, ts, stated = rec["ppid"], rec["ts"], rec["parent_image"]
        return chain


def _temp_level(path: str | None, cfg: dict) -> str | None:
    if not path:
        return None
    c = cfg["temp_service"]
    p = path.lower()
    if any(p.startswith(x) for x in c["posix_temp_prefixes"]):
        return "high"
    if any(r in p for r in c["temp_roots"]):
        return "high"
    if any(r in p for r in c["extra_roots_medium"]):
        return "medium"
    return None


# ---------------------------------------------------------------------------
# R2 new service from a temp folder
# ---------------------------------------------------------------------------
_SC_BIN = re.compile(r"binpath=\s*(?:\"((?:[^\"\\]|\\.)+)\"|'([^']+)'|(\S+))", re.I)
_SC_CMD = re.compile(r"(?:^|[\s\\/\"'&|])sc(?:\.exe)?[\"']?\s+(?:\\\\\S+\s+)?(?:create|config)\b", re.I)
_SERVICE_NOT_NEW = re.compile(r"stop|delet|uninstall|remov|disabl", re.I)
_SC_NAME = re.compile(r"\bcreate\s+(\"[^\"]+\"|\S+)", re.I)
_PS_BIN = re.compile(r"-binarypathname\s+(?:\"([^\"]+)\"|'([^']+)'|(\S+))", re.I)
_PS_NAME = re.compile(r"-name\s+(\"[^\"]+\"|'[^']+'|\S+)", re.I)
_UNIT_DIRS = ("/etc/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/",
              "/run/systemd/system/", "~/.config/systemd/user/")


class TempService:
    name = "temp_service"
    MITRE = ["T1543.003 Create or Modify System Process: Windows Service",
             "T1569.002 System Services: Service Execution"]

    def __init__(self, cfg: dict, allow: AllowList, ptable: ProcessTable):
        self.cfg, self.allow, self.pt = cfg, allow, ptable
        self.hosts = set(cfg["temp_service"]["service_hosts"])
        self.drops: OrderedDict[tuple, float] = OrderedDict()
        self.units: OrderedDict[tuple, float] = OrderedDict()

    @staticmethod
    def _clean(v: str | None) -> str | None:
        if v is None:
            return None
        return v.strip().strip('"').strip("'").replace('\\"', '"')

    def _cand(self, ev: Event, binary: str, name: str | None, how: str, level: str) -> list:
        approved = self.allow.service_match(name, binary, ev.ts, ev.host)
        if approved:
            return [Suppressed(self.name, ev.host, ev.ts, f"approved service {name or binary}",
                               approved, [ev.ref],
                               {"binary": binary, "service": name})]
        sig = [(f"signal:{how}", 0)]
        if level == "medium":
            sig.append(("user-writable (non-temp) folder", -15))
        if (ev.host, binary) in self.drops:
            sig.append(("binary was dropped into temp just before", 10))
        if ev.host in {h for h, _ in self.units}:
            sig.append(("new systemd unit file written", 5))
        if ev.signed is False:
            sig.append(("unsigned binary", 10))
        blocks = [("disable_service", name or binary), ("quarantine_file", binary)]
        h = ev.hashes.get("sha256") or next(iter(ev.hashes.values()), None)
        if h and how == "service-host-spawn":
            blocks.append(("block_hash", h))
        return [Candidate(self.name, ev.host, binary, ev.ts,
                          f"service {('`' + name + '` ') if name else ''}runs from temp folder: {binary}",
                          self.MITRE, [ev.ref], sig,
                          {"binary": binary, "service": name, "signal": how,
                           "cmdline": ev.cmdline, "image": ev.image},
                          blocks, user=ev.user)]

    def on_event(self, ev: Event) -> list:
        cat = ev.category
        if cat == "file":
            p = ev.path
            if p and ev.action in ("create", "modify", "rename"):
                if _temp_level(p, self.cfg):
                    self.drops[(ev.host, p)] = ev.ts
                    if len(self.drops) > 50000:
                        self.drops.popitem(last=False)
                if any(p.startswith(d) for d in _UNIT_DIRS) and p.endswith((".service", ".timer")):
                    self.units[(ev.host, p)] = ev.ts
                    if len(self.units) > 5000:
                        self.units.popitem(last=False)
                    lvl = _temp_level(ev.service_path, self.cfg)
                    if lvl:
                        name = ev.service_name or p.rsplit("/", 1)[-1]
                        return self._cand(ev, ev.service_path, name, "unit-file-temp-exec", lvl)
                    return [Watch(self.name, ev.host, ev.ts, f"systemd unit written: {p}", [ev.ref])]
            return []
        if cat == "service":
            if _SERVICE_NOT_NEW.search(ev.action or ""):
                return []
            binary = ev.service_path or exe_from_cmd(ev.path)
            lvl = _temp_level(binary, self.cfg)
            if lvl:
                return self._cand(ev, binary, ev.service_name, "service-install-event", lvl)
            return []
        if cat != "process" or ev.action != "start":
            return []
        img_base = base(ev.image)
        cmd = ev.cmdline or ""
        # (a) service host (services.exe / systemd) launching a binary from temp
        parent_base = base(ev.parent_image)
        if parent_base is None:
            pr = self.pt.get(ev.host, ev.ppid, ev.ts)
            parent_base = pr["base"] if pr else None
        if parent_base in self.hosts:
            lvl = _temp_level(ev.image, self.cfg)
            if lvl:
                return self._cand(ev, ev.image, ev.service_name, "service-host-spawn", lvl)
        # (b) sc.exe create ... binPath= <temp>, also when wrapped in cmd /c
        if _SC_CMD.search(cmd):
            m = _SC_BIN.search(cmd)
            if m:
                val = self._clean(m.group(1) or m.group(2) or m.group(3))
                binary = exe_from_cmd(val)
                lvl = _temp_level(binary, self.cfg)
                if lvl:
                    nm = _SC_NAME.search(cmd)
                    name = nm.group(1).strip('"').lower() if nm else None
                    return self._cand(ev, binary, name, "sc-create", lvl)
        # (c) PowerShell New-Service -BinaryPathName <temp>
        if img_base in ("powershell", "pwsh", "cmd") and "new-service" in cmd.lower():
            m = _PS_BIN.search(cmd)
            vals = [self._clean(m.group(1) or m.group(2) or m.group(3))] if m else []
            for v in vals + path_tokens(cmd):
                binary = exe_from_cmd(v)
                lvl = _temp_level(binary, self.cfg)
                if lvl:
                    nm = _PS_NAME.search(cmd)
                    name = nm.group(1).strip("\"'").lower() if nm else None
                    return self._cand(ev, binary, name, "powershell-new-service", lvl)
        # (d) systemd-run / systemctl / launchctl pointing at temp, or reg add ...\Services\...ImagePath
        if img_base in ("systemd-run", "systemctl", "launchctl", "reg") or (
                img_base in ("cmd", "powershell", "pwsh") and "\\services\\" in cmd.lower()
                and "imagepath" in cmd.lower()):
            if img_base == "reg" and not ("\\services\\" in cmd.lower() and "imagepath" in cmd.lower()):
                return []
            for t in path_tokens(cmd):
                lvl = _temp_level(t, self.cfg)
                if lvl:
                    return self._cand(ev, exe_from_cmd(t), ev.service_name, f"{img_base}-temp-unit", lvl)
        return []


# ---------------------------------------------------------------------------
# R3 office program starting a shell
# ---------------------------------------------------------------------------
class OfficeShell:
    name = "office_shell"
    MITRE = ["T1566.001 Phishing: Spearphishing Attachment", "T1204.002 User Execution: Malicious File",
             "T1059 Command and Scripting Interpreter"]

    def __init__(self, cfg: dict, allow: AllowList, ptable: ProcessTable):
        c = cfg["office_shell"]
        self.office = set(c["office"])
        self.shells = set(c["shells"])
        self.lol = set(c["lolbins"]) if c["lolbins_enabled"] else set()
        self.depth = int(c["max_depth"])
        self.allow, self.pt, self.cfg = allow, ptable, cfg

    def on_event(self, ev: Event) -> list:
        if ev.category != "process" or ev.action != "start":
            return []
        child = base(ev.image)
        if child not in self.shells and child not in self.lol:
            return []
        chain = self.pt.ancestors(ev, self.depth)
        office = next(((i, a) for i, a in enumerate(chain) if a["base"] in self.office), None)
        if office is None:
            return []
        depth, anc = office
        direct_parent = chain[0]["base"] if chain else None
        allow = self.allow.process_match(anc["base"], child, ev.cmdline, ev.ts, ev.host)
        if allow is None and depth > 0:
            allow = self.allow.process_match(direct_parent, child, ev.cmdline, ev.ts, ev.host)
        if allow:
            return [Suppressed(self.name, ev.host, ev.ts, f"approved {anc['base']} -> {child}", allow,
                               [ev.ref], {"cmdline": ev.cmdline})]
        sig = [(f"office parent: {anc['base']}", 0)]
        if depth > 0:
            sig.append((f"indirect (depth {depth + 1}) via {direct_parent}", 5))
        if child in self.lol:
            sig.append(("LOLBin child (not a shell)", -10))
        if ev.cmdline and _SUSP_CMD.search(ev.cmdline):
            sig.append(("suspicious command line (encoded/download/hidden)", 15))
        if _temp_level(ev.image, self.cfg):
            sig.append(("child binary in temp folder", 10))
        entity = f"{anc['base']}:{anc['pid']}" if anc.get("pid") else f"{anc['base']}"
        blocks = [("kill_process", f"{ev.host}:{ev.pid}" if ev.pid else (ev.image or child))]
        if anc.get("pid"):
            blocks.append(("kill_process", f"{ev.host}:{anc['pid']}"))
        h = ev.hashes.get("sha256")
        if h:
            blocks.append(("block_hash", h))
        tree = [a["base"] for a in reversed(chain[:depth + 1])] + [child]
        return [Candidate(self.name, ev.host, entity, ev.ts,
                          f"{anc['base']} spawned {child}" + (f" (via {direct_parent})" if depth else ""),
                          self.MITRE, [ev.ref], sig,
                          {"process_tree": " -> ".join(tree), "cmdline": ev.cmdline,
                           "child_pid": ev.pid, "office_pid": anc.get("pid")},
                          blocks, user=ev.user)]


# ---------------------------------------------------------------------------
# R4 file integrity against a hash baseline
# ---------------------------------------------------------------------------
class FIM:
    name = "fim"
    MITRE = ["T1565.001 Data Manipulation: Stored Data Manipulation",
             "T1070.004 Indicator Removal: File Deletion"]

    def __init__(self, cfg: dict, allow: AllowList, baseline: dict[str, dict[str, dict[str, str]]]):
        c = cfg["fim"]
        self.allow = allow
        self.base_by_host = baseline if "*" in baseline else {"*": baseline}
        self.learned: set[tuple] = set()
        self.learn = bool(c["learn_baseline"])
        self.crit = set(c["critical_paths"])
        self.crit_pre = tuple(c["critical_prefixes"])
        self.watched = tuple(c["watched_dirs"])

    def export_baseline(self) -> dict:
        """The loaded baseline plus learned and approved content, in loadable form."""
        return {"files": self.base_by_host["*"],
                "hosts": {h: v for h, v in self.base_by_host.items() if h != "*"}}

    def _critical(self, p: str) -> bool:
        return p in self.crit or p.startswith(self.crit_pre)

    def _cand(self, ev: Event, path: str, what: str, sig: list, ctx: dict) -> Candidate:
        if self._critical(path):
            sig = sig + [("critical system file", 25)]
        if (ev.host, path) in self.learned:
            sig = sig + [("baseline learned from stream", -5)]
        blocks = [("restore_file", path)]
        return Candidate(self.name, ev.host, path, ev.ts, f"file {what}: {path}", self.MITRE,
                         [ev.ref], sig, ctx, blocks, user=ev.user)

    def on_event(self, ev: Event) -> list:
        if ev.category != "file" or not ev.path or ev.action == "access":
            return []
        p = ev.path
        act = ev.action
        host_base = self.base_by_host.get(ev.host, {})
        glob_base = self.base_by_host["*"]

        def lookup(path):
            return host_base.get(path) or glob_base.get(path)

        def store(path, hashes):
            # approved / learned content is stored per host so other machines keep their baseline
            self.base_by_host.setdefault(ev.host, {})[path] = dict(hashes)

        if act == "rename" and ev.new_path and lookup(ev.new_path) and not lookup(p):
            p, act = ev.new_path, "modify"
        known = lookup(p)
        if known is None:
            if self.learn and ev.hashes and act in ("create", "modify"):
                store(p, ev.hashes)
                self.learned.add((ev.host, p))
            elif self.watched and act == "create" and p.startswith(self.watched):
                return [Watch(self.name, ev.host, ev.ts, f"new file in watched dir: {p}", [ev.ref])]
            return []
        if act == "delete":
            return [self._cand(ev, p, "deleted", [("baselined file removed", 10)], {"expected": known})]
        if act == "rename":
            return [self._cand(ev, p, "moved away", [("baselined file renamed", 5)],
                               {"expected": known, "new_path": ev.new_path})]
        if act == "chmod":
            return [self._cand(ev, p, "permissions changed", [], {"expected": known})]
        # create / modify / write
        new = ev.hashes
        common = [a for a in new if a in known]
        if common:
            if all(new[a] == known[a] for a in common):
                return []      # identical content (touch / same-hash rewrite)
            a = next(a for a in common if new[a] != known[a])
            new_h = new[a]
            candidates = (self.allow.fim_match(p, h, ev.ts, ev.host)
                          for algo, h in new.items() if known.get(algo) != h)
            allow = next((match for match in candidates if match), None)
            if allow:
                store(p, new)   # approved: the new content becomes the baseline
                return [Suppressed(self.name, ev.host, ev.ts, "approved change", allow, [ev.ref],
                                   {"path": p, "new_hash": new_h, "old_hash": known.get(a)})]
            return [self._cand(ev, p, "modified", [("hash mismatch", 10)],
                               {"algo": a, "expected": known[a], "observed": new_h})]
        allow = None
        for h in new.values():
            allow = self.allow.fim_match(p, h, ev.ts, ev.host)
            if allow:
                break
        if allow is None and not new:
            allow = self.allow.fim_match(p, None, ev.ts, ev.host)
        if allow:
            if new:
                store(p, new)
            return [Suppressed(self.name, ev.host, ev.ts, "approved change", allow, [ev.ref], {"path": p})]
        why = "no hash in event" if not new else f"hash algorithm {list(new)} not in baseline {list(known)}"
        candidate = self._cand(ev, p, "changed (unverified)", [("unverified: " + why, -10)],
                               {"expected": known, "observed": new or None})
        candidate.blocks = []
        return [candidate]
