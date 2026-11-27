"""Map any incoming JSON event onto one canonical Event.

The hidden stream may use different field names than the development stream,
so every canonical field has a list of aliases, matched case-insensitively on
flattened (dot-joined) keys.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import re
from math import isfinite
from dataclasses import dataclass, field
from typing import Any

# Fields that carry ground truth. They are removed before detection so the
# agent can never "cheat"; only evaluate.py reads them from the raw stream.
LABEL_FIELDS = {
    "label", "labels", "is_attack", "attack_id", "ground_truth", "attack",
    "malicious", "sequence_id", "attack_type", "is_malicious", "tag_attack",
}

ALIASES: dict[str, tuple[str, ...]] = {
    "ts": ("ts", "timestamp", "@timestamp", "time", "event_time", "eventtime",
           "timecreated", "utctime", "datetime", "date", "event.created"),
    "host": ("host", "hostname", "host.name", "computer", "computername",
             "machine", "device", "agent.hostname"),
    "category": ("category", "event_type", "eventtype", "type", "event.category",
                 "event.type", "kind", "log_type", "source_type"),
    "event_id": ("eventid", "event_id_win", "winlog.event_id", "event.code", "code"),
    "id": ("id", "event_id", "uid", "event.id", "record_id", "eventrecordid", "_id"),
    "action": ("action", "event.action", "operation", "op", "activity", "verb"),
    "outcome": ("outcome", "result", "status", "event.outcome", "success", "auth_result"),
    "user": ("user", "username", "user.name", "targetusername", "account",
             "account_name", "subjectusername", "login", "uname"),
    "src_ip": ("src_ip", "source_ip", "ip", "ipaddress", "source.ip", "remote_addr",
               "remote_ip", "client_ip", "src", "workstation_ip", "srcip"),
    "logon_type": ("logon_type", "logontype", "winlog.event_data.logontype"),
    "pid": ("process.pid", "pid", "process_id", "processid", "newprocessid"),
    "ppid": ("process.parent.pid", "ppid", "parent_pid", "parentprocessid", "parent_process_id"),
    "image": ("process.executable", "image", "process", "process_name", "exe", "newprocessname",
              "process.name", "proc", "path_exe"),
    "parent_image": ("process.parent.executable", "parent_image", "parent", "parentimage",
                     "parentprocessname", "process.parent.name",
                     "parent_process", "parent_name", "parent_exe",
                     "parent.executable", "parent.image", "parent.name"),
    "cmdline": ("process.command_line", "cmdline", "command_line", "commandline",
                "cmd", "process.args", "args"),
    "path": ("path", "file", "file_path", "filepath", "targetfilename", "file.path",
             "filename", "target", "object_name", "objectname"),
    "new_path": ("new_path", "dest_path", "target_path", "file.target_path", "rename_to"),
    "hash": ("hash", "sha256", "file_hash", "hashes", "file.hash.sha256", "new_hash",
             "md5", "sha1", "checksum", "digest"),
    "old_hash": ("old_hash", "previous_hash", "prev_hash"),
    "service_name": ("service_name", "servicename", "service", "service.name", "unit"),
    "service_path": ("service_path", "imagepath", "binary_path", "service_file_name",
                     "servicefilename", "exec_start", "service.executable", "binpath"),
    "message": ("message", "msg", "raw", "log", "line"),
    "signed": ("signed", "is_signed", "signature_status", "code_signature.trusted"),
}

# Windows / Sysmon event IDs -> (category, action, outcome)
EVENT_ID_MAP: dict[int, tuple[str, str | None, str | None]] = {
    4624: ("auth", "logon", "success"),
    4625: ("auth", "logon", "failure"),
    4771: ("auth", "kerberos_preauth", "failure"),
    4776: ("auth", "ntlm_validate", None),
    4688: ("process", "start", None),
    4689: ("process", "end", None),
    7045: ("service", "install", None),
    4697: ("service", "install", None),
    4663: ("file", "access", None),
    4660: ("file", "delete", None),
}
SYSMON_ID_MAP: dict[int, tuple[str, str | None, str | None]] = {
    1: ("process", "start", None),
    5: ("process", "end", None),
    11: ("file", "create", None),
    23: ("file", "delete", None),
    26: ("file", "delete", None),
}

_SSH_FAIL = re.compile(r"failed (?:password|publickey|keyboard-interactive\S*) for (?:invalid user )?(\S+) from (\S+)", re.I)
_SSH_OK = re.compile(r"accepted \S+ for (\S+) from (\S+)", re.I)
_SSH_INVALID = re.compile(r"invalid user (\S+) from (\S+)", re.I)

_ENV = {
    "%systemroot%": "c:/windows", "%windir%": "c:/windows",
    "%programdata%": "c:/programdata", "%public%": "c:/users/public",
    "%temp%": "c:/users/_/appdata/local/temp", "%tmp%": "c:/users/_/appdata/local/temp",
    "%localappdata%": "c:/users/_/appdata/local", "%appdata%": "c:/users/_/appdata/roaming",
    "%programfiles%": "c:/program files", "%systemdrive%": "c:",
    "%userprofile%": "c:/users/_",
}
_SHORT = {"locals~1": "local settings", "docume~1": "documents and settings",
          "progra~1": "program files", "progra~2": "program files (x86)"}
_EXE_EXT = (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".sh",
            ".py", ".scr", ".com", ".msi", ".jar", ".bin", ".elf", ".so")


@dataclass(slots=True)
class Event:
    ts: float | None
    seq: int
    ref: str                     # stable evidence reference (explicit id or line number)
    host: str = "unknown"
    category: str = "other"
    action: str | None = None
    outcome: str | None = None
    user: str | None = None
    domain: str | None = None
    src_ip: str | None = None
    logon_type: str | None = None
    pid: str | None = None
    ppid: str | None = None
    image: str | None = None
    parent_image: str | None = None
    cmdline: str | None = None
    path: str | None = None
    new_path: str | None = None
    hashes: dict[str, str] = field(default_factory=dict)
    old_hash: str | None = None
    service_name: str | None = None
    service_path: str | None = None
    signed: bool | None = None
    has_explicit_id: bool = False
    ts_missing: bool = False


def flatten(d: Any, prefix: str = "", out: dict | None = None) -> dict:
    out = {} if out is None else out
    if isinstance(d, dict):
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                flatten(v, key, out)
            out.setdefault(key.lower(), v)
            # also expose leaf names so "event_data.TargetUserName" matches "targetusername"
            if prefix and not isinstance(v, dict) and "parent" not in prefix.lower():
                out.setdefault(str(k).lower(), v)
    return out


def strip_labels(raw: dict) -> dict:
    return {k: v for k, v in raw.items() if str(k).lower() not in LABEL_FIELDS}


def pick(flat: dict, canon: str) -> Any:
    for a in ALIASES[canon]:
        v = flat.get(a)
        if v is None or v == "" or isinstance(v, dict):
            continue
        if isinstance(v, list) and canon != "cmdline":
            if not v:
                continue
            v = v[0]
        return v
    return None


# alias -> [(canonical field, priority)], so each event is scanned once
_ALIAS_INDEX: dict[str, list[tuple[str, int]]] = {}
for _canon, _names in ALIASES.items():
    for _prio, _name in enumerate(_names):
        _ALIAS_INDEX.setdefault(_name, []).append((_canon, _prio))


def index_fields(flat: dict) -> dict:
    """Same result as calling pick() for every canonical field, in one pass."""
    best: dict[str, tuple[int, Any]] = {}
    for key, v in flat.items():
        hits = _ALIAS_INDEX.get(key)
        if hits is None or v is None or v == "" or isinstance(v, dict):
            continue
        for canon, prio in hits:
            cur = best.get(canon)
            if cur is None or prio < cur[0]:
                if isinstance(v, list) and canon != "cmdline":
                    if not v:
                        continue
                    best[canon] = (prio, v[0])
                else:
                    best[canon] = (prio, v)
    return {k: x[1] for k, x in best.items()}


_KNOWN_CODES = set(EVENT_ID_MAP) | {1, 5, 11, 23, 26}


def _split_ids(flat: dict, has_text_category: bool) -> tuple[Any, int | None]:
    """'event_id' is ambiguous: a Windows code (4625) or a unique record id.
    It is read as a code only when it is a known code, no dedicated code field
    exists and the event carries no textual category."""
    explicit = pick(flat, "id")
    code = _to_int(pick(flat, "event_id"))
    ev_id_raw = flat.get("event_id")
    if (code is None and not has_text_category and not isinstance(ev_id_raw, bool)
            and _to_int(ev_id_raw) in _KNOWN_CODES):
        code = _to_int(ev_id_raw)
        if explicit == ev_id_raw:
            explicit = None
            for a in ALIASES["id"]:
                if a != "event_id" and flat.get(a) not in (None, ""):
                    explicit = flat[a]
                    break
    return explicit, code


def parse_ts(v: Any) -> float | None:
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        x = float(v)
        if not isfinite(x):
            return None
        if x > 1e17:            # Windows FILETIME (100 ns since 1601)
            return x / 1e7 - 11644473600
        if x > 1e14:            # microseconds
            return x / 1e6
        if x > 1e11:            # milliseconds
            return x / 1e3
        return x
    s = str(v).strip()
    if not s:
        return None
    try:
        return parse_ts(float(s))
    except ValueError:
        pass
    s2 = s.replace("Z", "+00:00").replace("z", "+00:00")
    if " " in s2 and "T" not in s2[:11]:
        s2 = s2.replace(" ", "T", 1)
    # trim sub-microsecond digits (e.g. .1234567) which fromisoformat rejects on older Pythons
    s2 = re.sub(r"(\.\d{6})\d+", r"\1", s2)
    try:
        d = _dt.datetime.fromisoformat(s2)
    except ValueError:
        for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S %Y", "%Y/%m/%d %H:%M:%S"):
            try:
                d = _dt.datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d.timestamp()


def norm_path(p: Any) -> str | None:
    if p is None:
        return None
    s = str(p).strip().strip('"').strip("'").strip()
    if not s:
        return None
    s = s.replace("\\", "/").lower()
    for pre in ("/??/", "//?/", "//./"):
        if s.startswith(pre):
            s = s[len(pre):]
    for k, v in _ENV.items():
        if k in s:
            s = s.replace(k, v)
    parts = s.split("/")
    parts = [_SHORT.get(x, x) for x in parts]
    s = "/".join(parts)
    while "//" in s[1:]:
        s = s[0] + s[1:].replace("//", "/")
    return s


def exe_from_cmd(cmd: Any) -> str | None:
    """Return the executable path at the start of a command line (quote-aware,
    tolerates unquoted paths containing spaces)."""
    if cmd is None:
        return None
    s = str(cmd).strip()
    if not s:
        return None
    if s[0] in "\"'":
        q = s[0]
        end = s.find(q, 1)
        return norm_path(s[1:end] if end > 0 else s[1:])
    toks = s.split(" ")
    acc = []
    for t in toks:
        acc.append(t)
        if t.lower().endswith(_EXE_EXT):
            return norm_path(" ".join(acc))
    return norm_path(toks[0])


def path_tokens(cmd: str | None) -> list[str]:
    """All path-like tokens inside a command line (quoted or bare)."""
    if not cmd:
        return []
    out = []
    for m in re.finditer(r'"([^"]+)"|\'([^\']+)\'|(\S+)', cmd):
        t = m.group(1) or m.group(2) or m.group(3)
        if t and ("\\" in t or "/" in t or "%" in t):
            t = t.split("=", 1)[1] if t.lower().startswith(("binpath=", "-binarypathname=")) and "=" in t else t
            np = norm_path(t)
            if np:
                out.append(np)
    return out


def base(p: str | None) -> str | None:
    if not p:
        return None
    b = p.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return b[:-4] if b.endswith(".exe") else b


def norm_user(u: Any) -> tuple[str | None, str | None]:
    if u is None:
        return None, None
    s = str(u).strip().lower()
    if not s or s in ("-", "n/a", "null", "none"):
        return None, None
    if "\\" in s:
        d, s = s.split("\\", 1)
        return s, d
    if "@" in s:
        s, d = s.split("@", 1)
        return s, d
    return s, None


def norm_ip(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in ("", "-", "::1", "127.0.0.1", "localhost", "n/a"):
        return None if s in ("", "-", "n/a") else s
    if s.startswith("::ffff:"):
        s = s[7:]
    # strip port forms "1.2.3.4:5555" (ipv4 only)
    if s.count(":") == 1 and "." in s:
        s = s.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return s


def parse_hashes(v: Any) -> dict[str, str]:
    if v is None:
        return {}
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if x:
                out[str(k).lower()] = str(x).strip().lower()
        return out
    s = str(v).strip()
    out: dict[str, str] = {}
    if "=" in s:
        for part in re.split(r"[,;\s]+", s):
            if "=" in part:
                k, x = part.split("=", 1)
                if x:
                    out[k.strip().lower()] = x.strip().lower()
        return out
    h = s.lower()
    for pre in ("sha256:", "md5:", "sha1:"):
        if h.startswith(pre):
            return {pre[:-1]: h[len(pre):]}
    algo = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(len(h))
    if algo and re.fullmatch(r"[0-9a-f]+", h):
        out[algo] = h
    elif h:
        out["unknown"] = h
    return out


def _to_int(v: Any) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _category_from_text(t: str) -> str | None:
    t = t.lower()
    if any(k in t for k in ("auth", "logon", "login", "ssh", "credential", "session")):
        return "auth"
    if "service" in t:
        return "service"
    if "process" in t or t in ("exec", "execve", "proc"):
        return "process"
    if "file" in t or "fim" in t or "integrity" in t:
        return "file"
    return None


def _outcome(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return "success" if v else "failure"
    t = str(v).lower()
    if any(k in t for k in ("fail", "unsuccess", "denied", "invalid", "bad", "wrong", "reject", "error", "0xc000",
                             "not allow", "unauthor", "locked", "disabled", "expired")):
        return "failure"
    if any(k in t for k in ("success", "accept", "ok", "pass", "granted", "true", "allowed")):
        return "success"
    return None


def _file_action(v: Any) -> str | None:
    if v is None:
        return None
    t = str(v).lower()
    for key, act in (("delet", "delete"), ("remov", "delete"), ("unlink", "delete"),
                     ("renam", "rename"), ("move", "rename"), ("chmod", "chmod"),
                     ("chown", "chmod"), ("perm", "chmod"), ("attrib", "chmod"),
                     ("creat", "create"), ("new", "create"), ("writ", "modify"),
                     ("modif", "modify"), ("chang", "modify"), ("updat", "modify"),
                     ("access", "access"), ("read", "access"), ("open", "access")):
        if key in t:
            return act
    return t


def normalize(raw: dict, seq: int) -> Event:
    clean = strip_labels(raw)
    flat = flatten(clean)
    fields = index_fields(flat)
    cat_raw = fields.get("category")
    text_cat = _category_from_text(str(cat_raw)) if cat_raw is not None and _to_int(cat_raw) is None else None
    explicit_id, eid = _split_ids(flat, text_cat is not None)
    ref = f"id:{explicit_id}" if explicit_id is not None else f"line:{seq}"
    ts_raw = fields.get("ts")
    ts = parse_ts(ts_raw)
    ev = Event(ts=ts, seq=seq, ref=ref, has_explicit_id=explicit_id is not None,
               ts_missing=ts is None)

    host = fields.get("host")
    ev.host = str(host).strip().lower() if host else "unknown"

    # ---- category / action / outcome --------------------------------------
    cat = text_cat
    provider = str(flat.get("provider", flat.get("channel", ""))).lower()
    if eid is None and text_cat is None:
        eid = _to_int(cat_raw)
    if eid is not None:
        m = SYSMON_ID_MAP.get(eid) if "sysmon" in provider else None
        m = m or EVENT_ID_MAP.get(eid) or (SYSMON_ID_MAP.get(eid) if eid < 30 else None)
        if m and (cat is None or cat == m[0]):
            cat = m[0]
            ev.action, ev.outcome = m[1], m[2]
    act_raw = fields.get("action")
    if cat is None and act_raw is not None:
        cat = _category_from_text(str(act_raw))
    msg = fields.get("message")

    user, domain = norm_user(fields.get("user"))
    ip = norm_ip(fields.get("src_ip"))

    if msg and (cat in (None, "auth")):
        m = _SSH_FAIL.search(str(msg)) or _SSH_INVALID.search(str(msg))
        if m:
            cat, ev.outcome = "auth", "failure"
            user = user or norm_user(m.group(1))[0]
            ip = ip or norm_ip(m.group(2))
        else:
            m = _SSH_OK.search(str(msg))
            if m:
                cat, ev.outcome = "auth", "success"
                user = user or norm_user(m.group(1))[0]
                ip = ip or norm_ip(m.group(2))

    # infer from present fields when nothing else told us
    if cat is None:
        runs = fields.get("image") or fields.get("cmdline")
        if user and fields.get("outcome") is not None and not runs and not fields.get("path"):
            cat = "auth"
        elif fields.get("service_path") or (fields.get("service_name") and not runs):
            cat = "service"
        elif fields.get("image") or fields.get("cmdline") or fields.get("parent_image"):
            cat = "process"
        elif fields.get("path") or fields.get("hash"):
            cat = "file"
    if cat == "process" and act_raw == "service_install" and fields.get("service_path"):
        cat = "service"
    ev.category = cat or "other"

    if ev.category == "auth":
        if ev.outcome is None:
            ev.outcome = _outcome(fields.get("outcome")) or _outcome(act_raw) or _outcome(cat_raw)
        lt = fields.get("logon_type")
        ev.logon_type = str(lt).lower() if lt is not None else None
        ev.action = ev.action or (str(act_raw).lower() if act_raw else "logon")
    elif ev.category == "file":
        ev.action = _file_action(act_raw) or ev.action or _file_action(cat_raw) or "modify"
    elif ev.category == "process":
        a = str(act_raw or ev.action or "start").lower()
        ev.action = "end" if any(k in a for k in ("end", "exit", "stop", "terminat")) else "start"
    elif ev.category == "service":
        ev.action = ev.action or (str(act_raw).lower() if act_raw else "install")

    ev.user, ev.domain, ev.src_ip = user, domain, ip
    pid, ppid = fields.get("pid"), fields.get("ppid")
    if flat.get("newprocessid") not in (None, ""):
        # Windows 4688: NewProcessId is the child, ProcessId is the creator
        pid = flat["newprocessid"]
        ppid = ppid if ppid is not None else flat.get("processid")
    ev.pid = str(pid).strip().lower() if pid is not None else None
    ev.ppid = str(ppid).strip().lower() if ppid is not None else None
    cmd = fields.get("cmdline")
    if isinstance(cmd, list):
        cmd = " ".join(str(x) for x in cmd)
    ev.cmdline = str(cmd) if cmd is not None else None
    img = fields.get("image")
    ev.image = norm_path(img) if img else exe_from_cmd(ev.cmdline)
    pimg = fields.get("parent_image")
    ev.parent_image = norm_path(pimg) if pimg else None
    ev.path = norm_path(fields.get("path"))
    ev.new_path = norm_path(fields.get("new_path"))
    hv = fields.get("hash")
    ev.hashes = parse_hashes(hv)
    # pick up explicitly named hash fields too
    for algo in ("sha256", "sha1", "md5"):
        if algo in flat and flat[algo]:
            ev.hashes.setdefault(algo, str(flat[algo]).lower())
    oh = fields.get("old_hash")
    ev.old_hash = str(oh).lower() if oh else None
    sn = fields.get("service_name")
    ev.service_name = str(sn).strip().lower() if sn else None
    sp = fields.get("service_path")
    ev.service_path = exe_from_cmd(sp) if sp else None
    sg = fields.get("signed")
    if sg is not None:
        ev.signed = sg if isinstance(sg, bool) else str(sg).lower() in ("true", "valid", "signed", "1", "yes")
    if ev.category == "process" and ev.image is None and ev.path:
        ev.image = ev.path
    return ev


def is_private_ip(ip: str | None) -> bool:
    if not ip:
        return True
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return True
