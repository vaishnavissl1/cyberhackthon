"""Allow-list for approved changes (HIPS). Entries are deliberately narrow: a FIM
entry needs a hash unless it opts in with allow_unhashed, so an attacker cannot
hide inside an approved path."""
from __future__ import annotations

import fnmatch
import ipaddress
import re
import sys
from typing import Any

from .normalize import base, norm_path, norm_user, parse_ts


def _glob(pattern: str | None, value: str | None) -> bool:
    if pattern is None:
        return True
    if value is None:
        return False
    return fnmatch.fnmatchcase(value, pattern)


class AllowList:
    def __init__(self, data: dict | None):
        data = data or {}
        self.fim: list[dict] = []
        self.services: list[dict] = []
        self.process: list[dict] = []
        self.auth: list[dict] = []
        for kind in ("fim", "services", "process", "auth"):
            for entry in data.get(kind, []):
                self.add(kind, entry)
        nb = data.get("never_block", {}) or {}
        self.never_block_ips = [ipaddress.ip_network(x, strict=False) for x in nb.get("ips", [])]
        self.never_block_users = {norm_user(u)[0] for u in nb.get("users", [])}
        self.never_block_paths = {norm_path(p) for p in nb.get("paths", [])}

    def add(self, kind: str, entry: dict, starts: float | None = None) -> bool:
        """Add one entry. Entries too loose to be safe are ignored, so the
        detection still raises an alert."""
        prep = {"fim": self._prep_fim, "services": self._prep_svc,
                "process": self._prep_proc, "auth": self._prep_auth}[kind]
        item = prep(entry)
        if item is None:
            print(f"[allowlist] WARNING ignored {kind} entry (missing required fields): {entry}",
                  file=sys.stderr)
            return False
        item["host"] = str(entry["host"]).lower() if entry.get("host") else None
        item["starts"] = starts
        getattr(self, kind).append(item)
        self._warn_broad(kind, item)
        return True

    # -- preparation ---------------------------------------------------------
    @staticmethod
    def _exp(e: dict) -> float | None:
        return parse_ts(e.get("expires")) if e.get("expires") else None

    def _prep_fim(self, e: dict) -> dict:
        return {"path": norm_path(e["path"]), "hash": (e.get("hash") or "").lower() or None,
                "allow_unhashed": bool(e.get("allow_unhashed")), "expires": self._exp(e),
                "ticket": e.get("ticket"), "raw": e}

    def _prep_svc(self, e: dict) -> dict | None:
        if not e.get("path"):
            return None     # a name alone would approve any binary registered under it
        return {"name": (e.get("name") or "").lower() or None,
                "path": norm_path(e.get("path")), "expires": self._exp(e), "raw": e}

    def _prep_proc(self, e: dict) -> dict | None:
        rx = e.get("cmdline_regex")
        if not (e.get("parent") and e.get("child") and rx):
            return None
        return {"parent": base(e["parent"]), "child": base(e["child"]),
                "cmd": re.compile(rx, re.I), "expires": self._exp(e), "raw": e}

    def _prep_auth(self, e: dict) -> dict | None:
        net = ipaddress.ip_network(e["src_ip"], strict=False) if e.get("src_ip") else None
        if net is None and not e.get("user"):
            return None
        return {"net": net, "user": norm_user(e.get("user"))[0], "expires": self._exp(e), "raw": e}

    @staticmethod
    def _warn_broad(kind: str, e: dict) -> None:
        broad = ((kind == "fim" and e["hash"] is None and (e["allow_unhashed"] or "*" in (e["path"] or "")))
                 or (kind == "auth" and e["net"] is not None
                     and e["net"].prefixlen < (24 if e["net"].version == 4 else 64)))
        if broad:
            print(f"[allowlist] WARNING broad {kind} entry: {e['raw']}", file=sys.stderr)

    @staticmethod
    def _live(e: dict, ts: float | None, host: str | None) -> bool:
        if e["host"] is not None and e["host"] != host:
            return False
        if ts is None:
            return True
        if e["starts"] is not None and ts < e["starts"]:
            return False
        return e["expires"] is None or ts <= e["expires"]

    # -- matching ------------------------------------------------------------
    def fim_match(self, path: str, new_hash: str | None, ts: float | None,
                  host: str | None = None) -> dict | None:
        for e in self.fim:
            if not self._live(e, ts, host) or not _glob(e["path"], path):
                continue
            if e["hash"] is not None:
                if new_hash and new_hash == e["hash"]:
                    return e["raw"]
            elif e["allow_unhashed"]:
                return e["raw"]
        return None

    def service_match(self, name: str | None, path: str | None, ts: float | None,
                      host: str | None = None) -> dict | None:
        for e in self.services:
            if not self._live(e, ts, host):
                continue
            # a process-based detection carries no service name: the path decides then
            if (e["name"] is None or name is None or e["name"] == name) and _glob(e["path"], path):
                return e["raw"]
        return None

    def process_match(self, parent: str | None, child: str | None, cmd: str | None,
                      ts: float | None, host: str | None = None) -> dict | None:
        for e in self.process:
            if not self._live(e, ts, host):
                continue
            if e["parent"] != parent or e["child"] != child:
                continue
            if not (cmd and e["cmd"].fullmatch(cmd.strip())):
                continue
            return e["raw"]
        return None

    def auth_match(self, ip: str | None, user: str | None, ts: float | None,
                   host: str | None = None) -> dict | None:
        for e in self.auth:
            if not self._live(e, ts, host):
                continue
            if e["net"] is not None:
                try:
                    if ip is None or ipaddress.ip_address(ip) not in e["net"]:
                        continue
                except ValueError:
                    continue
            if e["user"] and e["user"] != user:
                continue
            return e["raw"]
        return None

    def protected(self, kind: str, target: str | None) -> bool:
        if target is None:
            return False
        if kind == "ip":
            try:
                a = ipaddress.ip_address(target)
                return any(a in n for n in self.never_block_ips)
            except ValueError:
                return False
        if kind == "user":
            return target in self.never_block_users
        if kind == "path":
            return target in self.never_block_paths
        return False


def load_allowlist(data: Any) -> AllowList:
    return AllowList(data if isinstance(data, dict) else {})
