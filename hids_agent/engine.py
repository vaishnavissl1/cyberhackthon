"""Detection engine: routes events to rules, scores, de-duplicates alerts,
correlates incidents and applies the (simulated) prevention response."""
from __future__ import annotations

import itertools
from collections import Counter
from typing import Callable

from .allowlist import AllowList
from .config import SEV_ORDER, sev_from_score
from .normalize import Event, is_private_ip, norm_path, parse_hashes
from .rules import (FIM, Approvals, BruteForce, Candidate, OfficeShell, PreBlock, ProcessTable,
                    Suppressed, TempService, Watch)

Sink = Callable[[str, dict], None]


def load_baseline(data) -> dict[str, dict[str, dict[str, str]]]:
    """Returns {host_or_*: {path: {algo: hash}}}.

    Accepts {path: hash}, {path: {algo: hash}}, {path: {"hash": h, "algo": a}},
    a list of {"path", "hash"[, "algo", "host"]}, or {"hosts": {host: {...}}, "files": {...}}
    for per-host baselines (the same path differs between machines)."""
    out: dict[str, dict[str, dict[str, str]]] = {"*": {}}
    if not data:
        return out
    if isinstance(data, dict) and ("hosts" in data or "files" in data):
        out["*"] = _flat_baseline(data.get("files") or {})
        for host, entries in (data.get("hosts") or {}).items():
            out[str(host).lower()] = _flat_baseline(entries)
        return out
    if isinstance(data, list):
        for d in data:
            h = str(d.get("host")).lower() if d.get("host") else "*"
            out.setdefault(h, {}).update(_flat_baseline([d]))
        return out
    out["*"] = _flat_baseline(data)
    return out


def _flat_baseline(data) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    items = data.items() if isinstance(data, dict) else ((d.get("path"), d) for d in data)
    for path, v in items:
        p = norm_path(path)
        if not p:
            continue
        if isinstance(v, dict):
            if "hash" in v:
                h = parse_hashes(v["hash"])
                if v.get("algo") and len(h) == 1:
                    h = {str(v["algo"]).lower(): next(iter(h.values()))}
            else:
                h = parse_hashes(v)
        else:
            h = parse_hashes(v)
        if h:
            out[p] = h
    return out


MAX_EVIDENCE = 500   # event refs kept per alert; "hits" still counts every repeat


class Engine:
    def __init__(self, cfg: dict, allow: AllowList, baseline: dict, sink: Sink | None = None):
        self.cfg = cfg
        self.prevent = cfg["mode"] == "prevent"
        self.allow = allow
        self.sink = sink or (lambda kind, rec: None)
        self.pt = ProcessTable()
        self.rules = [
            BruteForce(cfg, allow, self.prevent),
            TempService(cfg, allow, self.pt),
            OfficeShell(cfg, allow, self.pt),
            FIM(cfg, allow, baseline),
            Approvals(cfg, allow),
        ]
        self.min_sev = SEV_ORDER.index(cfg["alert_min_severity"])
        self.cooldown = float(cfg["cooldown_s"])
        self.chain_w = float(cfg["chain_window_s"])
        sc = cfg["scoring"]
        self.base = sc["base"]
        self.floor = sc["floor"]
        self.priv = set(sc["privileged_users"])
        self.block_rules = set(cfg["response"]["block_rules"])
        self.ttl = cfg["response"]["ttl_s"]
        self.alerts: dict[str, dict] = {}
        self.evidence: dict[str, set] = {}
        self.open: dict[tuple, str] = {}
        self.host_recent: dict[str, list] = {}
        self.blocks: list[dict] = []
        self.block_keys: dict[tuple, dict] = {}
        self.active_ip_blocks: dict[str, float] = {}
        self.volume = Counter()
        self.watch: list[dict] = []
        self.audit: list[dict] = []
        self.ids = itertools.count(1)
        self.bids = itertools.count(1)
        self.stats = {"events": 0, "by_category": {}, "dropped_after_block": 0, "ts_missing": 0}
        self._n = 0
        self.last_ts = 0.0

    # ------------------------------------------------------------------ input
    def process(self, ev: Event) -> None:
        self.stats["events"] += 1
        bc = self.stats["by_category"]
        bc[ev.category] = bc.get(ev.category, 0) + 1
        if ev.ts_missing:
            self.stats["ts_missing"] += 1
        if ev.ts is None:
            ev.ts = self.last_ts
        self.last_ts = max(self.last_ts, ev.ts)
        self.volume[int(ev.ts // 60)] += 1
        since = self.active_ip_blocks.get((ev.host, ev.src_ip))
        if since is not None and since <= ev.ts < since + self.ttl:
            self.stats["dropped_after_block"] += 1
        if ev.category == "process" and ev.action == "start":
            # rules read ancestry first, then the event joins the table
            outs = [r.on_event(ev) for r in self.rules]
            self.pt.add(ev)
        elif ev.category == "process" and ev.action == "end":
            self.pt.remove(ev)
            outs = []
        else:
            outs = [r.on_event(ev) for r in self.rules]
        for out in outs:
            for item in out:
                self._handle(item, ev)
        for item in self.rules[0].tick(ev.ts):
            self._handle(item, ev)
        self._n += 1
        if self._n % 5000 == 0:
            self.rules[0].sweep(self.last_ts)

    def finish(self) -> None:
        """End of stream: settle pending decisions."""
        for item in self.rules[0].finish():
            self._handle(item, None)

    # --------------------------------------------------------------- handlers
    def _handle(self, item, ev: Event) -> None:
        if isinstance(item, Candidate):
            self.accept(item)
        elif isinstance(item, Watch):
            rec = {"type": "watch", "rule": item.rule, "host": item.host, "ts": item.ts,
                   "note": item.note, "reason": item.note, "evidence": item.evidence, **item.context}
            self.watch.append(rec)
            self.sink("watch", rec)
        elif isinstance(item, Suppressed):
            rec = {"type": "suppressed", "rule": item.rule, "host": item.host, "ts": item.ts,
                   "reason": item.reason, "allowlist_entry": item.allow_entry,
                   "entry": item.allow_entry.get("ticket") or item.allow_entry,
                   "evidence": item.evidence, **item.context}
            self.audit.append(rec)
            self.sink("audit", rec)
        elif isinstance(item, PreBlock):
            self._block(item.action, item.target, item.reason, None, "high", item.ts, item.host,
                        item.evidence)

    def _score(self, c: Candidate) -> tuple[int, list]:
        sig = list(c.signals)
        if c.user and (c.user in self.priv or c.user.endswith("admin")):
            sig.append((f"privileged account: {c.user}", 15))
        if c.rule != "bruteforce" and c.src_ip and not is_private_ip(c.src_ip):
            sig.append(("external source IP", 10))
        for ts, rule, aid in self.host_recent.get(c.host, []):
            if rule != c.rule and 0 <= c.ts - ts <= self.chain_w:
                sig.append((f"chain: follows {rule} alert {aid} on same host", 20))
                break
        base = c.base_override if c.base_override is not None else self.base.get(c.rule, 50)
        score = base + sum(p for _, p in sig)
        score = max(self.floor, min(100, score))
        return int(score), [{"signal": "base:" + c.rule, "points": base}] + \
            [{"signal": s, "points": p} for s, p in sig]

    def accept(self, c: Candidate) -> None:
        """Score a confirmed candidate and publish its simulated response."""
        key = (c.rule, c.host, c.entity)
        aid = self.open.get(key)
        if aid is not None:
            a = self.alerts[aid]
            if a["first_seen"] - self.cooldown <= c.ts <= a["last_seen"] + self.cooldown:
                a["first_seen"] = min(a["first_seen"], c.ts)
                a["last_seen"] = max(a["last_seen"], c.ts)
                seen = self.evidence[aid]
                for ref in c.evidence:
                    if ref not in seen and len(seen) < MAX_EVIDENCE:
                        seen.add(ref)
                        a["evidence"].append(ref)
                a["hits"] += 1
                if c.escalates:
                    a.update(title=c.title, context=c.context, user=c.user, mitre=c.mitre)
                score, sigs = self._score(c)
                if score > a["score"]:
                    a["score"], a["signals"], a["severity"], a["context"] = score, sigs, sev_from_score(score), c.context
                self._respond(a, c)
                self.sink("alert_update", {"id": aid, "last_seen": a["last_seen"], "hits": a["hits"],
                                           "score": a["score"], "severity": a["severity"],
                                           "title": a["title"],
                                           "new_evidence": c.evidence})
                return
        score, sigs = self._score(c)
        sev = sev_from_score(score)
        if SEV_ORDER.index(sev) < self.min_sev:
            rec = {"type": "watch", "rule": c.rule, "host": c.host, "ts": c.ts,
                   "note": "below alert threshold: " + c.title, "reason": "below alert threshold: " + c.title,
                   "evidence": c.evidence, "score": score}
            self.watch.append(rec)
            self.sink("watch", rec)
            return
        aid = f"A{next(self.ids):04d}"
        a = {"id": aid, "rule": c.rule, "title": c.title, "host": c.host, "entity": c.entity,
             "first_seen": c.ts, "last_seen": c.ts, "score": score, "severity": sev,
             "signals": sigs, "mitre": c.mitre, "evidence": sorted(set(c.evidence)),
             "hits": 1, "user": c.user, "src_ip": c.src_ip, "context": c.context,
             "blocks": [], "would_block": [], "requested_blocks": [], "observations": []}
        self.alerts[aid] = a
        self.evidence[aid] = set(a["evidence"])
        self.open[key] = aid
        self.host_recent.setdefault(c.host, []).append((c.ts, c.rule, aid))
        self.host_recent[c.host] = [x for x in self.host_recent[c.host] if c.ts - x[0] <= self.chain_w]
        self._respond(a, c)
        self.sink("alert", a)

    def _respond(self, a: dict, c: Candidate) -> None:
        """Apply the block policy; also runs for merged hits, which can name new targets."""
        observation = {"timestamp": c.ts, "evidence": c.evidence, "blocks": []}
        a["observations"].append(observation)
        for action, target in c.blocks:
            if not target:
                continue
            request = {"action": action, "target": target}
            if request not in a["requested_blocks"]:
                a["requested_blocks"].append(request)
            if self.prevent and c.rule in self.block_rules:
                # A launch often carries a binary but no service name. Correlate it
                # with installation evidence for that same binary.
                service_binary = c.context.get("binary") if action == "disable_service" else None
                b = self._block(action, target, c.title, a["id"], a["severity"], c.ts, c.host, c.evidence,
                                service_binary=service_binary)
                if b["id"] not in a["blocks"]:
                    a["blocks"].append(b["id"])
                if b["id"] not in observation["blocks"]:
                    observation["blocks"].append(b["id"])
            elif {"action": action, "target": target} not in a["would_block"]:
                a["would_block"].append({"action": action, "target": target})

    def _block(self, action: str, target: str, reason: str, aid: str | None, sev: str,
               ts: float, host: str, evidence: list, *, service_binary=None) -> dict:
        key = (host, action, service_binary or target)
        if key in self.block_keys and 0 <= ts - self.block_keys[key]["ts"] < self.ttl:
            b = self.block_keys[key]
            if aid and aid not in b["alert_ids"]:
                b["alert_ids"].append(aid)
            if service_binary and b["target"] == service_binary and target != service_binary:
                b["target"] = target
            for ref in evidence:
                if len(b["evidence"]) < MAX_EVIDENCE and ref not in b["evidence"]:
                    b["evidence"].append(ref)
            return b
        kind = {"block_ip": "ip", "lock_account": "user", "restore_file": "path",
                "quarantine_file": "path", "deny_file_change": "path"}.get(action)
        protected = bool(kind and self.allow.protected(kind, target))
        b = {"id": f"B{next(self.bids):04d}", "ts": ts, "host": host, "action": action,
             "target": target, "reason": reason, "alert_ids": [aid] if aid else [],
             "severity": sev, "ttl_s": self.ttl, "evidence": list(evidence)[-20:],
             "status": "skipped_protected" if protected else "active", "simulated": True}
        self.block_keys[key] = b
        self.blocks.append(b)
        if action == "block_ip" and not protected:
            self.active_ip_blocks[host, target] = ts
        self.sink("block", b)
        return b

    # ----------------------------------------------------------------- output
    def incidents(self) -> list[dict]:
        """Group alerts per host when they fall within the chain window of each other."""
        by_host: dict[str, list] = {}
        for a in sorted(self.alerts.values(), key=lambda x: x["first_seen"]):
            by_host.setdefault(a["host"], []).append(a)
        out = []
        n = 1
        for host, al in by_host.items():
            cur: list = []
            for a in al:
                if cur and a["first_seen"] - max(x["last_seen"] for x in cur) > self.chain_w:
                    out.append(self._inc(n, host, cur)); n += 1; cur = []
                cur.append(a)
            if cur:
                out.append(self._inc(n, host, cur)); n += 1
        return out

    @staticmethod
    def _inc(n: int, host: str, al: list) -> dict:
        top = max(al, key=lambda x: x["score"])
        ids = [a["id"] for a in al]
        return {"id": f"I{n:03d}", "host": host, "alerts": ids, "alert_ids": ids,
                "first_seen": al[0]["first_seen"], "last_seen": max(a["last_seen"] for a in al),
                "rules": sorted({a["rule"] for a in al}), "start": al[0]["first_seen"],
                "end": max(a["last_seen"] for a in al), "max_score": top["score"],
                "severity": top["severity"], "multi_stage": len({a["rule"] for a in al}) > 1}
