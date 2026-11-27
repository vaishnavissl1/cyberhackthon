"""Default configuration and loaders (JSON always works; YAML if PyYAML is installed)."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    "mode": "prevent",                     # detect | prevent
    "reorder_slack_s": 5,                  # event-time watermark slack
    "idle_flush_s": 2,                     # wall-clock flush when following a quiet stream
    "dedup_window": 200000,                # LRU size for explicit event ids
    "alert_min_severity": "medium",        # emit alerts at or above this
    "cooldown_s": 900,                     # same rule+entity within this -> same alert
    "chain_window_s": 1800,
    "bruteforce": {
        "n_fail": 5, "window_s": 300, "success_within_s": 600,
        "spray_users": 5, "dist_sources": 3,
        "skip_machine_accounts": True,
        "preempt_block_factor": 0,         # optional failure-only block at n_fail*factor
    },
    "temp_service": {
        "temp_roots": [
            "/appdata/local/temp/", ":/windows/temp/", "/local settings/temp/",
            ":/temp/", ":/tmp/", "/users/_/appdata/local/temp/",
        ],
        "posix_temp_prefixes": ["/tmp/", "/var/tmp/", "/dev/shm/"],
        "extra_roots_medium": [],          # e.g. ["/users/public/", ":/programdata/"]
        "service_hosts": ["services", "systemd"],
    },
    "office_shell": {
        "office": ["winword", "excel", "powerpnt", "outlook", "msaccess", "mspub",
                   "onenote", "visio", "eqnedt32", "soffice.bin", "soffice", "wordpad"],
        "shells": ["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta",
                   "bash", "sh", "zsh", "dash", "wsl", "powershell_ise"],
        "lolbins": ["rundll32", "regsvr32", "certutil", "bitsadmin", "wmic", "msbuild",
                    "installutil", "regasm", "regsvcs", "schtasks"],
        "lolbins_enabled": False,
        "max_depth": 3,
    },
    "fim": {
        "critical_paths": [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
            "/etc/hosts", "/etc/crontab", "/root/.ssh/authorized_keys",
            "c:/windows/system32/drivers/etc/hosts", "c:/windows/system32/config/sam",
        ],
        "critical_prefixes": ["c:/windows/system32/", "/etc/pam.d/", "/bin/", "/sbin/",
                              "/usr/bin/", "/usr/sbin/"],
        "watched_dirs": [],                # new files under these are logged
        "learn_baseline": False,           # first-seen hash becomes baseline (flagged)
    },
    "scoring": {
        "base": {"bruteforce": 55, "temp_service": 60, "office_shell": 55, "fim": 50},
        "floor": 40,                       # a confirmed detection never drops below medium
        "privileged_users": ["administrator", "admin", "root", "system", "domain admins"],
    },
    "response": {
        # in prevent mode a confirmed detection from these rules ALWAYS writes its block
        "block_rules": ["bruteforce", "temp_service", "office_shell", "fim"],
        "ttl_s": 86400,
    },
}

SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def sev_from_score(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def deep_merge(a: dict, b: dict) -> dict:
    out = copy.deepcopy(a)
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_structured(path: str | Path | None) -> Any:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"config file not found: {p}")
    text = p.read_text(encoding="utf-8-sig")
    if p.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as e:
            raise SystemExit(f"{p} is YAML but PyYAML is not installed; use the .json form") from e
        return yaml.safe_load(text)
    return json.loads(text)


def load_config(path: str | None, overrides: dict | None = None) -> dict:
    cfg = deep_merge(DEFAULTS, load_structured(path) or {})
    return deep_merge(cfg, overrides or {})
