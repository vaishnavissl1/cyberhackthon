"""The three known gaps: unknown stream formats, distributed attacks with no
success, and users behind one shared address looking like a password spray."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hids_agent.normalize import configure, normalize
from tests.helpers import alerts, auth, ev, run

ROOT = Path(__file__).resolve().parent.parent
NAT = "198.51.100.20"
FAIL_ONLY = {"bruteforce": {"alert_without_success": True, "failures_without_success": 10}}


class TestSharedAddress(unittest.TestCase):
    def test_users_typo_then_log_in(self):
        e = []
        for i in range(6):
            e += [auth(i * 20, "failure", user=f"u{i}", ip=NAT), auth(i * 20 + 5, "success", user=f"u{i}", ip=NAT)]
        eng, _ = run(e)
        self.assertEqual(alerts(eng), [])

    def test_all_fail_first_then_all_log_in(self):
        e = [auth(i, "failure", user=f"u{i}", ip=NAT) for i in range(6)]
        e += [auth(30 + i * 10, "success", user=f"u{i}", ip=NAT) for i in range(6)]
        eng, _ = run(e)
        self.assertEqual(alerts(eng), [])
        self.assertTrue(any("not a spray" in w["note"] for w in eng.watch))

    def test_real_spray_still_alerts(self):
        e = [auth(i, "failure", user=f"u{i}", ip=NAT) for i in range(8)] + [auth(30, "success", user="u3", ip=NAT)]
        eng, _ = run(e)
        a = alerts(eng)
        self.assertEqual((len(a), a[0]["context"]["variant"]), (1, "spray"))
        self.assertIn("block_ip", [b["action"] for b in eng.blocks])

    def test_spray_alert_fires_live_after_grace_period(self):
        from hids_agent.agent import Outputs, Pipeline
        from hids_agent.allowlist import load_allowlist
        from hids_agent.config import load_config
        from hids_agent.engine import Engine, load_baseline
        cfg = load_config(None)
        eng = Engine(cfg, load_allowlist(None), load_baseline(None))
        pipe = Pipeline(eng, cfg, Outputs(None, quiet=True))
        e = [auth(i, "failure", user=f"u{i}", ip=NAT) for i in range(8)] + [auth(30, "success", user="u3", ip=NAT)]
        for i, x in enumerate(e, 1):
            pipe.push(i, x)
        pipe.flush()
        self.assertEqual(alerts(eng), [], "still inside the grace period")
        pipe.push(99, auth(200, "success", user="someone", ip="10.9.9.9"))   # unrelated, later traffic
        pipe.flush()
        self.assertEqual(len(alerts(eng)), 1, "alert must fire once time passes, before the stream ends")

    def test_classic_brute_force_is_not_delayed(self):
        e = [auth(i, "failure", user="bob", ip=NAT) for i in range(6)] + [auth(10, "success", user="bob", ip=NAT)]
        eng, _ = run(e)
        self.assertEqual(alerts(eng)[0]["context"]["variant"], "classic")

    def test_failed_only_spray_waits_too(self):
        e = [auth(i, "failure", user=f"u{i}", ip=NAT) for i in range(6)]
        e += [auth(30 + i * 5, "success", user=f"u{i}", ip=NAT) for i in range(6)]
        eng, _ = run(e, cfg=FAIL_ONLY)
        self.assertEqual(alerts(eng), [])
        eng, _ = run([auth(i, "failure", user=f"u{i}", ip=NAT) for i in range(6)], cfg=FAIL_ONLY)
        self.assertEqual(len(alerts(eng)), 1)


class TestDistributedWithoutSuccess(unittest.TestCase):
    def fails(self, n=12, sources=4, user="admin"):
        return [auth(i * 3, "failure", user=user, ip=f"203.0.113.{i % sources + 1}") for i in range(n)]

    def test_detected_when_option_on(self):
        eng, _ = run(self.fails(), cfg=FAIL_ONLY)
        a = alerts(eng)
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["context"]["variant"], "failed_only_distributed")
        self.assertEqual(len([b for b in eng.blocks if b["action"] == "block_ip"]), 4)

    def test_off_by_default(self):
        eng, _ = run(self.fails())
        self.assertEqual(alerts(eng), [])

    def test_below_thresholds(self):
        eng, _ = run(self.fails(n=9), cfg=FAIL_ONLY)
        self.assertEqual(alerts(eng), [])
        eng, _ = run(self.fails(n=12, sources=2), cfg=FAIL_ONLY)
        self.assertEqual(alerts(eng), [])

    def test_long_attack_stays_one_alert(self):
        eng, _ = run(self.fails(n=600), cfg=FAIL_ONLY)
        self.assertEqual(len(alerts(eng)), 1)


class TestSchemaConfig(unittest.TestCase):
    def tearDown(self):
        configure(None)

    SCHEMA = {"schema": {"field_aliases": {"user": ["acct"], "src_ip": ["origin"]},
                         "category_map": {"logon_evt": "auth", "proc_launch": "process"},
                         "outcome_map": {"0": "failure", "1": "success"}}}

    def odd(self, sec, outcome, **kw):
        return ev(sec, evt="logon_evt", acct="bob", origin="203.0.113.7", rc=outcome, **kw)

    def test_unknown_format_detected_after_mapping(self):
        cfg = dict(self.SCHEMA)
        cfg["schema"] = dict(cfg["schema"], field_aliases={**cfg["schema"]["field_aliases"],
                                                           "category": ["evt"], "outcome": ["rc"]})
        e = [self.odd(i, "0") for i in range(6)] + [self.odd(10, "1")]
        self.assertEqual(alerts(run(e)[0]), [], "without the mapping nothing is understood")
        eng, _ = run(e, cfg=cfg)
        self.assertEqual(len(alerts(eng)), 1)

    def test_bad_field_name_is_rejected(self):
        with self.assertRaises(ValueError):
            configure({"field_aliases": {"usr": ["acct"]}})

    def test_configured_alias_wins_over_builtin(self):
        configure({"field_aliases": {"user": ["real_user"]}})
        e = normalize({"ts": 1, "type": "auth", "outcome": "failure", "user": "svc", "real_user": "bob"}, 1)
        self.assertEqual(e.user, "bob")


class TestRealWorldSignals(unittest.TestCase):
    def test_office_outside_program_files_scores_higher(self):
        from tests.helpers import proc
        cmd = "C:\\Windows\\SysWOW64\\cmd.exe"
        normal = run([proc(0, cmd, 11, 10, parent="C:\\Program Files\\Microsoft Office\\WINWORD.EXE")])[0]
        # pattern from a real sideloading sample: fake WINWORD.exe in AppData\Roaming
        fake = run([proc(0, cmd, 11, 10, parent="C:\\Users\\IEUser\\AppData\\Roaming\\WINWORD.exe")])[0]
        a, b = alerts(normal)[0], alerts(fake)[0]
        self.assertGreater(b["score"], a["score"])
        self.assertTrue(any("unusual folder" in s["signal"] for s in b["signals"]))
        self.assertFalse(any("unusual folder" in s["signal"] for s in a["signals"]))


class TestInspectStream(unittest.TestCase):
    def cli(self, events, *args):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.jsonl"
            p.write_text("".join(json.dumps(e) + "\n" for e in events) + "{bad\n", encoding="utf-8")
            r = subprocess.run([sys.executable, "-m", "hids_agent.inspect_stream", str(p), *args],
                               capture_output=True, text=True, cwd=ROOT, timeout=30, encoding="utf-8")
        return r

    def test_reports_problems(self):
        r = self.cli([{"id": 1, "ts": 1, "evt": "logon_evt", "acct": "bob"},
                      {"id": 2, "ts": 2, "type": "process", "image": "c:/x.exe"}])
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("UNCLASSIFIED", r.stdout)
        self.assertIn("evt=logon_evt", r.stdout)
        self.assertIn("missing (optional) in process events: pid (1), ppid (1)", r.stdout)
        self.assertIn("acct", r.stdout)
        self.assertIn("malformed 1", r.stdout)

    def test_clean_stream_passes(self):
        r = self.cli([{"id": 1, "ts": 1, "type": "auth", "user": "bob", "outcome": "failure", "src_ip": "10.0.0.1"}])
        self.assertIn("RESULT: OK", r.stdout, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
