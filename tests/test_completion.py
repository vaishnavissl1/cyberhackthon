"""Approval events, alerting on failed-only brute force, baseline export and
allow-list strictness."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import alerts, auth, ev, fevt, proc, run

ROOT = Path(__file__).resolve().parent.parent
OLD, NEW, EVIL = "a" * 64, "b" * 64, "e" * 64
EXCEL, CMD = "C:\\Office\\EXCEL.EXE", "C:\\Windows\\System32\\cmd.exe"
MACRO = "cmd /c z:\\macros\\report.bat"
ON = {"approvals": {"from_stream": True, "trusted_approvers": ["change-board"]}}
BASE = {"/etc/app.conf": OLD}


def approval(sec, by="change-board", **kw):
    return ev(sec, type="change_approval", approved_by=by, ticket="CHG-1", **kw)


class TestStreamApprovals(unittest.TestCase):
    def change(self, sec=10, h=NEW, **kw):
        return fevt(sec, "/etc/app.conf", sha256=h, **kw)

    def go(self, events, cfg=ON, baseline=BASE, **kw):
        return run(events, cfg=cfg, baseline=baseline, **kw)[0]

    def test_off_by_default(self):
        eng = self.go([approval(0, path="/etc/app.conf", sha256=NEW), self.change()], cfg=None)
        self.assertEqual(len(alerts(eng)), 1)
        self.assertTrue(any("from_stream is off" in w["note"] for w in eng.watch))

    def test_trusted_file_approval_suppresses_only_that_hash(self):
        eng = self.go([approval(0, path="/etc/app.conf", sha256=NEW), self.change(),
                       self.change(20, EVIL)])
        self.assertEqual((len(eng.audit), len(alerts(eng, "fim"))), (1, 1))
        self.assertEqual(alerts(eng)[0]["context"]["observed"], EVIL)

    def test_untrusted_or_missing_approver_is_rejected(self):
        for by in ("mallory", None):
            eng = self.go([approval(0, by=by, path="/etc/app.conf", sha256=NEW), self.change()])
            self.assertEqual(len(alerts(eng)), 1, by)
            self.assertTrue(any("rejected" in w["note"] for w in eng.watch))

    def test_empty_trust_list_trusts_nobody(self):
        eng = self.go([approval(0, path="/etc/app.conf", sha256=NEW), self.change()],
                      cfg={"approvals": {"from_stream": True}})
        self.assertEqual(len(alerts(eng)), 1)

    def test_not_retroactive(self):
        eng = self.go([self.change(0), approval(30, path="/etc/app.conf", sha256=NEW)])
        self.assertEqual(len(alerts(eng)), 1)

    def test_expiry_and_ttl_cap(self):
        eng = self.go([approval(0, path="/etc/app.conf", sha256=NEW), self.change(3700)])
        self.assertEqual(len(alerts(eng)), 1, "default lifetime is one hour")
        eng = self.go([approval(0, path="/etc/app.conf", sha256=NEW, expires="2099-01-01T00:00:00Z"),
                       self.change(90000)])
        self.assertEqual(len(alerts(eng)), 1, "lifetime is capped at one day")

    def test_scoped_to_its_host(self):
        eng = self.go([approval(0, path="/etc/app.conf", sha256=NEW), self.change(host="h2")])
        self.assertEqual(len(alerts(eng)), 1)

    def test_too_broad_approvals_are_rejected(self):
        for kw in ({"path": "/etc/*", "sha256": NEW}, {"path": "/etc/app.conf"},
                   {"src_ip": "10.0.0.0/8"}, {"image": CMD}):
            eng = self.go([approval(0, **kw)])
            self.assertTrue(any("rejected" in w["note"] for w in eng.watch), kw)
            self.assertEqual(eng.allow.fim + eng.allow.auth + eng.allow.process, [], kw)

    def test_process_approval_matches_exact_command_only(self):
        ok = approval(0, parent_image=EXCEL, image=CMD, cmdline=MACRO)
        eng = self.go([ok, proc(5, CMD, 11, 10, parent=EXCEL, cmd=MACRO)])
        self.assertEqual((alerts(eng), len(eng.audit)), ([], 1))
        eng = self.go([ok, proc(5, CMD, 11, 10, parent=EXCEL, cmd=MACRO + " & calc")])
        self.assertEqual(len(alerts(eng)), 1)

    def test_service_and_auth_approvals(self):
        tmp = "C:\\Windows\\Temp\\patch\\p.exe"
        eng = self.go([approval(0, service_name="patch", ImagePath=tmp),
                       ev(5, type="service", service_name="patch", ImagePath=tmp)])
        self.assertEqual((alerts(eng), len(eng.audit)), ([], 1))
        e = [approval(0, src_ip="203.0.113.9")]
        e += [auth(1 + i, "failure") for i in range(6)] + [auth(20, "success")]
        eng = self.go(e)
        self.assertEqual((alerts(eng), eng.blocks), ([], []))


class TestFailedOnlyBruteForce(unittest.TestCase):
    ON = {"bruteforce": {"alert_without_success": True, "failures_without_success": 10}}

    def fails(self, n, start=0, step=2, **kw):
        return [auth(start + i * step, "failure", **kw) for i in range(n)]

    def go(self, events, **kw):
        kw.setdefault("cfg", self.ON)
        return run(events, **kw)[0]

    def test_off_by_default(self):
        self.assertEqual(alerts(self.go(self.fails(30), cfg=None)), [])

    def test_threshold(self):
        self.assertEqual(alerts(self.go(self.fails(9))), [])
        eng = self.go(self.fails(10))
        self.assertEqual(len(alerts(eng)), 1)
        self.assertEqual(alerts(eng)[0]["context"]["variant"], "failed_only")
        self.assertIn("block_ip", [b["action"] for b in eng.blocks])
        self.assertNotIn("lock_account", [b["action"] for b in eng.blocks])

    def test_long_flood_is_one_alert(self):
        eng = self.go(self.fails(900, step=2))          # 30 minutes, longer than the cooldown
        self.assertEqual(len(alerts(eng)), 1)

    def test_later_success_upgrades_the_same_alert(self):
        eng = self.go(self.fails(12) + [auth(40, "success")])
        a = alerts(eng)
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["context"]["variant"], "classic")
        self.assertIn("then success", a[0]["title"])
        self.assertIn("lock_account", [b["action"] for b in eng.blocks])

    def test_spray_without_success(self):
        eng = self.go([auth(i, "failure", user=f"u{i}") for i in range(6)])
        self.assertEqual(len(alerts(eng)), 1)

    def test_slow_failures_stay_quiet(self):
        self.assertEqual(alerts(self.go(self.fails(20, step=120))), [])

    def test_second_attack_after_quiet_period(self):
        eng = self.go(self.fails(10) + self.fails(10, start=5000))
        self.assertEqual(len(alerts(eng)), 2)

    def test_allowlisted_scanner_is_audited_once(self):
        eng = self.go(self.fails(40), allow={"auth": [{"src_ip": "203.0.113.9/32"}]})
        self.assertEqual((alerts(eng), eng.blocks, len(eng.audit)), ([], [], 1))


class TestWindowBoundary(unittest.TestCase):
    def test_five_failures_spanning_exactly_the_window(self):
        for last, expected in ((300, 1), (301, 0)):
            e = [auth(t, "failure") for t in (0, 75, 150, 225, last)] + [auth(last + 5, "success")]
            self.assertEqual(len(alerts(run(e)[0])), expected, last)


class TestAllowListStrictness(unittest.TestCase):
    def shell(self, allow):
        return run([proc(0, CMD, 11, 10, parent=EXCEL, cmd=MACRO)], allow=allow)[0]

    def test_incomplete_process_entries_are_ignored(self):
        for entry in ({}, {"parent": "excel.exe"}, {"parent": "excel.exe", "child": "cmd.exe"},
                      {"parent": "excel.exe", "child": "cmd.exe", "cmdline": "typo key"}):
            self.assertEqual(len(alerts(self.shell({"process": [entry]}))), 1, entry)

    def test_regex_must_match_the_whole_command(self):
        entry = {"parent": "excel.exe", "child": "cmd.exe", "cmdline_regex": "report"}
        self.assertEqual(len(alerts(self.shell({"process": [entry]}))), 1)

    def test_approved_service_started_by_services_exe(self):
        allow = {"services": [{"name": "patch", "path": "c:/windows/temp/patch/p.exe"}]}
        services = "C:\\Windows\\System32\\services.exe"
        for image, expected in (("C:\\Windows\\Temp\\patch\\p.exe", 0), ("C:\\Windows\\Temp\\evil.exe", 1)):
            eng = run([proc(0, image, 50, 4, parent=services)], allow=allow)[0]
            self.assertEqual(len(alerts(eng)), expected, image)

    def test_same_path_under_another_service_name_alerts(self):
        allow = {"services": [{"name": "patch", "path": "c:/windows/temp/patch/p.exe"}]}
        e = [ev(0, type="service", service_name="other", ImagePath="C:\\Windows\\Temp\\patch\\p.exe")]
        self.assertEqual(len(alerts(run(e, allow=allow)[0])), 1)

    def test_host_scoped_entry(self):
        allow = {"fim": [{"path": "/etc/app.conf", "hash": NEW, "host": "h1"}]}
        e = [fevt(0, "/etc/app.conf", sha256=NEW), fevt(1, "/etc/app.conf", sha256=NEW, host="h2")]
        eng = run(e, allow=allow, baseline=BASE)[0]
        self.assertEqual([a["host"] for a in alerts(eng)], ["h2"])

    def test_service_entry_needs_a_path(self):
        e = [ev(0, type="service", service_name="patch", ImagePath="C:\\Windows\\Temp\\evil.exe")]
        self.assertEqual(len(alerts(run(e, allow={"services": [{"name": "patch"}]})[0])), 1)


class TestSaveBaseline(unittest.TestCase):
    def test_learn_save_and_reuse(self):
        def cli(args, events):
            return subprocess.run([sys.executable, "-m", "hids_agent.agent", "-q", *args],
                                  input="".join(json.dumps(e) + "\n" for e in events),
                                  capture_output=True, text=True, cwd=ROOT, timeout=30)

        with tempfile.TemporaryDirectory() as d:
            saved = str(Path(d) / "learned.json")
            r = cli(["--learn-baseline", "--save-baseline", saved, "--out", str(Path(d) / "a")],
                    [fevt(0, "/etc/app.conf", sha256=OLD), fevt(1, "C:\\App\\x.ini", sha256=NEW, host="h2")])
            self.assertEqual(r.returncode, 0, r.stderr)
            r = cli(["--baseline", saved, "--out", str(Path(d) / "b")],
                    [fevt(0, "/etc/app.conf", sha256=OLD), fevt(5, "/etc/app.conf", sha256=EVIL),
                     fevt(9, "C:\\App\\x.ini", sha256=NEW, host="h2")])
            self.assertEqual(r.returncode, 0, r.stderr)
            found = json.loads((Path(d) / "b" / "alerts.json").read_text())
        self.assertEqual([a["entity"] for a in found], ["/etc/app.conf"])


if __name__ == "__main__":
    unittest.main()
