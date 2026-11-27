import unittest

from tests.helpers import alerts, auth, ev, fevt, proc, run

OLD, NEW, APPROVED = "a" * 64, "b" * 64, "c" * 64
WORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
CMD = "C:\\Windows\\System32\\cmd.exe"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
SERVICES = "C:\\Windows\\System32\\services.exe"
TEMPBIN = "C:\\Windows\\Temp\\upd\\svc.exe"


def fails(n, start=0, step=2, **kw):
    return [auth(start + i * step, "failure", **kw) for i in range(n)]


class TestBruteForce(unittest.TestCase):
    def test_threshold(self):
        eng, _ = run(fails(4) + [auth(20, "success")])
        self.assertEqual(alerts(eng), [])
        eng, _ = run(fails(5) + [auth(20, "success")])
        self.assertEqual(len(alerts(eng, "bruteforce")), 1)
        self.assertIn(("block_ip", "203.0.113.9"), [(b["action"], b["target"]) for b in eng.blocks])

    def test_failures_without_success_are_not_alerts(self):
        eng, _ = run(fails(8))
        self.assertEqual(alerts(eng), [])
        self.assertTrue(eng.watch)

    def test_slow_failures_do_not_accumulate(self):
        eng, _ = run(fails(5, step=400) + [auth(2100, "success")])
        self.assertEqual(alerts(eng), [])

    def test_success_too_late(self):
        eng, _ = run(fails(6) + [auth(800, "success")])
        self.assertEqual(alerts(eng), [])

    def test_success_from_other_ip(self):
        eng, _ = run(fails(6) + [auth(20, "success", ip="10.0.0.7")])
        self.assertEqual(alerts(eng), [])

    def test_hosts_are_independent(self):
        ev_ = fails(3) + fails(3, start=10, host="h2") + [auth(30, "success")]
        eng, _ = run(ev_)
        self.assertEqual(alerts(eng), [])

    def test_username_case_and_domain(self):
        users = ["CORP\\Alice", "alice", "ALICE", "alice@corp", "Alice"]
        eng, _ = run([auth(i, "failure", user=u) for i, u in enumerate(users)] + [auth(9, "success")])
        self.assertEqual(len(alerts(eng)), 1)

    def test_spray(self):
        eng, _ = run([auth(i, "failure", user=f"u{i}") for i in range(6)] + [auth(30, "success", user="u3")])
        self.assertEqual(alerts(eng)[0]["context"]["variant"], "spray")

    def test_distributed(self):
        e = [auth(i, "failure", ip=f"198.51.100.{i % 3}") for i in range(6)]
        eng, _ = run(e + [auth(30, "success", ip="198.51.100.1")])
        self.assertEqual(alerts(eng)[0]["context"]["variant"], "distributed")

    def test_no_source_ip_still_detects_per_user(self):
        eng, _ = run(fails(5, ip=None) + [auth(20, "success", ip=None)])
        self.assertEqual(len(alerts(eng)), 1)

    def test_local_typos_by_many_users_are_not_a_spray(self):
        e = [auth(i, "failure", user=f"u{i}", ip=None) for i in range(6)]
        eng, _ = run(e + [auth(30, "success", user="u1", ip=None)])
        self.assertEqual(alerts(eng), [])

    def test_late_event_order(self):
        e = fails(5, start=100) + [auth(120, "success")]
        e[0], e[4] = e[4], e[0]
        eng, _ = run(e)
        self.assertEqual(len(alerts(eng)), 1)

    def test_one_alert_per_burst_and_new_alert_after_cooldown(self):
        e = fails(5) + [auth(20, "success"), auth(21, "success")]
        e += fails(5, start=3000) + [auth(3030, "success")]
        eng, _ = run(e)
        self.assertEqual(len(alerts(eng)), 2)

    def test_machine_account_skipped(self):
        eng, _ = run(fails(6, user="ws1$") + [auth(20, "success", user="ws1$")])
        self.assertEqual(alerts(eng), [])

    def test_allowlisted_source_is_audited(self):
        eng, _ = run(fails(25) + [auth(60, "success")], allow={"auth": [{"src_ip": "203.0.113.9/32"}]})
        self.assertEqual((alerts(eng), eng.blocks), ([], []))
        self.assertEqual(len(eng.audit), 1)


class TestOfficeShell(unittest.TestCase):
    def test_chain_is_one_alert(self):
        e = [proc(0, WORD, 10, 1), proc(1, CMD, 11, 10, cmd="cmd /c x"),
             proc(2, PS, 12, 11, parent=CMD, cmd="powershell -enc SQBFAFgA")]
        eng, _ = run(e)
        a = alerts(eng, "office_shell")
        self.assertEqual((len(a), a[0]["hits"]), (1, 2))

    def test_merged_hit_still_blocks_new_process(self):
        e = [proc(0, WORD, 10, 1), proc(1, CMD, 11, 10), proc(2, PS, 12, 11)]
        eng, _ = run(e)
        self.assertIn("h1:12", [b["target"] for b in eng.blocks])

    def test_grandchild_when_office_start_not_seen(self):
        e = [proc(0, "C:\\Tools\\helper.exe", 11, 10, parent=WORD), proc(1, PS, 12, 11)]
        eng, _ = run(e)
        self.assertEqual(len(alerts(eng, "office_shell")), 1)

    def test_benign_children(self):
        e = [proc(0, WORD, 10, 1), proc(1, "C:\\Windows\\splwow64.exe", 11, 10),
             proc(2, "C:\\Program Files\\Google\\chrome.exe", 12, 10),
             proc(3, CMD, 20, 2, parent="C:\\Windows\\explorer.exe")]
        eng, _ = run(e)
        self.assertEqual(alerts(eng), [])

    def test_pid_reuse(self):
        e = [proc(0, WORD, 10, 1), proc(100, "C:\\Windows\\notepad.exe", 10, 2),
             proc(101, CMD, 11, 10)]
        eng, _ = run(e)
        self.assertEqual(alerts(eng), [])

    def test_process_end_frees_pid(self):
        end = proc(50, WORD, 10, 1)
        end["action"] = "end"
        eng, _ = run([proc(0, WORD, 10, 1), end, proc(101, CMD, 11, 10)])
        self.assertEqual(alerts(eng), [])

    def test_stale_pid_does_not_override_stated_parent(self):
        e = [proc(0, WORD, 9, 1), proc(1, "C:\\x\\a.exe", 10, 9),
             proc(200, CMD, 11, 10, parent="C:\\Windows\\explorer.exe")]
        eng, _ = run(e)
        self.assertEqual(alerts(eng), [])

    def test_allowlisted_macro(self):
        allow = {"process": [{"parent": "excel.exe", "child": "cmd.exe",
                              "cmdline_regex": r"^cmd /c .*report\.bat$"}]}
        excel = "C:\\Office\\EXCEL.EXE"
        eng, _ = run([proc(0, CMD, 11, 10, parent=excel, cmd="cmd /c z:\\report.bat")], allow=allow)
        self.assertEqual((alerts(eng), len(eng.audit)), ([], 1))
        eng, _ = run([proc(0, CMD, 11, 10, parent=excel, cmd="cmd /c z:\\report.bat & calc")], allow=allow)
        self.assertEqual(len(alerts(eng)), 1)

    def test_libreoffice(self):
        eng, _ = run([proc(0, "/bin/sh", 11, 10, parent="/usr/lib/libreoffice/program/soffice.bin")])
        self.assertEqual(len(alerts(eng)), 1)


class TestTempService(unittest.TestCase):
    def one(self, events, **kw):
        eng, _ = run(events, **kw)
        return eng, alerts(eng, "temp_service")

    def test_service_host_spawn(self):
        _, a = self.one([proc(0, TEMPBIN, 50, 4, parent=SERVICES)])
        self.assertEqual(len(a), 1)

    def test_parent_known_only_by_pid(self):
        _, a = self.one([proc(0, SERVICES, 4, 1), proc(1, TEMPBIN, 50, 4)])
        self.assertEqual(len(a), 1)

    def test_systemd_from_tmp(self):
        _, a = self.one([proc(0, "/tmp/.x/kworker", 900, 1, parent="/usr/lib/systemd/systemd")])
        self.assertEqual(len(a), 1)

    def test_sc_create_then_spawn_is_one_alert(self):
        e = [proc(0, "C:\\Windows\\System32\\sc.exe", 60, 2,
                  cmd=f'sc create updsvc binPath= "{TEMPBIN} -k" start= auto'),
             proc(5, TEMPBIN, 61, 4, parent=SERVICES, sha256=NEW)]
        eng, a = self.one(e)
        self.assertEqual((len(a), a[0]["hits"]), (1, 2))
        self.assertIn(("block_hash", NEW), [(b["action"], b["target"]) for b in eng.blocks])

    def test_sc_inside_cmd(self):
        e = [proc(0, CMD, 60, 2, cmd="cmd /c sc.exe create x binPath= C:\\Windows\\Temp\\a.exe")]
        _, a = self.one(e)
        self.assertEqual(len(a), 1)

    def test_powershell_new_service(self):
        e = [proc(0, PS, 60, 2, cmd='powershell New-Service -Name bad -BinaryPathName "%TEMP%\\a.exe"')]
        _, a = self.one(e)
        self.assertEqual(len(a), 1)

    def test_service_event_with_env_path(self):
        _, a = self.one([ev(0, type="service", service_name="x", ImagePath="%SystemRoot%\\Temp\\x.exe")])
        self.assertEqual(len(a), 1)

    def test_windows_7045_raw(self):
        raw = {"EventRecordID": 9, "EventID": 7045, "TimeCreated": "2026-11-20T08:00:00Z",
               "Computer": "s1", "ServiceName": "p", "ImagePath": "\\??\\C:\\Windows\\Temp\\p.sys"}
        _, a = self.one([raw])
        self.assertEqual(len(a), 1)

    def test_unit_file_with_temp_exec(self):
        e = [fevt(0, "/etc/systemd/system/evil.service", "create", exec_start="/tmp/evil -d")]
        _, a = self.one(e)
        self.assertEqual(len(a), 1)

    def test_benign(self):
        e = [proc(0, "C:\\Program Files\\Vendor\\agent.exe", 70, 4, parent=SERVICES),
             proc(1, "C:\\Windows\\System32\\sc.exe", 71, 2,
                  cmd='sc create v binPath= "C:\\Program Files\\Vendor\\agent.exe"'),
             fevt(2, "/tmp/build.log", "create"),
             proc(3, "C:\\Windows\\Temp\\setup.exe", 72, 2, parent="C:\\Windows\\explorer.exe"),
             ev(4, type="service", action="stop", service_name="x", ImagePath="C:\\Windows\\Temp\\x.exe")]
        _, a = self.one(e)
        self.assertEqual(a, [])

    def test_allowlisted_service(self):
        allow = {"services": [{"name": "patch", "path": "c:/windows/temp/patch/p.exe"}]}
        e = [ev(0, type="service", service_name="patch", ImagePath="C:\\Windows\\Temp\\patch\\p.exe")]
        eng, a = self.one(e, allow=allow)
        self.assertEqual((a, len(eng.audit)), ([], 1))


class TestFIM(unittest.TestCase):
    BASE = {"/etc/passwd": OLD, "/opt/app/app.conf": OLD}

    def test_noncritical_change_still_alerts(self):
        eng, _ = run([fevt(0, "/opt/app/app.conf", sha256=NEW)], baseline=self.BASE)
        a = alerts(eng, "fim")
        self.assertEqual(len(a), 1)
        self.assertIn(a[0]["severity"], ("medium", "high", "critical"))
        self.assertTrue(eng.blocks)

    def test_same_hash_and_reads_are_quiet(self):
        e = [fevt(0, "/etc/passwd", sha256=OLD), fevt(1, "/etc/passwd", "read"),
             fevt(2, "/etc/other", sha256=NEW)]
        eng, _ = run(e, baseline=self.BASE)
        self.assertEqual(alerts(eng), [])

    def test_delete_rename_chmod_unverified(self):
        for e in (fevt(0, "/etc/passwd", "delete"),
                  fevt(0, "/etc/passwd", "rename", new_path="/tmp/p"),
                  fevt(0, "/etc/passwd", "chmod"),
                  fevt(0, "/etc/passwd"),
                  fevt(0, "/etc/passwd", md5="d" * 32)):
            eng, _ = run([e], baseline=self.BASE)
            self.assertEqual(len(alerts(eng, "fim")), 1, e)

    def test_rename_onto_baselined_file(self):
        eng, _ = run([fevt(0, "/tmp/evil", "rename", sha256=NEW, new_path="/etc/passwd")], baseline=self.BASE)
        self.assertEqual(alerts(eng, "fim")[0]["entity"], "/etc/passwd")

    def test_approved_then_unapproved(self):
        allow = {"fim": [{"path": "/opt/app/app.conf", "hash": APPROVED}]}
        e = [fevt(0, "/opt/app/app.conf", sha256=APPROVED), fevt(10, "/opt/app/app.conf", sha256=NEW)]
        eng, _ = run(e, allow=allow, baseline=self.BASE)
        self.assertEqual((len(eng.audit), len(alerts(eng, "fim"))), (1, 1))

    def test_expired_allow_entry(self):
        allow = {"fim": [{"path": "/etc/passwd", "hash": NEW, "expires": "2020-01-01T00:00:00Z"}]}
        eng, _ = run([fevt(0, "/etc/passwd", sha256=NEW)], allow=allow, baseline=self.BASE)
        self.assertEqual(len(alerts(eng)), 1)

    def test_per_host_baseline(self):
        base = {"hosts": {"h1": {"/etc/app": OLD}, "h2": {"/etc/app": NEW}}}
        e = [fevt(0, "/etc/app", sha256=OLD), fevt(1, "/etc/app", sha256=NEW, host="h2")]
        eng, _ = run(e, baseline=base)
        self.assertEqual(alerts(eng), [])

    def test_no_baseline(self):
        eng, _ = run([fevt(0, "/etc/passwd", sha256=NEW)])
        self.assertEqual(alerts(eng), [])


class TestResponseAndPipeline(unittest.TestCase):
    def test_detect_mode_writes_no_blocks(self):
        eng, _ = run(fails(25) + [auth(60, "success")], mode="detect")
        self.assertEqual((len(alerts(eng)), eng.blocks), (1, []))
        self.assertTrue(alerts(eng)[0]["would_block"])

    def test_protected_target(self):
        eng, _ = run(fails(5) + [auth(20, "success")], allow={"never_block": {"ips": ["203.0.113.0/24"]}})
        b = [b for b in eng.blocks if b["action"] == "block_ip"][0]
        self.assertEqual(b["status"], "skipped_protected")

    def test_duplicates_by_id_dropped_but_idless_kept(self):
        one = auth(0, "failure")
        eng, pipe = run([one, dict(one), dict(one)])
        self.assertEqual(pipe.stats["duplicates"], 2)
        same = [auth(0, "failure", id=None) for _ in range(5)] + [auth(1, "success", id=None)]
        eng, pipe = run(same)
        self.assertEqual((pipe.stats["duplicates"], len(alerts(eng))), (0, 1))

    def test_missing_timestamp_counted(self):
        e = auth(0, "failure")
        del e["timestamp"]
        eng, _ = run([auth(0, "failure"), e])
        self.assertEqual(eng.stats["ts_missing"], 1)


if __name__ == "__main__":
    unittest.main()
