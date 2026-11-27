import unittest

from hids_agent.normalize import base, exe_from_cmd, norm_path, normalize, parse_hashes, parse_ts
from tests.helpers import T0, run_text


class TestNormalize(unittest.TestCase):
    def test_windows_4625(self):
        e = normalize({"EventRecordID": 77, "TimeCreated": "2026-11-20T08:00:00Z", "Computer": "DC01",
                       "EventID": 4625, "TargetUserName": "CORP\\Bob", "IpAddress": "::ffff:198.51.100.4",
                       "LogonType": 3}, 1)
        self.assertEqual((e.category, e.outcome, e.user, e.domain, e.src_ip, e.host),
                         ("auth", "failure", "bob", "corp", "198.51.100.4", "dc01"))
        self.assertEqual(e.ref, "id:77")

    def test_ecs_nested_process(self):
        e = normalize({"@timestamp": "2026-11-20T08:00:00Z", "event": {"id": "x1", "category": "process",
                       "action": "start"}, "host": {"name": "WS1"},
                       "process": {"pid": 200, "executable": "C:\\Windows\\System32\\cmd.exe",
                                   "command_line": "cmd /c whoami",
                                   "parent": {"pid": 100, "executable": "C:\\Office\\WINWORD.EXE"}}}, 1)
        self.assertEqual(e.category, "process")
        self.assertEqual((e.pid, e.ppid), ("200", "100"))
        self.assertEqual(base(e.image), "cmd")
        self.assertEqual(base(e.parent_image), "winword")
        self.assertEqual(e.ref, "id:x1")

    def test_sshd_lines(self):
        f = normalize({"ts": 1795161600, "host": "web", "type": "auth",
                       "message": "Failed password for invalid user oracle from 192.0.2.7 port 5000 ssh2"}, 1)
        self.assertEqual((f.outcome, f.user, f.src_ip), ("failure", "oracle", "192.0.2.7"))
        s = normalize({"ts": 1795161600, "host": "web",
                       "message": "Accepted publickey for deploy from 10.0.0.5 port 2222 ssh2"}, 2)
        self.assertEqual((s.category, s.outcome, s.user), ("auth", "success", "deploy"))

    def test_event_id_ambiguity(self):
        code = normalize({"event_id": 4625, "user": "a", "ts": 1}, 1)
        self.assertEqual((code.category, code.outcome), ("auth", "failure"))
        self.assertFalse(code.has_explicit_id)
        rid = normalize({"event_id": 11, "type": "auth", "outcome": "success", "user": "a", "ts": 1}, 1)
        self.assertEqual(rid.category, "auth")
        self.assertEqual(rid.ref, "id:11")

    def test_timestamps(self):
        self.assertEqual(parse_ts("2026-11-20T08:00:00Z"), T0)
        self.assertEqual(parse_ts("2026-11-20T13:30:00+05:30"), T0)
        self.assertEqual(parse_ts(T0), T0)
        self.assertEqual(parse_ts(T0 * 1000), T0)
        self.assertEqual(parse_ts(str(T0)), T0)
        self.assertEqual(parse_ts("2026-11-20 08:00:00"), T0)
        self.assertAlmostEqual(parse_ts("2026-11-20T08:00:00.1234567Z"), T0 + 0.123456, places=5)
        self.assertIsNone(parse_ts("not a time"))

    def test_paths(self):
        self.assertEqual(norm_path('"C:\\Windows\\Temp\\a.exe"'), "c:/windows/temp/a.exe")
        self.assertEqual(norm_path("\\??\\C:\\Temp\\x.exe"), "c:/temp/x.exe")
        self.assertIn("/appdata/local/temp/", norm_path("%TEMP%\\x.exe"))
        self.assertEqual(norm_path("C:\\DOCUME~1\\bob\\LOCALS~1\\Temp\\x.exe"),
                         "c:/documents and settings/bob/local settings/temp/x.exe")

    def test_exe_from_cmd(self):
        self.assertEqual(exe_from_cmd('"C:\\Program Files\\A B\\x.exe" -k svc'), "c:/program files/a b/x.exe")
        self.assertEqual(exe_from_cmd("C:\\Program Files\\Vendor\\agent.exe --run"), "c:/program files/vendor/agent.exe")
        self.assertEqual(exe_from_cmd("/tmp/.x/kworker -d"), "/tmp/.x/kworker")

    def test_hashes(self):
        h = parse_hashes("MD5=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,SHA256=" + "B" * 64)
        self.assertEqual(h["sha256"], "b" * 64)
        self.assertEqual(h["md5"], "a" * 32)
        self.assertEqual(parse_hashes("sha256:" + "c" * 64), {"sha256": "c" * 64})
        self.assertEqual(parse_hashes("d" * 40), {"sha1": "d" * 40})

    def test_labels_are_stripped(self):
        e = normalize({"ts": 1, "type": "auth", "outcome": "failure", "user": "x", "attack_id": "S1",
                       "label": "bruteforce", "is_attack": True}, 1)
        self.assertEqual(e.category, "auth")   # labels do not influence anything

    def test_missing_fields_do_not_crash(self):
        e = normalize({}, 5)
        self.assertEqual((e.category, e.ref, e.ts), ("other", "line:5", None))


class TestStreamInput(unittest.TestCase):
    def test_malformed_lines_counted(self):
        text = '{"id":1,"ts":1,"type":"auth","outcome":"failure","user":"a"}\n{bad json\n\n' \
               '"just a string"\n{"id":2,"ts":2,"type":"auth","outcome":"success","user":"a"}\n'
        eng, pipe = run_text(text)
        self.assertEqual(pipe.stats["malformed"], 2)
        self.assertEqual(eng.stats["events"], 2)

    def test_json_array_and_wrapper(self):
        eng, _ = run_text('[{"id":1,"ts":1,"type":"auth","outcome":"failure","user":"a"},\n'
                          ' {"id":2,"ts":2,"type":"auth","outcome":"success","user":"a"}]')
        self.assertEqual(eng.stats["events"], 2)
        eng, _ = run_text('{"events": [{"id":1,"ts":1,"type":"file","path":"/x"}]}')
        self.assertEqual(eng.stats["events"], 1)

    def test_bom_and_crlf(self):
        eng, pipe = run_text('\ufeff{"id":1,"ts":1,"type":"auth","outcome":"failure","user":"a"}\r\n')
        self.assertEqual((eng.stats["events"], pipe.stats["malformed"]), (1, 0))

    def test_empty_stream(self):
        eng, pipe = run_text("")
        self.assertEqual((eng.stats["events"], len(eng.alerts)), (0, 0))


if __name__ == "__main__":
    unittest.main()
