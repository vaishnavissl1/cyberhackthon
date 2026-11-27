"""Regression tests for real-world field layouts and input handling."""
import json
import queue
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hids_agent.agent import EOF, stream_reader
from hids_agent.normalize import base, normalize
from tests.helpers import run_text

ROOT = Path(__file__).resolve().parent.parent


class TestWindowsAndSchema(unittest.TestCase):
    def test_4688_process_ids(self):
        e = normalize({"EventID": 4688, "TimeCreated": 1, "ProcessId": "0x1f4", "NewProcessId": "0x2a8",
                       "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                       "ParentProcessName": "C:\\Office\\WINWORD.EXE"}, 1)
        self.assertEqual((e.pid, e.ppid), ("0x2a8", "0x1f4"))

    def test_nested_parent_listed_first(self):
        e = normalize({"ts": 1, "type": "process", "process": {
            "parent": {"pid": 1, "command_line": "winword.exe /n", "executable": "c:/o/winword.exe"},
            "pid": 2, "command_line": "cmd /c whoami", "executable": "c:/w/cmd.exe"}}, 1)
        self.assertEqual((e.pid, e.cmdline, base(e.image)), ("2", "cmd /c whoami", "cmd"))

    def test_auth_with_service_field_stays_auth(self):
        e = normalize({"ts": 1, "user": "bob", "outcome": "failure", "service": "sshd",
                       "src_ip": "10.0.0.1"}, 1)
        self.assertEqual(e.category, "auth")

    def test_unsuccessful_is_failure(self):
        for word in ("unsuccessful", "FAILED", "denied", "Access not allowed", "wrong password"):
            self.assertEqual(normalize({"ts": 1, "type": "auth", "result": word}, 1).outcome, "failure", word)

    def test_sysmon_delete_with_text_category(self):
        e = normalize({"ts": 1, "EventID": 23, "provider": "Microsoft-Windows-Sysmon", "type": "file",
                       "TargetFilename": "C:\\x"}, 1)
        self.assertEqual(e.action, "delete")


class TestReader(unittest.TestCase):
    def test_pretty_printed_array(self):
        text = json.dumps([{"id": i, "ts": i, "type": "auth", "outcome": "failure", "user": "a"}
                           for i in range(1, 4)], indent=2)
        eng, pipe = run_text(text)
        self.assertEqual((eng.stats["events"], pipe.stats["malformed"]), (3, 0))

    def test_pretty_printed_wrapper(self):
        eng, pipe = run_text(json.dumps({"events": [{"id": 1, "ts": 1, "type": "file", "path": "/a"}]}, indent=2))
        self.assertEqual((eng.stats["events"], pipe.stats["malformed"]), (1, 0))

    def test_bom_before_array(self):
        eng, pipe = run_text('\ufeff[{"id":1,"ts":1,"type":"file","path":"/a"}]')
        self.assertEqual((eng.stats["events"], pipe.stats["malformed"]), (1, 0))

    def test_array_is_streamed_before_it_closes(self):
        class Live:
            """A pipe that delivers an unterminated array and then fails if read to the end."""
            def __init__(self):
                self.lines = iter(['[\n', '{"id":1},\n', '{"id":2},\n'])
                self.buf = ""

            def read(self, n=-1):
                assert n == 1, "reader must not wait for the whole stream"
                if not self.buf:
                    self.buf = next(self.lines, "")
                c, self.buf = self.buf[:1], self.buf[1:]
                return c

            def readline(self):
                if self.buf:
                    line, self.buf = self.buf, ""
                    return line
                return next(self.lines, "")

        q: queue.Queue = queue.Queue()
        stream_reader(Live(), q, [0])
        got = []
        while (item := q.get_nowait()) is not EOF:
            got.append(item[1])
        self.assertEqual(got, [{"id": 1}, {"id": 2}])


class TestCommandLine(unittest.TestCase):
    def cli(self, args, stdin=""):
        return subprocess.run([sys.executable, "-m", "hids_agent.agent", *args], input=stdin,
                              capture_output=True, text=True, cwd=ROOT, timeout=30)

    def test_missing_input_file_exits_with_error(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.cli(["--input", str(Path(d) / "nope.jsonl"), "--out", d, "-q"])
        self.assertNotEqual(r.returncode, 0)

    def test_pipe_end_to_end(self):
        lines = [json.dumps({"id": i, "ts": 1000 + i, "host": "a", "type": "auth", "outcome": "failure",
                             "user": "u", "src_ip": "203.0.113.5"}) for i in range(6)]
        lines.append(json.dumps({"id": 99, "ts": 1020, "host": "a", "type": "auth", "outcome": "success",
                                 "user": "u", "src_ip": "203.0.113.5"}))
        with tempfile.TemporaryDirectory() as d:
            r = self.cli(["--out", d, "-q"], "\n".join(lines) + "\n")
            self.assertEqual(r.returncode, 0, r.stderr)
            a = json.loads((Path(d) / "alerts.json").read_text())
            blocks = (Path(d) / "blocklist.jsonl").read_text().strip().splitlines()
        self.assertEqual((len(a), a[0]["rule"]), (1, "bruteforce"))
        self.assertTrue(blocks)


if __name__ == "__main__":
    unittest.main()
