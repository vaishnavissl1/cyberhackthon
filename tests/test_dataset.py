"""The labeled dataset builder, the replay script and the tuner's tie-break."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hids_agent.build_dataset import write

ROOT = Path(__file__).resolve().parent.parent


class TestBuildDataset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dev = Path(cls.tmp.name) / "dev"
        cls.hidden = Path(cls.tmp.name) / "hidden"
        cls.dev_info = write(cls.dev, "dev", 3)
        cls.hidden_info = write(cls.hidden, "hidden", 3)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def labels(self, folder):
        return json.loads((folder / "labels.json").read_text(encoding="utf-8"))

    def test_reproducible(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), "dev", 3)
            self.assertEqual((Path(d) / "events.jsonl").read_bytes(), (self.dev / "events.jsonl").read_bytes())

    def test_hidden_has_variants_never_seen_in_dev(self):
        dev = {l["variant"] for l in self.labels(self.dev)}
        hidden = {l["variant"] for l in self.labels(self.hidden)}
        self.assertTrue(hidden - dev)
        self.assertEqual({l["type"] for l in self.labels(self.hidden)},
                         {"bruteforce", "office_shell", "temp_service", "fim"})

    def test_labels_point_at_real_events_and_stream_has_no_labels(self):
        text = (self.hidden / "events.jsonl").read_text(encoding="utf-8")
        for l in self.labels(self.hidden):
            for eid in l["event_ids"]:
                self.assertIn(f'"{eid}"', text)
        for word in ("attack_id", "label", "variant"):
            self.assertNotIn(f'"{word}"', text)

    def test_agent_passes_core_target(self):
        out = Path(self.tmp.name) / "out"
        f = self.hidden
        r = subprocess.run([sys.executable, "-m", "hids_agent.agent", "-i", str(f / "events.jsonl"),
                            "--baseline", str(f / "baseline.json"), "--allowlist", str(f / "allowlist.json"),
                            "--labels", str(f / "labels.json"), "--out", str(out), "-q"],
                           capture_output=True, text=True, cwd=ROOT, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        report = json.loads((out / "report.json").read_text())
        self.assertEqual((report["status"], report["false_alarms"]), ("PASS", 0), report.get("missed"))


class TestReplayStream(unittest.TestCase):
    def test_pipe_passes_lines_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.jsonl"
            body = '{"id": 1, "ts": 100}\n{bad line\n{"id": 2, "ts": 101}\n'
            p.write_text(body, encoding="utf-8")
            r = subprocess.run([sys.executable, "-m", "hids_agent.replay_stream", str(p), "--speed", "1000"],
                               capture_output=True, text=True, cwd=ROOT, timeout=30)
        self.assertEqual(r.stdout, body)


class TestTunerTieBreak(unittest.TestCase):
    def test_prefers_defaults_over_most_lenient_tie(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "dev"
            write(f, "dev", 5)
            cfg = Path(d) / "chosen.json"
            r = subprocess.run([sys.executable, "-m", "hids_agent.tune", "--events", str(f / "events.jsonl"),
                                "--labels", str(f / "labels.json"), "--baseline", str(f / "baseline.json"),
                                "--allowlist", str(f / "allowlist.json"), "--failures", "4", "5",
                                "--windows", "300", "600", "--success-delays", "600", "--spray-users", "4", "5",
                                "--cooldowns", "900", "--config-out", str(cfg)],
                               capture_output=True, text=True, cwd=ROOT, timeout=900)
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
            chosen = json.loads(cfg.read_text())["bruteforce"]
        self.assertEqual((chosen["n_fail"], chosen["window_s"], chosen["spray_users"]), (5, 300, 5))


if __name__ == "__main__":
    unittest.main()
