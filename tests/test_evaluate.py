import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from hids_agent.evaluate import evaluate
from hids_agent.label_input import labels_from_stream
from tests.helpers import run_text
from tests.test_person_b import office, run, truth


class IntegratedEvaluation(unittest.TestCase):
    def test_grouped_alert_can_cover_two_distinct_sequences(self):
        case = run([office(ref="first"), office(ts=104, ref="second")])
        report = evaluate(case["alerts"], case["blocks"], [truth("one", ["first"]), truth("two", ["second"])])
        self.assertEqual(report["matches"]["A0001"]["attack_ids"], ["one", "two"])
        self.assertEqual((report["precision"], report["recall"], report["duplicate_matches"]), (1, 1, 0))

    def test_embedded_idless_references_agree_with_detector_framing(self):
        event = {"host":"workstation", "ts":100, "category":"process", "image":"cmd.exe",
                 "parent_image":"winword.exe", "attack_id":"seq-1", "attack_type":"office_shell"}
        benign = {"host":"workstation", "ts":99, "category":"process", "image":"browser.exe"}
        variants = [
            f"\n{json.dumps(benign)}\n{{malformed\n\n{json.dumps(event)}\n",
            json.dumps([benign, event], indent=2),
            json.dumps({"events":[benign,event]}, indent=2),
        ]
        for wire in variants:
            with self.subTest(wire=wire), TemporaryDirectory() as tmp:
                file = Path(tmp) / "events.json"
                file.write_text(wire, encoding="utf8")
                engine, _ = run_text(wire)
                report = evaluate(list(engine.alerts.values()), engine.blocks, labels_from_stream(file))
                self.assertEqual(report["detected"], 1)
                self.assertEqual(report["status"], "PASS")

    def test_correct_type_required_for_time_only_matches(self):
        case = run([office()])
        report = evaluate(case["alerts"], case["blocks"], [truth(ids=[], rule="temp_service")])
        self.assertEqual((report["false_alarms"], report["recall"]), (1, 0))

    def test_exit_codes_for_prevent_and_detect(self):
        root = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as tmp:
            for mode, expected in [("prevent", 0), ("detect", 1)]:
                output = Path(tmp) / mode
                run_args = ["hids_agent.agent", "--input", "examples/events.jsonl",
                            "--mode", mode, "--quiet", "--out", str(output)]
                subprocess.run([sys.executable, "-m", *run_args], cwd=root, check=True, capture_output=True)
                result = subprocess.run([sys.executable, "-m", "hids_agent.evaluate", "--out", str(output),
                                         "--labels", "examples/labels.json"], cwd=root, capture_output=True)
                self.assertEqual(result.returncode, expected, result.stderr)
