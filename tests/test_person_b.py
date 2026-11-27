import json
from io import StringIO
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from hids_agent.handoff import process
from hids_agent.contract import lines, read_json
from hids_agent.dashboard import render
from hids_agent.handoff import Engine
from hids_agent.evaluate import evaluate, labels_from_events
from hids_agent.gen_synthetic import dataset, export
from hids_agent.tune import search


def office(ts=100, ref="event1", host="desk", entity="word:18"):
    return dict(rule="office_shell", entity=entity, host=host, timestamp=ts, title="Office started a shell",
                evidence=[ref], requested_blocks=[{"action": "terminate_process", "target": "pid:20"}])


def truth(key="S1", ids=None, host="desk", rule="office_shell"):
    return dict(attack_id=key, type=rule, host=host, start=90, end=110,
                event_ids=["event1"] if ids is None else ids)


def run(rows, **kw):
    return process(enumerate(rows, 1), source="unit fixture", mode=kw.pop("mode", "prevent"), **kw)


def score(run_data, labels):
    return evaluate(run_data["alerts"], run_data["blocks"], labels)


class ResponseTests(unittest.TestCase):
    def test_score_floor_cap_and_named_signals(self):
        row = office()
        row["signals"] = ["privileged", "suspicious_cmdline", "temp_binary", "unsigned", "unsigned"]
        alert = run([row])["alerts"][0]
        self.assertEqual((alert["score"], alert["severity"]), (100, "critical"))
        self.assertEqual(sum(s["points"] for s in alert["signals"]), 105)

    def test_grouping_inclusive_boundary_sort_and_evidence_union(self):
        rows = [office(1901, "later"), office(1000, "again"), office(100, "first")]
        data = run(rows)
        self.assertEqual([a["hits"] for a in data["alerts"]], [2, 1])
        self.assertEqual(data["alerts"][0]["evidence"], ["id:first", "id:again"])
        self.assertEqual(data["blocks"][0]["alert_ids"], ["A0001", "A0002"])
        self.assertEqual(len(data["incidents"]), 1)

    def test_host_isolation_and_ttl(self):
        data = run([office(), office(host="other"), office(86500, "again")])
        self.assertEqual(len(data["blocks"]), 3)
        self.assertEqual(len(data["incidents"]), 3)

    def test_chain_bonus_uses_only_recent_different_rule_on_host(self):
        r = office()
        r.update(rule="temp_service", requested_blocks=[])
        data = run([r, office(1900), office(3701)])
        self.assertEqual([a["score"] for a in data["alerts"]], [60, 75, 55])

    def test_detect_mode_previews_but_writes_zero_blocks(self):
        data = run([office()], mode="detect")
        self.assertEqual(data["blocks"], [])
        self.assertEqual(data["alerts"][0]["requested_blocks"][0]["action"], "terminate_process")
        self.assertEqual(score(data, [truth()])["status"], "FAIL")

    def test_protected_ip_and_account_get_no_credit(self):
        row = office()
        row.update(rule="bruteforce", requested_blocks=[
            {"action":"block_ip", "target":"192.0.2.17"}, {"action":"lock_account", "target":"ADMIN"}])
        data = run([row], never_block={"ips":["192.0.2.0/24"], "users":["admin"]})
        self.assertEqual([b["status"] for b in data["blocks"]], ["skipped_protected"] * 2)
        self.assertEqual(score(data, [truth(rule="bruteforce")])["blocks_on_attacks"], [])

    def test_audit_watch_and_unverified_hash_do_not_alert(self):
        row = office()
        row.update(rule="file_integrity", signals=["unverified"], requested_blocks=[])
        note = dict(timestamp=123, host="h", evidence=["e"], reason="Approved revision")
        data = run([row, dict(note, kind="audit", entry="CHG-1"), dict(note, kind="watch")])
        self.assertEqual((len(data["alerts"]), len(data["blocks"]), len(data["watch"]), len(data["audit"])),
                         (0, 0, 2, 1))

    def test_bad_handoff_diagnoses_line(self):
        for patch in ({"timestamp":float("nan")}, {"requested_blocks":[{"action":"block_ip","target":"x"}]},
                      {"signals":["made_up"]}, {"evidence":[]}, {"timestamp":"2026-01-01T12:00:00"}):
            with self.subTest(patch=patch), self.assertRaisesRegex(ValueError, "handoff line 1"):
                run([{**office(), **patch}])

    def test_event_volume_and_timezone_equivalence(self):
        engine = Engine()
        for when in ("2026-01-01T00:00:00Z", "2026-01-01T05:30:00+05:30"):
            engine.add({"kind":"event", "timestamp":when})
        summary = engine.finish()["summary"]
        self.assertEqual(list(summary["events_per_minute"].values()), [2])


class EvaluationTests(unittest.TestCase):
    def test_exact_id_matching_scoped_to_host_and_rule(self):
        data = run([office(), office(host="other"), {**office(), "rule":"bruteforce","requested_blocks":[]}])
        r = score(data, [truth()])
        self.assertEqual((r["detected"], r["false_alarms"], r["status"]), (1, 2, "PASS"))
        self.assertAlmostEqual(r["precision"], 1/3)

    def test_third_false_alarm_fails_target(self):
        data = run([office(), *(office(host=f"other-{i}") for i in range(3))])
        self.assertEqual(score(data, [truth()])["status"], "FAIL")

    def test_unlabeled_empty_negative_and_missed(self):
        data = run([])
        self.assertEqual(score(data, None)["status"], "UNSCORED")
        self.assertIsNone(score(data, [])["precision"])
        self.assertEqual(score(data, [truth()])["missed"], ["S1"])
        self.assertEqual(score(data, [truth()])["recall"], 0)

    def test_wrong_id_never_falls_back_to_time(self):
        self.assertEqual(score(run([office()]), [truth(ids=["different"])])["false_alarms"], 1)

    def test_time_only_with_inclusive_slack(self):
        for ts, method in [(170, True), (171, False)]:
            report = score(run([office(ts)]), [truth(ids=[])])
            self.assertEqual(bool(report["matches"]), method)
            if method:
                self.assertEqual(report["matches"]["A0001"]["method"], "time")

    def test_ambiguous_labels_flagged_without_credit(self):
        for refs in ([], ["event1"]):
            r = score(run([office()]), [truth("a", refs), truth("b", refs)])
            self.assertEqual(r["ambiguous"]["A0001"], ["a","b"])
            self.assertEqual((r["recall"], r["precision"], r["f1"]), (0, 0, 0))

    def test_first_matching_observation_gives_latency_and_block_credit(self):
        rows = [office(40, "benign"), {**office(), "requested_blocks":[]}]
        r = score(run(rows), [truth()])
        self.assertEqual(r["latency_s"], {"S1":10})
        self.assertEqual(r["blocks_on_attacks"], [])

    def test_disjoint_group_observations_do_not_fill_time_gap(self):
        r = score(run([office(0), office(600)]), [truth(ids=[])])
        self.assertEqual(r["matches"], {})

    def test_aggregate_only_alert_needs_corroborating_block_evidence(self):
        data = run([office(40, "unrelated"), {**office(), "requested_blocks":[]}])
        del data["alerts"][0]["observations"]
        self.assertEqual(score(data, [truth()])["blocks_on_attacks"], [])

    def test_duplicate_predictions_cannot_increase_sequence_recall(self):
        r = score(run([office(), office(entity="other")]), [truth(), truth("miss", ["none"])])
        self.assertEqual((r["duplicate_matches"], r["matched_alerts"], r["detected"], r["recall"]), (1,2,1,.5))

    def test_input_labels_and_embedded_import(self):
        embedded = labels_from_events([
            {"id":"x","ts":20,"host":"desk","attack_id":"e","attack_type":"office_shell"},
            {"id":"y","ts":10,"host":"desk","attack_id":"e","attack_type":"office_shell"},
            {"id":"benign"}])
        self.assertEqual((embedded[0]["start"], embedded[0]["end"]), (10,20))
        self.assertEqual(score(run([office(ref="x")]), embedded)["recall"], 1)
        for bad in ([truth(),truth()], [{**truth(),"end":1}], [{**truth(),"event_ids":{}}]):
            with self.assertRaises(ValueError):
                score(run([]), bad)

    def test_html_treats_telemetry_as_text(self):
        row = office()
        row["title"] = '<img src=x onerror="alert(1)">'
        data = run([row])
        html = render(data, score(data, None), view="alerts")
        self.assertIn("&lt;img", html)
        self.assertNotIn(row["title"], html)

    def test_grid_replays_each_config_and_selects_passing_trial(self):
        calls = []
        def replay(config):
            calls.append(config["failed_logons"])
            return run([office()] if config["failed_logons"] == 5 else [])
        result = search({"failed_logons":[7, 5]}, replay, [truth()])
        self.assertEqual(calls, [7, 5])
        self.assertEqual(result["best"]["config"]["failed_logons"], 5)


class IntegrationTests(unittest.TestCase):
    def test_mixed_stream_preserves_ground_truth_and_marks_one_malformed_record(self):
        with TemporaryDirectory() as tmp:
            folder = Path(tmp) / "fixture"
            export(folder, "dev", mixed=True)
            decoded, bad = [], 0
            for line in (folder/"events-mixed.jsonl").read_text(encoding="utf-8-sig").splitlines():
                try:
                    decoded.append(json.loads(line))
                except json.JSONDecodeError:
                    bad += 1
            ids = [row["id"] for row in decoded]
            self.assertEqual((bad, len(ids)-len(set(ids))), (1,1))
            self.assertTrue(any("Computer" in r for r in decoded))
            self.assertTrue(any(isinstance(r.get("host"), dict) for r in decoded))
            self.assertEqual(set(ids), {r["id"] for r in dataset()["events"]})

    def test_seeded_fixture_contract_and_separate_labels(self):
        for split in ("dev", "holdout"):
            data = dataset(split)
            self.assertEqual(dataset(split), data)
            refs = {(e["host"], e["id"]) for e in data["events"]}
            self.assertTrue(all((l["host"], e) in refs for l in data["labels"] for e in l["event_ids"]))
            self.assertTrue(all("attack_id" not in e for e in data["events"]))
            result = run(data["handoff"])
            self.assertEqual(result["summary"]["events"], len(data["events"]))
            self.assertEqual(score(result, data["labels"])["status"], "PASS")

    def test_cli_pipeline_rescore_and_existing_run_protection(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            def cli(*args, stdin=None):
                return subprocess.run([sys.executable, "-m", *map(str,args)], input=stdin, capture_output=True, text=True)
            dest = root/"case"
            first = cli("hids_agent","run","--out",dest,stdin=json.dumps(office()))
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(read_json(dest/"report.json")["status"], "UNSCORED")
            label_file = root/"labels.json"
            label_file.write_text(json.dumps([truth()]), encoding="utf-8")
            result = cli("hids_agent.evaluate","--out",dest,"--labels",label_file)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PASS", (dest/"report.md").read_text(encoding="utf-8"))
            self.assertEqual(read_json(dest/"report.json")["blocks_on_attacks"], ["B0001"])
            bad = cli("hids_agent","run","--out",root/"broken",stdin='{}\n{not json}\n')
            self.assertNotEqual(bad.returncode, 0)
            self.assertFalse((root/"broken").exists())
            self.assertNotEqual(cli("hids_agent","demo","--out",dest).returncode, 0)
            with (dest/"alerts.jsonl").open(encoding="utf-8") as stream:
                self.assertEqual([row for _,row in lines(stream)], read_json(dest/"alerts.json"))

    def test_bom_and_invalid_json_diagnostic(self):
        with self.assertRaisesRegex(ValueError,"line 2"):
            list(lines(StringIO('\ufeff{}\ninvalid\n')))

    def test_source_header_after_blank_line(self):
        rows = lines(StringIO('\n{"kind":"source","name":"labelled fixture"}\n'))
        self.assertEqual(process(rows, source="import", mode="detect")["summary"]["source"], "labelled fixture")


if __name__ == "__main__":
    unittest.main()
