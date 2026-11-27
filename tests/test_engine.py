import unittest

from hids_agent.config import sev_from_score
from hids_agent.evaluate import evaluate
from hids_agent.rules import Candidate
from tests.helpers import proc, run


class IntegratedEngine(unittest.TestCase):
    def test_severity_boundaries_and_medium_floor(self):
        self.assertEqual([sev_from_score(v) for v in (19,20,39,40,59,60,79,80)],
                         ["info","low","low","medium","medium","high","high","critical"])
        engine, _ = run([])
        engine.accept(Candidate("fim", "host", "file", 100, "Change", [], ["id:1"], [("penalty", -100)]))
        self.assertEqual(next(iter(engine.alerts.values()))["score"], 40)

    def test_grouped_service_block_uses_name_and_spawn_only_still_blocks(self):
        path = r"C:\Windows\Temp\fixture.exe"
        launch = proc(2, path, 32, 4, parent="services.exe")
        registration = proc(1, "sc.exe", 31, 4, cmd=f'sc create Fixture binPath= "{path}"')
        for events in ([registration, launch], [launch], [dict(launch, ts=registration["timestamp"]), registration]):
            engine, _ = run(events)
            blocks = [b for b in engine.blocks if b["action"] == "disable_service"]
            self.assertEqual(len(blocks), 1)
            self.assertEqual(blocks[0]["target"], "fixture" if len(events) > 1 else "c:/windows/temp/fixture.exe")

    def test_evaluator_retains_exact_matches_after_summary_evidence_cap(self):
        engine, _ = run([])
        for i in range(510):
            engine.accept(Candidate("fim", "host", "/fixture", 100+i, "Change", [], [f"id:ev-{i}"],
                                    blocks=[("restore_file", "/fixture")]))
        alerts = list(engine.alerts.values())
        self.assertEqual((len(alerts[0]["evidence"]), alerts[0]["hits"]), (500, 510))
        report = evaluate(alerts, engine.blocks, [{"attack_id":"a", "type":"fim", "host":"host",
                                                   "start":608, "event_ids":["ev-509"]}])
        self.assertEqual(report["status"], "PASS")

    def test_approval_host_scope_and_unverified_hash_do_not_block(self):
        from tests.helpers import fevt
        old, new = "1"*64, "2"*64
        inputs = [fevt(1, "/config", sha256=new), fevt(2, "/config", sha256=new, host="other"),
                  fevt(3, "/config", host="third")]
        engine, _ = run(inputs, baseline={"/config":old}, allow={"fim":[{"host":"h1","path":"/config","hash":new}]})
        self.assertEqual([a["host"] for a in engine.audit], ["h1"])
        self.assertEqual([a["host"] for a in engine.alerts.values()], ["other","third"])
        self.assertEqual([b["host"] for b in engine.blocks], ["other"])
