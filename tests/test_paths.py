import json
import tempfile
import unittest
from pathlib import Path

from cloudctl.__main__ import run_scenario
from cloudctl.audit import report
from cloudctl.db import connect, row
from support import Workspace


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


class VerticalPaths(Workspace):
    def fixture(self, name):
        scenario = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        return run_scenario(self.db, scenario)

    def test_policy_revision_changes_observation_and_repair_eligibility(self):
        self.policy()
        self.replica(revision=1, value="safe")
        self.assertEqual(self.do("drift", "plan", plan_id="pre", policy_id="p1",
                                 service="api", min_healthy=0, at=8)["status"], "noop")
        self.do("policy", "draft", policy_id="p1", revision=2, value="strict", dependencies=[], at=9)
        publish = self.do("policy", "publish", policy_id="p1", revision=2)
        self.assertEqual(publish["affected_replicas"], ["r1"])
        self.assertEqual(row(self.db, "SELECT drift FROM inventories WHERE replica_id='r1'")["drift"],
                         "policy_changed")
        plan = self.do("drift", "plan", plan_id="post", policy_id="p1",
                       service="api", min_healthy=0, at=10)
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["target_revision"], 2)
        self.audit()

    def test_exception_temporarily_changes_repair_then_expiry_restores_it(self):
        self.policy()
        self.replica(revision=1, value="custom")
        self.do("agent", "exception", exception_id="ex1", replica_id="r1",
                policy_id="p1", approved_by="owner", expires_at=20, at=10)
        self.assertEqual(self.do("drift", "plan", plan_id="during", policy_id="p1",
                                 service="api", min_healthy=0, at=11)["status"], "noop")
        self.do("agent", "expire", at=20)
        self.assertEqual(self.do("drift", "plan", plan_id="after", policy_id="p1",
                                 service="api", min_healthy=0, at=21)["status"], "planned")
        self.audit()

    def test_failed_repair_changes_policy_target_without_claiming_convergence(self):
        self.policy()
        self.replica()
        self.do("policy", "draft", policy_id="p1", revision=2, value="strict", dependencies=[], at=7)
        self.do("policy", "publish", policy_id="p1", revision=2)
        self.do("drift", "plan", plan_id="fix", policy_id="p1", service="api",
                min_healthy=0, at=10)
        self.do("drift", "dispatch", action_id="fix:r1")
        self.do("drift", "receipt", receipt_id="fail", action_id="fix:r1",
                replica_id="r1", generation=1, revision=2, value="strict", at=11, success=False)
        self.assertEqual(self.do("drift", "confirm", action_id="fix:r1")["status"], "blocked")
        rollback = self.do("drift", "rollback", plan_id="fix", source_revision=1, at=12)
        self.assertEqual(rollback["new_revision"], 3)
        self.assertEqual(row(self.db, "SELECT drift FROM inventories WHERE replica_id='r1'")["drift"],
                         "policy_changed")
        self.audit()

    def test_each_subsystem_has_normal_and_failure_fixture(self):
        for prefix in ("策略发布", "副本观察", "修复执行"):
            for outcome in ("normal", "failure"):
                with self.subTest(prefix=prefix, outcome=outcome):
                    with tempfile.TemporaryDirectory() as directory:
                        db = connect(Path(directory) / "fixture.sqlite")
                        scenario = json.loads((FIXTURES / f"{prefix}-{outcome}.json").read_text(encoding="utf-8"))
                        result = run_scenario(db, scenario)
                        db.close()
                        self.assertEqual(result["audit"]["audit"], "consistent")
                        statuses = [item["result"]["status"] for item in result["steps"]]
                        self.assertTrue(any(status in statuses for status in
                                            ("active", "accepted", "planned", "blocked", "paused", "retired")))

    def test_three_saved_vertical_scenarios_replay_from_raw_evidence(self):
        expected = {"demo.json": "converged", "路径-例外窗口.json": "planned",
                    "路径-失败回退.json": "rolled_back"}
        for fixture, final_status in expected.items():
            with self.subTest(fixture=fixture):
                with tempfile.TemporaryDirectory() as directory:
                    db = connect(Path(directory) / "scenario.sqlite")
                    scenario = json.loads((FIXTURES / fixture).read_text(encoding="utf-8"))
                    result = run_scenario(db, scenario)
                    self.assertEqual(result["steps"][-1]["result"]["status"], final_status)
                    self.assertEqual(result["audit"]["audit"], "consistent")
                    db.close()

    def test_review_promised_subsystem_entry_fixtures_exist(self):
        for name, subsystem, operation in (("策略发布", "policy", "publish"),
                                           ("副本观察", "agent", "observe"),
                                           ("修复执行", "drift", "reconcile")):
            with self.subTest(subsystem=subsystem):
                path = FIXTURES / f"{name}.json"
                self.assertTrue(path.exists())
                scenario = json.loads(path.read_text(encoding="utf-8"))
                self.assertTrue(any(step["subsystem"] == subsystem and step["operation"] == operation
                                    for step in scenario["steps"]))


if __name__ == "__main__":
    unittest.main()
