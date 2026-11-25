import unittest

from cloudctl.db import row, rows
from support import Workspace


class RepairDecisions(Workspace):
    def test_wave_budget_requires_observation_and_fences_next_wave(self):
        self.policy()
        self.replica("r1")
        self.replica("r2")
        plan = self.do("drift", "plan", plan_id="fix", policy_id="p1",
                       service="api", min_healthy=1, at=10)
        self.assertEqual([item["wave"] for item in plan["waves"]], [1, 2])
        self.assertEqual(self.do("drift", "dispatch", action_id="fix:r2")["status"], "blocked")
        self.assertEqual(self.do("drift", "dispatch", action_id="fix:r1")["status"], "dispatched")
        self.assertEqual(self.do("drift", "dispatch", action_id="fix:r2")["status"], "blocked")
        self.audit()

    def test_failed_receipt_pauses_plan_and_preserves_old_observation(self):
        self.policy()
        self.replica()
        self.do("drift", "plan", plan_id="fix", policy_id="p1",
                service="api", min_healthy=0, at=10)
        self.do("drift", "dispatch", action_id="fix:r1")
        result = self.do("drift", "receipt", receipt_id="bad", action_id="fix:r1",
                         replica_id="r1", generation=0, revision=1, value="safe", at=11,
                         success=True)
        self.assertEqual(result["status"], "paused")
        self.assertEqual(self.do("drift", "dispatch", action_id="fix:r1")["status"], "blocked")
        self.assertEqual(row(self.db, "SELECT drift FROM inventories WHERE replica_id='r1'")["drift"],
                         "policy_changed")
        self.audit()

    def test_receipt_alone_cannot_claim_convergence(self):
        self.policy()
        self.replica()
        self.do("drift", "plan", plan_id="fix", policy_id="p1",
                service="api", min_healthy=0, at=10)
        self.do("drift", "dispatch", action_id="fix:r1")
        applied = self.do("drift", "receipt", receipt_id="good", action_id="fix:r1",
                          replica_id="r1", generation=1, revision=1, value="safe", at=11,
                          success=True)
        self.assertEqual(applied["status"], "applied")
        self.assertEqual(self.do("drift", "confirm", action_id="fix:r1")["status"], "pending")
        self.assertEqual(row(self.db, "SELECT status FROM plans WHERE id='fix'")["status"], "running")
        self.audit()

    def test_independent_observation_completes_plan(self):
        self.policy()
        self.replica()
        self.do("drift", "plan", plan_id="fix", policy_id="p1",
                service="api", min_healthy=0, at=10)
        self.do("drift", "dispatch", action_id="fix:r1")
        self.do("drift", "receipt", receipt_id="good", action_id="fix:r1",
                replica_id="r1", generation=1, revision=1, value="safe", at=11, success=True)
        self.do("agent", "observe", observation_id="fixed", replica_id="r1",
                generation=1, observed_at=12, received_at=13,
                policy_id="p1", revision=1, value="safe", origin="agent")
        result = self.do("drift", "confirm", action_id="fix:r1")
        self.assertEqual(result["status"], "converged")
        self.assertEqual(row(self.db, "SELECT status FROM actions WHERE id='fix:r1'")["status"],
                         "confirmed")
        self.audit()

    def test_paused_plan_chooses_new_rollback_revision(self):
        self.policy()
        self.replica()
        self.do("policy", "draft", policy_id="p1", revision=2, value="strict",
                dependencies=[], at=7)
        self.do("policy", "publish", policy_id="p1", revision=2)
        self.do("drift", "plan", plan_id="fix", policy_id="p1",
                service="api", min_healthy=0, at=10)
        self.do("drift", "dispatch", action_id="fix:r1")
        self.do("drift", "receipt", receipt_id="failed", action_id="fix:r1",
                replica_id="r1", generation=1, revision=2, value="strict", at=11, success=False)
        result = self.do("drift", "rollback", plan_id="fix", source_revision=1, at=12)
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(row(self.db, "SELECT active_revision FROM policies WHERE id='p1'")["active_revision"], 3)
        self.assertEqual(row(self.db, "SELECT status FROM plans WHERE id='fix'")["status"], "rolled_back")
        self.audit()

    def test_no_disruption_budget_returns_blocked_without_actions(self):
        self.policy()
        self.replica()
        result = self.do("drift", "plan", plan_id="fix", policy_id="p1",
                         service="api", min_healthy=1, at=10)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(len(rows(self.db, "SELECT id FROM actions")), 0)
        self.audit()


if __name__ == "__main__":
    unittest.main()
