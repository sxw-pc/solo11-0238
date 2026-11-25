import unittest

from cloudctl.db import row, rows
from support import Workspace


class ObservationDecisions(Workspace):
    def test_replica_generation_rejects_old_identity_without_erasing_history(self):
        self.policy()
        self.replica()
        self.do("agent", "register", replica_id="r1", service="api", namespace="edge",
                generation=2, healthy=True)
        stale = self.do("agent", "observe", observation_id="old-g1", replica_id="r1",
                        generation=1, observed_at=30, received_at=31,
                        policy_id="p1", revision=1, value="safe", origin="agent")
        self.assertEqual(stale["status"], "stale_generation")
        self.assertEqual(row(self.db, "SELECT generation,observed_at FROM inventories WHERE replica_id='r1'"),
                         {"generation": 2, "observed_at": 0})
        self.assertEqual(row(self.db, "SELECT status FROM observations WHERE id='old-g1'")["status"],
                         "stale_generation")
        self.audit()

    def test_late_observation_is_evidence_but_cannot_reverse_current_drift(self):
        self.policy()
        self.replica(revision=0, value="old", at=20)
        fixed = self.do("agent", "observe", observation_id="fixed", replica_id="r1",
                        generation=1, observed_at=30, received_at=31,
                        policy_id="p1", revision=1, value="safe", origin="agent")
        self.assertEqual(fixed["drift"], "converged")
        late = self.do("agent", "observe", observation_id="late", replica_id="r1",
                       generation=1, observed_at=25, received_at=35,
                       policy_id="p1", revision=0, value="old", origin="agent")
        self.assertEqual(late["status"], "stale_time")
        self.assertEqual(row(self.db, "SELECT drift FROM inventories WHERE replica_id='r1'")["drift"],
                         "converged")
        self.assertEqual(len(rows(self.db, "SELECT id FROM observations WHERE replica_id='r1'")), 3)
        self.audit()

    def test_policy_change_and_manual_override_have_different_responsibility(self):
        self.policy()
        self.replica(revision=0, value="old")
        self.assertEqual(row(self.db, "SELECT drift FROM inventories WHERE replica_id='r1'")["drift"],
                         "policy_changed")
        manual = self.do("agent", "observe", observation_id="manual", replica_id="r1",
                         generation=1, observed_at=8, received_at=9,
                         policy_id="p1", revision=1, value="custom", origin="operator")
        self.assertEqual(manual["drift"], "manual_override")
        wrong = self.do("agent", "observe", observation_id="wrong", replica_id="r1",
                        generation=1, observed_at=10, received_at=11,
                        policy_id="different", revision=1, value="safe", origin="agent")
        self.assertEqual(wrong["drift"], "wrong_policy")
        self.audit()

    def test_exception_changes_repair_eligibility_until_expiry(self):
        self.policy()
        self.replica(revision=1, value="custom")
        approved = self.do("agent", "exception", exception_id="ex1", replica_id="r1",
                           policy_id="p1", approved_by="service-owner", expires_at=20,
                           at=10, reason="planned hotfix")
        self.assertEqual(approved["drift"], "excepted")
        self.assertEqual(self.do("drift", "plan", plan_id="fix1", policy_id="p1",
                                 service="api", min_healthy=0, at=11)["status"], "noop")
        expired = self.do("agent", "expire", at=20)
        self.assertEqual(expired["drift"], {"r1": "manual_override"})
        self.assertEqual(self.do("drift", "plan", plan_id="fix1", policy_id="p1",
                                 service="api", min_healthy=0, at=21)["status"], "planned")
        self.audit()

    def test_exception_requires_current_target_and_real_owner(self):
        self.policy()
        self.replica(revision=0, value="old")
        bad = self.do("agent", "exception", exception_id="ex1", replica_id="r1",
                      policy_id="p1", approved_by="", expires_at=20, at=10)
        self.assertEqual(bad["status"], "rejected")
        wrong = self.do("agent", "exception", exception_id="ex2", replica_id="r1",
                        policy_id="not-target", approved_by="owner", expires_at=20, at=10)
        self.assertEqual(wrong["status"], "rejected")
        self.assertEqual(len(rows(self.db, "SELECT id FROM exceptions")), 0)
        self.audit()

    def test_exception_is_bound_to_target_revision(self):
        self.policy()
        self.replica(revision=1, value="custom")
        self.do("agent", "exception", exception_id="ex1", replica_id="r1",
                policy_id="p1", approved_by="service-owner", expires_at=50,
                at=10, reason="temporary deviation")
        self.assertEqual(row(self.db, "SELECT drift FROM inventories WHERE replica_id='r1'")["drift"],
                         "excepted")
        self.do("policy", "draft", policy_id="p1", revision=2,
                value="strict", dependencies=[], at=12)
        self.do("policy", "publish", policy_id="p1", revision=2)
        self.assertEqual(row(self.db, "SELECT drift FROM inventories WHERE replica_id='r1'")["drift"],
                         "policy_changed")
        self.assertEqual(self.do("drift", "plan", plan_id="fix", policy_id="p1",
                                 service="api", min_healthy=0, at=13)["status"], "planned")
        self.audit()


if __name__ == "__main__":
    unittest.main()
