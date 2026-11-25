import unittest

from cloudctl.db import row, rows
from support import Workspace


class PolicyDecisions(Workspace):
    def test_dependency_publication_and_immutable_revision(self):
        self.do("policy", "create", policy_id="child", namespace="edge", scope="worker", owner="platform")
        self.do("policy", "draft", policy_id="child", revision=1, value="v1",
                dependencies=["base"], at=1)
        self.assertEqual(self.do("policy", "publish", policy_id="child", revision=1)["status"], "blocked")
        self.policy(policy_id="base", scope="api")
        self.assertEqual(self.do("policy", "publish", policy_id="child", revision=1)["status"], "active")
        self.assertEqual(self.do("policy", "draft", policy_id="child", revision=1,
                                 value="rewritten", dependencies=[], at=3)["status"], "rejected")
        self.assertEqual(row(self.db, "SELECT value FROM revisions WHERE policy_id='child' AND revision=1")["value"], "v1")
        self.audit()

    def test_scope_ownership_conflict_and_replay(self):
        self.policy()
        self.do("policy", "create", policy_id="p2", namespace="edge", scope="*", owner="team-b")
        self.do("policy", "draft", policy_id="p2", revision=1, value="wide", dependencies=[], at=2)
        blocked = self.do("policy", "publish", policy_id="p2", revision=1)
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["conflicts"], ["p1"])
        self.assertEqual(row(self.db, "SELECT status FROM policies WHERE id='p2'")["status"], "draft")
        self.audit()

    def test_rollback_is_new_revision_and_changes_observed_target(self):
        self.policy()
        self.replica(revision=1, value="safe")
        self.do("policy", "draft", policy_id="p1", revision=2, value="strict", dependencies=[], at=10)
        changed = self.do("policy", "publish", policy_id="p1", revision=2)
        self.assertEqual(changed["affected_replicas"], ["r1"])
        self.assertEqual(row(self.db, "SELECT drift FROM inventories WHERE replica_id='r1'")["drift"], "policy_changed")
        restored = self.do("policy", "rollback", policy_id="p1", source_revision=1, at=20)
        self.assertEqual(restored["new_revision"], 3)
        self.assertEqual(row(self.db, "SELECT value FROM revisions WHERE policy_id='p1' AND revision=3")["value"], "safe")
        self.audit()

    def test_retirement_waits_for_live_dependents_and_installed_replicas(self):
        self.policy(policy_id="base", scope="api")
        self.policy(policy_id="child", scope="worker", dependencies=["base"])
        blocked = self.do("policy", "retire", policy_id="base", at=10)
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["blockers"]["dependent_policies"], ["child"])
        self.do("policy", "retire", policy_id="child", at=11)
        retired = self.do("policy", "retire", policy_id="base", at=12)
        self.assertEqual(retired["status"], "retired")
        self.assertEqual(row(self.db, "SELECT status FROM retirements WHERE policy_id='base'")["status"], "retired")
        self.audit()

    def test_duplicate_request_has_stable_result_and_payload_identity(self):
        payload = {"policy_id": "p1", "namespace": "edge", "scope": "api", "owner": "platform"}
        first = __import__("cloudctl.executor", fromlist=["execute"]).execute(
            self.db, "policy", "create", payload, "same")
        again = __import__("cloudctl.executor", fromlist=["execute"]).execute(
            self.db, "policy", "create", payload, "same")
        self.assertEqual(first, again)
        self.assertEqual(len(rows(self.db, "SELECT id FROM events")), 1)
        self.audit()

    def test_retirement_cannot_drop_a_policy_still_installed_on_replica(self):
        self.policy()
        self.replica(revision=1, value="safe")
        blocked = self.do("policy", "retire", policy_id="p1", at=10)
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["blockers"]["installed_replicas"], ["r1"])
        self.assertEqual(row(self.db, "SELECT status FROM policies WHERE id='p1'")["status"], "active")
        self.audit()

    def test_new_target_can_make_future_revision_observation_converge(self):
        self.policy()
        self.replica(revision=2, value="strict")
        self.assertEqual(row(self.db, "SELECT drift FROM inventories WHERE replica_id='r1'")["drift"],
                         "future_revision")
        self.do("policy", "draft", policy_id="p1", revision=2, value="strict",
                dependencies=[], at=8)
        self.do("policy", "publish", policy_id="p1", revision=2)
        self.assertEqual(row(self.db, "SELECT drift FROM inventories WHERE replica_id='r1'")["drift"],
                         "converged")
        self.assertEqual(self.do("drift", "plan", plan_id="fix", policy_id="p1",
                                 service="api", min_healthy=0, at=9)["status"], "noop")
        self.audit()


if __name__ == "__main__":
    unittest.main()
