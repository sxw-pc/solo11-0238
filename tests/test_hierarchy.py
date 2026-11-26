"""Hierarchical org -> cluster -> namespace targets, pins and identity fences.

These tests encode the east/west drill:

* p@1 = {tls: old, log: info} at the organization
* west override w@1 = {log: warn} only (explicit keys, no wholesale replace)
* p@2 changes tls -> new; east resolves {new, info}, west {new, warn}

They additionally cover both release routes, the mid-wave identity switch,
ancestor rollback, local retirement, two-layer conflicts, cycles, single
cluster failure, atomic rollback and full event replay.
"""

import json
from pathlib import Path

from cloudctl.__main__ import run_scenario
from cloudctl.db import canonical, connect, row
from cloudctl.policy import resolve_target
from support import Workspace


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


ORG_V1 = {"tls": "old", "log": "info"}
ORG_V2 = {"tls": "new", "log": "info"}
WEST_V1 = {"log": "warn"}


class HierarchyWorkspace(Workspace):
    def publish_org(self, revision=1, value=None, at=1):
        if revision == 1 and not row(self.db, "SELECT id FROM policies WHERE id='p'"):
            self.do("policy", "create", policy_id="p", layer="org",
                    scope="svc", owner="org")
        self.do("policy", "draft", policy_id="p", revision=revision,
                value=ORG_V1 if revision == 1 else (value or ORG_V2), at=at)
        return self.do("policy", "publish", policy_id="p", revision=revision)

    def publish_west(self, revision=1, value=None, at=2):
        if revision == 1 and not row(self.db, "SELECT id FROM policies WHERE id='w'"):
            self.do("policy", "create", policy_id="w", layer="cluster",
                    cluster="west", scope="svc", owner="west")
        self.do("policy", "draft", policy_id="w", revision=revision,
                value=WEST_V1 if revision == 1 else value, at=at)
        return self.do("policy", "publish", policy_id="w", revision=revision)

    def add_replica(self, cluster, index, observed_value, generation=1,
                    healthy=True, observed_at=5, namespace="prod", prefix=None):
        prefix = prefix or cluster[0]
        rid = f"{prefix}{index}"
        self.do("agent", "register", replica_id=rid, service="svc",
                namespace=namespace, cluster=cluster,
                generation=generation, healthy=healthy)
        return self.do("agent", "observe", observation_id=f"{rid}:init",
                       replica_id=rid, generation=generation,
                       observed_at=observed_at, received_at=observed_at + 1,
                       policy_id="p", revision=1, value=observed_value)

    def drill_six(self):
        """The reviewed raw materials: 3+3 converged replicas, min_healthy 2."""
        self.publish_org()
        self.publish_west()
        for i in range(1, 4):
            self.add_replica("east", i, {"tls": "old", "log": "info"}, prefix="e")
            self.add_replica("west", i, {"tls": "old", "log": "warn"}, prefix="w")

    def target(self, cluster):
        result = self.do("policy", "target", cluster=cluster,
                         namespace="prod", service="svc")
        return result["target"]

    def repair_step(self, plan_id, rid, value, at, generation=1):
        action_id = f"{plan_id}:{rid}"
        dispatched = self.do("drift", "dispatch", action_id=action_id)
        self.assertEqual(dispatched["status"], "dispatched", dispatched)
        receipt = self.do("drift", "receipt", receipt_id=f"rc:{action_id}:{at}",
                          action_id=action_id, replica_id=rid,
                          generation=generation, value=value, at=at, success=True)
        self.assertEqual(receipt["status"], "applied", receipt)
        self.do("agent", "observe", observation_id=f"ob:{action_id}:{at}",
                replica_id=rid, generation=generation, observed_at=at + 1,
                received_at=at + 2, policy_id="p", revision=2, value=value)
        return self.do("drift", "confirm", action_id=action_id)


class CompositionTests(HierarchyWorkspace):
    def test_key_level_merge_and_reproducible_identity(self):
        self.drill_six()
        west = self.target("west")
        east = self.target("east")
        self.assertEqual(west["values"], {"tls": "old", "log": "warn"})
        self.assertEqual(east["values"], {"tls": "old", "log": "info"})
        self.assertEqual(west["vector"], {"p": 1, "w": 1})
        self.assertEqual(east["vector"], {"p": 1})
        self.assertTrue(west["target_uid"].startswith("T"))
        self.assertEqual(west["target_uid"],
                         resolve_target(self.db, cluster="west", namespace="prod",
                                        service="svc")["target_uid"])
        # Identity is content+vector addressed and differs between clusters.
        self.assertNotEqual(west["target_uid"], east["target_uid"])
        self.audit()

    def test_publish_org_v2_composes_both_clusters_without_log_downgrade(self):
        self.drill_six()
        published = self.publish_org(revision=2, at=10)
        self.assertEqual(sorted(published["affected_clusters"]), ["east", "west"])
        self.assertEqual(len(published["affected_replicas"]), 6)
        self.assertEqual(self.target("east")["values"], {"tls": "new", "log": "info"})
        self.assertEqual(self.target("west")["values"], {"tls": "new", "log": "warn"})
        self.assertEqual(self.target("west")["vector"], {"p": 2, "w": 1})
        # Every replica is policy_changed, including west whose w@1 never moved.
        drifts = {r["replica_id"]: r["drift"]
                  for r in self.db.execute("SELECT replica_id,drift FROM inventories")}
        self.assertTrue(all(v == "policy_changed" for v in drifts.values()), drifts)
        self.audit()

    def test_namespace_only_addressing_after_topology_binding(self):
        # Topology declares "west" as a cluster node; replicas then need no
        # explicit cluster field and are addressed through namespace="west".
        self.do("policy", "node", node="org:default", kind="org", name="default")
        self.do("policy", "node", node="cluster:west", kind="cluster",
                name="west", parent="org:default")
        self.do("policy", "create", policy_id="p", layer="org", scope="svc", owner="o")
        self.do("policy", "draft", policy_id="p", revision=1, value=ORG_V1, at=1)
        self.do("policy", "publish", policy_id="p", revision=1)
        self.do("policy", "create", policy_id="w", namespace="west",
                scope="svc", owner="w")
        self.do("policy", "draft", policy_id="w", revision=1, value=WEST_V1, at=2)
        self.do("policy", "publish", policy_id="w", revision=1)
        self.do("agent", "register", replica_id="w1", service="svc",
                namespace="west", generation=1, healthy=True)
        self.do("agent", "observe", observation_id="w1o", replica_id="w1",
                generation=1, observed_at=5, received_at=6, policy_id="p",
                revision=1, value={"tls": "old", "log": "warn"})
        desired = resolve_target(self.db, namespace="west", service="svc")
        self.assertEqual(desired["values"], {"tls": "old", "log": "warn"})
        plan = self.do("drift", "plan", plan_id="wp", policy_id="w",
                       service="svc", namespace="west", min_healthy=0, at=7)
        self.assertEqual(plan["status"], "noop")
        self.audit()


    def test_plain_namespace_east_west_style_after_org_policy(self):
        # Some callers keep addressing clusters through the original namespace
        # field and never call the topology command explicitly.
        self.do("policy", "create", policy_id="p", layer="org", scope="svc", owner="o")
        self.do("policy", "draft", policy_id="p", revision=1, value=ORG_V1, at=1)
        self.do("policy", "publish", policy_id="p", revision=1)
        for cluster_name, logv in (("east", "info"), ("west", "warn")):
            self.do("policy", "create", policy_id="w" if cluster_name == "west" else "e-all",
                    namespace=cluster_name, scope="svc", owner=cluster_name)
            if cluster_name == "west":
                self.do("policy", "draft", policy_id="w", revision=1,
                        value={"log": "warn"}, at=2)
                self.do("policy", "publish", policy_id="w", revision=1)
            self.do("agent", "register", replica_id=f"{cluster_name}-1",
                    service="svc", namespace=cluster_name, generation=1, healthy=True)
            self.do("agent", "observe", observation_id=f"{cluster_name}-1:o",
                    replica_id=f"{cluster_name}-1", generation=1, observed_at=5,
                    received_at=6, policy_id="p", revision=1,
                    value={"tls": "old", "log": logv})
        west = resolve_target(self.db, namespace="west", service="svc")
        self.assertEqual(west["values"], {"tls": "old", "log": "warn"})
        east = resolve_target(self.db, namespace="east", service="svc")
        # east has no cluster override policy published (draft-only e-all), so
        # it inherits the organization values.
        self.assertEqual(east["values"], {"tls": "old", "log": "info"})
        plan = self.do("drift", "plan", plan_id="wp", policy_id="w",
                       service="svc", namespace="west", min_healthy=0, at=7)
        self.assertEqual(plan["status"], "noop")
        self.audit()


class RouteADynamicInheritance(HierarchyWorkspace):
    def test_two_independent_cluster_plans_and_full_west_convergence(self):
        self.drill_six()
        self.publish_org(revision=2, at=10)
        east = self.do("drift", "plan", plan_id="pe", policy_id="p",
                       service="svc", cluster="east", min_healthy=2, at=11)
        west = self.do("drift", "plan", plan_id="pw", policy_id="p",
                       service="svc", cluster="west", min_healthy=2, at=11)
        self.assertEqual(east["status"], "planned")
        self.assertEqual(west["status"], "planned")
        # 3 healthy against min_healthy 2 leaves exactly one serial slot.
        self.assertEqual([w["wave"] for w in west["waves"]], [1, 2, 3])
        self.assertEqual(west["revision_vector"], {"p": 2, "w": 1})
        self.assertEqual(west["target"], {"tls": "new", "log": "warn"})
        # Same policy/service may own one plan per cluster, not globally.
        # One dispatch in each cluster is allowed simultaneously.
        self.assertEqual(self.do("drift", "dispatch", action_id="pe:e1")["status"],
                         "dispatched")
        self.assertEqual(self.do("drift", "dispatch", action_id="pw:w1")["status"],
                         "dispatched")
        # Second west replica cannot start: wave 1 not confirmed.
        blocked = self.do("drift", "dispatch", action_id="pw:w2")
        self.assertEqual(blocked["status"], "blocked")
        # Complete west serially on the composed value.
        first = self.repair_step("pw", "w1", {"tls": "new", "log": "warn"}, 20)
        self.assertEqual(first["status"], "confirmed")
        second = self.repair_step("pw", "w2", {"tls": "new", "log": "warn"}, 30)
        self.assertEqual(second["status"], "confirmed")
        third = self.repair_step("pw", "w3", {"tls": "new", "log": "warn"}, 40)
        self.assertEqual(third["status"], "converged")
        self.assertEqual(row(self.db, "SELECT status FROM plans WHERE id='pw'")["status"],
                         "converged")
        # Route A timing: start immediately after publish, three 8-minute slots
        # fit a 30-minute maintenance window measured from publication.
        schedule = self.do("drift", "schedule", plan_id="pw", wave_minutes=8,
                           window_minutes=30, start_at=11, window_origin=10)
        self.assertTrue(schedule["fits"])
        self.assertTrue(schedule["meets_maintenance"])
        self.assertEqual(schedule["finish_at"], 35)
        self.audit()


class RouteBPinWindow(HierarchyWorkspace):
    def test_pin_freezes_west_then_health_window_releases_independent_plan(self):
        self.drill_six()
        pin = self.do("policy", "pin", pin_id="pin-west", cluster="west",
                      service="svc", min_healthy=2, window_minutes=30, at=6,
                      approved_by="ops-oncall")
        self.assertEqual(pin["status"], "pinned")
        frozen_uid = pin["target_uid"]
        self.publish_org(revision=2, at=10)
        # East moves; west keeps the pinned p@1+w@1 composition.
        self.assertEqual(self.target("east")["values"], {"tls": "new", "log": "info"})
        west = self.target("west")
        self.assertEqual(west["values"], {"tls": "old", "log": "warn"})
        self.assertTrue(west["pinned"])
        self.assertEqual(west["target_uid"], frozen_uid)
        # Converged against the pin -> nothing to dispatch yet.
        noop = self.do("drift", "plan", plan_id="w-early", policy_id="p",
                       service="svc", cluster="west", min_healthy=2, at=11)
        self.assertEqual(noop["status"], "noop")
        # A too-early release without a proven window stays blocked.
        early = self.do("policy", "release_pin", pin_id="pin-west", at=12)
        self.assertEqual(early["status"], "blocked")
        self.assertFalse(early["health"]["window_satisfied"])
        # West's own healthy samples span 30 minutes; release at t=40.
        self.do("agent", "health", sample_id="h0", cluster="west",
                service="svc", at=10, healthy_count=3, min_healthy=2)
        self.do("agent", "health", sample_id="h30", cluster="west",
                service="svc", at=40, healthy_count=3, min_healthy=2)
        released = self.do("policy", "release_pin", pin_id="pin-west", at=40)
        self.assertEqual(released["status"], "released")
        self.assertEqual(released["target"]["values"], {"tls": "new", "log": "warn"})
        self.assertFalse(released["target"]["pinned"])
        plan = self.do("drift", "plan", plan_id="w-late", policy_id="p",
                       service="svc", cluster="west", min_healthy=2, at=41)
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(len(plan["waves"]), 3)
        # Route B cannot dispatch before t=40; against a 30-minute window
        # opened at p@2 publication t=10 its serial work misses the deadline.
        schedule = self.do("drift", "schedule", plan_id="w-late", wave_minutes=10,
                           window_minutes=30, start_at=41, window_origin=10)
        self.assertFalse(schedule["meets_maintenance"])
        self.assertEqual(schedule["deadline_at"], 40)
        self.assertGreater(schedule["start_at"], schedule["deadline_at"])
        # Pin evidence is retained, not deleted.
        pin_row = row(self.db, "SELECT status FROM pins WHERE pin_id='pin-west'")
        self.assertEqual(pin_row["status"], "released")
        self.audit()

    def test_release_window_can_be_proven_by_observation_span_alone(self):
        self.drill_six()  # all west replicas have accepted observations at t=5
        self.do("policy", "pin", pin_id="pin", cluster="west", service="svc",
                min_healthy=2, window_minutes=30, at=6)
        self.publish_org(revision=2, at=10)
        # t=20 is only 15 minutes after the earliest west observation.
        self.assertEqual(self.do("policy", "release_pin", pin_id="pin", at=20)["status"],
                         "blocked")
        # t=35 gives a 30-minute cluster-local observation window.
        released = self.do("policy", "release_pin", pin_id="pin", at=35)
        self.assertEqual(released["status"], "released")
        self.assertTrue(released["health"]["observation_window_ok"])
        self.assertEqual(released["health"]["observed_replicas"], 3)
        self.audit()

    def test_revocable_pin_can_be_revoked_immediately(self):
        self.drill_six()
        self.do("policy", "pin", pin_id="pin", cluster="west", service="svc", at=6)
        self.publish_org(revision=2, at=10)
        self.assertEqual(self.target("west")["values"]["tls"], "old")
        revoked = self.do("policy", "revoke_pin", pin_id="pin", at=12)
        self.assertEqual(revoked["status"], "revoked")
        self.assertEqual(self.target("west")["values"]["tls"], "new")
        self.audit()


class IdentitySwitchTests(HierarchyWorkspace):
    def _drift_w1_w2(self):
        for i in (1, 2):
            self.do("agent", "observe", observation_id=f"w{i}:manual",
                    replica_id=f"w{i}", generation=1, observed_at=7 + i,
                    received_at=9, policy_id="w", revision=1,
                    value={"log": "custom"})

    def test_local_revision_unchanged_but_expanded_identity_fences_commands(self):
        self.drill_six()
        self._drift_w1_w2()
        # Plan under the LOCAL override id: target_revision stays w@1 forever,
        # which is exactly the numeric trap called out in the brief.
        old = self.do("drift", "plan", plan_id="old", policy_id="w",
                      service="svc", cluster="west", min_healthy=2, at=10)
        self.assertEqual(old["target_revision"], 1)
        old_uid = old["target_uid"]
        self.assertEqual(old["revision_vector"], {"p": 1, "w": 1})
        self.assertEqual([x["replica_id"] for x in old["waves"]], ["w1", "w2"])
        self.assertEqual(self.do("drift", "dispatch", action_id="old:w1")["status"],
                         "dispatched")
        # Ancestor moves after the first command is already out.
        self.publish_org(revision=2, at=11)
        current = self.target("west")
        self.assertNotEqual(current["target_uid"], old_uid)
        # w active_revision is still 1, yet the remaining old plan action is
        # fenced by the full expanded identity.
        fence = self.do("drift", "dispatch", action_id="old:w2")
        self.assertEqual(fence["status"], "blocked")
        self.assertIn("identity", fence["reason"])
        self.assertEqual(fence["frozen_target_uid"], old_uid)
        # The in-flight old command still accepts a receipt for the OLD value.
        receipt = self.do("drift", "receipt", receipt_id="old-rc",
                          action_id="old:w1", replica_id="w1", generation=1,
                          revision=1, value={"tls": "old", "log": "warn"},
                          at=12, success=True)
        self.assertEqual(receipt["status"], "applied")
        # A NEW-value receipt against the old action is an identity failure.
        # (Use w2 action which is still planned: receipt is rejected there;
        # instead prove digest validation on a duplicate id attempt path via
        # the already resolved action state below.)
        bad = self.do("drift", "receipt", receipt_id="bad-rc",
                      action_id="old:w1", replica_id="w1", generation=1,
                      value={"tls": "new", "log": "warn"}, at=12, success=True)
        self.assertEqual(bad["status"], "rejected")
        # Independent observation of the OLD expanded value confirms the OLD
        # action even though current classification is policy_changed.
        self.do("agent", "observe", observation_id="w1:old-fixed",
                replica_id="w1", generation=1, observed_at=13, received_at=14,
                policy_id="p", revision=1, value={"tls": "old", "log": "warn"})
        confirmed = self.do("drift", "confirm", action_id="old:w1")
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertEqual(confirmed["target_uid"], old_uid)
        inventory = row(self.db, "SELECT drift FROM inventories WHERE replica_id='w1'")
        self.assertEqual(inventory["drift"], "policy_changed")
        # Close the old identity wave without deleting anything.
        supersede = self.do("drift", "supersede", plan_id="old", at=15)
        self.assertEqual(supersede["status"], "superseded")
        self.assertEqual(supersede["obsoleted"], ["old:w2"])
        self.assertTrue(row(self.db, "SELECT id FROM actions WHERE id='old:w2'"))
        # New identity plan covers all replicas that still differ.
        new = self.do("drift", "plan", plan_id="new", policy_id="p",
                      service="svc", cluster="west", min_healthy=2, at=16)
        self.assertEqual(new["status"], "planned")
        self.assertEqual(new["revision_vector"], {"p": 2, "w": 1})
        self.assertEqual(len(new["waves"]), 3)
        self.do("drift", "dispatch", action_id="new:w1")
        self.do("drift", "receipt", receipt_id="new-rc", action_id="new:w1",
                replica_id="w1", generation=1,
                value={"tls": "new", "log": "warn"}, at=17, success=True)
        # Old observation/receipt cannot confirm the new target: no new
        # independent observation yet.
        self.assertEqual(self.do("drift", "confirm", action_id="new:w1")["status"],
                         "pending")
        self.do("agent", "observe", observation_id="w1:new-fixed",
                replica_id="w1", generation=1, observed_at=18, received_at=19,
                policy_id="p", revision=2, value={"tls": "new", "log": "warn"})
        self.assertEqual(self.do("drift", "confirm", action_id="new:w1")["status"],
                         "confirmed")
        self.audit()

    def test_wrong_expanded_value_receipt_fails_identity(self):
        self.drill_six()
        self._drift_w1_w2()
        # min_healthy=1 -> parallel=2, so w1 and w2 are both dispatchable.
        plan = self.do("drift", "plan", plan_id="old", policy_id="w",
                       service="svc", cluster="west", min_healthy=1, at=10)
        self.assertEqual([x["wave"] for x in plan["waves"]], [1, 1])
        self.do("drift", "dispatch", action_id="old:w1")
        self.do("drift", "dispatch", action_id="old:w2")
        bad = self.do("drift", "receipt", receipt_id="bad", action_id="old:w2",
                      replica_id="w2", generation=1,
                      value={"tls": "new", "log": "warn"}, at=11, success=True)
        self.assertEqual(bad["status"], "paused")
        self.assertFalse(bad["identity_valid"])
        self.assertEqual(row(self.db, "SELECT status FROM actions WHERE id='old:w2'")["status"],
                         "failed")
        self.audit()

    def test_supersede_blocked_while_command_outstanding(self):
        self.drill_six()
        self._drift_w1_w2()
        self.do("drift", "plan", plan_id="old", policy_id="w", service="svc",
                cluster="west", min_healthy=2, at=10)
        self.do("drift", "dispatch", action_id="old:w1")
        blocked = self.do("drift", "supersede", plan_id="old")
        self.assertEqual(blocked["status"], "blocked")
        self.assertIn("old:w1", blocked["outstanding"])
        self.audit()


class RetirementRollbackConflictCycle(HierarchyWorkspace):
    def test_local_retirement_falls_back_to_ancestor_values(self):
        self.drill_six()
        retired = self.do("policy", "retire", policy_id="w", at=20)
        self.assertEqual(retired["status"], "retired")
        west = self.target("west")
        self.assertEqual(west["values"], {"tls": "old", "log": "info"})
        self.assertNotIn("w", west["vector"])
        drift = row(self.db, "SELECT drift FROM inventories WHERE replica_id='w1'")
        self.assertEqual(drift["drift"], "policy_changed")
        self.audit()

    def test_ancestor_retirement_blocked_but_target_stays_unique(self):
        self.drill_six()
        blocked = self.do("policy", "retire", policy_id="p", at=20)
        self.assertEqual(blocked["status"], "blocked")
        ownerless = {(x["replica_id"], tuple(x["keys"]))
                     for x in blocked["blockers"]["ownerless_descendants"]}
        # West still has local log; only tls loses every owner. East loses both.
        self.assertIn(("w1", ("tls",)), ownerless)
        self.assertIn(("e1", ("log", "tls")), ownerless)
        self.assertEqual(row(self.db, "SELECT status FROM policies WHERE id='p'")["status"],
                         "active")
        self.assertIsNotNone(self.target("west")["target_uid"])
        self.audit()

    def test_ancestor_rollback_restores_values_as_new_revision(self):
        self.drill_six()
        self.publish_org(revision=2, at=10)
        self.assertEqual(self.target("west")["values"]["tls"], "new")
        rollback = self.do("policy", "rollback", policy_id="p",
                           source_revision=1, at=30)
        self.assertEqual(rollback["status"], "active")
        self.assertEqual(rollback["new_revision"], 3)
        west = self.target("west")
        self.assertEqual(west["values"], {"tls": "old", "log": "warn"})
        self.assertEqual(west["vector"]["p"], 3)
        # Rollback source and every revision remain readable.
        rev1 = row(self.db, "SELECT value,status FROM revisions WHERE policy_id='p' AND revision=1")
        self.assertIn("old", rev1["value"])
        self.assertEqual(len(__import__("cloudctl.db", fromlist=["rows"]).rows(
            self.db, "SELECT revision FROM revisions WHERE policy_id='p'")), 3)
        self.audit()

    def test_two_layer_scope_conflicts_are_blocked(self):
        self.drill_six()
        self.do("policy", "create", policy_id="p-dup", layer="org",
                scope="*", owner="other")
        self.do("policy", "draft", policy_id="p-dup", revision=1,
                value={"x": 1}, at=3)
        org_conflict = self.do("policy", "publish", policy_id="p-dup", revision=1)
        self.assertEqual(org_conflict["status"], "blocked")
        self.assertEqual(org_conflict["conflicts"], ["p"])
        self.do("policy", "create", policy_id="w-dup", layer="cluster",
                cluster="west", scope="svc", owner="other")
        self.do("policy", "draft", policy_id="w-dup", revision=1,
                value={"log": "error"}, at=4)
        cluster_conflict = self.do("policy", "publish", policy_id="w-dup", revision=1)
        self.assertEqual(cluster_conflict["status"], "blocked")
        self.assertEqual(cluster_conflict["conflicts"], ["w"])
        # Losing drafts never became active owners.
        topo = self.do("policy", "topology")
        self.assertEqual(topo["status"], "verified")
        self.audit()

    def test_inheritance_cycle_is_rejected_and_keeps_previous_chain(self):
        self.drill_six()
        cycle = self.do("policy", "node", node="org:default", kind="org",
                        parent="cluster:west", at=40)
        self.assertEqual(cycle["status"], "blocked")
        west_chain = self.do("policy", "topology")["chains"]["cluster:west"]
        self.assertEqual(west_chain, ["org:default", "cluster:west"])
        self.assertIsNotNone(self.target("west")["target_uid"])
        self.audit()


class SingleClusterFailureTests(HierarchyWorkspace):
    def test_west_outage_does_not_consume_east_budget(self):
        self.drill_six()
        self.publish_org(revision=2, at=10)
        # West loses two replicas -> only one healthy, below min_healthy=2.
        for i in (2, 3):
            self.do("agent", "register", replica_id=f"w{i}", service="svc",
                    namespace="prod", cluster="west", generation=2, healthy=False)
        west_guard = self.do("drift", "preflight", cluster="west",
                             service="svc", min_healthy=2)
        self.assertEqual(west_guard["status"], "blocked")
        self.assertEqual(west_guard["healthy"], 1)
        self.assertFalse(west_guard["healthy_enough"])
        west_plan = self.do("drift", "plan", plan_id="w", policy_id="p",
                            service="svc", cluster="west", min_healthy=2, at=11)
        self.assertEqual(west_plan["status"], "blocked")
        # East is independently healthy and plans/dispatches normally.
        east_guard = self.do("drift", "preflight", cluster="east",
                             service="svc", min_healthy=2)
        self.assertEqual(east_guard["status"], "ready")
        self.assertEqual(east_guard["healthy"], 3)
        east_plan = self.do("drift", "plan", plan_id="e", policy_id="p",
                            service="svc", cluster="east", min_healthy=2, at=11)
        self.assertEqual(east_plan["status"], "planned")
        self.assertEqual(self.do("drift", "dispatch", action_id="e:e1")["status"],
                         "dispatched")
        # Budget view for west still reports only west replicas/actions.
        west_guard2 = self.do("drift", "preflight", cluster="west",
                              service="svc", min_healthy=1)
        self.assertEqual(west_guard2["healthy"], 1)
        self.assertEqual(west_guard2["occupied"], 0)
        self.audit()

    def test_exactly_at_minimum_has_no_disruption_slot(self):
        self.drill_six()
        self.publish_org(revision=2, at=10)
        self.do("agent", "register", replica_id="w3", service="svc",
                namespace="prod", cluster="west", generation=2, healthy=False)
        guard = self.do("drift", "preflight", cluster="west",
                        service="svc", min_healthy=2)
        self.assertEqual(guard["healthy"], 2)
        self.assertTrue(guard["healthy_enough"])
        self.assertFalse(guard["can_dispatch"])
        plan = self.do("drift", "plan", plan_id="w", policy_id="p",
                       service="svc", cluster="west", min_healthy=2, at=11)
        self.assertEqual(plan["status"], "blocked")
        self.assertIn("budget", plan["reason"])
        self.audit()


class AtomicityAndReplayTests(HierarchyWorkspace):
    def test_failed_transaction_keeps_previous_unique_target(self):
        from cloudctl.db import transaction
        self.publish_org()
        before = self.target("east")["target_uid"]
        with self.assertRaises(RuntimeError):
            with transaction(self.db):
                self.db.execute(
                    "INSERT INTO policies(id,namespace,scope,owner,status) "
                    "VALUES('ghost','','svc','x','active')")
                raise RuntimeError("simulated commit failure")
        self.assertIsNone(row(self.db, "SELECT id FROM policies WHERE id='ghost'"))
        after = resolve_target(self.db, cluster="east", namespace="prod",
                               service="svc")["target_uid"]
        self.assertEqual(before, after)
        # The committed event log still replays consistently after the rollback.
        self.audit()

    def test_blocked_global_draft_publication_preserves_p1_target(self):
        self.drill_six()
        # A conflicting second org policy cannot publish; p@1 stays unique.
        self.do("policy", "create", policy_id="p2", layer="org",
                scope="svc", owner="x")
        self.do("policy", "draft", policy_id="p2", revision=1,
                value={"tls": "x"}, at=3)
        blocked = self.do("policy", "publish", policy_id="p2", revision=1)
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(self.target("west")["vector"], {"p": 1, "w": 1})
        self.audit()

    def test_full_drill_report_rebuilds_every_new_table(self):
        self.drill_six()
        self.publish_org(revision=2, at=10)
        self.do("policy", "pin", pin_id="pin", cluster="west",
                service="svc", window_minutes=30, min_healthy=2, at=11)
        self.do("agent", "health", sample_id="h", cluster="west",
                service="svc", at=40, healthy_count=3, min_healthy=2)
        self.do("policy", "release_pin", pin_id="pin", at=40)
        self.do("drift", "plan", plan_id="pw", policy_id="p",
                service="svc", cluster="west", min_healthy=2, at=41)
        result = self.audit()
        self.assertEqual(result["audit"], "consistent")
        self.assertGreaterEqual(result["event_count"], 20)


class SavedHierarchyFixtures(Workspace):
    def test_cross_cluster_fixtures_replay_consistently(self):
        expectations = {
            "跨集群继承.json": {"policy.publish": "active", "drift.confirm": "confirmed"},
            "跨集群钉住.json": {"policy.pin": "pinned", "policy.release_pin": "released"},
        }
        for filename, must_have in expectations.items():
            with self.subTest(fixture=filename):
                scenario = json.loads((FIXTURES / filename).read_text(encoding="utf-8"))
                result = run_scenario(self.db, scenario)
                self.assertEqual(result["audit"]["audit"], "consistent",
                                 result["audit"]["mismatches"])
                kinds = {}
                for item in result["steps"]:
                    pass
                statuses = {(scenario["steps"][i]["subsystem"] + "." +
                              scenario["steps"][i]["operation"]): item["result"]["status"]
                             for i, item in enumerate(result["steps"])}
                for operation, status in must_have.items():
                    self.assertEqual(statuses.get(operation), status, operation)
