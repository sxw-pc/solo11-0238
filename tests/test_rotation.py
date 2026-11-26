import hashlib
import json
import sqlite3
import unittest

from cloudctl.db import row
from cloudctl.secret_activation import activate
from support import Workspace


def digest(material):
    return hashlib.sha256(material.encode()).hexdigest()


class RotationCoordinatorTest(Workspace):
    def register_api(self, *replicas):
        for replica_id, generation in replicas:
            self.do("agent", "register", replica_id=replica_id, service="api",
                    namespace="edge", generation=generation, healthy=True)

    def prepare(self, rotation_id="rot1", min_serving=2, deadline=30, compromise=True):
        return self.do("rotation", "prepare", rotation_id=rotation_id, service="api",
                       namespace="edge", old_key_id="k1", new_key_id="k2",
                       min_serving=min_serving, revoke_deadline=deadline, at=0,
                       suspected_compromise=compromise)

    def deliver(self, replica_id, bundle, generation=1, key_id="k2", material=None):
        return self.do("rotation", "deliver", rotation_id="rot1", bundle=bundle,
                       replica_id=replica_id, key_id=key_id,
                       digest=digest(material or f"sealed-{replica_id}-{key_id}"),
                       generation=generation, at=5)

    def activate(self, replica_id, at=6, bundle=None):
        return self.do("rotation", "issue_activation", rotation_id="rot1",
                       replica_id=replica_id, bundle=bundle, at=at)

    def acknowledge(self, command_id, generation=1, at=7, success=True):
        return self.do("rotation", "activation_receipt", rotation_id="rot1",
                       command_id=command_id, generation=generation, at=at,
                       success=success)

    def trust(self, key_id, change, at):
        command = self.do("rotation", "issue_trust", rotation_id="rot1", key_id=key_id,
                          change=change, at=at)
        if command["status"] == "sent":
            command = self.do("rotation", "trust_receipt", rotation_id="rot1",
                              command_id=command["command_id"], at=at, success=True)
        return command

    def activate_pair(self, *replicas):
        for replica_id in replicas:
            self.deliver(replica_id, f"e-{replica_id}")
            command = self.activate(replica_id)
            self.assertEqual(command["status"], "sent")
            self.assertEqual(
                self.acknowledge(command["command_id"])["status"], "activated")

    def revoke_old(self, at):
        command = self.do("rotation", "issue_trust", rotation_id="rot1", key_id="k1",
                          change="revoke", at=at)
        self.assertEqual(command["status"], "sent", command)
        return self.do("rotation", "trust_receipt", rotation_id="rot1",
                       command_id=command["command_id"], at=at, success=True)

    # ------------------------------------------------------------------
    # Authorized route A: isolate the offline replica, then revoke.
    # ------------------------------------------------------------------
    def test_route_a_isolate_offline_replica_then_revoke(self):
        self.register_api(("a", 1), ("b", 1), ("c", 1))
        self.prepare()
        self.activate_pair("a", "b")
        self.assertEqual(self.trust("k2", "trust", 9)["status"], "trusted")
        # c still serves traffic holding only k1: revocation must be blocked.
        blocked = self.do("rotation", "issue_trust", rotation_id="rot1", key_id="k1",
                          change="revoke", at=10)
        self.assertEqual(blocked["status"], "blocked")
        self.assertIn("c", blocked["proof"]["serving"])
        self.assertEqual(blocked["proof"]["overlap"], True)
        # isolate c at minute 25, revoke at 29.
        self.assertEqual(self.do("rotation", "route", rotation_id="rot1",
                                 replica_id="c", action="isolate", at=25)["status"],
                         "routed")
        receipt = self.revoke_old(29)
        self.assertEqual(receipt["status"], "revoked")
        self.assertEqual(row(self.db, "SELECT status FROM rotations WHERE rotation_id='rot1'")
                         ["status"], "completed")
        proof = self.do("rotation", "inspect", rotation_id="rot1")["proof"]
        self.assertEqual(sorted(proof["serving"]), ["a", "b"])
        self.assertEqual(proof["isolated"], ["c"])
        self.assertEqual(proof["ready_count"], 2)
        self.audit()

    # ------------------------------------------------------------------
    # Authorized route B: on-board standby d, isolate b/c, then revoke.
    # ------------------------------------------------------------------
    def test_route_b_standby_replica_preserves_quorum(self):
        self.register_api(("a", 1), ("b", 1), ("c", 1))
        self.prepare()
        self.do("agent", "register", replica_id="d", service="api", namespace="edge",
                generation=1, healthy=True)
        self.activate_pair("a", "d")
        self.assertEqual(self.trust("k2", "trust", 9)["status"], "trusted")
        # d holds a trusted key but must still be explicitly routed into traffic.
        self.assertEqual(self.do("rotation", "route", rotation_id="rot1", replica_id="d",
                                 action="serve", at=20)["status"], "routed")
        self.assertEqual(self.do("rotation", "route", rotation_id="rot1", replica_id="b",
                                 action="isolate", at=20)["status"], "routed")
        self.assertEqual(self.do("rotation", "route", rotation_id="rot1", replica_id="c",
                                 action="isolate", at=20)["status"], "routed")
        receipt = self.revoke_old(28)
        self.assertEqual(receipt["status"], "revoked")
        proof = self.do("rotation", "inspect", rotation_id="rot1")["proof"]
        self.assertEqual(sorted(proof["serving"]), ["a", "d"])
        self.assertEqual(sorted(proof["isolated"]), ["b", "c"])
        # b/c retain a pending activation obligation, not a deletion.
        self.assertGreaterEqual(
            row(self.db, "SELECT COUNT(*) AS n FROM activation_ledger WHERE replica_id IN ('b','c')")["n"],
            2)
        self.audit()

    # ------------------------------------------------------------------
    # Sealed envelope / device generation constraints.
    # ------------------------------------------------------------------
    def test_envelope_sealed_for_another_replica_cannot_activate(self):
        self.register_api(("a", 1), ("b", 1))
        self.prepare()
        self.deliver("b", "e-b")
        result = self.activate("a", bundle="e-b")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["sealed_for"], "b")
        self.audit()

    def test_stale_device_generation_cannot_open_valid_seal(self):
        self.register_api(("a", 1), ("b", 1))
        self.prepare()
        self.deliver("b", "e-b", generation=1)
        self.do("agent", "register", replica_id="b", service="api", namespace="edge",
                generation=2, healthy=True)
        result = self.activate("b")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual((result["sealed_generation"], result["current_generation"]), (1, 2))
        self.audit()

    def test_resending_same_bundle_bytes_is_idempotent_but_content_conflict_rejects(self):
        self.register_api(("a", 1), ("b", 1))
        self.prepare()
        first = self.deliver("a", "e-a")
        self.assertEqual(first["status"], "delivered")
        second = self.deliver("a", "e-a")
        self.assertEqual(second["status"], "replayed")
        with self.assertRaises(Exception) as context:
            self.do("rotation", "deliver", rotation_id="rot1", bundle="e-a", replica_id="a",
                    key_id="k2", digest=digest("different-material"), generation=1, at=5)
        self.assertIn("envelope_conflict", str(context.exception))
        self.audit()

    # ------------------------------------------------------------------
    # Command / receipt separation and recovery along the same key identity.
    # ------------------------------------------------------------------
    def test_sent_command_is_not_effective_until_receipt(self):
        self.register_api(("a", 1), ("b", 1))
        self.prepare()
        self.deliver("a", "e-a")
        command = self.activate("a")
        self.assertEqual(command["status"], "sent")
        # No ledger row may exist before the receipt is accepted.
        self.assertEqual(
            row(self.db, "SELECT COUNT(*) AS n FROM activation_ledger WHERE command_id=?",
                (command["command_id"],))["n"], 0)
        self.assertEqual(
            self.acknowledge(command["command_id"])["status"], "activated")
        self.assertEqual(
            row(self.db, "SELECT COUNT(*) AS n FROM activation_ledger WHERE command_id=?",
                (command["command_id"],))["n"], 1)
        self.audit()

    def test_failed_receipt_recovers_under_original_command_and_key(self):
        self.register_api(("a", 1), ("b", 1))
        self.prepare()
        self.deliver("a", "e-a")
        command = self.activate("a")
        failed = self.acknowledge(command["command_id"], generation=9, at=7)
        self.assertEqual(failed["status"], "failed")
        retry = self.activate("a", at=8)
        self.assertEqual(retry["status"], "resent")
        self.assertEqual(retry["command_id"], command["command_id"])
        self.assertEqual(
            self.acknowledge(command["command_id"], at=9)["status"], "activated")
        self.assertEqual(
            row(self.db, "SELECT COUNT(*) AS n FROM rotation_commands WHERE id=?",
                (command["command_id"],))["n"], 1)
        self.audit()

    # ------------------------------------------------------------------
    # Revocation deadline, overlap and late-returning replica.
    # ------------------------------------------------------------------
    def test_overlap_must_exist_before_revocation(self):
        self.register_api(("a", 1), ("b", 1), ("c", 1))
        self.prepare()
        self.activate_pair("a", "b")
        self.do("rotation", "route", rotation_id="rot1", replica_id="c",
                action="isolate", at=20)
        # New key not yet trusted upstream: no dual-key overlap, revoke blocked.
        blocked = self.do("rotation", "issue_trust", rotation_id="rot1", key_id="k1",
                          change="revoke", at=21)
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["proof"]["overlap"], False)
        self.audit()

    def test_suspected_leak_deadline_caps_the_overlap_window(self):
        self.register_api(("a", 1), ("b", 1))
        self.prepare(deadline=30)
        # Any transition past the deadline while k1 stays trusted is rejected.
        late = self.do("rotation", "issue_trust", rotation_id="rot1", key_id="k2",
                       change="trust", at=31)
        self.assertEqual(late["status"], "blocked")
        self.assertEqual(late["revoke_deadline"], 30)
        self.audit()

    def test_late_returning_replica_cannot_reopen_revoked_key(self):
        self.register_api(("a", 1), ("b", 1), ("c", 1))
        self.prepare()
        self.activate_pair("a", "b")
        self.trust("k2", "trust", 9)
        self.do("rotation", "route", rotation_id="rot1", replica_id="c",
                action="isolate", at=25)
        self.revoke_old(29)
        # An old k1 envelope delivered late can never re-open the revoked key.
        self.do("rotation", "deliver", rotation_id="rot1", bundle="e-c-old", replica_id="c",
                key_id="k1", digest=digest("sealed-c-k1"), generation=1, at=31)
        command = self.do("rotation", "issue_activation", rotation_id="rot1",
                          replica_id="c", bundle="e-c-old", at=32)
        receipt = self.acknowledge(command["command_id"], at=33)
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("revoked", receipt["failure_reason"])
        self.audit()

    def test_routing_quorum_never_drops_below_two_serving(self):
        self.register_api(("a", 1), ("b", 1), ("c", 1))
        self.prepare(min_serving=2)
        self.assertEqual(self.do("rotation", "route", rotation_id="rot1", replica_id="a",
                                 action="isolate", at=10)["status"], "routed")
        second = self.do("rotation", "route", rotation_id="rot1", replica_id="b",
                         action="isolate", at=10)
        self.assertEqual(second["status"], "blocked")
        self.assertEqual(second["ready_after"], 1)
        self.audit()

    def test_replica_without_trusted_key_cannot_serve(self):
        self.register_api(("a", 1), ("b", 1), ("c", 1))
        self.prepare()
        self.do("agent", "register", replica_id="d", service="api", namespace="edge",
                generation=1, healthy=True)
        blocked = self.do("rotation", "route", rotation_id="rot1", replica_id="d",
                          action="serve", at=10)
        self.assertEqual(blocked["status"], "blocked")
        self.assertIsNone(blocked["held_key"])
        self.audit()

    # ------------------------------------------------------------------
    # No key material ever reaches durable evidence or reports.
    # ------------------------------------------------------------------
    def test_key_material_never_enters_events_or_report(self):
        self.register_api(("a", 1), ("b", 1), ("c", 1))
        self.prepare()
        secret = "super-secret-key-material"
        self.deliver("a", "e-a", material=secret)
        command = self.activate("a")
        self.acknowledge(command["command_id"])
        self.trust("k2", "trust", 9)
        summary = self.audit()
        blob = json.dumps(summary, ensure_ascii=False)
        self.assertNotIn(secret, blob)
        events = json.dumps([dict(item) for item in
                             self.db.execute("SELECT input_json,result_json FROM events")
                             .fetchall()], ensure_ascii=False)
        self.assertNotIn(secret, events)
        # Only the digest of the material is stored.
        self.assertEqual(row(self.db, "SELECT digest FROM secret_envelopes WHERE bundle='e-a'")
                         ["digest"], digest(secret))


class RotationReconcileIntegrationTest(Workspace):
    def test_rotation_budget_and_routing_fence_repair_waves(self):
        # Three healthy API replicas with an active policy they drift from.
        self.policy()
        for replica_id in ("a", "b", "c"):
            self.replica(replica_id)
        self.do("rotation", "prepare", rotation_id="rot1", service="api", namespace="edge",
                old_key_id="k1", new_key_id="k2", min_serving=2, revoke_deadline=30,
                at=10, suspected_compromise=True)
        # Isolating c removes it from repair eligibility: only a/b remain.
        self.do("rotation", "route", rotation_id="rot1", replica_id="c", action="isolate", at=11)
        plan = self.do("drift", "plan", plan_id="fix", policy_id="p1", service="api",
                       min_healthy=1, at=12)
        self.assertEqual(sorted(action["replica_id"] for action in plan["waves"]), ["a", "b"])
        # Open an activation command on serving replica a without acknowledging it:
        # its key is only "sent", so the repair budget cannot count it as safe.
        self.do("rotation", "deliver", rotation_id="rot1", bundle="e-a", replica_id="a",
                key_id="k2", digest=digest("sealed-a-k2"), generation=1, at=13)
        self.do("rotation", "issue_activation", rotation_id="rot1", replica_id="a", at=14)
        # With min_healthy=1, dispatching a's repair while its key is in flight
        # would leave zero safely serving replicas and must be fenced.
        dispatch = self.do("drift", "dispatch", action_id="fix:a")
        self.assertEqual(dispatch["status"], "blocked")
        # After the receipt, the budget opens again.
        self.do("rotation", "activation_receipt", rotation_id="rot1",
                command_id="rot1:activate:a", generation=1, at=15, success=True)
        self.assertEqual(
            self.do("drift", "dispatch", action_id="fix:a")["status"], "dispatched")
        self.audit()

    def test_repair_plans_without_rotation_keep_original_budget(self):
        self.policy()
        self.replica("r1")
        self.replica("r2")
        plan = self.do("drift", "plan", plan_id="fix", policy_id="p1", service="api",
                       min_healthy=1, at=10)
        self.assertEqual([item["wave"] for item in plan["waves"]], [1, 2])
        self.assertEqual(
            self.do("drift", "dispatch", action_id="fix:r1")["status"], "dispatched")
        self.audit()


class SealedEnvelopeLedgerTest(unittest.TestCase):
    """The fixed standalone modules keep their original direct-call contract."""

    def test_generation_fence_in_provisional_ledger(self):
        db = sqlite3.connect(":memory:")
        from cloudctl.secret_bundle import capture
        self.assertEqual(capture(db, "e1", "a", "k2", "sealed-key-2", generation=1),
                         "captured")
        self.assertEqual(activate(db, "a", generation=1)["key_id"], "k2")
        with self.assertRaises(ValueError):
            activate(db, "a", generation=2)
        self.assertEqual(capture(db, "e1", "a", "k2", "sealed-key-2", generation=1),
                         "replayed")
        with self.assertRaises(ValueError):
            capture(db, "e1", "a", "k3", "different", generation=1)


if __name__ == "__main__":
    unittest.main()
