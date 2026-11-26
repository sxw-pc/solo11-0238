"""Network fencing: the 29-34 dual-writer window and its executable closure.

Covers skew-aware leases, naive max-term danger, signed fence receipts and
loss/idempotent retry, independent gateway block proofs with exhaustive path
coverage, and the containment halves of both approved plans.
"""

import sqlite3
import unittest

from cloudctl.cluster import Cluster, PathBlocked
from cloudctl.drill import (DEFAULT_DECISION, EXT_PATHS, seed_drill,
                            run_plan_b, run_plan_a,
                            naive_paper_promotion_dual_window,
                            snapshot_originals, prepare_prefix,
                            contain_for_promote_b)
from cloudctl.failover import FailoverCourt, FenceNotReady
from cloudctl.fence import (evaluate_fence, verify_block_proof,
                            verify_fence_receipt)
from cloudctl.leader_lease import issue


class NetworkFenceTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.drill = seed_drill(self.db)
        self.court: FailoverCourt = self.drill["court"]
        self.cluster: Cluster = self.drill["cluster"]

    def tearDown(self):
        self.db.close()

    # ----- clock skew / the exact drill window ---------------------------
    def test_a_local_lease_still_admits_at_real_time_34(self):
        # Local clock lags real time by 4: real 34 -> local 30 == lease end.
        self.assertEqual(self.cluster.node("A")["lag"], 4)
        for real_t in range(29, 35):
            verdict = self.cluster.would_admit("A", real_t, write_term=3)
            self.assertTrue(verdict["admit"], (real_t, verdict["reason"]))
        expired = self.cluster.would_admit("A", 35, write_term=3)
        self.assertFalse(expired["admit"])
        self.assertIn("lease_expired", expired["reason"])

    def test_control_court_ticket_arrives_at_29(self):
        self.assertEqual(self.cluster.real_time, 29)
        self.assertEqual(issue(self.db, "B")["term"], 4)

    # ----- negative evidence: paper lease is not isolation ---------------
    def test_naive_max_term_lease_creates_dual_writers_29_to_34(self):
        demo = naive_paper_promotion_dual_window(self.db)
        self.assertEqual(demo["issued"],
                         {"node": "B", "term": 4, "index": 11})
        window = demo["window"]
        for t in ("29", "30", "31", "32", "33", "34"):
            self.assertEqual(window[t], ["A", "B"], f"t={t}")
        self.assertEqual(window["35"], ["B"])

    def test_lease_row_alone_satisfies_no_fence_coverage(self):
        issue(self.db, "B")
        coverage = evaluate_fence(
            old_node="A", epoch=5, required_paths=list(EXT_PATHS),
            node_secrets=self.cluster.secrets(),
            gateway_secrets={gw: s for gw, s in
                             self.db.execute("SELECT gw,secret FROM fo_gateways")},
            fence_receipts=[], gateway_proofs=[])
        self.assertFalse(coverage.satisfied)
        self.assertEqual(set(coverage.missing_paths), set(EXT_PATHS))

    # ----- gateway proofs are real enforcement ---------------------------
    def test_gateway_block_is_enforced_and_proof_is_independently_signed(self):
        proof = self.cluster.block_path("path-ext", 30)
        gw_secret = self.cluster.gateway_secret("gw-edge")
        self.assertTrue(verify_block_proof(proof, gw_secret))
        self.assertFalse(verify_block_proof(proof, "wrong-secret"))
        with self.assertRaises(PathBlocked):
            self.cluster.deliver("path-ext", 30, write_term=3)
        # The other independent entry path is still live -> partial coverage.
        self.assertEqual(
            [w["node"] for w in self.cluster.reachable_writers(30)], ["A"])

        coverage = evaluate_fence(
            old_node="A", epoch=5, required_paths=list(EXT_PATHS),
            node_secrets=self.cluster.secrets(),
            gateway_secrets={"gw-edge": self.cluster.gateway_secret("gw-edge"),
                             "gw-core": self.cluster.gateway_secret("gw-core")},
            gateway_proofs=[proof])
        self.assertFalse(coverage.satisfied)
        self.assertEqual(coverage.missing_paths, ["path-int"])

    def test_forged_or_court_signed_proof_is_rejected(self):
        proof = self.cluster.block_path("path-ext", 30)
        forged = dict(proof)
        forged["gateway"] = "control-court"
        # Court has no gateway secret; signature cannot verify under gw-edge.
        self.assertFalse(
            verify_block_proof(forged, self.cluster.gateway_secret("gw-edge")))

    def test_all_path_proofs_satisfy_gateway_fence(self):
        proofs = [self.cluster.block_path(pid, 30) for pid in EXT_PATHS]
        secrets = {gw: s for gw, s in
                   self.db.execute("SELECT gw,secret FROM fo_gateways")}
        coverage = evaluate_fence(
            old_node="A", epoch=5, required_paths=list(EXT_PATHS),
            node_secrets=self.cluster.secrets(), gateway_secrets=secrets,
            gateway_proofs=proofs)
        self.assertTrue(coverage.satisfied, coverage.reason())
        self.assertEqual(coverage.mode, "gateways")
        self.assertEqual(len(coverage.evidence_keys), 2)
        self.assertEqual(self.cluster.reachable_writers(30), [])

    # ----- fence receipt path and lost ACK -------------------------------
    def test_fence_receipt_stops_a_at_real_time_34_despite_clock(self):
        ack = self.cluster.send_fence("A", 5, "nonce-1", 30)
        self.assertTrue(
            verify_fence_receipt(ack, self.cluster.secrets()["A"]))
        verdict = self.cluster.would_admit("A", 34, write_term=3)
        self.assertFalse(verdict["admit"])
        self.assertEqual(verdict["reason"], "fenced_stale_epoch")
        # Routes still point at A, but its own fence enforcement rejects.
        self.assertEqual(self.cluster.reachable_writers(31), [])

    def test_lost_fence_ack_blocks_open_then_idempotent_retry_succeeds(self):
        did = "fence-loss"
        self.court.begin(did, plan="promote_b", at=29, leader="B", term=5)
        snapshot_originals(self.court, self.cluster, did, 29)
        prepare_prefix(self.court, self.cluster, did, 30)

        # A durably fences, but the ACK is dropped: court must not open.
        self.cluster.transport.drop_ack.add("A")
        with self.assertRaises(FenceNotReady):
            contain_for_promote_b(self.court, self.cluster, did, 30,
                                  mode="receipt", nonce="nonce-loss")
        decision = self.court.require(did)
        self.assertNotEqual(decision["stage"], "FENCE_READY")

        # Retry with the same epoch/nonce; fence is idempotent on A.
        self.cluster.transport.drop_ack.clear()
        bundle = contain_for_promote_b(self.court, self.cluster, did, 31,
                                       mode="receipt", nonce="nonce-loss")
        self.assertTrue(bundle["satisfied"])
        self.assertEqual(bundle["mode"], "receipt")
        acks = self.court.evidence(did, "fence_receipt")
        self.assertEqual(len(acks), 1)  # one unique evidence row

    def test_lost_fence_request_leaves_a_unfenced_until_redelivered(self):
        self.cluster.transport.drop_request.add("A")
        self.assertIsNone(self.cluster.send_fence("A", 5, "n", 30))
        self.assertEqual(self.cluster.node("A")["highest_fence"], 0)
        self.cluster.transport.drop_request.clear()
        ack = self.cluster.send_fence("A", 5, "n", 31)
        self.assertTrue(verify_fence_receipt(
            ack, self.cluster.secrets()["A"]))
        self.assertEqual(self.cluster.node("A")["highest_fence"], 5)

    # ----- approved plans: containment evidence --------------------------
    def test_old_primary_real_reachability_changes_before_after_blocks(self):
        # Before containment a real client write through the gateway succeeds.
        verdict = self.cluster.deliver("path-ext", 29, write_term=3)
        self.assertTrue(verdict["admit"])
        self.assertEqual(verdict["node"], "A")
        self.assertEqual(
            [w["node"] for w in self.cluster.reachable_writers(29)], ["A"])

        # Install and verify blocks on every registered A path.
        for path_id in EXT_PATHS:
            self.cluster.block_path(path_id, 30)
        for path_id in EXT_PATHS:
            with self.assertRaises(PathBlocked):
                self.cluster.deliver(path_id, 30, write_term=3)
        self.assertEqual(self.cluster.reachable_writers(30), [])

    def test_open_is_refused_without_fence_stage(self):
        from cloudctl.failover import UnsafeOpen
        did = "no-fence"
        self.court.begin(did, plan="promote_b", at=29, leader="B", term=5)
        self.court.mark_prefix_ready(
            did, leader="B", term=5, prefix_index=11, prefix_digest="x11",
            bundle={"authoritative_digest": "x11"}, at=30)
        with self.assertRaises(UnsafeOpen):
            self.court.commit_open(did, at=31, cluster=self.cluster,
                                   route_flips=list(EXT_PATHS))
        self.assertIsNone(self.court.current_leadership())

    def test_open_basis_persists_all_four_evidence_together(self):
        import json
        lead = run_plan_b(self.db, "four-in-one", open_at=31)
        basis = lead["basis"]
        # 1) same-position digest conflict
        conflicts = basis["prefix"]["conflicts"]
        self.assertEqual(conflicts[0]["index"], 11)
        self.assertEqual(conflicts[0]["target_digest"], "y11")
        self.assertEqual(conflicts[0]["authoritative_digest"], "x11")
        # 2) client ACK bound prefix
        self.assertEqual(basis["prefix"]["authoritative_digest"], "x11")
        self.assertEqual(basis["prefix"]["authoritative_index"], 11)
        # 3) old-primary containment / real reachability
        self.assertTrue(basis["fence"]["satisfied"])
        self.assertIn("reachable_writers_after_containment", basis["fence"])
        # 4) exact new-primary open time and reachability
        self.assertEqual(basis["opened_at"], 31)
        self.assertEqual(
            [w["node"] for w in basis["open_time_reachability"]], ["B"])
        # The same composite evidence is durable as the decision JSON.
        row = self.db.execute(
            "SELECT open_basis_json FROM fo_decisions WHERE decision_id=?",
            ("four-in-one",)).fetchone()
        self.assertEqual(json.loads(row[0])["opened_at"], 31)

    def test_plan_b_binds_gateway_isolation_before_b_open(self):
        lead = run_plan_b(self.db, "pb", fence_at=30, open_at=31)
        self.assertEqual((lead["node"], lead["term"]), ("B", 5))
        basis = lead["basis"]
        self.assertTrue(basis["fence"]["satisfied"])
        self.assertEqual(basis["fence"]["mode"], "gateways")
        self.assertEqual(set(basis["fence"]["required_paths"]),
                         {"path-ext", "path-int"})
        self.assertEqual([w["node"] for w in basis["open_time_reachability"]],
                         ["B"])
        # Under gateway-only containment A's own slow clock still considers
        # its term-3 lease valid at real 34 -- exactly why exhaustive gateway
        # proof was mandatory.  Locally admitting is harmless because no
        # client path reaches A any more.
        self.assertTrue(
            self.cluster.would_admit("A", 34, write_term=3)["admit"])
        self.assertEqual(
            [w["node"] for w in self.cluster.reachable_writers(34)], ["B"])
        # A stale term-3 write traversing a flipped entry is fence-rejected.
        from cloudctl.cluster import StaleWriter
        with self.assertRaises(StaleWriter):
            self.cluster.deliver("path-int", 34, write_term=3)

    def test_plan_a_requires_both_lease_close_and_gateway_closed_proof(self):
        lead = run_plan_a(self.db, "pa")
        self.assertEqual((lead["node"], lead["term"]), ("A", 5))
        fence = lead["basis"]["fence"]
        self.assertTrue(fence["satisfied"])
        self.assertIn("lease-closed:B:4", fence["evidence_keys"])
        self.assertTrue(any(k.startswith("gateways") or
                            k.startswith("gateway-proof") or
                            k.startswith("gateway-closed")
                            for k in fence["evidence_keys"]))
        # B's old term-4 write is dead and its path is denied.
        self.assertFalse(
            self.cluster.would_admit("B", 33, write_term=4)["admit"])
        with self.assertRaises(PathBlocked):
            self.cluster.deliver("path-b", 33, write_term=5)
        self.assertEqual(
            [w["node"] for w in self.cluster.reachable_writers(33)], ["A"])
        # Plan A never rewrites B: y11 remains its live conflict original.
        self.assertEqual(self.cluster.log("B").get(11)["digest"], "y11")


if __name__ == "__main__":
    unittest.main()
