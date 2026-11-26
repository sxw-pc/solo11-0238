"""Transaction prefix safety: digest conflicts, ACK authority and repair.

These tests produce executable evidence for the x11/y11 drill:

* every page keeps physical node, boot generation, prev digest and signer;
* same index + different digest is a conflict a higher term cannot overwrite;
* client acknowledged x11 must end up on the new leader and replica chain;
* W's anchored x11 page repairs B while y11 is preserved as a conflict original.
"""

import sqlite3
import unittest

from cloudctl.cluster import Cluster
from cloudctl.drill import (REQ_X11, X11, Y11, seed_drill)
from cloudctl.failover import FailoverCourt
from cloudctl.leader_lease import issue
from cloudctl.wal_rich import capture_rich
from cloudctl.wal_chain import (build_prefix_basis, first_conflict,
                               verify_chain)


class TransactionPrefixTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.drill = seed_drill(self.db)
        self.court: FailoverCourt = self.drill["court"]
        self.cluster: Cluster = self.drill["cluster"]

    def tearDown(self):
        self.db.close()

    # ----- page attribution ---------------------------------------------
    def test_every_page_retains_node_boot_generation_prev_and_signer(self):
        required = {"node", "boot", "prev_digest", "signer", "sig",
                    "term", "index", "digest", "ack"}
        for holder in ("A", "B", "W"):
            for page in self.cluster.raw_records(holder):
                self.assertTrue(required <= set(page), page.keys())
                self.assertGreaterEqual(page["boot"], 1)
                self.assertEqual(page["signer"], page["node"])
                self.assertTrue(page["prev_digest"])
                self.assertTrue(page["sig"])

        secrets = self.cluster.secrets()
        for holder in ("A", "B"):
            result = verify_chain(self.cluster.raw_records(holder), secrets)
            self.assertTrue(result.ok, result.errors)
        # W's partial anchored page verifies signature even without 1..10.
        w_result = verify_chain(self.cluster.raw_records("W"), secrets)
        self.assertTrue(w_result.ok, w_result.errors)

    def test_tampering_with_a_page_breaks_signature_and_chain(self):
        pages = self.cluster.raw_records("A")
        tampered = [dict(r) for r in pages]
        tampered[-1]["digest"] = "forged-x999"
        result = verify_chain(tampered, self.cluster.secrets())
        self.assertFalse(result.ok)
        self.assertTrue(any("signature" in e for e in result.errors))

    # ----- x11 vs y11 conflict ------------------------------------------
    def test_same_position_digest_conflict_is_detected_independent_of_term(self):
        a = self.cluster.raw_records("A")
        b = self.cluster.raw_records("B")
        self.assertEqual(11, first_conflict(a, b))
        a11 = next(r for r in a if r["index"] == 11)
        b11 = next(r for r in b if r["index"] == 11)
        self.assertEqual((a11["digest"], b11["digest"]), (X11, Y11))
        self.assertEqual(a11["term"], 3)
        self.assertEqual(b11["term"], 4)  # higher term, wrong content

    def test_naive_max_term_issue_picks_unacknowledged_y11(self):
        # The unchanged provisional module really writes B term4/index11.
        picked = issue(self.db, "B")
        self.assertEqual(picked, {"node": "B", "term": 4, "index": 11})
        b11 = self.cluster.log("B").get(11)
        self.assertEqual(b11["digest"], Y11)
        self.assertFalse(b11["ack"])
        # And the max-term candidate across nodes is B, which would lose x11.
        candidates = [issue(self.db, n) for n in ("A", "B")]
        max_term = max(candidates, key=lambda r: (r["term"], r["index"]))
        self.assertEqual(max_term["node"], "B")

    # ----- prefix repair -------------------------------------------------
    def _basis_for_b(self):
        receipts = {REQ_X11: self.court.get_request(REQ_X11)["receipt"]}
        return build_prefix_basis(
            target=self.cluster.log("B"),
            authoritative_source=self.cluster.log("W"),
            ack_receipts=receipts)

    def test_prefix_basis_anchors_w_x11_to_d10_and_flags_higher_term_conflict(self):
        w11 = self.cluster.log("W").get(11)
        self.assertEqual(w11["digest"], X11)
        self.assertEqual(w11["prev_digest"], "d10")
        self.assertEqual(w11["signer"], "A")

        basis = self._basis_for_b()
        self.assertEqual(basis.authoritative_index, 11)
        self.assertEqual(basis.authoritative_digest, X11)
        self.assertEqual(basis.common_index, 10)
        self.assertEqual([r["digest"] for r in basis.records], [X11])
        self.assertEqual([q["digest"] for q in basis.quarantined], [Y11])
        conflict = basis.conflicts[0]
        self.assertEqual(conflict["index"], 11)
        self.assertEqual(conflict["target_digest"], Y11)
        self.assertEqual(conflict["authoritative_digest"], X11)
        self.assertTrue(conflict["higher_term_cannot_overwrite"])

    def test_repair_places_x11_on_b_and_preserves_y11_as_original(self):
        from cloudctl.wal_chain import apply_prefix_repair
        basis = self._basis_for_b()
        b_log = self.cluster.log("B")
        removed = apply_prefix_repair(b_log, basis)
        self.assertEqual([r["digest"] for r in removed], [Y11])
        self.assertEqual(b_log.get(11)["digest"], X11)
        self.assertEqual(b_log.get(11)["signer"], "A")  # origin signer kept
        self.assertTrue(b_log.verify().ok)

    def test_missing_witness_page_makes_prefix_unprovable(self):
        db = sqlite3.connect(":memory:")
        seed_drill(db, witness=False)
        court = FailoverCourt(db)
        cluster = Cluster(db)
        receipts = {REQ_X11: court.get_request(REQ_X11)["receipt"]}
        with self.assertRaises(Exception):
            build_prefix_basis(target=cluster.log("B"),
                               authoritative_source=cluster.log("W"),
                               ack_receipts=receipts)
        db.close()

    # ----- end-to-end prefix survival ------------------------------------
    def test_acked_x11_appears_on_new_leader_and_replication_chain(self):
        from cloudctl.drill import run_plan_b
        from cloudctl.failover import OrderClient
        run_plan_b(self.db, "pfx")

        # New leader B serves the confirmed prefix with x11.
        b11 = self.cluster.log("B").get(11)
        self.assertEqual(b11["digest"], X11)

        # A new term-5 write extends x11 and replicates to W.
        client = OrderClient(self.court, self.cluster)
        receipt = client.submit("req-21", {"order_id": "ord-21"}, at=32)
        self.assertEqual((receipt["term"], receipt["prefix_index"]), (5, 11))
        self.assertEqual(receipt["prefix_digest"], X11)
        self.assertIn("W", receipt["replicated_to"])

        w_log = self.cluster.log("W")
        self.assertEqual(w_log.get(11)["digest"], X11)
        self.assertEqual(w_log.get(receipt["index"])["digest"],
                         receipt["digest"])
        chain_for_idx = self.cluster.replication_chain(receipt["index"])
        holders = {row["holder"] for row in chain_for_idx}
        self.assertIn("W", holders)
        self.assertTrue(all(row["digest"] == receipt["digest"]
                            for row in chain_for_idx))

        # The unacknowledged y11 survives only as a quarantined conflict copy.
        quarantined = self.cluster.quarantined("B")
        self.assertEqual([q["digest"] for q in quarantined], [Y11])
        self.assertEqual(self.cluster.log("B").get(11)["digest"], X11)


class RichWalCaptureTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.drill = seed_drill(self.db)
        self.cluster = Cluster(self.db)

    def tearDown(self):
        self.db.close()

    def test_capture_rich_retains_attribution_and_verifies_signatures(self):
        pages = self.cluster.raw_records("A")
        secrets = self.cluster.secrets()
        self.assertEqual(capture_rich(self.db, "rich-A", pages,
                                      secrets=secrets), "captured")
        self.assertEqual(capture_rich(self.db, "rich-A", pages,
                                      secrets=secrets), "replayed")
        raw = self.db.execute(
            "SELECT rows_json FROM wal_pages WHERE page='rich-A'").fetchone()[0]
        import json
        stored = json.loads(raw)
        for row in stored:
            for field in ("node", "boot", "prev_digest", "signer", "sig"):
                self.assertIn(field, row)

        # A changed rich page is still a hard conflict.
        tampered = [dict(r) for r in pages]
        tampered[-1]["digest"] = "forged"
        with self.assertRaises(ValueError):
            capture_rich(self.db, "rich-A", tampered, secrets=secrets)

        # A rich page with a bad signature is refused when secrets supplied.
        bad_sig = [dict(pages[0])]
        bad_sig[0]["sig"] = "0" * 64
        with self.assertRaises(ValueError):
            capture_rich(self.db, "bad-sig", bad_sig, secrets=secrets)

    def test_legacy_capture_contract_is_unchanged(self):
        from cloudctl.wal_capture import capture
        row = {"node": "a", "term": 2, "index": 7, "digest": "d7",
               "ack": True}
        self.assertEqual(capture(self.db, "p", [row]), "captured")
        with self.assertRaises(ValueError):
            capture(self.db, "extra", [{**row, "boot": 1}])


if __name__ == "__main__":
    unittest.main()
