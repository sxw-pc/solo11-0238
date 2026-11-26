"""Duplicate client requests, failover retries and lost ACK recovery.

Exactly-once evidence:

* same ``request_id`` + same payload returns the identical receipt and creates
  exactly one WAL item even when retried;
* same id with different payload is rejected;
* retries while the primary is fenced/not yet reopened get a retryable error
  and succeed once after OPEN;
* a response/ACK lost after commit still yields the durable receipt on retry
  after a real close/reopen restart;
* the pre-failover client ACK for x11 stays idempotent across the failover.
"""

import os
import sqlite3
import tempfile
import unittest

from cloudctl.cluster import Cluster, CrashSimulated
from cloudctl.drill import (DEFAULT_DECISION, REQ_X11, seed_drill,
                            run_plan_b, snapshot_originals, prepare_prefix,
                            contain_for_promote_b, open_leadership)
from cloudctl.failover import (FailoverCourt, OrderClient,
                               RequestIdConflict, LeaderNotOpen,
                               is_retryable_write_error)


class DuplicateClientRequestTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        seed_drill(self.db)
        self.court = FailoverCourt(self.db)
        self.cluster = Cluster(self.db)
        run_plan_b(self.db, "dup", open_at=31)
        self.client = OrderClient(self.court, self.cluster)

    def tearDown(self):
        self.db.close()

    def test_duplicate_request_returns_identical_receipt_single_wal_item(self):
        payload = {"order_id": "ord-31", "total": 4200}
        first = self.client.submit("req-31", payload, at=32)
        second = self.client.submit("req-31", payload, at=33)
        self.assertEqual(first, second)
        self.assertEqual(first["index"], 12)
        rows = self.db.execute(
            "SELECT COUNT(*) FROM fo_records WHERE holder='B' AND idx=?",
            (first["index"],)).fetchone()[0]
        self.assertEqual(rows, 1)
        requests = self.db.execute(
            "SELECT COUNT(*) FROM fo_client_requests WHERE request_id='req-31'"
        ).fetchone()[0]
        self.assertEqual(requests, 1)

    def test_same_request_id_different_payload_is_conflict(self):
        self.client.submit("req-32", {"order_id": "ord-32", "v": 1}, at=32)
        with self.assertRaises(RequestIdConflict):
            self.client.submit("req-32", {"order_id": "ord-32", "v": 2}, at=33)

    def test_receipt_is_bound_to_open_term_and_x11_prefix(self):
        receipt = self.client.submit("req-33", {"order_id": "ord-33"}, at=32)
        leadership = self.court.current_leadership()
        self.assertEqual(receipt["term"], leadership["term"])
        self.assertEqual(receipt["fence_epoch"], leadership["term"])
        self.assertEqual(receipt["prefix_index"],
                         leadership["prefix_index"])
        self.assertEqual(receipt["prefix_digest"],
                         leadership["prefix_digest"])
        self.assertEqual(receipt["commit_prefix"]["digest"], "x11")
        # Replication row is bound to the same term/digest.
        repl = self.cluster.replication_chain(receipt["index"])
        self.assertTrue(repl)
        self.assertTrue(all(r["term"] == 5 and r["digest"] == receipt["digest"]
                             for r in repl))

    def test_historical_x11_client_request_stays_idempotent_after_failover(self):
        original_payload = {"order_id": "ord-11", "action": "capture",
                            "amount": 1100}
        receipt = self.client.submit(REQ_X11, original_payload, at=32)
        self.assertEqual(receipt["digest"], "x11")
        self.assertEqual(receipt["term"], 3)
        # No new index-12 item was created by replaying the old request.
        self.assertIsNone(self.cluster.log("B").get(12))

    def test_retry_during_failover_is_retryable_then_succeeds_once(self):
        db = sqlite3.connect(":memory:")
        did = "retry-window"
        seed_drill(db)
        court = FailoverCourt(db)
        cluster = Cluster(db)
        court.begin(did, plan="promote_b", at=29, leader="B", term=5)
        snapshot_originals(court, cluster, did, 29)
        prepare_prefix(court, cluster, did, 30)
        contain_for_promote_b(court, cluster, did, 30)

        client = OrderClient(court, cluster)
        payload = {"order_id": "ord-40"}
        # Fence installed, OPEN not committed: retryable, nothing written.
        try:
            client.submit("req-40", payload, at=30)
            self.fail("expected a retryable leader error")
        except Exception as error:  # noqa: BLE001 - assert retry category
            self.assertTrue(is_retryable_write_error(error), type(error))
        self.assertEqual(
            db.execute("SELECT COUNT(*) FROM fo_client_requests "
                       "WHERE request_id='req-40'").fetchone()[0], 0)

        open_leadership(court, cluster, did, 31,
                        route_flips=("path-ext", "path-int"))
        receipt = client.submit("req-40", payload, at=32)
        retry = client.submit("req-40", payload, at=32)
        self.assertEqual(receipt, retry)
        self.assertEqual(receipt["leader"], "B")
        self.assertEqual(receipt["term"], 5)
        self.assertEqual(
            db.execute("SELECT COUNT(*) FROM fo_records "
                       "WHERE holder='B' AND request_id='req-40'").fetchone()[0],
            1)
        db.close()

    def test_ack_lost_after_commit_retry_after_restart_returns_same_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "order.db")
            db = sqlite3.connect(path)
            seed_drill(db)
            run_plan_b(db, "cr", open_at=31)
            court = FailoverCourt(db)
            cluster = Cluster(db)
            client = OrderClient(court, cluster)
            payload = {"order_id": "ord-41"}
            with self.assertRaises(CrashSimulated):
                client.submit("req-41", payload, at=32,
                              crash_after_commit=True)
            # Client never saw the ACK; process restarts for real.
            db.close()

            db2 = sqlite3.connect(path)
            court2 = FailoverCourt(db2)
            cluster2 = Cluster(db2)
            client2 = OrderClient(court2, cluster2)
            receipt = client2.submit("req-41", payload, at=34)
            self.assertEqual(receipt["leader"], "B")
            self.assertEqual(receipt["term"], 5)
            self.assertEqual(receipt["index"], 12)
            # Retry after restart did not duplicate B or W entries.
            for holder in ("B", "W"):
                count = db2.execute(
                    "SELECT COUNT(*) FROM fo_records WHERE holder=? AND idx=12",
                    (holder,)).fetchone()[0]
                self.assertEqual(count, 1, holder)
            self.assertEqual(
                db2.execute("SELECT COUNT(*) FROM fo_client_requests "
                            "WHERE request_id='req-41'").fetchone()[0], 1)
            db2.close()


if __name__ == "__main__":
    unittest.main()
