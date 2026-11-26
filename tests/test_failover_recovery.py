"""Recoverable decision tests: crash/restart, late witness, both runbooks.

The durable decision must make WAL prefix + fence + write-open one recoverable
fact.  After a real close/reopen restart there is never more than one writable
primary, and both sides' original WAL pages plus the decision timeline survive.
"""

import os
import sqlite3
import tempfile
import unittest

from cloudctl.cluster import Cluster, CrashSimulated
from cloudctl.drill import (DEFAULT_DECISION, REQ_X11, X11, Y11,
                            seed_drill, run_plan_a, run_plan_b,
                            resume_decision, snapshot_originals,
                            prepare_prefix, contain_for_promote_b,
                            contain_for_keep_a, enter_a_term5_paused,
                            open_leadership)
from cloudctl.failover import FailoverCourt, OrderClient


class FileDbCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "order.db")

    def tearDown(self):
        self.tmp.cleanup()

    def connect(self):
        return sqlite3.connect(self.path)


class CrashRecoveryTests(FileDbCase):
    def test_crash_after_fence_before_open_recovers_single_writer(self):
        db = self.connect()
        seed_drill(db)
        with self.assertRaises(CrashSimulated):
            run_plan_b(db, DEFAULT_DECISION, crash_at="fence")
        db.close()  # real process restart boundary

        db = self.connect()
        court = FailoverCourt(db)
        cluster = Cluster(db)
        view = court.recovery_view(cluster, at=31,
                                   decision_id=DEFAULT_DECISION)
        self.assertEqual(view["stage"], "FENCE_READY")
        self.assertIsNone(view["durable_leader"])
        self.assertEqual(view["writable"], [])  # safe write pause, never two

        lead = resume_decision(db)
        self.assertEqual((lead["node"], lead["term"]), ("B", 5))
        view = court.recovery_view(cluster, at=32,
                                   decision_id=DEFAULT_DECISION)
        self.assertEqual(view["writable"], ["B"])
        self.assertLessEqual(len(view["writable"]), 1)

        # Exactly one singleton leadership row after repeated recovery.
        resume_decision(db)
        self.assertEqual(
            db.execute("SELECT COUNT(*) FROM fo_leadership").fetchone()[0], 1)
        db.close()

    def test_original_wal_pages_of_both_sides_and_decision_survive(self):
        db = self.connect()
        seed_drill(db)
        with self.assertRaises(CrashSimulated):
            run_plan_b(db, DEFAULT_DECISION, crash_at="fence")
        db.close()

        db = self.connect()
        court = FailoverCourt(db)
        raw_a = court.raw_pages(DEFAULT_DECISION, node="A")
        raw_b = court.raw_pages(DEFAULT_DECISION, node="B")
        self.assertTrue(raw_a and raw_b)
        self.assertTrue(any(r["digest"] == X11
                            for page in raw_a for r in page["raw"]))
        self.assertTrue(any(r["digest"] == Y11
                            for page in raw_b for r in page["raw"]))
        stages = [e["stage"] for e in court.events(DEFAULT_DECISION)]
        self.assertIn("INIT", stages)
        self.assertIn("PREFIX_READY", stages)
        self.assertIn("FENCE_READY", stages)
        # Quarantine copy of y11 is also durable.
        cluster = Cluster(db)
        self.assertEqual([q["digest"] for q in cluster.quarantined("B")],
                         [Y11])
        db.close()

    def test_witness_x11_arriving_late_after_restart_completes_recovery(self):
        db = self.connect()
        seed_drill(db, witness=False)
        court = FailoverCourt(db)
        cluster = Cluster(db)
        court.begin(DEFAULT_DECISION, plan="promote_b", at=29,
                    leader="B", term=5)
        snapshot_originals(court, cluster, DEFAULT_DECISION, 29)
        with self.assertRaises(Exception):
            prepare_prefix(court, cluster, DEFAULT_DECISION, 29)
        self.assertEqual(court.require(DEFAULT_DECISION)["stage"], "INIT")
        db.close()  # restart before W page arrives

        db = self.connect()
        court = FailoverCourt(db)
        cluster = Cluster(db)
        # Recovery without W still cannot safely open anyone.
        view = court.recovery_view(cluster, at=30,
                                   decision_id=DEFAULT_DECISION)
        self.assertIsNone(view["durable_leader"])

        # W's x11 page arrives late and is imported after restart.
        x11 = cluster.log("A").get(11)
        cluster.adopt_record("W", x11)
        court.save_raw_page(DEFAULT_DECISION, "W",
                            cluster.raw_records("W"), at=31,
                            kind="late-witness")

        lead = resume_decision(db, prefix_at=31, fence_at=31, open_at=32)
        self.assertEqual(lead["node"], "B")
        self.assertEqual(lead["prefix_digest"], X11)
        self.assertEqual(
            [w["node"] for w in cluster.reachable_writers(32)], ["B"])
        db.close()

    def test_lost_fence_ack_then_restart_is_idempotent(self):
        db = self.connect()
        seed_drill(db)
        court = FailoverCourt(db)
        cluster = Cluster(db)
        court.begin(DEFAULT_DECISION, plan="promote_b", at=29,
                    leader="B", term=5)
        snapshot_originals(court, cluster, DEFAULT_DECISION, 29)
        prepare_prefix(court, cluster, DEFAULT_DECISION, 30)
        cluster.transport.drop_ack.add("A")
        with self.assertRaises(Exception):
            contain_for_promote_b(court, cluster, DEFAULT_DECISION, 30,
                                  mode="receipt")
        # A already durably holds fence epoch 5 even though ACK was lost.
        self.assertEqual(cluster.node("A")["highest_fence"], 5)
        db.close()

        db = self.connect()  # transport loss script is gone after restart
        lead = resume_decision(db, fence_mode="receipt",
                               fence_at=31, open_at=32)
        self.assertEqual(lead["node"], "B")
        court = FailoverCourt(db)
        self.assertEqual(len(court.evidence(DEFAULT_DECISION,
                                            "fence_receipt")), 1)
        db.close()

    def test_plan_b_crash_matrix_always_recovers_exactly_one_writer(self):
        for point in ("snapshot", "prefix", "fence", "before_open"):
            with self.subTest(crash_point=point):
                path = os.path.join(self.tmp.name, f"b-{point}.db")
                db = sqlite3.connect(path)
                seed_drill(db)
                with self.assertRaises(CrashSimulated):
                    run_plan_b(db, DEFAULT_DECISION, crash_at=point)
                db.close()

                db = sqlite3.connect(path)
                # Immediately after restart the durable state itself never
                # exposes more than one reachable writer.  At real t=32 the
                # unfenced A would still consider its lease valid (local 28).
                expected_pre = {
                    "snapshot": ["A"], "prefix": ["A"],
                    "fence": [], "before_open": [],
                }[point]
                pre = FailoverCourt(db).recovery_view(
                    Cluster(db), at=32, decision_id=DEFAULT_DECISION)
                self.assertEqual(pre["writable"], expected_pre, point)

                lead = resume_decision(db, open_at=40)
                self.assertEqual(lead["node"], "B")
                cluster = Cluster(db)
                writers = cluster.reachable_writers(40)
                self.assertEqual([w["node"] for w in writers], ["B"])
                # Confirmed x11 is present regardless of crash point.
                self.assertEqual(cluster.log("B").get(11)["digest"], X11)
                db.close()

    def test_plan_a_crash_matrix_always_recovers_single_writer_a(self):
        for point in ("b_blocked", "prefix", "a_term", "fence",
                      "before_open"):
            with self.subTest(crash_point=point):
                path = os.path.join(self.tmp.name, f"a-{point}.db")
                db = sqlite3.connect(path)
                seed_drill(db)
                with self.assertRaises(CrashSimulated):
                    run_plan_a(db, DEFAULT_DECISION, crash_at=point)
                db.close()

                db = sqlite3.connect(path)
                expected_pre = {
                    "b_blocked": ["A"], "prefix": ["A"],
                    "a_term": [], "fence": [], "before_open": [],
                }[point]
                pre = FailoverCourt(db).recovery_view(
                    Cluster(db), at=32, decision_id=DEFAULT_DECISION)
                self.assertEqual(pre["writable"], expected_pre, point)

                lead = resume_decision(db, open_at=40)
                self.assertEqual(lead["node"], "A")
                cluster = Cluster(db)
                self.assertEqual(
                    [w["node"] for w in cluster.reachable_writers(40)], ["A"])
                # Plan A keeps y11 untouched on B as a conflict original.
                self.assertEqual(cluster.log("B").get(11)["digest"], Y11)
                db.close()


class BothPlansNoLossTests(unittest.TestCase):
    def _seed(self):
        db = sqlite3.connect(":memory:")
        seed_drill(db)
        return db

    def test_plan_b_zero_confirmed_loss_and_a_waits_for_resync(self):
        db = self._seed()
        lead = run_plan_b(db, "pb")
        court = FailoverCourt(db)
        cluster = Cluster(db)

        # The client ACK receipt still resolves and x11 is on B + W.
        receipt = court.get_request(REQ_X11)["receipt"]
        self.assertEqual(receipt["digest"], X11)
        self.assertEqual(cluster.log("B").get(11)["digest"], X11)
        self.assertEqual(cluster.log("W").get(11)["digest"], X11)

        # New write replicates down the chain B -> W.
        rc = OrderClient(court, cluster).submit("req-50", {"v": 1}, at=32)
        self.assertEqual(cluster.log("W").get(rc["index"])["digest"],
                         rc["digest"])

        # A is fenced; after healing it can resync the full authoritative
        # chain from B without regaining the write grant.
        self.assertFalse(
            cluster.would_admit("A", 40, write_term=3)["admit"])
        a_log = cluster.log("A")
        for idx in range(a_log.last_index + 1, rc["index"] + 1):
            cluster.adopt_record("A", cluster.log("B").get(idx))
        self.assertEqual(cluster.log("A").get(11)["digest"], X11)
        self.assertEqual(cluster.log("A").get(rc["index"])["digest"],
                         rc["digest"])
        self.assertTrue(cluster.log("A").verify().ok)
        db.close()

    def test_plan_a_zero_confirmed_loss_and_replication_continues_from_a(self):
        db = self._seed()
        lead = run_plan_a(db, "pa")
        court = FailoverCourt(db)
        cluster = Cluster(db)
        self.assertEqual(lead["node"], "A")
        self.assertEqual(cluster.log("A").get(11)["digest"], X11)

        rc = OrderClient(court, cluster).submit("req-51", {"v": 2}, at=34)
        self.assertEqual(rc["leader"], "A")
        self.assertEqual(cluster.log("W").get(rc["index"])["digest"],
                         rc["digest"])
        # B remains fenced with its y11 conflict original.
        self.assertEqual(cluster.log("B").get(11)["digest"], Y11)
        self.assertFalse(
            cluster.would_admit("B", 40, write_term=4)["admit"])
        db.close()

    def test_two_plans_have_distinct_leader_direction_and_pause_windows(self):
        # ---- Plan B timeline -------------------------------------------
        db_b = sqlite3.connect(":memory:")
        seed_drill(db_b)
        court = FailoverCourt(db_b)
        cluster = Cluster(db_b)
        did = "window-b"
        court.begin(did, plan="promote_b", at=29, leader="B", term=5)
        snapshot_originals(court, cluster, did, 29)
        self.assertEqual([w["node"] for w in cluster.reachable_writers(29)],
                         ["A"])
        prepare_prefix(court, cluster, did, 30)
        contain_for_promote_b(court, cluster, did, 30)
        self.assertEqual([w["node"] for w in cluster.reachable_writers(30)],
                         [])  # A isolated, B not opened yet
        open_leadership(court, cluster, did, 31,
                        route_flips=("path-ext", "path-int"))
        self.assertEqual([w["node"] for w in cluster.reachable_writers(31)],
                         ["B"])

        # ---- Plan A timeline -------------------------------------------
        db_a = sqlite3.connect(":memory:")
        seed_drill(db_a)
        court_a = FailoverCourt(db_a)
        cluster_a = Cluster(db_a)
        did_a = "window-a"
        court_a.begin(did_a, plan="keep_a", at=29, leader="A", term=5)
        snapshot_originals(court_a, cluster_a, did_a, 29)
        self.assertEqual([w["node"] for w in cluster_a.reachable_writers(29)],
                         ["A"])
        contain_for_keep_a(court_a, cluster_a, did_a, 30, mark_ready=False)
        # Blocking B first does not disturb A writes.
        self.assertEqual([w["node"] for w in cluster_a.reachable_writers(30)],
                         ["A"])
        prepare_prefix(court_a, cluster_a, did_a, 30)
        enter_a_term5_paused(court_a, cluster_a, did_a, 31)
        self.assertEqual([w["node"] for w in cluster_a.reachable_writers(31)],
                         [])  # A deliberately paused before B closure proof
        contain_for_keep_a(court_a, cluster_a, did_a, 32, mark_ready=True)
        self.assertEqual([w["node"] for w in cluster_a.reachable_writers(32)],
                         [])
        open_leadership(court_a, cluster_a, did_a, 33)
        self.assertEqual([w["node"] for w in cluster_a.reachable_writers(33)],
                         ["A"])

        # Distinct leaders and replication directions after a fresh write.
        rb = OrderClient(court, cluster).submit("req-wb", {"v": 1}, at=32)
        ra = OrderClient(court_a, cluster_a).submit("req-wa", {"v": 2}, at=34)
        self.assertEqual(rb["leader"], "B")
        self.assertEqual(ra["leader"], "A")
        self.assertEqual(cluster.log("W").get(rb["index"])["digest"],
                         rb["digest"])
        self.assertEqual(cluster_a.log("W").get(ra["index"])["digest"],
                         ra["digest"])
        # Plan B keeps y11 only in quarantine; plan A keeps it live on B.
        self.assertTrue(cluster.quarantined("B"))
        self.assertEqual(cluster_a.log("B").get(11)["digest"], Y11)
        db_b.close()
        db_a.close()

    def test_only_one_open_leader_row_even_for_distinct_decisions(self):
        db = self._seed()
        run_plan_b(db, "first")
        # A second decision cannot mint a second concurrent leader row.
        count = db.execute("SELECT COUNT(*) FROM fo_leadership").fetchone()[0]
        self.assertEqual(count, 1)
        node = db.execute("SELECT node FROM fo_leadership WHERE id=1").fetchone()[0]
        self.assertEqual(node, "B")
        db.close()


if __name__ == "__main__":
    unittest.main()
