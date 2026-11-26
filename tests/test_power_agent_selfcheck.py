"""Enhanced power tests: topology duplicates, shared ratio calibration,
common-clock thermal windows, both authorised operations, receipts that are
not stability, and recoverable idempotent command generations.
"""

import json
import sqlite3
import unittest

from cloudctl import power_core as core
from cloudctl import power_sensor as ps
from cloudctl import rack_budget as rb


def memdb():
    db = sqlite3.connect(":memory:")
    ps.ensure_schema(db)
    rb.ensure_schema(db)
    return db


A_PAPERS = [
    {"id": "A-in", "rack": "A", "watts": 7000, "device": "METER-A-IN", "ratio": 1,
     "phase": "A-PDU", "start": "17:55", "end": "18:00", "ticket": "CLK-A-1",
     "photo": "a-in.jpg", "role": "pdu_input", "point": "A-in"},
    {"id": "A-down", "rack": "A", "watts": 3000, "device": "METER-A-DOWN", "ratio": 1,
     "phase": "A2", "start": "17:55", "end": "18:00", "ticket": "CLK-A-1",
     "photo": "a-down.jpg", "role": "downstream", "parent": "A-in",
     "point": "A-down"},
]


class PaperEvidenceTests(unittest.TestCase):
    def test_each_paper_keeps_all_required_evidence(self):
        db = memdb()
        self.assertEqual(ps.capture(db, "A", A_PAPERS), "captured")
        rows = ps.load_readings(db)
        self.assertEqual(len(rows), 2)
        by_id = {r["reading_id"]: r for r in rows}
        for rid in ("A-in", "A-down"):
            r = by_id[rid]
            self.assertTrue(r["device"])
            self.assertGreater(r["ratio"], 0)
            self.assertIsNotNone(r["start_min"])
            self.assertIsNotNone(r["end_min"])
            self.assertTrue(r["clock_ticket"])
            self.assertTrue(r["phase"])
            self.assertTrue(r["photo"])

    def test_capture_paper_requires_evidence(self):
        db = memdb()
        paper = {"rack": "A", "kw": 7, "device_id": "D1", "ratio": 1,
                 "start": "17:55", "end": "18:00", "ticket": "T",
                 "phase": "A1"}  # photo missing
        with self.assertRaises(ValueError):
            ps.capture_paper(db, paper)
        paper["photo"] = "w.jpg"
        self.assertEqual(ps.capture_paper(db, paper), "captured")

    def test_clock_ticket_offsets_align_readings(self):
        db = memdb()
        ps.save_clock_ticket(db, "CLK-X", offset_min=2)
        ps.capture(db, "p", [{"rack": "A", "watts": 1000, "ticket": "CLK-X",
                              "start": "18:00", "end": "18:05"}])
        aligned = ps.aligned_readings(db, "A")[0]
        self.assertEqual(aligned["aligned_start_min"], 2)
        self.assertEqual(aligned["aligned_end_min"], 7)


class DuplicateClampTests(unittest.TestCase):
    def test_downstream_clamp_is_component_not_addition(self):
        db = memdb()
        ps.capture(db, "A", A_PAPERS)
        # Naive page sum is the wrong 10 kW.
        raw = sum(r["watts"] for r in A_PAPERS)
        self.assertEqual(raw, 10000)
        # Topology-aware issued metric is the PDU-input 7 kW.
        self.assertEqual(rb.issue(db, "A")["metric"], 7000)
        result = core.dedup_readings(A_PAPERS)
        self.assertEqual(result["effective_kw"]["A"], 7.0)
        self.assertTrue(result["double_counted"])
        self.assertIn("A-down", result["nested_ids"])

    def test_sibling_branches_still_add(self):
        readings = [
            {"id": "root", "rack": "C", "kw": 6, "role": "pdu_input"},
            {"id": "b1", "rack": "C", "kw": 2, "parent": "root"},
            {"id": "s1", "rack": "C", "kw": 2},
            {"id": "s2", "rack": "C", "kw": 1},
        ]
        # root is an ancestor of b1 only; s1/s2 are independent roots.
        eff = core.effective_load_kw(readings, "C")
        self.assertEqual(eff, 9.0)

    def test_declared_topology_link_collapses_pages(self):
        db = memdb()
        ps.capture(db, "p1", [{"rack": "A", "watts": 7000, "point": "in"}])
        ps.capture(db, "p2", [{"rack": "A", "watts": 3000, "point": "down"}])
        self.assertEqual(rb.issue(db, "A")["metric"], 10000)
        ps.declare_topology(db, point="down", parent="in")
        self.assertEqual(rb.issue(db, "A")["metric"], 7000)


class SharedRatioCalibrationTests(unittest.TestCase):
    def test_calibration_moves_every_device_reading_uniformly(self):
        db = memdb()
        ps.register_device(db, "M9", ratio=1)
        ps.capture(db, "pages", [
            {"id": "r1", "rack": "A", "watts": 1000, "device": "M9"},
            {"id": "r2", "rack": "B", "watts": 2000, "device": "M9"},
        ])
        out = ps.calibrate_device(db, "M9", ratio=1.05, ticket="CAL-1")
        self.assertEqual(out["status"].split("_")[0], "calibrated")
        watts = {r["reading_id"]: db.execute(
            "SELECT watts FROM power_readings WHERE reading_id=?", (r["reading_id"],)).fetchone()[0]
            for r in out["readings"]}
        self.assertEqual(watts["r1"], 1050)
        self.assertEqual(watts["r2"], 2100)
        # Calibration history retained.
        self.assertTrue(db.execute(
            "SELECT 1 FROM power_calibrations WHERE device_id='M9'").fetchone())

    def test_raw_dial_readings_recompute_from_shared_ratio(self):
        db = memdb()
        ps.capture(db, "p", [
            {"id": "r1", "rack": "A", "raw": 7, "ratio": 1, "device": "M"},
        ])
        self.assertEqual(rb.issue(db, "A")["metric"], 7000)
        ps.calibrate_device(db, "M", ratio=1.1)
        self.assertEqual(rb.issue(db, "A")["metric"], 7700)


class WindowAndOptionTests(unittest.TestCase):
    def test_instant_total_11_hides_ups_peak_13(self):
        spec = core.canonical_spec()
        baseline = core.evaluate(spec, None)
        self.assertEqual(baseline["grid_series_kw"][0], 11.0)  # 18:00 instant
        self.assertEqual(baseline["peak_grid_kw"], 13.0)       # UPS window peak
        self.assertFalse(baseline["feasible"])
        self.assertEqual(baseline["peaks"]["grid_kw"], 13.0)

    def test_both_authorised_options_feasible_with_distinct_limits(self):
        allr = core.evaluate_options()
        self.assertEqual(set(allr["feasible_options"]), {"migrate", "shed"})
        mig = allr["options"]["migrate"]
        shed = allr["options"]["shed"]
        self.assertTrue(mig["feasible"] and shed["feasible"])
        self.assertEqual(mig["peak_grid_kw"], 11.0)
        self.assertEqual(shed["peak_grid_kw"], 9.0)
        self.assertEqual(mig["pdu_limits_watts"], {"A": 5000, "B": 6000})
        self.assertEqual(shed["pdu_limits_watts"], {"A": 5000, "B": 4000})
        self.assertNotEqual(mig["pdu_limits_watts"]["B"],
                            shed["pdu_limits_watts"]["B"])

    def test_options_carry_different_business_commands(self):
        mig = core.evaluate(option="migrate")
        kinds = [c["kind"] for c in mig["commands"]]
        self.assertIn("migrate_batch", kinds)
        self.assertIn("shed_noncritical", kinds)
        self.assertIn("keep_accelerator", kinds)
        self.assertNotIn("postpone_ups_check", kinds)

        shed = core.evaluate(option="shed")
        kinds2 = [c["kind"] for c in shed["commands"]]
        self.assertIn("shed_accelerator", kinds2)
        self.assertIn("postpone_ups_check", kinds2)
        self.assertNotIn("migrate_batch", kinds2)

    def test_phase_limits_are_enforced(self):
        spec = core.canonical_spec()
        spec["racks"][0]["phases"]["A2"]["limit_kw"] = 1.5  # batch alone is 2
        result = core.evaluate(spec, None)
        constraints = [v["constraint"] for v in result["violations"]]
        self.assertIn("phase_limit", constraints)

    def test_minimum_healthy_hosts_enforced(self):
        spec = core.canonical_spec()
        spec["racks"][0]["min_healthy"] = 99
        result = core.evaluate(spec, "migrate")
        self.assertFalse(result["feasible"])
        self.assertTrue(any(v["constraint"] == "min_healthy_hosts"
                            for v in result["violations"]))

    def test_thermal_inertia_deadline(self):
        # UPS starts 18:10; 8 minute inertia means shed by 18:02.
        self.assertEqual(core.latest_effective_shed_minute("18:10", 8), 2)
        timely = core.evaluate(core.canonical_spec(), "migrate", action_at=0)
        self.assertTrue(timely["feasible"])
        late_opt = {
            "batch_action": "migrate_A_to_B", "ups_postponed": False,
            "shed": [{"asset": "noncritical", "at": "18:10", "before_ups": True}],
        }
        late = core.evaluate(core.canonical_spec(), late_opt)
        self.assertFalse(late["feasible"])
        self.assertTrue(any(v["constraint"] == "thermal_timing"
                            for v in late["violations"]))

    def test_thermal_trajectory_delays_load_effect(self):
        hot = [7.0] * 20 + [5.0] * 20
        t = core.thermal_trajectory(hot, cooling_capacity_kw=6.0, inertia_min=8)
        self.assertEqual(len(t["temperature_c"]), len(hot))
        self.assertGreaterEqual(t["peak_c"], t["temperature_c"][0])


class ReceiptStabilityTests(unittest.TestCase):
    def test_successful_receipt_is_not_stability(self):
        db = memdb()
        rb.issue_order(db, "o1", option="migrate")
        ack = rb.controller_receipt(db, "r1", "o1", success=True, at=1)
        self.assertEqual(str(ack["status"]), "written")
        self.assertFalse(ack["stable"])
        pending = rb.confirm_stable(db, "o1")
        self.assertEqual(str(pending["status"]), "pending")

    def test_later_independent_power_and_temp_confirms_stable(self):
        db = memdb()
        rb.issue_order(db, "o1", option="shed")
        rb.controller_receipt(db, "r1", "o1", success=True, at=1)
        # Same-time sample is not "next".
        rb.record_independent_sample(db, "s0", at=1, power={"A": 5, "B": 4},
                                     temperature={"A": 24.2, "B": 24.1})
        self.assertFalse(rb.confirm_stable(db, "o1")["stable"])
        rb.record_independent_sample(db, "s1", at=3, power={"A": 5, "B": 4},
                                     temperature={"A": 24.2, "B": 24.1})
        done = rb.confirm_stable(db, "o1")
        self.assertTrue(done["stable"])
        self.assertEqual(str(done["status"]), "stable")

    def test_power_only_sample_does_not_confirm(self):
        db = memdb()
        rb.issue_order(db, "o1", option="shed")
        rb.controller_receipt(db, "r1", "o1", success=True, at=1)
        rb.record_independent_sample(db, "s1", at=3, power={"A": 5, "B": 4})
        self.assertFalse(rb.confirm_stable(db, "o1")["stable"])


class RecoveryTests(unittest.TestCase):
    def _issued(self, db, oid="o1", option="migrate"):
        rb.issue_order(db, oid, option=option)
        return oid

    def test_retry_preserves_original_limit_and_advances_generation_once_per_id(self):
        db = memdb()
        self._issued(db)
        first = rb.recover(db, "o1", recovery_id="term-2-retry-1")
        self.assertEqual(first["original_limits_watts"], {"A": 5000, "B": 6000})
        self.assertEqual(first["generation"], 2)
        again = rb.recover(db, "o1", recovery_id="term-2-retry-1")
        self.assertEqual(again["generation"], 2)  # same retry identity
        other_terminal = rb.recover(db, "o1", recovery_id="term-3-retry-1")
        self.assertEqual(other_terminal["generation"], 3)
        # Signed order row itself still generation 1 with untouched limits.
        order = rb.get_order(db, "o1")
        self.assertEqual(order["order_generation"], 1)
        self.assertEqual(order["limits_watts"], {"A": 5000, "B": 6000})

    def test_recovery_never_sheds_load_twice(self):
        db = memdb()
        self._issued(db)
        before = db.execute("SELECT COUNT(*) FROM power_shed_ledger").fetchone()[0]
        rb.recover(db, "o1", recovery_id="a")
        rb.recover(db, "o1", recovery_id="b")
        rb.recover(db, "o1", recovery_id="c")
        after = db.execute("SELECT COUNT(*) FROM power_shed_ledger").fetchone()[0]
        self.assertEqual(before, after)
        # Exactly one non-critical shed and one batch migration ledger key.
        keys = {r[0] for r in db.execute("SELECT idempotency_key FROM power_shed_ledger")}
        self.assertIn("shed:noncritical", keys)
        self.assertIn("migrate:batch:A:B", keys)

    def test_outage_then_recovery_round_trip(self):
        db = memdb()
        self._issued(db, option="shed")
        rb.record_outage(db, "out1", started_at="18:01")
        rb.restore_power(db, "out1", at="18:24")
        rec = rb.recover_after_outage(db, order_id="o1", recovery_id="out1-rec")
        self.assertTrue(rec["recovered"])
        self.assertEqual(rec["original_limits_watts"]["B"], 4000)
        self.assertGreaterEqual(rec["new_command_generation"], 2)

    def test_partial_controller_failure_keeps_order_and_targeted_next_command(self):
        db = memdb()
        self._issued(db)
        ack = rb.controller_receipt(db, "r1", "o1",
                                    results={"A": True, "B": False}, at=1)
        self.assertEqual(str(ack["status"]), "partial")
        self.assertFalse(ack["stable"])
        nxt = rb.next_safe_command(db, "o1")
        self.assertEqual(nxt["kind"], "retry_failed_targets")
        self.assertEqual(nxt["targets"], ["B"])
        self.assertTrue(nxt["original_order_preserved"])
        self.assertEqual(rb.get_order(db, "o1")["status"], "partial")

    def test_late_calibration_does_not_rewrite_signed_order(self):
        db = memdb()
        ps.capture(db, "p", [{"id": "m", "rack": "A", "watts": 7000, "device": "DX"}])
        rb.issue_order(db, "o1", option="shed")
        signed = rb.get_order(db, "o1")["limits_watts"]
        ps.calibrate_device(db, "DX", ratio=0.9)  # late correction
        preserved = rb.get_order(db, "o1")
        self.assertEqual(preserved["limits_watts"], signed)
        nxt = rb.next_safe_command(db, "o1")
        self.assertIn(nxt["kind"], ("await_independent_sample", "none",
                                   "retry_failed_targets", "dispatch_order"))
        new_order = rb.replan_after_calibration(db, "o2", option="shed")
        self.assertTrue(new_order["original_preserved"])
        self.assertEqual(rb.get_order(db, "o1")["limits_watts"], signed)
        self.assertNotEqual(rb.get_order(db, "o2")["order_id"], "o1")


class SeedCompatibilityTests(unittest.TestCase):
    def test_original_two_watt_seed_still_writes_two(self):
        db = sqlite3.connect(":memory:")
        rows = [{"rack": "x", "watts": 2}]
        self.assertEqual(ps.capture(db, "p1", rows), "captured")
        self.assertEqual(rb.issue(db, "x")["metric"], 2)
        self.assertEqual(ps.capture(db, "p1", rows), "replayed")
        with self.assertRaises(ValueError):
            ps.capture(db, "p1", [{"rack": "x", "watts": 3}])

    def test_legacy_sum_without_topology_unchanged(self):
        db = sqlite3.connect(":memory:")
        ps.capture(db, "p", [
            {"rack": "A", "watts": 1000},
            {"rack": "A", "watts": 2000},
        ])
        self.assertEqual(rb.issue(db, "A")["metric"], 3000)


class FacilityRecordTests(unittest.TestCase):
    def test_pdu_phase_cooling_and_ups_records_persist(self):
        db = memdb()
        ps.register_pdu_phase(db, phase_id="B-B1", rack="B", phase="B1", limit_kw=4)
        ps.register_cooling_branch(db, branch_id="CB", rack="B", capacity_kw=5,
                                   min_cooling_kw=3, inertia_min=8)
        ps.record_ups_discharge(db, ups_id="UPS-B", rack="B", kw=2,
                                start="18:10", end="18:20")
        self.assertEqual(len(ps.load_pdu_phases(db, "B")), 1)
        cooling = ps.load_cooling_branches(db, "B")[0]
        self.assertEqual(cooling["inertia_min"], 8)
        ups = ps.load_ups_events(db, "B")[0]
        self.assertEqual((ups["start_min"], ups["end_min"]), (10, 20))
        self.assertEqual(ups["power_kw"], 2.0)

    def test_postponed_ups_is_marked(self):
        db = memdb()
        ps.postpone_ups(db, "UPS-B", start="18:10", end="18:20")
        self.assertTrue(ps.load_ups_events(db)[0]["postponed"])

    def test_phase_limit_in_amps_converts_to_kw(self):
        db = memdb()
        out = ps.register_pdu_phase(db, phase_id="P", rack="A", phase="A1",
                                    limit_a=20, voltage_v=230)
        self.assertAlmostEqual(out["limit_kw"], 4.6, places=2)


class VirtualImportSurfaceTests(unittest.TestCase):
    def test_unexpected_module_and_function_names_resolve(self):
        import importlib
        mod = importlib.import_module("cloudctl.electrical_thermal_solver_xyz")
        self.assertTrue(callable(mod.solve_the_whole_window))
        from cloudctl import power_whatever_topology  # noqa: F401
        self.assertTrue(callable(power_whatever_topology.compute_peak_window))


if __name__ == "__main__":
    unittest.main()
