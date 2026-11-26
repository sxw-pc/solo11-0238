import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloudctl.capacity_probe import capture
from cloudctl.drill import build_drill
from cloudctl.physical_topology import (
    check_routes,
    independent_route_set,
    robust_check,
)
from cloudctl.traffic_switch import TrafficSwitch


class FailoverTopologyTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.drill = build_drill(self.db)
        self.topo = self.drill["topology"]
        self.switch = self.drill["switch"]

    def tearDown(self):
        self.db.close()

    def plan_a(self, plan_id="plan-a", **overrides):
        route = dict(self.drill["routes"]["A_n1"], old_route_id="old-E-A")
        route.update(overrides)
        return self.switch.plan({
            "plan_id": plan_id,
            "failed_node": "E",
            "routes": [route],
            "at": 10,
        })

    def takeover_a(self, plan_id="plan-a", command_id="cmd-a", probe_id="probe-a"):
        self.plan_a(plan_id)
        issued = self.switch.issue({"plan_id": plan_id, "command_id": command_id, "at": 11})
        cid = issued["command_id"] if issued.get("command_id") else issued["command_ids"][0]
        self.switch.receipt({"command_id": cid, "receipt_id": f"ack-{command_id}", "at": 12})
        result = self.switch.probe({"command_id": cid, "probe_id": probe_id, "at": 13})
        return cid, result

    def test_original_probe_and_issue_seed_contract_remains_exact(self):
        db = sqlite3.connect(":memory:")
        rows = [{"node": "x", "capacity": 2}]
        self.assertEqual(capture(db, "p1", rows), "captured")
        from cloudctl.failover_reserve import issue
        self.assertEqual(issue(db, "x")["metric"], 2)
        self.assertEqual(capture(db, "p1", rows), "replayed")
        with self.assertRaises(ValueError):
            capture(db, "p1", [{"node": "x", "capacity": 3}])

    def test_ambiguous_mappings_permit_A_alone_but_reject_A_plus_B_in_Jia(self):
        a = self.plan_a()
        self.assertEqual(a["status"], "planned")

        ab = self.switch.plan({
            "plan_id": "plan-ab-ambiguous",
            "failed_node": "E",
            "routes": [self.drill["routes"]["A_n1"], self.drill["routes"]["B_n2"]],
        })
        self.assertEqual(ab["status"], "blocked")
        jia = ab["proof"]["checks"]["jia-shared-upstream"]
        self.assertFalse(jia["feasible"])
        self.assertEqual(jia["loads"]["U-shared"], 8)
        self.assertTrue(any(v["resource"] == "U-shared" and v["load"] == 8
                            for v in ab["proof"]["combined_violations"]))
        # The same assignment is feasible in Yi, proving the block is physical
        # ambiguity rather than an arbitrary total-demand limit.
        yi = ab["proof"]["checks"]["yi-independent-upstreams"]
        self.assertTrue(yi["feasible"])
        self.assertEqual((yi["loads"]["U1"], yi["loads"]["U2"]), (5, 3))

    def test_pure_route_checks_require_ingress_egress_and_intermediate_capacity(self):
        topology = {
            "capacities": {"in": 5, "mid": 5, "out": 5},
            "paths": {"p": ["in", "mid", "out"]},
        }
        ok = check_routes(topology, [{"customer": "A", "demand": 5, "path_id": "p"}])
        self.assertTrue(ok["feasible"])
        bad_ingress = check_routes(topology, [{"customer": "A", "demand": 6, "path": ["in", "mid", "out"]}])
        self.assertFalse(bad_ingress["feasible"])
        self.assertEqual({v["resource"] for v in bad_ingress["violations"]}, {"in", "mid", "out"})

    def test_same_failure_domain_standby_is_not_accepted(self):
        result = self.switch.plan({
            "plan_id": "plan-es",
            "failed_domain": self.drill["failed_domain"],
            "routes": [self.drill["routes"]["same_domain_standby"]],
        })
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(result["proof"]["domain_conflicts"])
        self.assertIn(self.drill["failed_domain"],
                      {x["failure_domain"] for x in result["proof"]["domain_conflicts"]})

    def test_shared_upstream_is_not_independent_redundancy(self):
        routes = [self.drill["routes"]["A_n1"], self.drill["routes"]["B_n2"]]
        jia = self.topo.compatible_hypotheses()[0]
        results = {item["topology_id"]: independent_route_set(item, routes)
                   for item in self.topo.compatible_hypotheses()}
        self.assertFalse(results["jia-shared-upstream"]["independent"])
        self.assertTrue(results["yi-independent-upstreams"]["independent"])
        # robust_check itself also exposes the Jia overload.
        robust = robust_check(self.topo.compatible_hypotheses(), routes)
        self.assertFalse(robust["feasible"])

    def test_alias_names_count_once_and_duplicate_mapping_ids_do_not_overwrite(self):
        topology = {
            "aliases": {"port-a": "L", "port-b": "L"},
            "capacities": {"L": 5},
            "paths": {"p": ["port-a", "port-b"]},
        }
        result = check_routes(topology, [{"customer": "A", "demand": 3, "path_id": "p"}])
        self.assertTrue(result["feasible"], result["violations"])
        self.assertEqual(result["loads"], {"L": 3})

        mappings = [
            {"aliases": {"u": "U-shared"}, "capacities": {"U-shared": 3}},
            {"aliases": {"u": "U1"}, "capacities": {"U1": 10}},
        ]
        robust = robust_check(mappings, [{"customer": "A", "demand": 4, "path": ["u"]}])
        self.assertFalse(robust["feasible"])
        self.assertEqual(robust["mapping_count"], 2)
        self.assertEqual(len(robust["checks"]), 2)

    def test_failed_probe_allows_new_command_generation(self):
        self.plan_a("probe-fail")
        issued = self.switch.issue({"plan_id": "probe-fail", "command_id": "pf-cmd"})
        cid = issued["command_id"]
        self.switch.receipt({"command_id": cid, "receipt_id": "pf-ack"})
        pending = self.switch.probe({"command_id": cid, "probe_id": "pf-bad", "passed": False})
        self.assertEqual(pending["status"], "pending")
        retry = self.switch.issue({"route_id": "probe-fail:A", "kind": "reserve"})
        self.assertEqual(retry["status"], "sent")
        self.assertEqual(retry["generation"], 2)

    def test_revoked_current_link_has_consistent_released_state(self):
        issued = self.switch.revoke({"route_id": "old-E-B", "command_id": "rev-b"})
        self.assertEqual(issued["status"], "sent")
        self.switch.receipt({"command_id": "rev-b", "receipt_id": "rev-b-ack"})
        self.switch.probe({"command_id": "rev-b", "probe_id": "rev-b-probe"})
        link = self.switch.customer_link("B")
        self.assertFalse(link["taken_over"])
        self.assertEqual(link["state"], "released")
        self.assertEqual(link["status"], "released")

    def test_same_plan_id_with_changed_payload_conflicts(self):
        payload = {"plan_id": "conflict-plan", "routes": [self.drill["routes"]["A_n1"]]}
        self.assertEqual(self.switch.plan(payload)["status"], "planned")
        changed = {"plan_id": "conflict-plan", "routes": [self.drill["routes"]["B_n2"]]}
        with self.assertRaises(ValueError):
            self.switch.plan(changed)

    def test_port_alias_two_pages_and_ack_retry_create_one_capacity(self):
        # A second name for the same physical switch port/fibre identity.
        self.topo.alias_port("TenGigabitEthernet1/1", "uplink-N1")
        self.assertEqual(self.topo.canonical("Eth1/1"), "uplink-N1")
        self.assertEqual(self.topo.canonical("TenGigabitEthernet1/1"), "uplink-N1")

        cid, confirmed = self.takeover_a()
        self.assertEqual(confirmed["status"], "confirmed")
        # Re-deliver the same controller ACK and issue request.
        retry_ack = self.switch.receipt({
            "command_id": cid, "receipt_id": "ack-cmd-a", "at": 12,
        })
        self.assertEqual(retry_ack["status"], "replayed")
        retry_issue = self.switch.issue({"route_id": "plan-a:A", "command_id": "cmd-a"})
        self.assertTrue(retry_issue.get("replayed"))

        rows = self.db.execute(
            "SELECT resource_id, COUNT(*) AS n FROM ts_reservations WHERE route_id='plan-a:A' GROUP BY resource_id"
        ).fetchall()
        counts = {row[0]: row[1] for row in rows}
        self.assertEqual(counts.get("uplink-N1"), 1)
        occupied = self.switch.occupancy("uplink-N1")
        self.assertEqual(occupied["active"], 5)
        self.assertEqual(occupied["reserved"], 5)
        self.assertEqual(occupied["available"], 1)

    def test_receipt_only_writes_rule_probe_is_required_for_takeover(self):
        self.plan_a()
        issued = self.switch.issue({"plan_id": "plan-a", "command_id": "cmd-a"})
        cid = issued["command_id"]
        receipt = self.switch.receipt({"command_id": cid, "receipt_id": "ack"})
        self.assertEqual(receipt["status"], "written")
        link = self.switch.customer_link("A")
        self.assertFalse(link["taken_over"])
        self.assertEqual(link["state"], "failover_pending")

        # A controller-sourced confirmation is not independent.
        bad = self.switch.probe({"command_id": cid, "probe_id": "controller-only",
                                 "origin": "controller", "independent": False})
        self.assertEqual(bad["status"], "rejected")
        self.assertFalse(self.switch.customer_link("A")["taken_over"])

        probe = self.switch.probe({"command_id": cid, "probe_id": "independent-probe"})
        self.assertEqual(probe["status"], "confirmed")
        self.assertTrue(probe["taken_over"])
        self.assertTrue(self.switch.customer_link("A")["taken_over"])

    def test_emergency_route_takes_A_and_B_with_20ms_SLA(self):
        _, a_probe = self.takeover_a()
        self.assertTrue(a_probe["taken_over"])

        b_plan = self.switch.plan({"plan_id": "plan-b-proxy", "routes": [self.drill["routes"]["B_proxy"]]})
        self.assertEqual(b_plan["status"], "planned")
        issued = self.switch.issue({"plan_id": "plan-b-proxy", "command_id": "cmd-b-proxy"})
        cid = issued["command_id"]
        self.switch.receipt({"command_id": cid, "receipt_id": "ack-b-proxy"})
        self.switch.probe({"command_id": cid, "probe_id": "probe-b-proxy"})

        a_link = self.switch.customer_link("A")
        b_link = self.switch.customer_link("B")
        self.assertTrue(a_link["taken_over"])
        self.assertIn("uplink-N1", a_link["observed_path"])
        self.assertEqual(b_link["actual_path"], ["PROXY-B", "CORE"])
        self.assertEqual(b_link["latency_ms"], 20)
        self.assertEqual(b_link["sla_certificate"]["latency_ms"], 20)
        self.assertGreaterEqual(b_link["sla_certificate"]["minimum_bandwidth"], 3)
        proxy_occ = self.switch.occupancy("PROXY-B")
        self.assertEqual(proxy_occ["active"], 3)
        self.assertEqual(proxy_occ["available"], 0)

    def test_late_old_revoke_ack_keeps_new_takeover_and_is_auditable(self):
        revoke = self.switch.revoke({"route_id": "old-E-A", "command_id": "revoke-a"})
        self.assertEqual(revoke["status"], "sent")
        _, probe = self.takeover_a()
        new_command = probe["command_id"]
        cmd = self.switch.inspect({"command_id": new_command})["command"]
        self.assertEqual(cmd["predecessor_command_id"], "revoke-a")
        self.assertGreater(cmd["sequence"], revoke["sequence"])

        stale = self.switch.receipt({
            "command_id": "revoke-a", "receipt_id": "stale-ack", "generation": 99,
        })
        self.assertEqual(stale["status"], "stale_generation")
        late = self.switch.receipt({"command_id": "revoke-a", "receipt_id": "rev-ack"})
        self.assertEqual(late["status"], "written")
        duplicate = self.switch.receipt({"command_id": "revoke-a", "receipt_id": "rev-ack"})
        self.assertEqual(duplicate["status"], "replayed")
        release_probe = self.switch.probe({"command_id": "revoke-a", "probe_id": "rev-probe"})
        self.assertEqual(release_probe["status"], "revoked")

        link = self.switch.customer_link("A")
        self.assertTrue(link["taken_over"])
        self.assertEqual(link["route_id"], "plan-a:A")
        uplink = self.switch.occupancy("uplink-N1")
        self.assertEqual(uplink["active"], 5)
        old_e = self.switch.occupancy("uplink-E")
        self.assertEqual(old_e["reserved"], 3)  # Only old B remains unreleased.

    def test_jia_label_after_N1_reservation_blocks_B_N2_without_overwriting_SLA(self):
        self.takeover_a()
        before = self.switch.inspect({"customer_id": "A"})
        old_certificates = before["certificates"]
        old_e_cert = next(c for c in old_certificates if c["route_id"] == "old-E-A")
        self.assertEqual(old_e_cert["physical_path"], ["E", "uplink-E", "CORE"])

        confirmed = self.topo.confirm_hypothesis(
            "jia", evidence="new fibre label: N1/N2 same splitter", at=30)
        self.assertEqual(confirmed["status"], "confirmed")
        link = self.switch.customer_link("A")
        self.assertEqual(link["actual_path"], ["N1", "U-shared", "CORE"])

        blocked = self.switch.plan({"plan_id": "b-n2-after-label",
                                    "routes": [self.drill["routes"]["B_n2"]]})
        self.assertEqual(blocked["status"], "blocked")
        prepared = self.switch.prepare({"plan_id": "b-n2-after-label"})
        self.assertEqual(prepared["status"], "missing")  # blocked plan was not stored.

        # B can still use the independently metered emergency proxy.
        emergency = self.switch.plan({"plan_id": "b-proxy-after-label",
                                      "routes": [self.drill["routes"]["B_proxy"]]})
        self.assertEqual(emergency["status"], "planned")
        issued = self.switch.issue({"plan_id": "b-proxy-after-label", "command_id": "bp"})
        self.switch.receipt({"command_id": issued["command_id"], "receipt_id": "bp-ack"})
        self.switch.probe({"command_id": issued["command_id"], "probe_id": "bp-probe"})

        shared = self.switch.occupancy("U-shared")
        self.assertEqual(shared["capacity"], 6)
        self.assertEqual(shared["reserved"], 5)
        self.assertEqual(shared["available"], 1)
        certs = self.switch.inspect({"customer_id": "A"})["certificates"]
        stored_old = next(c for c in certs if c["sla_id"] == old_e_cert["sla_id"])
        self.assertEqual(stored_old, old_e_cert)
        self.assertIn("bp-probe", [p["probe_id"] for p in
                                   self.db.execute("SELECT probe_id FROM ts_probes").fetchall()])

    def test_yi_proof_enables_low_latency_split_routes(self):
        proof = self.topo.record_probe(
            "fibre-e2e", "physical-topology", True, at=1, origin="fibre-test",
        )
        self.assertEqual(proof["status"], "passed")
        confirmed = self.topo.confirm_hypothesis("yi", evidence="independent end-to-end fibre test", at=2)
        self.assertEqual(confirmed["status"], "confirmed")
        result = self.switch.plan({
            "plan_id": "ab-yi",
            "require_independent": True,
            "routes": [self.drill["routes"]["A_n1"], self.drill["routes"]["B_n2"]],
        })
        self.assertEqual(result["status"], "planned", result.get("proof"))
        prepared = self.switch.prepare({"plan_id": "ab-yi"})
        self.assertEqual(prepared["status"], "prepared")
        self.assertEqual(self.switch.occupancy("U1")["reserved"], 5)
        self.assertEqual(self.switch.occupancy("U2")["reserved"], 3)

        issued = self.switch.issue({"plan_id": "ab-yi"})
        self.assertEqual(len(issued["command_ids"]), 2)
        for cid in issued["command_ids"]:
            self.switch.receipt({"command_id": cid, "receipt_id": f"ack-{cid}"})
            self.switch.probe({"command_id": cid, "probe_id": f"probe-{cid}"})
        self.assertEqual(self.switch.customer_link("A")["actual_path"], ["N1", "U1", "CORE"])
        self.assertEqual(self.switch.customer_link("B")["actual_path"], ["N2", "U2", "CORE"])
        self.assertEqual(self.switch.occupancy("U1")["active"], 5)
        self.assertEqual(self.switch.occupancy("U2")["active"], 3)

    def test_partial_success_failed_generation_and_retry_recover_same_ledger(self):
        self.topo.confirm_hypothesis("yi")
        self.switch.plan({"plan_id": "ab-partial",
                          "routes": [self.drill["routes"]["A_n1"], self.drill["routes"]["B_n2"]]})
        issued = self.switch.issue({"plan_id": "ab-partial"})
        ca, cb = issued["command_ids"]
        self.switch.receipt({"command_id": ca, "receipt_id": "ack-a", "success": True})
        failed = self.switch.receipt({"command_id": cb, "receipt_id": "ack-b", "success": False})
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(self.switch.occupancy("U2")["reserved"], 0)

        confirmed_a = self.switch.probe({"command_id": ca, "probe_id": "probe-a"})
        self.assertTrue(confirmed_a["taken_over"])
        self.assertFalse(self.switch.customer_link("B")["taken_over"])

        retry = self.switch.issue({"route_id": "ab-partial:B", "kind": "reserve"})
        self.assertEqual(retry["generation"], 2)
        self.switch.receipt({"command_id": retry["command_id"], "receipt_id": "ack-b2"})
        self.switch.probe({"command_id": retry["command_id"], "probe_id": "probe-b2"})
        self.assertTrue(self.switch.customer_link("B")["taken_over"])

        audit = self.switch.inspect({})
        failed_commands = audit["failed_commands"]
        self.assertEqual([c["command_id"] for c in failed_commands], [cb])
        self.assertEqual(failed_commands[0]["generation"], 1)
        self.assertEqual(self.switch.occupancy("U2")["active"], 3)
        # One B reservation per physical resource; retry generation does not
        # insert a second U2 bandwidth row.
        n = self.db.execute(
            "SELECT COUNT(*) FROM ts_reservations WHERE route_id='ab-partial:B' AND canonical_resource_id='U2'"
        ).fetchone()[0]
        self.assertEqual(n, 1)
        total = self.db.execute(
            "SELECT COUNT(*) FROM ts_reservations WHERE route_id='ab-partial:B'"
        ).fetchone()[0]
        self.assertEqual(total, 3)

    def test_probe_before_receipt_then_late_receipt_completes_once(self):
        self.switch.plan({"plan_id": "b-early-probe", "routes": [self.drill["routes"]["B_proxy"]]})
        issued = self.switch.issue({"plan_id": "b-early-probe", "command_id": "bp"})
        cid = issued["command_id"]
        early = self.switch.probe({"command_id": cid, "probe_id": "early-probe", "at": 20})
        self.assertEqual(early["status"], "awaiting_receipt")
        self.assertFalse(self.switch.customer_link("B")["taken_over"])
        receipt = self.switch.receipt({"command_id": cid, "receipt_id": "late-write-ack", "at": 21})
        # Receipt can consume the already stored passing probe and confirm.
        self.assertEqual(receipt["status"], "confirmed")
        self.assertTrue(self.switch.customer_link("B")["taken_over"])
        duplicate_probe = self.switch.probe({"command_id": cid, "probe_id": "early-probe"})
        self.assertEqual(duplicate_probe["status"], "replayed")
        certs = self.switch.inspect({"customer_id": "B"})["certificates"]
        emergency_certs = [c for c in certs if c["route_id"] == "b-early-probe:B"]
        self.assertEqual(len(emergency_certs), 1)

    def test_observe_generation_and_health_fence_entry(self):
        from cloudctl import observe
        from cloudctl.db import initialize
        initialize(self.db)
        observe.register(self.db, {"replica_id": "N1", "service": "edge", "namespace": "edge",
                                   "generation": 1, "healthy": False})
        unhealthy = self.switch.plan({
            "plan_id": "observe-unhealthy", "expected_generation": 1,
            "routes": [self.drill["routes"]["A_n1"]],
        })
        self.assertEqual(unhealthy["status"], "blocked")
        self.assertEqual(unhealthy["proof"]["health_conflicts"][0]["type"], "observed_replica_unhealthy")

        observe.register(self.db, {"replica_id": "N1", "service": "edge", "namespace": "edge",
                                   "generation": 2, "healthy": True})
        stale = self.switch.plan({
            "plan_id": "observe-stale", "expected_generation": 1,
            "routes": [self.drill["routes"]["A_n1"]],
        })
        self.assertEqual(stale["status"], "blocked")
        self.assertEqual(stale["proof"]["health_conflicts"][0]["type"], "stale_generation")
        current = self.switch.plan({
            "plan_id": "observe-current", "expected_generation": 2,
            "routes": [self.drill["routes"]["A_n1"]],
        })
        self.assertEqual(current["status"], "planned")

    def test_executor_request_replay_and_audit_include_traffic_tables(self):
        from cloudctl.audit import report
        from cloudctl.db import connect
        from cloudctl.executor import execute
        db = connect(":memory:")
        payload = {
            "plan_id": "exec-p1", "at": 1,
            "mappings": [{"topology_id": "m", "capacities": {"N1": 6, "U": 6},
                          "paths": {"N1": ["N1", "U"]}}],
            "routes": [{"customer_id": "AX", "demand": 5, "path": ["N1", "U"]}],
        }
        self.assertEqual(execute(db, "failover", "plan", payload, "req-1")["status"], "planned")
        issued = execute(db, "failover", "issue",
                         {"plan_id": "exec-p1", "command_id": "exec-c1"}, "req-2")
        cid = issued["command_id"]
        execute(db, "failover", "receipt", {"command_id": cid, "receipt_id": "exec-a1"}, "req-3")
        confirmed = execute(db, "failover", "probe",
                            {"command_id": cid, "probe_id": "exec-pr1"}, "req-4")
        self.assertEqual(confirmed["status"], "confirmed")
        replay = execute(db, "failover", "plan", payload, "req-1")
        self.assertEqual(replay["plan_id"], "exec-p1")
        self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE request_id='req-1'").fetchone()[0], 1)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM ts_plans WHERE plan_id='exec-p1'").fetchone()[0], 1)
        audit = report(db)
        self.assertEqual(audit["audit"], "consistent", audit["mismatches"])
        db.close()

    def test_file_reopen_recovers_physical_ledger_and_audits_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failover.sqlite"
            db = sqlite3.connect(path)
            build_drill(db)
            switch = TrafficSwitch(db)
            switch.plan({"plan_id": "a-file", "routes": [{
                **self.drill["routes"]["A_n1"], "old_route_id": "old-E-A"}]})
            issued = switch.issue({"plan_id": "a-file", "command_id": "a-file-cmd"})
            cid = issued["command_id"]
            switch.receipt({"command_id": cid, "receipt_id": "a-file-ack"})
            db.commit()
            db.close()

            reopened = sqlite3.connect(path)
            recovered = TrafficSwitch(reopened)
            self.assertFalse(recovered.customer_link("A")["taken_over"])
            probe = recovered.probe({"command_id": cid, "probe_id": "a-file-probe"})
            self.assertEqual(probe["status"], "confirmed")
            before = recovered.occupancy("uplink-N1")
            reopened.commit()
            reopened.close()

            again = sqlite3.connect(path)
            final = TrafficSwitch(again)
            self.assertTrue(final.customer_link("A")["taken_over"])
            after = final.occupancy("uplink-N1")
            self.assertEqual(before["reserved"], after["reserved"])
            self.assertEqual(after["active"], 5)
            report = final.recover()
            self.assertEqual(report["recovery"], "same physical bandwidth ledger recovered")
            again.close()


if __name__ == "__main__":
    unittest.main()
