"""Provenance-graph permits and node cutover under source ambiguity.

The same inputs power every test: build b2/d2 carries two compatible upstream
evidences for its base layer L (clean L1 and tainted L0), while the running
b1/d1 build rests on a complete, clean signing chain over Lold.  A production
permit must hold under *every* compatible layer source, and repository
publishability stays separate from what nodes actually run.
"""

import unittest

from cloudctl.audit import report
from cloudctl.db import row
from support import Workspace


class ProvenanceSeed(Workspace):
    def origin(self, origin_id, trusted, description=""):
        return self.do("image", "origin", origin_id=origin_id, trusted=trusted, description=description)

    def key(self, key_id="ci-key", generation=1):
        return self.do("image", "key", key_id=key_id, generation=generation)

    def finding(self, layer_digest, level, at=1):
        return self.do("image", "layer_finding", layer_digest=layer_digest,
                       vuln_level=level, at=at)

    def evidence(self, evidence_id, layer_digest, source_layer, origin_id, at=1):
        return self.do("image", "layer_evidence", evidence_id=evidence_id,
                       layer_digest=layer_digest, source_layer=source_layer,
                       origin_id=origin_id, at=at)

    def build(self, build, digest, layers, tag="api:stable", parent_build=None,
              signing_key="ci-key", key_generation=1, at=2, packet=None):
        payload = dict(build=build, image="api", tag=tag, digest=digest,
                       source_commit=f"scm:{build}", environment_digest=f"env:{build}",
                       layers=layers, signing_key=signing_key, key_generation=key_generation,
                       builder="trusted-ci", at=at)
        if parent_build is not None:
            payload["parent_build"] = parent_build
        if packet is not None:
            payload["packet"] = packet
        return self.do("image", "build", **payload)

    def scan(self, build, digest, full_layer, scanner_version="scan-v1", at=3):
        return self.do("image", "scan", build=build, scanner_version=scanner_version,
                       full_layer=full_layer, target_digest=digest, scanned_at=at)

    def rule(self, rule_id, layer_kind, min_level, scanner_version="scan-v1", effective_at=1):
        return self.do("image", "scanner_rule", rule_id=rule_id, scanner_version=scanner_version,
                       layer_kind=layer_kind, min_level=min_level, effective_at=effective_at)

    def license(self, permit_id, build, at=4, tag="api:stable"):
        return self.do("permit", "license", permit_id=permit_id, image="api", tag=tag,
                       build=build, at=at)

    def seed_world(self):
        # Trust positions and the ci signing key generation.
        self.origin("upstream-clean", True, "verified upstream rebuild channel")
        self.origin("upstream-doubt", False, "channel that once redistributed tainted bases")
        self.key()
        self.rule("high-block", "base", "high")
        self.rule("upstream-block", "upstream", "high")
        # Old service version b1/d1 running on three healthy nodes, clean Lold chain.
        self.finding("Lroot", "none")
        self.evidence("ev-lold", "Lold", "Lroot", "upstream-clean")
        self.build("b1", "d1", ["Lold", "app1"], at=2)
        self.scan("b1", "d1", True)
        # New build b2/d2: base layer L has two physically compatible upstreams.
        self.finding("L0", "high")
        self.finding("L1", "none")
        self.evidence("ev-l-clean", "L", "L1", "upstream-clean")
        self.evidence("ev-l-taint", "L", "L0", "upstream-doubt")
        self.build("b2", "d2", ["L", "app2"], at=2)
        # The scanner only inspected the top-level application package, not the layers.
        self.scan("b2", "d2", False, at=3)

    def node(self, node_id, digest="d1", build="b1", healthy=True):
        return self.do("rollout", "register_node", node_id=node_id, service="api",
                       running_digest=digest, running_build=build, healthy=healthy)

    def seed_nodes(self):
        for node_id in ("n1", "n2", "n3"):
            self.node(node_id)

    def probe(self, probe_id, node_id, digest, at, independent=True, healthy=True):
        return self.do("rollout", "probe", probe_id=probe_id, node_id=node_id, service="api",
                       digest=digest, healthy=healthy, at=at, independent=independent)

    def switch_and_confirm(self, rollout_id, node_id, digest, dispatch_at, probe_at):
        dispatched = self.do("rollout", "switch", rollout_id=rollout_id, node_id=node_id,
                             at=dispatch_at)
        self.assertEqual(dispatched["status"], "dispatched")
        # Re-dispatch after a restart must not send the command a second time.
        self.assertEqual(self.do("rollout", "switch", rollout_id=rollout_id,
                                 node_id=node_id, at=dispatch_at)["status"], "dispatched")
        self.probe(f"probe:{rollout_id}:{node_id}", node_id, digest, probe_at)
        return self.do("rollout", "confirm", rollout_id=rollout_id, node_id=node_id, at=probe_at)


class AmbiguousBaseLayer(ProvenanceSeed):
    def test_same_inputs_block_d2_but_keep_b1_servable(self):
        self.seed_world()
        blocked = self.license("permit-d2", "b2")
        self.assertEqual(blocked["status"], "blocked")
        codes = {problem["code"] for problem in blocked["evidence"]["problems"]}
        # The scanner only saw the top-level application package: that alone blocks d2.
        self.assertIn("full_layer_scan_missing", codes)
        # Even after a full-layer scan, the tainted compatible source L0 still blocks d2:
        # a single clean path (L1) is never enough while L0 stays physically compatible.
        self.scan("b2", "d2", True, at=4)
        full = self.license("permit-d2-full", "b2", at=5)
        self.assertEqual(full["status"], "blocked")
        self.assertTrue(any(problem.get("origin_id") == "upstream-doubt"
                            for problem in full["evidence"]["problems"]))
        permitted = self.license("permit-b1", "b1")
        self.assertEqual(permitted["status"], "permitted")
        self.assertEqual(permitted["digest"], "d1")
        # The blocked decisions stay on the books instead of vanishing.
        self.assertEqual(row(self.db, "SELECT status FROM image_permits WHERE permit_id='permit-d2'")
                         ["status"], "blocked")
        self.audit()

    def test_clean_path_alone_never_licenses_when_tainted_path_remains_compatible(self):
        self.seed_world()
        # Remove only the scanner gap: a full-layer scan now exists, ambiguity remains.
        self.scan("b2", "d2", True, at=4)
        blocked = self.license("permit-d2-fullscan", "b2", at=5)
        self.assertEqual(blocked["status"], "blocked")
        codes = {problem["code"] for problem in blocked["evidence"]["problems"]}
        self.assertNotIn("full_layer_scan_missing", codes)
        self.assertIn("untrusted_origin", codes)
        # Resolving the ambiguity (tainted evidence retracted) needs an explicit order trail,
        # and a fresh permit id then licenses the exact same top-level digest.
        self.do("permit", "order", order_id="ord-retract-l0", image="api", digest="d2",
                order_type="stop", reason="tainted upstream evidence withdrawn from circulation",
                at=6, related_permit="permit-d2-fullscan")
        self.do("image", "retract_evidence", evidence_id="ev-l-taint", at=7,
                reason="upstream-doubt channel proven invalid for L")
        cleared = self.do("permit", "license", permit_id="permit-d2-clear", image="api",
                          tag="api:stable", build="b2", at=8)
        self.assertEqual(cleared["status"], "permitted")
        self.assertEqual(cleared["digest"], "d2")
        # The earlier blocked permit is still historically readable.
        self.assertEqual(row(self.db,
                             "SELECT status FROM image_permits WHERE permit_id='permit-d2-fullscan'")
                         ["status"], "blocked")
        self.audit()

    def test_late_build_packet_waits_for_base_layer_evidence(self):
        self.origin("upstream-clean", True)
        self.key()
        self.rule("high-block", "base", "high")
        # Build arrives before any provenance edge for its base layer.
        self.build("b9", "d9", ["L9", "app9"], at=2)
        self.scan("b9", "d9", True, at=3)
        waiting = self.license("permit-b9-late", "b9", at=4)
        self.assertEqual(waiting["status"], "blocked")
        self.assertIn("base_layer_evidence_missing",
                      {problem["code"] for problem in waiting["evidence"]["problems"]})
        # Late evidence fills the graph; the new permit request can now be decided.
        self.evidence("ev-l9", "L9", "Lroot9", "upstream-clean", at=5)
        granted = self.license("permit-b9-ready", "b9", at=6)
        self.assertEqual(granted["status"], "permitted")
        self.audit()


class RemediationRoutes(ProvenanceSeed):
    def test_route_a_rebuild_on_clean_source_then_retire_old_digest(self):
        self.seed_world()
        self.seed_nodes()
        self.assertEqual(self.license("permit-b1", "b1")["status"], "permitted")
        self.assertEqual(self.license("permit-d2", "b2")["status"], "blocked")
        # Route A: reproducible rebuild b3/d3 with an unambiguous clean base chain.
        self.evidence("ev-lb-clean", "Lb", "L1", "upstream-clean")
        self.build("b3", "d3", ["Lb", "app3"], parent_build="b2", at=8)
        self.scan("b3", "d3", True, at=9)
        permit = self.license("permit-b3", "b3", at=10)
        self.assertEqual(permit["status"], "permitted")
        self.assertEqual(
            row(self.db, "SELECT parent_build FROM image_builds WHERE build='b3'")["parent_build"],
            "b2")
        retag = self.do("permit", "retag", image="api", tag="api:stable", digest="d3",
                        at=11, reason="promote clean rebuild b3")
        self.assertEqual(retag["status"], "retagged")
        # Tag moved, but nodes are still running d1: publishability != node state.
        self.assertTrue(all(row(self.db,
                                "SELECT running_digest FROM image_nodes WHERE node_id=?",
                                (node_id,))["running_digest"] == "d1"
                            for node_id in ("n1", "n2", "n3")))
        rollout = self.do("rollout", "rollout", rollout_id="ro-a", image="api",
                          target_digest="d3", fallback_digest="d1", min_healthy=2, at=12)
        self.assertEqual(rollout["status"], "planned")
        self.assertEqual([wave["wave"] for wave in rollout["waves"]], [1, 2, 3])
        # Wave one at a time; jumping ahead is fenced by the health floor / wave order.
        self.assertEqual(self.do("rollout", "switch", rollout_id="ro-a", node_id="n2",
                                 at=13)["status"], "blocked")
        for index, node_id in enumerate(("n1", "n2", "n3")):
            result = self.switch_and_confirm("ro-a", node_id, "d3", 13 + index, 14 + index)
        self.assertEqual(result["status"], "complete")
        # Retiring d1 needs independent absence evidence at or after the request,
        # not merely the tag change or mid-cutover switch probes.
        early = self.do("rollout", "retire", image="api", digest="d1", at=20)
        self.assertEqual(early["status"], "pending")
        for index, node_id in enumerate(("n1", "n2", "n3")):
            self.probe(f"probe:absence:{node_id}", node_id, "d3", 20 + index)
        retired = self.do("rollout", "retire", image="api", digest="d1", at=20)
        self.assertEqual(retired["status"], "retired")
        self.assertEqual(row(self.db,
                             "SELECT COUNT(*) AS n FROM image_nodes WHERE running_digest='d1'")["n"], 0)
        self.audit()

    def test_route_b_minimal_signed_hotfix_layer_keeps_service_on_old_chain(self):
        self.seed_world()
        self.seed_nodes()
        self.assertEqual(self.license("permit-b1", "b1")["status"], "permitted")
        # Route B: separately signed minimal security layer on top of the proven b1 chain.
        self.build("b1h", "d1h", ["Lold", "app1", "h1"], parent_build="b1", at=8)
        self.scan("b1h", "d1h", True, at=9)
        permit = self.license("permit-b1h", "b1h", at=10)
        self.assertEqual(permit["status"], "permitted")
        self.assertEqual(
            row(self.db, "SELECT parent_build FROM image_builds WHERE build='b1h'")["parent_build"],
            "b1")
        self.do("permit", "retag", image="api", tag="api:stable", digest="d1h", at=11,
                reason="promote signed hotfix on b1 chain")
        rollout = self.do("rollout", "rollout", rollout_id="ro-b", image="api",
                          target_digest="d1h", fallback_digest="d1", min_healthy=2, at=12)
        last = None
        for index, node_id in enumerate(("n1", "n2", "n3")):
            last = self.switch_and_confirm("ro-b", node_id, "d1h", 13 + index, 14 + index)
        self.assertEqual(last["status"], "complete")
        for node_id in ("n1", "n2", "n3"):
            self.probe(f"probe:b-absence:{node_id}", node_id, "d1h", 20)
        self.assertEqual(self.do("rollout", "retire", image="api", digest="d1", at=20)["status"],
                         "retired")
        # The running content differs from the rebuild route: no L0/L1/Lb byte ever shipped.
        used = {item["layer"] for item in self.db.execute(
            "SELECT layer FROM image_build_layers WHERE build='b1h'").fetchall()}
        self.assertEqual(used, {"Lold", "app1", "h1"})
        self.audit()

    def test_node_probe_rollback_restores_service_after_a_failed_switch(self):
        self.seed_world()
        self.seed_nodes()
        self.evidence("ev-lb-clean", "Lb", "L1", "upstream-clean")
        self.build("b3", "d3", ["Lb", "app3"], parent_build="b2", at=8)
        self.scan("b3", "d3", True, at=9)
        self.assertEqual(self.license("permit-b3", "b3", at=10)["status"], "permitted")
        self.do("rollout", "rollout", rollout_id="ro-r", image="api", target_digest="d3",
                fallback_digest="d1", min_healthy=2, at=11)
        self.assertEqual(self.do("rollout", "switch", rollout_id="ro-r", node_id="n1",
                                 at=12)["status"], "dispatched")
        # Node reports itself back on the fallback digest; an independent probe confirms it.
        self.probe("probe:rb-n1", "n1", "d1", 13)
        pending = self.do("rollout", "rollback", rollout_id="ro-r", node_id="n1", at=13)
        self.assertEqual(pending["status"], "rolled_back")
        self.assertEqual(row(self.db,
                             "SELECT switch_status FROM image_rollout_nodes WHERE rollout_id='ro-r' "
                             "AND node_id='n1'")["switch_status"], "rolled_back")
        # Rollback is idempotent: the same request never issues a second fallback command.
        self.assertEqual(self.do("rollout", "rollback", rollout_id="ro-r", node_id="n1",
                                 at=13)["status"], "rolled_back")
        self.assertEqual(row(self.db, "SELECT status FROM image_rollouts WHERE rollout_id='ro-r'")
                         ["status"], "paused")
        self.audit()


class RevocationAndReplay(ProvenanceSeed):
    def test_key_revocation_mid_cutover_freezes_waves_without_rewriting_history(self):
        self.seed_world()
        self.seed_nodes()
        self.evidence("ev-lb-clean", "Lb", "L1", "upstream-clean")
        self.build("b3", "d3", ["Lb", "app3"], parent_build="b2", at=8)
        self.scan("b3", "d3", True, at=9)
        self.assertEqual(self.license("permit-b3", "b3", at=10)["status"], "permitted")
        self.do("rollout", "rollout", rollout_id="ro-k", image="api", target_digest="d3",
                fallback_digest="d1", min_healthy=2, at=11)
        self.switch_and_confirm("ro-k", "n1", "d3", 12, 13)
        # Signing key is revoked after one node has switched.
        self.do("image", "revoke_key", key_id="ci-key", generation=1, at=14,
                reason="key material suspected compromised")
        self.do("permit", "order", order_id="ord-recall-d3", image="api", digest="d3",
                order_type="recall", reason="signing key generation revoked", at=15)
        # Further switches are frozen; the already-issued permit row itself is not rewritten.
        blocked = self.do("rollout", "switch", rollout_id="ro-k", node_id="n2", at=16)
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(row(self.db, "SELECT status FROM image_rollouts WHERE rollout_id='ro-k'")
                         ["status"], "paused")
        self.assertEqual(row(self.db,
                             "SELECT status FROM image_permits WHERE permit_id='permit-b3'")
                         ["status"], "permitted")
        # A fresh licensing request at the later time is what reflects the revocation.
        later = self.do("permit", "license", permit_id="permit-b3-after-revoke", image="api",
                        tag="api:stable", build="b3", at=17)
        self.assertEqual(later["status"], "blocked")
        self.assertIn("signing_key_revoked",
                      {problem["code"] for problem in later["evidence"]["problems"]})
        # Resign route: new key generation signs the same rebuilt content.
        self.do("image", "key", key_id="ci-key", generation=2)
        self.build("b4", "d4", ["Lb", "app3"], parent_build="b3",
                  signing_key="ci-key", key_generation=2, at=18)
        self.scan("b4", "d4", True, at=19)
        self.assertEqual(self.license("permit-b4", "b4", at=20)["status"], "permitted")
        self.audit()

    def test_later_scanner_rule_cannot_retroactively_block_an_old_permit(self):
        self.seed_world()
        self.seed_nodes()
        self.evidence("ev-lb-clean", "Lb", "L1", "upstream-clean")
        self.build("b3", "d3", ["Lb", "app3"], parent_build="b2", at=8)
        self.scan("b3", "d3", True, at=9)
        self.assertEqual(self.license("permit-b3", "b3", at=10)["status"], "permitted")
        # A new scanner generation arrives later with a stricter rule; old permit stands.
        self.do("image", "scanner_rule", rule_id="new-medium-block", scanner_version="scan-v2",
                layer_kind="base", min_level="medium", effective_at=30)
        self.assertEqual(row(self.db,
                             "SELECT status FROM image_permits WHERE permit_id='permit-b3'")
                         ["status"], "permitted")
        # But a stop order based on the new rule is recorded and freezes new cutover requests.
        self.do("permit", "order", order_id="ord-stop-newrule", image="api", digest="d3",
                order_type="stop", reason="scan-v2 medium rule now in force", at=31)
        blocked = self.do("rollout", "rollout", rollout_id="ro-late", image="api",
                          target_digest="d3", fallback_digest="d1", min_healthy=2, at=32)
        self.assertEqual(blocked["status"], "blocked")
        self.audit()

    def test_tag_move_does_not_change_node_inventory_and_rollout_restarts_once(self):
        self.seed_world()
        self.seed_nodes()
        self.evidence("ev-lb-clean", "Lb", "L1", "upstream-clean")
        self.build("b3", "d3", ["Lb", "app3"], parent_build="b2", at=8)
        self.scan("b3", "d3", True, at=9)
        self.assertEqual(self.license("permit-b3", "b3", at=10)["status"], "permitted")
        self.do("permit", "retag", image="api", tag="api:stable", digest="d3", at=11,
                reason="repository promotion")
        # Nodes still show d1 regardless of the repository tag.
        for node_id in ("n1", "n2", "n3"):
            self.assertEqual(row(self.db,
                                 "SELECT running_digest FROM image_nodes WHERE node_id=?",
                                 (node_id,))["running_digest"], "d1")
        self.do("rollout", "rollout", rollout_id="ro-idem", image="api", target_digest="d3",
                fallback_digest="d1", min_healthy=2, at=12)
        # Replaying the whole rollout request returns the stored plan, never a second wave set.
        again = self.do("rollout", "rollout", rollout_id="ro-idem", image="api",
                        target_digest="d3", fallback_digest="d1", min_healthy=2, at=12)
        self.assertEqual(again["status"], "replayed")
        self.assertEqual(row(self.db,
                             "SELECT COUNT(*) AS n FROM image_rollout_nodes WHERE rollout_id='ro-idem'")
                         ["n"], 3)
        self.assertEqual(self.do("rollout", "switch", rollout_id="ro-idem", node_id="n1",
                                 at=13)["status"], "dispatched")
        # A restart re-driving the identical command idempotently returns the same state.
        self.assertEqual(self.do("rollout", "switch", rollout_id="ro-idem", node_id="n1",
                                 at=13)["status"], "dispatched")
        self.assertEqual(row(self.db,
                             "SELECT COUNT(*) AS n FROM image_rollout_nodes "
                             "WHERE rollout_id='ro-idem' AND switch_status='dispatched'")["n"], 1)
        self.audit()

    def test_two_builds_reusing_one_tainted_base_are_both_unpublishable(self):
        self.origin("upstream-doubt", False)
        self.key()
        self.rule("high-block", "base", "high")
        self.finding("L0", "high")
        # Two distinct build numbers reuse the same tainted base layer.
        self.evidence("ev-shared-a", "Lbase", "L0", "upstream-doubt")
        self.build("bx", "dx", ["Lbase", "appx"], at=2)
        self.build("by", "dy", ["Lbase", "appy"], at=3)
        self.scan("bx", "dx", True, at=4)
        self.scan("by", "dy", True, at=5)
        for build, digest in (("bx", "dx"), ("by", "dy")):
            result = self.license(f"permit-{build}", build, at=6)
            self.assertEqual(result["status"], "blocked")
            codes = {problem["code"] for problem in result["evidence"]["problems"]}
            self.assertTrue({"untrusted_origin", "untrusted_upstream_root"} & codes)
            self.assertTrue(any(problem.get("layer") in ("Lbase", "L0")
                                for problem in result["evidence"]["problems"]))
        self.audit()

    def test_full_event_replay_rebuilds_graph_permits_and_node_state(self):
        self.seed_world()
        self.seed_nodes()
        self.assertEqual(self.license("permit-b1", "b1")["status"], "permitted")
        self.assertEqual(self.license("permit-d2", "b2")["status"], "blocked")
        self.do("permit", "order", order_id="ord-hold-d2", image="api", digest="d2",
                order_type="stop", reason="ambiguous base layer provenance", at=5)
        result = report(self.db)
        self.assertEqual(result["audit"], "consistent", result["mismatches"])


if __name__ == "__main__":
    unittest.main()
