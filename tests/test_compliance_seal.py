import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloudctl import merkle
from cloudctl.audit import report, replay_events, verify_sealed_evidence
from cloudctl.compliance_capture import capture
from cloudctl.compliance_seal import (
    archive_leaves, attach_late, causal_closure, export_key, get_certificate,
    issue_certificate, revoke_witness, seal_window, supplement,
)
from cloudctl.db import connect, initialize, row
from cloudctl.executor import execute
from cloudctl.reconcile import action_claims
from cloudctl.verifier import verify_bundle, verify_credential


def build_drill(dbfile):
    """The review drill: policy p@2 at event 17, applied receipt at 20, a sample
    taken at minute 29 that only lands at 41, compliance window [20, 30),
    sealed at 35. The policy draft exists before the window."""
    db = connect(dbfile)
    initialize(db)
    seq = 0

    def do(subsystem, operation, **payload):
        nonlocal seq
        seq += 1
        return execute(db, subsystem, operation, payload, f"drill:{seq}:{operation}")

    for i in range(1, 9):
        do("policy", "create", policy_id=f"p{i}", namespace="edge", scope=f"svc{i}", owner="platform")
    for i in range(1, 9):
        do("policy", "draft", policy_id=f"p{i}", revision=1, value=f"v{i}", dependencies=[], at=i)
    # event 17: policy p revision 2 published; its draft is a pre-window prerequisite.
    do("policy", "create", policy_id="p", namespace="edge", scope="a", owner="platform")
    do("policy", "draft", policy_id="p", revision=1, value="SECRET-base-value", dependencies=[], at=10)
    do("policy", "draft", policy_id="p", revision=2, value="SECRET-TARGET-VALUE", dependencies=[], at=15)
    published = do("policy", "publish", policy_id="p", revision=2)
    do("agent", "register", replica_id="a1", service="a", namespace="edge", generation=1, healthy=True)
    do("agent", "observe", observation_id="a1:old", replica_id="a1", generation=1,
        observed_at=18, received_at=19, policy_id="p", revision=1,
        value="SECRET-base-value", origin="agent")
    planned = do("drift", "plan", plan_id="fix", policy_id="p", service="a",
                 min_healthy=0, at=19)
    do("drift", "dispatch", action_id="fix:a1")
    # event 20: successful repair receipt -> applied, not yet confirmed.
    applied = do("drift", "receipt", receipt_id="rcpt", action_id="fix:a1", replica_id="a1",
                 generation=1, revision=2, value="SECRET-TARGET-VALUE", at=20, success=True)
    capture(db, "p@2", [{"service": "a", "at": 20}])
    return db, {"published": published, "planned": planned, "applied": applied}


class TimeSealDrill(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dbfile = Path(self.temp.name) / "drill.sqlite"
        self.db, self.results = build_drill(self.dbfile)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def seal(self):
        return seal_window(self.db, "a", 20, 30, 35)

    def test_seal_fixes_causal_closure_not_id_or_received_truncation(self):
        result = self.seal()
        self.assertEqual(result["status"], "sealed")
        seal = row(self.db, "SELECT * FROM seal_registry WHERE seal_id=?", (result["seal_id"],))
        window_ids = json.loads(seal["window_event_ids"])
        prereq = json.loads(seal["prereq_event_ids"])
        # The in-window events are the receipt (business time 20) plus the p@2 page.
        receipt_event = row(self.db, "SELECT id FROM events WHERE kind='drift.receipt'")
        self.assertIn(receipt_event["id"], window_ids)
        # Pre-window causal prerequisites: the rev-2 draft at 15, plan, dispatch ...
        draft_event = row(self.db, "SELECT id FROM events WHERE kind='policy.draft' "
                                   "AND input_json LIKE '%\"policy_id\":\"p\"%' "
                                   "AND input_json LIKE '%\"revision\":2%'")
        self.assertIn(draft_event["id"], prereq)
        self.assertNotIn(draft_event["id"], window_ids)
        # Unrelated services never enter the closure.
        unrelated = [r[0] for r in self.db.execute(
            "SELECT id FROM events WHERE subject LIKE 'p%' AND subject<>'p' "
            "AND subject NOT LIKE '%fix%'")]
        self.assertTrue(unrelated)
        self.assertTrue(set(unrelated).isdisjoint(set(window_ids) | set(prereq)))
        # The same (service, window) has one identity, even on concurrent re-run.
        again = self.seal()
        self.assertEqual(again["status"], "already_sealed")
        self.assertEqual(again["seal_id"], result["seal_id"])

    def test_late_sample_forms_appendix_and_never_rewrites_the_original_summary(self):
        sealed = self.seal()
        original_root = sealed["root"]
        # At seal time the action proposition is receipt-applied-only.
        claims = action_claims(self.db, service="a", prefix_event_id=sealed["prefix_event_id"])
        self.assertEqual(claims[0]["statement"], "receipt_applied_only")
        # The sample really was taken at 29 but only arrives at 41.
        late = execute(self.db, "agent", "observe", {
            "observation_id": "a1:fixed", "replica_id": "a1", "generation": 1,
            "observed_at": 29, "received_at": 41, "policy_id": "p", "revision": 2,
            "value": "SECRET-TARGET-VALUE", "origin": "agent"}, "drill:late:observe")
        self.assertEqual(late["drift"], "converged")
        attached = attach_late(self.db, sealed["seal_id"], 41)
        self.assertEqual(attached["status"], "attached")
        seal = row(self.db, "SELECT * FROM seal_registry WHERE seal_id=?", (sealed["seal_id"],))
        self.assertEqual(seal["root"], original_root)  # original summary immutable
        # The sealed prefix and window membership are frozen; the late event id
        # (one beyond the prefix) never enters either list.
        late_id = row(self.db, "SELECT id FROM events WHERE request_id='drill:late:observe'")["id"]
        sealed_ids = set(json.loads(seal["window_event_ids"])) | set(
            json.loads(seal["prereq_event_ids"]))
        self.assertNotIn(late_id, sealed_ids)
        self.assertEqual(seal["prefix_event_id"], sealed["prefix_event_id"])
        # The appendix carries the late event and an anchor back to the seal root.
        att_leaves = [r[0] for r in self.db.execute(
            "SELECT leaf_key FROM seal_attachment_leaves WHERE attachment_id=?",
            (attached["attachment_id"],))]
        self.assertIn(attached["anchor_key"], att_leaves)
        anchor = row(self.db, "SELECT content_json FROM seal_attachment_leaves WHERE leaf_key=?",
                     (attached["anchor_key"],))
        self.assertEqual(json.loads(anchor["content_json"])["seal_root"], original_root)
        # Re-attaching with nothing new is a no-op and the full audit stays consistent.
        self.assertEqual(attach_late(self.db, sealed["seal_id"], 42)["status"], "noop")
        self.assertEqual(verify_sealed_evidence(self.db)["audit"], "consistent")

    def test_regulator_and_customer_get_two_disclosure_routes_same_root(self):
        sealed = self.seal()
        execute(self.db, "agent", "observe", {
            "observation_id": "a1:fixed", "replica_id": "a1", "generation": 1,
            "observed_at": 29, "received_at": 41, "policy_id": "p", "revision": 2,
            "value": "SECRET-TARGET-VALUE", "origin": "agent"}, "drill:late:observe")
        attached = attach_late(self.db, sealed["seal_id"], 41)
        issuer = export_key(self.db, "issuer")

        regulator = issue_certificate(self.db, sealed["seal_id"], "regulator-a", "regulator")
        customer = issue_certificate(self.db, sealed["seal_id"], "customer-a", "customer")
        reg_bundle, cust_bundle = regulator["bundle"], customer["bundle"]
        # Same externally verifiable root and manifest, different readers.
        self.assertEqual(reg_bundle["seal_root"], cust_bundle["seal_root"])
        self.assertEqual(reg_bundle["seal_manifest"], cust_bundle["seal_manifest"])
        # Both prove: at 35 only applied, no fabricated convergence.
        statements = {p["statement"] for p in cust_bundle["propositions"]}
        self.assertIn("receipt_applied_only", statements)
        self.assertNotIn("independently_confirmed", statements)
        self.assertTrue(cust_bundle["absence_proofs"])
        # Regulator sees the plaintext policy value; the customer never can.
        reg_blob = json.dumps(reg_bundle)
        cust_blob = json.dumps(cust_bundle)
        self.assertIn("SECRET-TARGET-VALUE", reg_blob)
        self.assertNotIn("SECRET-TARGET-VALUE", cust_blob)
        self.assertNotIn("SECRET-base-value", cust_blob)
        # Redaction markers exist and the redacted leaf still verifies.
        self.assertTrue(cust_bundle["redactions"])
        # Both bundles verify independently with the issuer key, no database needed.
        reg_report = verify_bundle(reg_bundle, issuer["secret_hex"])
        cust_report = verify_bundle(cust_bundle, issuer["secret_hex"])
        self.assertTrue(reg_report["valid"], reg_report["failures"])
        self.assertTrue(cust_report["valid"], cust_report["failures"])
        # Upgraded certificates include the appendix; the originals stay on file.
        reg2 = issue_certificate(self.db, sealed["seal_id"], "regulator-a", "regulator",
                                 [attached["attachment_id"]])
        cust2 = issue_certificate(self.db, sealed["seal_id"], "customer-a", "customer",
                                  [attached["attachment_id"]])
        self.assertNotEqual(reg2["certificate_id"], regulator["certificate_id"])
        self.assertNotIn("SECRET-TARGET-VALUE", json.dumps(cust2["bundle"]))
        self.assertTrue(verify_bundle(reg2["bundle"], issuer["secret_hex"])["valid"])
        self.assertTrue(verify_bundle(cust2["bundle"], issuer["secret_hex"])["valid"])
        # Customer supplement only proves the convergence proposition, no plaintext.
        sup = supplement(self.db, sealed["seal_id"], "customer-a", "customer",
                         [attached["attachment_id"]], 45)
        self.assertTrue(verify_credential(sup["bundle"], issuer["secret_hex"]))
        self.assertNotIn("SECRET", json.dumps(sup["bundle"]))
        self.assertTrue(sup["bundle"]["upgraded_propositions"])

    def test_tampered_or_redacted_by_deletion_chain_is_rejected_not_consistent(self):
        sealed = self.seal()
        issuer = export_key(self.db, "issuer")
        bundle = issue_certificate(self.db, sealed["seal_id"], "aud", "customer")["bundle"]
        # A forged leaf (delete-then-rehash role branch) breaks the manifest digest.
        forged = json.loads(json.dumps(bundle))
        some_key = forged["redactions"][0]
        forged["leaves"][some_key]["input"]["value"] = "rewritten"
        report = verify_bundle(forged, issuer["secret_hex"])
        self.assertFalse(report["valid"])
        # Tampering with the root itself is caught through the signature.
        forged2 = json.loads(json.dumps(bundle))
        forged2["seal_root"] = "0" * 64
        self.assertFalse(verify_bundle(forged2, issuer["secret_hex"])["valid"])
        # Deleting a committed leaf row in storage cannot make the audit pass.
        self.db.execute("DELETE FROM seal_leaves WHERE seal_id=? LIMIT 1", (sealed["seal_id"],))
        self.assertEqual(verify_sealed_evidence(self.db)["audit"], "diverged")

    def test_revocation_archives_old_certificate_and_issues_signed_credential(self):
        sealed = self.seal()
        issue_certificate(self.db, sealed["seal_id"], "witness", "customer")
        issuer = export_key(self.db, "issuer")
        rev = revoke_witness(self.db, "audience:witness", 50, "key compromise drill")
        self.assertTrue(verify_credential(rev["bundle"], issuer["secret_hex"]))
        self.assertTrue(rev["certificates"])
        # The original certificate is still retrievable from the archive.
        archived = get_certificate(self.db, rev["certificates"][0])
        self.assertEqual(archived["seal_id"], sealed["seal_id"])
        key = row(self.db, "SELECT status FROM seal_keys WHERE key_id='audience:witness'")
        self.assertEqual(key["status"], "revoked")

    def test_archival_compression_keeps_external_root_verifiable(self):
        sealed = self.seal()
        issuer = export_key(self.db, "issuer")
        bundle = issue_certificate(self.db, sealed["seal_id"], "reg", "regulator")["bundle"]
        archived = archive_leaves(self.db, sealed["seal_id"])
        self.assertEqual(archived["root"], sealed["root"])
        # The issued certificate remains fully verifiable against the stored root.
        self.assertTrue(verify_bundle(bundle, issuer["secret_hex"])["valid"])
        self.assertEqual(verify_sealed_evidence(self.db)["audit"], "consistent")

    def test_convergence_is_not_fabricated_before_new_observation_arrives(self):
        sealed = self.seal()
        claims = action_claims(self.db, service="a", prefix_event_id=sealed["prefix_event_id"])
        self.assertEqual(claims[0]["statement"], "receipt_applied_only")
        # Even with a later confirm command existing after the prefix, prefix view cannot see it.
        execute(self.db, "agent", "observe", {
            "observation_id": "a1:fixed", "replica_id": "a1", "generation": 1,
            "observed_at": 29, "received_at": 41, "policy_id": "p", "revision": 2,
            "value": "SECRET-TARGET-VALUE", "origin": "agent"}, "drill:late:observe")
        still = action_claims(self.db, service="a", prefix_event_id=sealed["prefix_event_id"])
        self.assertEqual(still[0]["statement"], "receipt_applied_only")
        confirmed = execute(self.db, "drift", "confirm",
                            {"action_id": "fix:a1"}, "drill:late:confirm")
        self.assertEqual(confirmed["status"], "converged")
        full = action_claims(self.db, service="a")
        self.assertEqual(full[0]["statement"], "independently_confirmed")

    def test_duplicate_pages_and_page_conflicts_keep_unique_seal(self):
        rows = [{"service": "a", "at": 22}]
        self.assertEqual(capture(self.db, "dup", rows), "captured")
        self.assertEqual(capture(self.db, "dup", rows), "replayed")
        with self.assertRaises(ValueError):
            capture(self.db, "dup", [{"service": "a", "at": 23}])
        first = seal_window(self.db, "a", 20, 30, 35)
        second = seal_window(self.db, "a", 20, 30, 35)
        self.assertEqual(first["seal_id"], second["seal_id"])

    def test_power_loss_leaves_no_partial_seal_and_is_replayable(self):
        from cloudctl.compliance_seal import initialize as init_seals
        init_seals(self.db)
        before = self.db.execute("SELECT COUNT(*) FROM seal_registry").fetchone()[0]
        with self.assertRaises(RuntimeError):
            seal_window_with_failure(self.db, "a", 20, 30, 35)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM seal_registry").fetchone()[0], before)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM seal_leaves").fetchone()[0], 0)
        # A retry after recovery succeeds and the event replay report is intact.
        self.assertEqual(self.seal()["status"], "sealed")
        self.assertEqual(report(self.db)["audit"], "consistent")

    def test_merkle_inclusion_and_absence_proofs(self):
        entries = [("k1", merkle.digest(1)), ("k2", merkle.digest(2)), ("k3", merkle.digest(3))]
        tree = merkle.Tree(entries)
        for key, h in entries:
            self.assertTrue(merkle.verify_inclusion(tree.root, key, h, tree.inclusion(key)))
        self.assertTrue(merkle.verify_absence(tree.root, "k2b", entries, tree.absence("k2b")))
        self.assertTrue(merkle.verify_absence(tree.root, "k0", entries, tree.absence("k0")))
        self.assertTrue(merkle.verify_absence(tree.root, "k9", entries, tree.absence("k9")))
        self.assertFalse(merkle.verify_absence(tree.root, "k1", entries, tree.absence("k1")))
        # A proof from another tree must not validate.
        other = merkle.Tree(entries + [("k4", merkle.digest(4))])
        self.assertFalse(merkle.verify_inclusion(tree.root, "k2", merkle.digest(2),
                                                 other.inclusion("k2")))

    def test_prefix_replay_rebuilds_only_the_sealed_event_prefix(self):
        sealed = self.seal()
        replay, errors = replay_events(self.db, sealed["prefix_event_id"])
        self.assertEqual(errors, [])
        replayed = replay.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
        self.assertEqual(replayed, sealed["prefix_event_id"])
        # A later-arriving event is absent from the prefix replay but present live.
        execute(self.db, "agent", "observe", {
            "observation_id": "a1:fixed", "replica_id": "a1", "generation": 1,
            "observed_at": 29, "received_at": 41, "policy_id": "p", "revision": 2,
            "value": "SECRET-TARGET-VALUE", "origin": "agent"}, "drill:late:observe")
        replay2, errors2 = replay_events(self.db, sealed["prefix_event_id"])
        self.assertEqual(errors2, [])
        self.assertEqual(replay2.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"],
                         sealed["prefix_event_id"])
        replay2.close()
        # The full live replay report still includes the late event and is consistent.
        self.assertEqual(report(self.db)["audit"], "consistent")

    def test_causal_closure_helper_includes_dependency_chain(self):
        events = [dict(r) for r in self.db.execute("SELECT * FROM events ORDER BY id")]
        for event in events:
            event["input"] = json.loads(event["input_json"])
        receipt = next(e for e in events if e["kind"] == "drift.receipt")
        closure = causal_closure(self.db, events, [receipt["id"]])
        kind_rows = [self.db.execute("SELECT kind FROM events WHERE id=?", (eid,)).fetchone()
                     for eid in closure]
        kinds = {item["kind"] for item in kind_rows}
        self.assertIn("policy.draft", kinds)
        self.assertIn("drift.dispatch", kinds)


class LegacyCaptureSeed(unittest.TestCase):
    def test_fixed_capture_seed_still_drives_provisional_written_result(self):
        db = sqlite3.connect(":memory:")
        rows = [{"service": "x", "at": 2}]
        from cloudctl.compliance_seal import issue
        self.assertEqual(capture(db, "p1", rows), "captured")
        self.assertEqual(issue(db, "x")["metric"], 2)
        self.assertEqual(capture(db, "p1", rows), "replayed")
        with self.assertRaises(ValueError):
            capture(db, "p1", [{"service": "x", "at": 3}])


# --- helpers ----------------------------------------------------------------


def seal_window_with_failure(db, service, start, end, signed_at):
    """Simulate a crash mid-seal: the surrounding transaction must roll back."""
    import cloudctl.compliance_seal as cs
    original = cs._assertion_leaves

    def boom(_events):
        raise RuntimeError("simulated power loss")

    cs._assertion_leaves = boom
    try:
        return cs.seal_window(db, service, start, end, signed_at)
    finally:
        cs._assertion_leaves = original


if __name__ == "__main__":
    unittest.main()
