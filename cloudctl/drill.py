"""The A/B/W drill and the two approved, resumable recovery runbooks.

Drill originals (all asserted by the tests):

* A is primary term 3 and holds client-acknowledged item 11 digest ``x11``.
* B is term 4, replicated only through item 10, then wrote an
  unacknowledged local item 11 digest ``y11`` at the same position.
* Independent witness W keeps the signed ``x11`` page carrying the item-10
  previous digest, so it can refill the confirmed chain onto B.
* A's local lease ends at local time 30; its clock lags real time by 4, so it
  still admits writes at real time 34.
* B's term-4 ticket reaches the control court at real time 29.

Two approved plans:

``promote_b``  isolate A at every gateway, prove all client entries are
               blocked, quarantine y11, refill x11 from W, atomically open B
               at term 5 and flip routes.  Primary becomes B.

``keep_a``     block B's partition writes, verify A+x11 against W, advance A
               to term 5 paused, require B's signed old-lease close *and*
               independent gateway closed proof, then open A.  Primary stays
               A; B's y11 is retained as a conflict original.

Every step is idempotent and durable; :func:`run_plan_b` / :func:`run_plan_a`
can be called again on a freshly reopened database after a simulated crash.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .cluster import (Cluster, CrashSimulated, immediate_tx, insert_record_row)
from .failover import (FailoverCourt, FenceNotReady, LeaderNotOpen,
                       OrderClient, PrefixNotReady, STAGE_FENCE, STAGE_OPEN,
                       STAGE_PREFIX)
from .fence import evaluate_fence
from .wal_chain import (apply_prefix_repair, build_prefix_basis)
from .wal_capture import capture as legacy_capture
from .leader_lease import issue as legacy_issue


NEW_TERM = 5
REQ_X11 = "req-order-11"
X11 = "x11"
Y11 = "y11"
DEFAULT_DECISION = "failover-order-db"

EXT_PATHS = ("path-ext", "path-int")
B_PATHS = ("path-b",)


# ---------------------------------------------------------------------------
# Scenario construction
# ---------------------------------------------------------------------------

def seed_drill(db: sqlite3.Connection, *, at: int = 29,
               witness: bool = True, legacy_pages: bool = True,
               decision_id: str = DEFAULT_DECISION) -> Dict[str, object]:
    """Build the exact offline drill.  Idempotent for an in-memory fresh DB."""
    court = FailoverCourt(db)
    cluster = Cluster(db)
    cluster.set_real_time(at)

    cluster.add_node("A", boot=3, lag=4, leader_term=3,
                     lease_until_local=30, note="old primary, slow clock")
    cluster.add_node("B", boot=2, lag=0, leader_term=4,
                     lease_until_local=40, note="term4 replica + local y11")
    cluster.add_node("W", boot=1, lag=0, note="independent witness")

    # A's full chain 1..11, with x11 client acknowledged.
    for i in range(1, 11):
        cluster.append_local("A", term=3, digest=f"d{i}", ack=True)
    rec_x11 = cluster.append_local(
        "A", term=3, digest=X11, ack=True, request_id=REQ_X11)

    # B replicated A's 1..10 verbatim (original signer A retained)...
    a_log = cluster.log("A")
    for i in range(1, 11):
        cluster.adopt_record("B", a_log.get(i))
    # ...then self-wrote term-4 y11 at index 11 with no client receipt.
    rec_y11 = cluster.append_local("B", term=4, digest=Y11, ack=False)

    # W independently custodians the signed x11 page (with prev digest d10).
    if witness:
        cluster.adopt_record("W", rec_x11)

    # Independent gateways and registered client entry paths.
    cluster.add_gateway("gw-edge")
    cluster.add_gateway("gw-core")
    cluster.add_gateway("gw-b")
    cluster.add_path("path-ext", "gw-edge", "A", routed=True)
    cluster.add_path("path-int", "gw-core", "A", routed=True)
    # B side path exists but no client route is live before recovery.
    cluster.add_path("path-b", "gw-b", "B", routed=False)

    # The durable client success receipt for x11 (independent hard evidence).
    order_payload = {"order_id": "ord-11", "action": "capture", "amount": 1100}
    receipt_x11 = {
        "request_id": REQ_X11, "status": "accepted", "leader": "A", "node": "A",
        "term": 3, "index": 11, "digest": X11, "fence_epoch": 3,
        "prefix_index": 10, "prefix_digest": "d10",
        "replicated_to": ["W"], "at": 20,
    }
    court.put_receipt(REQ_X11, order_payload, receipt_x11, at=20,
                      status="client_ack")

    if legacy_pages:
        # Feed the same originals to the unchanged legacy capture/issue
        # modules so the naive max-term behaviour remains demonstrable.
        legacy_capture(db, "legacy-A", [
            {"node": "A", "term": 3, "index": 10, "digest": "d10", "ack": True},
            {"node": "A", "term": 3, "index": 11, "digest": X11, "ack": True},
        ])
        legacy_capture(db, "legacy-B", [
            {"node": "B", "term": 4, "index": 10, "digest": "d10", "ack": True},
            {"node": "B", "term": 4, "index": 11, "digest": Y11, "ack": False},
        ])

    return {"court": court, "cluster": cluster, "x11": rec_x11,
            "y11": rec_y11, "decision_id": decision_id}


def reopen(path: Path | str):
    """Real restart boundary: close the old connection externally and reopen."""
    db = sqlite3.connect(str(path))
    return db, FailoverCourt(db), Cluster(db)


# ---------------------------------------------------------------------------
# Shared resumable steps
# ---------------------------------------------------------------------------

def _crash(crash_at: Optional[str], point: str) -> None:
    if crash_at == point:
        raise CrashSimulated(point)


def snapshot_originals(court: FailoverCourt, cluster: Cluster,
                       decision_id: str, at: int) -> Dict[str, int]:
    counts = {}
    for node in ("A", "B", "W"):
        records = cluster.raw_records(node)
        court.save_raw_page(decision_id, node, records or [], at=at,
                            kind="original-wal")
        counts[node] = len(records)
    return counts


def _ack_receipts(court: FailoverCourt) -> Dict[str, Dict[str, object]]:
    rows = court.db.execute(
        "SELECT request_id,receipt_json FROM fo_client_requests "
        "WHERE status IN ('accepted','client_ack')").fetchall()
    import json
    return {rid: json.loads(raw) for rid, raw in rows}


def prepare_prefix(court: FailoverCourt, cluster: Cluster,
                   decision_id: str, at: int) -> Dict[str, object]:
    decision = court.require(decision_id)
    if decision["stage"] in (STAGE_PREFIX, STAGE_FENCE, STAGE_OPEN):
        return decision["prefix"]  # type: ignore[return-value]

    leader = str(decision["leader"])
    target_log = cluster.log(leader)
    witness_log = cluster.log("W")
    receipts = _ack_receipts(court)
    try:
        basis = build_prefix_basis(target=target_log,
                                   authoritative_source=witness_log,
                                   ack_receipts=receipts)
    except Exception as error:
        court.update_wait(decision_id, f"prefix_unresolved:{error}", at)
        raise PrefixNotReady(str(error)) from error

    # Detach divergent tail (y11) durably, preserving it in quarantine...
    removed_raw = cluster.quarantine_tail(
        leader, basis.common_index, decision_id=decision_id, at=at)
    # ...then adopt authoritative repair records (x11 from W).
    secrets = cluster.secrets()
    repair_log = cluster.log(leader)
    for rec in basis.records:
        adopted = repair_log.adopt(rec)
        with immediate_tx(court.db):
            insert_record_row(court.db, leader, adopted)
            court.db.execute(
                "INSERT INTO fo_replication(term,idx,digest,holder,"
                "request_id,at) VALUES(?,?,?,?,?,?)",
                (int(rec["term"]), int(rec["index"]), str(rec["digest"]),
                 leader, rec.get("request_id"), at))

    bundle = basis.as_bundle()
    bundle["removed_originals"] = [
        {"index": r["index"], "digest": r["digest"], "term": r["term"],
         "signer": r["signer"]} for r in removed_raw]
    bundle["target_leader"] = leader
    court.mark_prefix_ready(
        decision_id, leader=leader, term=NEW_TERM,
        prefix_index=basis.authoritative_index,
        prefix_digest=basis.authoritative_digest, bundle=bundle, at=at)
    return bundle


def _gateway_secrets(cluster: Cluster) -> Dict[str, str]:
    return {gw: secret for gw, secret in
            cluster.db.execute("SELECT gw,secret FROM fo_gateways")}


def contain_for_promote_b(court: FailoverCourt, cluster: Cluster,
                          decision_id: str, at: int, *,
                          mode: str = "gateway",
                          paths: Optional[Sequence[str]] = None,
                          epoch: int = NEW_TERM,
                          nonce: str = "fence-A-term5") -> Dict[str, object]:
    decision = court.require(decision_id)
    if decision["stage"] in (STAGE_FENCE, STAGE_OPEN):
        return decision["fence"]  # type: ignore[return-value]

    # Exhaustive path set defaults to every registered path homed on A.
    if paths is None:
        paths = tuple(p["path_id"] for p in cluster.paths_for("A"))
    paths = tuple(paths)

    # B must not accept term-4 writes locally while being repaired.
    with immediate_tx(court.db):
        court.db.execute("UPDATE fo_nodes SET accepting_writes=0 WHERE node='B'")

    ack_payloads: List[Dict[str, object]] = []
    if mode == "receipt":
        ack = cluster.send_fence("A", epoch, nonce, at)
        if ack is None:
            court.update_wait(decision_id, "fence_ack_lost_or_request_lost", at)
            raise FenceNotReady("fence receipt unavailable (ACK/request lost)")
        court.add_evidence(decision_id, "fence_receipt", ack,
                           key=f"fence-ack:A:{epoch}:{nonce}", at=at)

    proof_payloads: List[Dict[str, object]] = []
    if mode == "gateway":
        for path_id in paths:
            proof = cluster.block_path(path_id, at)
            court.add_evidence(
                decision_id, "gateway_proof", proof,
                key=f"gateway-proof:{path_id}:v{proof['rule_version']}", at=at)

    for ev in court.evidence(decision_id):
        if ev["kind"] == "fence_receipt":
            ack_payloads.append(ev["payload"])
        elif ev["kind"] == "gateway_proof":
            proof_payloads.append(ev["payload"])

    coverage = evaluate_fence(
        old_node="A", epoch=epoch, required_paths=list(paths),
        node_secrets=cluster.secrets(),
        gateway_secrets=_gateway_secrets(cluster),
        fence_receipts=ack_payloads, gateway_proofs=proof_payloads)
    if not coverage.satisfied:
        court.update_wait(decision_id, coverage.reason(), at)
        raise FenceNotReady(coverage.reason())

    writers_after = cluster.reachable_writers(at)
    bundle = {
        "satisfied": True, "mode": coverage.mode,
        "evidence_keys": coverage.evidence_keys,
        "required_paths": list(paths), "epoch": epoch, "at": at,
        "reachable_writers_after_containment": writers_after,
        "old_primary_real_reachability": (
            "no client write path admits A after containment; sweep returned "
            f"{[w['node'] for w in writers_after]}"),
    }
    court.mark_fence_ready(decision_id, fence_bundle=bundle, at=at)
    return bundle


def enter_a_term5_paused(court: FailoverCourt, cluster: Cluster,
                         decision_id: str, at: int, *,
                         lease_until_local: int = 60) -> None:
    """A joins term 5 but stays write-paused until B is fully closed."""
    with immediate_tx(court.db):
        court.db.execute(
            "UPDATE fo_nodes SET leader_term=5, open_term=0, "
            "highest_fence=5, accepting_writes=0, "
            "lease_until_local=? WHERE node='A'", (lease_until_local,))
    court.add_evidence(decision_id, "term_entry",
                       {"node": "A", "term": 5, "paused": True, "at": at,
                        "basis": "x11 verified with witness W"},
                       key="term-entry:A:5", at=at)


def contain_for_keep_a(court: FailoverCourt, cluster: Cluster,
                       decision_id: str, at: int, *,
                       paths: Optional[Sequence[str]] = None,
                       old_term: int = 4,
                       mark_ready: bool = True) -> Dict[str, object]:
    """Block B writes, close B's old lease and prove gateway closure.

    Physical evidence collection is idempotent and may happen before the
    prefix stage; ``mark_ready`` only transitions the durable decision once
    the prefix is also known good.
    """
    decision = court.require(decision_id)
    if mark_ready and decision["stage"] in (STAGE_FENCE, STAGE_OPEN):
        return decision["fence"]  # type: ignore[return-value]

    if paths is None:
        paths = tuple(p["path_id"] for p in cluster.paths_for("B"))
    paths = tuple(paths)

    # 1. Real gateway write block in B's partition.
    for path_id in paths:
        path = cluster.path(path_id)
        if not int(path["write_denied"]):
            proof = cluster.block_path(path_id, at)
            court.add_evidence(
                decision_id, "gateway_proof", proof,
                key=f"gateway-proof:{path_id}:v{proof['rule_version']}", at=at)

    # 2. Fence epoch + signed closure of B's old term-4 lease.
    ack = cluster.send_fence("B", NEW_TERM, "fence-B-term5", at)
    if ack is not None:
        court.add_evidence(decision_id, "fence_receipt", ack,
                           key="fence-ack:B:5:fence-B-term5", at=at)
    if cluster.node("B")["leader_term"] is not None:
        closed = cluster.close_lease("B", old_term, at)
        court.add_evidence(decision_id, "lease_closed", closed,
                           key=f"lease-closed:B:{old_term}", at=at)
    else:
        prior = [e["payload"] for e in court.evidence(decision_id, "lease_closed")]
        if not prior:
            closed = cluster.close_lease("B", old_term, at)
            court.add_evidence(decision_id, "lease_closed", closed,
                               key=f"lease-closed:B:{old_term}", at=at)

    # 3. Independent gateway confirms closed state at a fresh rule version.
    for path_id in paths:
        path = cluster.path(path_id)
        already_closed_proof = [
            e for e in court.evidence(decision_id, "gateway_closed_proof")
            if e["payload"].get("path_id") == path_id
            and int(e["payload"].get("rule_version", 0))
            >= int(path["rule_version"])]
        if not already_closed_proof:
            closed_proof = cluster.confirm_path_closed(path_id, at + 1)
            court.add_evidence(
                decision_id, "gateway_closed_proof", closed_proof,
                key=f"gateway-closed:{path_id}:v{closed_proof['rule_version']}",
                at=at + 1)

    proofs = [ev["payload"] for ev in court.evidence(decision_id)
              if ev["kind"] in ("gateway_proof", "gateway_closed_proof")]
    closes = [ev["payload"] for ev in court.evidence(decision_id)
              if ev["kind"] == "lease_closed"]
    acks = [ev["payload"] for ev in court.evidence(decision_id)
            if ev["kind"] == "fence_receipt"]
    coverage = evaluate_fence(
        old_node="B", epoch=NEW_TERM, required_paths=list(paths),
        node_secrets=cluster.secrets(),
        gateway_secrets=_gateway_secrets(cluster),
        fence_receipts=acks, gateway_proofs=proofs,
        require_lease_closed=old_term, lease_closed_receipts=closes,
        receipt_can_satisfy=False)
    if not coverage.satisfied:
        court.update_wait(decision_id, coverage.reason(), at)
        raise FenceNotReady(coverage.reason())

    writers_after = cluster.reachable_writers(at + 1)
    bundle = {
        "satisfied": True, "mode": coverage.mode,
        "evidence_keys": coverage.evidence_keys,
        "required_paths": list(paths), "old_lease_term": old_term, "at": at + 1,
        "reachable_writers_after_containment": writers_after,
    }
    if mark_ready:
        court.mark_fence_ready(decision_id, fence_bundle=bundle, at=at + 1)
    return bundle


def open_leadership(court: FailoverCourt, cluster: Cluster,
                    decision_id: str, at: int, *,
                    route_flips: Sequence[str] = ()) -> Dict[str, object]:
    return court.commit_open(decision_id, at=at, cluster=cluster,
                             route_flips=route_flips)


# ---------------------------------------------------------------------------
# Composite resumable runbooks
# ---------------------------------------------------------------------------

def run_plan_b(db: sqlite3.Connection,
               decision_id: str = DEFAULT_DECISION, *,
               begin_at: int = 29, snapshot_at: int = 29,
               prefix_at: int = 30, fence_at: int = 30, open_at: int = 31,
               fence_mode: str = "gateway",
               fence_paths: Optional[Sequence[str]] = None,
               route_flips: Sequence[str] = EXT_PATHS,
               crash_at: Optional[str] = None) -> Dict[str, object]:
    court = FailoverCourt(db)
    cluster = Cluster(db)
    court.begin(decision_id, plan="promote_b", at=begin_at,
                leader="B", term=NEW_TERM)
    _crash(crash_at, "begin")

    snapshot_originals(court, cluster, decision_id, snapshot_at)
    _crash(crash_at, "snapshot")

    prepare_prefix(court, cluster, decision_id, prefix_at)
    _crash(crash_at, "prefix")

    contain_for_promote_b(court, cluster, decision_id, fence_at,
                          mode=fence_mode, paths=fence_paths)
    _crash(crash_at, "fence")

    _crash(crash_at, "before_open")
    leadership = open_leadership(court, cluster, decision_id, open_at,
                                 route_flips=route_flips)
    _crash(crash_at, "after_open")
    return leadership


def run_plan_a(db: sqlite3.Connection,
               decision_id: str = DEFAULT_DECISION, *,
               begin_at: int = 29, block_at: int = 30,
               prefix_at: int = 30, term_at: int = 31,
               close_at: int = 32, open_at: int = 33,
               crash_at: Optional[str] = None) -> Dict[str, object]:
    court = FailoverCourt(db)
    cluster = Cluster(db)
    court.begin(decision_id, plan="keep_a", at=begin_at,
                leader="A", term=NEW_TERM)
    _crash(crash_at, "begin")

    snapshot_originals(court, cluster, decision_id, begin_at)
    _crash(crash_at, "snapshot")

    # Approved order starts by blocking B's partition writes and collecting
    # closure evidence; the durable FENCE_READY transition waits for prefix.
    contain_for_keep_a(court, cluster, decision_id, close_at, mark_ready=False)
    _crash(crash_at, "b_blocked")

    prepare_prefix(court, cluster, decision_id, prefix_at)
    _crash(crash_at, "prefix")

    enter_a_term5_paused(court, cluster, decision_id, term_at)
    _crash(crash_at, "a_term")

    contain_for_keep_a(court, cluster, decision_id, close_at, mark_ready=True)
    _crash(crash_at, "fence")

    _crash(crash_at, "before_open")
    leadership = open_leadership(court, cluster, decision_id, open_at,
                                route_flips=())
    _crash(crash_at, "after_open")
    return leadership


def resume_decision(db: sqlite3.Connection,
                    decision_id: str = DEFAULT_DECISION, *,
                    crash_at: Optional[str] = None,
                    **kwargs) -> Dict[str, object]:
    """Restart recovery entry point: continue whatever decision was durable."""
    court = FailoverCourt(db)
    decision = court.require(decision_id)
    if decision["plan"] == "promote_b":
        return run_plan_b(db, decision_id, crash_at=crash_at, **kwargs)
    return run_plan_a(db, decision_id, crash_at=crash_at, **kwargs)


# ---------------------------------------------------------------------------
# Naive behaviour kept as executable negative evidence
# ---------------------------------------------------------------------------

def naive_max_term_issue(db: sqlite3.Connection, node: str = "B"):
    """Thin wrapper around the unchanged provisional lease issuer."""
    return legacy_issue(db, node)


def naive_paper_promotion_dual_window(db: sqlite3.Connection, *,
                                      path_id: str = "path-ext",
                                      start: int = 29, end: int = 35
                                      ) -> Dict[str, object]:
    """Issue the max-term lease and route to B with no fence of A.

    Returns ``{"issued": ..., "window": {real_time: [writers]}}``.  This is
    the unsafe behaviour the new runbooks replace: A keeps admitting term-3
    writes until real time 34 while B is already reachable as term 4.
    """
    cluster = Cluster(db)
    issued = legacy_issue(db, "B")
    # A paper promotion flips a client entry to B but installs no deny rule
    # on A's other independent entry path (and no fence receipt).
    cluster.flip_route(path_id, "B", start)
    window: Dict[str, List[str]] = {}
    for t in range(start, end + 1):
        window[str(t)] = [w["node"] for w in cluster.reachable_writers(t)]
    return {"issued": issued, "window": window}


def _evidence_report() -> Dict[str, object]:
    import json
    reports: Dict[str, object] = {}

    naive_db = sqlite3.connect(":memory:")
    seed_drill(naive_db)
    reports["naive_max_term"] = naive_paper_promotion_dual_window(naive_db)
    naive_db.close()

    for plan, runner in (("promote_b", run_plan_b), ("keep_a", run_plan_a)):
        db = sqlite3.connect(":memory:")
        seed_drill(db)
        decision = f"report-{plan}"
        lead = runner(db, decision)
        court = FailoverCourt(db)
        cluster = Cluster(db)
        client = OrderClient(court, cluster)
        receipt = client.submit(f"req-after-{plan}", {"order_id": "final"},
                                at=40)
        reports[plan] = {
            "leader": lead["node"], "term": lead["term"],
            "prefix": {"index": lead["prefix_index"],
                       "digest": lead["prefix_digest"]},
            "open_reachability": [w["node"] for w in
                                  lead["basis"]["open_time_reachability"]],
            "post_open_writers_t40": [w["node"] for w in
                                      cluster.reachable_writers(40)],
            "next_write": {"index": receipt["index"],
                           "term": receipt["term"],
                           "digest": receipt["digest"][:12],
                           "replicated_to": receipt["replicated_to"]},
            "quarantined": [q["digest"] for q in cluster.quarantined("B")],
        }
        db.close()
    return reports


if __name__ == "__main__":
    import json
    print(json.dumps(_evidence_report(), ensure_ascii=False, indent=2,
                     sort_keys=True))
