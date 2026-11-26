"""Recoverable failover decision and exactly-once client write boundary.

The court persists one decision aggregate plus append-only evidence.  The
final OPEN commit binds, in a single SQLite transaction:

* the verified/repair-completed WAL prefix (index + digest + evidence),
* the fence basis (old-primary receipt or exhaustive gateway proofs),
* the unique writable leader identity and term,
* the gateway route flip that makes that leader actually reachable.

A crash between the durable FENCE_READY step and the OPEN commit therefore
cannot leave two writable primaries: the singleton leadership row either does
not exist or names exactly one leader.  Re-running the resumable plan (see
:mod:`cloudctl.drill`) completes the interrupted decision.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Dict, List, Mapping, Optional, Sequence

from .cluster import (Cluster, PathBlocked, StaleWriter, NoRoute,
                      immediate_tx, insert_record_row, load_log)
from .wal_chain import canonical


COURT_SCHEMA = """
CREATE TABLE IF NOT EXISTS fo_decisions (
  decision_id TEXT PRIMARY KEY,
  plan TEXT NOT NULL,
  stage TEXT NOT NULL,
  leader TEXT,
  term INTEGER,
  prefix_index INTEGER,
  prefix_digest TEXT,
  wait_reason TEXT,
  prefix_json TEXT,
  fence_json TEXT,
  open_basis_json TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  opened_at INTEGER
);
CREATE TABLE IF NOT EXISTS fo_decision_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  decision_id TEXT NOT NULL,
  at INTEGER NOT NULL,
  stage TEXT NOT NULL,
  detail_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fo_raw_pages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  decision_id TEXT NOT NULL,
  node TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'wal',
  digest TEXT NOT NULL,
  raw_json TEXT NOT NULL,
  at INTEGER NOT NULL,
  UNIQUE(decision_id, node, kind, digest)
);
CREATE TABLE IF NOT EXISTS fo_evidence (
  evidence_key TEXT PRIMARY KEY,
  decision_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fo_client_requests (
  request_id TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fo_leadership (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  decision_id TEXT NOT NULL,
  node TEXT NOT NULL,
  term INTEGER NOT NULL,
  prefix_index INTEGER NOT NULL,
  prefix_digest TEXT NOT NULL,
  opened_at INTEGER NOT NULL,
  basis_json TEXT NOT NULL
);
"""

STAGE_INIT = "INIT"
STAGE_PREFIX = "PREFIX_READY"
STAGE_FENCE = "FENCE_READY"
STAGE_OPEN = "OPEN"
STAGE_ORDER = [STAGE_INIT, STAGE_PREFIX, STAGE_FENCE, STAGE_OPEN]


class FailoverError(ValueError):
    pass


class PrefixNotReady(FailoverError):
    pass


class FenceNotReady(FailoverError):
    pass


class UnsafeOpen(FailoverError):
    pass


class RequestIdConflict(FailoverError):
    pass


class LeaderNotOpen(FailoverError):
    """Retryable: no reachable open leader yet (or path still fenced)."""


def is_retryable_write_error(error: BaseException) -> bool:
    return isinstance(error, (LeaderNotOpen, PathBlocked, NoRoute, StaleWriter))


def init_court_schema(db: sqlite3.Connection) -> None:
    db.executescript(COURT_SCHEMA)
    db.commit()


class FailoverCourt:
    def __init__(self, db: sqlite3.Connection):
        self.db = db
        init_court_schema(db)

    # ----- decision aggregate --------------------------------------------
    def begin(self, decision_id: str, *, plan: str, at: int,
              leader: Optional[str] = None, term: Optional[int] = None
              ) -> Dict[str, object]:
        if plan not in ("promote_b", "keep_a"):
            raise FailoverError(f"unknown plan {plan}")
        existing = self.get(decision_id)
        if existing is not None:
            if existing["plan"] != plan:
                raise FailoverError(
                    f"decision {decision_id} already plan={existing['plan']}")
            return existing
        with immediate_tx(self.db):
            self.db.execute(
                "INSERT INTO fo_decisions(decision_id,plan,stage,leader,term,"
                "created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                (decision_id, plan, STAGE_INIT, leader, term, at, at))
            self._event(decision_id, at, STAGE_INIT, {"plan": plan})
        return self.get(decision_id)  # type: ignore[return-value]

    def get(self, decision_id: str) -> Optional[Dict[str, object]]:
        row = self.db.execute("SELECT * FROM fo_decisions WHERE decision_id=?",
                              (decision_id,)).fetchone()
        if row is None:
            return None
        cols = [d[0] for d in self.db.execute(
            "SELECT * FROM fo_decisions LIMIT 0").description]
        data = dict(zip(cols, row))
        for key in ("prefix_json", "fence_json", "open_basis_json"):
            if data.get(key):
                data[key.removesuffix("_json")] = json.loads(data[key])
        return data

    def events(self, decision_id: str) -> List[Dict[str, object]]:
        rows = self.db.execute(
            "SELECT at,stage,detail_json FROM fo_decision_events "
            "WHERE decision_id=? ORDER BY id", (decision_id,)).fetchall()
        return [{"at": at, "stage": stage, "detail": json.loads(detail)}
                for at, stage, detail in rows]

    def _event(self, decision_id: str, at: int, stage: str,
               detail: Mapping[str, object]) -> None:
        self.db.execute(
            "INSERT INTO fo_decision_events(decision_id,at,stage,detail_json) "
            "VALUES(?,?,?,?)",
            (decision_id, at, stage, canonical(detail)))

    def update_wait(self, decision_id: str, reason: Optional[str], at: int) -> None:
        with immediate_tx(self.db):
            self.db.execute(
                "UPDATE fo_decisions SET wait_reason=?, updated_at=? "
                "WHERE decision_id=?", (reason, at, decision_id))

    def mark_prefix_ready(self, decision_id: str, *, leader: str, term: int,
                          prefix_index: int, prefix_digest: str,
                          bundle: Mapping[str, object], at: int) -> None:
        with immediate_tx(self.db):
            self.db.execute(
                "UPDATE fo_decisions SET stage=?, leader=?, term=?, "
                "prefix_index=?, prefix_digest=?, prefix_json=?, "
                "wait_reason=NULL, updated_at=? WHERE decision_id=?",
                (STAGE_PREFIX, leader, term, prefix_index, prefix_digest,
                 canonical(bundle), at, decision_id))
            self._event(decision_id, at, STAGE_PREFIX, bundle)

    def mark_fence_ready(self, decision_id: str, *,
                         fence_bundle: Mapping[str, object], at: int) -> None:
        decision = self.require(decision_id)
        if decision["stage"] not in (STAGE_PREFIX, STAGE_FENCE, STAGE_OPEN):
            raise FenceNotReady("prefix stage has not completed")
        with immediate_tx(self.db):
            self.db.execute(
                "UPDATE fo_decisions SET stage=?, fence_json=?, "
                "wait_reason=NULL, updated_at=? WHERE decision_id=?",
                (STAGE_FENCE, canonical(fence_bundle), at, decision_id))
            self._event(decision_id, at, STAGE_FENCE, fence_bundle)

    def require(self, decision_id: str) -> Dict[str, object]:
        decision = self.get(decision_id)
        if decision is None:
            raise FailoverError(f"unknown decision {decision_id}")
        return decision

    # ----- immutable original WAL pages ----------------------------------
    def save_raw_page(self, decision_id: str, node: str, raw: object, *,
                      at: int, kind: str = "wal") -> str:
        if isinstance(raw, str):
            raw_text = raw
            parsed = json.loads(raw_text)
            digest = canonical(parsed)
        else:
            raw_text = canonical(raw)
            digest = raw_text
        import hashlib
        page_digest = hashlib.sha256(digest.encode("utf-8")).hexdigest()
        inserted = False
        with immediate_tx(self.db):
            before = self.db.execute(
                "SELECT 1 FROM fo_raw_pages WHERE decision_id=? AND node=? "
                "AND kind=? AND digest=?",
                (decision_id, node, kind, page_digest)).fetchone()
            if before is None:
                self.db.execute(
                    "INSERT INTO fo_raw_pages(decision_id,node,kind,digest,"
                    "raw_json,at) VALUES(?,?,?,?,?,?)",
                    (decision_id, node, kind, page_digest, raw_text, at))
                inserted = True
        return "captured" if inserted else "duplicate"

    def raw_pages(self, decision_id: str, *, node: Optional[str] = None
                  ) -> List[Dict[str, object]]:
        if node:
            rows = self.db.execute(
                "SELECT node,kind,digest,raw_json,at FROM fo_raw_pages "
                "WHERE decision_id=? AND node=? ORDER BY id",
                (decision_id, node)).fetchall()
        else:
            rows = self.db.execute(
                "SELECT node,kind,digest,raw_json,at FROM fo_raw_pages "
                "WHERE decision_id=? ORDER BY id",
                (decision_id,)).fetchall()
        return [{"node": n, "kind": k, "digest": dg,
                "raw": json.loads(raw), "at": at}
                for n, k, dg, raw, at in rows]

    # ----- append-only evidence ------------------------------------------
    def add_evidence(self, decision_id: str, kind: str,
                      payload: Mapping[str, object], *, key: str,
                      at: int) -> str:
        with immediate_tx(self.db):
            exists = self.db.execute(
                "SELECT 1 FROM fo_evidence WHERE evidence_key=?", (key,)).fetchone()
            if exists:
                return "duplicate"
            self.db.execute(
                "INSERT INTO fo_evidence(evidence_key,decision_id,kind,"
                "payload_json,at) VALUES(?,?,?,?,?)",
                (key, decision_id, kind, canonical(payload), at))
        return "stored"

    def evidence(self, decision_id: str, kind: Optional[str] = None
                 ) -> List[Dict[str, object]]:
        if kind:
            rows = self.db.execute(
                "SELECT evidence_key,kind,payload_json,at FROM fo_evidence "
                "WHERE decision_id=? AND kind=? ORDER BY rowid",
                (decision_id, kind)).fetchall()
        else:
            rows = self.db.execute(
                "SELECT evidence_key,kind,payload_json,at FROM fo_evidence "
                "WHERE decision_id=? ORDER BY rowid", (decision_id,)).fetchall()
        return [{"key": k, "kind": kind_, "at": at,
                 "payload": json.loads(payload)}
                for k, kind_, payload, at in rows]

    # ----- client receipts / idempotency ---------------------------------
    def put_receipt(self, request_id: str, payload: Mapping[str, object],
                    receipt: Mapping[str, object], at: int, *,
                    status: str = "accepted") -> None:
        with immediate_tx(self.db):
            self.db.execute(
                "INSERT OR REPLACE INTO fo_client_requests"
                "(request_id,payload_json,status,receipt_json,created_at) "
                "VALUES(?,?,?,?,?)",
                (request_id, canonical(payload), status,
                 canonical(receipt), at))

    def get_request(self, request_id: str) -> Optional[Dict[str, object]]:
        row = self.db.execute(
            "SELECT payload_json,status,receipt_json FROM fo_client_requests "
            "WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            return None
        return {"payload": json.loads(row[0]), "status": row[1],
                "receipt": json.loads(row[2])}

    def check_idempotent(self, request_id: str,
                         payload: Mapping[str, object]
                         ) -> Optional[Dict[str, object]]:
        prior = self.get_request(request_id)
        if prior is None:
            return None
        if prior["payload"] != payload:
            raise RequestIdConflict(
                f"request_id {request_id} reused with different payload")
        return prior["receipt"]

    # ----- singleton current leadership ----------------------------------
    def current_leadership(self) -> Optional[Dict[str, object]]:
        row = self.db.execute("SELECT * FROM fo_leadership WHERE id=1").fetchone()
        if row is None:
            return None
        cols = [d[0] for d in self.db.execute(
            "SELECT * FROM fo_leadership LIMIT 0").description]
        data = dict(zip(cols, row))
        data["basis"] = json.loads(data.pop("basis_json"))
        return data

    def commit_open(self, decision_id: str, *, at: int,
                    cluster: Cluster,
                    route_flips: Sequence[str] = ()) -> Dict[str, object]:
        """Atomically bind prefix + fence + unique leader OPEN + routes.

        The gateway route flips and node open grant are written inside the
        same immediate transaction; the reachability sweep is then evaluated
        on that uncommitted state.  OPEN only commits when the sweep returns
        exactly the chosen leader, so a second reachable writer makes the
        whole decision roll back.
        """
        decision = self.require(decision_id)
        if decision["stage"] == STAGE_OPEN:
            leadership = self.current_leadership()
            if leadership and leadership["decision_id"] == decision_id:
                return leadership
            raise UnsafeOpen("decision already open without leadership row")
        if decision["stage"] != STAGE_FENCE:
            raise UnsafeOpen(
                f"cannot open from stage {decision['stage']}; fence not ready")
        if not decision.get("prefix_json") or not decision.get("fence_json"):
            raise UnsafeOpen("open requires prefix and fence evidence")
        leader = decision["leader"]
        term = int(decision["term"])
        prefix_index = int(decision["prefix_index"])
        prefix_digest = str(decision["prefix_digest"])
        fence = decision["fence"]
        prefix = decision["prefix"]
        if not fence.get("satisfied"):
            raise UnsafeOpen("fence coverage not satisfied")

        with immediate_tx(self.db):
            self.db.execute(
                "INSERT INTO fo_leadership(id,decision_id,node,term,"
                "prefix_index,prefix_digest,opened_at,basis_json) "
                "VALUES(1,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET decision_id=excluded.decision_id,"
                "node=excluded.node,term=excluded.term,"
                "prefix_index=excluded.prefix_index,"
                "prefix_digest=excluded.prefix_digest,"
                "opened_at=excluded.opened_at,basis_json=excluded.basis_json",
                (decision_id, leader, term, prefix_index, prefix_digest,
                 at, "{}"))
            # The grant and fence high-water mark commit with the decision.
            self.db.execute(
                "UPDATE fo_nodes SET open_term=?, accepting_writes=1, "
                "highest_fence=MAX(highest_fence,?) WHERE node=?",
                (term, term, leader))
            for path_id in route_flips:
                self.db.execute(
                    "UPDATE fo_paths SET target=?, route_target=?, "
                    "write_denied=0, rule_version=rule_version+1 "
                    "WHERE path_id=?", (leader, leader, path_id))

            # In-transaction physical reachability evidence.
            reachability = cluster.reachable_writers(at)
            writer_names = [w["node"] for w in reachability]
            if writer_names != [leader]:
                raise UnsafeOpen(
                    f"open-time reachability must be exactly [{leader}], "
                    f"got {writer_names}; open rolled back")

            basis = {
                "decision_id": decision_id, "leader": leader, "term": term,
                "opened_at": at,
                "prefix": prefix, "fence": fence,
                "open_time_reachability": reachability,
                "route_flips": list(route_flips),
                "evidence_note": ("same-position digest conflict, client ACK "
                                  "prefix, old-writer containment and open "
                                  "time are bound in this decision"),
            }
            self.db.execute("UPDATE fo_leadership SET basis_json=? WHERE id=1",
                            (canonical(basis),))
            self.db.execute(
                "UPDATE fo_decisions SET stage=?, open_basis_json=?, "
                "opened_at=?, updated_at=? WHERE decision_id=?",
                (STAGE_OPEN, canonical(basis), at, at, decision_id))
            self._event(decision_id, at, STAGE_OPEN,
                        {"leader": leader, "term": term,
                         "prefix_index": prefix_index,
                         "prefix_digest": prefix_digest,
                         "route_flips": list(route_flips),
                         "reachable_writers": writer_names})
        leadership = self.current_leadership()
        assert leadership is not None
        return leadership

    # ----- restart recovery view -----------------------------------------
    def recovery_view(self, cluster: Cluster, *, at: int,
                       decision_id: Optional[str] = None) -> Dict[str, object]:
        leadership = self.current_leadership()
        writers = cluster.reachable_writers(at)
        if len(writers) > 1:
            # The durable singleton should make this impossible; surface it
            # loudly rather than silently choosing.
            raise AssertionError(f"dual reachable writers after recovery: {writers}")
        decision = self.get(decision_id) if decision_id else None
        return {
            "at": at,
            "decision_id": decision_id,
            "stage": decision["stage"] if decision else None,
            "wait_reason": decision.get("wait_reason") if decision else None,
            "durable_leader": ({"node": leadership["node"],
                                 "term": leadership["term"],
                                 "decision_id": leadership["decision_id"]}
                                if leadership else None),
            "reachable_writers": writers,
            "writable": [w["node"] for w in writers],
            "raw_page_count": (len(self.raw_pages(decision_id))
                               if decision_id else 0),
            "events": self.events(decision_id) if decision_id else [],
        }


class OrderClient:
    """Idempotent order-write client bound to the open term and prefix."""

    def __init__(self, court: FailoverCourt, cluster: Cluster, *,
                 path_id: str = "path-ext", replicate_to: Sequence[str] = ("W",)):
        self.court = court
        self.db = court.db
        self.cluster = cluster
        self.path_id = path_id
        self.replicate_to = tuple(replicate_to)

    def submit(self, request_id: str, payload: Mapping[str, object], *,
               at: Optional[int] = None,
               crash_after_commit: bool = False) -> Dict[str, object]:
        prior = self.court.check_idempotent(request_id, payload)
        if prior is not None:
            return prior
        at = self.cluster.real_time if at is None else at

        leadership = self.court.current_leadership()
        if leadership is None:
            raise LeaderNotOpen(
                f"{request_id}: no committed leader decision yet (retry)")
        leader = str(leadership["node"])
        term = int(leadership["term"])

        # Real gateway traversal + old-epoch fence / lease admission.
        verdict = self.cluster.deliver(self.path_id, at, write_term=term)
        if verdict["node"] != leader:
            raise LeaderNotOpen(
                f"path reaches {verdict['node']} but decision names {leader}")

        secrets = self.cluster.secrets()
        with immediate_tx(self.db):
            # Re-check idempotency inside the write transaction.
            row = self.db.execute(
                "SELECT receipt_json,payload_json FROM fo_client_requests "
                "WHERE request_id=?", (request_id,)).fetchone()
            if row is not None:
                if json.loads(row[1]) != payload:
                    raise RequestIdConflict(
                        f"request_id {request_id} reused with different payload")
                return json.loads(row[0])

            log = load_log(self.db, leader, secrets)
            # Leader side request de-duplication from its own WAL.
            for existing in log.records:
                if existing.get("request_id") == request_id:
                    raise LeaderNotOpen(
                        "request already in leader WAL but receipt missing; "
                        "reconcile before retry")
            boot = int(self.cluster.node(leader)["boot"])
            record = log.append(term=term, payload=payload, ack=True,
                                 request_id=request_id, boot=boot)
            insert_record_row(self.db, leader, record)

            replicas = []
            for holder in self.replicate_to:
                replica_log = load_log(self.db, holder, secrets)
                adopted = replica_log.adopt(record)
                insert_record_row(self.db, holder, adopted)
                self.db.execute(
                    "INSERT INTO fo_replication(term,idx,digest,holder,"
                    "request_id,at) VALUES(?,?,?,?,?,?)",
                    (term, record["index"], record["digest"], holder,
                     request_id, at))
                replicas.append(holder)

            prefix_index = int(leadership["prefix_index"])
            receipt = {
                "request_id": request_id,
                "status": "accepted",
                "leader": leader,
                "node": leader,
                "term": term,
                "index": record["index"],
                "digest": record["digest"],
                "fence_epoch": term,
                "prefix_index": prefix_index,
                "prefix_digest": leadership["prefix_digest"],
                "replicated_to": replicas,
                "commit_prefix": {
                    "index": prefix_index,
                    "digest": leadership["prefix_digest"],
                },
                "admission": verdict["reason"],
                "at": at,
            }
            self.db.execute(
                "INSERT INTO fo_client_requests(request_id,payload_json,"
                "status,receipt_json,created_at) VALUES(?,?,?,?,?)",
                (request_id, canonical(payload), "accepted",
                 canonical(receipt), at))
        if crash_after_commit:
            # Stands in for the ACK packet (or the caller response) being
            # lost after the transaction durably committed.
            from .cluster import CrashSimulated
            raise CrashSimulated("client_ack_lost_after_commit")
        return receipt
