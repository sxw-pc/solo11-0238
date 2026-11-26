"""Executable in-process simulation of physical nodes, gateways and paths.

All state is persisted in the same SQLite database as the control court so a
"restart" is a real close/reopen cycle.  The simulation is intentionally not
mock-call assertion: gateway rules block writes, fence epochs are enforced by
nodes and reachability sweeps actually evaluate every registered client path.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Dict, Iterable, List, Mapping, Optional, Set

from .fence import (fence_receipt, lease_admits, verify_fence_receipt)
from .wal_chain import WalLog, canonical


CLUSTER_SCHEMA = """
CREATE TABLE IF NOT EXISTS fo_meta (
  key TEXT PRIMARY KEY, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fo_nodes (
  node TEXT PRIMARY KEY,
  secret TEXT NOT NULL,
  boot INTEGER NOT NULL DEFAULT 1,
  lag INTEGER NOT NULL DEFAULT 0,
  leader_term INTEGER,
  lease_until_local INTEGER,
  highest_fence INTEGER NOT NULL DEFAULT 0,
  open_term INTEGER NOT NULL DEFAULT 0,
  accepting_writes INTEGER NOT NULL DEFAULT 1,
  note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS fo_records (
  holder TEXT NOT NULL,
  idx INTEGER NOT NULL,
  term INTEGER NOT NULL,
  digest TEXT NOT NULL,
  request_id TEXT,
  raw_json TEXT NOT NULL,
  PRIMARY KEY(holder, idx)
);
CREATE TABLE IF NOT EXISTS fo_quarantine (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  decision_id TEXT,
  holder TEXT NOT NULL,
  idx INTEGER NOT NULL,
  digest TEXT NOT NULL,
  raw_json TEXT NOT NULL,
  at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fo_gateways (
  gw TEXT PRIMARY KEY, secret TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fo_paths (
  path_id TEXT PRIMARY KEY,
  gw TEXT NOT NULL,
  target TEXT,
  route_target TEXT,
  write_denied INTEGER NOT NULL DEFAULT 0,
  rule_version INTEGER NOT NULL DEFAULT 1,
  kind TEXT NOT NULL DEFAULT 'client'
);
CREATE TABLE IF NOT EXISTS fo_replication (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  term INTEGER NOT NULL,
  idx INTEGER NOT NULL,
  digest TEXT NOT NULL,
  holder TEXT NOT NULL,
  request_id TEXT,
  at INTEGER NOT NULL
);
"""


class ClusterError(ValueError):
    pass


class PathBlocked(ClusterError):
    pass


class NoRoute(ClusterError):
    pass


class StaleWriter(ClusterError):
    pass


class CrashSimulated(RuntimeError):
    """Raised by crash hooks to stand in for a process/kernel crash."""


@contextmanager
def immediate_tx(db: sqlite3.Connection):
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise


def init_cluster_schema(db: sqlite3.Connection) -> None:
    db.executescript(CLUSTER_SCHEMA)
    db.execute("INSERT OR IGNORE INTO fo_meta(key,value) VALUES('real_time','0')")
    db.commit()


# ---------------------------------------------------------------------------
# Record repository helpers (usable inside an outer transaction)
# ---------------------------------------------------------------------------

def load_log(db: sqlite3.Connection, holder: str,
             secrets: Mapping[str, str]) -> WalLog:
    rows = db.execute(
        "SELECT raw_json FROM fo_records WHERE holder=? ORDER BY idx",
        (holder,)).fetchall()
    records = [json.loads(r[0]) for r in rows]
    return WalLog.from_records(holder, records, secrets)


def insert_record_row(db: sqlite3.Connection, holder: str,
                      record: Mapping[str, object]) -> None:
    db.execute(
        "INSERT INTO fo_records(holder,idx,term,digest,request_id,raw_json) "
        "VALUES(?,?,?,?,?,?)",
        (holder, record["index"], record["term"], record["digest"],
         record.get("request_id"), canonical(record)))


class FenceTransport:
    """Scriptable network behaviour for fence RPCs.

    ``drop_request`` simulates a lost fence command (old node never fenced);
    ``drop_ack`` simulates the ambiguous case where the node durably fenced but
    the receipt never reached the court.  Retrying the same epoch/nonce is
    idempotent.
    """

    def __init__(self) -> None:
        self.drop_request: Set[str] = set()
        self.drop_ack: Set[str] = set()
        self.calls: List[Dict[str, object]] = []


class Cluster:
    def __init__(self, db: sqlite3.Connection):
        self.db = db
        init_cluster_schema(db)
        self.transport = FenceTransport()

    # ----- clock ---------------------------------------------------------
    @property
    def real_time(self) -> int:
        row = self.db.execute("SELECT value FROM fo_meta WHERE key='real_time'").fetchone()
        return int(row[0])

    def set_real_time(self, value: int) -> None:
        with immediate_tx(self.db):
            self.db.execute("UPDATE fo_meta SET value=? WHERE key='real_time'",
                            (str(value),))

    def advance(self, delta: int = 1) -> int:
        value = self.real_time + delta
        self.set_real_time(value)
        return value

    # ----- nodes ---------------------------------------------------------
    def add_node(self, node: str, secret: Optional[str] = None, *,
                 boot: int = 1, lag: int = 0,
                 leader_term: Optional[int] = None,
                 lease_until_local: Optional[int] = None,
                 highest_fence: int = 0, open_term: int = 0,
                 accepting_writes: bool = True,
                 note: str = "") -> None:
        secret = secret or f"secret-{node}"
        with immediate_tx(self.db):
            self.db.execute(
                "INSERT OR REPLACE INTO fo_nodes"
                "(node,secret,boot,lag,leader_term,lease_until_local,"
                " highest_fence,open_term,accepting_writes,note) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (node, secret, boot, lag, leader_term, lease_until_local,
                 highest_fence, open_term, 1 if accepting_writes else 0, note))

    def node(self, node: str) -> Dict[str, object]:
        row = self.db.execute("SELECT * FROM fo_nodes WHERE node=?",
                              (node,)).fetchone()
        if row is None:
            raise ClusterError(f"unknown node {node}")
        cols = [d[0] for d in self.db.execute("SELECT * FROM fo_nodes LIMIT 0").description]
        return dict(zip(cols, row))

    def secrets(self) -> Dict[str, str]:
        return {r[0]: r[1] for r in self.db.execute("SELECT node,secret FROM fo_nodes")}

    def set_skew(self, node: str, *, lag: Optional[int] = None) -> None:
        with immediate_tx(self.db):
            if lag is not None:
                self.db.execute("UPDATE fo_nodes SET lag=? WHERE node=?", (lag, node))

    def reboot(self, node: str) -> int:
        """Physical restart: boot generation advances, disk state survives."""
        with immediate_tx(self.db):
            self.db.execute("UPDATE fo_nodes SET boot=boot+1 WHERE node=?", (node,))
        return int(self.node(node)["boot"])

    def log(self, node: str) -> WalLog:
        return load_log(self.db, node, self.secrets())

    def append_local(self, node: str, *, term: int,
                     digest: Optional[str] = None, payload: Optional[object] = None,
                     ack: bool = False, request_id: Optional[str] = None,
                     at_index: Optional[int] = None) -> Dict[str, object]:
        state = self.node(node)
        log = load_log(self.db, node, self.secrets())
        rec = log.append(term=term, digest=digest, payload=payload, ack=ack,
                         request_id=request_id, boot=int(state["boot"]),
                         at_index=at_index)
        with immediate_tx(self.db):
            insert_record_row(self.db, node, rec)
        return rec

    def adopt_record(self, holder: str, record: Mapping[str, object]) -> Dict[str, object]:
        log = load_log(self.db, holder, self.secrets())
        rec = log.adopt(record)
        with immediate_tx(self.db):
            insert_record_row(self.db, holder, rec)
        return rec

    def raw_records(self, holder: str) -> List[Dict[str, object]]:
        rows = self.db.execute(
            "SELECT raw_json FROM fo_records WHERE holder=? ORDER BY idx",
            (holder,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def quarantine_tail(self, holder: str, common_index: int, *,
                        decision_id: str, at: int) -> List[Dict[str, object]]:
        rows = self.db.execute(
            "SELECT idx,digest,raw_json FROM fo_records "
            "WHERE holder=? AND idx>? ORDER BY idx",
            (holder, common_index)).fetchall()
        removed: List[Dict[str, object]] = []
        with immediate_tx(self.db):
            for idx, digest, raw in rows:
                self.db.execute(
                    "INSERT INTO fo_quarantine"
                    "(decision_id,holder,idx,digest,raw_json,at) "
                    "VALUES(?,?,?,?,?,?)",
                    (decision_id, holder, idx, digest, raw, at))
                self.db.execute("DELETE FROM fo_records WHERE holder=? AND idx=?",
                                (holder, idx))
                removed.append(json.loads(raw))
        return removed

    def quarantined(self, holder: Optional[str] = None) -> List[Dict[str, object]]:
        if holder:
            rows = self.db.execute(
                "SELECT decision_id,holder,idx,digest,raw_json,at FROM fo_quarantine "
                "WHERE holder=? ORDER BY id", (holder,)).fetchall()
        else:
            rows = self.db.execute(
                "SELECT decision_id,holder,idx,digest,raw_json,at FROM fo_quarantine "
                "ORDER BY id").fetchall()
        return [{"decision_id": d, "holder": h, "index": i, "digest": dg,
                 "raw": json.loads(raw), "at": at}
                for d, h, i, dg, raw, at in rows]

    def record_replication(self, *, term: int, idx: int, digest: str,
                           holder: str, request_id: Optional[str], at: int) -> None:
        with immediate_tx(self.db):
            self.db.execute(
                "INSERT INTO fo_replication(term,idx,digest,holder,request_id,at) "
                "VALUES(?,?,?,?,?,?)",
                (term, idx, digest, holder, request_id, at))

    def replication_chain(self, idx: Optional[int] = None
                          ) -> List[Dict[str, object]]:
        if idx is None:
            rows = self.db.execute(
                "SELECT term,idx,digest,holder,request_id,at FROM fo_replication "
                "ORDER BY id").fetchall()
        else:
            rows = self.db.execute(
                "SELECT term,idx,digest,holder,request_id,at FROM fo_replication "
                "WHERE idx=? ORDER BY id", (idx,)).fetchall()
        return [dict(zip(("term", "index", "digest", "holder",
                          "request_id", "at"), r)) for r in rows]

    # ----- gateways and client entry paths -------------------------------
    def add_gateway(self, gw: str, secret: Optional[str] = None) -> None:
        secret = secret or f"gw-secret-{gw}"
        with immediate_tx(self.db):
            self.db.execute("INSERT OR REPLACE INTO fo_gateways(gw,secret) VALUES(?,?)",
                            (gw, secret))

    def gateway_secret(self, gw: str) -> str:
        row = self.db.execute("SELECT secret FROM fo_gateways WHERE gw=?", (gw,)).fetchone()
        if row is None:
            raise ClusterError(f"unknown gateway {gw}")
        return row[0]

    def add_path(self, path_id: str, gw: str, target: str, *,
                 routed: bool = True, kind: str = "client") -> None:
        with immediate_tx(self.db):
            self.db.execute(
                "INSERT OR REPLACE INTO fo_paths"
                "(path_id,gw,target,route_target,write_denied,rule_version,kind) "
                "VALUES(?,?,?,?,0,1,?)",
                (path_id, gw, target, target if routed else None, kind))

    def path(self, path_id: str) -> Dict[str, object]:
        row = self.db.execute("SELECT * FROM fo_paths WHERE path_id=?",
                              (path_id,)).fetchone()
        if row is None:
            raise ClusterError(f"unknown path {path_id}")
        cols = [d[0] for d in self.db.execute("SELECT * FROM fo_paths LIMIT 0").description]
        return dict(zip(cols, row))

    def paths_for(self, target: str) -> List[Dict[str, object]]:
        rows = self.db.execute("SELECT path_id FROM fo_paths WHERE target=? ORDER BY path_id",
                               (target,)).fetchall()
        return [self.path(r[0]) for r in rows]

    def all_client_paths(self) -> List[str]:
        return [r[0] for r in self.db.execute(
            "SELECT path_id FROM fo_paths WHERE kind='client' ORDER BY path_id")]

    def block_path(self, path_id: str, at: int) -> Dict[str, object]:
        """Install a real deny rule and return the signed gateway proof."""
        path = self.path(path_id)
        version = int(path["rule_version"]) + 1
        with immediate_tx(self.db):
            self.db.execute(
                "UPDATE fo_paths SET write_denied=1, rule_version=? WHERE path_id=?",
                (version, path_id))
        from .fence import block_proof
        proof = block_proof(gateway=str(path["gw"]),
                            gateway_secret=self.gateway_secret(str(path["gw"])),
                            path_id=path_id, target=str(path["target"]),
                            rule_version=version, at=at, state="blocked")
        return proof

    def confirm_path_closed(self, path_id: str, at: int) -> Dict[str, object]:
        path = self.path(path_id)
        if not path["write_denied"]:
            raise ClusterError(f"path {path_id} is not blocked")
        version = int(path["rule_version"]) + 1
        with immediate_tx(self.db):
            self.db.execute("UPDATE fo_paths SET rule_version=? WHERE path_id=?",
                            (version, path_id))
        from .fence import block_proof
        return block_proof(gateway=str(path["gw"]),
                           gateway_secret=self.gateway_secret(str(path["gw"])),
                           path_id=path_id, target=str(path["target"]),
                           rule_version=version, at=at, state="closed")

    def flip_route(self, path_id: str, new_target: str, at: int) -> None:
        """Atomically point an entry path at the promoted leader and allow writes."""
        with immediate_tx(self.db):
            self.db.execute(
                "UPDATE fo_paths SET target=?, route_target=?, write_denied=0, "
                "rule_version=rule_version+1 WHERE path_id=?",
                (new_target, new_target, path_id))

    # ----- fence RPC -----------------------------------------------------
    def send_fence(self, target: str, epoch: int, nonce: str,
                   at: int) -> Optional[Dict[str, object]]:
        self.transport.calls.append({"target": target, "epoch": epoch,
                                     "nonce": nonce, "at": at})
        if target in self.transport.drop_request:
            return None
        state = self.node(target)
        # Durable promise: persist the high-water fence epoch before ACK.
        if int(state["highest_fence"]) < epoch:
            with immediate_tx(self.db):
                self.db.execute(
                    "UPDATE fo_nodes SET highest_fence=? WHERE node=?",
                    (epoch, target))
        receipt = fence_receipt(node=target, secret=self.secrets()[target],
                                epoch=epoch, nonce=nonce,
                                boot=int(state["boot"]), at=at,
                                prior_lease_term=state["leader_term"]
                                if isinstance(state["leader_term"], int) else None)
        if target in self.transport.drop_ack:
            return None
        return receipt

    def close_lease(self, target: str, term: int, at: int) -> Dict[str, object]:
        """Node durably closes its old-term write lease and signs the fact."""
        from .fence import lease_closed_receipt
        state = self.node(target)
        with immediate_tx(self.db):
            self.db.execute(
                "UPDATE fo_nodes SET leader_term=NULL, lease_until_local=NULL "
                "WHERE node=? AND leader_term=?",
                (target, term))
        return lease_closed_receipt(node=target, secret=self.secrets()[target],
                                   term=term, boot=int(state["boot"]), at=at)

    # ----- write admission / reachability --------------------------------
    def would_admit(self, node: str, at: int,
                    write_term: Optional[int] = None) -> Dict[str, object]:
        state = self.node(node)
        if write_term is None:
            write_term = int(state["open_term"] or state["leader_term"] or 0)
        if not state["accepting_writes"]:
            return {"node": node, "term": write_term, "admit": False,
                    "reason": "writes_paused_for_failover", "real_time": at}
        if write_term < int(state["highest_fence"]):
            return {"node": node, "term": write_term, "admit": False,
                    "reason": "fenced_stale_epoch", "real_time": at}
        # An atomic court open grant admits the new leader term directly.
        if state["open_term"] and write_term == int(state["open_term"]) \
                and write_term >= int(state["highest_fence"]):
            return {"node": node, "term": write_term, "admit": True,
                    "reason": "open_leadership_grant", "real_time": at}
        allowed, reason = lease_admits(
            real_time=at, lag=int(state["lag"]),
            lease_until_local=state["lease_until_local"],
            lease_term=state["leader_term"],
            write_term=write_term,
            highest_fence_epoch=int(state["highest_fence"]))
        return {"node": node, "term": write_term, "admit": allowed,
                "reason": reason, "real_time": at}

    def deliver(self, path_id: str, at: int, write_term: Optional[int] = None
                ) -> Dict[str, object]:
        """Evaluate a client write traversing a real gateway entry path."""
        path = self.path(path_id)
        if path["write_denied"]:
            raise PathBlocked(f"path {path_id} denied by {path['gw']} "
                              f"v{path['rule_version']}")
        target = path["route_target"]
        if not target:
            raise NoRoute(f"path {path_id} has no routed primary")
        verdict = self.would_admit(str(target), at, write_term)
        if not verdict["admit"]:
            raise StaleWriter(f"{target} rejects write: {verdict['reason']}")
        return verdict

    def reachable_writers(self, at: int) -> List[Dict[str, object]]:
        """Every distinct node currently reachable *and* admitting writes."""
        found: Dict[str, Dict[str, object]] = {}
        for path_id in self.all_client_paths():
            path = self.path(path_id)
            if path["write_denied"] or not path["route_target"]:
                continue
            target = str(path["route_target"])
            verdict = self.would_admit(target, at)
            if verdict["admit"] and target not in found:
                found[target] = {"node": target, "path": path_id,
                                 "gateway": path["gw"], "term": verdict["term"],
                                 "reason": verdict["reason"]}
        return [found[k] for k in sorted(found)]

    def assert_single_writer(self, at: int, expected: Optional[str] = None) -> None:
        writers = self.reachable_writers(at)
        names = [w["node"] for w in writers]
        if len(names) > 1:
            raise AssertionError(f"dual reachable writers at t={at}: {names}")
        if expected is not None and names != [expected]:
            raise AssertionError(
                f"at t={at} expected writer [{expected}], got {names}")
