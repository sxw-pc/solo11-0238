"""Transactional persistence and immutable decision evidence."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path


SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY, namespace TEXT NOT NULL, scope TEXT NOT NULL,
  owner TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft',
  active_revision INTEGER, generation INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS revisions (
  policy_id TEXT NOT NULL REFERENCES policies(id), revision INTEGER NOT NULL,
  value TEXT NOT NULL, dependencies TEXT NOT NULL, status TEXT NOT NULL,
  created_at INTEGER NOT NULL, PRIMARY KEY(policy_id, revision)
);
CREATE TABLE IF NOT EXISTS retirements (
  policy_id TEXT PRIMARY KEY REFERENCES policies(id), requested_at INTEGER NOT NULL,
  status TEXT NOT NULL, blockers TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS inventories (
  replica_id TEXT PRIMARY KEY, service TEXT NOT NULL, namespace TEXT NOT NULL,
  generation INTEGER NOT NULL, healthy INTEGER NOT NULL,
  policy_id TEXT, revision INTEGER, value TEXT, observed_at INTEGER NOT NULL DEFAULT 0,
  drift TEXT NOT NULL DEFAULT 'unknown', drift_reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS observations (
  id TEXT PRIMARY KEY, replica_id TEXT NOT NULL REFERENCES inventories(replica_id),
  generation INTEGER NOT NULL, observed_at INTEGER NOT NULL, received_at INTEGER NOT NULL,
  policy_id TEXT, revision INTEGER, value TEXT, origin TEXT NOT NULL,
  status TEXT NOT NULL, drift TEXT NOT NULL, reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exceptions (
  id TEXT PRIMARY KEY, replica_id TEXT NOT NULL REFERENCES inventories(replica_id),
  policy_id TEXT NOT NULL, policy_revision INTEGER NOT NULL,
  approved_by TEXT NOT NULL, expires_at INTEGER NOT NULL,
  status TEXT NOT NULL, reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plans (
  id TEXT PRIMARY KEY, policy_id TEXT NOT NULL REFERENCES policies(id),
  target_revision INTEGER NOT NULL, service TEXT NOT NULL, min_healthy INTEGER NOT NULL,
  status TEXT NOT NULL, created_at INTEGER NOT NULL, current_wave INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES plans(id),
  replica_id TEXT NOT NULL REFERENCES inventories(replica_id),
  wave INTEGER NOT NULL, expected_generation INTEGER NOT NULL,
  status TEXT NOT NULL, result TEXT NOT NULL DEFAULT '',
  UNIQUE(plan_id, replica_id)
);
CREATE TABLE IF NOT EXISTS receipts (
  id TEXT PRIMARY KEY, action_id TEXT NOT NULL REFERENCES actions(id),
  replica_id TEXT NOT NULL, generation INTEGER NOT NULL, revision INTEGER NOT NULL,
  value TEXT NOT NULL, observed_at INTEGER NOT NULL, status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL, subject TEXT NOT NULL, input_json TEXT NOT NULL,
  result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_replica ON observations(replica_id,observed_at);
CREATE INDEX IF NOT EXISTS idx_actions_plan ON actions(plan_id,wave);
"""


class DecisionError(ValueError):
    """Invalid command or stale identity, separate from a business rejection."""


def connect(filename):
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def initialize(connection):
    connection.executescript(SCHEMA)


@contextmanager
def transaction(connection):
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise


def row(connection, sql, parameters=()):
    found = connection.execute(sql, parameters).fetchone()
    return dict(found) if found else None


def rows(connection, sql, parameters=()):
    return [dict(item) for item in connection.execute(sql, parameters).fetchall()]


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def previous(connection, request_id, payload):
    found = row(connection, "SELECT input_json,result_json FROM events WHERE request_id=?", (request_id,))
    if found is None:
        return None
    if found["input_json"] != canonical(payload):
        raise DecisionError(f"request_id {request_id} was reused with different input")
    return json.loads(found["result_json"])


def record(connection, request_id, kind, subject, payload, result):
    connection.execute(
        "INSERT INTO events(request_id,kind,subject,input_json,result_json) VALUES(?,?,?,?,?)",
        (request_id, kind, subject, canonical(payload), canonical(result)),
    )
    return result


def require(payload, *names):
    absent = [name for name in names if name not in payload]
    if absent:
        raise DecisionError("missing fields: " + ", ".join(absent))


def decision(status, reason, **details):
    return {"status": status, "reason": reason, **details}
