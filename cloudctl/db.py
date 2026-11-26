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
CREATE TABLE IF NOT EXISTS image_builds (
  build TEXT PRIMARY KEY, image TEXT NOT NULL, tag TEXT NOT NULL, digest TEXT NOT NULL,
  source_commit TEXT NOT NULL, environment_digest TEXT NOT NULL,
  signing_key TEXT NOT NULL, key_generation INTEGER NOT NULL,
  builder TEXT NOT NULL, captured_at INTEGER NOT NULL, parent_build TEXT,
  packet TEXT NOT NULL, packet_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS image_build_layers (
  build TEXT NOT NULL, layer TEXT NOT NULL, position INTEGER NOT NULL,
  PRIMARY KEY(build, position)
);
CREATE TABLE IF NOT EXISTS image_layers (
  digest TEXT PRIMARY KEY, kind TEXT NOT NULL, vuln_level TEXT NOT NULL DEFAULT 'none'
);
CREATE TABLE IF NOT EXISTS image_layer_evidence (
  layer_digest TEXT NOT NULL, source_layer TEXT NOT NULL,
  origin_id TEXT NOT NULL, evidence_id TEXT NOT NULL, recorded_at INTEGER NOT NULL,
  retracted_at INTEGER, PRIMARY KEY(evidence_id)
);
CREATE TABLE IF NOT EXISTS image_origins (
  origin_id TEXT PRIMARY KEY, description TEXT NOT NULL, trusted INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS image_signing_keys (
  key_id TEXT NOT NULL, generation INTEGER NOT NULL, revoked_at INTEGER,
  revoke_reason TEXT NOT NULL DEFAULT '', PRIMARY KEY(key_id, generation)
);
CREATE TABLE IF NOT EXISTS image_scanner_rules (
  rule_id TEXT NOT NULL, scanner_version TEXT NOT NULL, layer_kind TEXT NOT NULL,
  min_level TEXT NOT NULL, effective_at INTEGER NOT NULL, PRIMARY KEY(rule_id)
);
CREATE TABLE IF NOT EXISTS image_scans (
  build TEXT NOT NULL, scanner_version TEXT NOT NULL, full_layer INTEGER NOT NULL,
  target_digest TEXT NOT NULL, scanned_at INTEGER NOT NULL, PRIMARY KEY(build, scanner_version, full_layer)
);
CREATE TABLE IF NOT EXISTS image_permits (
  permit_id TEXT PRIMARY KEY, image TEXT NOT NULL, tag TEXT NOT NULL,
  build TEXT NOT NULL, digest TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL,
  decided_at INTEGER NOT NULL, evidence_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS image_orders (
  order_id TEXT PRIMARY KEY, image TEXT NOT NULL, digest TEXT NOT NULL,
  order_type TEXT NOT NULL, reason TEXT NOT NULL, issued_at INTEGER NOT NULL,
  related_permit TEXT
);
CREATE TABLE IF NOT EXISTS image_nodes (
  node_id TEXT PRIMARY KEY, service TEXT NOT NULL, healthy INTEGER NOT NULL,
  running_digest TEXT NOT NULL, running_build TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS image_rollouts (
  rollout_id TEXT PRIMARY KEY, image TEXT NOT NULL, target_digest TEXT NOT NULL,
  fallback_digest TEXT NOT NULL, min_healthy INTEGER NOT NULL,
  status TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS image_rollout_nodes (
  rollout_id TEXT NOT NULL, node_id TEXT NOT NULL, wave INTEGER NOT NULL,
  switch_status TEXT NOT NULL DEFAULT 'planned', digest_at_dispatch TEXT,
  PRIMARY KEY(rollout_id, node_id)
);
CREATE TABLE IF NOT EXISTS image_node_probes (
  probe_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, service TEXT NOT NULL,
  digest TEXT NOT NULL, healthy INTEGER NOT NULL, probed_at INTEGER NOT NULL,
  independent INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS image_tag_history (
  image TEXT NOT NULL, tag TEXT NOT NULL, digest TEXT NOT NULL,
  changed_at INTEGER NOT NULL, reason TEXT NOT NULL, PRIMARY KEY(image, tag, changed_at)
);
CREATE INDEX IF NOT EXISTS idx_observations_replica ON observations(replica_id,observed_at);
CREATE INDEX IF NOT EXISTS idx_actions_plan ON actions(plan_id,wave);
CREATE INDEX IF NOT EXISTS idx_layer_evidence ON image_layer_evidence(layer_digest);
CREATE INDEX IF NOT EXISTS idx_build_layers ON image_build_layers(build,position);
CREATE INDEX IF NOT EXISTS idx_rollout_nodes ON image_rollout_nodes(rollout_id,wave);
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
