"""Recompute decisions from durable request evidence and compare live state."""

import json
import sqlite3

from .db import canonical, initialize, rows
from .executor import execute


TABLES = ("policies", "revisions", "retirements", "inventories", "observations",
          "exceptions", "plans", "actions", "receipts",
          "image_builds", "image_build_layers", "image_layers", "image_layer_evidence",
          "image_origins", "image_signing_keys", "image_scanner_rules", "image_scans",
          "image_permits", "image_orders", "image_nodes", "image_rollouts",
          "image_rollout_nodes", "image_node_probes", "image_tag_history")


def report(connection):
    initialize(connection)
    events = rows(connection, "SELECT * FROM events ORDER BY id")
    replay = sqlite3.connect(":memory:", isolation_level=None)
    replay.row_factory = sqlite3.Row
    replay.execute("PRAGMA foreign_keys=ON")
    initialize(replay)
    mismatches = []
    for event in events:
        subsystem, operation = event["kind"].split(".", 1)
        expected = json.loads(event["result_json"])
        try:
            actual = execute(replay, subsystem, operation,
                             json.loads(event["input_json"]), event["request_id"])
        except Exception as error:
            mismatches.append({"event": event["id"], "error": str(error)})
            continue
        if canonical(actual) != canonical(expected):
            mismatches.append({"event": event["id"], "stored": expected, "replayed": actual})
    for table in TABLES:
        live = rows(connection, f"SELECT * FROM {table} ORDER BY rowid")
        rebuilt = rows(replay, f"SELECT * FROM {table} ORDER BY rowid")
        if canonical(live) != canonical(rebuilt):
            mismatches.append({"table": table, "live_rows": len(live), "replayed_rows": len(rebuilt)})
    summary = {
        "event_count": len(events), "audit": "consistent" if not mismatches else "diverged",
        "mismatches": mismatches,
        "policies": rows(connection, "SELECT id,status,active_revision,generation FROM policies ORDER BY id"),
        "replicas": rows(connection, "SELECT replica_id,generation,drift,drift_reason FROM inventories ORDER BY replica_id"),
        "plans": rows(connection, "SELECT id,status,target_revision,current_wave FROM plans ORDER BY id"),
        "recent_decisions": [
            {"id": event["id"], "kind": event["kind"], "subject": event["subject"],
             "result": json.loads(event["result_json"])} for event in events[-15:]
        ],
    }
    replay.close()
    return summary
