"""Recompute decisions from durable request evidence and compare live state."""

import json
import sqlite3

from .db import canonical, initialize, rows
from .executor import execute


TABLES = ("policies", "revisions", "retirements", "nodes", "inventories", "observations",
          "exceptions", "effective_targets", "pins", "health_samples",
          "plans", "actions", "receipts")


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
        "plans": rows(connection, "SELECT id,status,target_revision,current_wave,"
                     "cluster,target_uid,target_digest FROM plans ORDER BY id"),
        "hierarchy_nodes": rows(connection, "SELECT node,kind,name,parent,status "
                                "FROM nodes ORDER BY node"),
        "pins": rows(connection, "SELECT pin_id,cluster,service,target_uid,status,"
                     "window_minutes FROM pins ORDER BY pin_id"),
        "effective_targets": rows(connection, "SELECT target_uid,service,cluster,digest,"
                                  "vector_json,pinned FROM effective_targets ORDER BY target_uid"),
        "recent_decisions": [
            {"id": event["id"], "kind": event["kind"], "subject": event["subject"],
             "result": json.loads(event["result_json"])} for event in events[-15:]
        ],
    }
    replay.close()
    return summary
