"""Recompute decisions from durable request evidence and compare live state."""

import json
import sqlite3

from .db import canonical, initialize, rows
from .executor import execute
from . import merkle


TABLES = ("policies", "revisions", "retirements", "inventories", "observations",
          "exceptions", "plans", "actions", "receipts")


def replay_events(connection, limit=None):
    """Replay an event prefix (or all events) into a fresh in-memory database."""
    initialize(connection)
    sql = "SELECT * FROM events ORDER BY id"
    if limit is not None:
        sql += f" LIMIT {int(limit)}"
    replay = sqlite3.connect(":memory:", isolation_level=None)
    replay.row_factory = sqlite3.Row
    replay.execute("PRAGMA foreign_keys=ON")
    initialize(replay)
    errors = []
    for event in connection.execute(sql):
        expected = json.loads(event["result_json"])
        try:
            actual = execute(replay, *event["kind"].split(".", 1),
                             json.loads(event["input_json"]), event["request_id"])
        except Exception as error:  # pragma: no cover - replay must stay total
            errors.append({"event": event["id"], "error": str(error)})
            continue
        if canonical(actual) != canonical(expected):
            errors.append({"event": event["id"], "stored": expected, "replayed": actual})
    return replay, errors


def verify_sealed_evidence(connection):
    """Check seals against replayable event prefixes and committed roots.

    Deleting redacted leaves does not make the report say ``consistent``: the
    manifest root is recomputed from surviving (key, digest) pairs and every
    disclosed leaf is checked, so tampering or a broken redaction is reported.
    """
    from . import compliance_seal
    compliance_seal.initialize(connection)
    findings = []
    seals = rows(connection, "SELECT * FROM seal_registry ORDER BY seq")
    for seal in seals:
        replay, errors = replay_events(connection, seal["prefix_event_id"])
        if errors:
            findings.append({"seal_id": seal["seal_id"], "replay": "diverged", "errors": errors})
        manifest = json.loads(seal["manifest_json"])
        recomputed = merkle.root_for((item["key"], item["digest"]) for item in manifest)
        if recomputed != seal["root"]:
            findings.append({"seal_id": seal["seal_id"], "root": "mismatch",
                             "stored": seal["root"], "recomputed": recomputed})
        stored = rows(connection, "SELECT leaf_key,digest,content_json FROM seal_leaves "
                      "WHERE seal_id=?", (seal["seal_id"],))
        if len(stored) != len(manifest):
            findings.append({"seal_id": seal["seal_id"], "leaf_rows": "missing",
                             "manifest": len(manifest), "stored": len(stored)})
        by_key = {item["leaf_key"]: item for item in stored}
        for item in manifest:
            row = by_key.get(item["key"])
            if row is None:
                findings.append({"seal_id": seal["seal_id"], "leaf": item["key"], "state": "missing"})
                continue
            if row["digest"] != item["digest"]:
                findings.append({"seal_id": seal["seal_id"], "leaf": item["key"],
                                 "state": "digest_changed"})
                continue
            if row["content_json"] is None:
                continue  # archived/compressed: manifest still anchors the root
            leaf = json.loads(row["content_json"])
            actual = (merkle.event_leaf_digest(leaf) if leaf.get("kind") == "event"
                      else merkle.generic_leaf_digest(leaf))
            if actual != item["digest"]:
                findings.append({"seal_id": seal["seal_id"], "leaf": item["key"],
                                 "state": "content_digest_mismatch"})
        replay.close()
        for att in rows(connection, "SELECT * FROM seal_attachments WHERE seal_id=?",
                        (seal["seal_id"],)):
            att_manifest = json.loads(att["manifest_json"])
            if merkle.root_for((i["key"], i["digest"]) for i in att_manifest) != att["root"]:
                findings.append({"attachment_id": att["attachment_id"], "root": "mismatch"})
    return {"audit": "consistent" if not findings else "diverged",
            "seals_checked": len(seals), "findings": findings}


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
