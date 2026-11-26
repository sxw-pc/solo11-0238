"""Production permits quantified over every compatible layer provenance path.

A permit is granted only when the whole provenance graph is unambiguous in the
safe direction: every evidence edge reachable from the build's base layers must
end at a trusted upstream origin, every physically reachable layer must pass
the scanner rules that were in force at decision time, the signature key
generation must be live, and a full-layer scan must cover the exact digest that
will run.  One tainted compatible source (L0 beside clean L1) blocks the permit
even though a clean path exists.

Decisions are immutable rows.  Later scanner rules or key revocations never
rewrite an old permit; they only power new decisions and stop/recall/resign
orders, which are themselves an append-only, replay-safe ledger.
"""

import json

from .db import DecisionError, canonical, decision, row, rows


SEVERITY = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _layer_meta(connection, layer):
    return row(connection, "SELECT * FROM image_layers WHERE digest=?", (layer,))


def _rule_violations(connection, layer, scanner_version, at):
    meta = _layer_meta(connection, layer)
    kind = meta["kind"] if meta else "product"
    level = meta["vuln_level"] if meta else "none"
    violations = []
    for rule in rows(
            connection,
            "SELECT * FROM image_scanner_rules WHERE scanner_version=? AND effective_at<=? "
            "AND layer_kind IN (?, '*') ORDER BY rule_id",
            (scanner_version, at, kind)):
        if SEVERITY.get(level, 0) >= SEVERITY.get(rule["min_level"], 99):
            violations.append({"code": "scanner_rule_violation", "layer": layer,
                               "rule_id": rule["rule_id"], "vuln_level": level,
                               "min_level": rule["min_level"]})
    return violations


def evaluate_provenance(connection, build_row, scanner_version, at):
    """Return (visited_layers, problems).  Empty problems means every byte is sourced."""
    build = build_row["build"]
    build_layers = rows(connection,
                        "SELECT layer,position FROM image_build_layers WHERE build=? ORDER BY position",
                        (build,))
    visited, problems = set(), []

    def walk_upstream(layer, trail):
        if layer in trail:
            problems.append({"code": "provenance_cycle", "layer": layer, "path": list(trail) + [layer]})
            return
        trail = trail + [layer]
        visited.add(layer)
        problems.extend(_rule_violations(connection, layer, scanner_version, at))
        edges = rows(connection,
                     "SELECT e.*,o.trusted AS origin_trusted,o.description AS origin_description "
                     "FROM image_layer_evidence e JOIN image_origins o ON o.origin_id=e.origin_id "
                     "WHERE e.layer_digest=? AND e.retracted_at IS NULL ORDER BY e.evidence_id",
                     (layer,))
        if not edges:
            problems.append({"code": "upstream_evidence_missing", "layer": layer, "path": trail})
            return
        for edge in edges:
            source = edge["source_layer"]
            path = trail + [source]
            if not edge["origin_trusted"]:
                # Marked on the layer whose own provenance is ambiguous, so d2's
                # blocked decision visibly carries the upstream-doubt origin.
                problems.append({"code": "untrusted_origin", "layer": layer, "origin_id": edge["origin_id"],
                                 "source_layer": source, "path": path})
            visited.add(source)
            problems.extend(_rule_violations(connection, source, scanner_version, at))
            # A trusted origin terminates the chain at the upstream root; an untrusted
            # origin still requires every further compatible source to be examined.
            deeper = rows(connection,
                          "SELECT evidence_id FROM image_layer_evidence "
                          "WHERE layer_digest=? AND retracted_at IS NULL",
                          (source,))
            if not deeper:
                if not edge["origin_trusted"]:
                    problems.append({"code": "untrusted_upstream_root", "layer": layer,
                                     "source_layer": source, "origin_id": edge["origin_id"],
                                     "path": path})
                continue
            walk_upstream(source, trail)

    for item in build_layers:
        layer = item["layer"]
        visited.add(layer)
        meta = _layer_meta(connection, layer)
        kind = meta["kind"] if meta else "product"
        problems.extend(_rule_violations(connection, layer, scanner_version, at))
        if kind in ("base", "upstream"):
            edges = rows(connection,
                         "SELECT evidence_id FROM image_layer_evidence "
                         "WHERE layer_digest=? AND retracted_at IS NULL",
                         (layer,))
            if not edges:
                # A late build packet whose base-layer evidence has not arrived cannot be licensed.
                problems.append({"code": "base_layer_evidence_missing", "layer": layer,
                                 "path": [layer]})
                continue
            walk_upstream(layer, [])
    return sorted(visited), problems


def evaluate_build(connection, image, tag, build, at):
    build_row = row(connection, "SELECT * FROM image_builds WHERE build=?", (build,))
    if not build_row:
        return None, [{"code": "unknown_build", "build": build}], None
    if build_row["image"] != image or build_row["tag"] != tag:
        problem = {"code": "tag_build_mismatch", "image": image, "tag": tag, "build": build}
        return build_row, [problem], {"build": dict(build_row), "problems": [problem]}
    problems = []
    key = row(connection, "SELECT * FROM image_signing_keys WHERE key_id=? AND generation=?",
              (build_row["signing_key"], build_row["key_generation"]))
    if not key:
        problems.append({"code": "signing_key_unknown", "key_id": build_row["signing_key"],
                         "generation": build_row["key_generation"]})
    elif key["revoked_at"] is not None and key["revoked_at"] <= at:
        problems.append({"code": "signing_key_revoked", "key_id": build_row["signing_key"],
                         "generation": build_row["key_generation"], "revoked_at": key["revoked_at"]})
    scan = row(connection,
               "SELECT * FROM image_scans WHERE build=? AND full_layer=1 AND target_digest=? "
               "AND scanned_at<=? ORDER BY scanned_at DESC",
               (build, build_row["digest"], at))
    if not scan:
        problems.append({"code": "full_layer_scan_missing", "build": build,
                         "digest": build_row["digest"]})
        scanner_version = None
    else:
        scanner_version = scan["scanner_version"]
        visited, graph_problems = evaluate_provenance(connection, build_row, scanner_version, at)
        problems.extend(graph_problems)
    evidence = {"build": dict(build_row), "scan": dict(scan) if scan else None,
                "scanner_version": scanner_version, "problems": problems,
                "decided_with_rules_at": at}
    return build_row, problems, evidence


def license_build(connection, payload):
    for name in ("permit_id", "image", "tag", "build", "at"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    permit_id, image, tag, build, at = (str(payload["permit_id"]), str(payload["image"]),
                                        str(payload["tag"]), str(payload["build"]),
                                        int(payload["at"]))
    existing = row(connection, "SELECT * FROM image_permits WHERE permit_id=?", (permit_id,))
    if existing:
        if (existing["image"], existing["tag"], existing["build"], existing["decided_at"]) != (
                image, tag, build, at):
            raise DecisionError("permit id reused with a different licensing request")
        return decision(existing["status"], existing["reason"], permit_id=permit_id,
                        image=image, tag=tag, build=build, digest=existing["digest"],
                        evidence=json.loads(existing["evidence_json"]), replayed=True)
    result = evaluate_build(connection, image, tag, build, at)
    if result[0] is None:
        raise DecisionError(result[1][0]["code"])
    build_row, problems, evidence = result
    if problems:
        status, reason = "blocked", "provenance is not safe across every compatible source"
    else:
        status, reason = "permitted", "every executable byte is attested along all compatible layer paths"
    connection.execute(
        "INSERT INTO image_permits(permit_id,image,tag,build,digest,status,reason,decided_at,evidence_json) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (permit_id, image, tag, build, build_row["digest"], status, reason, at,
         canonical(evidence)),
    )
    return decision(status, reason, permit_id=permit_id, image=image, tag=tag, build=build,
                    digest=build_row["digest"], evidence=evidence)


def issue_order(connection, payload):
    for name in ("order_id", "image", "digest", "order_type", "reason", "at"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    order_type = str(payload["order_type"])
    if order_type not in ("stop", "recall", "resign"):
        raise DecisionError("order_type must be stop, recall or resign")
    order_id = str(payload["order_id"])
    existing = row(connection, "SELECT * FROM image_orders WHERE order_id=?", (order_id,))
    if existing:
        fields = ("image", "digest", "order_type", "reason", "issued_at", "related_permit")
        current = tuple(existing[name] for name in fields)
        wanted = (str(payload["image"]), str(payload["digest"]), order_type,
                  str(payload["reason"]), int(payload["at"]),
                  str(payload["related_permit"]) if payload.get("related_permit") is not None else None)
        if current != wanted:
            raise DecisionError("order id reused with different content")
        return decision("replayed", "order already on the ledger", order_id=order_id,
                        order_type=order_type)
    if not row(connection, "SELECT 1 FROM image_builds WHERE digest=?", (str(payload["digest"]),)):
        raise DecisionError("order references a digest with no captured build")
    connection.execute(
        "INSERT INTO image_orders(order_id,image,digest,order_type,reason,issued_at,related_permit) "
        "VALUES(?,?,?,?,?,?,?)",
        (order_id, str(payload["image"]), str(payload["digest"]), order_type,
         str(payload["reason"]), int(payload["at"]),
         str(payload["related_permit"]) if payload.get("related_permit") is not None else None),
    )
    return decision("issued", "order appended; historic permits and rollout state stay traceable",
                    order_id=order_id, order_type=order_type, digest=str(payload["digest"]))


def retag(connection, payload):
    for name in ("image", "tag", "digest", "at", "reason"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    image, tag, digest, at = (str(payload["image"]), str(payload["tag"]),
                              str(payload["digest"]), int(payload["at"]))
    permit = row(
        connection,
        "SELECT * FROM image_permits WHERE image=? AND digest=? AND status='permitted' "
        "ORDER BY decided_at DESC", (image, digest))
    if not permit:
        return decision("blocked", "repository tag cannot move to a digest without a valid production permit",
                        image=image, tag=tag, digest=digest)
    connection.execute(
        "INSERT INTO image_tag_history(image,tag,digest,changed_at,reason) VALUES(?,?,?,?,?)",
        (image, tag, digest, at, str(payload["reason"])),
    )
    return decision("retagged", "repository tag moved; node running state is tracked separately",
                    image=image, tag=tag, digest=digest, changed_at=at)


def active_stop(connection, image, digest, at):
    return rows(connection,
                "SELECT * FROM image_orders WHERE image=? AND digest=? AND order_type IN ('stop','recall') "
                "AND issued_at<=? ORDER BY issued_at", (image, digest, at))


HANDLERS = {"license": license_build, "order": issue_order, "retag": retag}
