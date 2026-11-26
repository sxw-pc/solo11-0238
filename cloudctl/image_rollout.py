"""Node cutover: durable switch commands, independent probes and retirement.

Repository publishability (a permit plus a tag) and what nodes actually run are
kept in separate tables.  Every switch command and probe is a natural-key row,
so after a restart the same rollout request cannot be dispatched twice: replay
returns the stored decision and the running digest only changes once the node's
own evidence plus an independent probe confirm it.
"""

from .db import decision, row, rows
from .image_permit import active_stop


def register_node(connection, payload):
    for name in ("node_id", "service", "running_digest", "running_build"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    node_id = str(payload["node_id"])
    healthy = int(bool(payload.get("healthy", True)))
    existing = row(connection, "SELECT * FROM image_nodes WHERE node_id=?", (node_id,))
    values = (str(payload["service"]), healthy, str(payload["running_digest"]),
              str(payload["running_build"]))
    if existing:
        if tuple(existing[name] for name in ("service", "healthy", "running_digest", "running_build")) != values:
            raise DecisionError("node identity changed; node inventory moves through rollout and probe evidence")
        return decision("replayed", "node already registered", node_id=node_id,
                        running_digest=existing["running_digest"])
    connection.execute(
        "INSERT INTO image_nodes(node_id,service,healthy,running_digest,running_build) VALUES(?,?,?,?,?)",
        (node_id, *values),
    )
    return decision("registered", "node running inventory recorded", node_id=node_id,
                    service=values[0], running_digest=values[2])


def create_rollout(connection, payload):
    for name in ("rollout_id", "image", "target_digest", "fallback_digest", "min_healthy", "at"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    rollout_id = str(payload["rollout_id"])
    existing = row(connection, "SELECT * FROM image_rollouts WHERE rollout_id=?", (rollout_id,))
    if existing:
        fields = ("image", "target_digest", "fallback_digest", "min_healthy", "created_at")
        wanted = (str(payload["image"]), str(payload["target_digest"]),
                  str(payload["fallback_digest"]), int(payload["min_healthy"]), int(payload["at"]))
        if tuple(existing[name] for name in fields) != wanted:
            raise DecisionError("rollout id reused with different content")
        return decision("replayed", "rollout already planned",
                        rollout_id=rollout_id, rollout_status=existing["status"])
    image, target_digest, fallback_digest = (str(payload["image"]),
                                             str(payload["target_digest"]),
                                             str(payload["fallback_digest"]))
    permit = row(connection,
                 "SELECT * FROM image_permits WHERE image=? AND digest=? AND status='permitted' "
                 "ORDER BY decided_at DESC", (image, target_digest))
    if not permit:
        return decision("blocked", "rollout target has no valid production permit",
                        rollout_id=rollout_id, digest=target_digest)
    if active_stop(connection, image, target_digest, int(payload["at"])):
        return decision("blocked", "stop/recall order forbids new cutover commands for this digest",
                        rollout_id=rollout_id, digest=target_digest)
    if not row(connection, "SELECT 1 FROM image_builds WHERE digest=?", (fallback_digest,)):
        raise DecisionError("fallback digest has no captured build")
    min_healthy = int(payload["min_healthy"])
    nodes = rows(connection, "SELECT * FROM image_nodes WHERE service=? ORDER BY node_id", (image,))
    if not nodes:
        return decision("blocked", "no registered nodes run this service", rollout_id=rollout_id)
    healthy = sum(int(node["healthy"]) for node in nodes)
    if min_healthy < 0 or min_healthy > healthy:
        return decision("blocked", "minimum healthy count exceeds current service health",
                        healthy=healthy, min_healthy=min_healthy)
    parallel = healthy - min_healthy
    if parallel < 1:
        return decision("blocked", "no disruption budget remains for a cutover wave",
                        healthy=healthy, min_healthy=min_healthy)
    connection.execute(
        "INSERT INTO image_rollouts(rollout_id,image,target_digest,fallback_digest,min_healthy,"
        "status,created_at) VALUES(?,?,?,?,?,'planned',?)",
        (rollout_id, image, target_digest, fallback_digest, min_healthy, int(payload["at"])),
    )
    waves = []
    for index, node in enumerate(nodes):
        wave = index // parallel + 1
        connection.execute(
            "INSERT INTO image_rollout_nodes(rollout_id,node_id,wave) VALUES(?,?,?)",
            (rollout_id, node["node_id"], wave),
        )
        waves.append({"node_id": node["node_id"], "wave": wave})
    return decision("planned", "cutover waves preserve the service health floor",
                    rollout_id=rollout_id, target_digest=target_digest,
                    fallback_digest=fallback_digest, waves=waves, parallel=parallel)


def switch_node(connection, payload):
    for name in ("rollout_id", "node_id", "at"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    rollout_id, node_id, at = (str(payload["rollout_id"]), str(payload["node_id"]),
                               int(payload["at"]))
    rollout = row(connection, "SELECT * FROM image_rollouts WHERE rollout_id=?", (rollout_id,))
    if not rollout:
        return decision("rejected", "rollout does not exist")
    member = row(connection, "SELECT * FROM image_rollout_nodes WHERE rollout_id=? AND node_id=?",
                 (rollout_id, node_id))
    if not member:
        return decision("rejected", "node is not part of this rollout")
    if rollout["status"] in ("cancelled", "retired"):
        return decision("blocked", f"rollout is {rollout['status']}", rollout_id=rollout_id)
    if active_stop(connection, rollout["image"], rollout["target_digest"], at):
        connection.execute("UPDATE image_rollouts SET status='paused' WHERE rollout_id=?", (rollout_id,))
        return decision("blocked", "stop/recall order freezes further node switches",
                        rollout_id=rollout_id, digest=rollout["target_digest"])
    if member["switch_status"] == "switched":
        return decision("switched", "same switch command is already confirmed; not dispatched twice",
                        rollout_id=rollout_id, node_id=node_id, digest=member["digest_at_dispatch"])
    if member["switch_status"] == "dispatched":
        return decision("dispatched", "switch command remains in flight and is not re-sent",
                        rollout_id=rollout_id, node_id=node_id)
    if member["switch_status"] == "rolled_back":
        return decision("blocked", "node already fell back to the rollout fallback digest",
                        rollout_id=rollout_id, node_id=node_id)
    previous = rows(connection,
                    "SELECT node_id,switch_status FROM image_rollout_nodes WHERE rollout_id=? AND wave<?",
                    (rollout_id, member["wave"]))
    pending = [item["node_id"] for item in previous if item["switch_status"] != "switched"]
    if pending:
        return decision("blocked", "previous cutover wave is not fully switched",
                        rollout_id=rollout_id, pending=pending)
    same_wave = rows(connection,
                     "SELECT switch_status FROM image_rollout_nodes WHERE rollout_id=? AND wave=?",
                     (rollout_id, member["wave"]))
    in_flight = sum(item["switch_status"] == "dispatched" for item in same_wave)
    # Switched nodes stay healthy and keep serving; only in-flight switches
    # temporarily remove capacity, matching the wave budget chosen at planning.
    healthy = row(connection, "SELECT COUNT(*) AS n FROM image_nodes WHERE service=? AND healthy=1",
                  (rollout["image"],))["n"]
    if healthy - in_flight - 1 < rollout["min_healthy"]:
        return decision("blocked", "switch would breach the service health floor",
                        healthy=healthy, in_flight=in_flight,
                        min_healthy=rollout["min_healthy"])
    node = row(connection, "SELECT * FROM image_nodes WHERE node_id=?", (node_id,))
    connection.execute(
        "UPDATE image_rollout_nodes SET switch_status='dispatched',digest_at_dispatch=? "
        "WHERE rollout_id=? AND node_id=?",
        (node["running_digest"], rollout_id, node_id),
    )
    connection.execute("UPDATE image_rollouts SET status='running' WHERE rollout_id=?", (rollout_id,))
    return decision("dispatched", "durable switch command issued once for the frozen running digest",
                    rollout_id=rollout_id, node_id=node_id, wave=member["wave"],
                    target_digest=rollout["target_digest"], digest_at_dispatch=node["running_digest"])


def report_node(connection, payload):
    for name in ("probe_id", "node_id", "service", "digest", "at"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    probe_id = str(payload["probe_id"])
    node_id, service, digest = (str(payload["node_id"]), str(payload["service"]),
                                str(payload["digest"]))
    probed_at = int(payload["at"])
    independent = int(bool(payload.get("independent", False)))
    node = row(connection, "SELECT * FROM image_nodes WHERE node_id=?", (node_id,))
    if not node:
        raise DecisionError("probe references an unregistered node")
    # Health is only changed when the probe explicitly speaks to it; an evidence
    # probe for a digest must not silently mark a healthy node unhealthy.
    healthy = int(bool(payload["healthy"])) if "healthy" in payload else int(node["healthy"])
    fields = ("node_id", "service", "digest", "healthy", "probed_at", "independent")
    wanted = (node_id, service, digest, healthy, probed_at, independent)
    existing = row(connection, "SELECT * FROM image_node_probes WHERE probe_id=?", (probe_id,))
    if existing:
        if tuple(existing[name] for name in fields) != wanted:
            raise DecisionError("probe id reused with different probe evidence")
        return decision("replayed", "probe already recorded", probe_id=probe_id,
                        digest=existing["digest"])
    running_build = str(payload["running_build"]) if payload.get("running_build") is not None \
        else node["running_build"]
    connection.execute(
        "INSERT INTO image_node_probes(probe_id,node_id,service,digest,healthy,probed_at,independent) "
        "VALUES(?,?,?,?,?,?,?)",
        (probe_id, *wanted),
    )
    connection.execute(
        "UPDATE image_nodes SET healthy=?,running_digest=?,running_build=? WHERE node_id=?",
        (healthy, digest, running_build, node_id),
    )
    return decision("recorded", "observed node running state; independent probes confirm real cutover",
                    probe_id=probe_id, node_id=node_id, digest=digest, healthy=bool(healthy))


def confirm_switch(connection, payload):
    for name in ("rollout_id", "node_id", "at"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    rollout_id, node_id, at = str(payload["rollout_id"]), str(payload["node_id"]), int(payload["at"])
    rollout = row(connection, "SELECT * FROM image_rollouts WHERE rollout_id=?", (rollout_id,))
    member = row(connection, "SELECT * FROM image_rollout_nodes WHERE rollout_id=? AND node_id=?",
                 (rollout_id, node_id))
    if not rollout or not member:
        return decision("rejected", "rollout node membership does not exist")
    if member["switch_status"] == "switched":
        return decision("switched", "switch already confirmed by independent probe",
                        rollout_id=rollout_id, node_id=node_id)
    if member["switch_status"] != "dispatched":
        return decision("blocked", "node has no dispatched switch to confirm",
                        switch_status=member["switch_status"])
    node = row(connection, "SELECT * FROM image_nodes WHERE node_id=?", (node_id,))
    probe = row(connection,
                "SELECT * FROM image_node_probes WHERE node_id=? AND independent=1 AND digest=? "
                "AND probed_at<=? ORDER BY probed_at DESC", (node_id, rollout["target_digest"], at))
    if not probe:
        return decision("pending", "independent probe has not observed the target digest on this node",
                        rollout_id=rollout_id, node_id=node_id, observed=node["running_digest"],
                        target_digest=rollout["target_digest"])
    connection.execute(
        "UPDATE image_rollout_nodes SET switch_status='switched',digest_at_dispatch=? "
        "WHERE rollout_id=? AND node_id=?",
        (rollout["target_digest"], rollout_id, node_id),
    )
    remaining = rows(connection,
                     "SELECT node_id FROM image_rollout_nodes WHERE rollout_id=? AND switch_status<>'switched'",
                     (rollout_id,))
    if not remaining:
        connection.execute("UPDATE image_rollouts SET status='complete' WHERE rollout_id=?", (rollout_id,))
        return decision("complete", "every node independently observed on the target digest",
                        rollout_id=rollout_id)
    return decision("switched", "node cutover confirmed by independent probe; other waves remain",
                    rollout_id=rollout_id, node_id=node_id,
                    remaining=[item["node_id"] for item in remaining])


def rollback_switch(connection, payload):
    for name in ("rollout_id", "node_id", "at"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    rollout_id, node_id, at = str(payload["rollout_id"]), str(payload["node_id"]), int(payload["at"])
    rollout = row(connection, "SELECT * FROM image_rollouts WHERE rollout_id=?", (rollout_id,))
    member = row(connection, "SELECT * FROM image_rollout_nodes WHERE rollout_id=? AND node_id=?",
                 (rollout_id, node_id))
    if not rollout or not member:
        return decision("rejected", "rollout node membership does not exist")
    if member["switch_status"] == "rolled_back":
        return decision("rolled_back", "fallback already confirmed; rollback not issued twice",
                        rollout_id=rollout_id, node_id=node_id)
    if member["switch_status"] not in ("dispatched", "switched"):
        return decision("blocked", "node has no dispatched or switched cutover to roll back",
                        switch_status=member["switch_status"])
    node = row(connection, "SELECT * FROM image_nodes WHERE node_id=?", (node_id,))
    probe = row(connection,
                "SELECT * FROM image_node_probes WHERE node_id=? AND independent=1 AND digest=? "
                "AND probed_at<=? ORDER BY probed_at DESC",
                (node_id, rollout["fallback_digest"], at))
    if not probe:
        return decision("pending", "independent probe has not observed the fallback digest yet",
                        rollout_id=rollout_id, node_id=node_id, fallback_digest=rollout["fallback_digest"],
                        observed=node["running_digest"])
    connection.execute(
        "UPDATE image_rollout_nodes SET switch_status='rolled_back',digest_at_dispatch=? "
        "WHERE rollout_id=? AND node_id=?",
        (rollout["fallback_digest"], rollout_id, node_id),
    )
    connection.execute("UPDATE image_rollouts SET status='paused' WHERE rollout_id=?", (rollout_id,))
    return decision("rolled_back", "node independently observed back on the rollback point",
                    rollout_id=rollout_id, node_id=node_id,
                    fallback_digest=rollout["fallback_digest"])


def retire_digest(connection, payload):
    for name in ("image", "digest", "at"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    image, digest, at = str(payload["image"]), str(payload["digest"]), int(payload["at"])
    order_id = f"retire:{image}:{digest}:{at}"
    prior = row(connection, "SELECT * FROM image_orders WHERE order_id=?", (order_id,))
    if prior:
        return decision("retired", "retirement already recorded; replayed request issues nothing new",
                        image=image, digest=digest, replayed=True)
    nodes = rows(connection, "SELECT node_id,running_digest FROM image_nodes WHERE service=?", (image,))
    still_running = [node["node_id"] for node in nodes if node["running_digest"] == digest]
    if still_running:
        return decision("blocked", "digest still observed running on nodes; a tag move is not retirement",
                        digest=digest, nodes=still_running)
    # Switch-confirmation probes verified the *target* digest mid-cutover; they
    # are not absence evidence.  Require an independent probe recorded no earlier
    # than this retirement request, explicitly observing some other digest.
    checked = rows(connection,
                   "SELECT node_id FROM image_node_probes WHERE service=? AND independent=1 "
                   "AND digest<>? AND probed_at>=? GROUP BY node_id",
                   (image, digest, at))
    seen = {item["node_id"] for item in checked}
    missing = sorted({node["node_id"] for node in nodes} - seen)
    if missing:
        return decision("pending", "independent absence probe missing for at least one node",
                        digest=digest, missing=missing)
    connection.execute(
        "INSERT INTO image_orders(order_id,image,digest,order_type,reason,issued_at,related_permit) "
        "VALUES(?,?,?, 'recall',?,?,NULL)",
        (order_id, image, digest,
         "retirement confirmed by independent node absence probes", at),
    )
    return decision("retired", "old image proven gone from every node; recall order closes the ledger",
                    image=image, digest=digest)


def inspect_rollout(connection, payload):
    rollout_id = str(payload["rollout_id"])
    rollout = row(connection, "SELECT * FROM image_rollouts WHERE rollout_id=?", (rollout_id,))
    if not rollout:
        return decision("missing", "rollout does not exist")
    return decision("found", "durable rollout, node switch and probe evidence",
                    rollout=rollout,
                    nodes=rows(connection,
                               "SELECT * FROM image_rollout_nodes WHERE rollout_id=? ORDER BY wave,node_id",
                               (rollout_id,)),
                    probes=rows(connection,
                                "SELECT p.* FROM image_node_probes p JOIN image_rollout_nodes m "
                                "ON m.node_id=p.node_id WHERE m.rollout_id=? ORDER BY p.probed_at",
                                (rollout_id,)))


HANDLERS = {
    "register_node": register_node,
    "rollout": create_rollout,
    "switch": switch_node,
    "probe": report_node,
    "confirm": confirm_switch,
    "rollback": rollback_switch,
    "retire": retire_digest,
    "inspect": inspect_rollout,
}
