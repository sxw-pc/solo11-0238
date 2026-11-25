"""Replica identity, event-time observations, drift and bounded exceptions."""

from .db import decision, row, rows
from .policy import target


def register(connection, payload):
    replica_id = str(payload["replica_id"])
    generation = int(payload["generation"])
    existing = row(connection, "SELECT * FROM inventories WHERE replica_id=?", (replica_id,))
    if existing and generation < existing["generation"]:
        return decision("rejected", "older replica generation cannot replace current inventory",
                        current_generation=existing["generation"])
    if existing and generation == existing["generation"]:
        if (existing["service"], existing["namespace"]) != (payload["service"], payload["namespace"]):
            return decision("rejected", "same generation changed immutable identity")
        connection.execute("UPDATE inventories SET healthy=? WHERE replica_id=?",
                           (int(bool(payload.get("healthy", True))), replica_id))
        return decision("registered", "existing replica generation refreshed", replica_id=replica_id)
    if existing:
        connection.execute(
            "UPDATE inventories SET service=?,namespace=?,generation=?,healthy=?,policy_id=NULL,"
            "revision=NULL,value=NULL,observed_at=0,drift='unknown',drift_reason='new replica generation' "
            "WHERE replica_id=?",
            (payload["service"], payload["namespace"], generation,
             int(bool(payload.get("healthy", True))), replica_id),
        )
    else:
        connection.execute(
            "INSERT INTO inventories(replica_id,service,namespace,generation,healthy) VALUES(?,?,?,?,?)",
            (replica_id, payload["service"], payload["namespace"], generation,
             int(bool(payload.get("healthy", True)))),
        )
    return decision("registered", "replica identity available for observation",
                    replica_id=replica_id, generation=generation)


def active_exception(connection, replica_id, policy_id, policy_revision, at):
    if not policy_id:
        return None
    return row(connection,
               "SELECT * FROM exceptions WHERE replica_id=? AND policy_id=? AND policy_revision=? "
               "AND status='active' AND expires_at>? ORDER BY expires_at DESC LIMIT 1",
               (replica_id, policy_id, policy_revision, at))


def classify(connection, inventory, policy_id, revision, value, at):
    desired = target(connection, inventory)
    if desired is None:
        return "no_target", "no active policy matches this replica", None
    if policy_id == desired["policy_id"] and revision == desired["revision"] and value == desired["value"]:
        return "converged", "observed revision and value match active target", desired
    if policy_id != desired["policy_id"]:
        base = "wrong_policy"
        reason = "observed policy identity differs from active target"
    elif revision == desired["revision"] and value != desired["value"]:
        base = "manual_override"
        reason = "same target revision has different actual value"
    elif revision is None or revision < desired["revision"]:
        base = "policy_changed"
        reason = "installed revision is behind active target"
    else:
        base = "future_revision"
        reason = "installed revision is ahead of active target"
    exception = active_exception(connection, inventory["replica_id"], desired["policy_id"],
                                 desired["revision"], at)
    if exception:
        return "excepted", f"{base}: approved exception {exception['id']} expires {exception['expires_at']}", desired
    return base, reason, desired


def observe(connection, payload):
    replica_id = str(payload["replica_id"])
    observation_id = str(payload["observation_id"])
    inventory = row(connection, "SELECT * FROM inventories WHERE replica_id=?", (replica_id,))
    if not inventory:
        return decision("rejected", "replica is not registered", replica_id=replica_id)
    if row(connection, "SELECT id FROM observations WHERE id=?", (observation_id,)):
        return decision("rejected", "observation ID already exists", observation_id=observation_id)
    generation = int(payload["generation"])
    observed_at, received_at = int(payload["observed_at"]), int(payload["received_at"])
    if received_at < observed_at:
        return decision("rejected", "receive time predates observed time")
    revision = payload.get("revision")
    revision = int(revision) if revision is not None else None
    value = payload.get("value")
    if generation != inventory["generation"]:
        status, drift, reason, desired = "stale_generation", "historical", "old replica generation", None
    elif observed_at <= inventory["observed_at"]:
        status, drift, reason, desired = "stale_time", "historical", "late observation cannot replace current state", None
    else:
        drift, reason, desired = classify(connection, inventory, payload.get("policy_id"),
                                           revision, value, observed_at)
        status = "accepted"
    connection.execute(
        "INSERT INTO observations(id,replica_id,generation,observed_at,received_at,policy_id,"
        "revision,value,origin,status,drift,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (observation_id, replica_id, generation, observed_at, received_at,
         payload.get("policy_id"), revision, value, str(payload.get("origin", "agent")),
         status, drift, reason),
    )
    if status == "accepted":
        connection.execute(
            "UPDATE inventories SET policy_id=?,revision=?,value=?,observed_at=?,drift=?,drift_reason=? "
            "WHERE replica_id=?",
            (payload.get("policy_id"), revision, value, observed_at, drift, reason, replica_id),
        )
    return decision(status, reason, observation_id=observation_id, drift=drift,
                    target=desired, replica_id=replica_id)


def grant_exception(connection, payload):
    replica_id = str(payload["replica_id"])
    inventory = row(connection, "SELECT * FROM inventories WHERE replica_id=?", (replica_id,))
    if not inventory:
        return decision("rejected", "replica is not registered")
    desired = target(connection, inventory)
    if not desired or desired["policy_id"] != payload["policy_id"]:
        return decision("rejected", "exception target must be current policy")
    if not str(payload.get("approved_by", "")).strip():
        return decision("rejected", "service owner approval is required")
    if int(payload["expires_at"]) <= int(payload["at"]):
        return decision("rejected", "exception expiry must be future")
    exception_id = str(payload["exception_id"])
    if row(connection, "SELECT id FROM exceptions WHERE id=?", (exception_id,)):
        return decision("rejected", "exception ID already exists")
    connection.execute(
        "INSERT INTO exceptions(id,replica_id,policy_id,policy_revision,approved_by,expires_at,status,reason) "
        "VALUES(?,?,?,?,?,?,'active',?)",
        (exception_id, replica_id, desired["policy_id"], desired["revision"], payload["approved_by"],
         int(payload["expires_at"]), str(payload.get("reason", "planned deviation"))),
    )
    drift, reason, _ = classify(connection, inventory, inventory["policy_id"], inventory["revision"],
                                inventory["value"], int(payload["at"]))
    connection.execute("UPDATE inventories SET drift=?,drift_reason=? WHERE replica_id=?",
                       (drift, reason, replica_id))
    return decision("approved", "time-bound drift exception changes repair eligibility",
                    exception_id=exception_id, drift=drift)


def expire_exceptions(connection, payload):
    at = int(payload["at"])
    expired = rows(connection, "SELECT id,replica_id FROM exceptions WHERE status='active' AND expires_at<=?",
                   (at,))
    connection.execute("UPDATE exceptions SET status='expired' WHERE status='active' AND expires_at<=?",
                       (at,))
    affected = set(item["replica_id"] for item in expired)
    decisions = {}
    for replica_id in affected:
        inventory = row(connection, "SELECT * FROM inventories WHERE replica_id=?", (replica_id,))
        drift, reason, _ = classify(connection, inventory, inventory["policy_id"],
                                    inventory["revision"], inventory["value"], at)
        connection.execute("UPDATE inventories SET drift=?,drift_reason=? WHERE replica_id=?",
                           (drift, reason, replica_id))
        decisions[replica_id] = drift
    return decision("expired", "expired exception no longer suppresses repair",
                    exception_ids=[x["id"] for x in expired], drift=decisions)


def inspect(connection, payload):
    replica_id = str(payload["replica_id"])
    inventory = row(connection, "SELECT * FROM inventories WHERE replica_id=?", (replica_id,))
    if not inventory:
        return decision("missing", "replica is not registered")
    desired = target(connection, inventory)
    return decision("observed", "current inventory and target",
                    inventory=inventory, target=desired,
                    observations=rows(connection, "SELECT * FROM observations WHERE replica_id=? ORDER BY observed_at",
                                      (replica_id,)))


HANDLERS = {"register": register, "observe": observe, "exception": grant_exception,
            "expire": expire_exceptions, "inspect": inspect}
