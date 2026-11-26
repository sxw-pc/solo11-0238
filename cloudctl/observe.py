"""Replica identity, event-time observations, drift and bounded exceptions."""

from .db import canonical, decision, row, rows
from .policy import (
    active_pin,
    anchor_context,
    ensure_node,
    hierarchical_drift,
    parse_value,
    target,
    value_digest,
)


def register(connection, payload):
    replica_id = str(payload["replica_id"])
    generation = int(payload["generation"])
    cluster = payload.get("cluster")
    cluster = str(cluster) if cluster not in (None, "") else ""
    existing = row(connection, "SELECT * FROM inventories WHERE replica_id=?", (replica_id,))
    if existing and generation < existing["generation"]:
        return decision("rejected", "older replica generation cannot replace current inventory",
                        current_generation=existing["generation"])
    if existing and generation == existing["generation"]:
        if (existing["service"], existing["namespace"]) != (payload["service"], payload["namespace"]):
            return decision("rejected", "same generation changed immutable identity")
        if cluster and existing["cluster"] and cluster != existing["cluster"]:
            return decision("rejected", "same generation changed cluster identity")
        connection.execute("UPDATE inventories SET healthy=? WHERE replica_id=?",
                           (int(bool(payload.get("healthy", True))), replica_id))
        return decision("registered", "existing replica generation refreshed", replica_id=replica_id)
    if cluster:
        ensure_node(connection, f"cluster:{cluster}", "cluster", cluster)
    if existing:
        connection.execute(
            "UPDATE inventories SET service=?,namespace=?,generation=?,healthy=?,policy_id=NULL,"
            "revision=NULL,value=NULL,observed_at=0,drift='unknown',drift_reason='new replica generation',"
            "cluster=?,target_uid=NULL,observed_digest=NULL,observed_vector=NULL WHERE replica_id=?",
            (payload["service"], payload["namespace"], generation,
             int(bool(payload.get("healthy", True))), cluster, replica_id),
        )
    else:
        connection.execute(
            "INSERT INTO inventories(replica_id,service,namespace,generation,healthy,cluster) "
            "VALUES(?,?,?,?,?,?)",
            (replica_id, payload["service"], payload["namespace"], generation,
             int(bool(payload.get("healthy", True))), cluster),
        )
    result = decision("registered", "replica identity available for observation",
                      replica_id=replica_id, generation=generation)
    if cluster:
        result["cluster"] = cluster
    return result


def active_exception(connection, replica_id, policy_id, policy_revision, at):
    if not policy_id:
        return None
    return row(connection,
               "SELECT * FROM exceptions WHERE replica_id=? AND policy_id=? AND policy_revision=? "
               "AND status='active' AND expires_at>? ORDER BY expires_at DESC LIMIT 1",
               (replica_id, policy_id, policy_revision, at))


def _vector_claim(payload):
    vector = payload.get("vector", payload.get("revision_vector"))
    if isinstance(vector, str):
        try:
            vector = __import__("json").loads(vector)
        except ValueError:
            vector = None
    return vector if isinstance(vector, dict) else None


def classify(connection, inventory, policy_id, revision, value, at,
             digest_claim=None, vector_claim=None):
    desired = target(connection, inventory)
    if desired is None:
        return "no_target", "no active policy matches this replica", None
    if desired.get("kind") == "hierarchical":
        digest_claim = digest_claim or (value_digest(value) if value is not None else None)
        base, reason = hierarchical_drift(desired, policy_id, revision, value,
                                         digest_claim, vector_claim)
        exception = active_exception(connection, inventory["replica_id"], desired["policy_id"],
                                     desired["revision"], at)
        if exception and base != "converged":
            return ("excepted",
                    f"{base}: approved exception {exception['id']} expires {exception['expires_at']}",
                    desired)
        return base, reason, desired
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
    raw_value = payload.get("value")
    stored_value = canonical(raw_value) if isinstance(raw_value, (dict, list)) else raw_value
    vector_claim = _vector_claim(payload)
    digest_claim = payload.get("digest")
    if digest_claim is None and isinstance(raw_value, (dict, list)):
        digest_claim = value_digest(raw_value)
    target_uid_claim = payload.get("target_uid")
    healthy = payload.get("healthy")
    if generation != inventory["generation"]:
        status, drift, reason, desired = "stale_generation", "historical", "old replica generation", None
    elif observed_at <= inventory["observed_at"]:
        status, drift, reason, desired = "stale_time", "historical", "late observation cannot replace current state", None
    else:
        drift, reason, desired = classify(
            connection, inventory, payload.get("policy_id"), revision, raw_value, observed_at,
            digest_claim=digest_claim, vector_claim=vector_claim)
        status = "accepted"
    bound_uid = desired["target_uid"] if desired and desired.get("kind") == "hierarchical" else target_uid_claim
    connection.execute(
        "INSERT INTO observations(id,replica_id,generation,observed_at,received_at,policy_id,"
        "revision,value,origin,status,drift,reason,target_uid,digest,vector_json) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (observation_id, replica_id, generation, observed_at, received_at,
         payload.get("policy_id"), revision, stored_value, str(payload.get("origin", "agent")),
         status, drift, reason, bound_uid, digest_claim,
         canonical(vector_claim) if vector_claim is not None else None),
    )
    if status == "accepted":
        connection.execute(
            "UPDATE inventories SET policy_id=?,revision=?,value=?,observed_at=?,drift=?,drift_reason=?,"
            "target_uid=?,observed_digest=?,observed_vector=? WHERE replica_id=?",
            (payload.get("policy_id"), revision, stored_value, observed_at, drift, reason,
             bound_uid, digest_claim,
             canonical(vector_claim) if vector_claim is not None else None, replica_id),
        )
        if healthy is not None:
            connection.execute("UPDATE inventories SET healthy=? WHERE replica_id=?",
                               (int(bool(healthy)), replica_id))
    return decision(status, reason, observation_id=observation_id, drift=drift,
                    target=desired, replica_id=replica_id)


def grant_exception(connection, payload):
    replica_id = str(payload["replica_id"])
    inventory = row(connection, "SELECT * FROM inventories WHERE replica_id=?", (replica_id,))
    if not inventory:
        return decision("rejected", "replica is not registered")
    desired = target(connection, inventory)
    allowed_policy = bool(desired) and (
        desired["policy_id"] == payload["policy_id"]
        or (desired.get("kind") == "hierarchical"
            and payload["policy_id"] in (desired.get("vector") or {})))
    if not desired or not allowed_policy:
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


def record_health(connection, payload):
    cluster = str(payload.get("cluster") or payload.get("cluster_name") or "")
    namespace = str(payload.get("namespace") or "")
    service = str(payload["service"])
    at = int(payload["at"])
    minimum = int(payload.get("min_healthy", 0) or 0)
    total = payload.get("total_count", payload.get("total"))
    healthy_count = int(payload["healthy_count"])
    if total is None:
        total = row(connection,
                    "SELECT COUNT(*) AS n FROM inventories WHERE service=? "
                    "AND (?='' OR cluster=?) AND (?='' OR namespace=?)",
                    (service, cluster, cluster, namespace, namespace))["n"]
    total = int(total)
    sample_id = str(payload.get("sample_id") or payload.get("health_id")
                    or payload.get("id") or f"health:{cluster}:{namespace}:{service}:{at}")
    if row(connection, "SELECT id FROM health_samples WHERE id=?", (sample_id,)):
        return decision("duplicate", "health sample already recorded", sample_id=sample_id)
    connection.execute(
        "INSERT INTO health_samples(id,cluster,namespace,service,at,healthy_count,total_count,"
        "min_healthy,source) VALUES(?,?,?,?,?,?,?,?,?)",
        (sample_id, cluster, namespace, service, at, healthy_count, total, minimum,
         str(payload.get("source", "agent"))),
    )
    if payload.get("sync_replicas", False):
        healthy_ids = set(payload.get("healthy_replica_ids", []))
        for replica in rows(connection, "SELECT replica_id FROM inventories WHERE service=? "
                            "AND (?='' OR cluster=?)", (service, cluster, cluster)):
            connection.execute("UPDATE inventories SET healthy=? WHERE replica_id=?",
                               (1 if replica["replica_id"] in healthy_ids else 0,
                                replica["replica_id"]))
    return decision("recorded", "cluster-local health evidence stored", sample_id=sample_id,
                    cluster=cluster, healthy_count=healthy_count, total_count=total)


def health_window(connection, payload):
    from .policy import evaluate_health_window
    cluster = str(payload.get("cluster") or payload.get("cluster_name") or "")
    namespace = str(payload.get("namespace") or "")
    service = str(payload["service"])
    minimum = int(payload["min_healthy"])
    at = int(payload.get("at", 0) or 0)
    window = int(payload.get("window_minutes", payload.get("window", 0)) or 0)
    health = evaluate_health_window(connection, cluster, namespace, service, minimum, at, window)
    status = "satisfied" if health["window_satisfied"] else "blocked"
    return decision(status, "cluster-local min_healthy and observation window", **health)


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
            "expire": expire_exceptions, "inspect": inspect,
            "health": record_health, "heartbeat": record_health,
            "health_check": record_health, "sample": record_health,
            "window": health_window, "health_window": health_window}
