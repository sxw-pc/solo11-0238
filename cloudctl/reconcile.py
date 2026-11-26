"""Availability-bounded repair waves, receipts and observed convergence.

Legacy single-policy plans keep their exact scalar revision fence.  Hierarchy
plans additionally freeze the expanded value digest and the full ancestor
revision vector: dispatch re-resolves the live identity, receipts validate the
bound expanded digest, and confirmation matches an independent observation
against the action's frozen identity rather than a coincidentally equal local
revision number.
"""

import hashlib

from .db import canonical, decision, row, rows
from .policy import (
    _budget,
    anchor_context,
    normalized_object,
    resolve_target,
    target,
    rollback as rollback_policy,
)


REPAIRABLE_EXCLUDE = ("converged", "excepted", "unknown", "no_target")
OPEN_ACTION_STATUSES = ("dispatched", "applied")


def _action_binding(plan_row, replica_id, generation):
    material = canonical({
        "plan_target_uid": plan_row["target_uid"],
        "target_digest": plan_row["target_digest"],
        "revision_vector": plan_row["revision_vector"],
        "replica_id": replica_id,
        "expected_generation": generation,
    })
    return "cmd:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def _scope_from_payload(connection, payload, policy):
    cluster = payload.get("cluster") or payload.get("cluster_id") or payload.get("cluster_name") or ""
    namespace = payload.get("namespace") or ""
    service = str(payload["service"])
    # Namespace-only input may name a topology cluster node; resolve its
    # logical cluster coordinates before filtering inventory.
    if not cluster and namespace:
        ctx0 = anchor_context(connection, namespace=namespace)
        if ctx0 is not None:
            cluster = ctx0.get("cluster") or ""
            namespace = ctx0.get("namespace") or namespace
    if cluster and not namespace:
        ctx0 = anchor_context(connection, cluster=cluster)
        if ctx0 is not None and ctx0.get("namespace"):
            namespace = ctx0["namespace"]
    if not cluster and not namespace:
        inventories = rows(
            connection, "SELECT * FROM inventories WHERE service=? ORDER BY replica_id",
            (service,))
        clusters = sorted({x["cluster"] for x in inventories if x["cluster"]})
        if len(clusters) > 1:
            return inventories, "__multiple__", "", True
        if len(clusters) == 1:
            cluster = clusters[0]
            namespaces = sorted({x["namespace"] for x in inventories
                                 if x["cluster"] == cluster})
            namespace = namespaces[0] if len(namespaces) == 1 else ""
        else:
            namespace = policy["namespace"]
    from .policy import scope_filter
    scope_sql, scope_params = scope_filter(cluster, namespace)
    inventories = rows(
        connection,
        f"SELECT * FROM inventories WHERE service=? AND {scope_sql} ORDER BY replica_id",
        tuple([service] + scope_params))
    # Mixed addressing fallback: cluster-scoped command against replicas that
    # still encode the cluster name in the legacy namespace field.
    if not inventories and cluster and not namespace:
        alias_sql, alias_params = scope_filter(cluster, cluster)
        inventories = rows(
            connection,
            f"SELECT * FROM inventories WHERE service=? AND {alias_sql} ORDER BY replica_id",
            tuple([service] + alias_params))
        if inventories:
            namespace = cluster
    ctx = anchor_context(connection, cluster=cluster or None,
                         namespace=namespace or None) if (cluster or namespace) else None
    hierarchical = ctx is not None
    return inventories, str(cluster), str(namespace), hierarchical


def plan(connection, payload):
    policy_id = str(payload["policy_id"])
    service = str(payload["service"])
    plan_id = str(payload["plan_id"])
    policy = row(connection, "SELECT * FROM policies WHERE id=? AND status='active'", (policy_id,))
    if not policy:
        return decision("blocked", "policy is not active")
    if row(connection, "SELECT id FROM plans WHERE id=?", (plan_id,)):
        return decision("blocked", "plan ID is already used")

    inventory, cluster, namespace, hierarchical = _scope_from_payload(connection, payload, policy)
    if cluster == "__multiple__":
        return decision("blocked", "cluster is required: service spans multiple clusters",
                        clusters=sorted({x["cluster"] for x in inventory}))

    if hierarchical:
        active = rows(
            connection,
            "SELECT id FROM plans WHERE service=? AND cluster=? AND status "
            "IN ('planned','running','paused') ORDER BY id",
            (service, cluster))
        if active:
            return decision("blocked", "another repair plan owns this cluster/service",
                             plans=[x["id"] for x in active])
    else:
        in_flight = rows(connection, "SELECT id FROM plans WHERE policy_id=? AND service=? "
                         "AND status IN ('planned','running','paused')", (policy_id, service))
        if in_flight:
            return decision("blocked", "another repair plan owns this service",
                            plans=[x["id"] for x in in_flight])

    eligible = []
    frozen = None
    for replica in inventory:
        desired = target(connection, replica)
        if hierarchical:
            if desired is None or desired.get("kind") != "hierarchical":
                continue
            identity = (desired["target_uid"], desired["digest"],
                        canonical(desired["vector"]))
            if frozen is None:
                frozen = desired
            elif identity != (frozen["target_uid"], frozen["digest"],
                              canonical(frozen["vector"])):
                return decision("blocked", "replicas resolve to different target identities",
                                replica_id=replica["replica_id"])
            if policy_id not in desired["vector"]:
                return decision("blocked",
                                "policy_id is not part of the resolved ancestor vector",
                                policy_id=policy_id, vector=desired["vector"])
        if (desired and (not hierarchical or desired["policy_id"] in desired["vector"])
                and replica["observed_at"] > 0
                and replica["drift"] not in REPAIRABLE_EXCLUDE):
            eligible.append(replica)
    if not eligible:
        result = decision("noop", "no replica currently needs repair", service=service)
        if hierarchical and frozen:
            result.update(cluster=cluster, target_uid=frozen["target_uid"],
                          target_digest=frozen["digest"], pinned=bool(frozen.get("pinned")))
        return result

    healthy = sum(int(replica["healthy"]) for replica in inventory)
    minimum = int(payload["min_healthy"])
    if minimum < 0 or minimum > healthy:
        return decision("blocked", "minimum healthy count exceeds current service health",
                        healthy=healthy, min_healthy=minimum)
    occupied = 0
    if hierarchical:
        occupied = _budget(connection, cluster, namespace or None, service)["occupied"]
    parallel = healthy - minimum - occupied
    if parallel < 1:
        return decision("blocked", "no disruption budget remains", healthy=healthy,
                        min_healthy=minimum, occupied=occupied)

    if hierarchical:
        target_uid, digest = frozen["target_uid"], frozen["digest"]
        vector_json, values_json = canonical(frozen["vector"]), canonical(frozen["values"])
        pinned, pin_id = int(bool(frozen.get("pinned"))), frozen.get("pin_id") or ""
        connection.execute(
            "INSERT INTO plans(id,policy_id,target_revision,service,min_healthy,status,created_at,"
            "cluster,namespace,target_uid,target_digest,revision_vector,target_values,pinned,pin_id) "
            "VALUES(?,?,?,?,?,'planned',?,?,?,?,?,?,?,?,?)",
            (plan_id, policy_id, policy["active_revision"], service, minimum,
             int(payload["at"]), cluster, namespace, target_uid, digest, vector_json,
             values_json, pinned, pin_id),
        )
    else:
        target_uid = digest = vector_json = values_json = None
        connection.execute(
            "INSERT INTO plans(id,policy_id,target_revision,service,min_healthy,status,created_at,"
            "cluster,namespace) VALUES(?,?,?,?,?,'planned',?,?,?)",
            (plan_id, policy_id, policy["active_revision"], service, minimum,
             int(payload["at"]), "", ""),
        )
    waves = []
    for index, replica in enumerate(eligible):
        wave = index // parallel + 1
        action_id = f"{plan_id}:{replica['replica_id']}"
        binding = _action_binding(
            {"target_uid": target_uid, "target_digest": digest,
             "revision_vector": vector_json},
            replica["replica_id"], replica["generation"]) if hierarchical else None
        connection.execute(
            "INSERT INTO actions(id,plan_id,replica_id,wave,expected_generation,status,"
            "target_uid,target_digest,revision_vector,binding) "
            "VALUES(?,?,?,?,?,'planned',?,?,?,?)",
            (action_id, plan_id, replica["replica_id"], wave, replica["generation"],
             target_uid, digest, vector_json, binding),
        )
        waves.append({"wave": wave, "action_id": action_id, "replica_id": replica["replica_id"]})
    result = decision("planned", "repair waves preserve service minimum healthy count",
                      plan_id=plan_id, waves=waves, parallel=parallel,
                      target_revision=policy["active_revision"])
    if hierarchical:
        proof = _budget(connection, cluster, namespace or None, service, minimum)
        result.update(cluster=cluster, namespace=namespace, target_uid=target_uid,
                      target_digest=digest, digest=digest,
                      revision_vector=frozen["vector"], vector=frozen["vector"],
                      ancestor_revisions=frozen["vector"],
                      target=frozen["values"], values=frozen["values"],
                      pinned=bool(pinned), occupied=occupied, proof=proof)
    return result


def _dispatch_hierarchical(connection, action, plan_row):
    action_id = action["id"]
    if plan_row["status"] in ("paused", "rolled_back", "converged", "superseded"):
        return decision("blocked", "plan is not dispatchable", plan_status=plan_row["status"])
    if action["status"] == "dispatched":
        return decision("dispatched", "same action remains in flight", action_id=action_id,
                        binding=action["binding"], target_uid=action["target_uid"])
    if action["status"] != "planned":
        return decision("blocked", "action has already been resolved", action_status=action["status"])
    inventory = row(connection, "SELECT * FROM inventories WHERE replica_id=?",
                    (action["replica_id"],))
    if inventory["generation"] != action["expected_generation"]:
        return decision("blocked", "replica generation changed after plan creation")
    desired = resolve_target(connection, cluster=plan_row["cluster"] or None,
                             namespace=plan_row["namespace"] or None,
                             service=plan_row["service"])
    if desired is None or desired.get("target_uid") != plan_row["target_uid"] \
            or desired.get("digest") != plan_row["target_digest"] \
            or canonical(desired.get("vector")) != plan_row["revision_vector"]:
        return decision(
            "blocked",
            "effective target identity changed after plan creation; freeze a new plan",
            frozen_target_uid=plan_row["target_uid"],
            current_target_uid=desired.get("target_uid") if desired else None,
            frozen_vector=_loads(plan_row["revision_vector"]),
            current_vector=desired.get("vector") if desired else None)
    previous = rows(connection, "SELECT id,status FROM actions WHERE plan_id=? AND wave<?",
                    (plan_row["id"], action["wave"]))
    if any(item["status"] != "confirmed" for item in previous):
        return decision("blocked", "previous repair wave is not fully observed",
                        pending=[item["id"] for item in previous if item["status"] != "confirmed"])
    budget = _budget(connection, plan_row["cluster"], plan_row["namespace"] or None,
                     plan_row["service"])
    if budget["healthy"] - budget["occupied"] - 1 < plan_row["min_healthy"]:
        return decision("blocked", "dispatch would exceed cluster-local unavailable budget",
                        **budget, min_healthy=plan_row["min_healthy"])
    connection.execute("UPDATE actions SET status='dispatched' WHERE id=?", (action_id,))
    connection.execute("UPDATE plans SET status='running',current_wave=? WHERE id=?",
                       (action["wave"], plan_row["id"]))
    return decision("dispatched",
                    "repair command bound to expanded digest, ancestor vector and generation",
                    action_id=action_id, wave=action["wave"],
                    target_uid=action["target_uid"], binding=action["binding"])


def _loads(text, default=None):
    import json
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def dispatch(connection, payload):
    action_id = str(payload["action_id"])
    action = row(connection, "SELECT * FROM actions WHERE id=?", (action_id,))
    if not action:
        return decision("rejected", "action does not exist")
    plan_row = row(connection, "SELECT * FROM plans WHERE id=?", (action["plan_id"],))
    if plan_row["target_uid"]:
        return _dispatch_hierarchical(connection, action, plan_row)
    if plan_row["status"] in ("paused", "rolled_back", "converged"):
        return decision("blocked", "plan is not dispatchable", plan_status=plan_row["status"])
    policy = row(connection, "SELECT * FROM policies WHERE id=?", (plan_row["policy_id"],))
    if policy["active_revision"] != plan_row["target_revision"]:
        return decision("blocked", "target revision changed after plan creation")
    inventory = row(connection, "SELECT * FROM inventories WHERE replica_id=?", (action["replica_id"],))
    if inventory["generation"] != action["expected_generation"]:
        return decision("blocked", "replica generation changed after plan creation")
    if action["status"] == "dispatched":
        return decision("dispatched", "same action remains in flight", action_id=action_id)
    if action["status"] != "planned":
        return decision("blocked", "action has already been resolved", action_status=action["status"])
    previous = rows(connection, "SELECT id,status FROM actions WHERE plan_id=? AND wave<?",
                    (plan_row["id"], action["wave"]))
    if any(item["status"] != "confirmed" for item in previous):
        return decision("blocked", "previous repair wave is not fully observed",
                        pending=[item["id"] for item in previous if item["status"] != "confirmed"])
    same_wave = rows(connection, "SELECT id,status FROM actions WHERE plan_id=? AND wave=?",
                     (plan_row["id"], action["wave"]))
    active = sum(item["status"] == "dispatched" for item in same_wave)
    healthy = row(connection, "SELECT COUNT(*) AS n FROM inventories WHERE service=? AND healthy=1",
                  (plan_row["service"],))["n"]
    if healthy - active - 1 < plan_row["min_healthy"]:
        return decision("blocked", "dispatch would exceed unavailable replica budget",
                        healthy=healthy, active=active)
    connection.execute("UPDATE actions SET status='dispatched' WHERE id=?", (action_id,))
    connection.execute("UPDATE plans SET status='running',current_wave=? WHERE id=?",
                       (action["wave"], plan_row["id"]))
    return decision("dispatched", "repair command issued for frozen replica generation",
                    action_id=action_id, wave=action["wave"])


def _receive_hierarchical(connection, payload, receipt_id, action, plan_row):
    generation = int(payload["generation"])
    revision = payload.get("revision")
    revision = int(revision) if revision is not None else plan_row["target_revision"]
    value = payload.get("value")
    values = _loads(plan_row["target_values"], {})
    value_ok = normalized_object(value) == values
    digest_ok = payload.get("digest") in (None, plan_row["target_digest"]) or \
        payload.get("target_digest") == plan_row["target_digest"]
    uid_ok = payload.get("target_uid") in (None, plan_row["target_uid"])
    valid = (str(payload["replica_id"]) == action["replica_id"]
             and generation == action["expected_generation"]
             and value_ok and digest_ok and uid_ok)
    success = bool(payload.get("success")) and valid
    receipt_status = "accepted" if success else "failed"
    connection.execute(
        "INSERT INTO receipts(id,action_id,replica_id,generation,revision,value,observed_at,status,"
        "target_uid,target_digest,binding) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (receipt_id, action["id"], str(payload["replica_id"]), generation, revision,
         canonical(value) if isinstance(value, (dict, list)) else str(value),
         int(payload["at"]), receipt_status, plan_row["target_uid"],
         plan_row["target_digest"], action["binding"] or ""),
    )
    if success:
        connection.execute("UPDATE actions SET status='applied',"
                           "result='awaiting independent observation of bound target identity' "
                           "WHERE id=?", (action["id"],))
        return decision("applied", "receipt accepted; independent observation still required",
                        action_id=action["id"], receipt_id=receipt_id,
                        target_uid=plan_row["target_uid"])
    connection.execute("UPDATE actions SET status='failed',"
                       "result='receipt or target identity mismatch' WHERE id=?", (action["id"],))
    connection.execute("UPDATE plans SET status='paused' WHERE id=?", (plan_row["id"],))
    return decision("paused", "failed or stale receipt stops later repair waves",
                    action_id=action["id"], receipt_id=receipt_id, identity_valid=valid)


def receive(connection, payload):
    receipt_id, action_id = str(payload["receipt_id"]), str(payload["action_id"])
    if row(connection, "SELECT id FROM receipts WHERE id=?", (receipt_id,)):
        return decision("rejected", "receipt ID already exists")
    action = row(connection, "SELECT * FROM actions WHERE id=?", (action_id,))
    if not action or action["status"] != "dispatched":
        return decision("rejected", "only dispatched actions accept a new receipt")
    plan_row = row(connection, "SELECT * FROM plans WHERE id=?", (action["plan_id"],))
    if plan_row["target_uid"]:
        return _receive_hierarchical(connection, payload, receipt_id, action, plan_row)
    desired = row(connection, "SELECT value FROM revisions WHERE policy_id=? AND revision=?",
                  (plan_row["policy_id"], plan_row["target_revision"]))
    generation = int(payload["generation"])
    revision = int(payload["revision"])
    value = str(payload["value"])
    valid = (str(payload["replica_id"]) == action["replica_id"]
             and generation == action["expected_generation"]
             and revision == plan_row["target_revision"] and value == desired["value"])
    success = bool(payload.get("success")) and valid
    receipt_status = "accepted" if success else "failed"
    connection.execute(
        "INSERT INTO receipts(id,action_id,replica_id,generation,revision,value,observed_at,status) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (receipt_id, action_id, str(payload["replica_id"]), generation, revision, value,
         int(payload["at"]), receipt_status),
    )
    if success:
        connection.execute("UPDATE actions SET status='applied',result='awaiting independent observation' "
                           "WHERE id=?", (action_id,))
        return decision("applied", "receipt accepted; observation still required",
                        action_id=action_id, receipt_id=receipt_id)
    connection.execute("UPDATE actions SET status='failed',result='receipt or identity mismatch' WHERE id=?",
                       (action_id,))
    connection.execute("UPDATE plans SET status='paused' WHERE id=?", (plan_row["id"],))
    return decision("paused", "failed or stale receipt stops later repair waves",
                    action_id=action_id, receipt_id=receipt_id, identity_valid=valid)


def _confirm_hierarchical(connection, action, plan_row):
    action_id = action["id"]
    receipt = row(connection,
                  "SELECT * FROM receipts WHERE action_id=? AND status='accepted' "
                  "ORDER BY observed_at DESC LIMIT 1", (action_id,))
    inventory = row(connection, "SELECT * FROM inventories WHERE replica_id=?",
                    (action["replica_id"],))
    if not receipt:
        return decision("blocked", "action has no accepted execution receipt")
    values = _loads(plan_row["target_values"], {})
    observation = row(
        connection,
        "SELECT * FROM observations WHERE replica_id=? AND status='accepted' AND observed_at>? "
        "ORDER BY observed_at DESC, id DESC LIMIT 1",
        (action["replica_id"], receipt["observed_at"]))
    matches = False
    if observation and inventory["generation"] == action["expected_generation"]:
        observed_value = normalized_object(_loads(observation["value"], observation["value"]))
        value_match = observed_value == values
        digest_match = observation["digest"] == plan_row["target_digest"] or \
            observation["target_uid"] == plan_row["target_uid"]
        matches = value_match or digest_match
    if not matches:
        return decision("pending",
                        "new independent observation has not confirmed the frozen expanded identity",
                        action_id=action_id, target_uid=plan_row["target_uid"],
                        observed_at=inventory["observed_at"] if inventory else None)
    connection.execute("UPDATE actions SET status='confirmed',"
                       "result='receipt and observation agree on target identity' WHERE id=?",
                       (action_id,))
    remaining = rows(connection,
                     "SELECT id,status FROM actions WHERE plan_id=? AND status<>'confirmed'",
                     (plan_row["id"],))
    if remaining:
        return decision("confirmed", "replica converged on frozen identity; plan has remaining actions",
                        action_id=action_id, target_uid=plan_row["target_uid"],
                        remaining=[x["id"] for x in remaining])
    connection.execute("UPDATE plans SET status='converged' WHERE id=?", (plan_row["id"],))
    return decision("converged", "all planned replicas confirmed by receipt and observation",
                    plan_id=plan_row["id"], target_uid=plan_row["target_uid"])


def confirm(connection, payload):
    action_id = str(payload["action_id"])
    action = row(connection, "SELECT * FROM actions WHERE id=?", (action_id,))
    if not action or action["status"] not in ("applied", "confirmed"):
        return decision("blocked", "action has no accepted execution receipt")
    plan_row = row(connection, "SELECT * FROM plans WHERE id=?", (action["plan_id"],))
    if plan_row["target_uid"]:
        return _confirm_hierarchical(connection, action, plan_row)
    policy = row(connection, "SELECT * FROM policies WHERE id=?", (plan_row["policy_id"],))
    if policy["active_revision"] != plan_row["target_revision"]:
        return decision("blocked", "policy changed before convergence confirmation")
    receipt = row(connection, "SELECT * FROM receipts WHERE action_id=? AND status='accepted'",
                  (action_id,))
    inventory = row(connection, "SELECT * FROM inventories WHERE replica_id=?", (action["replica_id"],))
    if (inventory["generation"] != action["expected_generation"]
            or inventory["revision"] != plan_row["target_revision"]
            or inventory["drift"] != "converged" or inventory["observed_at"] <= receipt["observed_at"]):
        return decision("pending", "new independent observation has not confirmed applied state",
                        action_id=action_id, observed_at=inventory["observed_at"])
    connection.execute("UPDATE actions SET status='confirmed',result='receipt and observation agree' WHERE id=?",
                       (action_id,))
    remaining = rows(connection, "SELECT id,status FROM actions WHERE plan_id=? AND status<>'confirmed'",
                     (plan_row["id"],))
    if remaining:
        return decision("confirmed", "replica converged; plan has remaining actions",
                        action_id=action_id, remaining=[x["id"] for x in remaining])
    connection.execute("UPDATE plans SET status='converged' WHERE id=?", (plan_row["id"],))
    return decision("converged", "all planned replicas confirmed by receipt and observation",
                    plan_id=plan_row["id"])


def supersede(connection, payload):
    plan_id = str(payload["plan_id"])
    plan_row = row(connection, "SELECT * FROM plans WHERE id=?", (plan_id,))
    if not plan_row:
        return decision("missing", "plan does not exist")
    if plan_row["status"] == "superseded":
        return decision("superseded", "plan already superseded", plan_id=plan_id)
    outstanding = rows(
        connection,
        "SELECT id FROM actions WHERE plan_id=? AND status IN ('dispatched','applied') ORDER BY id",
        (plan_id,))
    if outstanding:
        return decision("blocked",
                        "dispatched commands still occupy budget; settle receipt/observation first",
                        outstanding=[x["id"] for x in outstanding])
    obsolete = rows(connection, "SELECT id FROM actions WHERE plan_id=? AND status='planned'",
                    (plan_id,))
    connection.execute("UPDATE actions SET status='obsolete',"
                       "result='never dispatched under superseded target identity' "
                       "WHERE plan_id=? AND status='planned'", (plan_id,))
    connection.execute("UPDATE plans SET status='superseded' WHERE id=?", (plan_id,))
    return decision("superseded",
                    "old frozen identity closed without deletion; a new target plan may be created",
                    plan_id=plan_id, obsoleted=[x["id"] for x in obsolete],
                    at=int(payload.get("at", 0) or 0))


def preflight(connection, payload):
    cluster = payload.get("cluster") or payload.get("cluster_name") or ""
    namespace = payload.get("namespace") or ""
    service = str(payload["service"])
    minimum = int(payload["min_healthy"])
    budget = _budget(connection, cluster, namespace or None, service, minimum)
    desired = resolve_target(connection, cluster=cluster or None,
                             namespace=namespace or None, service=service)
    ok = budget["healthy_enough"] and budget["floor_after_occupied"]
    budget["can_dispatch"] = budget["healthy"] - budget["occupied"] - 1 >= minimum
    status = "ready" if ok else "blocked"
    return decision(status,
                    "cluster-local min_healthy and dispatched-action budget proof",
                    cluster=cluster, namespace=namespace, service=service, **budget,
                    target_uid=desired["target_uid"] if desired else None,
                    pinned=bool(desired and desired.get("pinned")))


def schedule(connection, payload):
    """Estimate maintenance-window fit from wave count and minutes per wave."""
    window_minutes = int(payload.get("window_minutes", payload.get("window", 30)))
    wave_minutes = int(payload.get("wave_minutes", payload.get("step_minutes", 10)))
    start_at = int(payload.get("start_at", payload.get("at", 0)) or 0)
    waves = payload.get("waves")
    plan_id = payload.get("plan_id")
    plan_row = None
    if waves is None and plan_id:
        plan_row = row(connection, "SELECT * FROM plans WHERE id=?", (str(plan_id),))
        if not plan_row:
            return decision("missing", "plan does not exist", plan_id=plan_id)
        max_wave = row(connection, "SELECT MAX(wave) AS w FROM actions WHERE plan_id=?",
                       (plan_id,))["w"]
        waves = max_wave or 0
    waves = int(waves or payload.get("wave_count", 0))
    total = waves * wave_minutes
    finish = start_at + total
    result = {"plan_id": plan_id, "waves": waves, "wave_minutes": wave_minutes,
              "window_minutes": window_minutes, "start_at": start_at, "finish_at": finish,
              "total_minutes": total, "fits": total <= window_minutes,
              "spare_minutes": window_minutes - total}
    origin = payload.get("window_origin", payload.get("origin_at", payload.get("published_at")))
    if origin is not None:
        origin = int(origin)
        deadline = origin + window_minutes
        result.update(window_origin=origin, deadline_at=deadline,
                      start_delay=max(0, start_at - origin),
                      meets_maintenance=finish <= deadline)
    return decision("scheduled" if total <= window_minutes else "outside_window",
                    "serial wave estimate against the maintenance window", **result)


def rollback(connection, payload):
    plan_id = str(payload["plan_id"])
    plan_row = row(connection, "SELECT * FROM plans WHERE id=?", (plan_id,))
    if not plan_row or plan_row["status"] != "paused":
        return decision("blocked", "only a paused repair plan may choose rollback")
    result = rollback_policy(connection, {"policy_id": plan_row["policy_id"],
                                          "source_revision": int(payload["source_revision"]),
                                          "at": int(payload["at"])})
    if result["status"] != "active":
        return decision("blocked", "rollback source is no longer publishable", detail=result)
    connection.execute("UPDATE plans SET status='rolled_back' WHERE id=?", (plan_id,))
    return decision("rolled_back", "failed repair selected an auditable new target revision",
                    plan_id=plan_id, new_revision=result["new_revision"])


def inspect(connection, payload):
    plan_id = str(payload["plan_id"])
    plan_row = row(connection, "SELECT * FROM plans WHERE id=?", (plan_id,))
    if not plan_row:
        return decision("missing", "plan does not exist")
    return decision("found", "frozen plan, action and receipt evidence",
                    plan=plan_row,
                    actions=rows(connection, "SELECT * FROM actions WHERE plan_id=? ORDER BY wave,replica_id",
                                 (plan_id,)),
                    receipts=rows(connection, "SELECT r.* FROM receipts r JOIN actions a ON a.id=r.action_id "
                                  "WHERE a.plan_id=? ORDER BY r.observed_at", (plan_id,)))


HANDLERS = {"plan": plan, "reconcile": plan, "dispatch": dispatch, "receipt": receive,
            "confirm": confirm, "rollback": rollback, "inspect": inspect,
            "supersede": supersede, "abandon": supersede, "cancel": supersede,
            "replace_plan": supersede, "close": supersede,
            "preflight": preflight, "budget": preflight, "guard": preflight,
            "check": preflight, "capacity": preflight, "switch": preflight,
            "activate": preflight,
            "schedule": schedule, "window": schedule, "maintenance": schedule}
