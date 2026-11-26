"""Availability-bounded repair waves, receipts and observed convergence."""

from . import rotation_coordinator
from .db import decision, row, rows
from .policy import target, rollback as rollback_policy


def plan(connection, payload):
    policy_id = str(payload["policy_id"])
    service = str(payload["service"])
    plan_id = str(payload["plan_id"])
    policy = row(connection, "SELECT * FROM policies WHERE id=? AND status='active'", (policy_id,))
    if not policy:
        return decision("blocked", "policy is not active")
    if row(connection, "SELECT id FROM plans WHERE id=?", (plan_id,)):
        return decision("blocked", "plan ID is already used")
    in_flight = rows(connection, "SELECT id FROM plans WHERE policy_id=? AND service=? "
                     "AND status IN ('planned','running','paused')", (policy_id, service))
    if in_flight:
        return decision("blocked", "another repair plan owns this service", plans=[x["id"] for x in in_flight])
    inventory = rows(connection, "SELECT * FROM inventories WHERE service=? AND namespace=? ORDER BY replica_id",
                     (service, policy["namespace"]))
    # During a credential rotation, replicas isolated from traffic are not
    # repair-availability units, and only the routing membership serves.
    serving = set(rotation_coordinator.serving_members(connection, service, policy["namespace"]))
    inventory = [replica for replica in inventory
                 if not serving or replica["replica_id"] in serving]
    eligible = []
    for replica in inventory:
        desired = target(connection, replica)
        if (desired and desired["policy_id"] == policy_id and replica["observed_at"] > 0
                and replica["drift"] not in ("converged", "excepted", "unknown", "no_target")):
            eligible.append(replica)
    if not eligible:
        return decision("noop", "no replica currently needs repair", service=service)
    healthy = sum(int(replica["healthy"]) for replica in inventory)
    minimum = int(payload["min_healthy"])
    if minimum < 0 or minimum > healthy:
        return decision("blocked", "minimum healthy count exceeds current service health",
                        healthy=healthy, min_healthy=minimum)
    parallel = healthy - minimum
    if parallel < 1:
        return decision("blocked", "no disruption budget remains", healthy=healthy,
                        min_healthy=minimum)
    connection.execute(
        "INSERT INTO plans(id,policy_id,target_revision,service,min_healthy,status,created_at) "
        "VALUES(?,?,?,?,?,'planned',?)",
        (plan_id, policy_id, policy["active_revision"], service, minimum, int(payload["at"])),
    )
    waves = []
    for index, replica in enumerate(eligible):
        wave = index // parallel + 1
        action_id = f"{plan_id}:{replica['replica_id']}"
        connection.execute(
            "INSERT INTO actions(id,plan_id,replica_id,wave,expected_generation,status) "
            "VALUES(?,?,?,?,?,'planned')",
            (action_id, plan_id, replica["replica_id"], wave, replica["generation"]),
        )
        waves.append({"wave": wave, "action_id": action_id, "replica_id": replica["replica_id"]})
    return decision("planned", "repair waves preserve service minimum healthy count",
                    plan_id=plan_id, waves=waves, parallel=parallel, target_revision=policy["active_revision"])


def dispatch(connection, payload):
    action_id = str(payload["action_id"])
    action = row(connection, "SELECT * FROM actions WHERE id=?", (action_id,))
    if not action:
        return decision("rejected", "action does not exist")
    plan_row = row(connection, "SELECT * FROM plans WHERE id=?", (action["plan_id"],))
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
    healthy = rotation_coordinator.serving_healthy_count(
        connection, plan_row["service"], policy["namespace"])
    # A rotation in progress fences its routing membership: in-flight activation
    # commands do not yet count as effective keys, and isolated replicas are
    # outside the serving set.
    healthy -= rotation_coordinator.frozen_serving_count(
        connection, plan_row["service"], policy["namespace"])
    if healthy - active - 1 < plan_row["min_healthy"]:
        return decision("blocked", "dispatch would exceed unavailable replica budget",
                        healthy=healthy, active=active)
    connection.execute("UPDATE actions SET status='dispatched' WHERE id=?", (action_id,))
    connection.execute("UPDATE plans SET status='running',current_wave=? WHERE id=?",
                       (action["wave"], plan_row["id"]))
    return decision("dispatched", "repair command issued for frozen replica generation",
                    action_id=action_id, wave=action["wave"])


def receive(connection, payload):
    receipt_id, action_id = str(payload["receipt_id"]), str(payload["action_id"])
    if row(connection, "SELECT id FROM receipts WHERE id=?", (receipt_id,)):
        return decision("rejected", "receipt ID already exists")
    action = row(connection, "SELECT * FROM actions WHERE id=?", (action_id,))
    if not action or action["status"] != "dispatched":
        return decision("rejected", "only dispatched actions accept a new receipt")
    plan_row = row(connection, "SELECT * FROM plans WHERE id=?", (action["plan_id"],))
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


def confirm(connection, payload):
    action_id = str(payload["action_id"])
    action = row(connection, "SELECT * FROM actions WHERE id=?", (action_id,))
    if not action or action["status"] not in ("applied", "confirmed"):
        return decision("blocked", "action has no accepted execution receipt")
    plan_row = row(connection, "SELECT * FROM plans WHERE id=?", (action["plan_id"],))
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
            "confirm": confirm, "rollback": rollback, "inspect": inspect}
