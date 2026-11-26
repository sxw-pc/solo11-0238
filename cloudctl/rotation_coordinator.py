"""Recoverable credential rotation across device keys, upstream trust and routing.

The coordinator turns the provisional envelope/activation ledger into an
executable rotation by joining three entities that must agree at every crash
point:

* **device-held keys** -- sealed envelopes are opened against the replica's
  current device generation; the effect is a two-phase command/receipt pair
  (``issue_activation`` / ``activation_receipt``). A sent command is never
  treated as effective until its receipt is validated, so a power loss between
  dispatch and acknowledgement cannot confuse "sent" with "applied".
* **upstream authenticator trust** -- key trust changes use the same
  command/receipt split (``issue_trust`` / ``trust_receipt``) and an
  append-only :class:`key_trust_ledger`, giving a verifiable dual-key overlap
  interval or an isolation proof.
* **traffic routing membership** -- the append-only :class:`routing_ledger`
  records which replicas actually serve traffic. Routing changes are local
  control-plane decisions (single durable step, not remote commands) and are
  fenced by the serving quorum: no change may leave fewer than
  ``min_serving`` healthy replicas holding an upstream-trusted key.

Every ledger is append-only: issued activations, trust changes, routing moves
and revocation receipts are never rewritten. Recovery after a failed receipt
continues under the original command and physical key identity. Only key
identities and material digests are stored -- key material never reaches this
module, the event log, the audit report or any output.
"""

from .db import DecisionError, decision, require, row, rows
from .secret_activation import append_activation

ACTIVATION_TABLES = ("rotations", "rotation_commands", "key_trust_ledger",
                     "activation_ledger", "routing_ledger")


# ---------------------------------------------------------------------------
# Read models
# ---------------------------------------------------------------------------

def _rotation(connection, rotation_id):
    found = row(connection, "SELECT * FROM rotations WHERE rotation_id=?", (rotation_id,))
    if not found:
        raise DecisionError("rotation does not exist")
    return found


def _active_rotation(connection, service, namespace):
    return row(
        connection,
        "SELECT * FROM rotations WHERE service=? AND namespace=? AND status='active' "
        "ORDER BY created_at DESC, rowid DESC LIMIT 1",
        (service, namespace),
    )


def trusted_keys(connection, rotation_id):
    """Current upstream-trusted key set, replayed from append-only evidence."""
    trusted = set()
    for entry in rows(connection,
                      "SELECT key_id,change FROM key_trust_ledger WHERE rotation_id=? ORDER BY id",
                      (rotation_id,)):
        if entry["change"] == "trust":
            trusted.add(entry["key_id"])
        else:
            trusted.discard(entry["key_id"])
    return trusted


def _was_revoked(connection, rotation_id, key_id):
    """An explicit revoke entry can never be undone by a late activation."""
    return row(
        connection,
        "SELECT 1 AS hit FROM key_trust_ledger WHERE rotation_id=? AND key_id=? "
        "AND change='revoke' LIMIT 1",
        (rotation_id, key_id),
    ) is not None


def held_key(connection, rotation_id, replica_id):
    found = row(
        connection,
        "SELECT key_id FROM activation_ledger WHERE rotation_id=? AND replica_id=? "
        "ORDER BY id DESC LIMIT 1",
        (rotation_id, replica_id),
    )
    return found["key_id"] if found else None


def routing_members(connection, rotation_id):
    """Latest routing action per replica."""
    members = {}
    for entry in rows(connection,
                      "SELECT replica_id,action FROM routing_ledger WHERE rotation_id=? ORDER BY id",
                      (rotation_id,)):
        members[entry["replica_id"]] = entry["action"]
    return members


def serving_members(connection, service, namespace):
    """Replicas currently serving traffic under the active rotation, or all
    registered healthy replicas when no rotation is active (neutral default)."""
    rotation = _active_rotation(connection, service, namespace)
    if not rotation:
        return [item["replica_id"] for item in rows(
            connection,
            "SELECT replica_id FROM inventories WHERE service=? AND namespace=? ORDER BY replica_id",
            (service, namespace))]
    return sorted(replica for replica, action in
                  routing_members(connection, rotation["rotation_id"]).items()
                  if action == "serve")


def frozen_serving_count(connection, service, namespace):
    """Serving replicas whose activation command is in flight (sent, not yet
    acknowledged): they cannot be counted as safely serviceable."""
    rotation = _active_rotation(connection, service, namespace)
    if not rotation:
        return 0
    serving = set(serving_members(connection, service, namespace))
    if not serving:
        return 0
    return row(
        connection,
        "SELECT COUNT(DISTINCT c.replica_id) AS n FROM rotation_commands c "
        "WHERE c.rotation_id=? AND c.kind='activate' AND c.status='sent' "
        "AND c.replica_id IN (%s)" % ",".join("?" for _ in serving),
        (rotation["rotation_id"], *serving),
    )["n"]


def serving_healthy_count(connection, service, namespace):
    """Healthy replicas inside the active rotation's routing membership. With
    no active rotation this is the plain healthy inventory count, keeping the
    original repair budget unchanged."""
    rotation = _active_rotation(connection, service, namespace)
    if not rotation:
        return row(
            connection,
            "SELECT COUNT(*) AS n FROM inventories WHERE service=? AND healthy=1",
            (service,),
        )["n"]
    serving = set(serving_members(connection, service, namespace))
    if not serving:
        return 0
    placeholders = ",".join("?" for _ in serving)
    return row(
        connection,
        f"SELECT COUNT(*) AS n FROM inventories WHERE service=? AND namespace=? "
        f"AND healthy=1 AND replica_id IN ({placeholders})",
        (service, namespace, *serving),
    )["n"]


def _view(connection, rotation):
    rotation_id = rotation["rotation_id"]
    trusted = trusted_keys(connection, rotation_id)
    members = routing_members(connection, rotation_id)
    inventories = {item["replica_id"]: item for item in rows(
        connection, "SELECT * FROM inventories WHERE service=? AND namespace=?",
        (rotation["service"], rotation["namespace"]))}
    replica_ids = sorted(set(members) | set(inventories))
    replicas = []
    for replica_id in replica_ids:
        inventory = inventories.get(replica_id)
        key = held_key(connection, rotation_id, replica_id)
        route = members.get(replica_id)
        replicas.append({
            "replica_id": replica_id,
            "route": route,
            "healthy": bool(inventory and inventory["healthy"]),
            "generation": inventory["generation"] if inventory else None,
            "held_key": key,
            "held_key_trusted": key in trusted if key else False,
        })
    serving = [item for item in replicas if item["route"] == "serve"]
    ready = [item["replica_id"] for item in serving if item["held_key_trusted"]]
    new_trust = row(connection,
                    "SELECT MIN(at) AS at FROM key_trust_ledger WHERE rotation_id=? "
                    "AND key_id=? AND change='trust'",
                    (rotation_id, rotation["new_key_id"]))
    return {
        "trusted_keys": sorted(trusted),
        "serving": [item["replica_id"] for item in serving],
        "isolated": [item["replica_id"] for item in replicas if item["route"] == "isolate"],
        "ready_serving": ready,
        "ready_count": len(ready),
        "min_serving": rotation["min_serving"],
        "old_key": rotation["old_key_id"],
        "new_key": rotation["new_key_id"],
        "new_key_trusted_at": new_trust["at"] if new_trust else None,
        "replicas": replicas,
    }


def _deadline_guard(connection, rotation, at):
    """Once a leak is suspected, no state transition may leave the old key
    trusted past the authorized latest revocation instant."""
    if not rotation["suspected_compromise"] or rotation["status"] != "active":
        return None
    if int(at) <= int(rotation["revoke_deadline"]):
        return None
    if rotation["old_key_id"] in trusted_keys(connection, rotation["rotation_id"]):
        return decision(
            "blocked", "rotation passed revocation deadline while old key remains trusted",
            rotation_id=rotation["rotation_id"], revoke_deadline=rotation["revoke_deadline"], at=int(at))
    return None


def _command(connection, command_id):
    found = row(connection, "SELECT * FROM rotation_commands WHERE id=?", (command_id,))
    if not found:
        raise DecisionError("rotation command does not exist")
    return found


# ---------------------------------------------------------------------------
# Rotation lifecycle
# ---------------------------------------------------------------------------

def prepare(connection, payload):
    require(payload, "rotation_id", "service", "namespace", "old_key_id",
            "new_key_id", "min_serving", "revoke_deadline", "at")
    rotation_id = str(payload["rotation_id"])
    existing = row(connection, "SELECT * FROM rotations WHERE rotation_id=?", (rotation_id,))
    if existing:
        identity = (existing["service"], existing["namespace"], existing["old_key_id"],
                    existing["new_key_id"], existing["min_serving"],
                    existing["revoke_deadline"])
        if identity != (str(payload["service"]), str(payload["namespace"]),
                        str(payload["old_key_id"]), str(payload["new_key_id"]),
                        int(payload["min_serving"]), int(payload["revoke_deadline"])):
            raise DecisionError("rotation_id reused with different scope")
        return decision("active", "rotation already prepared", rotation_id=rotation_id)
    if _active_rotation(connection, str(payload["service"]), str(payload["namespace"])):
        return decision("blocked", "another rotation already owns this service")
    min_serving = int(payload["min_serving"])
    if min_serving < 1:
        return decision("blocked", "min_serving must be positive", min_serving=min_serving)
    if int(payload["revoke_deadline"]) <= int(payload["at"]):
        return decision("blocked", "revocation deadline must be in the future")
    seeded = rows(connection,
                  "SELECT * FROM inventories WHERE service=? AND namespace=? ORDER BY replica_id",
                  (str(payload["service"]), str(payload["namespace"])))
    if sum(int(item["healthy"]) for item in seeded) < min_serving:
        return decision("blocked", "not enough healthy replicas to start a rotation",
                        healthy=sum(int(item["healthy"]) for item in seeded),
                        min_serving=min_serving)
    connection.execute(
        "INSERT INTO rotations(rotation_id,service,namespace,old_key_id,new_key_id,"
        "min_serving,revoke_deadline,suspected_compromise,status,created_at) "
        "VALUES (?,?,?,?,?,?,?,?,'active',?)",
        (rotation_id, str(payload["service"]), str(payload["namespace"]),
         str(payload["old_key_id"]), str(payload["new_key_id"]), min_serving,
         int(payload["revoke_deadline"]), int(bool(payload.get("suspected_compromise", False))),
         int(payload["at"])),
    )
    # Upstream currently recognizes the old key: seed the immutable trust ledger.
    connection.execute(
        "INSERT INTO key_trust_ledger(rotation_id,key_id,change,at,command_id) "
        "VALUES (?,?, 'trust', ?, ?)",
        (rotation_id, str(payload["old_key_id"]), int(payload["at"]),
         f"{rotation_id}:seed:trust:{str(payload['old_key_id'])}"),
    )
    # Current routing membership and existing old-key holdings are evidence,
    # not commands: seed both append-only ledgers.
    for inventory in seeded:
        connection.execute(
            "INSERT INTO routing_ledger(rotation_id,replica_id,action,at,command_id) "
            "VALUES (?,?,'serve',?,?)",
            (rotation_id, inventory["replica_id"], int(payload["at"]),
             f"{rotation_id}:seed:route:{inventory['replica_id']}"),
        )
        connection.execute(
            "INSERT INTO activation_ledger(rotation_id,replica_id,key_id,generation,at,"
            "source,command_id) VALUES (?,?,?,?,?, 'seed', ?)",
            (rotation_id, inventory["replica_id"], str(payload["old_key_id"]),
             inventory["generation"], int(payload["at"]),
             f"{rotation_id}:seed:hold:{inventory['replica_id']}"),
        )
    return decision("prepared",
                    "rotation bounded by serving quorum and revocation deadline",
                    rotation_id=rotation_id,
                    serving=[item["replica_id"] for item in seeded],
                    revoke_deadline=int(payload["revoke_deadline"]),
                    min_serving=min_serving)


def deliver(connection, payload):
    """Record an offline-delivered sealed envelope. Only the material digest is
    stored; raw key material never enters an event, report or output."""
    require(payload, "rotation_id", "bundle", "replica_id", "key_id",
            "digest", "generation", "at")
    rotation = _rotation(connection, str(payload["rotation_id"]))
    key_id = str(payload["key_id"])
    if key_id not in (rotation["old_key_id"], rotation["new_key_id"]):
        return decision("blocked", "envelope key is not part of this rotation", key_id=key_id)
    deadline = _deadline_guard(connection, rotation, payload["at"])
    if deadline:
        return deadline
    connection.execute(
        "CREATE TABLE IF NOT EXISTS secret_envelopes ("
        "bundle TEXT PRIMARY KEY, replica TEXT, key_id TEXT, digest TEXT, generation INTEGER)")
    bundle = str(payload["bundle"])
    replica_id = str(payload["replica_id"])
    generation = int(payload["generation"])
    digest = str(payload["digest"])
    old = row(connection, "SELECT replica,key_id,digest,generation FROM secret_envelopes "
                          "WHERE bundle=?", (bundle,))
    if old:
        if (old["replica"], old["key_id"], old["digest"], old["generation"]) != \
                (replica_id, key_id, digest, generation):
            raise DecisionError("envelope_conflict")
        return decision("replayed", "same sealed envelope bytes already captured",
                        bundle=bundle, replica_id=replica_id, key_id=key_id,
                        digest=digest)
    connection.execute(
        "INSERT INTO secret_envelopes(bundle,replica,key_id,digest,generation) "
        "VALUES (?,?,?,?,?)", (bundle, replica_id, key_id, digest, generation))
    return decision("delivered", "sealed envelope captured for the declared device generation",
                    bundle=bundle, replica_id=replica_id, key_id=key_id,
                    generation=generation, digest=digest)


# ---------------------------------------------------------------------------
# Device activation: command / receipt split
# ---------------------------------------------------------------------------

def _envelope_for(connection, rotation, replica_id, bundle=None):
    if bundle:
        found = row(connection,
                    "SELECT bundle,replica,key_id,digest,generation FROM secret_envelopes "
                    "WHERE bundle=?", (str(bundle),))
        if not found:
            return None, decision("blocked", "sealed envelope was never delivered",
                                  bundle=str(bundle))
        if found["replica"] != replica_id:
            return None, decision("blocked",
                                  "envelope is sealed for another replica and cannot be opened",
                                  bundle=str(bundle), sealed_for=found["replica"],
                                  replica_id=replica_id)
        return found, None
    found = row(connection,
                "SELECT bundle,replica,key_id,digest,generation FROM secret_envelopes "
                "WHERE replica=? AND key_id=? ORDER BY rowid DESC LIMIT 1",
                (replica_id, rotation["new_key_id"]))
    if not found:
        return None, decision("blocked", "replica has no envelope for the new key",
                              replica_id=replica_id, key_id=rotation["new_key_id"])
    return found, None


def issue_activation(connection, payload):
    require(payload, "rotation_id", "replica_id", "at")
    rotation = _rotation(connection, str(payload["rotation_id"]))
    replica_id = str(payload["replica_id"])
    deadline = _deadline_guard(connection, rotation, payload["at"])
    if deadline:
        return deadline
    inventory = row(connection, "SELECT * FROM inventories WHERE replica_id=?", (replica_id,))
    if not inventory:
        return decision("blocked", "replica is not registered", replica_id=replica_id)
    envelope, blocked = _envelope_for(connection, rotation, replica_id, payload.get("bundle"))
    if blocked:
        return blocked
    if int(envelope["generation"]) != int(inventory["generation"]):
        return decision("blocked",
                        "envelope generation does not match current device generation",
                        replica_id=replica_id, sealed_generation=envelope["generation"],
                        current_generation=inventory["generation"])
    command_id = f"{rotation['rotation_id']}:activate:{replica_id}"
    prior = row(connection, "SELECT * FROM rotation_commands WHERE id=?", (command_id,))
    if prior:
        if prior["key_id"] != envelope["key_id"]:
            return decision("blocked",
                            "recovery must continue under the original physical key identity",
                            command_id=command_id, original_key=prior["key_id"],
                            requested_key=envelope["key_id"])
        if prior["status"] == "acked":
            return decision("activated", "activation already acknowledged",
                            command_id=command_id, replica_id=replica_id,
                            key_id=envelope["key_id"])
        if prior["status"] == "sent":
            return decision("in_flight", "activation command sent; no receipt yet",
                            command_id=command_id, replica_id=replica_id,
                            key_id=envelope["key_id"])
        # failed: recovery reuses the same command and key identity.
        connection.execute(
            "UPDATE rotation_commands SET status='sent', detail=?, updated_at=? WHERE id=?",
            ("resent after failed receipt along original key identity",
             int(payload["at"]), command_id))
        return decision("resent", "failed activation retried under the same key identity",
                        command_id=command_id, replica_id=replica_id,
                        key_id=envelope["key_id"])
    connection.execute(
        "INSERT INTO rotation_commands(id,rotation_id,kind,replica_id,key_id,status,"
        "detail,created_at,updated_at) VALUES (?,?, 'activate', ?, ?, 'sent', ?, ?, ?)",
        (command_id, rotation["rotation_id"], replica_id, envelope["key_id"],
         "sealed envelope opened; awaiting device receipt",
         int(payload["at"]), int(payload["at"])))
    return decision("sent", "activation command issued; effectiveness waits for receipt",
                    command_id=command_id, replica_id=replica_id,
                    key_id=envelope["key_id"], generation=envelope["generation"])


def activation_receipt(connection, payload):
    require(payload, "rotation_id", "command_id", "generation", "at", "success")
    rotation = _rotation(connection, str(payload["rotation_id"]))
    command = _command(connection, str(payload["command_id"]))
    if command["rotation_id"] != rotation["rotation_id"] or command["kind"] != "activate":
        return decision("blocked", "receipt does not match an activation command of this rotation",
                        command_id=command["id"])
    if command["status"] == "acked":
        return decision("activated", "activation already acknowledged",
                        command_id=command["id"], replica_id=command["replica_id"],
                        key_id=command["key_id"])
    if command["status"] == "failed" and not bool(payload["success"]):
        return decision("failed", "failure receipt already recorded",
                        command_id=command["id"], replica_id=command["replica_id"])
    if command["status"] != "sent":
        return decision("blocked", "command is not awaiting a receipt",
                        command_id=command["id"], command_status=command["status"])
    inventory = row(connection, "SELECT * FROM inventories WHERE replica_id=?",
                    (command["replica_id"],))
    valid_generation = inventory is not None and \
        int(inventory["generation"]) == int(payload["generation"]) == \
        int(_command_detail_generation(connection, command))
    success = bool(payload["success"]) and valid_generation
    if success and _was_revoked(connection, rotation["rotation_id"], command["key_id"]):
        # A late receipt must never re-establish a revoked / leaked key. A key
        # that is merely not trusted *yet* is still installable: that pre-loading
        # is what creates the verifiable dual-key overlap window.
        success = False
        failure_reason = "key was revoked by the upstream authenticator and cannot be re-opened"
    else:
        failure_reason = "receipt or device generation mismatch"
    if not success:
        connection.execute(
            "UPDATE rotation_commands SET status='failed', detail=?, updated_at=? WHERE id=?",
            (failure_reason, int(payload["at"]), command["id"]))
        return decision("failed", "activation receipt rejected; command must be retried",
                        command_id=command["id"], replica_id=command["replica_id"],
                        key_id=command["key_id"], failure_reason=failure_reason)
    connection.execute(
        "INSERT INTO activation_ledger(rotation_id,replica_id,key_id,generation,at,"
        "source,command_id) VALUES (?,?,?,?,?, 'receipt', ?)",
        (rotation["rotation_id"], command["replica_id"], command["key_id"],
         int(payload["generation"]), int(payload["at"]), command["id"]))
    append_activation(connection, command["replica_id"], command["key_id"],
                      int(payload["generation"]), int(payload["at"]), "receipt",
                      command["id"])
    connection.execute(
        "UPDATE rotation_commands SET status='acked', detail=?, updated_at=? WHERE id=?",
        ("device receipt and generation verified", int(payload["at"]), command["id"]))
    return decision("activated", "device holds the new key under its current generation",
                    command_id=command["id"], replica_id=command["replica_id"],
                    key_id=command["key_id"])


def _command_detail_generation(connection, command):
    envelope = row(connection,
                   "SELECT generation FROM secret_envelopes WHERE replica=? AND key_id=? "
                   "ORDER BY rowid DESC LIMIT 1",
                   (command["replica_id"], command["key_id"]))
    return envelope["generation"] if envelope else -1


# ---------------------------------------------------------------------------
# Upstream trust: command / receipt split with overlap / isolation proof
# ---------------------------------------------------------------------------

def _revocation_proof(connection, rotation, at):
    """The old key may only be revoked when every traffic-serving healthy
    replica already holds an upstream-trusted key and the serving quorum holds.
    Returns a proof dict, or a blocked decision."""
    view = _view(connection, rotation)
    serving = [item for item in view["replicas"] if item["route"] == "serve"]
    unready = [item["replica_id"] for item in serving if not item["held_key_trusted"]
               or item["held_key"] == rotation["old_key_id"]]
    overlap = view["new_key_trusted_at"] is not None and \
        view["new_key_trusted_at"] <= int(at) and \
        rotation["old_key_id"] in view["trusted_keys"]
    proof = {
        "serving": view["serving"],
        "isolated": view["isolated"],
        "ready_serving": view["ready_serving"],
        "ready_count": view["ready_count"],
        "min_serving": view["min_serving"],
        "overlap": overlap,
        "new_key_trusted_at": view["new_key_trusted_at"],
    }
    if unready:
        return None, decision("blocked",
                              "traffic-serving replicas still rely on the old key; isolate or activate them",
                              rotation_id=rotation["rotation_id"], unready=unready, proof=proof)
    if view["ready_count"] < rotation["min_serving"]:
        return None, decision("blocked",
                              "revocation would leave fewer than the authorized serving quorum",
                              rotation_id=rotation["rotation_id"], proof=proof)
    if not overlap:
        return None, decision("blocked",
                              "no verifiable dual-key overlap: new key is not yet upstream trusted",
                              rotation_id=rotation["rotation_id"], proof=proof)
    return proof, None


def issue_trust(connection, payload):
    require(payload, "rotation_id", "key_id", "change", "at")
    rotation = _rotation(connection, str(payload["rotation_id"]))
    key_id, change = str(payload["key_id"]), str(payload["change"])
    if change not in ("trust", "revoke"):
        raise DecisionError("trust change must be 'trust' or 'revoke'")
    if key_id not in (rotation["old_key_id"], rotation["new_key_id"]):
        return decision("blocked", "key is not part of this rotation", key_id=key_id)
    deadline = _deadline_guard(connection, rotation, payload["at"])
    if deadline:
        return deadline
    trusted = trusted_keys(connection, rotation["rotation_id"])
    if change == "trust" and key_id in trusted:
        return decision("trusted", "key is already upstream trusted", key_id=key_id)
    if change == "revoke" and key_id not in trusted:
        return decision("revoked", "key is already outside the upstream trusted set", key_id=key_id)
    if change == "revoke" and key_id == rotation["old_key_id"]:
        _, blocked = _revocation_proof(connection, rotation, payload["at"])
        if blocked:
            return blocked
    command_id = f"{rotation['rotation_id']}:trust:{key_id}:{change}"
    prior = row(connection, "SELECT * FROM rotation_commands WHERE id=?", (command_id,))
    if prior:
        if prior["status"] == "sent":
            return decision("in_flight", "trust command sent; no authenticator receipt yet",
                            command_id=command_id, key_id=key_id, change=change)
        if prior["status"] == "acked":
            return decision("effective", "trust change already acknowledged",
                            command_id=command_id, key_id=key_id, change=change)
    connection.execute(
        "INSERT INTO rotation_commands(id,rotation_id,kind,replica_id,key_id,status,"
        "detail,created_at,updated_at) VALUES (?,?, 'trust', NULL, ?, 'sent', ?, ?, ?)",
        (command_id, rotation["rotation_id"], key_id,
         f"awaiting upstream authenticator receipt for {change}",
         int(payload["at"]), int(payload["at"])))
    return decision("sent", "upstream trust command issued; effectiveness waits for receipt",
                    command_id=command_id, key_id=key_id, change=change)


def trust_receipt(connection, payload):
    require(payload, "rotation_id", "command_id", "at", "success")
    rotation = _rotation(connection, str(payload["rotation_id"]))
    command = _command(connection, str(payload["command_id"]))
    if command["rotation_id"] != rotation["rotation_id"] or command["kind"] != "trust":
        return decision("blocked", "receipt does not match a trust command of this rotation",
                        command_id=command["id"])
    if command["status"] == "acked":
        return decision("effective", "trust change already acknowledged",
                        command_id=command["id"], key_id=command["key_id"])
    if command["status"] != "sent":
        return decision("blocked", "command is not awaiting a receipt",
                        command_id=command["id"], command_status=command["status"])
    if not bool(payload["success"]):
        connection.execute(
            "UPDATE rotation_commands SET status='failed', detail=?, updated_at=? WHERE id=?",
            ("upstream authenticator rejected the trust change",
             int(payload["at"]), command["id"]))
        return decision("failed", "upstream rejected the trust change; nothing was trusted",
                        command_id=command["id"], key_id=command["key_id"])
    change = "revoke" if command["id"].endswith(":revoke") else "trust"
    connection.execute(
        "INSERT INTO key_trust_ledger(rotation_id,key_id,change,at,command_id) "
        "VALUES (?,?,?,?,?)",
        (rotation["rotation_id"], command["key_id"], change,
         int(payload["at"]), command["id"]))
    connection.execute(
        "UPDATE rotation_commands SET status='acked', detail=?, updated_at=? WHERE id=?",
        ("upstream authenticator receipt recorded", int(payload["at"]), command["id"]))
    status = "revoked" if change == "revoke" else "trusted"
    if change == "revoke" and command["key_id"] == rotation["old_key_id"]:
        connection.execute("UPDATE rotations SET status='completed' WHERE rotation_id=?",
                           (rotation["rotation_id"],))
        status = "revoked"
    return decision(status, "upstream trust ledger updated from authenticator receipt",
                    command_id=command["id"], key_id=command["key_id"],
                    trusted_keys=sorted(trusted_keys(connection, rotation["rotation_id"])))


# ---------------------------------------------------------------------------
# Routing membership: local, durable, quorum-fenced
# ---------------------------------------------------------------------------

def route(connection, payload):
    require(payload, "rotation_id", "replica_id", "action", "at")
    rotation = _rotation(connection, str(payload["rotation_id"]))
    replica_id, action = str(payload["replica_id"]), str(payload["action"])
    if action not in ("serve", "isolate"):
        raise DecisionError("routing action must be 'serve' or 'isolate'")
    deadline = _deadline_guard(connection, rotation, payload["at"])
    if deadline:
        return deadline
    members = routing_members(connection, rotation["rotation_id"])
    if members.get(replica_id) == action:
        return decision("unchanged", "replica already has this routing state",
                        replica_id=replica_id, action=action)
    inventory = row(connection, "SELECT * FROM inventories WHERE replica_id=?", (replica_id,))
    if not inventory:
        return decision("blocked", "replica is not registered", replica_id=replica_id)
    if action == "serve":
        if not int(inventory["healthy"]):
            return decision("blocked", "unhealthy replica cannot join traffic routing",
                            replica_id=replica_id)
        key = held_key(connection, rotation["rotation_id"], replica_id)
        if not key or key not in trusted_keys(connection, rotation["rotation_id"]):
            return decision("blocked",
                            "replica cannot serve without a key the upstream authenticator recognizes",
                            replica_id=replica_id, held_key=key)
    # Project the post-change serving set and enforce the availability quorum.
    projected = dict(members)
    projected[replica_id] = action
    trusted = trusted_keys(connection, rotation["rotation_id"])
    ready = 0
    for member_id, member_action in projected.items():
        if member_action != "serve":
            continue
        member_inventory = row(connection, "SELECT healthy FROM inventories WHERE replica_id=?",
                               (member_id,))
        member_key = held_key(connection, rotation["rotation_id"], member_id)
        if member_inventory and int(member_inventory["healthy"]) \
                and member_key and member_key in trusted:
            ready += 1
    if ready < rotation["min_serving"]:
        return decision("blocked",
                        "routing change would break the minimum serving quorum",
                        replica_id=replica_id, action=action,
                        ready_after=ready, min_serving=rotation["min_serving"])
    connection.execute(
        "INSERT INTO routing_ledger(rotation_id,replica_id,action,at,command_id) "
        "VALUES (?,?,?,?,NULL)",
        (rotation["rotation_id"], replica_id, action, int(payload["at"])))
    return decision("routed", "traffic membership updated under the serving quorum",
                    replica_id=replica_id, action=action,
                    serving=sorted(r for r, a in projected.items() if a == "serve"),
                    isolated=sorted(r for r, a in projected.items() if a == "isolate"))


def inspect(connection, payload):
    require(payload, "rotation_id")
    rotation = _rotation(connection, str(payload["rotation_id"]))
    return decision("found", "rotation posture and immutable evidence",
                    rotation=rotation, proof=_view(connection, rotation),
                    commands=rows(connection,
                                  "SELECT id,kind,replica_id,key_id,status,detail,created_at,"
                                  "updated_at FROM rotation_commands WHERE rotation_id=? ORDER BY id",
                                  (rotation["rotation_id"],)),
                    trust_ledger=rows(connection,
                                      "SELECT key_id,change,at,command_id FROM key_trust_ledger "
                                      "WHERE rotation_id=? ORDER BY id",
                                      (rotation["rotation_id"],)),
                    routing_ledger=rows(connection,
                                        "SELECT replica_id,action,at FROM routing_ledger "
                                        "WHERE rotation_id=? ORDER BY id",
                                        (rotation["rotation_id"],)))


HANDLERS = {"prepare": prepare, "deliver": deliver,
            "issue_activation": issue_activation, "activation_receipt": activation_receipt,
            "issue_trust": issue_trust, "trust_receipt": trust_receipt,
            "route": route, "inspect": inspect}
