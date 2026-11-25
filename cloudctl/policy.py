"""Policy ownership, immutable revisions, publication and retirement."""

import json

from .db import DecisionError, decision, row, rows


def matching(connection, namespace, service):
    return rows(
        connection,
        "SELECT * FROM policies WHERE namespace=? AND scope IN (?, '*') "
        "AND status='active' ORDER BY CASE WHEN scope='*' THEN 1 ELSE 0 END, id",
        (namespace, service),
    )


def target(connection, inventory):
    candidates = matching(connection, inventory["namespace"], inventory["service"])
    if len(candidates) > 1:
        raise DecisionError("multiple active policies match the same replica")
    if not candidates:
        return None
    policy = candidates[0]
    revision = row(
        connection, "SELECT * FROM revisions WHERE policy_id=? AND revision=?",
        (policy["id"], policy["active_revision"]),
    )
    return {"policy_id": policy["id"], "revision": revision["revision"],
            "value": revision["value"], "generation": policy["generation"]}


def create(connection, payload):
    policy_id = str(payload["policy_id"])
    if row(connection, "SELECT id FROM policies WHERE id=?", (policy_id,)):
        return decision("rejected", "policy already exists", policy_id=policy_id)
    namespace = str(payload["namespace"])
    scope = str(payload["scope"])
    owner = str(payload["owner"])
    connection.execute(
        "INSERT INTO policies(id,namespace,scope,owner) VALUES(?,?,?,?)",
        (policy_id, namespace, scope, owner),
    )
    return decision("created", "draft policy registered", policy_id=policy_id,
                    namespace=namespace, scope=scope, owner=owner)


def draft(connection, payload):
    policy_id = str(payload["policy_id"])
    policy = row(connection, "SELECT * FROM policies WHERE id=?", (policy_id,))
    if not policy or policy["status"] == "retired":
        return decision("rejected", "policy missing or retired", policy_id=policy_id)
    revision = int(payload["revision"])
    if row(connection, "SELECT revision FROM revisions WHERE policy_id=? AND revision=?",
           (policy_id, revision)):
        return decision("rejected", "revision is immutable", policy_id=policy_id, revision=revision)
    largest = row(connection, "SELECT MAX(revision) AS n FROM revisions WHERE policy_id=?", (policy_id,))["n"]
    if revision <= (largest or 0):
        return decision("rejected", "revision must increase", last_revision=largest)
    dependencies = list(payload.get("dependencies", []))
    if len(set(dependencies)) != len(dependencies):
        return decision("rejected", "duplicate dependencies")
    value = str(payload["value"])
    connection.execute(
        "INSERT INTO revisions(policy_id,revision,value,dependencies,status,created_at) "
        "VALUES(?,?,?,?,?,?)",
        (policy_id, revision, value, json.dumps(dependencies), "draft", int(payload["at"])),
    )
    return decision("drafted", "immutable revision stored", policy_id=policy_id, revision=revision)


def _cycle(connection, policy_id, dependencies):
    graph = {}
    for revision in rows(connection, "SELECT policy_id,dependencies FROM revisions WHERE status='active'"):
        graph[revision["policy_id"]] = json.loads(revision["dependencies"])
    graph[policy_id] = dependencies
    visiting, visited = set(), set()

    def visit(node):
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for child in graph.get(node, []):
            if visit(child):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return visit(policy_id)


def publish(connection, payload):
    policy_id, revision = str(payload["policy_id"]), int(payload["revision"])
    policy = row(connection, "SELECT * FROM policies WHERE id=?", (policy_id,))
    proposed = row(connection, "SELECT * FROM revisions WHERE policy_id=? AND revision=?",
                   (policy_id, revision))
    if not policy or not proposed or policy["status"] == "retired":
        return decision("blocked", "no publishable policy revision", policy_id=policy_id)
    if proposed["status"] == "active" and policy["active_revision"] == revision:
        return decision("active", "revision already active", policy_id=policy_id, revision=revision)
    if proposed["status"] != "draft":
        return decision("blocked", "only draft revisions can publish", revision=revision)
    dependencies = json.loads(proposed["dependencies"])
    inactive = [name for name in dependencies if not row(
        connection, "SELECT id FROM policies WHERE id=? AND status='active'", (name,))]
    if inactive:
        return decision("blocked", "dependency is not active", dependencies=inactive)
    if _cycle(connection, policy_id, dependencies):
        return decision("blocked", "dependency cycle", dependencies=dependencies)
    conflicts = [p["id"] for p in rows(
        connection, "SELECT id,scope,owner FROM policies WHERE namespace=? "
        "AND status='active' AND id<>? AND (scope=? OR scope='*' OR ?='*')",
        (policy["namespace"], policy_id, policy["scope"], policy["scope"]),
    )]
    if conflicts:
        return decision("blocked", "scope already has an active owner", conflicts=conflicts)
    connection.execute("UPDATE revisions SET status='superseded' WHERE policy_id=? AND status='active'",
                       (policy_id,))
    connection.execute("UPDATE revisions SET status='active' WHERE policy_id=? AND revision=?",
                       (policy_id, revision))
    connection.execute("UPDATE policies SET active_revision=?,status='active',generation=generation+1 "
                       "WHERE id=?", (revision, policy_id))
    affected = rows(connection, "SELECT * FROM inventories WHERE namespace=? AND (?='*' OR service=?)",
                    (policy["namespace"], policy["scope"], policy["scope"]))
    for replica in affected:
        matches = (replica["policy_id"] == policy_id and replica["revision"] == revision
                   and replica["value"] == proposed["value"])
        drift = "converged" if matches else "policy_changed"
        reason = ("installed state matches newly active target" if matches else
                  f"target {policy_id}@{revision} differs from installed state")
        connection.execute("UPDATE inventories SET drift=?,drift_reason=? WHERE replica_id=?",
                           (drift, reason, replica["replica_id"]))
    return decision("active", "publication changed target revision", policy_id=policy_id,
                    revision=revision, affected_replicas=[x["replica_id"] for x in affected])


def rollback(connection, payload):
    policy_id, source_revision = str(payload["policy_id"]), int(payload["source_revision"])
    policy = row(connection, "SELECT * FROM policies WHERE id=?", (policy_id,))
    source = row(connection, "SELECT * FROM revisions WHERE policy_id=? AND revision=?",
                 (policy_id, source_revision))
    if not policy or policy["status"] != "active" or not source or source["status"] == "draft":
        return decision("blocked", "rollback source is not a published revision")
    new_revision = row(connection, "SELECT MAX(revision) AS n FROM revisions WHERE policy_id=?", (policy_id,))["n"] + 1
    copied = {"policy_id": policy_id, "revision": new_revision, "value": source["value"],
              "dependencies": json.loads(source["dependencies"]), "at": int(payload["at"])}
    draft(connection, copied)
    result = publish(connection, {"policy_id": policy_id, "revision": new_revision})
    return {**result, "restored_from": source_revision, "new_revision": new_revision}


def retire(connection, payload):
    policy_id = str(payload["policy_id"])
    policy = row(connection, "SELECT * FROM policies WHERE id=?", (policy_id,))
    if not policy:
        return decision("rejected", "policy does not exist")
    if policy["status"] == "retired":
        return decision("retired", "already retired", policy_id=policy_id)
    dependent = [p["policy_id"] for p in rows(
        connection, "SELECT policy_id,dependencies FROM revisions WHERE status='active'")
        if p["policy_id"] != policy_id and policy_id in json.loads(p["dependencies"])]
    installed = [r["replica_id"] for r in rows(
        connection, "SELECT replica_id FROM inventories WHERE policy_id=?", (policy_id,))]
    blockers = {"dependent_policies": dependent, "installed_replicas": installed}
    status = "blocked" if dependent or installed else "retired"
    connection.execute(
        "INSERT INTO retirements(policy_id,requested_at,status,blockers) VALUES(?,?,?,?) "
        "ON CONFLICT(policy_id) DO UPDATE SET requested_at=excluded.requested_at,"
        "status=excluded.status,blockers=excluded.blockers",
        (policy_id, int(payload["at"]), status, json.dumps(blockers)),
    )
    if status == "retired":
        connection.execute("UPDATE policies SET status='retired',active_revision=NULL,generation=generation+1 "
                           "WHERE id=?", (policy_id,))
        connection.execute("UPDATE revisions SET status='retired' WHERE policy_id=? AND status='active'",
                           (policy_id,))
    return decision(status, "retirement dependency clearance", policy_id=policy_id, blockers=blockers)


HANDLERS = {"create": create, "draft": draft, "publish": publish,
            "rollback": rollback, "retire": retire}
