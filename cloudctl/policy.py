"""Policy ownership, immutable revisions, publication, hierarchy and pins.

The original single-namespace/single-policy resolver is preserved verbatim for
legacy inputs.  Inputs that name an org/cluster/namespace hierarchy use the
additive composition path: active policies on the org -> cluster -> namespace
chain are merged key by key (a closer layer only replaces the explicit keys it
publishes), and every expanded target gets a reproducible content identity
(value digest plus ancestor revision vector).
"""

import hashlib
import json

from .db import DecisionError, canonical, decision, row, rows


# ---------------------------------------------------------------------------
# Value / identity helpers
# ---------------------------------------------------------------------------

def parse_value(value):
    """Decode JSON-object strings, leave legacy scalar strings untouched."""
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            loaded = json.loads(value)
        except ValueError:
            return value
        if isinstance(loaded, (dict, list)):
            return loaded
        return value
    return value


def normalized_object(value):
    parsed = parse_value(value)
    if isinstance(parsed, dict):
        return json.loads(canonical(parsed))
    return parsed


def value_digest(value):
    obj = normalized_object(value)
    return "sha256:" + hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def identity_uid(digest, vector):
    raw = canonical({"digest": digest, "vector": vector or {}})
    return "T" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _col(item, name, default=None):
    if item is None:
        return default
    try:
        return item[name]
    except (KeyError, IndexError):
        return default


def _first(payload, *names):
    for name in names:
        if name in payload and payload[name] is not None:
            return payload[name]
    return None


# ---------------------------------------------------------------------------
# Legacy target resolution (unchanged contract for single-cluster inputs)
# ---------------------------------------------------------------------------

def matching(connection, namespace, service):
    return rows(
        connection,
        "SELECT * FROM policies WHERE namespace=? AND scope IN (?, '*') "
        "AND status='active' ORDER BY CASE WHEN scope='*' THEN 1 ELSE 0 END, id",
        (namespace, service),
    )


def legacy_target(connection, inventory):
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


# ---------------------------------------------------------------------------
# Hierarchy topology: org -> cluster -> namespace
# ---------------------------------------------------------------------------

def org_key(org=None):
    return f"org:{org or 'default'}"


def cluster_key(cluster):
    return f"cluster:{cluster}"


def namespace_key(cluster, namespace):
    return f"namespace:{cluster or '_'}:{namespace}"


def ensure_node(connection, key, kind, name, parent=None, at=0):
    existing = row(connection, "SELECT * FROM nodes WHERE node=?", (key,))
    if existing:
        return existing
    connection.execute(
        "INSERT INTO nodes(node,kind,name,parent,status,created_at) VALUES(?,?,?,?,'active',?)",
        (key, kind, name, parent, int(at or 0)),
    )
    if parent:
        parent_kind = {"cluster": "org", "namespace": "cluster"}.get(kind, "org")
        if kind == "cluster":
            ensure_node(connection, parent, "org", parent.split(":", 1)[-1], None, at)
        elif kind == "namespace":
            ensure_node(connection, parent, "cluster", parent.split(":", 1)[-1],
                        org_key(), at)
    else:
        if kind != "org":
            default_parent = org_key()
            ensure_node(connection, default_parent, "org", "default", None, at)
            connection.execute("UPDATE nodes SET parent=? WHERE node=? AND parent IS NULL",
                               (default_parent, key))
    return row(connection, "SELECT * FROM nodes WHERE node=?", (key,))


def _implicit_parent(key, org=None):
    if key.startswith("namespace:"):
        rest = key.split(":", 1)[1]
        cluster = rest.split(":", 1)[0]
        return cluster_key(cluster)
    if key.startswith("cluster:"):
        return org_key(org)
    return None


def node_chain(connection, anchor, org=None):
    """Root-to-leaf node keys for an anchor, verifying there is no cycle."""
    chain = []
    seen = set()
    key = anchor
    while key:
        if key in seen:
            raise DecisionError(f"inheritance cycle detected at node {key}")
        seen.add(key)
        chain.append(key)
        node = row(connection, "SELECT * FROM nodes WHERE node=?", (key,))
        parent = node["parent"] if node and node["parent"] else _implicit_parent(key, org)
        key = parent
    chain.reverse()
    return chain


def anchor_context(connection, cluster=None, namespace=None, org=None):
    """Resolve loose cluster/namespace names into a verified node chain.

    Returns None when the input is legacy (no cluster and the namespace is not
    registered as a hierarchy node).
    """
    cluster = _col_type(cluster)
    namespace = _col_type(namespace)
    org = _col_type(org)
    if cluster:
        if namespace:
            anchor = namespace_key(cluster, namespace)
            return {"chain": node_chain(connection, anchor, org), "cluster": cluster,
                    "namespace": namespace, "anchor": anchor, "org": org}
        anchor = cluster_key(cluster)
        return {"chain": node_chain(connection, anchor, org), "cluster": cluster,
                "namespace": namespace or "", "anchor": anchor, "org": org}
    if namespace:
        found = row(
            connection,
            "SELECT * FROM nodes WHERE status='active' AND "
            "(node=? OR name=?) ORDER BY CASE kind WHEN 'cluster' THEN 0 "
            "WHEN 'namespace' THEN 1 ELSE 2 END LIMIT 1",
            (cluster_key(namespace), namespace),
        )
        if not found:
            return None
        if found["kind"] == "cluster":
            return {"chain": node_chain(connection, found["node"], org),
                    "cluster": found["name"], "namespace": "",
                    "anchor": found["node"], "org": org}
        parent = found["parent"] or ""
        cluster_name = parent.split(":", 1)[-1] if parent.startswith("cluster:") else ""
        return {"chain": node_chain(connection, found["node"], org),
                "cluster": cluster_name, "namespace": found["name"],
                "anchor": found["node"], "org": org}
    return None


def _col_type(value):
    if value is None:
        return None
    value = str(value)
    return value if value != "" else None


def inventory_context(connection, inventory):
    return anchor_context(
        connection,
        cluster=_col(inventory, "cluster", "") or None,
        namespace=inventory["namespace"],
        org=_col(inventory, "org"),
    )


def is_hierarchical(connection, inventory):
    try:
        return inventory_context(connection, inventory) is not None
    except DecisionError:
        # A cyclic hierarchy is still hierarchical; callers that resolve will
        # surface the cycle as a blocked decision rather than silently legacy.
        return True


def hierarchy_active(connection):
    """True once any explicit hierarchy node/layered policy exists.

    This gates namespace-name heuristics so legacy single-namespace inputs keep
    using the original one-policy resolver exactly.
    """
    node = row(connection, "SELECT 1 AS x FROM nodes LIMIT 1")
    if node:
        return True
    layered = row(connection, "SELECT 1 AS x FROM policies WHERE node IS NOT NULL LIMIT 1")
    return bool(layered)


# ---------------------------------------------------------------------------
# Composition and identity
# ---------------------------------------------------------------------------

def compose_chain(connection, chain, service, excluded_policy=None):
    """Merge active object revisions root -> leaf.  Explicit keys only."""
    values, vector, sources = {}, {}, []
    for node_key in chain:
        policies = rows(
            connection,
            "SELECT * FROM policies WHERE node=? AND status='active' "
            "AND scope IN (?, '*') ORDER BY CASE WHEN scope='*' THEN 1 ELSE 0 END, id",
            (node_key, service),
        )
        policies = [p for p in policies if p["id"] != excluded_policy]
        if len(policies) > 1:
            ids = [p["id"] for p in policies]
            raise DecisionError(f"multiple active policies own {service} at {node_key}: {ids}")
        if not policies:
            continue
        policy = policies[0]
        revision = row(
            connection, "SELECT * FROM revisions WHERE policy_id=? AND revision=?",
            (policy["id"], policy["active_revision"]),
        )
        if revision is None:
            raise DecisionError(f"active policy {policy['id']} has no active revision")
        obj = parse_value(revision["value"])
        if not isinstance(obj, dict):
            raise DecisionError(
                f"hierarchical policy {policy['id']}@{revision['revision']} "
                "must expand to a key/value object")
        values.update(obj)
        vector[policy["id"]] = revision["revision"]
        node = row(connection, "SELECT kind FROM nodes WHERE node=?", (node_key,))
        sources.append({
            "node": node_key,
            "layer": node["kind"] if node else node_key.split(":", 1)[0],
            "policy_id": policy["id"],
            "revision": revision["revision"],
            "keys": sorted(obj),
        })
    return values, vector, sources


def active_pin(connection, cluster, service, namespace=""):
    if not cluster:
        return None
    pins = rows(
        connection,
        "SELECT * FROM pins WHERE status='active' AND service=? AND cluster=? "
        "ORDER BY issued_at DESC, pin_id",
        (service, cluster),
    )
    for pin in pins:
        if pin["namespace"] and namespace and pin["namespace"] != namespace:
            continue
        return pin
    return pins[0] if pins else None


def desired_from_pin(pin):
    values = json.loads(pin["values_json"])
    vector = json.loads(pin["vector_json"])
    sources = json.loads(pin["sources_json"] or "[]")
    primary = sources[0]["policy_id"] if sources else (sorted(vector)[0] if vector else None)
    return {
        "kind": "hierarchical", "policy_id": primary,
        "revision": vector.get(primary) if primary else None,
        "value": values, "values": values, "value_json": canonical(values),
        "digest": pin["digest"], "target_uid": pin["target_uid"],
        "vector": vector, "revision_vector": canonical(vector), "sources": sources,
        "cluster": pin["cluster"], "namespace": pin["namespace"],
        "pinned": True, "pin_id": pin["pin_id"], "generation": None,
    }


def resolve_in_context(connection, ctx, service):
    pin = active_pin(connection, ctx["cluster"], service, ctx.get("namespace", ""))
    if pin:
        desired = desired_from_pin(pin)
        desired["chain"] = ctx["chain"]
        return desired
    values, vector, sources = compose_chain(connection, ctx["chain"], service)
    if not sources:
        return None
    digest = value_digest(values)
    uid = identity_uid(digest, vector)
    primary = sources[0]["policy_id"]
    policy = row(connection, "SELECT generation FROM policies WHERE id=?", (primary,))
    return {
        "kind": "hierarchical", "policy_id": primary,
        "revision": vector[primary],
        "value": values, "values": values, "value_json": canonical(values),
        "digest": digest, "target_uid": uid,
        "vector": vector, "revision_vector": canonical(vector), "sources": sources,
        "cluster": ctx["cluster"], "namespace": ctx.get("namespace", ""),
        "anchor": ctx["anchor"], "chain": ctx["chain"],
        "pinned": False, "pin_id": None,
        "generation": policy["generation"] if policy else None,
    }


def target(connection, inventory):
    """Unique reproducible target for one replica at the current event time."""
    ctx = inventory_context(connection, inventory)
    if ctx is None:
        return legacy_target(connection, inventory)
    return resolve_in_context(connection, ctx, inventory["service"])


# Descriptive aliases for callers/tests that name this step explicitly.
def resolve_target(connection, *args, cluster=None, namespace=None, service=None, org=None):
    """Resolve a unique effective target.

    Accepted positional forms:
      resolve_target(db, namespace, service)
      resolve_target(db, cluster, namespace, service)
    plus the keyword form used throughout this module.  A single positional
    argument is treated as the service when ``service`` is absent only if it
    cannot name a scope; keyword arguments are unambiguous and preferred.
    """
    if len(args) == 2 and service is None:
        namespace, service = args
    elif len(args) >= 3:
        cluster, namespace, service = args[0], args[1], args[2]
    elif len(args) == 1:
        if service is None:
            service = args[0]
    ctx = anchor_context(connection, cluster=cluster, namespace=namespace, org=org)
    if ctx is None:
        return None
    return resolve_in_context(connection, ctx, service)


effective_target = resolve_target_hierarchical = compose_target = resolve = resolve_target
effective = compose = get_target = resolve_target
digest = value_digest
identity = target_identity = identity_uid


def expand_revisions(connection, refs):
    """Expand an ordered root->leaf list of immutable policy revisions.

    Each ref is ``(policy_id, revision)`` or ``{"policy_id": ..., "revision":
    ...}``.  This is the point-in-time, replayable form: callers freeze the
    returned ``vector``/``digest``/``target_uid`` instead of relying on the
    policy's current active revision.
    """
    values, vector, sources = {}, {}, []
    for ref in refs:
        if isinstance(ref, dict):
            policy_id, revision = str(ref["policy_id"]), int(ref["revision"])
            layer = ref.get("layer")
        else:
            policy_id, revision = str(ref[0]), int(ref[1])
            layer = None
        rev = row(connection, "SELECT * FROM revisions WHERE policy_id=? AND revision=?",
                  (policy_id, revision))
        if rev is None:
            raise DecisionError(f"unknown immutable revision {policy_id}@{revision}")
        obj = parse_value(rev["value"])
        if not isinstance(obj, dict):
            raise DecisionError(f"{policy_id}@{revision} is not a key/value object")
        keys = sorted(obj)
        values.update(obj)
        vector[policy_id] = revision
        sources.append({"policy_id": policy_id, "revision": revision,
                        "layer": layer, "keys": keys})
    digest_value = value_digest(values)
    return {"values": values, "value": values, "digest": digest_value,
            "target_uid": identity_uid(digest_value, vector),
            "vector": vector, "sources": sources}


expand = expand_revisions
compose_revisions = revision_vector_expand = expand_revisions


def materialize(connection, desired, at=0):
    if not desired or desired.get("kind") != "hierarchical":
        return None
    connection.execute(
        "INSERT OR IGNORE INTO effective_targets(target_uid,service,cluster,namespace,anchor,"
        "values_json,digest,vector_json,sources_json,pinned,pin_id,created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (desired["target_uid"], desired.get("service", ""), desired.get("cluster", ""),
         desired.get("namespace", ""), desired.get("anchor", ""),
         canonical(desired["values"]), desired["digest"], canonical(desired["vector"]),
         canonical(desired["sources"]), 1 if desired.get("pinned") else 0,
         desired.get("pin_id") or "", int(at or 0)),
    )
    return desired["target_uid"]


# ---------------------------------------------------------------------------
# Drift comparison for expanded object targets
# ---------------------------------------------------------------------------

def hierarchical_drift(desired, policy_id, revision, value,
                       digest_claim=None, vector_claim=None, adjudicated_uid=None):
    observed = normalized_object(value)
    value_matches = isinstance(observed, dict) and observed == desired["values"]
    if not value_matches and digest_claim and digest_claim == desired["digest"]:
        value_matches = True
    if value_matches:
        return "converged", "observed expanded value matches active target identity"
    # The stored observation was adjudicated against a different frozen
    # composition identity: an ancestor rollback/publication or a local
    # retirement moved the target even if a local policy revision number did not.
    if adjudicated_uid and adjudicated_uid != desired["target_uid"]:
        return "policy_changed", "expanded target identity changed since last observation"
    vector_claim = vector_claim if isinstance(vector_claim, dict) else None
    if vector_claim and vector_claim == desired["vector"]:
        return "manual_override", "target vector matches but expanded value differs"
    if policy_id and policy_id not in desired["vector"]:
        return "wrong_policy", "observed policy identity is outside the inheritance chain"
    if (policy_id and policy_id in desired["vector"] and revision is not None
            and int(revision) == int(desired["vector"][policy_id])):
        return "manual_override", "same source revision has different explicit value"
    return "policy_changed", "ancestor revision vector or expanded value is behind target"


def recompute_inventory(connection, replica_id):
    inventory = row(connection, "SELECT * FROM inventories WHERE replica_id=?", (replica_id,))
    if not inventory:
        return None
    ctx = inventory_context(connection, inventory)
    if ctx is None:
        return None
    try:
        desired = resolve_in_context(connection, ctx, inventory["service"])
    except DecisionError:
        connection.execute(
            "UPDATE inventories SET drift='conflict', drift_reason=? WHERE replica_id=?",
            ("inheritance resolution is not unique", replica_id))
        return "conflict"
    if desired is None:
        drift, reason = "no_target", "no active policy matches this replica"
    else:
        vector_claim = None
        if inventory["observed_vector"]:
            try:
                vector_claim = json.loads(inventory["observed_vector"])
            except ValueError:
                vector_claim = None
        drift, reason = hierarchical_drift(
            desired, inventory["policy_id"], inventory["revision"], inventory["value"],
            inventory["observed_digest"], vector_claim,
            adjudicated_uid=inventory["target_uid"])
    connection.execute("UPDATE inventories SET drift=?,drift_reason=? WHERE replica_id=?",
                       (drift, reason, replica_id))
    return drift


def all_hierarchical_inventories(connection):
    result = []
    for inventory in rows(connection, "SELECT * FROM inventories ORDER BY replica_id"):
        if is_hierarchical(connection, inventory):
            result.append(inventory)
    return result


# ---------------------------------------------------------------------------
# Policy authoring
# ---------------------------------------------------------------------------

def _policy_node(payload):
    node = _first(payload, "node", "node_path", "target_node", "node_id")
    layer = _first(payload, "layer", "level", "tier", "type",
                   "scope_level", "hierarchy_level") or ""
    layer = str(layer)
    if layer == "organization":
        layer = "org"
    if layer not in ("", "org", "cluster", "namespace"):
        layer = ""
    org = _first(payload, "org", "organization", "org_id", "org_name")
    cluster = _first(payload, "cluster", "cluster_id", "cluster_name")
    namespace = _first(payload, "namespace", "ns")
    name = _first(payload, "name", "node_name")
    if not node:
        if layer in ("org", "organization"):
            node = org_key(org or name)
            layer = "org"
        elif layer == "cluster":
            node = cluster_key(cluster or name or namespace)
        elif layer == "namespace":
            node = namespace_key(cluster, namespace or name)
        elif cluster:
            node = namespace_key(cluster, namespace) if namespace else cluster_key(cluster)
        elif org and not namespace:
            node = org_key(org)
            layer = "org"
    if node and not layer:
        if node.startswith("org:"):
            layer = "org"
        elif node.startswith("cluster:"):
            layer = "cluster"
        elif node.startswith("namespace:"):
            layer = "namespace"
    return node, layer, org, cluster, namespace


def create(connection, payload):
    policy_id = str(payload["policy_id"])
    if row(connection, "SELECT id FROM policies WHERE id=?", (policy_id,)):
        return decision("rejected", "policy already exists", policy_id=policy_id)
    node, layer, org, cluster, namespace = _policy_node(payload)
    if not node and namespace:
        existing_node = row(
            connection,
            "SELECT node,kind FROM nodes WHERE status='active' AND (node=? OR name=?) "
            "ORDER BY CASE kind WHEN 'cluster' THEN 0 ELSE 1 END LIMIT 1",
            (cluster_key(namespace), namespace),
        )
        if existing_node:
            node, layer = existing_node["node"], existing_node["kind"]
        elif hierarchy_active(connection) or org or payload.get("as_cluster"):
            # Compatibility for callers that address east/west through the
            # original namespace field once hierarchy mode is in use.
            node, layer = cluster_key(namespace), "cluster"
            cluster = cluster or namespace
    if node:
        if layer == "org":
            ensure_node(connection, node, "org", str(org or "default"))
        elif layer == "cluster":
            ensure_node(connection, node, "cluster",
                        str(cluster or payload.get("name") or namespace or node.split(":", 1)[-1]),
                        org_key(org))
        elif layer == "namespace":
            ensure_node(connection, node, "namespace", str(namespace or payload.get("name")),
                        _implicit_parent(node, org))
    if not namespace:
        namespace = ""
    scope = str(payload["scope"])
    owner = str(payload["owner"])
    connection.execute(
        "INSERT INTO policies(id,namespace,scope,owner,node,layer) VALUES(?,?,?,?,?,?)",
        (policy_id, str(namespace), scope, owner, node, layer),
    )
    result = decision("created", "draft policy registered", policy_id=policy_id,
                      namespace=str(namespace), scope=scope, owner=owner)
    if node:
        result.update(node=node, layer=layer)
    return result


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
    raw_value = payload["value"]
    # Preserve legacy scalar storage exactly; canonicalize structured values.
    value = canonical(raw_value) if isinstance(raw_value, (dict, list)) else str(raw_value)
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


def _scope_conflicts(connection, policy):
    if policy["node"]:
        return [p["id"] for p in rows(
            connection,
            "SELECT id FROM policies WHERE node=? AND status='active' AND id<>? "
            "AND (scope=? OR scope='*' OR ?='*')",
            (policy["node"], policy["id"], policy["scope"], policy["scope"]),
        )]
    return [p["id"] for p in rows(
        connection, "SELECT id,scope,owner FROM policies WHERE namespace=? "
        "AND status='active' AND id<>? AND (scope=? OR scope='*' OR ?='*')",
        (policy["namespace"], policy["id"], policy["scope"], policy["scope"]),
    )]


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
    conflicts = _scope_conflicts(connection, policy)
    if conflicts:
        where = policy["node"] or policy["namespace"]
        return decision("blocked", "scope already has an active owner",
                        conflicts=conflicts, scope_owner=where)
    connection.execute("UPDATE revisions SET status='superseded' WHERE policy_id=? AND status='active'",
                       (policy_id,))
    connection.execute("UPDATE revisions SET status='active' WHERE policy_id=? AND revision=?",
                       (policy_id, revision))
    connection.execute("UPDATE policies SET active_revision=?,status='active',generation=generation+1 "
                       "WHERE id=?", (revision, policy_id))

    affected = rows(connection, "SELECT * FROM inventories WHERE namespace=? AND (?='*' OR service=?)",
                    (policy["namespace"], policy["scope"], policy["scope"]))
    affected_ids = []
    for replica in affected:
        affected_ids.append(replica["replica_id"])
        if is_hierarchical(connection, replica):
            recompute_inventory(connection, replica["replica_id"])
            continue
        matches = (replica["policy_id"] == policy_id and replica["revision"] == revision
                   and replica["value"] == proposed["value"])
        drift = "converged" if matches else "policy_changed"
        reason = ("installed state matches newly active target" if matches else
                  f"target {policy_id}@{revision} differs from installed state")
        connection.execute("UPDATE inventories SET drift=?,drift_reason=? WHERE replica_id=?",
                           (drift, reason, replica["replica_id"]))

    # Hierarchy fan-out: an org/cluster publication reaches descendants that
    # the namespace-local query above cannot see.
    hierarchy_affected = []
    for replica in all_hierarchical_inventories(connection):
        if replica["replica_id"] in affected_ids:
            continue
        before = replica["drift"]
        new_drift = recompute_inventory(connection, replica["replica_id"])
        if new_drift is not None:
            hierarchy_affected.append(replica["replica_id"])
            affected_ids.append(replica["replica_id"])
    result = decision("active", "publication changed target revision", policy_id=policy_id,
                      revision=revision, affected_replicas=affected_ids)
    if policy["node"] or hierarchy_affected:
        clusters = sorted({_col(r, "cluster", "") or r["namespace"]
                           for r in all_hierarchical_inventories(connection)
                           if r["replica_id"] in affected_ids})
        result.update(node=policy["node"], hierarchy_affected=hierarchy_affected,
                      affected_clusters=clusters)
    return result


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


def _hierarchy_retirement_safety(connection, policy):
    """Return (ownerless_records, inherited_ids) for a layered policy."""
    ownerless, inherited = [], []
    for inventory in all_hierarchical_inventories(connection):
        try:
            desired = target(connection, inventory)
        except DecisionError:
            ownerless.append({"replica_id": inventory["replica_id"], "keys": ["<cycle>"]})
            continue
        if not desired or policy["id"] not in desired["vector"]:
            continue
        inherited.append(inventory["replica_id"])
        ctx = inventory_context(connection, inventory)
        try:
            remaining, _, _ = compose_chain(connection, ctx["chain"], inventory["service"],
                                            excluded_policy=policy["id"])
        except DecisionError:
            remaining = {}
        lost = sorted(set(desired["values"]) - set(remaining))
        if lost:
            ownerless.append({"replica_id": inventory["replica_id"], "keys": lost})
    return ownerless, inherited


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

    if policy["node"]:
        ownerless, inherited = _hierarchy_retirement_safety(connection, policy)
        blockers = {"dependent_policies": dependent,
                    "ownerless_descendants": ownerless,
                    "inherited_replicas": inherited}
        status = "blocked" if dependent or ownerless else "retired"
        connection.execute(
            "INSERT INTO retirements(policy_id,requested_at,status,blockers) VALUES(?,?,?,?) "
            "ON CONFLICT(policy_id) DO UPDATE SET requested_at=excluded.requested_at,"
            "status=excluded.status,blockers=excluded.blockers",
            (policy_id, int(payload["at"]), status, canonical(blockers)),
        )
        if status == "retired":
            connection.execute("UPDATE policies SET status='retired',active_revision=NULL,"
                               "generation=generation+1 WHERE id=?", (policy_id,))
            connection.execute("UPDATE revisions SET status='retired' WHERE policy_id=? "
                               "AND status='active'", (policy_id,))
            recomputed = []
            for replica in all_hierarchical_inventories(connection):
                drift = recompute_inventory(connection, replica["replica_id"])
                if drift is not None:
                    recomputed.append({"replica_id": replica["replica_id"], "drift": drift})
            return decision("retired",
                            "local layer retired; ancestor keys still own the target",
                            policy_id=policy_id, blockers=blockers, recomputed=recomputed)
        return decision(status, "retirement would leave inherited keys without an owner",
                        policy_id=policy_id, blockers=blockers)

    installed = [r["replica_id"] for r in rows(
        connection, "SELECT replica_id FROM inventories WHERE policy_id=?", (policy_id,))]
    blockers = {"dependent_policies": dependent, "installed_replicas": installed}
    status = "blocked" if dependent or installed else "retired"
    connection.execute(
        "INSERT INTO retirements(policy_id,requested_at,status,blockers) VALUES(?,?,?,?) "
        "ON CONFLICT(policy_id) DO UPDATE SET requested_at=excluded.requested_at,"
        "status=excluded.status,blockers=excluded.blockers",
        (policy_id, int(payload["at"]), status, canonical(blockers)),
    )
    if status == "retired":
        connection.execute("UPDATE policies SET status='retired',active_revision=NULL,generation=generation+1 "
                           "WHERE id=?", (policy_id,))
        connection.execute("UPDATE revisions SET status='retired' WHERE policy_id=? AND status='active'",
                           (policy_id,))
    return decision(status, "retirement dependency clearance", policy_id=policy_id, blockers=blockers)


# ---------------------------------------------------------------------------
# Topology authoring / verification
# ---------------------------------------------------------------------------

def create_node(connection, payload):
    key = _first(payload, "node", "node_path", "path")
    kind = str(_first(payload, "kind", "type", "layer") or "cluster")
    name = str(_first(payload, "name", "cluster", "cluster_name") or key or "")
    parent = _first(payload, "parent", "parent_node")
    at = int(payload.get("at", 0) or 0)
    if not key:
        if kind == "org":
            key = org_key(_first(payload, "org", "organization") or name or "default")
        elif kind == "cluster":
            cname = _first(payload, "cluster", "cluster_name", "name")
            key = cluster_key(cname)
            name = str(cname)
            parent = parent or org_key(_first(payload, "org", "organization"))
        elif kind == "namespace":
            cname = _first(payload, "cluster", "cluster_name")
            ns = _first(payload, "namespace", "name")
            key = namespace_key(cname, ns)
            name = str(ns)
            parent = parent or cluster_key(cname)
    if not key:
        return decision("rejected", "node identity is required")
    existing = row(connection, "SELECT * FROM nodes WHERE node=?", (key,))
    if existing:
        new_parent = parent if parent is not None else existing["parent"]
        if new_parent and new_parent != existing["parent"]:
            connection.execute("UPDATE nodes SET parent=? WHERE node=?", (new_parent, key))
            try:
                node_chain(connection, key)
            except DecisionError as error:
                # Roll back the parent move inside this transaction.
                connection.execute("UPDATE nodes SET parent=? WHERE node=?",
                                   (existing["parent"], key))
                return decision("blocked", str(error), node=key)
        return decision("exists", "node already registered", node=key, kind=existing["kind"])
    if parent:
        parent_row = row(connection, "SELECT node FROM nodes WHERE node=?", (parent,))
        if not parent_row:
            return decision("blocked", "parent node does not exist", parent=parent)
    ensure_node(connection, key, kind, name or key, parent, at)
    try:
        node_chain(connection, key)
    except DecisionError as error:
        return decision("blocked", str(error), node=key)
    return decision("created", "hierarchy node registered", node=key, kind=kind, parent=parent)


def topology_report(connection, payload=None):
    nodes = rows(connection, "SELECT node,kind,name,parent,status FROM nodes ORDER BY node")
    chains = {}
    for node in nodes:
        if node["kind"] in ("cluster", "namespace"):
            try:
                chains[node["node"]] = node_chain(connection, node["node"])
            except DecisionError as error:
                chains[node["node"]] = {"cycle": str(error)}
    conflicts = []
    for node in nodes:
        owned = rows(
            connection,
            "SELECT scope, GROUP_CONCAT(id) AS ids FROM policies WHERE node=? "
            "AND status='active' GROUP BY scope HAVING COUNT(*)>1",
            (node["node"],))
        for item in owned:
            conflicts.append({"node": node["node"], "scope": item["scope"],
                              "policy_ids": item["ids"].split(",")})
    status = "verified" if not conflicts and not any(
        isinstance(v, dict) and "cycle" in v for v in chains.values()) else "conflict"
    return decision(status, "org/cluster/namespace inheritance graph",
                    nodes=nodes, chains=chains, conflicts=conflicts)


# ---------------------------------------------------------------------------
# Revocable target pins (route B)
# ---------------------------------------------------------------------------

def _budget(connection, cluster, namespace, service, minimum=None):
    scope_sql, scope_params = scope_filter(cluster, namespace)
    where = f"service=? AND {scope_sql}"
    params = [service] + scope_params
    healthy = row(connection, f"SELECT COUNT(*) AS n FROM inventories WHERE {where} AND healthy=1",
                  tuple(params))["n"]
    total = row(connection, f"SELECT COUNT(*) AS n FROM inventories WHERE {where}",
                tuple(params))["n"]
    action_scope, action_params = scope_filter(cluster, namespace, alias="i")
    occupied = row(
        connection,
        f"SELECT COUNT(DISTINCT a.replica_id) AS n FROM actions a "
        f"JOIN inventories i ON i.replica_id=a.replica_id "
        f"WHERE a.status IN ('dispatched','applied') AND i.service=? AND {action_scope}",
        tuple([service] + action_params))["n"]
    result = {"healthy": healthy, "total": total, "occupied": occupied}
    if minimum is not None:
        result["min_healthy"] = minimum
        result["healthy_enough"] = healthy >= minimum
        result["floor_after_occupied"] = healthy - occupied >= minimum
        result["available_parallel"] = max(0, healthy - minimum - occupied)
    return result


def scope_filter(cluster, namespace, alias=""):
    """SQL fragment matching one cluster boundary under both addressing styles.

    Explicit cluster tagging wins; namespace-addressed rows with empty cluster
    still belong to the named logical cluster when both coordinates are given.
    """
    col = f"{alias}." if alias else ""
    cluster = cluster or ""
    namespace = namespace or ""
    if cluster and namespace:
        return (f"(({col}cluster=?) OR ({col}cluster='' AND {col}namespace=?))",
                [cluster, namespace])
    if cluster:
        return f"{col}cluster=?", [cluster]
    if namespace:
        return f"{col}namespace=?", [namespace]
    return "1=1", []


def evaluate_health_window(connection, cluster, namespace, service, minimum, at, window_minutes,
                           attestation=None):
    budget = _budget(connection, cluster, namespace, service, minimum)
    at = int(at)
    window_minutes = int(window_minutes or 0)
    samples = rows(
        connection,
        "SELECT * FROM health_samples WHERE cluster=? AND service=? AND at<=? "
        "ORDER BY at,id",
        (cluster or "", service, at),
    )
    if namespace:
        samples = [s for s in samples if not s["namespace"] or s["namespace"] == namespace]
    unhealthy_times = [s["at"] for s in samples if s["healthy_count"] < minimum]
    run_start = max(unhealthy_times) if unhealthy_times else None
    good = [s for s in samples if s["at"] > (run_start if run_start is not None else -1)]

    sample_span = (at - good[0]["at"]) if good else None
    sample_ok = True
    if window_minutes > 0:
        sample_ok = bool(good) and sample_span is not None and sample_span >= window_minutes

    # Fallback evidence: the span of accepted independent observations from
    # the cluster's own replicas (at least min_healthy distinct replicas).
    scope_sql, scope_params = scope_filter(cluster, namespace)
    replica_ids = [r["replica_id"] for r in rows(
        connection, f"SELECT replica_id FROM inventories WHERE service=? AND {scope_sql}",
        tuple([service] + scope_params))]
    obs_span = None
    observed_replicas = 0
    observation_ok = False
    if replica_ids:
        marks = ",".join("?" for _ in replica_ids)
        earliest = row(
            connection,
            f"SELECT MIN(observed_at) AS first_at, COUNT(DISTINCT replica_id) AS n "
            f"FROM observations WHERE status='accepted' AND observed_at<=? "
            f"AND replica_id IN ({marks})",
            tuple([at] + replica_ids))
        if earliest and earliest["first_at"] is not None:
            obs_span = at - int(earliest["first_at"])
            observed_replicas = int(earliest["n"])
            observation_ok = (observed_replicas >= max(1, minimum)
                              and (window_minutes == 0 or obs_span >= window_minutes))

    # Explicit pre-authorized attestation (recorded as an event) may prove the
    # sustained duration when an external health system owns the window.
    attestation_ok = False
    attested_span = None
    if isinstance(attestation, dict):
        attested_span = attestation.get("healthy_for_minutes")
        if attested_span is None and attestation.get("healthy_since") is not None:
            attested_span = at - int(attestation["healthy_since"])
        if attested_span is not None:
            attestation_ok = int(attested_span) >= window_minutes
        elif attestation.get("window_satisfied") is True:
            attestation_ok = True

    span = sample_span if sample_ok else (obs_span if observation_ok else attested_span)
    window_ok = sample_ok or observation_ok or attestation_ok or window_minutes == 0
    proven = budget["healthy_enough"] and budget["floor_after_occupied"] and window_ok
    budget.update(window_minutes=window_minutes, window_span=span,
                  window_satisfied=proven, sample_count=len(samples),
                  sample_window_ok=sample_ok, observation_window_ok=observation_ok,
                  observed_replicas=observed_replicas,
                  attestation_window_ok=attestation_ok)
    return budget



def issue_pin(connection, payload):
    pin_id = str(_first(payload, "pin_id", "id", "certificate_id") or "")
    if not pin_id:
        return decision("rejected", "pin_id is required")
    if row(connection, "SELECT pin_id FROM pins WHERE pin_id=?", (pin_id,)):
        return decision("rejected", "pin already exists", pin_id=pin_id)
    cluster = _first(payload, "cluster", "cluster_id", "cluster_name")
    namespace = _first(payload, "namespace", "ns") or ""
    service = str(_first(payload, "service") or "")
    if not cluster and namespace:
        ctx0 = anchor_context(connection, namespace=namespace)
        if ctx0:
            cluster, namespace = ctx0["cluster"], ctx0.get("namespace", "")
    if not cluster or not service:
        return decision("rejected", "cluster and service are required to pin a target")
    if active_pin(connection, str(cluster), service, namespace):
        return decision("blocked", "an active pin already owns this cluster/service",
                        cluster=cluster, service=service)
    at = int(payload.get("at", payload.get("issued_at", 0)) or 0)

    target_uid = payload.get("target_uid")
    explicit_refs = _first(payload, "refs", "revisions", "revision_refs")
    explicit_vector = payload.get("vector", payload.get("revision_vector"))
    if isinstance(explicit_vector, str):
        try:
            explicit_vector = json.loads(explicit_vector)
        except ValueError:
            explicit_vector = None
    if target_uid:
        stored = row(connection, "SELECT * FROM effective_targets WHERE target_uid=?", (target_uid,))
        if not stored:
            return decision("blocked", "pinned target_uid is not a known immutable identity",
                            target_uid=target_uid)
        digest, vector = stored["digest"], json.loads(stored["vector_json"])
        values = json.loads(stored["values_json"])
        sources = json.loads(stored["sources_json"])
        target_uid = stored["target_uid"]
    elif explicit_refs:
        expanded = expand_revisions(connection, explicit_refs)
        target_uid, digest = expanded["target_uid"], expanded["digest"]
        vector, values, sources = expanded["vector"], expanded["values"], expanded["sources"]
    elif isinstance(explicit_vector, dict):
        def depth(policy_id):
            pol = row(connection, "SELECT node,layer FROM policies WHERE id=?", (policy_id,))
            layer = (pol["layer"] if pol else "") or ""
            return {"org": 0, "cluster": 1, "namespace": 2}.get(layer, 3)
        refs = [(pid, rev) for pid, rev in
                sorted(explicit_vector.items(), key=lambda kv: (depth(kv[0]), kv[0]))]
        expanded = expand_revisions(connection, refs)
        target_uid, digest = expanded["target_uid"], expanded["digest"]
        vector, values, sources = expanded["vector"], expanded["values"], expanded["sources"]
    else:
        desired = resolve_target(connection, cluster=cluster, namespace=namespace or None,
                                 service=service)
        if desired is None:
            return decision("blocked", "no unique active target to pin",
                            cluster=cluster, service=service)
        if desired.get("pinned"):
            return decision("blocked", "target is already pinned", pin_id=desired.get("pin_id"))
        target_uid, digest = desired["target_uid"], desired["digest"]
        vector, values, sources = desired["vector"], desired["values"], desired["sources"]
        materialize(connection, {**desired, "service": service}, at)

    minimum = payload.get("min_healthy")
    window = int(_first(payload, "window_minutes", "window", "healthy_window") or 0)
    connection.execute(
        "INSERT INTO pins(pin_id,node,cluster,namespace,service,target_uid,digest,vector_json,"
        "values_json,sources_json,status,approved_by,reason,min_healthy,window_minutes,issued_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,'active',?,?,?,?,?)",
        (pin_id, cluster_key(cluster), str(cluster), str(namespace), service, target_uid, digest,
         canonical(vector), canonical(values), canonical(sources),
         str(payload.get("approved_by", "ops")), str(payload.get("reason", "revision pin")),
         int(minimum) if minimum is not None else None, window, at),
    )
    return decision("pinned", "revocable certificate freezes an expanded target identity",
                    pin_id=pin_id, status_detail="active", cluster=cluster, service=service,
                    target_uid=target_uid, digest=digest, vector=vector, values=values)


def _find_pin(connection, payload):
    pin_id = _first(payload, "pin_id", "id", "certificate_id")
    if pin_id:
        return row(connection, "SELECT * FROM pins WHERE pin_id=?", (str(pin_id),))
    cluster = _first(payload, "cluster", "cluster_id", "cluster_name")
    service = payload.get("service")
    if cluster and service:
        return active_pin(connection, str(cluster), str(service), payload.get("namespace", ""))
    return None


def release_pin(connection, payload):
    pin = _find_pin(connection, payload)
    if not pin:
        return decision("missing", "pin does not exist")
    if pin["status"] == "released":
        return decision("released", "pin already released", pin_id=pin["pin_id"],
                        target_uid=pin["target_uid"])
    if pin["status"] == "revoked":
        return decision("blocked", "revoked pin cannot be released through a health window",
                        pin_id=pin["pin_id"])
    at = int(payload.get("at", pin["issued_at"]) or pin["issued_at"])
    minimum = payload.get("min_healthy")
    minimum = int(minimum if minimum is not None else
                  (pin["min_healthy"] if pin["min_healthy"] is not None else None))
    if minimum is None:
        return decision("blocked", "min_healthy is required to prove the release window")
    window = int(_first(payload, "window_minutes", "window")
                 if _first(payload, "window_minutes", "window") is not None
                 else pin["window_minutes"])
    health = evaluate_health_window(
        connection, pin["cluster"], pin["namespace"], pin["service"], minimum, at, window,
        attestation={
            "healthy_for_minutes": payload.get("healthy_for_minutes"),
            "healthy_since": payload.get("healthy_since"),
            "window_satisfied": payload.get("window_satisfied"),
        } if any(k in payload for k in
                 ("healthy_for_minutes", "healthy_since", "window_satisfied")) else None)
    if not health["window_satisfied"]:
        return decision("blocked",
                        "cluster-local health and observation window are not proven",
                        pin_id=pin["pin_id"], health=health)
    detail = canonical(health)
    connection.execute(
        "UPDATE pins SET status='released',released_at=?,release_at=?,release_detail_json=? "
        "WHERE pin_id=?", (at, at, detail, pin["pin_id"]))
    scope_sql, scope_params = scope_filter(pin["cluster"], pin["namespace"])
    recomputed = {}
    for inventory in rows(
            connection,
            f"SELECT * FROM inventories WHERE service=? AND {scope_sql}",
            tuple([pin["service"]] + scope_params)):
        drift = recompute_inventory(connection, inventory["replica_id"])
        if drift is not None:
            recomputed[inventory["replica_id"]] = drift
    desired = resolve_target(connection, cluster=pin["cluster"],
                             namespace=pin["namespace"] or None, service=pin["service"])
    return decision("released", "health window proven; pin released to current ancestor target",
                    pin_id=pin["pin_id"], cluster=pin["cluster"], health=health,
                    drift=recomputed,
                    target_uid=desired["target_uid"] if desired else None,
                    target=desired)


def revoke_pin(connection, payload):
    pin = _find_pin(connection, payload)
    if not pin:
        return decision("missing", "pin does not exist")
    if pin["status"] == "revoked":
        return decision("revoked", "pin already revoked", pin_id=pin["pin_id"])
    at = int(payload.get("at", payload.get("revoked_at", pin["issued_at"])) or pin["issued_at"])
    connection.execute("UPDATE pins SET status='revoked',released_at=? WHERE pin_id=?",
                       (at, pin["pin_id"]))
    scope_sql, scope_params = scope_filter(pin["cluster"], pin["namespace"])
    recomputed = {}
    for inventory in rows(connection,
                          f"SELECT * FROM inventories WHERE service=? AND {scope_sql}",
                          tuple([pin["service"]] + scope_params)):
        drift = recompute_inventory(connection, inventory["replica_id"])
        if drift is not None:
            recomputed[inventory["replica_id"]] = drift
    desired = resolve_target(connection, cluster=pin["cluster"],
                             namespace=pin["namespace"] or None, service=pin["service"])
    return decision("revoked", "pin revoked; unique inherited target is active again",
                    pin_id=pin["pin_id"], drift=recomputed,
                    target_uid=desired["target_uid"] if desired else None, target=desired)


def show_target(connection, payload):
    cluster = _first(payload, "cluster", "cluster_id", "cluster_name")
    namespace = _first(payload, "namespace", "ns")
    service = str(payload["service"])
    desired = resolve_target(connection, cluster=cluster, namespace=namespace, service=service)
    if desired is None:
        return decision("no_target", "no active policy matches", cluster=cluster,
                        namespace=namespace, service=service)
    return decision("found", "unique reproducible effective target", target=desired)


HANDLERS = {
    "create": create, "draft": draft, "publish": publish,
    "rollback": rollback, "retire": retire,
    "node": create_node, "bind": create_node, "topology": topology_report,
    "verify": topology_report, "hierarchy": topology_report,
    "pin": issue_pin, "issue_pin": issue_pin, "create_pin": issue_pin, "freeze": issue_pin,
    "unpin": release_pin, "release_pin": release_pin, "pin_release": release_pin,
    "release": release_pin,
    "revoke": revoke_pin, "revoke_pin": revoke_pin, "pin_revoke": revoke_pin,
    "target": show_target, "resolve": show_target, "effective_target": show_target,
}
