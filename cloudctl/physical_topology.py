"""Physical failure domains, link identity and compatible topology mappings.

The important distinction in this module is between an observed port/link claim
and a physical bandwidth resource.  Two differently named switch ports can be
aliases of one physical link.  While a fibre label is missing, several topology
mappings can remain compatible; capacity is safe only when a route fits *every*
compatible mapping.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterable

from .db import decision


SCHEMA = """
CREATE TABLE IF NOT EXISTS pt_failure_domains (
  domain_id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  healthy INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active',
  attrs_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS pt_nodes (
  node_id TEXT PRIMARY KEY,
  domain_id TEXT,
  zone TEXT NOT NULL DEFAULT '',
  capacity INTEGER,
  generation INTEGER NOT NULL DEFAULT 1,
  healthy INTEGER NOT NULL DEFAULT 1,
  role TEXT NOT NULL DEFAULT '',
  attrs_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS pt_resources (
  resource_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL DEFAULT 'link',
  capacity INTEGER,
  domain_id TEXT,
  metered INTEGER NOT NULL DEFAULT 0,
  authoritative INTEGER NOT NULL DEFAULT 0,
  healthy INTEGER NOT NULL DEFAULT 1,
  attrs_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS pt_ports (
  port_id TEXT PRIMARY KEY,
  node_id TEXT,
  page_id TEXT,
  reported_capacity INTEGER,
  physical_resource_id TEXT,
  attrs_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS pt_equivalence (
  resource_a TEXT NOT NULL,
  resource_b TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '',
  at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(resource_a, resource_b)
);
CREATE TABLE IF NOT EXISTS pt_hypotheses (
  hypothesis_id TEXT PRIMARY KEY,
  exclusive_group TEXT NOT NULL DEFAULT 'physical',
  status TEXT NOT NULL DEFAULT 'candidate',
  spec_json TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0,
  confirmed_at INTEGER
);
CREATE TABLE IF NOT EXISTS pt_link_probes (
  probe_id TEXT PRIMARY KEY,
  target_kind TEXT NOT NULL DEFAULT 'link',
  target_id TEXT NOT NULL,
  generation INTEGER NOT NULL DEFAULT 1,
  passed INTEGER,
  observed_at INTEGER NOT NULL DEFAULT 0,
  received_at INTEGER NOT NULL DEFAULT 0,
  origin TEXT NOT NULL DEFAULT 'independent-probe',
  digest TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'recorded',
  raw_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_pt_nodes_domain ON pt_nodes(domain_id);
CREATE INDEX IF NOT EXISTS idx_pt_resources_domain ON pt_resources(domain_id);
"""


def init_topology(db: sqlite3.Connection) -> sqlite3.Connection:
    """Install topology tables without touching the older control-plane schema."""
    db.row_factory = sqlite3.Row
    exists = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pt_hypotheses'"
    ).fetchone()
    if not exists:
        db.executescript(SCHEMA)
    node_columns = {row[1] for row in db.execute("PRAGMA table_info(pt_nodes)")}
    if node_columns and "generation" not in node_columns:
        db.execute("ALTER TABLE pt_nodes ADD COLUMN generation INTEGER NOT NULL DEFAULT 1")
    return db


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _load_json(value: str | None, default: Any) -> Any:
    if not value:
        return default
    return json.loads(value)


def _digest(value: Any) -> str:
    raw = _json(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _row(db: sqlite3.Connection, sql: str, params: tuple = ()) -> dict | None:
    found = db.execute(sql, params).fetchone()
    return dict(found) if found else None


def _rows(db: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(item) for item in db.execute(sql, params).fetchall()]


@contextmanager
def _transaction(db: sqlite3.Connection):
    outer = db.in_transaction
    if not outer:
        db.execute("BEGIN IMMEDIATE")
    try:
        yield
    except Exception:
        if not outer:
            db.rollback()
        raise
    else:
        if not outer:
            db.commit()


# ---------------------------------------------------------------------------
# Pure topology helpers.  These are intentionally usable without SQLite so a
# caller can evaluate candidate mappings from raw JSON artifacts.
# ---------------------------------------------------------------------------


def _mapping_aliases(spec: dict) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for key, value in (spec.get("aliases") or spec.get("maps") or spec.get("mapping") or {}).items():
        aliases[str(key)] = str(value)
    for group in spec.get("equivalence") or spec.get("equivalent") or []:
        members = [str(x) for x in group]
        if members:
            canonical = min(members)
            for member in members:
                aliases[member] = canonical
    return aliases


def canonical_in_mapping(resource_id: str, aliases: dict[str, str]) -> str:
    seen = set()
    current = str(resource_id)
    while current in aliases and current not in seen:
        seen.add(current)
        current = aliases[current]
    return current


def normalize_spec(topology: dict | None = None) -> dict:
    topology = dict(topology or {})
    capacities: dict[str, int | None] = {}
    domains: dict[str, str] = {}
    metered: set[str] = set()

    for section in ("capacities", "capacity"):
        value = topology.get(section)
        if isinstance(value, dict):
            for key, cap in value.items():
                capacities[str(key)] = None if cap is None else int(cap)

    for section in ("nodes", "resources", "links"):
        items = topology.get(section)
        if isinstance(items, dict):
            for key, item in items.items():
                key = str(key)
                if isinstance(item, (int, float)):
                    capacities.setdefault(key, int(item))
                elif isinstance(item, dict):
                    if item.get("capacity") is not None:
                        capacities[key] = int(item["capacity"])
                    if item.get("failure_domain") or item.get("domain_id") or item.get("domain"):
                        domains[key] = str(item.get("failure_domain") or item.get("domain_id") or item.get("domain"))
                    if item.get("metered"):
                        metered.add(key)
        elif isinstance(items, list):
            for item in items:
                if not isinstance(item, dict) or not item.get("id"):
                    continue
                key = str(item["id"])
                if item.get("capacity") is not None:
                    capacities[key] = int(item["capacity"])
                if item.get("failure_domain") or item.get("domain_id") or item.get("domain"):
                    domains[key] = str(item.get("failure_domain") or item.get("domain_id") or item.get("domain"))
                if item.get("metered"):
                    metered.add(key)

    if isinstance(topology.get("failure_domains"), dict):
        domains.update({str(k): str(v) for k, v in topology["failure_domains"].items()})

    paths: dict[str, list[str]] = {}
    raw_paths = topology.get("paths") or topology.get("routes") or {}
    if isinstance(raw_paths, dict):
        for key, path in raw_paths.items():
            if isinstance(path, dict):
                path = path.get("path") or path.get("resources") or path.get("links")
            paths[str(key)] = [str(x) for x in (path or [])]
    elif isinstance(raw_paths, list):
        for index, path in enumerate(raw_paths):
            if isinstance(path, dict):
                key = str(path.get("id") or path.get("path_id") or index)
                value = path.get("path") or path.get("resources") or path.get("links") or []
            else:
                key = str(index)
                value = path
            paths[key] = [str(x) for x in value]

    aliases = _mapping_aliases(topology)
    topology_id = str(topology.get("topology_id") or topology.get("id") or "")
    return {
        "topology_id": topology_id,
        "capacities": capacities,
        "domains": domains,
        "metered": sorted(metered),
        "paths": paths,
        "aliases": aliases,
        "raw": topology,
    }


def route_resources(route: dict | Iterable, spec: dict | None = None) -> list[str]:
    """Return the invariant resource identities used by one route."""
    if not isinstance(route, dict):
        route = {"path": list(route)}
    path_id = route.get("path_id") or route.get("route_path") or route.get("via")
    path = route.get("path") or route.get("resource_path") or route.get("resources") or route.get("links")
    normalized = normalize_spec(spec) if spec is not None else None
    if path is None and path_id and normalized and path_id in normalized["paths"]:
        path = normalized["paths"][path_id]
    if path is None and path_id and normalized and str(path_id) in normalized["paths"]:
        path = normalized["paths"][str(path_id)]
    if path is None and route.get("target") and normalized:
        path = normalized["paths"].get(str(route["target"]))
    result = [str(x) for x in (path or [])]
    # If a named path exists in the mapping, use its mapped concrete path.
    if not result and path_id and normalized:
        result = list(normalized["paths"].get(str(path_id), []))
    for endpoint in ("ingress", "entry", "source_node", "node", "target"):
        value = route.get(endpoint)
        if value is not None and str(value) not in result:
            result.insert(0 if endpoint in ("source_node",) else len(result), str(value))
    for endpoint in ("egress", "exit"):
        value = route.get(endpoint)
        if value is not None and str(value) not in result:
            result.append(str(value))
    return result


def route_demand(route: dict | int | float, default: int | None = None) -> int:
    if isinstance(route, (int, float)):
        return int(route)
    for key in ("demand", "bandwidth", "amount", "mbps", "units", "capacity"):
        if key in route and route[key] is not None:
            return int(route[key])
    if default is not None:
        return int(default)
    raise ValueError("route demand is required")


def canonical_route(route: dict | Iterable, spec: dict | None = None) -> list[str]:
    normalized = normalize_spec(spec) if spec is not None else normalize_spec({})
    aliases = normalized["aliases"]
    resources = route_resources(route, spec)
    return [canonical_in_mapping(x, aliases) for x in resources]


def check_routes(topology: dict | None, routes: list[dict] | dict | None = None) -> dict:
    """Check ingress, egress and every intermediate resource capacity."""
    if routes is None and isinstance(topology, list):
        # check_routes(routes) convenience form.
        routes = topology
        topology = {}
    spec = normalize_spec(topology)
    if isinstance(routes, dict):
        routes = routes.get("routes") or routes.get("assignments") or []
    routes = list(routes or [])

    loads: dict[str, int] = {}
    customers: dict[str, list[dict]] = {}
    route_results = []
    violations = []

    for index, item in enumerate(routes):
        if not isinstance(item, dict):
            item = {"path": list(item)}
        customer = str(item.get("customer_id") or item.get("customer") or item.get("id") or f"route-{index}")
        demand = route_demand(item)
        path = canonical_route(item, topology)
        # Aliases and repeated names for the same canonical physical resource
        # consume the route's bandwidth only once.
        unique_path = list(dict.fromkeys(path))
        route_violations = []
        for resource in unique_path:
            loads[resource] = loads.get(resource, 0) + demand
            customers.setdefault(resource, []).append({"customer_id": customer, "demand": demand})
            capacity = spec["capacities"].get(resource)
            if capacity is None:
                violation = {"type": "unknown_capacity", "resource": resource, "customer_id": customer}
                violations.append(violation)
                route_violations.append(violation)
            elif loads[resource] > capacity:
                violation = {
                    "type": "capacity_exceeded",
                    "resource": resource,
                    "capacity": capacity,
                    "load": loads[resource],
                    "over": loads[resource] - capacity,
                    "customer_id": customer,
                }
                violations.append(violation)
                route_violations.append(violation)
        route_results.append({"customer_id": customer, "demand": demand, "path": unique_path,
                              "violations": route_violations, "fits": not route_violations})

    available = {
        resource: spec["capacities"].get(resource, 0) - loads.get(resource, 0)
        for resource in spec["capacities"]
    }
    return {
        "feasible": not violations,
        "topology_id": spec["topology_id"],
        "loads": loads,
        "customers": customers,
        "available": available,
        "violations": violations,
        "routes": route_results,
    }


def robust_check(topologies: Iterable[dict] | dict | None, routes: list[dict]) -> dict:
    """Require one invariant route set to fit all compatible physical mappings."""
    if isinstance(topologies, dict):
        if "mappings" in topologies or "topologies" in topologies:
            topologies = topologies.get("mappings") or topologies.get("topologies")
        else:
            topologies = [topologies]
    topologies = list(topologies or [])
    checks = {}
    results = []
    used_keys = set()
    for index, topology in enumerate(topologies):
        result = check_routes(topology, routes)
        base_key = result["topology_id"] or f"mapping-{index}"
        key = base_key
        duplicate = 1
        while key in used_keys:
            duplicate += 1
            key = f"{base_key}-{duplicate}"
        used_keys.add(key)
        result["mapping_key"] = key
        result["mapping_index"] = index
        checks[key] = result
        results.append(result)
    feasible = bool(results) and all(item["feasible"] for item in results)
    worst_loads: dict[str, int] = {}
    for result in results:
        for resource, load in result["loads"].items():
            worst_loads[resource] = max(worst_loads.get(resource, 0), load)
    return {"feasible": feasible, "all_mappings_fit": feasible, "checks": checks,
            "results": results, "worst_loads": worst_loads, "mapping_count": len(results)}


def route_failure_domains(route: dict, topology: dict | None = None) -> list[str]:
    spec = normalize_spec(topology)
    path = canonical_route(route, topology)
    domains = []
    for resource in path:
        domain = spec["domains"].get(resource)
        if domain:
            domains.append(domain)
    return domains


def independent_route_set(topology: dict | None, routes: list[dict]) -> dict:
    """Routes are independent only when they share neither physical resource nor domain."""
    spec = normalize_spec(topology)
    resolved = []
    for item in routes:
        full_path = canonical_route(item, topology)
        # The final endpoint is the common egress/destination.  Its capacity is
        # still enforced by check_routes, but sharing that destination does not
        # make two distinct upstream paths non-independent.
        path = set(full_path[:-1] if len(full_path) > 1 else full_path)
        egress = full_path[-1] if full_path else None
        domains = {spec["domains"].get(x) for x in path if spec["domains"].get(x)}
        if egress and spec["domains"].get(egress):
            domains.discard(spec["domains"][egress])
        customer = str(item.get("customer_id") or item.get("customer") or item.get("id") or len(resolved))
        resolved.append((customer, path, domains))
    reasons = []
    for i, (customer_a, path_a, domains_a) in enumerate(resolved):
        for customer_b, path_b, domains_b in resolved[i + 1:]:
            shared_links = sorted(path_a & path_b)
            shared_domains = sorted(domains_a & domains_b)
            if shared_links:
                reasons.append({"customers": [customer_a, customer_b], "shared_resources": shared_links})
            if shared_domains:
                reasons.append({"customers": [customer_a, customer_b], "shared_domains": shared_domains})
    return {"independent": not reasons, "conflicts": reasons}


def maximum_flow(topology: dict, source: str, sink: str) -> dict:
    """Small Edmonds-Karp implementation with node capacity splitting."""
    spec = normalize_spec(topology)
    capacities: dict[tuple[str, str], int] = {}
    node_caps = spec["capacities"]

    def add_edge(u: str, v: str, cap: int):
        capacities[(u, v)] = capacities.get((u, v), 0) + max(0, int(cap))
        capacities.setdefault((v, u), 0)

    def in_node(node: str) -> str:
        return f"{node}::__in"

    def out_node(node: str) -> str:
        return f"{node}::__out"

    nodes = set(node_caps)
    raw = spec["raw"]
    edges = raw.get("edges") or raw.get("links") or []
    if isinstance(edges, dict):
        edges = [dict(item, id=key) if isinstance(item, dict) else {"id": key, "capacity": item}
                 for key, item in edges.items()]
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        u = str(edge.get("from") or edge.get("source") or edge.get("u"))
        v = str(edge.get("to") or edge.get("sink") or edge.get("v") or edge.get("target"))
        nodes.update((u, v))
        cap = edge.get("capacity")
        if cap is None:
            cap = node_caps.get(str(edge.get("id")))
        if cap is not None:
            add_edge(out_node(u), in_node(v), int(cap))

    for node in nodes:
        cap = node_caps.get(node)
        if cap is None:
            cap = 10**12
        add_edge(in_node(node), out_node(node), int(cap))

    source_n = out_node(source)
    sink_n = in_node(sink)
    if source == sink:
        return {"max_flow": 0, "flows": {}}

    flow = 0
    residual = dict(capacities)
    while True:
        parent = {source_n: None}
        queue = [source_n]
        for current in queue:
            for (u, v), cap in residual.items():
                if u != current or cap <= 0 or v in parent:
                    continue
                parent[v] = u
                queue.append(v)
                if v == sink_n:
                    break
            if sink_n in parent:
                break
        if sink_n not in parent:
            break
        add = 10**18
        v = sink_n
        while v != source_n:
            u = parent[v]
            add = min(add, residual[(u, v)])
            v = u
        v = sink_n
        while v != source_n:
            u = parent[v]
            residual[(u, v)] -= add
            residual[(v, u)] = residual.get((v, u), 0) + add
            v = u
        flow += add

    flows = {f"{u}->{v}": cap - residual.get((u, v), cap)
             for (u, v), cap in capacities.items() if cap - residual.get((u, v), cap) > 0}
    return {"max_flow": flow, "flows": flows}


# ---------------------------------------------------------------------------
# SQLite-backed identity registry.
# ---------------------------------------------------------------------------


class TopologyRegistry:
    def __init__(self, db: sqlite3.Connection | None = None):
        self.db = init_topology(db if db is not None else sqlite3.connect(":memory:"))

    def domain(self, domain_id: str, name: str = "", healthy: bool = True, **attrs) -> dict:
        domain_id = str(domain_id)
        with _transaction(self.db):
            old = _row(self.db, "SELECT * FROM pt_failure_domains WHERE domain_id=?", (domain_id,))
            if old:
                self.db.execute("UPDATE pt_failure_domains SET name=?,healthy=? WHERE domain_id=?",
                                (name or old["name"], int(healthy), domain_id))
            else:
                self.db.execute("INSERT INTO pt_failure_domains(domain_id,name,healthy,attrs_json) VALUES(?,?,?,?)",
                                (domain_id, name, int(healthy), _json(attrs)))
        return decision("registered", "failure domain recorded", domain_id=domain_id)

    def fail_domain(self, domain_id: str, at: int = 0) -> dict:
        with _transaction(self.db):
            found = _row(self.db, "SELECT * FROM pt_failure_domains WHERE domain_id=?", (domain_id,))
            if not found:
                return decision("missing", "failure domain does not exist", domain_id=domain_id)
            self.db.execute("UPDATE pt_failure_domains SET healthy=0,status='failed' WHERE domain_id=?",
                            (domain_id,))
            nodes = _rows(self.db, "SELECT node_id FROM pt_nodes WHERE domain_id=?", (domain_id,))
        return decision("failed", "whole failure domain is unavailable for independent redundancy",
                        domain_id=domain_id, nodes=[x["node_id"] for x in nodes], at=at)

    def node(self, node_id: str, capacity: int | None = None, domain_id: str | None = None,
             healthy: bool = True, zone: str = "", role: str = "", generation: int = 1, **attrs) -> dict:
        node_id = str(node_id)
        with _transaction(self.db):
            self.db.execute(
                "INSERT INTO pt_nodes(node_id,domain_id,zone,capacity,generation,healthy,role,attrs_json) "
                "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET "
                "domain_id=excluded.domain_id,zone=excluded.zone,capacity=excluded.capacity,"
                "generation=excluded.generation,healthy=excluded.healthy,role=excluded.role,"
                "attrs_json=excluded.attrs_json",
                (node_id, domain_id, zone, capacity, int(generation), int(healthy), role, _json(attrs)),
            )
        return decision("registered", "node identity recorded", node_id=node_id, generation=int(generation))

    def resource(self, resource_id: str, capacity: int | None = None, kind: str = "link",
                 domain_id: str | None = None, metered: bool = False, authoritative: bool = False,
                 healthy: bool = True, **attrs) -> dict:
        resource_id = str(resource_id)
        with _transaction(self.db):
            self.db.execute(
                "INSERT INTO pt_resources(resource_id,kind,capacity,domain_id,metered,authoritative,"
                "healthy,attrs_json) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(resource_id) DO UPDATE SET "
                "kind=excluded.kind,capacity=COALESCE(excluded.capacity,pt_resources.capacity),"
                "domain_id=COALESCE(excluded.domain_id,pt_resources.domain_id),"
                "metered=excluded.metered,authoritative=excluded.authoritative,"
                "healthy=excluded.healthy,attrs_json=excluded.attrs_json",
                (resource_id, kind, capacity, domain_id, int(metered), int(authoritative),
                 int(healthy), _json(attrs)),
            )
        return decision("registered", "physical or observed bandwidth resource recorded",
                        resource_id=resource_id)

    def alias_port(self, port_id: str, physical_resource_id: str, node_id: str | None = None,
                   page_id: str | None = None, reported_capacity: int | None = None, **attrs) -> dict:
        port_id, physical_resource_id = str(port_id), str(physical_resource_id)
        with _transaction(self.db):
            self.db.execute(
                "INSERT INTO pt_ports(port_id,node_id,page_id,reported_capacity,physical_resource_id,attrs_json) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(port_id) DO UPDATE SET "
                "node_id=excluded.node_id,page_id=excluded.page_id,"
                "reported_capacity=excluded.reported_capacity,"
                "physical_resource_id=excluded.physical_resource_id,attrs_json=excluded.attrs_json",
                (port_id, node_id, page_id, reported_capacity, physical_resource_id, _json(attrs)),
            )
            self._equate_now(port_id, physical_resource_id, "port-alias", 0)
        return decision("aliased", "port name resolves to one physical link identity",
                        port_id=port_id, physical_resource_id=physical_resource_id,
                        canonical_resource_id=self.canonical(port_id))

    def _equate_now(self, a: str, b: str, evidence: str = "", at: int = 0):
        a, b = str(a), str(b)
        if a == b:
            return
        low, high = sorted((a, b))
        self.db.execute(
            "INSERT OR IGNORE INTO pt_equivalence(resource_a,resource_b,evidence,at) VALUES(?,?,?,?)",
            (low, high, evidence, int(at)),
        )

    def equate(self, resource_a: str, resource_b: str, evidence: str = "", at: int = 0) -> dict:
        with _transaction(self.db):
            self._equate_now(resource_a, resource_b, evidence, at)
            canonical = self.canonical(resource_a)
        return decision("equated", "physical link equivalence recorded",
                        canonical_resource_id=canonical,
                        equivalence_class=self.equivalence_class(resource_a))

    # Common domain-language aliases.
    declare_equivalence = equate
    add_equivalence = equate

    def canonical(self, resource_id: str) -> str:
        resource_id = str(resource_id)
        pairs = _rows(self.db, "SELECT resource_a,resource_b FROM pt_equivalence")
        parent: dict[str, str] = {}

        def find(x: str) -> str:
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)

        for pair in pairs:
            union(pair["resource_a"], pair["resource_b"])
        # Every registered port alias participates in the same equivalence graph.
        for port in _rows(self.db, "SELECT port_id,physical_resource_id FROM pt_ports"):
            if port["physical_resource_id"]:
                union(port["port_id"], port["physical_resource_id"])

        root = find(resource_id)
        members = [member for member in list(parent) if find(member) == root]
        if resource_id not in members:
            members.append(resource_id)
        placeholders = ",".join("?" for _ in members)
        resources = _rows(
            self.db,
            f"SELECT resource_id,authoritative FROM pt_resources WHERE resource_id IN ({placeholders})",
            tuple(members),
        ) if members else []
        authoritative = sorted(row["resource_id"] for row in resources if row["authoritative"])
        if authoritative:
            return authoritative[0]
        registered = sorted(row["resource_id"] for row in resources)
        if registered:
            # A registered bandwidth identity is preferable to a raw port name.
            return registered[0]
        return root

    canonical_link = canonical
    canonical_resource = canonical

    def equivalent(self, a: str, b: str) -> bool:
        return self.canonical(a) == self.canonical(b)

    same_physical_link = equivalent

    def equivalence_class(self, resource_id: str) -> list[str]:
        target = self.canonical(resource_id)
        ids = {str(resource_id)}
        for pair in _rows(self.db, "SELECT resource_a,resource_b FROM pt_equivalence"):
            ids.update((pair["resource_a"], pair["resource_b"]))
        for port in _rows(self.db, "SELECT port_id,physical_resource_id FROM pt_ports"):
            if port["physical_resource_id"]:
                ids.update((port["port_id"], port["physical_resource_id"]))
        return sorted(x for x in ids if self.canonical(x) == target)

    def equivalence_classes(self) -> list[list[str]]:
        ids = set()
        for row in _rows(self.db, "SELECT resource_a,resource_b FROM pt_equivalence"):
            ids.update((row["resource_a"], row["resource_b"]))
        for row in _rows(self.db, "SELECT port_id,physical_resource_id FROM pt_ports"):
            ids.add(row["port_id"])
            if row["physical_resource_id"]:
                ids.add(row["physical_resource_id"])
        groups: dict[str, list[str]] = {}
        for resource_id in ids:
            groups.setdefault(self.canonical(resource_id), []).append(resource_id)
        return [sorted(members) for members in sorted(groups.values(), key=lambda x: x[0])]

    def effective_capacity(self, resource_id: str) -> int | None:
        canonical = self.canonical(resource_id)
        members = self.equivalence_class(resource_id)
        rows = _rows(self.db, "SELECT resource_id,capacity,authoritative,kind FROM pt_resources")
        by_id = {row["resource_id"]: row for row in rows}
        for node in _rows(self.db, "SELECT node_id AS resource_id,capacity,0 AS authoritative,'node' AS kind FROM pt_nodes"):
            by_id.setdefault(node["resource_id"], node)
        capacities = []
        physical = []
        for member in members + [canonical]:
            row = by_id.get(member)
            if not row or row["capacity"] is None:
                continue
            capacities.append(int(row["capacity"]))
            if row["authoritative"] or row["kind"] == "physical":
                physical.append(int(row["capacity"]))
        if physical:
            return min(physical)
        return min(capacities) if capacities else None

    def add_hypothesis(self, hypothesis_id: str, spec: dict, status: str = "candidate",
                       exclusive_group: str = "physical", evidence: str = "", at: int = 0) -> dict:
        hypothesis_id = str(hypothesis_id)
        raw = _json(spec)
        with _transaction(self.db):
            old = _row(self.db, "SELECT spec_json FROM pt_hypotheses WHERE hypothesis_id=?", (hypothesis_id,))
            if old:
                if old["spec_json"] != raw:
                    raise ValueError("topology_hypothesis_conflict")
                return decision("replayed", "topology mapping already recorded", hypothesis_id=hypothesis_id)
            self.db.execute(
                "INSERT INTO pt_hypotheses(hypothesis_id,exclusive_group,status,spec_json,evidence,"
                "created_at,confirmed_at) VALUES(?,?,?,?,?,?,?)",
                (hypothesis_id, exclusive_group, status, raw, evidence, int(at),
                 int(at) if status == "confirmed" else None),
            )
        return decision("recorded", "compatible topology mapping saved", hypothesis_id=hypothesis_id,
                        mapping_status=status)

    add_topology = add_hypothesis
    register_mapping = add_hypothesis

    def confirm_hypothesis(self, hypothesis_id: str, evidence: str = "fibre-end-to-end-test",
                           at: int = 0, reject_others: bool = True) -> dict:
        with _transaction(self.db):
            found = _row(self.db, "SELECT * FROM pt_hypotheses WHERE hypothesis_id=?", (hypothesis_id,))
            if not found:
                return decision("missing", "topology hypothesis does not exist", hypothesis_id=hypothesis_id)
            prior = _row(
                self.db,
                "SELECT hypothesis_id FROM pt_hypotheses WHERE exclusive_group=? AND status='confirmed' LIMIT 1",
                (found["exclusive_group"],),
            )
            if prior and prior["hypothesis_id"] != hypothesis_id:
                return decision("conflict",
                                "a different physical topology is already proven; use a new topology generation",
                                confirmed_hypothesis_id=prior["hypothesis_id"],
                                requested_hypothesis_id=hypothesis_id)
            self.db.execute(
                "UPDATE pt_hypotheses SET status='confirmed',evidence=?,confirmed_at=? WHERE hypothesis_id=?",
                (evidence, int(at), hypothesis_id),
            )
            rejected = []
            if reject_others:
                others = _rows(self.db,
                               "SELECT hypothesis_id FROM pt_hypotheses WHERE exclusive_group=? "
                               "AND hypothesis_id<>? AND status<>'rejected'",
                               (found["exclusive_group"], hypothesis_id))
                for other in others:
                    self.db.execute("UPDATE pt_hypotheses SET status='rejected' WHERE hypothesis_id=?",
                                    (other["hypothesis_id"],))
                    rejected.append(other["hypothesis_id"])
                spec = json.loads(found["spec_json"])
                for a, b in spec.get("confirm_equivalence", []):
                    self._equate_now(a, b, evidence, at)
                for key, value in (spec.get("aliases") or spec.get("maps") or {}).items():
                    self._equate_now(key, value, evidence, at)
        return decision("confirmed", "physical topology proven; incompatible mappings rejected",
                        hypothesis_id=hypothesis_id, rejected=rejected)

    confirm_topology = confirm_hypothesis
    prove_topology = confirm_hypothesis

    def compatible_hypotheses(self) -> list[dict]:
        rows = _rows(self.db, "SELECT * FROM pt_hypotheses ORDER BY hypothesis_id")
        confirmed = [row for row in rows if row["status"] == "confirmed"]
        selected = confirmed or [row for row in rows if row["status"] == "candidate"]
        result = []
        for row in selected:
            spec = json.loads(row["spec_json"])
            spec.setdefault("topology_id", row["hypothesis_id"])
            result.append(spec)
        return result

    compatible_topologies = compatible_hypotheses
    mappings = compatible_hypotheses

    def db_spec(self) -> dict:
        capacities: dict[str, int | None] = {}
        domains: dict[str, str] = {}
        metered = []
        for row in _rows(self.db, "SELECT node_id,capacity,domain_id FROM pt_nodes"):
            capacities[row["node_id"]] = row["capacity"]
            if row["domain_id"]:
                domains[row["node_id"]] = row["domain_id"]
        for row in _rows(self.db, "SELECT resource_id,capacity,domain_id,metered FROM pt_resources"):
            capacities[row["resource_id"]] = row["capacity"]
            if row["domain_id"]:
                domains[row["resource_id"]] = row["domain_id"]
            if row["metered"]:
                metered.append(row["resource_id"])
        return {"topology_id": "registered", "capacities": capacities, "failure_domains": domains,
                "metered": metered}

    def record_probe(self, probe_id: str, target_id: str, passed: bool | None = True,
                     generation: int = 1, at: int = 0, received_at: int | None = None,
                     origin: str = "independent-probe", raw: dict | None = None,
                     target_kind: str = "link") -> dict:
        raw = raw or {}
        digest = _digest(raw)
        with _transaction(self.db):
            old = _row(self.db, "SELECT * FROM pt_link_probes WHERE probe_id=?", (probe_id,))
            if old:
                return decision("replayed", "link probe already stored", probe_id=probe_id,
                                probe_status=old["status"])
            status = "passed" if passed else "failed" if passed is False else "observed"
            self.db.execute(
                "INSERT INTO pt_link_probes(probe_id,target_kind,target_id,generation,passed,"
                "observed_at,received_at,origin,digest,status,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (probe_id, target_kind, target_id, int(generation),
                 None if passed is None else int(bool(passed)), int(at),
                 int(at if received_at is None else received_at), origin, digest, status, _json(raw)),
            )
        return decision(status, "link probe original evidence stored", probe_id=probe_id, digest=digest)

    capture_link_probe = record_probe


# Module-level function facade.
def registry(db: sqlite3.Connection) -> TopologyRegistry:
    return TopologyRegistry(db)


def build_topology(db: sqlite3.Connection | None = None, spec: dict | None = None,
                   hypothesis_id: str = "topology"):
    """Build a registry (persistent when db is supplied) or normalized spec."""
    if db is None:
        return normalize_spec(spec or {})
    reg = TopologyRegistry(db)
    if spec is not None:
        reg.add_hypothesis(hypothesis_id or spec.get("topology_id") or spec.get("id"), spec)
    return reg


create_topology = build_topology


def _payload(payload: dict | None, kwargs: dict) -> dict:
    data = dict(payload or {})
    data.update({k: v for k, v in kwargs.items() if v is not None})
    return data


def register_failure_domain(db, payload: dict | str | None = None, **kwargs):
    if isinstance(payload, str):
        payload = {"domain_id": payload}
    p = _payload(payload, kwargs)
    return TopologyRegistry(db).domain(p.get("domain_id") or p.get("id"), p.get("name", ""),
                                       p.get("healthy", True), **{k: v for k, v in p.items()
                                                                  if k not in ("domain_id", "id", "name", "healthy")})


add_failure_domain = register_failure_domain
add_domain = register_failure_domain
create_domain = register_failure_domain
declare_domain = register_failure_domain


def fail_domain(db, payload: dict | str | None = None, **kwargs):
    if isinstance(payload, str):
        payload = {"domain_id": payload}
    p = _payload(payload, kwargs)
    return TopologyRegistry(db).fail_domain(p.get("domain_id") or p.get("id"), int(p.get("at", 0)))


def register_node(db, payload: dict | str | None = None, capacity=None, domain_id=None, **kwargs):
    if not isinstance(payload, dict):
        payload = {"node_id": payload, "capacity": capacity, "domain_id": domain_id, **kwargs}
    p = _payload(payload, kwargs)
    return TopologyRegistry(db).node(p.get("node_id") or p.get("id"), p.get("capacity"),
                                    p.get("domain_id") or p.get("failure_domain"),
                                    p.get("healthy", True), p.get("zone", ""), p.get("role", ""),
                                    int(p.get("generation", 1)))


add_node = register_node


def register_resource(db, payload: dict | str | None = None, capacity=None, kind=None,
                      domain_id=None, **kwargs):
    if not isinstance(payload, dict):
        payload = {"resource_id": payload, "capacity": capacity, "kind": kind or "link",
                   "domain_id": domain_id, **kwargs}
    p = _payload(payload, kwargs)
    return TopologyRegistry(db).resource(
        p.get("resource_id") or p.get("link_id") or p.get("id"), p.get("capacity"),
        p.get("kind", "link"), p.get("domain_id") or p.get("failure_domain"),
        bool(p.get("metered", False)), bool(p.get("authoritative", False)), p.get("healthy", True))


add_link = register_resource
register_link = register_resource
register_physical_link = register_resource
add_physical_link = register_resource


def alias_port(db, payload: dict | str | None = None, physical_resource_id: str | None = None, **kwargs):
    if isinstance(payload, str):
        payload = {"port_id": payload, "physical_resource_id": physical_resource_id}
    p = _payload(payload, kwargs)
    return TopologyRegistry(db).alias_port(
        p.get("port_id") or p.get("port"), p.get("physical_resource_id") or p.get("resource_id") or p.get("link_id"),
        p.get("node_id"), p.get("page_id"), p.get("reported_capacity"))


add_port_alias = alias_port
bind_alias = alias_port


def equate(db, resource_a=None, resource_b=None, payload: dict | None = None, **kwargs):
    if isinstance(resource_a, dict) and payload is None:
        payload = resource_a
        resource_a = None
    p = _payload(payload, kwargs)
    a = resource_a or p.get("resource_a") or p.get("left") or p.get("a")
    b = resource_b or p.get("resource_b") or p.get("right") or p.get("b")
    return TopologyRegistry(db).equate(a, b, p.get("evidence", ""), int(p.get("at", 0)))


equate_links = equate
declare_equivalence = equate
add_equivalence = equate


def canonical_link(db, resource_id):
    return TopologyRegistry(db).canonical(resource_id)


def equivalent(db, a, b):
    return TopologyRegistry(db).equivalent(a, b)


def add_hypothesis(db, payload: dict | str | None = None, spec: dict | None = None, **kwargs):
    if isinstance(payload, str):
        payload = {"hypothesis_id": payload, "spec": spec or {}}
    p = _payload(payload, kwargs)
    return TopologyRegistry(db).add_hypothesis(
        p.get("hypothesis_id") or p.get("topology_id") or p.get("id"),
        p.get("spec") or p.get("topology") or {k: v for k, v in p.items()
                                               if k not in ("hypothesis_id", "topology_id", "id", "status",
                                                            "evidence", "at", "exclusive_group")},
        p.get("status", "candidate"), p.get("exclusive_group", "physical"),
        p.get("evidence", ""), int(p.get("at", 0)))


register_topology = add_hypothesis
add_topology = add_hypothesis


def confirm_hypothesis(db, payload: dict | str | None = None, evidence: str | None = None, **kwargs):
    if isinstance(payload, str):
        payload = {"hypothesis_id": payload, "evidence": evidence}
    p = _payload(payload, kwargs)
    return TopologyRegistry(db).confirm_hypothesis(
        p.get("hypothesis_id") or p.get("topology_id") or p.get("id"),
        p.get("evidence", "fibre-end-to-end-test"), int(p.get("at", 0)))


confirm_topology = confirm_hypothesis
prove_topology = confirm_hypothesis


def record_link_probe(db, payload: dict | str | None = None, *args, **kwargs):
    if not isinstance(payload, dict):
        positional = list(args)
        payload = {
            "probe_id": payload,
            "target_id": kwargs.pop("target_id", positional.pop(0) if positional else None),
            "passed": kwargs.pop("passed", positional.pop(0) if positional else True),
        }
        if positional:
            payload["generation"] = positional.pop(0)
        if positional:
            payload["at"] = positional.pop(0)
    p = _payload(payload, kwargs)
    return TopologyRegistry(db).record_probe(
        p.get("probe_id") or p.get("id"), p.get("target_id") or p.get("link_id"),
        p.get("passed", True), int(p.get("generation", 1)), int(p.get("at", 0)),
        p.get("received_at"), p.get("origin", "independent-probe"),
        p.get("raw") or p.get("payload"), p.get("target_kind", "link"))


capture_link_probe = record_link_probe
record_probe_result = record_link_probe
capture_probe_result = record_link_probe
declare_port_alias = alias_port
confirm_physical_topology = confirm_hypothesis
prove_physical_topology = confirm_hypothesis
record_probe = record_link_probe


HANDLERS = {
    "register": register_node,
    "register_domain": register_failure_domain,
    "add_failure_domain": register_failure_domain,
    "fail_domain": fail_domain,
    "register_node": register_node,
    "node": register_node,
    "register_resource": register_resource,
    "register_link": register_resource,
    "add_link": register_resource,
    "link": register_resource,
    "alias": alias_port,
    "alias_port": alias_port,
    "equate": equate,
    "equate_links": equate,
    "add_hypothesis": add_hypothesis,
    "register_topology": register_topology,
    "topology": add_hypothesis,
    "confirm_hypothesis": confirm_hypothesis,
    "confirm_topology": confirm_topology,
    "prove": confirm_hypothesis,
    "prove_topology": confirm_hypothesis,
    "record_probe": record_link_probe,
    "capture": record_link_probe,
    "capture_probe": record_link_probe,
    "capture_link_probe": record_link_probe,
    "link_probe": record_link_probe,
}


# Descriptive class aliases used by different entry points and tests.
PhysicalTopology = TopologyRegistry
Topology = TopologyRegistry
LinkTopology = TopologyRegistry
FailoverTopology = TopologyRegistry
PhysicalLinkTopology = TopologyRegistry
TopologyModel = TopologyRegistry
FailureDomainTopology = TopologyRegistry
LinkRegistry = TopologyRegistry
TopologyStore = TopologyRegistry
TopologyService = TopologyRegistry
TopologyManager = TopologyRegistry


def plan_route(topology: dict | None = None, route: dict | None = None, **kwargs):
    """Convenience wrapper returning the capacity proof for one route."""
    if route is None and topology is not None and not isinstance(topology, dict):
        # plan_route(route) calling style.
        route = topology
        topology = {}
    if route is None:
        route = kwargs
    return check_routes(topology, [route])


def route_fits(topology: dict, route: dict) -> bool:
    return bool(check_routes(topology, [route])["feasible"])


def all_mappings_fit(topologies, routes) -> dict:
    return robust_check(topologies, routes)


find_route = plan_route
evaluate_route = plan_route
