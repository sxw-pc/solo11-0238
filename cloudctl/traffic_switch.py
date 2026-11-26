"""Executable physical traffic takeover protocol.

State discipline:

* planning proves one invariant route against every compatible topology map;
* preparation holds real capacity in SQLite before a network command is sent;
* a controller receipt only records that a rule was written;
* an independent probe is required before a customer link is "taken over";
* command generations and ids make receipt/probe retries idempotent;
* SLA certificates are append-only.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from typing import Any

from .db import decision
from .physical_topology import (
    TopologyRegistry,
    canonical_in_mapping,
    independent_route_set,
    normalize_spec,
    robust_check,
    route_resources,
)


RESERVED_STATES = ("held", "written", "active", "release_pending")
COUNTED_STATES = RESERVED_STATES
TERMINAL_COMMAND_STATES = ("confirmed", "revoked", "failed", "stale")


SCHEMA = """
CREATE TABLE IF NOT EXISTS ts_plans (
  plan_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ts_customers (
  customer_id TEXT PRIMARY KEY,
  demand INTEGER NOT NULL,
  minimum_bandwidth INTEGER,
  max_latency_ms INTEGER,
  attrs_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ts_routes (
  route_id TEXT PRIMARY KEY,
  plan_id TEXT,
  customer_id TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  kind TEXT NOT NULL DEFAULT 'primary',
  path_id TEXT,
  path_json TEXT NOT NULL,
  demand INTEGER NOT NULL,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'planned',
  topology_id TEXT,
  old_route_id TEXT,
  created_at INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ts_reservations (
  reservation_id TEXT PRIMARY KEY,
  route_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  canonical_resource_id TEXT NOT NULL,
  amount INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'held',
  command_id TEXT,
  idempotency_key TEXT,
  created_at INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(route_id, canonical_resource_id)
);
CREATE TABLE IF NOT EXISTS ts_commands (
  command_id TEXT PRIMARY KEY,
  idempotency_key TEXT UNIQUE,
  sequence_no INTEGER NOT NULL,
  route_id TEXT,
  customer_id TEXT,
  plan_id TEXT,
  kind TEXT NOT NULL,
  generation INTEGER NOT NULL DEFAULT 1,
  predecessor_command_id TEXT,
  status TEXT NOT NULL DEFAULT 'planned',
  success INTEGER,
  receipt_id TEXT,
  receipt_json TEXT,
  receipt_at INTEGER,
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ts_receipts (
  receipt_id TEXT PRIMARY KEY,
  command_id TEXT NOT NULL,
  generation INTEGER,
  success INTEGER NOT NULL,
  status TEXT NOT NULL,
  at INTEGER NOT NULL DEFAULT 0,
  payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS ts_probes (
  probe_id TEXT PRIMARY KEY,
  command_id TEXT NOT NULL,
  generation INTEGER,
  passed INTEGER,
  independent INTEGER NOT NULL DEFAULT 1,
  origin TEXT NOT NULL DEFAULT 'independent-probe',
  observed_at INTEGER NOT NULL DEFAULT 0,
  received_at INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS ts_customer_links (
  customer_id TEXT PRIMARY KEY,
  current_route_id TEXT,
  pending_route_id TEXT,
  taken_over INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'pending',
  actual_path_json TEXT NOT NULL DEFAULT '[]',
  latency_ms INTEGER NOT NULL DEFAULT 0,
  sla_id TEXT,
  generation INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ts_sla_certificates (
  sla_id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  route_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  bandwidth INTEGER NOT NULL,
  minimum_bandwidth INTEGER,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  physical_path_json TEXT NOT NULL DEFAULT '[]',
  payload_json TEXT NOT NULL,
  issued_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(customer_id, version),
  UNIQUE(route_id)
);
CREATE TABLE IF NOT EXISTS ts_audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL DEFAULT 0,
  action TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  generation INTEGER,
  detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ts_resources_route ON ts_reservations(route_id);
CREATE INDEX IF NOT EXISTS ts_commands_route ON ts_commands(route_id, kind, generation);
CREATE INDEX IF NOT EXISTS ts_probes_command ON ts_probes(command_id);
"""


def init_switch(db: sqlite3.Connection) -> sqlite3.Connection:
    db.row_factory = sqlite3.Row
    existing = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('ts_plans','pt_hypotheses')"
    )}
    if not {"ts_plans", "pt_hypotheses"}.issubset(existing):
        db.executescript(SCHEMA)
    # Lightweight additive migration for long-lived local databases.
    columns = {row[1] for row in db.execute("PRAGMA table_info(ts_customer_links)")}
    if "pending_route_id" not in columns:
        db.execute("ALTER TABLE ts_customer_links ADD COLUMN pending_route_id TEXT")
    if "state" not in columns:
        db.execute("ALTER TABLE ts_customer_links ADD COLUMN state TEXT NOT NULL DEFAULT 'pending'")
    TopologyRegistry(db)
    return db


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _row(db, sql, params=()):
    found = db.execute(sql, params).fetchone()
    return dict(found) if found else None


def _rows(db, sql, params=()):
    return [dict(item) for item in db.execute(sql, params).fetchall()]


@contextmanager
def _tx(db):
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


def _data(payload, kwargs=None, default_key=None):
    if isinstance(payload, dict):
        data = dict(payload)
    elif payload is None:
        data = {}
    else:
        data = {default_key or "id": payload}
    if kwargs:
        data.update({k: v for k, v in kwargs.items() if v is not None})
    return data


def _at(p: dict) -> int:
    return int(p.get("at") or p.get("observed_at") or p.get("time") or p.get("issued_at") or 0)


class TrafficSwitch:
    """Database-backed failover protocol."""

    def __init__(self, db: sqlite3.Connection | None = None):
        self.db = init_switch(db if db is not None else sqlite3.connect(":memory:"))
        self.topo = TopologyRegistry(self.db)

    # ------------------------------------------------------------------
    # Low-level evidence and setup.
    # ------------------------------------------------------------------

    def audit(self, action: str, aggregate_id: str, detail: dict | None = None,
              generation: int | None = None, at: int = 0):
        self.db.execute(
            "INSERT INTO ts_audit(at,action,aggregate_id,generation,detail_json) VALUES(?,?,?,?,?)",
            (int(at), action, str(aggregate_id), generation, _json(detail or {})),
        )

    def add_customer(self, payload: dict | None = None, **kwargs):
        p = _data(payload, kwargs, "customer_id")
        customer_id = str(p.get("customer_id") or p.get("id"))
        demand = int(p.get("demand", p.get("bandwidth", p.get("minimum_bandwidth", 0))))
        minimum = p.get("minimum_bandwidth", p.get("minimum", p.get("min_bandwidth", demand)))
        with _tx(self.db):
            old = _row(self.db, "SELECT * FROM ts_customers WHERE customer_id=?", (customer_id,))
            if old:
                return decision("replayed", "customer already registered", customer_id=customer_id)
            self.db.execute(
                "INSERT INTO ts_customers(customer_id,demand,minimum_bandwidth,max_latency_ms,attrs_json,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (customer_id, demand, int(minimum), p.get("max_latency_ms") or p.get("latency_budget"),
                 _json(p.get("attrs") or {}), _at(p)),
            )
            self.audit("customer.registered", customer_id, {"demand": demand}, at=_at(p))
        return decision("registered", "customer bandwidth identity recorded", customer_id=customer_id, demand=demand)

    register_customer = add_customer

    def adopt_active_route(self, payload: dict | None = None, **kwargs):
        """Record an already-taken-over route and its real active reservations."""
        p = _data(payload, kwargs, "route_id")
        route_id = str(p.get("route_id") or p.get("id"))
        customer_id = str(p.get("customer_id") or p.get("customer"))
        demand = int(p.get("demand") or p.get("bandwidth") or 0)
        path = [str(x) for x in (p.get("path") or p.get("resources") or [])]
        if not path and p.get("resource_id"):
            path = [str(p["resource_id"])]
        latency = int(p.get("latency_ms", p.get("latency", 0)))
        at = _at(p)
        with _tx(self.db):
            if _row(self.db, "SELECT route_id FROM ts_routes WHERE route_id=?", (route_id,)):
                return decision("replayed", "route already adopted", route_id=route_id)
            self.db.execute(
                "INSERT INTO ts_routes(route_id,plan_id,customer_id,version,kind,path_id,path_json,demand,"
                "latency_ms,status,topology_id,old_route_id,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,'active',?,?,?,?)",
                (route_id, p.get("plan_id"), customer_id, int(p.get("version", 1)),
                 p.get("kind", "primary"), p.get("path_id"), _json(path), demand, latency,
                 p.get("topology_id"), p.get("old_route_id"), at, at),
            )
            for resource in dict.fromkeys(self.topo.canonical(x) for x in path):
                rid = f"res:{route_id}:{resource}"
                self.db.execute(
                    "INSERT INTO ts_reservations(reservation_id,route_id,customer_id,resource_id,"
                    "canonical_resource_id,amount,status,created_at,updated_at) VALUES(?,?,?,?,?,?,'active',?,?)",
                    (rid, route_id, customer_id, resource, resource, demand, at, at),
                )
            command_id = p.get("command_id") or f"cmd:{route_id}:reserve:1"
            self.db.execute(
                "INSERT OR IGNORE INTO ts_commands(command_id,idempotency_key,sequence_no,route_id,customer_id,"
                "kind,generation,status,success,receipt_id,receipt_json,receipt_at,payload_json,created_at,updated_at) "
                "VALUES(?,?,?,?,?, 'reserve',1,'confirmed',1,?,?,?,?,?,?)",
                (command_id, command_id, self._next_sequence(), route_id, customer_id,
                 p.get("receipt_id") or f"receipt:{command_id}", _json({"adopted": True}), at,
                 _json({"adopted": True}), at, at),
            )
            self.db.execute(
                "INSERT OR IGNORE INTO ts_probes(probe_id,command_id,generation,passed,independent,status,payload_json) "
                "VALUES(?,?,1,1,1,'confirmed',?)",
                (p.get("probe_id") or f"probe:{command_id}", command_id, _json({"adopted": True})),
            )
            self._upsert_customer_link(route_id, customer_id, path, latency, at)
            sla = self._issue_sla(route_id, at, certificate_id=p.get("sla_id"))
            self.audit("route.adopted", route_id, {"customer_id": customer_id, "path": path}, at=at)
        return self.customer_link(customer_id)

    # ------------------------------------------------------------------
    # Planning.
    # ------------------------------------------------------------------

    def _next_sequence(self) -> int:
        row = _row(self.db, "SELECT COALESCE(MAX(sequence_no),0)+1 AS n FROM ts_commands")
        return int(row["n"])

    def _mappings(self, p: dict) -> list[dict]:
        explicit = p.get("mappings") or p.get("topologies")
        if explicit is not None:
            mappings = explicit if isinstance(explicit, list) else [explicit]
        else:
            ids = p.get("topology_ids") or ([p["topology_id"]] if p.get("topology_id") else None)
            if ids:
                mappings = []
                for topology_id in ids:
                    row = _row(self.db, "SELECT spec_json FROM pt_hypotheses WHERE hypothesis_id=?", (str(topology_id),))
                    if row:
                        spec = json.loads(row["spec_json"])
                        spec.setdefault("topology_id", str(topology_id))
                        mappings.append(spec)
            else:
                mappings = self.topo.compatible_hypotheses()
        base = self.topo.db_spec()
        merged = []
        for mapping in mappings or [{}]:
            spec = dict(mapping)
            spec["capacities"] = {**base.get("capacities", {}), **(mapping.get("capacities") or {})}
            spec["failure_domains"] = {**base.get("failure_domains", {}), **(mapping.get("failure_domains") or {})}
            if not spec.get("topology_id"):
                spec["topology_id"] = mapping.get("topology_id") or mapping.get("id") or "registered"
            merged.append(spec)
        return merged

    def _route_items(self, p: dict, plan_id: str) -> list[dict]:
        routes = p.get("routes") or p.get("assignments") or p.get("customers") or []
        if isinstance(routes, dict):
            routes = [dict(customer_id=key, **(value if isinstance(value, dict) else {"demand": value}))
                      for key, value in routes.items()]
        result = []
        for index, item in enumerate(routes):
            if not isinstance(item, dict):
                item = {"customer_id": str(item)}
            customer_id = str(item.get("customer_id") or item.get("customer") or item.get("id") or f"C{index}")
            customer = _row(self.db, "SELECT * FROM ts_customers WHERE customer_id=?", (customer_id,))
            demand = item.get("demand") or item.get("bandwidth") or item.get("amount")
            if demand is None and customer:
                demand = customer["demand"]
            if demand is None:
                raise ValueError(f"demand required for customer {customer_id}")
            route_id = str(item.get("route_id") or f"{plan_id}:{customer_id}")
            path = item.get("path") or item.get("resources") or item.get("resource_path")
            if path is None:
                # Resolve named target/path through the first available mapping.
                mappings = self._mappings(p)
                path = []
                for mapping in mappings:
                    resolved = route_resources(item, mapping)
                    if resolved:
                        path = resolved
                        break
            result.append({
                "route_id": route_id,
                "customer_id": customer_id,
                "demand": int(demand),
                "path": [str(x) for x in (path or [])],
                "path_id": item.get("path_id") or item.get("target") or item.get("via"),
                "latency_ms": int(item.get("latency_ms", item.get("latency", 0))),
                "kind": item.get("kind", "primary"),
                "topology_id": item.get("topology_id"),
                "old_route_id": item.get("old_route_id"),
                "require_independent": bool(item.get("independent", False)),
                "raw": item,
            })
        return result

    def plan(self, payload: dict | None = None, **kwargs):
        p = _data(payload, kwargs, "plan_id")
        plan_id = str(p.get("plan_id") or p.get("id") or
                      f"plan-{hashlib.sha256(_json(p).encode('utf-8')).hexdigest()[:16]}")
        old = _row(self.db, "SELECT payload_json,result_json FROM ts_plans WHERE plan_id=?", (plan_id,))
        if old:
            if old["payload_json"] != _json(p):
                raise ValueError("plan_id_conflict")
            result = json.loads(old["result_json"])
            return {**result, "replayed": True}

        routes = self._route_items(p, plan_id)
        if not routes:
            return decision("rejected", "at least one route is required", plan_id=plan_id)
        mappings = self._mappings(p)
        assignment_dicts = [{"customer_id": r["customer_id"], "demand": r["demand"], "path": r["path"]}
                            for r in routes]
        proof = robust_check(mappings, assignment_dicts)

        # Combine proposed routes with the durable ledger.  Existing observed
        # identities are resolved through each candidate mapping, so an
        # already-held uplink-N1 reservation becomes U-shared in Jia and U1 in
        # Yi before the combined capacity decision is made.
        existing = self._counted_loads()
        combined_violations = []
        for mapping, check in zip(mappings, proof.get("results", [])):
            spec = normalize_spec(mapping)
            mapping_id = check.get("topology_id") or spec["topology_id"]
            baseline: dict[str, int] = {}
            for resource_id, item in existing.items():
                concrete = canonical_in_mapping(resource_id, spec["aliases"])
                baseline[concrete] = baseline.get(concrete, 0) + int(item["amount"])
            proposed = check.get("loads", {})
            combined = dict(baseline)
            for resource_id, amount in proposed.items():
                combined[resource_id] = combined.get(resource_id, 0) + int(amount)
            for resource_id, load in combined.items():
                capacity = spec["capacities"].get(resource_id)
                if capacity is not None and load > capacity:
                    violation = {"type": "combined_capacity_exceeded", "topology_id": mapping_id,
                                 "resource": resource_id, "capacity": capacity, "load": load,
                                 "over": load - capacity}
                    combined_violations.append(violation)
                    proof["feasible"] = False
                    proof["all_mappings_fit"] = False
            check["combined_loads"] = combined
        if combined_violations:
            proof["combined_violations"] = combined_violations

        failed_domain = p.get("failed_domain")
        if not failed_domain and p.get("failed_node"):
            node = _row(self.db, "SELECT domain_id FROM pt_nodes WHERE node_id=?", (str(p["failed_node"]),))
            failed_domain = node["domain_id"] if node else None
        domain_conflicts = []
        if failed_domain:
            for mapping in mappings:
                spec = normalize_spec(mapping)
                for route in routes:
                    concrete = [canonical_in_mapping(x, spec["aliases"]) for x in route["path"]]
                    for resource in route["path"] + concrete:
                        if spec["domains"].get(resource) == failed_domain:
                            domain_conflicts.append({"route_id": route["route_id"], "resource": resource,
                                                     "failure_domain": failed_domain,
                                                     "topology_id": spec["topology_id"]})
        if domain_conflicts:
            proof["domain_conflicts"] = domain_conflicts
            proof["feasible"] = False

        health_conflicts = []
        has_inventory = _row(
            self.db, "SELECT name FROM sqlite_master WHERE type='table' AND name='inventories'"
        )
        for route in routes:
            expected_generation = route["raw"].get("expected_generation", p.get("expected_generation"))
            for resource in route["path"]:
                node = _row(self.db, "SELECT healthy,generation FROM pt_nodes WHERE node_id=?", (resource,))
                if node and not node["healthy"]:
                    health_conflicts.append({"route_id": route["route_id"], "resource": resource,
                                             "type": "node_unhealthy"})
                link = _row(self.db, "SELECT healthy FROM pt_resources WHERE resource_id=?", (resource,))
                if link and not link["healthy"]:
                    health_conflicts.append({"route_id": route["route_id"], "resource": resource,
                                             "type": "link_unhealthy"})
            entry = route["raw"].get("target") or route["raw"].get("entry") or (route["path"][0] if route["path"] else None)
            if has_inventory and entry:
                inventory = _row(self.db, "SELECT healthy,generation FROM inventories WHERE replica_id=?",
                                 (str(entry),))
                if inventory:
                    if not inventory["healthy"]:
                        health_conflicts.append({"route_id": route["route_id"], "resource": entry,
                                                 "type": "observed_replica_unhealthy"})
                    if expected_generation is not None and int(expected_generation) != int(inventory["generation"]):
                        health_conflicts.append({"route_id": route["route_id"], "resource": entry,
                                                 "type": "stale_generation",
                                                 "expected_generation": int(expected_generation),
                                                 "current_generation": inventory["generation"]})
        if health_conflicts:
            proof["health_conflicts"] = health_conflicts
            proof["feasible"] = False

        independence = {mapping.get("topology_id", f"m{i}"):
                        independent_route_set(mapping, assignment_dicts)
                        for i, mapping in enumerate(mappings)}
        proof["independence"] = independence
        if p.get("require_independent"):
            if not all(item["independent"] for item in independence.values()):
                proof["feasible"] = False
                proof["independence_required"] = True

        if not proof["feasible"]:
            return decision("blocked", "route is not safe in every compatible physical topology",
                            plan_id=plan_id, proof=proof)

        at = _at(p)
        with _tx(self.db):
            # Persist conservative capacities for invariant observed resource
            # identities when callers supplied mappings inline rather than
            # registering resources first.
            invariant_resources = sorted({resource for route in routes for resource in route["path"]})
            for resource in invariant_resources:
                safe_caps = []
                domains = []
                for mapping in mappings:
                    spec = normalize_spec(mapping)
                    concrete = canonical_in_mapping(resource, spec["aliases"])
                    cap = spec["capacities"].get(concrete)
                    if cap is None:
                        cap = spec["capacities"].get(resource)
                    if cap is not None:
                        safe_caps.append(int(cap))
                    domain = spec["domains"].get(concrete) or spec["domains"].get(resource)
                    if domain:
                        domains.append(domain)
                safe_capacity = min(safe_caps) if safe_caps else None
                self.db.execute(
                    "INSERT OR IGNORE INTO pt_resources(resource_id,kind,capacity,domain_id,metered,"
                    "authoritative,healthy,attrs_json) VALUES(?, 'planned-safe', ?, ?, 0,0,1,'{}')",
                    (resource, safe_capacity, domains[0] if domains else None),
                )
            self.db.execute("INSERT INTO ts_plans(plan_id,status,payload_json,result_json,created_at) VALUES(?,?,?,?,?)",
                            (plan_id, "planned", _json(p), _json({"planned": True}), at))
            for route in routes:
                self.db.execute(
                    "INSERT INTO ts_routes(route_id,plan_id,customer_id,version,kind,path_id,path_json,demand,"
                    "latency_ms,status,topology_id,old_route_id,created_at,updated_at) "
                    "VALUES(?,?,?,?,1,?,?,?,?,'planned',?,?,?,?)",
                    (route["route_id"], plan_id, route["customer_id"], route["kind"], route["path_id"],
                     _json(route["path"]), route["demand"], route["latency_ms"], route["topology_id"],
                     route["old_route_id"], at, at),
                )
            result = decision("planned", "route fits every compatible mapping and failure-domain constraint",
                             plan_id=plan_id, routes=[{k: v for k, v in r.items() if k != "raw"} for r in routes],
                             proof=proof)
            self.db.execute("UPDATE ts_plans SET result_json=? WHERE plan_id=?", (_json(result), plan_id))
            self.audit("plan.created", plan_id, {"routes": [r["route_id"] for r in routes]}, at=at)
        return result

    plan_failover = plan

    # ------------------------------------------------------------------
    # Two-phase capacity reservation.
    # ------------------------------------------------------------------

    def _counted_loads(self, exclude_route_ids=()) -> dict[str, dict]:
        excluded = set(exclude_route_ids)
        loads: dict[str, dict] = {}
        rows = _rows(self.db, "SELECT * FROM ts_reservations")
        for row in rows:
            if row["route_id"] in excluded or row["status"] not in COUNTED_STATES:
                continue
            canonical = self.topo.canonical(row["resource_id"])
            item = loads.setdefault(canonical, {"amount": 0, "customers": []})
            item["amount"] += int(row["amount"])
            item["customers"].append({"customer_id": row["customer_id"], "amount": row["amount"],
                                      "route_id": row["route_id"], "status": row["status"]})
        return loads

    def prepare(self, payload: dict | None = None, **kwargs):
        p = _data(payload, kwargs, "plan_id")
        if p.get("routes") or p.get("assignments"):
            planned = self.plan(p)
            if planned.get("status") != "planned":
                return planned
            p["plan_id"] = planned["plan_id"]
        plan_id = str(p.get("plan_id") or p.get("id"))
        if not plan_id:
            return decision("rejected", "plan_id is required")
        plan = _row(self.db, "SELECT * FROM ts_plans WHERE plan_id=?", (plan_id,))
        if not plan:
            return decision("missing", "failover plan does not exist", plan_id=plan_id)
        routes = _rows(self.db, "SELECT * FROM ts_routes WHERE plan_id=? ORDER BY route_id", (plan_id,))
        if not routes:
            return decision("missing", "plan has no routes", plan_id=plan_id)
        if _row(self.db, "SELECT reservation_id FROM ts_reservations WHERE route_id=? LIMIT 1", (routes[0]["route_id"],)):
            return self.reservation_report(plan_id)

        at = _at(p)
        with _tx(self.db):
            existing = self._counted_loads(exclude_route_ids=[r["route_id"] for r in routes])
            incremental: dict[str, int] = {}
            normalized = []
            for route in routes:
                path = json.loads(route["path_json"])
                canonical_path = list(dict.fromkeys(self.topo.canonical(x) for x in path))
                normalized.append((route, canonical_path))
                for resource in canonical_path:
                    incremental[resource] = incremental.get(resource, 0) + int(route["demand"])
            violations = []
            for resource, added in incremental.items():
                capacity = self.topo.effective_capacity(resource)
                used = existing.get(resource, {}).get("amount", 0)
                if capacity is None:
                    violations.append({"resource": resource, "type": "unknown_capacity"})
                elif used + added > capacity:
                    violations.append({"resource": resource, "capacity": capacity, "used": used,
                                       "requested": added, "load": used + added,
                                       "over": used + added - capacity})
            if violations:
                return decision("blocked", "real physical capacity reservation rejected",
                                plan_id=plan_id, violations=violations)
            for route, canonical_path in normalized:
                for resource in canonical_path:
                    reservation_id = f"res:{route['route_id']}:{resource}"
                    self.db.execute(
                        "INSERT OR IGNORE INTO ts_reservations(reservation_id,route_id,customer_id,resource_id,"
                        "canonical_resource_id,amount,status,idempotency_key,created_at,updated_at) "
                        "VALUES(?,?,?,?,?,?, 'held',?,?,?)",
                        (reservation_id, route["route_id"], route["customer_id"], resource, resource,
                         route["demand"], f"prepare:{plan_id}:{route['route_id']}:{resource}", at, at),
                    )
                self.db.execute("UPDATE ts_routes SET status='prepared',updated_at=? WHERE route_id=?",
                                (at, route["route_id"]))
            self.db.execute("UPDATE ts_plans SET status='prepared' WHERE plan_id=?", (plan_id,))
            self.audit("plan.prepared", plan_id, {"incremental": incremental}, at=at)
        return self.reservation_report(plan_id, status="prepared",
                                       reason="capacity held durably; network command not yet confirmed")

    reserve = prepare

    def reservation_report(self, plan_id: str, status: str = "reserved", reason: str = ""):
        rows = _rows(self.db,
                     "SELECT r.* FROM ts_reservations r JOIN ts_routes rt ON rt.route_id=r.route_id "
                     "WHERE rt.plan_id=? ORDER BY r.reservation_id", (plan_id,))
        return decision(status, reason or "reservation ledger", plan_id=plan_id,
                        reservations=rows, loads=self.occupancy())

    # ------------------------------------------------------------------
    # Command issuance, controller receipt and independent probes.
    # ------------------------------------------------------------------

    def issue(self, payload: dict | str | None = None, *args, **kwargs):
        p = _data(payload, kwargs, "command_id")
        # Convenience: issue(db, "plan-id") issues every route in the plan.
        if isinstance(payload, str) and not _row(self.db, "SELECT command_id FROM ts_commands WHERE command_id=?", (payload,)):
            plan = _row(self.db, "SELECT plan_id FROM ts_plans WHERE plan_id=?", (payload,))
            if plan and not p.get("plan_id"):
                p["plan_id"] = payload
        if args and isinstance(args[0], (str, int)) and "generation" not in p:
            p["generation"] = int(args[0])

        if p.get("plan_id") and not p.get("route_id"):
            prepared = self.prepare({"plan_id": p["plan_id"], "at": p.get("at", 0)})
            if prepared.get("status") == "blocked":
                return prepared
            routes = _rows(self.db, "SELECT route_id FROM ts_routes WHERE plan_id=? ORDER BY route_id", (p["plan_id"],))
            requested_command = p.get("command_id") or p.get("request_id")
            commands = []
            for index, route in enumerate(routes):
                child = {k: v for k, v in p.items() if k not in ("command_id", "request_id")}
                child.update(route_id=route["route_id"], plan_id=p["plan_id"])
                if requested_command:
                    child["command_id"] = str(requested_command) if len(routes) == 1 else \
                        f"{requested_command}:{route['customer_id'] if 'customer_id' in route.keys() else index}"
                result = self.issue(child)
                commands.append(result)
            command_ids = [c.get("command_id") for c in commands if c.get("command_id")]
            result = decision("dispatched", "reserve commands issued for plan routes",
                              plan_id=p["plan_id"], commands=commands, command_ids=command_ids)
            if len(command_ids) == 1:
                result["command_id"] = command_ids[0]
            return result

        command_id = p.get("command_id") or p.get("idempotency_key") or p.get("request_id")
        if command_id:
            old = _row(self.db, "SELECT * FROM ts_commands WHERE command_id=? OR idempotency_key=?",
                       (str(command_id), str(command_id)))
            if old:
                return {**self._command_view(old), "replayed": True}

        route_id = p.get("route_id")
        if not route_id:
            return decision("rejected", "route_id or plan_id is required to issue a command")
        route = _row(self.db, "SELECT * FROM ts_routes WHERE route_id=?", (str(route_id),))
        if not route:
            return decision("missing", "route does not exist", route_id=route_id)
        kind = str(p.get("kind") or ("revoke" if p.get("revoke") else "reserve"))
        at = _at(p)

        if not command_id and not p.get("generation"):
            latest = _row(
                self.db,
                "SELECT * FROM ts_commands WHERE route_id=? AND kind=? ORDER BY sequence_no DESC LIMIT 1",
                (route_id, kind),
            )
            if latest and latest["status"] not in ("failed", "probe_failed"):
                return {**self._command_view(latest), "replayed": True}

        explicit_predecessor = p.get("predecessor_command_id") or p.get("after")
        if kind == "reserve" and route["old_route_id"] and not explicit_predecessor:
            prior_revoke = _row(
                self.db,
                "SELECT command_id FROM ts_commands WHERE route_id=? AND kind='revoke' "
                "ORDER BY sequence_no DESC LIMIT 1",
                (route["old_route_id"],),
            )
            if not prior_revoke and p.get("auto_revoke", True):
                revoked = self.revoke({
                    "route_id": route["old_route_id"],
                    "at": at,
                    "command_id": p.get("old_revoke_command_id"),
                })
                if revoked.get("status") not in ("sent", "replayed"):
                    return decision("blocked", "causal old-route release command could not be created",
                                    cause=revoked)

        with _tx(self.db):
            if kind == "reserve" and not _row(self.db, "SELECT reservation_id FROM ts_reservations WHERE route_id=?",
                                              (route_id,)):
                # Direct issue is allowed; it performs the safe prepare phase first.
                prepared = self.prepare({"plan_id": route["plan_id"], "at": at})
                if prepared.get("status") == "blocked":
                    return prepared
            generation = int(p.get("generation") or 0)
            if generation <= 0:
                row = _row(self.db, "SELECT COALESCE(MAX(generation),0)+1 AS g FROM ts_commands "
                                    "WHERE route_id=? AND kind=?", (route_id, kind))
                generation = int(row["g"])
            if not command_id:
                command_id = f"cmd:{route_id}:{kind}:{generation}"
            idem = p.get("idempotency_key") or p.get("request_id") or command_id
            if _row(self.db, "SELECT command_id FROM ts_commands WHERE idempotency_key=?", (idem,)):
                old = _row(self.db, "SELECT * FROM ts_commands WHERE idempotency_key=?", (idem,))
                return {**self._command_view(old), "replayed": True}

            predecessor = p.get("predecessor_command_id") or p.get("after")
            if not predecessor and kind == "reserve" and route["old_route_id"]:
                old_cmd = _row(self.db,
                               "SELECT command_id FROM ts_commands WHERE route_id=? AND kind='revoke' "
                               "ORDER BY sequence_no DESC LIMIT 1", (route["old_route_id"],))
                predecessor = old_cmd["command_id"] if old_cmd else None
            if predecessor and not _row(self.db, "SELECT command_id FROM ts_commands WHERE command_id=?",
                                        (str(predecessor),)):
                return decision("rejected", "predecessor command does not exist",
                                predecessor_command_id=predecessor)
            sequence = self._next_sequence()
            self.db.execute(
                "INSERT INTO ts_commands(command_id,idempotency_key,sequence_no,route_id,customer_id,plan_id,kind,"
                "generation,predecessor_command_id,status,payload_json,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?, 'sent',?,?,?)",
                (command_id, idem, sequence, route_id, route["customer_id"], route["plan_id"], kind,
                 generation, predecessor, _json(p), at, at),
            )
            if kind == "reserve":
                self.db.execute("UPDATE ts_reservations SET status='held',command_id=?,updated_at=? WHERE route_id=?",
                                (command_id, at, route_id))
                self.db.execute("UPDATE ts_routes SET status='sent',updated_at=? WHERE route_id=?", (at, route_id))
                self._mark_switch_pending(route, at)
            elif kind == "revoke":
                self.db.execute("UPDATE ts_reservations SET status='release_pending',updated_at=? WHERE route_id=?",
                                (at, route_id))
                self.db.execute("UPDATE ts_routes SET status='release_pending',updated_at=? WHERE route_id=?",
                                (at, route_id))
            self.audit("command.issued", command_id,
                       {"route_id": route_id, "kind": kind, "generation": generation,
                        "sequence": sequence, "predecessor": predecessor}, generation, at)
            view = self._command_view(_row(self.db, "SELECT * FROM ts_commands WHERE command_id=?",
                                           (command_id,)))
            view.pop("status", None)
        return decision("sent", f"{kind} command issued with durable generation", **view)

    dispatch = issue

    def revoke(self, payload: dict | str | None = None, **kwargs):
        if isinstance(payload, str):
            payload = {"route_id": payload}
        p = _data(payload, kwargs, "route_id")
        p["kind"] = "revoke"
        return self.issue(p)

    def _command_view(self, row: dict | None) -> dict:
        if not row:
            return {}
        return {
            "command_id": row["command_id"],
            "generation": row["generation"],
            "sequence": row["sequence_no"],
            "kind": row["kind"],
            "status": row["status"],
            "route_id": row["route_id"],
            "customer_id": row["customer_id"],
            "plan_id": row["plan_id"],
            "predecessor_command_id": row["predecessor_command_id"],
            "receipt_id": row["receipt_id"],
            "success": row["success"],
        }

    def receipt(self, payload: dict | str | None = None, *args, **kwargs):
        p = _data(payload, kwargs, "command_id")
        for arg in args:
            if isinstance(arg, bool):
                p.setdefault("success", arg)
            elif isinstance(arg, int):
                p.setdefault("generation", arg)
            elif isinstance(arg, str):
                if arg.isdigit():
                    p.setdefault("generation", int(arg))
                elif not p.get("receipt_id"):
                    p.setdefault("receipt_id", arg)
                else:
                    p.setdefault("generation", arg)

        batch = p.get("results") or p.get("receipts")
        if isinstance(batch, (list, dict)):
            items = batch.items() if isinstance(batch, dict) else enumerate(batch)
            outcomes = []
            for key, value in items:
                if isinstance(value, dict):
                    child = dict(value)
                    child.setdefault("command_id", key if isinstance(batch, dict) else value.get("command_id"))
                else:
                    child = {"command_id": key if isinstance(batch, dict) else value,
                             "success": bool(value) if isinstance(batch, dict) else True}
                child.setdefault("at", p.get("at", 0))
                outcomes.append(self.receipt(child))
            failed = [x for x in outcomes if x.get("status") == "failed"]
            succeeded = [x for x in outcomes if x not in failed]
            status = "partial" if failed and succeeded else ("failed" if failed else "written")
            return decision(status, "controller batch results applied independently",
                            results=outcomes, partial_success=bool(failed and succeeded),
                            success_count=len(succeeded), failure_count=len(failed))

        command_id = str(p.get("command_id") or p.get("id"))
        receipt_id = str(p.get("receipt_id") or p.get("ack_id") or p.get("idempotency_key")
                         or f"receipt:{command_id}:{p.get('generation', '')}")
        success = bool(p.get("success", p.get("accepted", p.get("ok", True))))
        at = _at(p)
        with _tx(self.db):
            cmd = _row(self.db, "SELECT * FROM ts_commands WHERE command_id=?", (command_id,))
            if not cmd:
                return decision("missing", "command does not exist", command_id=command_id)
            supplied_generation = p.get("generation")
            if supplied_generation is not None and int(supplied_generation) != int(cmd["generation"]):
                self.db.execute(
                    "INSERT OR IGNORE INTO ts_receipts(receipt_id,command_id,generation,success,status,at,payload_json) "
                    "VALUES(?,?,?,?,'stale_generation',?,?)",
                    (receipt_id, command_id, int(supplied_generation), int(success), at, _json(p)))
                return decision("stale_generation", "receipt generation does not match current command",
                                command_id=command_id, command_generation=cmd["generation"],
                                supplied_generation=int(supplied_generation))
            old_receipt = _row(self.db, "SELECT * FROM ts_receipts WHERE receipt_id=?", (receipt_id,))
            if old_receipt:
                return decision("replayed", "controller receipt retry did not create capacity",
                                command_id=command_id, receipt_id=receipt_id, command_status=cmd["status"])
            if cmd["receipt_id"] and not p.get("force"):
                return decision("replayed", "command already has a controller receipt; ACK is idempotent",
                                command_id=command_id, receipt_id=cmd["receipt_id"], command_status=cmd["status"])
            self.db.execute(
                "INSERT INTO ts_receipts(receipt_id,command_id,generation,success,status,at,payload_json) "
                "VALUES(?,?,?,?,?,?,?)",
                (receipt_id, command_id, cmd["generation"], int(success),
                 "accepted" if success else "failed", at, _json(p)))
            if not success:
                self.db.execute(
                    "UPDATE ts_commands SET status='failed',success=0,receipt_id=?,receipt_json=?,receipt_at=?,"
                    "updated_at=? WHERE command_id=?",
                    (receipt_id, _json(p), at, at, command_id))
                if cmd["kind"] == "reserve":
                    self.db.execute("UPDATE ts_reservations SET status='failed',updated_at=? WHERE command_id=?",
                                    (at, command_id))
                    self.db.execute("UPDATE ts_routes SET status='failed',updated_at=? WHERE route_id=?",
                                    (at, cmd["route_id"]))
                else:
                    self.db.execute("UPDATE ts_reservations SET status='active',updated_at=? WHERE route_id=?",
                                    (at, cmd["route_id"]))
                    self.db.execute("UPDATE ts_routes SET status='active',updated_at=? WHERE route_id=?",
                                    (at, cmd["route_id"]))
                self.audit("command.failed", command_id, {"receipt_id": receipt_id}, cmd["generation"], at)
                return decision("failed", "controller rejected or partially failed the command",
                                command_id=command_id, receipt_id=receipt_id)

            new_status = "written" if cmd["kind"] == "reserve" else "revoke_written"
            self.db.execute(
                "UPDATE ts_commands SET status=?,success=1,receipt_id=?,receipt_json=?,receipt_at=?,updated_at=? "
                "WHERE command_id=?",
                (new_status, receipt_id, _json(p), at, at, command_id))
            if cmd["kind"] == "reserve":
                self.db.execute("UPDATE ts_reservations SET status='written',updated_at=? WHERE command_id=?",
                                (at, command_id))
                self.db.execute("UPDATE ts_routes SET status='written',updated_at=? WHERE route_id=?",
                                (at, cmd["route_id"]))
            self.audit("command.receipted", command_id, {"receipt_id": receipt_id, "status": new_status},
                       cmd["generation"], at)
            passing_probe = _row(
                self.db,
                "SELECT * FROM ts_probes WHERE command_id=? AND generation=? AND passed=1 AND independent=1 "
                "ORDER BY observed_at DESC LIMIT 1",
                (command_id, cmd["generation"]))
            if passing_probe:
                return self._confirm_command(command_id, at)
            return decision("written", "controller receipt only proves the rule was written; independent probe required",
                            command_id=command_id, receipt_id=receipt_id, generation=cmd["generation"],
                            probe_required=True)

    acknowledge = receipt
    ack = receipt
    controller_receipt = receipt

    def probe(self, payload: dict | str | None = None, *args, **kwargs):
        p = _data(payload, kwargs, "command_id")
        for arg in args:
            if isinstance(arg, bool):
                p.setdefault("passed", arg)
            elif isinstance(arg, int):
                p.setdefault("generation", arg)
            elif isinstance(arg, str):
                if arg.isdigit():
                    p.setdefault("generation", int(arg))
                elif arg.startswith(("probe", "pr-", "fiber", "fibre")):
                    p.setdefault("probe_id", arg)
                else:
                    p.setdefault("probe_id", arg)
        probe_id = str(p.get("probe_id") or p.get("id") or
                       f"probe-{hashlib.sha256(_json(p).encode('utf-8')).hexdigest()[:16]}")
        command_id = str(p.get("command_id") or p.get("target_id") or "")
        passed = p.get("passed", p.get("healthy", p.get("confirmed", True)))
        passed = None if passed is None else bool(passed)
        independent = bool(p.get("independent", p.get("independent_confirmation", True)))
        origin = str(p.get("origin") or ("independent-probe" if independent else "controller"))
        if origin == "controller":
            independent = False
        at = _at(p)
        received_at = int(p.get("received_at", at))

        with _tx(self.db):
            cmd = _row(self.db, "SELECT * FROM ts_commands WHERE command_id=?", (command_id,))
            if not cmd:
                return decision("missing", "command does not exist", command_id=command_id)
            old = _row(self.db, "SELECT status FROM ts_probes WHERE probe_id=?", (probe_id,))
            if old:
                return decision("replayed", "probe evidence already stored", probe_id=probe_id,
                                probe_status=old["status"])
            supplied_generation = p.get("generation")
            if supplied_generation is not None and int(supplied_generation) != int(cmd["generation"]):
                self.db.execute(
                    "INSERT INTO ts_probes(probe_id,command_id,generation,passed,independent,origin,observed_at,"
                    "received_at,status,payload_json) VALUES(?,?,?,?,?,?,?,?, 'stale_generation',?)",
                    (probe_id, command_id, int(supplied_generation),
                     None if passed is None else int(passed), int(independent), origin, at, received_at, _json(p)))
                return decision("stale_generation", "late probe belongs to an old command generation",
                                command_id=command_id, command_generation=cmd["generation"],
                                supplied_generation=int(supplied_generation))
            if not independent:
                self.db.execute(
                    "INSERT INTO ts_probes(probe_id,command_id,generation,passed,independent,origin,observed_at,"
                    "received_at,status,payload_json) VALUES(?,?,?,?,0,?,?,?, 'not_independent',?)",
                    (probe_id, command_id, cmd["generation"], None if passed is None else int(passed),
                     origin, at, received_at, _json(p)))
                return decision("rejected", "controller receipt is not an independent probe", command_id=command_id)
            if passed is False:
                self.db.execute(
                    "INSERT INTO ts_probes(probe_id,command_id,generation,passed,independent,origin,observed_at,"
                    "received_at,status,payload_json) VALUES(?,?,?,0,1,?,?,?, 'probe_failed',?)",
                    (probe_id, command_id, cmd["generation"], origin, at, received_at, _json(p)))
                self.db.execute("UPDATE ts_commands SET status='probe_failed',updated_at=? WHERE command_id=?",
                                (at, command_id))
                return decision("pending", "independent probe did not pass; customer cannot be marked taken over",
                                command_id=command_id, probe_id=probe_id)
            self.db.execute(
                "INSERT INTO ts_probes(probe_id,command_id,generation,passed,independent,origin,observed_at,"
                "received_at,status,payload_json) VALUES(?,?,?,1,1,?,?,?, 'passed',?)",
                (probe_id, command_id, cmd["generation"], origin, at, received_at, _json(p)))
            if cmd["status"] in ("written", "revoke_written", "confirmed", "revoked"):
                return self._confirm_command(command_id, at, probe_id=probe_id)
            self.db.execute("UPDATE ts_probes SET status='awaiting_receipt' WHERE probe_id=?", (probe_id,))
            return decision("awaiting_receipt", "probe passed but controller write receipt is not yet durable",
                            command_id=command_id, probe_id=probe_id, taken_over=False)

    confirm_probe = probe
    probe_confirm = probe
    confirm = probe

    def _confirm_command(self, command_id: str, at: int, probe_id: str | None = None):
        cmd = _row(self.db, "SELECT * FROM ts_commands WHERE command_id=?", (command_id,))
        if not cmd:
            return decision("missing", "command does not exist")
        if cmd["status"] == "confirmed" and cmd["kind"] == "reserve":
            link = self.customer_link(cmd["customer_id"])
            return decision("confirmed", "reservation already independently confirmed",
                            command_id=command_id, taken_over=True, customer_link=link, replayed=True)
        if cmd["status"] == "revoked" and cmd["kind"] == "revoke":
            return decision("revoked", "route release already independently confirmed",
                            command_id=command_id, replayed=True)

        if cmd["kind"] == "reserve":
            route = _row(self.db, "SELECT * FROM ts_routes WHERE route_id=?", (cmd["route_id"],))
            path = json.loads(route["path_json"]) if route else []
            self.db.execute("UPDATE ts_commands SET status='confirmed',updated_at=? WHERE command_id=?",
                            (at, command_id))
            self.db.execute("UPDATE ts_reservations SET status='active',updated_at=? WHERE route_id=?",
                            (at, cmd["route_id"]))
            self.db.execute("UPDATE ts_routes SET status='taken_over',updated_at=? WHERE route_id=?",
                            (at, cmd["route_id"]))
            self._upsert_customer_link(cmd["route_id"], cmd["customer_id"], path, route["latency_ms"] if route else 0, at)
            sla = self._issue_sla(cmd["route_id"], at)
            self.audit("route.taken_over", cmd["route_id"],
                       {"command_id": command_id, "probe_id": probe_id, "path": path}, cmd["generation"], at)
            link = self.customer_link(cmd["customer_id"])
            return decision("confirmed", "independent probe passed; customer connection is taken over",
                            command_id=command_id, probe_id=probe_id, taken_over=True,
                            customer_id=cmd["customer_id"], route_id=cmd["route_id"],
                            actual_path=link.get("actual_path"), actual_link=link.get("actual_link"),
                            sla_certificate=sla, customer_link=link)

        self.db.execute("UPDATE ts_commands SET status='revoked',updated_at=? WHERE command_id=?", (at, command_id))
        self.db.execute("UPDATE ts_reservations SET status='released',updated_at=? WHERE route_id=?",
                        (at, cmd["route_id"]))
        self.db.execute("UPDATE ts_routes SET status='released',updated_at=? WHERE route_id=?",
                        (at, cmd["route_id"]))
        link = _row(self.db, "SELECT * FROM ts_customer_links WHERE customer_id=?", (cmd["customer_id"],))
        if link and link["current_route_id"] == cmd["route_id"]:
            self.db.execute("UPDATE ts_customer_links SET taken_over=0,current_route_id=NULL,"
                            "state='released',updated_at=? WHERE customer_id=?",
                            (at, cmd["customer_id"]))
        self.audit("route.released", cmd["route_id"], {"command_id": command_id, "probe_id": probe_id},
                   cmd["generation"], at)
        return decision("revoked", "independent probe confirmed old route release",
                        command_id=command_id, route_id=cmd["route_id"])

    # ------------------------------------------------------------------
    # Customer evidence, SLA and occupancy.
    # ------------------------------------------------------------------

    def _mark_switch_pending(self, route: dict, at: int):
        old = _row(self.db, "SELECT * FROM ts_customer_links WHERE customer_id=?", (route["customer_id"],))
        current_route_id = old["current_route_id"] if old else route.get("old_route_id")
        actual_path = old["actual_path_json"] if old else "[]"
        latency = old["latency_ms"] if old else 0
        sla_id = old["sla_id"] if old else None
        generation = old["generation"] if old else 1
        self.db.execute(
            "INSERT INTO ts_customer_links(customer_id,current_route_id,pending_route_id,taken_over,state,"
            "actual_path_json,latency_ms,sla_id,generation,updated_at) "
            "VALUES(?,?,?,0,'failover_pending',?,?,?,?,?) "
            "ON CONFLICT(customer_id) DO UPDATE SET pending_route_id=excluded.pending_route_id,"
            "taken_over=0,state='failover_pending',updated_at=excluded.updated_at",
            (route["customer_id"], current_route_id, route["route_id"], actual_path, latency,
             sla_id, generation, at))

    def mark_domain_failed(self, payload: dict | str | None = None, **kwargs):
        """Mark customer links traversing a failed domain as degraded evidence."""
        p = _data(payload, kwargs, "domain_id")
        domain_id = p.get("domain_id") or p.get("failed_domain")
        failed_node = p.get("failed_node") or p.get("node_id")
        at = _at(p)
        affected = []
        with _tx(self.db):
            routes = _rows(self.db, "SELECT * FROM ts_routes WHERE status='taken_over' OR status='active'")
            for route in routes:
                path = json.loads(route["path_json"])
                in_domain = False
                for resource in path:
                    if domain_id:
                        canonical = self.topo.canonical(resource)
                        spec_domain = _row(self.db, "SELECT domain_id FROM pt_resources WHERE resource_id=?",
                                           (canonical,))
                        node_domain = _row(self.db, "SELECT domain_id FROM pt_nodes WHERE node_id=?", (canonical,))
                        if ((spec_domain and spec_domain["domain_id"] == domain_id) or
                                (node_domain and node_domain["domain_id"] == domain_id)):
                            in_domain = True
                    if failed_node and (resource == failed_node or self.topo.canonical(resource) == failed_node):
                        in_domain = True
                if in_domain:
                    affected.append(route["route_id"])
                    self.db.execute(
                        "UPDATE ts_customer_links SET taken_over=0,state='domain_failed',updated_at=? "
                        "WHERE customer_id=? AND current_route_id=?",
                        (at, route["customer_id"], route["route_id"]))
                    self.db.execute("UPDATE ts_routes SET status='domain_failed',updated_at=? WHERE route_id=?",
                                    (at, route["route_id"]))
                    self.audit("link.domain_failed", route["route_id"], {"domain_id": domain_id}, at=at)
        return decision("degraded" if affected else "observed",
                        "affected customer links are no longer marked taken over", routes=affected)

    def _upsert_customer_link(self, route_id: str, customer_id: str, path: list[str], latency: int, at: int):
        canonical_path = [self.topo.canonical(x) for x in path]
        old = _row(self.db, "SELECT generation FROM ts_customer_links WHERE customer_id=?", (customer_id,))
        generation = int(old["generation"]) + 1 if old else 1
        self.db.execute(
            "INSERT INTO ts_customer_links(customer_id,current_route_id,pending_route_id,taken_over,state,"
            "actual_path_json,latency_ms,generation,updated_at) "
            "VALUES(?,?,NULL,1,'taken_over',?,?,?,?) ON CONFLICT(customer_id) DO UPDATE SET "
            "current_route_id=excluded.current_route_id,pending_route_id=NULL,taken_over=1,state='taken_over',"
            "actual_path_json=excluded.actual_path_json,latency_ms=excluded.latency_ms,"
            "generation=ts_customer_links.generation+1,updated_at=excluded.updated_at",
            (customer_id, route_id, _json(canonical_path), int(latency), generation, at))

    def _issue_sla(self, route_id: str, at: int, certificate_id: str | None = None) -> dict:
        existing = _row(self.db, "SELECT payload_json FROM ts_sla_certificates WHERE route_id=?", (route_id,))
        if existing:
            return json.loads(existing["payload_json"])
        route = _row(self.db, "SELECT * FROM ts_routes WHERE route_id=?", (route_id,))
        if not route:
            raise ValueError("cannot issue SLA for missing route")
        customer = _row(self.db, "SELECT * FROM ts_customers WHERE customer_id=?", (route["customer_id"],))
        prior = _row(self.db, "SELECT COALESCE(MAX(version),0)+1 AS v FROM ts_sla_certificates WHERE customer_id=?",
                     (route["customer_id"],))
        version = int(prior["v"])
        path = json.loads(route["path_json"])
        physical_path = [self.topo.canonical(x) for x in path]
        sla_id = certificate_id or f"sla:{route_id}:v{version}"
        payload = {
            "sla_id": sla_id,
            "certificate_id": sla_id,
            "customer_id": route["customer_id"],
            "route_id": route_id,
            "version": version,
            "bandwidth": route["demand"],
            "guaranteed_bandwidth": route["demand"],
            "minimum_bandwidth": customer["minimum_bandwidth"] if customer else route["demand"],
            "latency_ms": route["latency_ms"],
            "latency_delta_ms": route["latency_ms"],
            "physical_path": physical_path,
            "actual_link": physical_path[1] if len(physical_path) > 1 else (physical_path[0] if physical_path else None),
            "issued_at": at,
            "immutable": True,
        }
        self.db.execute(
            "INSERT INTO ts_sla_certificates(sla_id,customer_id,route_id,version,bandwidth,minimum_bandwidth,"
            "latency_ms,physical_path_json,payload_json,issued_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (sla_id, route["customer_id"], route_id, version, route["demand"],
             payload["minimum_bandwidth"], route["latency_ms"], _json(physical_path), _json(payload), at))
        self.db.execute("UPDATE ts_customer_links SET sla_id=? WHERE customer_id=?",
                        (sla_id, route["customer_id"]))
        self.audit("sla.issued", sla_id, {"route_id": route_id, "version": version}, at=at)
        return payload

    def occupancy(self, link_id: str | dict | None = None):
        if isinstance(link_id, dict):
            link_id = link_id.get("link_id") or link_id.get("resource_id") or link_id.get("id")
        loads = self._counted_loads()
        active_loads: dict[str, dict] = {}
        for row in _rows(self.db, "SELECT * FROM ts_reservations WHERE status='active'"):
            canonical = self.topo.canonical(row["resource_id"])
            item = active_loads.setdefault(canonical, {"amount": 0, "customers": []})
            item["amount"] += int(row["amount"])
            item["customers"].append({"customer_id": row["customer_id"], "amount": row["amount"],
                                      "route_id": row["route_id"]})
        links = []
        resource_ids = set(loads) | set(active_loads)
        for resource in _rows(self.db, "SELECT resource_id FROM pt_resources"):
            resource_ids.add(self.topo.canonical(resource["resource_id"]))
        for node in _rows(self.db, "SELECT node_id FROM pt_nodes"):
            resource_ids.add(self.topo.canonical(node["node_id"]))
        for resource_id in sorted(resource_ids):
            capacity = self.topo.effective_capacity(resource_id)
            reserved = loads.get(resource_id, {}).get("amount", 0)
            actual = active_loads.get(resource_id, {}).get("amount", 0)
            links.append({
                "link_id": resource_id,
                "canonical_resource_id": resource_id,
                "capacity": capacity,
                "reserved": reserved,
                "active": actual,
                "available": None if capacity is None else capacity - reserved,
                "active_available": None if capacity is None else capacity - actual,
                "reservations": loads.get(resource_id, {}).get("customers", []),
                "active_customers": active_loads.get(resource_id, {}).get("customers", []),
            })
        if link_id is not None:
            canonical = self.topo.canonical(str(link_id))
            match = next((item for item in links if item["link_id"] == canonical), None)
            return match or decision("missing", "link has no capacity ledger", link_id=link_id)
        return {"links": links}

    link_occupancy = occupancy

    def customer_link(self, customer_id: str):
        row = _row(self.db, "SELECT * FROM ts_customer_links WHERE customer_id=?", (str(customer_id),))
        if not row:
            customer = _row(self.db, "SELECT customer_id FROM ts_customers WHERE customer_id=?", (str(customer_id),))
            if not customer:
                return decision("missing", "customer link does not exist", customer_id=customer_id)
            return {"customer_id": customer_id, "taken_over": False, "status": "pending", "actual_path": []}
        stored_path = json.loads(row["actual_path_json"])
        path = [self.topo.canonical(x) for x in stored_path]
        sla = None
        if row["sla_id"]:
            cert = _row(self.db, "SELECT payload_json FROM ts_sla_certificates WHERE sla_id=?", (row["sla_id"],))
            sla = json.loads(cert["payload_json"]) if cert else None
        occupancy = self.occupancy()
        related = [item for item in occupancy["links"] if item["link_id"] in path]
        return {
            "customer_id": row["customer_id"],
            "status": "taken_over" if row["taken_over"] else row["state"],
            "state": row["state"],
            "taken_over": bool(row["taken_over"]),
            "route_id": row["current_route_id"],
            "current_route_id": row["current_route_id"],
            "pending_route_id": row["pending_route_id"] if "pending_route_id" in row.keys() else None,
            "actual_path": path,
            "physical_path": path,
            "observed_path": stored_path,
            "actual_link": next((x for x in reversed(path) if x not in ("CORE",)), path[-1] if path else None),
            "entry": path[0] if path else None,
            "latency_ms": row["latency_ms"],
            "generation": row["generation"],
            "sla_id": row["sla_id"],
            "sla_certificate": sla,
            "link_occupancy": related,
        }

    def inspect(self, payload: dict | str | None = None, **kwargs):
        p = _data(payload, kwargs, "aggregate_id")
        plan_id = p.get("plan_id")
        customer_id = p.get("customer_id")
        route_id = p.get("route_id")
        command_id = p.get("command_id")
        if isinstance(payload, str) and not any([plan_id, customer_id, route_id, command_id]):
            if _row(self.db, "SELECT plan_id FROM ts_plans WHERE plan_id=?", (payload,)):
                plan_id = payload
            elif _row(self.db, "SELECT command_id FROM ts_commands WHERE command_id=?", (payload,)):
                command_id = payload
            else:
                customer_id = payload
        if command_id:
            cmd = _row(self.db, "SELECT * FROM ts_commands WHERE command_id=?", (command_id,))
            if not cmd:
                return decision("missing", "command not found", command_id=command_id)
            return decision("found", "command, receipts and probes", command=self._command_view(cmd),
                            receipts=_rows(self.db, "SELECT * FROM ts_receipts WHERE command_id=?", (command_id,)),
                            probes=_rows(self.db, "SELECT * FROM ts_probes WHERE command_id=?", (command_id,)))
        if customer_id:
            return decision("found", "customer actual link and immutable SLA history",
                            link=self.customer_link(customer_id),
                            certificates=[json.loads(r["payload_json"]) for r in _rows(
                                self.db, "SELECT payload_json FROM ts_sla_certificates WHERE customer_id=? ORDER BY version",
                                (customer_id,))],
                            commands=_rows(self.db, "SELECT * FROM ts_commands WHERE customer_id=? ORDER BY sequence_no",
                                           (customer_id,)))
        if plan_id:
            return decision("found", "plan routes commands reservations and probes",
                            plan=_row(self.db, "SELECT * FROM ts_plans WHERE plan_id=?", (plan_id,)),
                            routes=_rows(self.db, "SELECT * FROM ts_routes WHERE plan_id=? ORDER BY route_id", (plan_id,)),
                            reservations=_rows(self.db,
                                               "SELECT r.* FROM ts_reservations r JOIN ts_routes rt ON rt.route_id=r.route_id "
                                               "WHERE rt.plan_id=? ORDER BY r.reservation_id", (plan_id,)),
                            commands=_rows(self.db, "SELECT * FROM ts_commands WHERE plan_id=? ORDER BY sequence_no",
                                           (plan_id,)))
        return decision("found", "traffic failover audit state",
                        plans=_rows(self.db, "SELECT plan_id,status,created_at FROM ts_plans ORDER BY created_at"),
                        routes=_rows(self.db, "SELECT route_id,customer_id,status,demand,latency_ms FROM ts_routes ORDER BY route_id"),
                        commands=_rows(self.db, "SELECT command_id,route_id,kind,generation,sequence_no,status FROM ts_commands ORDER BY sequence_no"),
                        failed_commands=_rows(self.db, "SELECT * FROM ts_commands WHERE status='failed' ORDER BY sequence_no"),
                        audit=_rows(self.db, "SELECT * FROM ts_audit ORDER BY seq"))

    def recover(self, payload: dict | None = None, **kwargs):
        """Reopen-safe recovery report; all authority is already in SQLite."""
        init_switch(self.db)
        report = self.inspect(payload or {})
        report["recovery"] = "same physical bandwidth ledger recovered"
        report["occupancy"] = self.occupancy()
        return report


# Module-level facade.
def switch(db) -> TrafficSwitch:
    return TrafficSwitch(db)


def create_protocol(db) -> TrafficSwitch:
    return TrafficSwitch(db)


coordinator = switch


def _call(method: str, db, payload=None, *args, **kwargs):
    return getattr(TrafficSwitch(db), method)(payload, *args, **kwargs)


def add_customer(db, payload=None, **kwargs):
    return TrafficSwitch(db).add_customer(payload, **kwargs)


def adopt_active_route(db, payload=None, **kwargs):
    return TrafficSwitch(db).adopt_active_route(payload, **kwargs)


def mark_domain_failed(db, payload=None, **kwargs):
    return TrafficSwitch(db).mark_domain_failed(payload, **kwargs)


def plan(db, payload=None, **kwargs):
    return TrafficSwitch(db).plan(payload, **kwargs)


plan_failover = plan


def prepare(db, payload=None, **kwargs):
    return TrafficSwitch(db).prepare(payload, **kwargs)


reserve = prepare


def issue(db, payload=None, *args, **kwargs):
    return TrafficSwitch(db).issue(payload, *args, **kwargs)


def dispatch(db, payload=None, *args, **kwargs):
    return TrafficSwitch(db).dispatch(payload, *args, **kwargs)


def revoke(db, payload=None, **kwargs):
    return TrafficSwitch(db).revoke(payload, **kwargs)


def receipt(db, payload=None, *args, **kwargs):
    return TrafficSwitch(db).receipt(payload, *args, **kwargs)


acknowledge = receipt
ack = receipt
controller_receipt = receipt


def probe(db, payload=None, *args, **kwargs):
    return TrafficSwitch(db).probe(payload, *args, **kwargs)


confirm_probe = probe
probe_confirm = probe
confirm = probe


def customer_link(db, customer_id=None, **kwargs):
    if isinstance(customer_id, dict):
        return TrafficSwitch(db).customer_link(customer_id.get("customer_id") or customer_id.get("id"))
    return TrafficSwitch(db).customer_link(customer_id)


def occupancy(db, link_id=None, **kwargs):
    return TrafficSwitch(db).occupancy(link_id)


link_occupancy = occupancy


def inspect(db, payload=None, **kwargs):
    return TrafficSwitch(db).inspect(payload, **kwargs)


def recover(db, payload=None, **kwargs):
    return TrafficSwitch(db).recover(payload, **kwargs)


HANDLERS = {
    "add_customer": add_customer,
    "register_customer": add_customer,
    "adopt_active_route": adopt_active_route,
    "plan": plan,
    "plan_failover": plan,
    "prepare": prepare,
    "reserve": reserve,
    "issue": issue,
    "dispatch": issue,
    "submit": issue,
    "submit_reservation": issue,
    "revoke": revoke,
    "release": revoke,
    "receipt": receipt,
    "receive": receipt,
    "ack": ack,
    "acknowledge": acknowledge,
    "controller_receipt": controller_receipt,
    "probe": probe,
    "confirm": confirm,
    "confirm_probe": confirm_probe,
    "customer_link": customer_link,
    "occupancy": occupancy,
    "link_occupancy": link_occupancy,
    "inspect": inspect,
    "recover": recover,
    "mark_domain_failed": mark_domain_failed,
}


# Descriptive aliases for the executable protocol.
FailoverCoordinator = TrafficSwitch
TrafficFailover = TrafficSwitch
TrafficTakeover = TrafficSwitch
SwitchoverCoordinator = TrafficSwitch
FailoverProtocol = TrafficSwitch
FailoverManager = TrafficSwitch
TrafficManager = TrafficSwitch
SwitchProtocol = TrafficSwitch
TrafficSwitchProtocol = TrafficSwitch
FailoverService = TrafficSwitch
TrafficService = TrafficSwitch
SwitchService = TrafficSwitch
TrafficSwitchService = TrafficSwitch

create_plan = plan
create_failover_plan = plan
start_failover = issue
execute_switch = issue
submit_reservation = issue
submit_reservation_command = issue
dispatch_command = dispatch
controller_ack = ack
acknowledge_command = acknowledge
acknowledge_controller_receipt = receipt
record_receipt = receipt
record_controller_receipt = receipt
confirm_with_probe = probe
record_probe_result = probe
record_probe_confirmation = probe
confirm_takeover_with_probe = probe
confirm_takeover = probe
get_customer_link = customer_link
show_customer_link = customer_link
get_occupancy = occupancy
get_link_occupancy = occupancy
capacity_occupancy = occupancy
recovery_report = recover
