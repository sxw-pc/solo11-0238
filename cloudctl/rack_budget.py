"""Executable rack power limits, signed orders and recoverable execution.

The original :func:`issue` entry point still sums/collapses captured readings
for one subject and writes a row to ``rack_orders``; the seed's two watt page
therefore still yields metric ``2``.

On top of that this module provides:

* topology/window aware planning (delegated to :mod:`cloudctl.power_core`),
* immutable signed limit orders with monotonically increasing generations,
* controller receipts that only mean "setpoint written",
* independent power + temperature confirmation before "stable",
* an idempotent command/shed ledger and recovery after outage or retry,
* late-calibration handling that preserves signed limits and proposes the
  next safe command instead of rewriting history.
"""

import json
from contextlib import nullcontext
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import power_core as core
from . import power_sensor as sensor


def _tx(db):
    return core.write_tx(db)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

ORDER_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS rack_orders (subject TEXT, metric INTEGER)""",
    """CREATE TABLE IF NOT EXISTS power_limit_orders (
        order_id TEXT PRIMARY KEY,
        scope TEXT NOT NULL DEFAULT 'AB',
        order_generation INTEGER NOT NULL DEFAULT 1,
        command_generation INTEGER NOT NULL DEFAULT 1,
        option_name TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'signed',
        feasible INTEGER NOT NULL DEFAULT 1,
        limits_json TEXT NOT NULL DEFAULT '{}',
        phase_limits_json TEXT NOT NULL DEFAULT '{}',
        peak_json TEXT NOT NULL DEFAULT '{}',
        spec_json TEXT NOT NULL DEFAULT '{}',
        plan_json TEXT NOT NULL DEFAULT '{}',
        result_json TEXT NOT NULL DEFAULT '{}',
        request_id TEXT,
        parent_order_id TEXT NOT NULL DEFAULT '',
        calibration_digest TEXT NOT NULL DEFAULT '',
        signed_at INTEGER NOT NULL DEFAULT 0,
        receipt_at INTEGER,
        stable_at INTEGER,
        created_at INTEGER NOT NULL DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS power_command_generations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scope TEXT NOT NULL DEFAULT 'AB',
        generation INTEGER NOT NULL,
        order_id TEXT NOT NULL DEFAULT '',
        command_id TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL DEFAULT 'set_limits',
        target TEXT NOT NULL DEFAULT '',
        payload_json TEXT NOT NULL DEFAULT '{}',
        idempotency_key TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'prepared',
        reason TEXT NOT NULL DEFAULT '',
        at_min INTEGER NOT NULL DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS power_controller_receipts (
        receipt_id TEXT PRIMARY KEY,
        order_id TEXT NOT NULL,
        target TEXT NOT NULL DEFAULT '',
        generation INTEGER NOT NULL DEFAULT 1,
        success INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'written',
        detail TEXT NOT NULL DEFAULT '',
        at_min INTEGER NOT NULL DEFAULT 0,
        payload_json TEXT NOT NULL DEFAULT '{}'
    )""",
    """CREATE TABLE IF NOT EXISTS power_samples (
        sample_id TEXT PRIMARY KEY,
        at_min INTEGER NOT NULL DEFAULT 0,
        source TEXT NOT NULL DEFAULT 'independent',
        independent INTEGER NOT NULL DEFAULT 1,
        power_json TEXT NOT NULL DEFAULT '{}',
        temperature_json TEXT NOT NULL DEFAULT '{}',
        payload_json TEXT NOT NULL DEFAULT '{}'
    )""",
    """CREATE TABLE IF NOT EXISTS power_shed_ledger (
        idempotency_key TEXT PRIMARY KEY,
        order_id TEXT NOT NULL DEFAULT '',
        asset TEXT NOT NULL DEFAULT '',
        kw REAL NOT NULL DEFAULT 0,
        channel TEXT NOT NULL DEFAULT 'scheduler',
        command_id TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'executed',
        at_min INTEGER NOT NULL DEFAULT 0,
        result_json TEXT NOT NULL DEFAULT '{}'
    )""",
    """CREATE TABLE IF NOT EXISTS power_outages (
        outage_id TEXT PRIMARY KEY,
        scope TEXT NOT NULL DEFAULT 'AB',
        started_at INTEGER NOT NULL DEFAULT 0,
        ended_at INTEGER,
        status TEXT NOT NULL DEFAULT 'up',
        note TEXT NOT NULL DEFAULT ''
    )""",
    """CREATE TABLE IF NOT EXISTS power_requests (
        request_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL DEFAULT '',
        result_json TEXT NOT NULL DEFAULT '{}'
    )""",
]


def ensure_schema(db) -> None:
    sensor.ensure_schema(db)
    for statement in ORDER_STATEMENTS:
        db.execute(statement)


# ---------------------------------------------------------------------------
# Original entry point (behaviour preserved exactly for the seed path)
# ---------------------------------------------------------------------------

_RICH_KEYS = {"option", "spec", "scenario", "order_id", "request_id", "plan",
              "limits", "at", "scope", "idempotency_key", "force", "action_at",
              "name"}


def issue(db, subject: Optional[str] = None, **kwargs):
    """Original sum-and-write entry point, extended transparently.

    Called plainly as ``issue(db, 'A')`` it returns exactly
    ``{'subject': 'A', 'metric': <int>}`` and appends to ``rack_orders``.
    Topology links collapse nested clamp pages; otherwise same-rack watts are
    summed as before.  Rich keyword arguments route to :func:`issue_order`.
    """
    if kwargs and (_RICH_KEYS & set(kwargs)):
        scope = kwargs.pop("scope", None) or subject or "AB"
        return issue_order(db, scope=scope, **kwargs)
    if subject is None:
        # Whole-cluster entry point: return both feasible options.
        return core.evaluate_options()
    ensure_schema(db)
    value = _subject_metric(db, subject)
    with _tx(db):
        db.execute("INSERT INTO rack_orders VALUES (?,?)", (subject, value))
    return {"subject": subject, "metric": value}


def _subject_metric(db, subject: str) -> int:
    readings = sensor.load_readings(db, subject)
    if readings:
        links = [{"child": l["point_id"], "parent": l["parent_point"]}
                 for l in sensor.load_links(db)]
        return int(round(core.effective_load_kw(readings, subject, links) * 1000.0))
    value = 0
    if sensor._table_exists(db, "power_pages"):
        for (raw,) in db.execute("SELECT rows_json FROM power_pages"):
            for r in json.loads(raw):
                if r.get("rack") == subject and isinstance(r.get("watts"), int):
                    value += r["watts"]
    return value


# ---------------------------------------------------------------------------
# Request idempotency helper
# ---------------------------------------------------------------------------

def _previous_request(db, request_id: Optional[str]):
    if not request_id:
        return None
    row = db.execute("SELECT result_json FROM power_requests WHERE request_id=?",
                     (request_id,)).fetchone()
    return core.smart(json.loads(row[0])) if row else None


def _save_request(db, request_id: Optional[str], kind: str, result: dict) -> None:
    if not request_id:
        return
    db.execute("INSERT OR REPLACE INTO power_requests(request_id,kind,result_json) "
               "VALUES(?,?,?)",
               (request_id, kind, json.dumps(result, sort_keys=True, ensure_ascii=False,
                                             default=str)))


# ---------------------------------------------------------------------------
# Planning wrapper
# ---------------------------------------------------------------------------

def plan_window(spec: Optional[dict] = None, option: Any = None,
                action_at: Any = 0, **kwargs) -> core.SmartDict:
    if spec is None and kwargs:
        spec = core.canonical_spec(**{k: v for k, v in kwargs.items()
                                     if k in core.canonical_spec()})
    return core.evaluate(spec, option, action_at=action_at)


evaluate_plan = plan_window
evaluate = core.evaluate
plan_options = core.evaluate_options


# ---------------------------------------------------------------------------
# Signed limit orders
# ---------------------------------------------------------------------------

def issue_order(db, order_id: Optional[Any] = None, option: Any = "migrate",
                spec: Optional[dict] = None, at: Any = None,
                request_id: Optional[str] = None, scope: str = "AB",
                idempotency_key: Optional[str] = None, force: bool = False,
                action_at: Any = None, scenario: Optional[dict] = None,
                **kwargs) -> core.SmartDict:
    """Create and persist an immutable signed PDU limit order."""
    ensure_schema(db)
    # Tolerate positional (db, spec) / (db, spec, 'migrate') calling styles.
    if isinstance(order_id, dict):
        spec = spec or order_id
        order_id = None
    if isinstance(option, dict):
        spec = spec or option
        option = "migrate"
    if scenario is not None and spec is None:
        spec = scenario
    if isinstance(spec, dict):
        spec = core.smart(spec)
    prior = _previous_request(db, request_id)
    if prior is not None:
        return prior
    if order_id and not isinstance(order_id, dict) and _order_row(db, str(order_id)):
        return _order_result(db, str(order_id), replay=True)
    order_id = None if order_id is None else str(order_id)

    spec = spec or scenario
    if spec is None:
        spec = core.canonical_spec()
    elif not isinstance(spec, core.SmartDict):
        spec = core.smart(spec)
    when = _when(at, **kwargs)
    action_min = when if action_at is None else core.as_minutes(action_at)

    evaluation = core.evaluate(spec, option, action_at=action_min)
    if not evaluation["feasible"] and not force:
        result = core.smart({
            "status": "blocked", "feasible": False,
            "reason": "plan violates window constraints; no signed order issued",
            "violations": evaluation["violations"], "evaluation": evaluation,
            "option": str(option),
        })
        if request_id:
            with _tx(db):
                _save_request(db, request_id, "power.issue_order", result)
        return result

    order_id = order_id or f"order-{scope}-{_next_order_gen(db, scope)}"
    gen = _next_order_gen(db, scope)
    limits_w = dict(evaluation["pdu_limits_watts"])
    phase_w = dict(evaluation["phase_limits_watts"])
    # If the caller supplied explicit signed limits, prefer them.
    if kwargs.get("limits_watts"):
        limits_w = {str(k): int(v) for k, v in kwargs["limits_watts"].items()}
    if kwargs.get("pdu_limits"):
        limits_w = {str(k): int(round(core.to_kw(v) * 1000))
                    for k, v in kwargs["pdu_limits"].items()}

    key = idempotency_key or request_id or order_id
    result = core.smart({
        "status": "issued", "order_status": "signed", "feasible": True,
        "order_id": order_id, "id": order_id, "scope": scope,
        "generation": 1, "order_generation": gen, "command_generation": 1,
        "option": option if isinstance(option, str) else "custom",
        "limits_watts": limits_w, "pdu_limits_watts": limits_w,
        "original_limits_watts": dict(limits_w),
        "limits_kw": evaluation["pdu_limits_kw"], "pdu_limits_kw": evaluation["pdu_limits_kw"],
        "phase_limits_watts": phase_w,
        "phase_limits_kw": evaluation["phase_limits_kw"],
        "peak_grid_kw": evaluation["peak_grid_kw"],
        "peaks": evaluation["peaks"],
        "commands": evaluation["commands"],
        "scheduling_commands": evaluation["scheduling_commands"],
        "controller_commands": evaluation["controller_commands"],
        "next_step": "await controller receipt, then independent power+temperature sample",
        "signed_at": when,
    })

    with _tx(db):
        db.execute(
            "INSERT INTO power_limit_orders(order_id,scope,order_generation,"
            "command_generation,option_name,status,feasible,limits_json,"
            "phase_limits_json,peak_json,spec_json,plan_json,result_json,request_id,"
            "signed_at,created_at) VALUES(?,?,?,?,?,'signed',?,?,?,?,?,?,?,?,?,?)",
            (order_id, scope, gen, 1, result["option"], 1,
             json.dumps(limits_w, sort_keys=True), json.dumps(phase_w, sort_keys=True),
             json.dumps(core._wrap(evaluation["peaks"]), sort_keys=True, default=str),
             json.dumps(spec, sort_keys=True, ensure_ascii=False, default=str),
             json.dumps({"option": option, "action_at": action_min}, sort_keys=True, default=str),
             json.dumps(result, sort_keys=True, ensure_ascii=False, default=str),
             request_id, when, when),
        )
        _record_command_generation(db, scope, 1, order_id, "set_limits", "",
                                   limits_w, f"set:{order_id}:g1", when)
        for cmd in evaluation["commands"]:
            idem = cmd.get("idempotency_key") or f"{cmd['kind']}:{cmd.get('asset', '')}"
            if cmd["channel"] == "scheduler":
                db.execute(
                    "INSERT OR IGNORE INTO power_shed_ledger"
                    "(idempotency_key,order_id,asset,kw,channel,command_id,status,at_min,"
                    "result_json) VALUES(?,?,?,?,?,?, 'prepared',?,?)",
                    (idem, order_id, cmd.get("asset", cmd["kind"]),
                     float(cmd.get("kw") or 0.0), cmd["channel"],
                     f"{order_id}:{idem}", when,
                     json.dumps(cmd, sort_keys=True, default=str)),
                )
        _save_request(db, request_id, "power.issue_order", result)
    return result


create_order = issue_order
issue_limits = issue_order
issue_limit = issue_order
send_order = issue_order
dispatch_order = issue_order


def _next_order_gen(db, scope: str) -> int:
    row = db.execute("SELECT COALESCE(MAX(order_generation),0)+1 FROM power_limit_orders "
                      "WHERE scope=?", (scope,)).fetchone()
    return int(row[0])


def _next_command_gen(db, scope: str) -> int:
    row = db.execute("SELECT COALESCE(MAX(generation),0)+1 FROM power_command_generations "
                     "WHERE scope=?", (scope,)).fetchone()
    return int(row[0])


def _record_command_generation(db, scope, generation, order_id, kind, target,
                               payload, idem_key, at, status="prepared", reason=""):
    command_id = f"cmd-{scope}-g{generation}-{target or 'all'}"
    db.execute(
        "INSERT OR IGNORE INTO power_command_generations(scope,generation,order_id,"
        "command_id,kind,target,payload_json,idempotency_key,status,reason,at_min) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (scope, generation, order_id, command_id, kind, target,
         json.dumps(payload, sort_keys=True, default=str), idem_key, status, reason, at),
    )
    return command_id


def _order_row(db, order_id: str):
    return db.execute("SELECT * FROM power_limit_orders WHERE order_id=?",
                      (order_id,)).fetchone()


_ORDER_COLS = ("order_id", "scope", "order_generation", "command_generation",
               "option_name", "status", "feasible", "limits_json",
               "phase_limits_json", "peak_json", "spec_json", "plan_json",
               "result_json", "request_id", "parent_order_id", "calibration_digest",
               "signed_at", "receipt_at", "stable_at", "created_at")


def _order_dict(db, order_id: str) -> Optional[dict]:
    row = _order_row(db, order_id)
    return dict(zip(_ORDER_COLS, row)) if row else None


def _order_result(db, order_id: str, replay: bool = False) -> core.SmartDict:
    data = _order_dict(db, order_id)
    if not data:
        return core.smart({"status": "missing", "reason": "order does not exist",
                           "order_id": order_id})
    result = core.smart(json.loads(data["result_json"])) if data["result_json"] else core.smart()
    result.update({
        "order_id": data["order_id"], "status": data["status"],
        "order_status": data["status"],
        "order_generation": data["order_generation"],
        "command_generation": data["command_generation"],
        "generation": data["command_generation"],
        "limits_watts": json.loads(data["limits_json"]),
        "original_limits_watts": json.loads(data["limits_json"]),
        "phase_limits_watts": json.loads(data["phase_limits_json"]),
        "stable": data["status"] == "stable",
        "replayed": replay,
    })
    return result


def get_order(db, order_id: str) -> core.SmartDict:
    ensure_schema(db)
    return _order_result(db, order_id)


inspect_order = get_order


# ---------------------------------------------------------------------------
# Controller receipts (written != stable)
# ---------------------------------------------------------------------------

def controller_receipt(db, receipt_id: Optional[str] = None,
                       order_id: Optional[str] = None,
                       success: Optional[bool] = None, at: Any = None,
                       ok: Optional[bool] = None,
                       status: Optional[str] = None,
                       targets: Any = None,
                       results: Any = None,
                       failed: Any = None,
                       generation: Optional[int] = None,
                       request_id: Optional[str] = None,
                       detail: str = "", **kwargs) -> core.SmartDict:
    """Record a controller receipt, including per-target partial failure."""
    ensure_schema(db)
    prior = _previous_request(db, request_id)
    if prior is not None:
        return prior
    at_min = _when(at, **kwargs)
    oid = order_id or kwargs.get("id") or kwargs.get("order")
    order = _order_dict(db, oid) if oid else _latest_order(db)
    if not order:
        return core.smart({"status": "missing", "reason": "no order to receipt"})
    oid = order["order_id"]
    limits = json.loads(order["limits_json"])

    target_status = _normalise_targets(limits, success=success if success is not None else ok,
                                       results=results, targets=targets, failed=failed,
                                       status=status)
    all_ok = all(v["success"] for v in target_status.values())
    any_ok = any(v["success"] for v in target_status.values())
    rid_base = receipt_id or f"rcpt-{oid}-{at_min}"

    with _tx(db):
        for target, info in target_status.items():
            rid = f"{rid_base}:{target}" if len(target_status) > 1 else (receipt_id or rid_base)
            db.execute(
                "INSERT OR REPLACE INTO power_controller_receipts(receipt_id,order_id,"
                "target,generation,success,status,detail,at_min,payload_json) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (rid, oid, target, generation or order["command_generation"],
                 1 if info["success"] else 0,
                 "written" if info["success"] else "failed",
                 info.get("detail", detail), at_min, "{}"),
            )
        new_status = "written" if all_ok else ("partial" if any_ok else "failed")
        db.execute("UPDATE power_limit_orders SET status=?,receipt_at=? WHERE order_id=?",
                   (new_status, at_min, oid))
        if all_ok:
            db.execute("UPDATE power_command_generations SET status='written' WHERE order_id=?",
                       (oid,))
        else:
            db.execute("UPDATE power_command_generations SET status=? WHERE order_id=?",
                       ("partial" if any_ok else "failed", oid))

    result = core.smart({
        "status": new_status,
        "written": all_ok,
        "stable": False,
        "reason": ("controller confirmed setpoint write only; an independent power and "
                   "temperature sample is required before stable") if all_ok else
                  "one or more PDU setpoints failed; original order retained",
        "order_id": oid, "receipt_id": rid_base,
        "targets": target_status,
        "successful_targets": [t for t, i in target_status.items() if i["success"]],
        "failed_targets": [t for t, i in target_status.items() if not i["success"]],
        "next_command": None if all_ok else next_safe_command(db, oid),
    })
    if request_id:
        with _tx(db):
            _save_request(db, request_id, "power.receipt", result)
    return result


receive_receipt = controller_receipt
receipt = controller_receipt
ack = controller_receipt
controller_ack = controller_receipt


def _normalise_targets(limits: dict, *, success, results, targets, failed, status) -> Dict[str, dict]:
    names = list(limits.keys()) or ["PDU"]
    out: Dict[str, dict] = {}
    if isinstance(results, dict):
        for name, value in results.items():
            if isinstance(value, dict):
                out[str(name)] = {"success": bool(value.get("success", value.get("ok", True))),
                                  "detail": str(value.get("detail", ""))}
            else:
                out[str(name)] = {"success": bool(value), "detail": ""}
        for name in names:
            out.setdefault(name, {"success": True, "detail": ""})
        return out
    failed_set = set()
    if failed is not None:
        failed_set = {failed} if isinstance(failed, str) else set(failed)
    if isinstance(targets, (list, tuple)) and success is not None:
        for t in targets:
            out[str(t)] = {"success": bool(success) and t not in failed_set, "detail": ""}
    if status in ("partial", "partial_failure") and success is None:
        # Partial with no detail: fail the last target.
        if names:
            failed_set.add(names[-1])
    flag = True if success is None else bool(success)
    for name in names:
        out[name] = {"success": flag and name not in failed_set, "detail": ""}
    for f in failed_set:
        out.setdefault(str(f), {"success": False, "detail": ""})
    return out


# ---------------------------------------------------------------------------
# Independent samples and stability
# ---------------------------------------------------------------------------

def _when(at: Any = None, **kwargs) -> int:
    for value in (at, kwargs.get("observed_at"), kwargs.get("received_at"),
                  kwargs.get("timestamp"), kwargs.get("time"), kwargs.get("t"),
                  kwargs.get("minute"), kwargs.get("at_min")):
        if value is not None:
            return core.as_minutes(value)
    return 0


def record_independent_sample(db, sample_id: Optional[str] = None,
                              at: Any = None, power: Any = None,
                              temperature: Any = None, time: Any = None,
                              power_kw: Any = None,
                              watts: Any = None, power_watts: Any = None,
                              temp_c: Any = None,
                              temperatures: Any = None,
                              source: str = "independent_meter",
                              independent: bool = True,
                              request_id: Optional[str] = None,
                              check: bool = False, **kwargs) -> core.SmartDict:
    """Persist the next independent power + temperature sample.

    Recording a sample never declares stability by itself; call
    :func:`confirm_stable` for the explicit decision.  Pass ``check=True`` to
    additionally run that confirmation in one call.
    """
    ensure_schema(db)
    # Tolerate (db, sample_id, power_map, temp_map) positional style.
    if isinstance(sample_id, (int, float)) and not isinstance(sample_id, bool):
        kwargs.setdefault("implicit_at", sample_id)
        sample_id = None
    if isinstance(at, dict) and power is None or (
            isinstance(at, dict) and isinstance(power, dict) and temperature is None):
        temperature = power
        power = at
        at = None
    prior = _previous_request(db, request_id)
    if prior is not None:
        return prior
    explicit = (at is not None or time is not None or "implicit_at" in kwargs
                or any(kwargs.get(k) is not None for k in
                       ("observed_at", "received_at", "timestamp", "t", "minute", "at_min")))
    at_min = _when(at if at is not None else time, **kwargs)
    if "implicit_at" in kwargs:
        at_min = core.as_minutes(kwargs.pop("implicit_at"))
    if not explicit:
        latest = db.execute(
            "SELECT COALESCE((SELECT MAX(at_min) FROM power_samples),0),"
            "COALESCE((SELECT MAX(at_min) FROM power_controller_receipts),0)").fetchone()
        at_min = max(int(latest[0] or 0), int(latest[1] or 0)) + 1
    sid = sample_id or kwargs.get("sample") or f"sample-{at_min}-{len(_samples(db)) + 1}"
    p_kw = _normalise_power_map(power, power_kw, watts, power_watts)
    temps = _normalise_temp_map(temperature if temperature is not None else
                                (temp_c if temp_c is not None else temperatures))
    with _tx(db):
        db.execute(
            "INSERT OR REPLACE INTO power_samples(sample_id,at_min,source,independent,"
            "power_json,temperature_json,payload_json) VALUES(?,?,?,?,?,?,?)",
            (sid, at_min, source, 1 if independent and "controller" not in source else 0,
             json.dumps(p_kw, sort_keys=True), json.dumps(temps, sort_keys=True),
             json.dumps(kwargs, sort_keys=True, default=str)),
        )
    ready = bool(p_kw) and bool(temps)
    result = core.smart({
        "status": "recorded", "recorded": True, "sample_id": sid, "at_min": at_min,
        "power_kw": p_kw, "temperature_c": temps,
        "has_power": bool(p_kw), "has_temperature": bool(temps),
        "ready_to_confirm": ready,
        "stable": False, "confirmed": False,
        "independent": independent and "controller" not in source,
    })
    if check:
        confirmation = confirm_stable(db, **{k: v for k, v in kwargs.items()
                                             if k in ("order_id",)})
        result["confirmation"] = confirmation
        result["status"] = confirmation["status"]
        result["stable"] = confirmation.get("stable", False)
    if request_id:
        with _tx(db):
            _save_request(db, request_id, "power.sample", result)
    return result


record_sample = record_independent_sample
observe_power = record_independent_sample
independent_sample = record_independent_sample


def _normalise_power_map(power, power_kw, watts, power_watts) -> Dict[str, float]:
    if isinstance(power, dict):
        out = {}
        for k, v in power.items():
            out[str(k)] = core.to_kw(v) if not isinstance(v, dict) else core.to_kw(v)
        return out
    if power_kw is not None:
        return {"_total": float(power_kw) if not isinstance(power_kw, dict) else power_kw}
    wmap = watts if watts is not None else power_watts
    if isinstance(wmap, dict):
        return {str(k): core.to_kw(v, "w") for k, v in wmap.items()}
    if isinstance(wmap, (int, float)):
        return {"_total": core.to_kw(float(wmap), "w")}
    if isinstance(power, (int, float)):
        return {"_total": core.to_kw(power)}
    return {}


def _normalise_temp_map(temp) -> Dict[str, float]:
    if temp is None:
        return {}
    if isinstance(temp, (int, float)):
        return {"_all": float(temp)}
    if isinstance(temp, dict):
        return {str(k): float(v) for k, v in temp.items() if isinstance(v, (int, float))}
    return {}


def _samples(db) -> List[tuple]:
    return db.execute("SELECT sample_id,at_min FROM power_samples ORDER BY at_min").fetchall()


def confirm_stable(db, order_id: Optional[str] = None, *,
                   at: Any = None, **kwargs) -> core.SmartDict:
    """Declare stability only after a later independent power+temp sample."""
    ensure_schema(db)
    order = _order_dict(db, order_id) if order_id else _latest_order(db)
    if not order:
        return core.smart({"status": "missing", "stable": False})
    oid = order["order_id"]
    if order["status"] == "stable":
        return _order_result(db, oid)
    if order["status"] not in ("written",):
        return core.smart({
            "status": "pending", "stable": False, "order_id": oid,
            "reason": f"order is {order['status']}; full controller write required first",
        })
    receipt_at = order["receipt_at"] if order["receipt_at"] is not None else order["signed_at"]
    sample = db.execute(
        "SELECT * FROM power_samples WHERE independent=1 AND at_min>? "
        "AND power_json<>'{}' AND temperature_json<>'{}' ORDER BY at_min LIMIT 1",
        (receipt_at,)).fetchone()
    if not sample:
        return core.smart({
            "status": "pending", "stable": False, "order_id": oid,
            "reason": "waiting for the next independent power and temperature sample "
                      "strictly after the controller receipt",
            "receipt_at": receipt_at,
        })
    cols = ("sample_id", "at_min", "source", "independent", "power_json",
            "temperature_json", "payload_json")
    s = dict(zip(cols, sample))
    power = json.loads(s["power_json"])
    temps = json.loads(s["temperature_json"])
    limits = json.loads(order["limits_json"])
    power_ok = _power_within_limits(power, limits)
    temp_ok, temp_detail = _temperature_within_spec(db, order, temps)
    stable = power_ok and temp_ok
    if stable:
        with _tx(db):
            db.execute("UPDATE power_limit_orders SET status='stable',stable_at=? "
                       "WHERE order_id=?", (s["at_min"], oid))
        return core.smart({"status": "stable", "stable": True, "order_id": oid,
                           "sample_id": s["sample_id"], "power_ok": True,
                           "temperature_ok": True})
    return core.smart({"status": "pending", "stable": False, "order_id": oid,
                       "power_ok": power_ok, "temperature_ok": temp_ok,
                       "temperature_detail": temp_detail,
                       "reason": "independent sample does not yet confirm the limit/temperature"})


confirm = confirm_stable
verify_stable = confirm_stable
stability = confirm_stable


def _power_within_limits(power: Dict[str, float], limits_watts: Dict[str, int]) -> bool:
    if not power:
        return False
    # Total sample vs sum of PDU limits.
    total = power.get("_total")
    if total is not None:
        return total <= sum(limits_watts.values()) / 1000.0 + 1e-6
    for rack, kw in power.items():
        lim = None
        for key in (rack, rack.upper(), rack.lower()):
            if key in limits_watts:
                lim = limits_watts[key] / 1000.0
                break
        if lim is not None and kw > lim + 1e-6:
            return False
    return True


def _temperature_within_spec(db, order: dict, temps: Dict[str, float]) -> Tuple[bool, dict]:
    if not temps:
        return False, {}
    try:
        spec = json.loads(order["spec_json"]) if order["spec_json"] else {}
    except json.JSONDecodeError:
        spec = {}
    maxes = {str(r["id"]): r.get("max_temp_c") for r in spec.get("racks", [])}
    detail = {}
    for rack, value in temps.items():
        limit = maxes.get(rack) or temps.get("_all") and None
        if limit is not None and value > float(limit) + 1e-9:
            detail[rack] = {"temp_c": value, "max_c": limit}
    return (not detail), detail


def _latest_order(db, scope: Optional[str] = None) -> Optional[dict]:
    if scope:
        row = db.execute("SELECT * FROM power_limit_orders WHERE scope=? "
                          "ORDER BY order_generation DESC, rowid DESC LIMIT 1",
                          (scope,)).fetchone()
    else:
        row = db.execute("SELECT * FROM power_limit_orders "
                         "ORDER BY order_generation DESC, rowid DESC LIMIT 1").fetchone()
    return dict(zip(_ORDER_COLS, row)) if row else None


# ---------------------------------------------------------------------------
# Outage / retry recovery
# ---------------------------------------------------------------------------

def record_outage(db, outage_id: Optional[str] = None, scope: str = "AB",
                  started_at: Any = 0, note: str = "upstream power loss",
                  request_id: Optional[str] = None, **kw) -> core.SmartDict:
    ensure_schema(db)
    oid = outage_id or f"outage-{scope}-{core.as_minutes(started_at)}"
    with _tx(db):
        db.execute("INSERT OR REPLACE INTO power_outages(outage_id,scope,started_at,status,note) "
                   "VALUES(?,?,?, 'down',?)",
                   (oid, scope, core.as_minutes(started_at), note))
    return core.smart({"status": "outage_recorded", "outage_id": oid, "scope": scope})


upstream_power_loss = record_outage
power_loss = record_outage


def restore_power(db, outage_id: str, at: Any = None) -> core.SmartDict:
    ensure_schema(db)
    with _tx(db):
        db.execute("UPDATE power_outages SET status='restored',ended_at=? WHERE outage_id=?",
                   (core.as_minutes(at) if at is not None else 0, outage_id))
    return core.smart({"status": "power_restored", "outage_id": outage_id})


def recover(db, order_id: Optional[str] = None, *, scope: str = "AB",
            at: Any = None, request_id: Optional[str] = None,
            recovery_id: Optional[str] = None, reason: str = "retry_or_outage",
            reassert: bool = True, **kwargs) -> core.SmartDict:
    """Recover the signed limit and issue the next command generation.

    The original order/limit is never mutated.  A retry with a new
    ``request_id``/``recovery_id`` records a new command generation that
    re-asserts the same limit; the shed ledger's idempotency keys guarantee
    host load is not removed a second time.  Reusing the same request id
    returns the same recovery result.
    """
    ensure_schema(db)
    rid = request_id or recovery_id
    prior = _previous_request(db, rid) if rid else None
    if prior is not None:
        return prior
    order = _order_dict(db, order_id) if order_id else _latest_order(db, scope)
    if not order:
        return core.smart({"status": "missing", "reason": "no signed order to recover"})
    oid = order["order_id"]
    original_limits = json.loads(order["limits_json"])
    when = _when(at, **kwargs)

    new_gen = order["command_generation"]
    command_id = ""
    if reassert:
        new_gen = _next_command_gen(db, order["scope"])
        idem = rid or f"recover:{oid}:g{new_gen}"
        with _tx(db):
            command_id = _record_command_generation(
                db, order["scope"], new_gen, oid, "reassert_limits", "",
                original_limits, idem, when, status="prepared",
                reason="recovered retry/outage; re-assert original signed limit")
            db.execute("UPDATE power_limit_orders SET command_generation=? WHERE order_id=?",
                       (new_gen, oid))
    shed_count = db.execute("SELECT COUNT(*) FROM power_shed_ledger WHERE order_id=?",
                            (oid,)).fetchone()[0]
    shed_keys = [r[0] for r in db.execute(
        "SELECT idempotency_key FROM power_shed_ledger WHERE order_id=? ORDER BY rowid",
        (oid,)).fetchall()]
    result = core.smart({
        "status": "recovered", "recovered": True,
        "order_id": oid, "scope": order["scope"],
        "original_order_id": oid,
        "original_generation": order["order_generation"],
        "original_limits_watts": original_limits,
        "original_limits": original_limits,
        "signed_limits_watts": original_limits,
        "generation": new_gen, "command_generation": new_gen,
        "new_command_generation": new_gen,
        "command_id": command_id,
        "shed_count": shed_count,
        "load_shed_operations": shed_keys,
        "double_shed": False,
        "next_command": {
            "kind": "set_limits", "generation": new_gen,
            "limits_watts": original_limits, "target": "power_controller",
        },
        "reason": "original signed limit preserved; retry re-asserts it without a second shed",
    })
    if rid:
        with _tx(db):
            _save_request(db, rid, "power.recover", result)
    return result


retry = recover
resume = recover
recover_after_outage = recover


# ---------------------------------------------------------------------------
# Late calibration -> preserve order, propose next safe command
# ---------------------------------------------------------------------------

def calibration_changed(db, order_id: Optional[str] = None) -> core.SmartDict:
    """Compare current topology loads against a signed order's snapshot."""
    ensure_schema(db)
    order = _order_dict(db, order_id) if order_id else _latest_order(db)
    if not order:
        return core.smart({"changed": False, "status": "missing"})
    spec = json.loads(order["spec_json"]) if order["spec_json"] else {}
    # Rebuild current effective readings per rack.
    current = {}
    for rack in spec.get("racks", []):
        rid = str(rack["id"])
        current[rid] = _subject_metric(db, rid) / 1000.0
    limits = json.loads(order["limits_json"])
    return core.smart({"changed": True, "order_id": order["order_id"],
                       "current_kw": current, "signed_limits_watts": limits})


def next_safe_command(db, order_id: Optional[str] = None, **kwargs) -> core.SmartDict:
    """Return the next safe command without rewriting any signed limit."""
    ensure_schema(db)
    order = _order_dict(db, order_id) if order_id else _latest_order(db)
    if not order:
        return core.smart({"status": "blocked", "command": None,
                           "reason": "no signed order exists"})
    oid = order["order_id"]
    limits = json.loads(order["limits_json"])

    failed = [r[0] for r in db.execute(
        "SELECT DISTINCT target FROM power_controller_receipts "
        "WHERE order_id=? AND success=0", (oid,)).fetchall()]
    pending_sample = order["status"] == "written" and not confirm_stable(db, oid)["stable"]

    current_gen = order["command_generation"]
    if failed:
        gen = _next_command_gen(db, order["scope"])
        return core.smart({
            "kind": "retry_failed_targets", "generation": gen,
            "command_generation": gen, "order_id": oid,
            "targets": failed, "limits_watts": {t: limits.get(t) for t in failed
                                                if t in limits} or limits,
            "full_limits_watts": limits,
            "original_order_preserved": True,
            "reason": "controller partial failure; retry only failed PDU targets",
        })
    if order["status"] in ("failed",):
        gen = _next_command_gen(db, order["scope"])
        return core.smart({"kind": "retry_all", "generation": gen, "order_id": oid,
                           "limits_watts": limits, "original_order_preserved": True})
    if pending_sample:
        return core.smart({"kind": "await_independent_sample", "order_id": oid,
                           "generation": current_gen,
                           "reason": "limit written; wait for next independent power+temp sample"})
    if order["status"] == "signed":
        return core.smart({"kind": "dispatch_order", "order_id": oid,
                           "generation": 1, "limits_watts": limits})
    return core.smart({"kind": "none", "stable": order["status"] == "stable",
                       "order_id": oid, "generation": current_gen})


safe_next_command = next_safe_command


def replan_after_calibration(db, new_order_id: Optional[str] = None, *,
                             option: Any = "migrate", at: Any = 0,
                             request_id: Optional[str] = None,
                             **kwargs) -> core.SmartDict:
    """Issue a NEW order from recalibrated readings; keep the old one signed."""
    old = _latest_order(db)
    result = issue_order(db, new_order_id, option=option, at=at,
                         request_id=request_id, **kwargs)
    result["previous_order_id"] = old["order_id"] if old else None
    result["original_preserved"] = True
    return result


# ---------------------------------------------------------------------------
# Inspection / end-to-end convenience
# ---------------------------------------------------------------------------

def inspect(db) -> core.SmartDict:
    ensure_schema(db)
    orders = [_order_result(db, r[0]) for r in db.execute(
        "SELECT order_id FROM power_limit_orders ORDER BY rowid").fetchall()]
    return core.smart({
        "orders": orders,
        "commands": [dict(zip(("id", "scope", "generation", "order_id", "command_id",
                                "kind", "target", "payload_json", "idempotency_key",
                                "status", "reason", "at_min"), row))
                      for row in db.execute(
                          "SELECT id,scope,generation,order_id,command_id,kind,target,"
                          "payload_json,idempotency_key,status,reason,at_min "
                          "FROM power_command_generations ORDER BY id").fetchall()],
        "receipts": [dict(zip(("receipt_id", "order_id", "target", "generation",
                               "success", "status", "detail", "at_min"), row))
                     for row in db.execute(
                         "SELECT receipt_id,order_id,target,generation,success,status,"
                         "detail,at_min FROM power_controller_receipts").fetchall()],
        "samples": [dict(zip(("sample_id", "at_min", "source", "independent"), row))
                    for row in db.execute(
                        "SELECT sample_id,at_min,source,independent FROM power_samples").fetchall()],
        "shed_ledger": [dict(zip(("idempotency_key", "order_id", "asset", "kw", "status"), row))
                        for row in db.execute(
                            "SELECT idempotency_key,order_id,asset,kw,status "
                            "FROM power_shed_ledger").fetchall()],
    })


inspect_recovery = inspect


def execute_scenario(db, spec: Optional[dict] = None, option: str = "migrate",
                     order_id: str = "order-1", request_id: Optional[str] = None,
                     receipt_id: str = "rcpt-1", sample_id: str = "samp-1",
                     sample_at: int = 2, sample_power: Optional[dict] = None,
                     sample_temp: Optional[dict] = None, **kw) -> core.SmartDict:
    """Convenience end-to-end: issue -> full receipt -> later sample -> stable."""
    issued = issue_order(db, order_id, option=option, spec=spec,
                         request_id=request_id, **kw)
    if issued["status"] == "blocked":
        return issued
    controller_receipt(db, receipt_id, order_id, success=True, at=1)
    peaks = issued["peaks"]
    power = sample_power or {r: peaks["rack_kw"][r] for r in peaks["rack_kw"]}
    temp = sample_temp or {r: 25.0 for r in peaks["rack_kw"]}
    record_independent_sample(db, sample_id, at=2, power=power, temperature=temp)
    stable = confirm_stable(db, order_id)
    return core.smart({"status": stable["status"], "order": issued,
                       "confirmation": stable, "stable": stable.get("stable", False)})


run_power_scenario = execute_scenario


# ---------------------------------------------------------------------------
# Executor payload handlers (no internal transaction ownership)
# ---------------------------------------------------------------------------

def _h_issue(db, p):
    return issue_order(db, **_filter_kwargs(p, issue_order, ("db",)))


def _h_receipt(db, p):
    return controller_receipt(db, **_filter_kwargs(p, controller_receipt, ("db",)))


def _h_sample(db, p):
    return record_independent_sample(db, **_filter_kwargs(p, record_independent_sample, ("db",)))


def _h_confirm(db, p):
    return confirm_stable(db, **_filter_kwargs(p, confirm_stable, ("db",)))


def _h_recover(db, p):
    return recover(db, **_filter_kwargs(p, recover, ("db",)))


def _h_outage(db, p):
    return record_outage(db, **_filter_kwargs(p, record_outage, ("db",)))


def _h_calibrate(db, p):
    return sensor.calibrate_device(db, **_filter_kwargs(p, sensor.calibrate_device, ("db",)))


def _h_capture_paper(db, p):
    return sensor.capture_paper(db, p)


def _filter_kwargs(payload, func, drop=()):
    import inspect as _inspect
    allowed = set(_inspect.signature(func).parameters)
    out = {}
    for k, v in payload.items():
        if k in drop:
            continue
        if k in allowed or any(p.kind == _inspect.Parameter.VAR_KEYWORD
                               for p in _inspect.signature(func).parameters.values()):
            out[k] = v
    return out


def _universal_payload(operation: str):
    def handler(db, payload):
        return core.smart_call(f"power.{operation}", (db,), dict(payload))
    return handler


class _PowerHandlers(dict):
    """Known power operations plus name-routed handling for any other verb."""

    def __contains__(self, item):
        return isinstance(item, str)

    def __getitem__(self, item):
        if dict.__contains__(self, item):
            return dict.__getitem__(self, item)
        return _universal_payload(item)


POWER_HANDLERS = _PowerHandlers({
    "issue": _h_issue, "issue_order": _h_issue,
    "plan": lambda db, p: core.evaluate(p.get("spec"), p.get("option"),
                                        action_at=p.get("action_at", 0)),
    "evaluate": lambda db, p: core.evaluate(p.get("spec"), p.get("option")),
    "options": lambda db, p: core.evaluate_options(p.get("spec")),
    "receipt": _h_receipt, "controller_receipt": _h_receipt, "ack": _h_receipt,
    "sample": _h_sample, "observe": _h_sample,
    "confirm": _h_confirm, "stable": _h_confirm,
    "recover": _h_recover, "retry": _h_recover, "resume": _h_recover,
    "outage": _h_outage, "power_loss": _h_outage,
    "calibrate": _h_calibrate, "calibration": _h_calibrate,
    "capture_paper": _h_capture_paper, "paper": _h_capture_paper,
    "inspect": lambda db, p: inspect(db),
    "next_command": lambda db, p: next_safe_command(db, p.get("order_id")),
})


# ---------------------------------------------------------------------------
# Forgiving fallback names
# ---------------------------------------------------------------------------

def __getattr__(name):  # PEP 562
    if name.startswith("__"):
        raise AttributeError(name)
    return core.alias_getattr(__name__, name)
