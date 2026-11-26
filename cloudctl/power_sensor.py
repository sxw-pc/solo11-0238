"""Offline capture for rack electrical capacity.

Besides the original digest-backed :func:`capture` page store, this module
persists the paper evidence the operations office requires:

* device id, shared CT multiplier (互感器倍率),
* sample start/end and common clock ticket (校时票),
* PDU phase and wiring photo reference,
* measurement topology links (which clamp is nested downstream),
* shared device calibrations that move every reading of one meter.

The legacy single-page ``{'rack', 'watts'}`` contract is unchanged: the seed
page with a two watt reading still writes a two watt order metric.
"""

import hashlib
import json
from contextlib import nullcontext
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import power_core as core


def _tx(db):
    """Commit context for standalone connections; join executor transactions."""
    return core.write_tx(db)

POWER_SCHEMA = """
CREATE TABLE IF NOT EXISTS power_devices (
  device_id TEXT PRIMARY KEY,
  ratio REAL NOT NULL DEFAULT 1,
  ratio_ticket TEXT NOT NULL DEFAULT '',
  calibrated_at INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS power_calibrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  ratio REAL NOT NULL,
  ticket TEXT NOT NULL DEFAULT '',
  at_min INTEGER NOT NULL DEFAULT 0,
  note TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS power_readings (
  reading_id TEXT PRIMARY KEY,
  page TEXT NOT NULL DEFAULT '',
  ordinal INTEGER NOT NULL DEFAULT 0,
  rack TEXT NOT NULL DEFAULT '',
  point TEXT NOT NULL DEFAULT '',
  device TEXT NOT NULL DEFAULT '',
  phase TEXT NOT NULL DEFAULT '',
  watts INTEGER NOT NULL DEFAULT 0,
  raw_value REAL,
  ratio REAL NOT NULL DEFAULT 1,
  start_min INTEGER,
  end_min INTEGER,
  clock_ticket TEXT NOT NULL DEFAULT '',
  clock_offset_min REAL NOT NULL DEFAULT 0,
  photo TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT '',
  parent_point TEXT NOT NULL DEFAULT '',
  same_branch INTEGER NOT NULL DEFAULT 1,
  kw REAL NOT NULL DEFAULT 0,
  row_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS power_topology (
  point_id TEXT PRIMARY KEY,
  rack TEXT NOT NULL DEFAULT '',
  phase TEXT NOT NULL DEFAULT '',
  parent_point TEXT NOT NULL DEFAULT '',
  relation TEXT NOT NULL DEFAULT 'downstream_of',
  branch TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS clock_tickets (
  ticket TEXT PRIMARY KEY,
  source TEXT NOT NULL DEFAULT '',
  offset_min REAL NOT NULL DEFAULT 0,
  calibrated_at INTEGER NOT NULL DEFAULT 0,
  payload_json TEXT NOT NULL DEFAULT '{}'
);
"""


def ensure_schema(db) -> None:
    db.execute(
        "CREATE TABLE IF NOT EXISTS power_pages "
        "(page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)"
    )
    for statement in [s.strip() for s in POWER_SCHEMA.split(";") if s.strip()]:
        db.execute(statement)
    for statement in FACILITY_STATEMENTS:
        db.execute(statement)


FACILITY_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS power_pdu_phases (
        phase_id TEXT PRIMARY KEY,
        pdu_id TEXT NOT NULL DEFAULT '',
        rack TEXT NOT NULL DEFAULT '',
        phase TEXT NOT NULL DEFAULT '',
        limit_kw REAL,
        limit_a REAL,
        voltage_v REAL NOT NULL DEFAULT 230,
        payload_json TEXT NOT NULL DEFAULT '{}'
    )""",
    """CREATE TABLE IF NOT EXISTS power_cooling_branches (
        branch_id TEXT PRIMARY KEY,
        rack TEXT NOT NULL DEFAULT '',
        capacity_kw REAL NOT NULL DEFAULT 0,
        min_cooling_kw REAL NOT NULL DEFAULT 0,
        inertia_min INTEGER NOT NULL DEFAULT 8,
        max_temp_c REAL,
        payload_json TEXT NOT NULL DEFAULT '{}'
    )""",
    """CREATE TABLE IF NOT EXISTS power_ups_events (
        ups_id TEXT NOT NULL,
        event_id TEXT PRIMARY KEY,
        rack TEXT NOT NULL DEFAULT '',
        phase TEXT NOT NULL DEFAULT '',
        power_kw REAL NOT NULL DEFAULT 0,
        start_min INTEGER,
        end_min INTEGER,
        kind TEXT NOT NULL DEFAULT 'discharge_check',
        postponed INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'scheduled',
        payload_json TEXT NOT NULL DEFAULT '{}'
    )""",
]


# ---------------------------------------------------------------------------
# Backward compatible capture
# ---------------------------------------------------------------------------

def _valid_legacy_rows(rows: Any) -> bool:
    return (
        isinstance(rows, list)
        and rows
        and all(
            isinstance(r, dict)
            and ("rack" in r or "subject" in r or "row" in r)
            and _row_watts(r) is not None
            for r in rows
        )
    )


_ZH_ROW_KEYS = {
    "机架": "rack", "排": "rack", "机柜": "rack",
    "设备编号": "device", "设备": "device", "钳表编号": "device", "表号": "device",
    "瓦数": "watts", "瓦特": "watts",
    "互感器倍率": "ratio", "倍率": "ratio",
    "相位": "phase", "相": "phase",
    "接线照片": "photo", "照片": "photo",
    "校时票": "ticket", "校时单号": "ticket",
    "采样开始": "start", "采样起": "start", "起始": "start", "开始时间": "start",
    "采样结束": "end", "采样止": "end", "结束时间": "end", "终止": "end",
    "上游": "parent", "上级测点": "parent",
}


def _normalize_row_keys(row: dict) -> dict:
    out = dict(row)
    for key, value in list(row.items()):
        english = _ZH_ROW_KEYS.get(str(key))
        if english and english not in out:
            out[english] = value
    return out


def _row_watts(r: dict) -> Optional[int]:
    """Return non-negative integer watts when present and valid."""
    if "watts" in r:
        w = r["watts"]
        if isinstance(w, int) and not isinstance(w, bool) and w >= 0:
            return w
        return None
    if "w" in r and isinstance(r["w"], (int, float)) and r["w"] >= 0:
        return int(round(float(r["w"])))
    if "power_w" in r and isinstance(r["power_w"], (int, float)) and r["power_w"] >= 0:
        return int(round(float(r["power_w"])))
    if any(k in r for k in ("kw", "power_kw", "kilowatts")):
        try:
            return int(round(core.to_kw(r) * 1000.0))
        except (TypeError, ValueError):
            return None
    raw_key = next((k for k in ("raw", "raw_value", "dial", "indicated") if k in r), None)
    if raw_key is not None:
        try:
            raw = float(r[raw_key])
            ratio = float(r.get("ratio", r.get("ct_ratio", r.get("multiplier", 1))) or 1)
            return _raw_to_watts(raw, ratio)
        except (TypeError, ValueError):
            return None
    return None


def _first(r: dict, *names: str, default: Any = "") -> Any:
    for name in names:
        if name in r and r[name] is not None:
            return r[name]
    return default


def capture(db, page, rows, **metadata):
    """Capture an offline paper page.

    Legacy behaviour: validates rack + non-negative integer watts, stores a
    SHA-256 digest and returns ``captured`` / ``replayed``; a changed page
    raises ``ValueError('page_conflict')``.  Extra paper-evidence keys are
    accepted and normalised into relational tables.
    """
    db.execute(
        "CREATE TABLE IF NOT EXISTS power_pages "
        "(page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)"
    )
    norm_rows = [_normalize_row_keys(r) if isinstance(r, dict) else r for r in rows] \
        if isinstance(rows, list) else rows
    if not _valid_legacy_rows(norm_rows):
        raise ValueError("invalid_page")
    raw = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(raw.encode()).hexdigest()
    old = db.execute("SELECT digest FROM power_pages WHERE page=?", (page,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError("page_conflict")
        return "replayed"
    ensure_schema(db)
    with _tx(db):
        db.execute("INSERT INTO power_pages VALUES (?,?,?)", (page, digest, raw))
        _persist_rows(db, page, norm_rows, metadata)
    return "captured"


def _persist_rows(db, page: str, rows: Sequence[dict], metadata: dict) -> None:
    default_ticket = metadata.get("ticket") or metadata.get("clock_ticket") or ""
    default_photo = metadata.get("photo") or metadata.get("wiring_photo") or ""
    for i, r0 in enumerate(rows):
        r = dict(r0)
        watts = _row_watts(r)
        kw = watts / 1000.0
        device = str(_first(r, "device", "device_id", "meter", "meter_id", "clamp",
                            default=metadata.get("device", "")))
        ratio = float(_first(r, "ratio", "ct_ratio", "multiplier", "factor",
                             default=metadata.get("ratio", 1.0)) or 1.0)
        raw_value = _first(r, "raw", "raw_value", "dial", "indicated", "reading")
        raw_value = float(raw_value) if raw_value != "" else None
        if raw_value is not None:
            watts = _raw_to_watts(raw_value, ratio)
            kw = watts / 1000.0
        rid = str(_first(r, "id", "reading_id", "point_id", "key",
                         default=f"{page}:{i}"))
        rack = str(_first(r, "rack", "subject", "row", "pdu", "rack_id", default=""))
        point = str(_first(r, "point", "point_id", "location", "measurement_point",
                           default=rid))
        phase = str(_first(r, "phase", "leg", "phase_id", default=""))
        start = _first(r, "start", "start_at", "sample_start", "sampled_from",
                       "time_start", default=metadata.get("start"))
        end = _first(r, "end", "end_at", "sample_end", "sampled_to", "time_end",
                     default=metadata.get("end"))
        start_min = core.as_minutes(start) if start not in (None, "") else None
        end_min = core.as_minutes(end) if end not in (None, "") else None
        ticket = str(_first(r, "ticket", "clock_ticket", "time_ticket",
                            "calibration_ticket", default=default_ticket))
        offset = float(_first(r, "clock_offset", "offset_min", "time_offset",
                              default=0.0) or 0.0)
        photo = str(_first(r, "photo", "photo_ref", "wiring_photo", "photo_id",
                           "image", "attachment", default=default_photo))
        role = str(_first(r, "role", "point_role", "clamp_role", "position",
                          default=""))
        parent = _first(r, "parent", "parent_point", "upstream", "upstream_of",
                        "downstream_of", "component_of", "nested_in", default="")
        same_branch = 0 if r.get("different_branch") else 1
        db.execute(
            "INSERT OR REPLACE INTO power_readings "
            "(reading_id,page,ordinal,rack,point,device,phase,watts,raw_value,ratio,"
            "start_min,end_min,clock_ticket,clock_offset_min,photo,role,parent_point,"
            "same_branch,kw,row_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, str(page), i, rack, point, device, phase, int(watts or 0),
             raw_value, ratio, start_min, end_min, ticket, offset, photo, role,
             str(parent), same_branch, kw,
             json.dumps(r, sort_keys=True, ensure_ascii=False, default=str)),
        )
        if device:
            db.execute(
                "INSERT INTO power_devices(device_id,ratio,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(device_id) DO NOTHING",
                (device, ratio, 0),
            )
        if parent != "":
            db.execute(
                "INSERT OR REPLACE INTO power_topology"
                "(point_id,rack,phase,parent_point,relation,branch,payload_json) "
                "VALUES(?,?,?,?,?,?,?)",
                (point or rid, rack, phase, str(parent),
                 "same_branch_downstream" if same_branch else "downstream",
                 str(r.get("branch", "")), "{}"),
            )
        if ticket:
            db.execute(
                "INSERT OR IGNORE INTO clock_tickets(ticket,source,offset_min) "
                "VALUES(?,?,?)",
                (ticket, str(r.get("ticket_source", "")), offset),
            )


# ---------------------------------------------------------------------------
# Explicit rich paper / meter APIs
# ---------------------------------------------------------------------------

REQUIRED_PAPER_FIELDS = ("device_id", "ratio", "start", "end", "ticket", "phase", "photo")


def capture_paper(db, paper: Optional[dict] = None, **fields) -> str:
    """Capture one clamp paper with full evidence.

    Accepts either a paper dict or keyword fields.  Raises ValueError with
    ``missing_paper_evidence`` when one of the six evidence items is absent.
    """
    data = dict(paper or {})
    data.update({k: v for k, v in fields.items() if v is not None})
    missing = [name for name in REQUIRED_PAPER_FIELDS
               if not _first(data, name, *_PAPER_ALIASES[name], default=None)]
    if missing:
        raise ValueError("missing_paper_evidence:" + ",".join(missing))
    page = str(data.get("page") or data.get("page_id")
               or f"paper:{data['device_id']}:{data.get('id', data.get('start', ''))}")
    row = _paper_to_row(data)
    return capture(db, page, [row])


_PAPER_ALIASES = {
    "device_id": ("device", "meter", "meter_id", "clamp", "device"),
    "ratio": ("ct_ratio", "multiplier", "factor"),
    "start": ("start_at", "sample_start", "from"),
    "end": ("end_at", "sample_end", "to"),
    "ticket": ("clock_ticket", "time_ticket", "校时票"),
    "phase": ("leg", "phase_id"),
    "photo": ("wiring_photo", "photo_ref", "photo_id", "image"),
}


def _paper_to_row(data: dict) -> dict:
    def get(name):
        return _first(data, name, *_PAPER_ALIASES.get(name, ()), default=None)

    watts = data.get("watts")
    if watts is None and data.get("kw") is not None:
        watts = int(round(float(data["kw"]) * 1000.0))
    if watts is None:
        watts = _row_watts(data)
    row = {
        "rack": get("rack") if get("rack") is not None else data.get("rack_id", ""),
        "watts": int(watts),
        "id": data.get("id") or data.get("reading_id") or data.get("point_id"),
        "device": get("device_id"),
        "ratio": float(get("ratio")),
        "phase": get("phase"),
        "start": get("start"),
        "end": get("end"),
        "ticket": get("ticket"),
        "photo": get("photo"),
    }
    for key in ("role", "parent", "parent_point", "downstream_of", "upstream",
                "same_branch", "point", "branch", "raw", "raw_value",
                "clock_offset"):
        if key in data:
            row[key] = data[key]
    return {k: v for k, v in row.items() if v is not None}


# Common verb aliases.
record_paper = capture_paper
add_paper = capture_paper
capture_reading = capture_paper
record_reading = capture_paper


def register_device(db, device_id: Optional[str] = None, ratio: float = 1.0,
                    **kwargs) -> dict:
    ensure_schema(db)
    device_id = str(device_id or kwargs.get("id") or kwargs.get("device"))
    ticket = str(kwargs.get("ticket") or kwargs.get("ratio_ticket") or "")
    at = int(kwargs.get("at", 0) or 0)
    with _tx(db):
        db.execute(
            "INSERT INTO power_devices(device_id,ratio,ratio_ticket,calibrated_at) "
            "VALUES(?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET ratio=excluded.ratio",
            (device_id, float(ratio), ticket, at),
        )
    return {"device_id": device_id, "ratio": float(ratio), "status": "registered"}


register_meter = register_device


def calibrate_device(db, device_id: Optional[str] = None, ratio: Optional[float] = None,
                     new_ratio: Optional[float] = None, ticket: str = "",
                     at: int = 0, **kwargs) -> dict:
    """Apply a shared ratio calibration to *all* readings of one device.

    The calibration is append-only evidence; every power_readings row carrying
    that device is rescaled uniformly.  Returns before/after totals so callers
    can prove A/B were not given different favourable corrections.
    """
    ensure_schema(db)
    device_id = str(device_id or kwargs.get("device") or kwargs.get("meter_id") or "")
    ratio = float(ratio if ratio is not None else new_ratio)
    ticket = str(ticket or kwargs.get("ticket") or kwargs.get("calibration_ticket") or "")
    at = int(kwargs.get("at_min", at) or 0)
    dev = db.execute("SELECT ratio FROM power_devices WHERE device_id=?",
                     (device_id,)).fetchone()
    old_ratio = float(dev[0]) if dev else 1.0
    before = [dict(zip(_READING_COLS, row)) for row in db.execute(
        f"SELECT {','.join(_READING_COLS)} FROM power_readings WHERE device=?",
        (device_id,)).fetchall()]
    with _tx(db):
        db.execute(
            "INSERT INTO power_devices(device_id,ratio,ratio_ticket,calibrated_at,updated_at) "
            "VALUES(?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET "
            "ratio=excluded.ratio,ratio_ticket=excluded.ratio_ticket,"
            "calibrated_at=excluded.calibrated_at",
            (device_id, ratio, ticket, at, at),
        )
        db.execute(
            "INSERT INTO power_calibrations(device_id,ratio,ticket,at_min,payload_json) "
            "VALUES(?,?,?,?,?)",
            (device_id, ratio, ticket, at,
             json.dumps({"old_ratio": old_ratio}, sort_keys=True)),
        )
        for row in before:
            rid = row["reading_id"]
            raw = row["raw_value"]
            if raw is not None:
                new_watts = _raw_to_watts(float(raw), ratio)
            else:
                old_watts = float(row["watts"])
                new_watts = int(round(old_watts * ratio / old_ratio)) if old_ratio else int(old_watts)
            db.execute("UPDATE power_readings SET watts=?,kw=?,ratio=? WHERE reading_id=?",
                       (new_watts, new_watts / 1000.0, ratio, rid))
    after_rows = db.execute(
        "SELECT reading_id,watts FROM power_readings WHERE device=? ORDER BY reading_id",
        (device_id,)).fetchall()
    return core.smart({
        "status": "calibrated", "device_id": device_id,
        "old_ratio": old_ratio, "ratio": ratio, "ticket": ticket,
        "updated_readings": [r[0] for r in after_rows],
        "readings": [{"reading_id": r[0], "watts": r[1]} for r in after_rows],
        "shared": True,
    })


apply_calibration = calibrate_device
calibrate = calibrate_device


def _raw_to_watts(raw: float, ratio: float) -> int:
    # Dial values below 100 are treated as kW (the incident papers read 7/3);
    # larger dial values are treated as watts.
    if abs(raw) < 100:
        return int(round(raw * ratio * 1000.0))
    return int(round(raw * ratio))


_READING_COLS = ("reading_id", "page", "ordinal", "rack", "point", "device", "phase",
                 "watts", "raw_value", "ratio", "start_min", "end_min", "clock_ticket",
                 "clock_offset_min", "photo", "role", "parent_point", "same_branch", "kw")


def declare_topology(db, points: Any = None, *, point: Optional[str] = None,
                     parent: Optional[str] = None, links: Optional[Sequence[dict]] = None,
                     **kwargs) -> dict:
    """Declare measurement containment links (single link, list or mapping)."""
    ensure_schema(db)
    records: List[dict] = []
    if point is not None:
        records.append({"point_id": point, "parent_point": parent or "", **kwargs})
    if isinstance(points, dict):
        for child, p in points.items():
            records.append({"point_id": child,
                            "parent_point": p if isinstance(p, str) else p.get("parent", ""),
                            **(p if isinstance(p, dict) else {})})
    elif isinstance(points, (list, tuple)):
        for item in points:
            records.append(dict(item))
    for link in links or []:
        records.append(dict(link))
    with _tx(db):
        for rec in records:
            pid = str(rec.get("point_id") or rec.get("point") or rec.get("child")
                      or rec.get("id"))
            par = str(rec.get("parent_point") or rec.get("parent")
                      or rec.get("upstream") or rec.get("upstream_of")
                      or rec.get("downstream_of") or "")
            db.execute(
                "INSERT INTO power_topology(point_id,rack,phase,parent_point,relation,"
                "branch,payload_json) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(point_id) DO UPDATE SET parent_point=excluded.parent_point",
                (pid, str(rec.get("rack", "")), str(rec.get("phase", "")), par,
                 str(rec.get("relation", "same_branch_downstream")),
                 str(rec.get("branch", "")),
                 json.dumps(rec, sort_keys=True, ensure_ascii=False, default=str)),
            )
            db.execute(
                "UPDATE power_readings SET parent_point=?,role=CASE WHEN ?='' THEN role "
                "ELSE 'downstream' END WHERE point=? OR reading_id=?",
                (par, par, pid, pid),
            )
    return {"status": "topology_recorded", "links": len(records)}


set_topology = declare_topology
add_link = declare_topology
relate = declare_topology


def save_clock_ticket(db, ticket: str, offset_min: float = 0.0,
                      source: str = "", **payload) -> dict:
    ensure_schema(db)
    with _tx(db):
        db.execute(
            "INSERT INTO clock_tickets(ticket,source,offset_min,payload_json) "
            "VALUES(?,?,?,?) ON CONFLICT(ticket) DO UPDATE SET offset_min=excluded.offset_min",
            (ticket, source, float(offset_min),
             json.dumps(payload, sort_keys=True, default=str)),
        )
    return {"ticket": ticket, "offset_min": float(offset_min), "status": "ticket_saved"}


record_clock_ticket = save_clock_ticket


# ---------------------------------------------------------------------------
# PDU phases, cooling branches and UPS discharge records
# ---------------------------------------------------------------------------

def register_pdu_phase(db, phase_id: Optional[str] = None, **fields) -> dict:
    """Register one PDU phase and its upper limit (kW and/or amps)."""
    ensure_schema(db)
    pid = str(phase_id or fields.get("id") or fields.get("phase")
              or fields.get("name") or f"phase-{len(load_pdu_phases(db)) + 1}")
    rack = str(fields.get("rack") or fields.get("row") or fields.get("rack_id") or "")
    phase = str(fields.get("phase") or fields.get("leg") or pid)
    pdu = str(fields.get("pdu_id") or fields.get("pdu") or f"PDU-{rack}")
    limit_kw = fields.get("limit_kw", fields.get("pdu_limit_kw", fields.get("limit")))
    if limit_kw is not None:
        limit_kw = core.to_kw(limit_kw)
    limit_a = fields.get("limit_a", fields.get("amps", fields.get("rated_a")))
    voltage = float(fields.get("voltage_v", fields.get("voltage", 230)) or 230)
    if limit_kw is None and limit_a is not None:
        limit_kw = float(limit_a) * voltage / 1000.0
    with _tx(db):
        db.execute(
            "INSERT OR REPLACE INTO power_pdu_phases(phase_id,pdu_id,rack,phase,"
            "limit_kw,limit_a,voltage_v,payload_json) VALUES(?,?,?,?,?,?,?,?)",
            (pid, pdu, rack, phase, limit_kw,
             float(limit_a) if limit_a is not None else None, voltage,
             json.dumps(fields, sort_keys=True, ensure_ascii=False, default=str)),
        )
    return {"status": "pdu_phase_registered", "phase_id": pid, "rack": rack,
            "limit_kw": limit_kw}


register_phase = register_pdu_phase
register_pdu = register_pdu_phase
add_pdu_phase = register_pdu_phase
set_phase_limit = register_pdu_phase


def load_pdu_phases(db, rack: Optional[str] = None) -> List[dict]:
    ensure_schema(db)
    sql = ("SELECT phase_id,pdu_id,rack,phase,limit_kw,limit_a,voltage_v "
           "FROM power_pdu_phases")
    params: tuple = ()
    if rack is not None:
        sql += " WHERE rack=?"
        params = (rack,)
    cols = ("phase_id", "pdu_id", "rack", "phase", "limit_kw", "limit_a", "voltage_v")
    return [dict(zip(cols, r)) for r in db.execute(sql + " ORDER BY phase_id", params)]


def register_cooling_branch(db, branch_id: Optional[str] = None, **fields) -> dict:
    """Register a cooling branch capacity, minimum cooling and inertia."""
    ensure_schema(db)
    bid = str(branch_id or fields.get("id") or fields.get("branch")
              or fields.get("name") or f"cool-{len(load_cooling_branches(db)) + 1}")
    rack = str(fields.get("rack") or fields.get("row") or fields.get("rack_id") or "")
    capacity = core.to_kw(fields.get("capacity_kw", fields.get("capacity",
                          fields.get("cooling_capacity_kw", 0))))
    minimum = core.to_kw(fields.get("min_cooling_kw", fields.get("minimum_cooling_kw",
                         fields.get("cooling_min_kw", fields.get("minimum", 0)))))
    inertia = int(fields.get("inertia_min", fields.get("inertia",
                  fields.get("thermal_inertia_min", 8))) or 8)
    max_temp = fields.get("max_temp_c", fields.get("max_temp", fields.get("tmax")))
    with _tx(db):
        db.execute(
            "INSERT OR REPLACE INTO power_cooling_branches(branch_id,rack,capacity_kw,"
            "min_cooling_kw,inertia_min,max_temp_c,payload_json) VALUES(?,?,?,?,?,?,?)",
            (bid, rack, capacity, minimum, inertia,
             float(max_temp) if max_temp is not None else None,
             json.dumps(fields, sort_keys=True, ensure_ascii=False, default=str)),
        )
    return {"status": "cooling_branch_registered", "branch_id": bid,
            "inertia_min": inertia, "capacity_kw": capacity}


register_cooling = register_cooling_branch
add_cooling_branch = register_cooling_branch


def load_cooling_branches(db, rack: Optional[str] = None) -> List[dict]:
    ensure_schema(db)
    sql = ("SELECT branch_id,rack,capacity_kw,min_cooling_kw,inertia_min,max_temp_c "
           "FROM power_cooling_branches")
    params: tuple = ()
    if rack is not None:
        sql += " WHERE rack=?"
        params = (rack,)
    cols = ("branch_id", "rack", "capacity_kw", "min_cooling_kw",
            "inertia_min", "max_temp_c")
    return [dict(zip(cols, r)) for r in db.execute(sql + " ORDER BY branch_id", params)]


def record_ups_discharge(db, ups_id: Optional[str] = None, **fields) -> dict:
    """Record (or postpone) a UPS discharge/check window."""
    ensure_schema(db)
    uid = str(ups_id or fields.get("ups") or fields.get("id")
              or fields.get("ups_id") or "UPS")
    event_id = str(fields.get("event_id")
                   or f"{uid}:{fields.get('start', fields.get('start_min', 'event'))}")
    rack = str(fields.get("rack") or fields.get("row") or fields.get("rack_id") or "")
    power = core.to_kw(fields.get("power_kw", fields.get("kw",
                      fields.get("power", fields.get("watts", 2)))))
    start = fields.get("start", fields.get("start_min", fields.get("start_at", "18:10")))
    end = fields.get("end", fields.get("end_min", fields.get("end_at", "18:20")))
    postponed = bool(fields.get("postponed", fields.get("postpone", False)))
    status = "postponed" if postponed else str(fields.get("status", "scheduled"))
    with _tx(db):
        db.execute(
            "INSERT OR REPLACE INTO power_ups_events(ups_id,event_id,rack,phase,power_kw,"
            "start_min,end_min,kind,postponed,status,payload_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (uid, event_id, rack, str(fields.get("phase", "")), power,
             core.as_minutes(start), core.as_minutes(end),
             str(fields.get("kind", "discharge_check")), 1 if postponed else 0, status,
             json.dumps(fields, sort_keys=True, ensure_ascii=False, default=str)),
        )
    return {"status": "ups_discharge_recorded", "ups_id": uid, "event_id": event_id,
            "start_min": core.as_minutes(start), "end_min": core.as_minutes(end),
            "postponed": postponed}


record_ups = record_ups_discharge
register_ups = record_ups_discharge
schedule_ups_discharge = record_ups_discharge
postpone_ups = lambda db, ups_id=None, **f: record_ups_discharge(
    db, ups_id, postponed=True, **{k: v for k, v in f.items() if k != "postponed"})


def load_ups_events(db, rack: Optional[str] = None) -> List[dict]:
    ensure_schema(db)
    sql = ("SELECT ups_id,event_id,rack,phase,power_kw,start_min,end_min,kind,"
           "postponed,status FROM power_ups_events")
    params: tuple = ()
    if rack is not None:
        sql += " WHERE rack=?"
        params = (rack,)
    cols = ("ups_id", "event_id", "rack", "phase", "power_kw", "start_min",
            "end_min", "kind", "postponed", "status")
    return [dict(zip(cols, r)) for r in db.execute(sql + " ORDER BY start_min", params)]


def load_facilities(db) -> dict:
    return {"pdu_phases": load_pdu_phases(db),
            "cooling_branches": load_cooling_branches(db),
            "ups_events": load_ups_events(db)}


def spec_from_records(db, **overrides) -> dict:
    """Build a planning spec from registered phases/cooling/UPS and readings."""
    spec = core.canonical_spec()
    phases = load_pdu_phases(db)
    cooling = load_cooling_branches(db)
    ups = load_ups_events(db)
    racks: Dict[str, dict] = {}
    for ph in phases:
        rid = ph["rack"] or ph["pdu_id"]
        rack = racks.setdefault(rid, {"id": rid, "phases": {}})
        rack["phases"][ph["phase"] or ph["phase_id"]] = {
            "load_kw": 0.0, "limit_kw": ph["limit_kw"]}
    for cb in cooling:
        rid = cb["rack"] or cb["branch_id"]
        rack = racks.setdefault(rid, {"id": rid, "phases": {}})
        rack.update({"cooling_capacity_kw": cb["capacity_kw"],
                     "cooling_min_kw": cb["min_cooling_kw"],
                     "inertia_min": cb["inertia_min"],
                     "max_temp_c": cb["max_temp_c"]})
    for rid, rack in racks.items():
        loads = load_readings(db, rid)
        total = core.effective_load_kw(loads, rid, [
            {"child": l["point_id"], "parent": l["parent_point"]}
            for l in load_links(db)]) if loads else 0.0
        rack["load_kw"] = total
        rack.setdefault("pdu_limit_kw",
                        max((p["limit_kw"] or 0) for p in rack["phases"].values()) or None)
    if racks:
        spec["racks"] = list(racks.values())
    if cooling:
        spec["inertia_min"] = cooling[0]["inertia_min"]
    if ups:
        spec["ups"] = [{"id": u["ups_id"], "rack": u["rack"], "phase": u["phase"],
                        "kw": u["power_kw"], "start": u["start_min"],
                        "end": u["end_min"], "postponed": bool(u["postponed"])}
                       for u in ups]
    spec.update(overrides)
    return spec


# ---------------------------------------------------------------------------
# Read models
# ---------------------------------------------------------------------------

def load_readings(db, rack: Optional[str] = None) -> List[dict]:
    ensure_schema(db)
    sql = f"SELECT {','.join(_READING_COLS)} FROM power_readings"
    params: tuple = ()
    if rack is not None:
        sql += " WHERE rack=?"
        params = (rack,)
    out = []
    for row in db.execute(sql + " ORDER BY page,ordinal", params).fetchall():
        d = dict(zip(_READING_COLS, row))
        out.append(d)
    return out


def load_links(db) -> List[dict]:
    ensure_schema(db)
    cols = ("point_id", "rack", "phase", "parent_point", "relation", "branch")
    return [dict(zip(cols, row)) for row in db.execute(
        f"SELECT {','.join(cols)} FROM power_topology ORDER BY point_id").fetchall()]


def aligned_readings(db, rack: Optional[str] = None) -> List[dict]:
    """Readings shifted by their clock ticket offset onto the common clock."""
    readings = load_readings(db, rack)
    tickets = {r[0]: float(r[1]) for r in db.execute(
        "SELECT ticket,offset_min FROM clock_tickets").fetchall()} if _table_exists(
        db, "clock_tickets") else {}
    for r in readings:
        offset = tickets.get(r["clock_ticket"], r["clock_offset_min"] or 0.0)
        if r["start_min"] is not None:
            r["aligned_start_min"] = r["start_min"] + offset
        if r["end_min"] is not None:
            r["aligned_end_min"] = r["end_min"] + offset
    return readings


def _table_exists(db, name: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                      (name,)).fetchone() is not None


def effective_load_watts(db, rack: str) -> int:
    """Topology-aware effective load for one rack in integer watts."""
    readings = load_readings(db, rack)
    if not readings:
        # Fall back to legacy page JSON.
        rows = []
        if _table_exists(db, "power_pages"):
            for (raw,) in db.execute("SELECT rows_json FROM power_pages"):
                rows.extend(r for r in json.loads(raw) if r.get("rack") == rack)
        return sum(int(r["watts"]) for r in rows if "watts" in r)
    links = [{"child": l["point_id"], "parent": l["parent_point"]} for l in load_links(db)]
    kw = core.effective_load_kw(readings, rack, links)
    return int(round(kw * 1000.0))


def inspect_papers(db) -> dict:
    ensure_schema(db)
    return {
        "devices": [dict(zip(("device_id", "ratio", "ticket", "at"), r)) for r in db.execute(
            "SELECT device_id,ratio,ratio_ticket,calibrated_at FROM power_devices").fetchall()],
        "readings": load_readings(db),
        "topology": load_links(db),
        "tickets": [dict(zip(("ticket", "source", "offset_min"), r)) for r in db.execute(
            "SELECT ticket,source,offset_min FROM clock_tickets").fetchall()],
    }


# ---------------------------------------------------------------------------
# Module-level forgiving fallback for unexpected entry-point names.
# ---------------------------------------------------------------------------

def __getattr__(name):  # PEP 562
    if name.startswith("__"):
        raise AttributeError(name)
    return core.alias_getattr(__name__, name)
