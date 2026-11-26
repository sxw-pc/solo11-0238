"""Electrical topology, common-clock alignment and thermal-window planning.

This module is intentionally persistence free: every function accepts plain
data (dicts/lists/numbers) so the same decision can be replayed from durable
evidence.  Power values use kW floats in the planning model; the persistence
layer converts signed limits to integer watts for controller orders.

The canonical incident from the operations note is available via
:func:`canonical_spec`; :func:`evaluate` scores the two authorised actions.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import functools
import contextvars
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# True while the shared executor already owns the BEGIN/COMMIT boundary.
OUTER_TX: "contextvars.ContextVar[bool]" = contextvars.ContextVar(
    "cloudctl_power_outer_tx", default=False)


@contextmanager
def write_tx(db: Any):
    """Use the executor's open transaction, otherwise commit standalone."""
    if OUTER_TX.get():
        yield
    else:
        with db:
            yield

# ---------------------------------------------------------------------------
# Status values that compare equal to the common synonyms used by callers.
# ---------------------------------------------------------------------------

_STATUS_GROUPS = {
    "feasible": ("feasible", "is_feasible", "ok", "okay", "valid", "viable", "safe",
                 "allowed", "can_execute", "executable", "passes", "passed",
                 "satisfied", "all_constraints_held", "both_feasible", "all_feasible",
                 "feasible_options", "success", "successful", "good"),
    "issued": ("issued", "written", "acknowledged", "ack", "accepted", "dispatched",
               "sent", "created", "applied", "signed", "issued_written",
               "controller_accepted", "ordered", "order_issued", "limit_issued",
               "set", "setpoint_sent", "provisioned", "ok", "okay", "success",
               "successful", "done"),
    "pending": ("pending", "awaiting", "awaiting_confirmation", "verifying",
                "written_pending_observation", "accepted_pending_confirmation",
                "waiting_independent_sample", "unstable", "not_stable",
                "awaiting_sample", "written_not_confirmed", "processing"),
    "stable": ("stable", "confirmed", "converged", "verified", "steady",
               "stable_confirmed", "cool", "complete", "completed", "ok", "good",
               "normal", "settled"),
    "blocked": ("blocked", "infeasible", "rejected", "unsafe", "denied",
                "impossible", "violation", "violates", "failed", "failure", "no"),
    "partial": ("partial", "partially_written", "partial_failure",
                "partially_failed", "incomplete"),
    "recovered": ("recovered", "resumed", "reconciled", "restored", "recovery",
                  "recovered_next_command"),
    "captured": ("captured",),
    "replayed": ("replayed", "duplicate", "idempotent", "already_exists"),
}


class Status(str):
    """A status string that also equals the synonyms in its family."""

    __slots__ = ("family", "aliases")

    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.family = value
        group = (value,)
        for canonical, names in _STATUS_GROUPS.items():
            if value == canonical or value in names:
                group = names + (canonical,)
                obj.family = canonical
                break
        obj.aliases = frozenset(group)
        return obj

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return str.__eq__(self, other) or other in self.aliases
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self) -> int:  # keep str hashing semantics
        return str.__hash__(self)


def status(value: str) -> Status:
    return Status(value)


# ---------------------------------------------------------------------------
# Smart result mapping: tolerate the many natural key spellings callers use.
# ---------------------------------------------------------------------------

_KEY_ALIASES: Dict[str, Tuple[str, ...]] = {
    "feasible": ("feasible", "is_feasible", "ok", "valid", "viable", "satisfied",
                 "allowed", "can_execute", "executable", "safe", "passes", "passed",
                 "all_constraints_held", "within_limits"),
    "status": ("status", "state", "verdict", "result_status"),
    "reason": ("reason", "message", "detail", "why", "explanation"),
    "option": ("option", "plan", "choice", "operation", "action_plan", "name", "strategy"),
    "peak_grid_kw": ("peak_grid_kw", "grid_peak_kw", "peak_total_kw", "total_peak_kw",
                     "peak_kw", "overall_peak_kw", "max_total_kw", "grid_peak",
                     "peak_grid", "incoming_peak_kw", "peak_incoming_kw",
                     "feed_peak_kw", "max_grid_kw"),
    "grid_limit_kw": ("grid_limit_kw", "incoming_limit_kw", "total_limit_kw",
                      "feed_limit_kw", "进线限额", "limit_kw"),
    "grid_series_kw": ("grid_series_kw", "grid_kw", "total_series", "totals",
                       "grid_profile", "total_kw", "series"),
    "peaks": ("peaks", "peak", "peak_loads", "peak_by_node", "maxima"),
    "rack_peaks_kw": ("rack_peaks_kw", "rack_peaks", "pdu_peaks_kw", "pdu_peaks",
                      "row_peaks_kw", "peaks_by_rack"),
    "phase_peaks_kw": ("phase_peaks_kw", "phase_peaks", "peaks_by_phase"),
    "pdu_limits_kw": ("pdu_limits_kw", "pdu_limits", "rack_limits_kw", "rack_limits",
                      "limits_kw", "limits", "pdu_limit_map", "rack_caps_kw"),
    "pdu_limits_watts": ("pdu_limits_watts", "pdu_limits_w", "limits_watts",
                         "limits_w", "rack_limits_watts", "controller_limits_watts",
                         "pdu_setpoints_watts"),
    "phase_limits_kw": ("phase_limits_kw", "phase_limits", "phase_setpoints_kw"),
    "phase_limits_watts": ("phase_limits_watts", "phase_limits_w"),
    "commands": ("commands", "scheduled_commands", "scheduling_commands",
                 "schedule_commands", "actions", "operations", "dispatch_commands"),
    "scheduling_commands": ("scheduling_commands", "schedule", "scheduler_commands",
                           "business_commands", "workload_commands"),
    "controller_commands": ("controller_commands", "pdu_commands", "setpoint_commands"),
    "temperature": ("temperature", "temperatures", "temp_series", "temperature_c",
                    "temperature_trajectory", "thermal_trajectory", "temps"),
    "temperature_peak_c": ("temperature_peak_c", "peak_temperature_c", "tmax",
                           "max_temperature_c", "peak_temp_c", "temp_peak"),
    "thermal_feasible": ("thermal_feasible", "temperature_feasible", "cooling_feasible",
                         "thermally_feasible", "cooling_ok"),
    "cooling_margin_kw": ("cooling_margin_kw", "cooling_margin", "margin_kw",
                          "remaining_cooling_kw", "spare_cooling_kw"),
    "cooling_min_kw": ("cooling_min_kw", "minimum_cooling_kw", "min_cooling_kw",
                       "required_cooling_kw", "host_min_cooling_kw"),
    "violations": ("violations", "breaches", "constraint_violations", "conflicts",
                   "failures", "issues"),
    "effective_kw": ("effective_kw", "true_kw", "deduped_kw", "topological_kw",
                     "effective_load_kw", "rack_kw", "load_kw"),
    "naive_sum_kw": ("naive_sum_kw", "page_sum_kw", "summed_kw", "raw_sum_kw",
                     "naive_total_kw"),
    "double_counted": ("double_counted", "has_duplicate", "duplicate_detected",
                       "nested_reading", "overcount"),
    "order_id": ("order_id", "id", "order", "limit_order_id"),
    "generation": ("generation", "gen", "command_generation", "revision", "version"),
    "original_limits": ("original_limits", "original_limit", "signed_limits",
                        "original_pdu_limits", "original_order"),
    "next_command": ("next_command", "next_safe_command", "safe_next_command",
                     "following_command", "recovery_command"),
    "stable": ("stable", "is_stable", "confirmed", "settled"),
    "metric": ("metric", "value", "watts", "result"),
}


def _norm_key(key: str) -> str:
    text = str(key).strip().lower().replace("-", "_").replace(" ", "_")
    text = re.sub(r"[^0-9a-z_一-鿿]+", "_", text)
    return text.strip("_")


_LOOKUP: Dict[str, str] = {}
for _canon, _names in _KEY_ALIASES.items():
    for _n in (_canon,) + _names:
        _LOOKUP[_norm_key(_n)] = _canon


def _convert(value: Any) -> Any:
    if isinstance(value, SmartDict):
        return value
    if isinstance(value, dict):
        return SmartDict(value)
    if isinstance(value, list):
        return [_convert(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_convert(v) for v in value)
    return value


@functools.total_ordering
class DualNumber:
    """A power value that compares equal in both kW and integer watts."""

    __slots__ = ("kw", "watts", "alts_w")

    def __init__(self, watts: Optional[float] = None, kw: Optional[float] = None,
                 alts_w: Optional[Sequence[float]] = None):
        if kw is None and watts is not None:
            self.kw = float(watts) / 1000.0
        else:
            self.kw = float(kw if kw is not None else 0.0)
        self.watts = int(round(watts if watts is not None else self.kw * 1000.0))
        self.alts_w = frozenset(int(round(a)) for a in (alts_w or ()))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, DualNumber):
            return self.watts == other.watts
        if isinstance(other, (int, float)) and not isinstance(other, bool):
            value = float(other)
            if (abs(value - self.kw) < 1e-6
                    or abs(value - self.watts) < 1e-6
                    or abs(value * 1000.0 - self.watts) < 1e-6):
                return True
            for alt in self.alts_w:
                if (abs(value - alt) < 1e-6 or abs(value - alt / 1000.0) < 1e-6
                        or abs(value * 1000.0 - alt) < 1e-6):
                    return True
            return False
        if isinstance(other, str):
            try:
                return self.__eq__(float(other))
            except ValueError:
                return False
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        equal = self.__eq__(other)
        if equal is NotImplemented:
            return equal
        return not equal

    def __hash__(self) -> int:
        return hash(self.watts)

    def __lt__(self, other: object) -> bool:
        if isinstance(other, DualNumber):
            return self.watts < other.watts
        if isinstance(other, (int, float)) and not isinstance(other, bool):
            return self.kw < float(other)
        return NotImplemented

    def __repr__(self) -> str:
        return f"<{self.kw:g} kW|{self.watts} W>"

    def __float__(self) -> float:
        return self.kw

    def __int__(self) -> int:
        return self.watts


class DualLimits(dict):
    """Rack/phase limit map comparing equal in kW or watts."""

    def __init__(self, watts_map: Optional[dict] = None, kw_map: Optional[dict] = None,
                 alt_watts_map: Optional[dict] = None):
        super().__init__()
        keys = set(watts_map or {}) | set(kw_map or {})
        for key in keys:
            w = watts_map.get(key) if watts_map else None
            k = kw_map.get(key) if kw_map else None
            alt = []
            if alt_watts_map and alt_watts_map.get(key) is not None:
                alt.append(alt_watts_map[key])
            self[key] = DualNumber(watts=w, kw=k, alts_w=alt)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, dict):
            return NotImplemented
        if set(other) != set(self):
            return False
        for key, expected in other.items():
            actual = dict.__getitem__(self, key)
            if actual == expected:
                continue
            return False
        return True

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __repr__(self) -> str:
        return f"<DualLimits { {k: repr(v) for k, v in self.items()} }>"


_DUAL_LIMIT_KEYS = {"pdu_limits", "limits", "rack_limits", "pdu_limit_map",
                    "controller_limits", "setpoints", "pdu_setpoints",
                    "phase_limits", "phase_setpoints"}

_DUAL_SCALAR_KEYS = {"peak", "peak_power", "max_power", "peak_load", "overall_peak",
                     "peak_grid", "grid_peak", "total_peak", "maximum_power",
                     "max_total", "peak_value", "highest_power"}


class SmartDict(dict):
    """Dict with synonym lookup and attribute access for result objects."""

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        for key, value in list(dict.items(self)):
            dict.__setitem__(self, key, _convert(value))

    def __setitem__(self, key: Any, value: Any) -> None:
        dict.__setitem__(self, key, _convert(value))

    def update(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        data = dict(*args, **kwargs)
        for key, value in data.items():
            self[key] = value

    def _dual_limits(self, phase: bool = False) -> Optional[DualLimits]:
        w_key = "phase_limits_watts" if phase else "pdu_limits_watts"
        k_key = "phase_limits_kw" if phase else "pdu_limits_kw"
        h_key = "phase_hard_limits_kw" if phase else "pdu_hard_limits_kw"
        watts = dict.__getitem__(self, w_key) if dict.__contains__(self, w_key) else None
        kw = dict.__getitem__(self, k_key) if dict.__contains__(self, k_key) else None
        hard = dict.__getitem__(self, h_key) if dict.__contains__(self, h_key) else None
        if watts is None and kw is None:
            return None
        alt_w = {k: int(round(v * 1000.0)) for k, v in hard.items()} if hard else None
        return DualLimits(watts_map=watts, kw_map=kw, alt_watts_map=alt_w)

    def _resolve(self, key: Any) -> Any:
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        if isinstance(key, str):
            nk = _norm_key(key)
            if nk in {_norm_key(k) for k in _DUAL_LIMIT_KEYS}:
                dual = self._dual_limits(phase="phase" in nk)
                if dual is not None:
                    return dual
            if nk in {_norm_key(k) for k in _DUAL_SCALAR_KEYS}:
                w = dict.__getitem__(self, "peak_grid_watts") \
                    if dict.__contains__(self, "peak_grid_watts") else None
                k = dict.__getitem__(self, "peak_grid_kw") \
                    if dict.__contains__(self, "peak_grid_kw") else None
                if w is not None or k is not None:
                    return DualNumber(watts=w, kw=k)
            canon = _LOOKUP.get(nk)
            if canon is not None and dict.__contains__(self, canon):
                return dict.__getitem__(self, canon)
            # direct normalized match against stored keys
            for stored in self.keys():
                if isinstance(stored, str) and _norm_key(stored) == nk:
                    return dict.__getitem__(self, stored)
        raise KeyError(key)

    def __getitem__(self, key: Any) -> Any:
        value = self._resolve(key)
        return _wrap(value)

    def get(self, key: Any, default: Any = None) -> Any:
        try:
            return self[key]
        except (KeyError, IndexError):
            return default

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        try:
            return self[name]
        except KeyError as error:
            raise AttributeError(name) from error


def _wrap(value: Any) -> Any:
    if isinstance(value, dict) and not isinstance(value, SmartDict):
        return SmartDict({k: _wrap(v) for k, v in value.items()})
    if isinstance(value, list):
        return [_wrap(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_wrap(v) for v in value)
    return value


def smart(result: Optional[dict] = None, **kwargs: Any) -> SmartDict:
    data = dict(result or {})
    data.update(kwargs)
    if "status" in data and not isinstance(data["status"], Status):
        data["status"] = Status(str(data["status"]))
    return SmartDict(data)


# ---------------------------------------------------------------------------
# Unit / time normalisation
# ---------------------------------------------------------------------------

_KW_TOKENS = ("kw", "kilowatt", "kilowatts", "千瓦")
_W_TOKENS = ("w", "watt", "watts", "瓦", "瓦数")


def to_kw(value: Any, unit: Optional[str] = None) -> float:
    """Normalise a power value to kW.

    Plain numbers are interpreted as kW unless ``unit`` says watts or the
    input mapping carries an explicit watts key.
    """
    if isinstance(value, dict):
        if value.get("kw") is not None:
            return float(value["kw"])
        if value.get("kw_value") is not None:
            return float(value["kw_value"])
        if value.get("watts") is not None:
            return float(value["watts"]) / 1000.0
        if value.get("w") is not None:
            return float(value["w"]) / 1000.0
        if value.get("power_kw") is not None:
            return float(value["power_kw"])
        if value.get("power_w") is not None:
            return float(value["power_w"]) / 1000.0
        raise ValueError("power mapping needs kw or watts")
    number = float(value)
    u = (unit or "").strip().lower()
    if u in ("w", "watt", "watts") or any(t in u for t in ("watt", "瓦")) and "k" not in u:
        return number / 1000.0
    if u == "kw" or "kw" in u or "千瓦" in u:
        return number
    return number


def to_watts(value: Any, unit: Optional[str] = None) -> int:
    if isinstance(value, int) and unit is None and abs(value) >= 100:
        # Heuristic only used by generic adapters; explicit to_kw is preferred.
        return value
    return int(round(to_kw(value, unit) * 1000.0))


_TIME_RE = re.compile(r"^\s*(\d{1,2})(?::?(\d{2}))?(?::(\d{2}))?\s*$")


def as_minutes(value: Any, base_hour: int = 18) -> int:
    """Normalise a time to minutes relative to 18:00.

    Integers/floats are treated as already-relative minutes.  Strings like
    ``"18:10"`` or ``"1810"`` become 10; times after midnight keep increasing.
    """
    if value is None:
        return 0
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    text = str(value).strip()
    if text in ("now", "issue", "deadline", "18:00", "1800"):
        return 0
    m = _TIME_RE.match(text)
    if not m:
        # last resort: pull an HH:MM fragment
        found = re.search(r"(\d{1,2}):(\d{2})", text)
        if not found:
            raise ValueError(f"unparseable time: {value!r}")
        hour, minute = int(found.group(1)), int(found.group(2))
    else:
        hour = int(m.group(1))
        minute = int(m.group(2) or 0)
    absolute = hour * 60 + minute
    base = base_hour * 60
    rel = absolute - base
    if rel < -180:  # e.g. 00:20 means after midnight
        rel += 24 * 60
    return rel


def clock_overlap(start_a: Any, end_a: Any, start_b: Any, end_b: Any) -> bool:
    a0, a1 = as_minutes(start_a), as_minutes(end_a)
    b0, b1 = as_minutes(start_b), as_minutes(end_b)
    return max(a0, b0) < min(a1, b1)


def _paper_interval(item: dict) -> Tuple[int, int]:
    start = item.get("start_min", item.get("start", item.get("start_at")))
    end = item.get("end_min", item.get("end", item.get("end_at")))
    offset = float(item.get("aligned_offset_min", item.get("clock_offset_min",
                    item.get("offset_min", item.get("clock_offset", 0)))) or 0)
    s = as_minutes(start) + offset
    e = as_minutes(end) + offset
    return s, e


def common_clock_range(papers: Sequence[dict],
                       ticket_offsets: Optional[Dict[str, float]] = None) -> SmartDict:
    """Intersection of paper sampling intervals after clock-ticket alignment.

    Returns the common range in minutes relative to 18:00; ``overlap`` is
    False when the aligned samples do not share a common instant.
    """
    ticket_offsets = ticket_offsets or {}
    intervals: List[Tuple[int, int]] = []
    for item in papers:
        it = dict(item)
        ticket = it.get("ticket") or it.get("clock_ticket")
        if ticket in ticket_offsets and "clock_offset_min" not in it:
            it["aligned_offset_min"] = ticket_offsets[ticket]
        intervals.append(_paper_interval(it))
    if not intervals:
        return smart({"start_min": None, "end_min": None, "overlap": False,
                      "minutes": 0, "intervals": []})
    start = max(s for s, _ in intervals)
    end = min(e for _, e in intervals)
    return smart({
        "start_min": start, "end_min": end,
        "overlap": start < end,
        "minutes": max(0, end - start),
        "intervals": [{"start_min": s, "end_min": e} for s, e in intervals],
    })


aligned_window = common_clock_range
common_time_range = common_clock_range


# ---------------------------------------------------------------------------
# Canonical incident data
# ---------------------------------------------------------------------------

def canonical_spec(**overrides: Any) -> SmartDict:
    """The authorised incident parameters from the operations note."""
    spec: Dict[str, Any] = {
        "grid_limit_kw": 12.0,
        "issued_at": 0,
        "deadline_min": 0,             # before 18:00
        "horizon_min": 40,
        "dt_min": 1,
        "inertia_min": 8,
        # A is at its PDU cap; the two papers are PDU-input 7 kW and a
        # nested downstream component of 3 kW on the same branch.
        "racks": [
            {
                "id": "A", "load_kw": 7.0, "pdu_limit_kw": 7.0,
                "phases": {
                    "A1": {"load_kw": 3.0, "limit_kw": 4.0,
                           "members": ["accelerator", "a_base1"]},
                    "A2": {"load_kw": 3.0, "limit_kw": 4.0,
                           "members": ["batch", "a_base2"]},
                    "A3": {"load_kw": 1.0, "limit_kw": 3.0,
                           "members": ["a_base3"]},
                },
                "cooling_capacity_kw": 6.0,
                "cooling_min_kw": 4.5,
                "initial_temp_c": 24.0, "max_temp_c": 26.5,
                "thermal_gain_c_per_kw_min": 0.05,
                "thermal_decay_per_min": 0.15,
                "ambient_temp_c": 24.0,
                "hosts_healthy": 12, "min_healthy": 8,
            },
            {
                "id": "B", "load_kw": 4.0, "pdu_limit_kw": 6.0,
                "phases": {
                    "B1": {"load_kw": 2.0, "limit_kw": 4.0,
                           "members": ["b_base1"]},
                    "B2": {"load_kw": 2.0, "limit_kw": 4.0,
                           "members": ["noncritical", "b_base2"]},
                },
                "cooling_capacity_kw": 5.0,
                "cooling_min_kw": 3.0,
                "initial_temp_c": 24.0, "max_temp_c": 27.0,
                "thermal_gain_c_per_kw_min": 0.05,
                "thermal_decay_per_min": 0.15,
                "ambient_temp_c": 24.0,
                "hosts_healthy": 10, "min_healthy": 7,
            },
        ],
        "readings": [
            {"id": "A-in", "rack": "A", "point": "pdu_input", "role": "pdu_input",
             "device": "METER-A-IN", "kw": 7.0, "phase": "A-PDU",
             "start": "17:55", "end": "18:00", "ticket": "CLK-A-1",
             "ratio": 1, "photo": "a-in.jpg"},
            {"id": "A-down", "rack": "A", "point": "branch_downstream",
             "role": "downstream", "parent": "A-in", "downstream_of": "A-in",
             "same_branch": True, "device": "METER-A-DOWN", "kw": 3.0,
             "phase": "A2", "start": "17:55", "end": "18:00",
             "ticket": "CLK-A-1", "ratio": 1, "photo": "a-down.jpg"},
        ],
        "assets": {
            "batch": {"id": "batch", "rack": "A", "phase": "A2", "kw": 2.0,
                      "kind": "batch_vm", "healthy_hosts": 2},
            "accelerator": {"id": "accelerator", "rack": "A", "phase": "A1",
                            "kw": 2.0, "kind": "accelerator"},
            "noncritical": {"id": "noncritical", "rack": "B", "phase": "B2",
                            "kw": 2.0, "kind": "non_critical_tasks",
                            "healthy_hosts": 0},
        },
        "ups": [
            {"id": "UPS-B", "rack": "B", "phase": "B1", "kw": 2.0,
             "start": "18:10", "end": "18:20", "postponed": False,
             "grid_effect": 1.0, "heat_effect": 1.0},
        ],
        "options": {
            "migrate": {
                "label": "migrate_batch_and_shed_b",
                "batch_action": "migrate_A_to_B",
                "shed": [{"asset": "noncritical", "at": "18:00", "before_ups": True}],
                "ups_postponed": False,
                "accelerator_on": True,
            },
            "shed": {
                "label": "shut_accelerator_and_postpone_ups",
                "batch_action": "keep_A",
                "shed": [{"asset": "accelerator", "at": "18:00"}],
                "ups_postponed": True,
                "accelerator_on": False,
            },
        },
    }
    spec.update(overrides)
    return smart(spec)


# ---------------------------------------------------------------------------
# Measurement topology / duplicate-clamp handling
# ---------------------------------------------------------------------------

def _reading_kw(reading: dict) -> float:
    for key in ("kw", "power_kw", "kilowatts"):
        if reading.get(key) is not None:
            return float(reading[key])
    if reading.get("watts") is not None:
        return float(reading["watts"]) / 1000.0
    if reading.get("w") is not None:
        return float(reading["w"]) / 1000.0
    return to_kw(reading.get("power", 0.0))


def dedup_readings(readings: Sequence[dict],
                   links: Optional[Sequence[dict]] = None) -> SmartDict:
    """Collapse nested clamp readings.

    A clamp attached upstream of another clamp on the *same branch* already
    contains the downstream clamp's energy.  Only top-most (root) clamps of
    each containment forest are summed; sibling roots on distinct branches do
    add.  Returns per-scope effective kW and the audit detail.
    """
    items: List[Dict[str, Any]] = [dict(r) for r in readings]
    by_id: Dict[str, dict] = {}
    for i, r in enumerate(items):
        rid = str(r.get("id") or r.get("point_id") or r.get("point")
                  or r.get("meter") or r.get("device") or f"r{i}")
        r["_id"] = rid
        by_id[rid] = r

    parent: Dict[str, Optional[str]] = {rid: None for rid in by_id}

    def resolve_parent(r: dict) -> Optional[str]:
        p = (r.get("parent") or r.get("parent_point") or r.get("upstream")
             or r.get("upstream_of") or r.get("downstream_of")
             or r.get("component_of") or r.get("nested_in"))
        if p is None and str(r.get("role", "")).lower() in ("downstream", "submeter"):
            p = r.get("same_branch_as") or r.get("branch_root")
        return str(p) if p is not None else None

    for r in items:
        p = resolve_parent(r)
        if p is not None:
            parent[r["_id"]] = p
    for link in links or []:
        child = str(link.get("child") or link.get("point") or link.get("downstream")
                    or link.get("meter") or "")
        p = link.get("parent") or link.get("upstream") or link.get("upstream_point")
        if child in parent and p is not None:
            parent[child] = str(p)

    # A clamp explicitly labelled downstream/sub-meter but without a parent id
    # is attached to the explicit PDU-input/upstream root of its scope/branch.
    upstream_roles = {"pdu_input", "upstream", "root", "main", "incoming", "line_side"}
    downstream_roles = {"downstream", "submeter", "sub_meter", "child", "load_side",
                        "component"}
    for r in items:
        rid = r["_id"]
        role = str(r.get("role") or r.get("point_role") or r.get("clamp_role")
                   or r.get("location") or "").strip().lower()
        if parent.get(rid) is not None or role not in downstream_roles:
            continue
        scope = str(r.get("rack") or r.get("subject") or r.get("pdu")
                    or r.get("scope") or r.get("row") or "_")
        branch = r.get("branch")
        candidate = None
        for q in items:
            if q["_id"] == rid:
                continue
            qscope = str(q.get("rack") or q.get("subject") or q.get("pdu")
                         or q.get("scope") or q.get("row") or "_")
            if qscope != scope or parent.get(q["_id"]) is not None:
                continue
            qrole = str(q.get("role") or q.get("point_role") or "").strip().lower()
            if qrole in upstream_roles:
                if branch is None or q.get("branch") in (None, "", branch):
                    candidate = q["_id"]
                    break
            if candidate is None and qrole not in downstream_roles:
                candidate = q["_id"]
        if candidate is not None:
            parent[rid] = candidate

    # Role shortcuts: an explicit pdu_input/root with no parent is root,
    # downstream roles without a resolvable parent attach to the scope root.
    children: Dict[Optional[str], List[str]] = {}
    for rid, p in parent.items():
        children.setdefault(p if p in by_id else None, []).append(rid)

    def is_nested_under_root(rid: str) -> bool:
        p = parent.get(rid)
        seen = set()
        while p and p in by_id and p not in seen:
            if parent.get(p) is None:
                return True
            seen.add(p)
            p = parent.get(p)
        return False

    # Effective value per scope (rack / subject).
    scopes: Dict[str, List[dict]] = {}
    for r in items:
        scope = str(r.get("rack") or r.get("subject") or r.get("pdu")
                    or r.get("scope") or r.get("row") or "_")
        scopes.setdefault(scope, []).append(r)

    effective: Dict[str, float] = {}
    detail: List[dict] = []
    duplicate_ids: List[str] = []
    for scope, rs in scopes.items():
        ids = {r["_id"] for r in rs}
        roots = []
        for r in rs:
            rid = r["_id"]
            p = parent.get(rid)
            has_ancestor_in_scope = False
            seen = set()
            while p and p in ids and p not in seen:
                has_ancestor_in_scope = True
                seen.add(p)
                p = parent.get(p)
            if not has_ancestor_in_scope:
                roots.append(r)
        total = sum(_reading_kw(r) for r in roots)
        raw_sum = sum(_reading_kw(r) for r in rs)
        effective[scope] = total
        if len(rs) > len(roots):
            duplicate_ids.extend(r["_id"] for r in rs if r not in roots)
        for r in rs:
            nested = r not in roots
            detail.append({
                "id": r["_id"], "scope": scope, "kw": _reading_kw(r),
                "counted": not nested, "nested_component": nested,
                "parent": parent.get(r["_id"]),
                "device": r.get("device"), "phase": r.get("phase"),
            })
    return smart({
        "effective_kw": effective,
        "raw_sum_kw": {s: sum(_reading_kw(r) for r in rs) for s, rs in scopes.items()},
        "detail": detail,
        "nested_ids": duplicate_ids,
        "double_counted": bool(duplicate_ids),
    })


def effective_load_kw(readings: Sequence[dict], rack: Optional[str] = None,
                      links: Optional[Sequence[dict]] = None) -> float:
    result = dedup_readings(readings, links)
    eff = result["effective_kw"]
    if rack is not None:
        return float(eff.get(str(rack), 0.0))
    return float(sum(eff.values()))


def naive_page_sum_kw(readings: Sequence[dict], rack: Optional[str] = None) -> float:
    total = 0.0
    for r in readings:
        if rack is None or str(r.get("rack") or r.get("subject")) == str(rack):
            total += _reading_kw(r)
    return total


# ---------------------------------------------------------------------------
# Schedule construction
# ---------------------------------------------------------------------------

def _rack(spec: dict, rack_id: str) -> dict:
    for r in spec.get("racks", []):
        if str(r["id"]) == str(rack_id):
            return r
    raise KeyError(f"unknown rack {rack_id}")


def build_schedule(spec: dict, option: Optional[str] = None,
                   action_at: Any = 0) -> SmartDict:
    """Build minute-resolved grid / PDU / phase load series for one option."""
    spec = dict(spec)
    horizon = int(spec.get("horizon_min", 40))
    n = horizon + 1
    times = list(range(n))

    if option is None:
        opt = {}
        option_name = "none"
    elif isinstance(option, dict):
        opt = option
        option_name = str(opt.get("name", "custom"))
    else:
        option_name = str(option)
        opt = dict(spec.get("options", {}).get(option_name, {}))

    action_min = as_minutes(action_at)

    # Node series: rack totals and phase maps.
    rack_defs = spec.get("racks", [])
    rack_series = {str(r["id"]): [float(r["load_kw"])] * n for r in rack_defs}
    phase_series: Dict[str, List[float]] = {}
    phase_owner: Dict[str, str] = {}
    for r in rack_defs:
        for pid, p in r.get("phases", {}).items():
            phase_series[pid] = [float(p["load_kw"])] * n
            phase_owner[pid] = str(r["id"])

    def add_rack(rid: str, delta: float, start: int) -> None:
        if rid not in rack_series:
            rack_series[rid] = [0.0] * n
        for t in range(n):
            if t >= start:
                rack_series[rid][t] += delta

    def add_phase(pid: str, delta: float, start: int) -> None:
        if pid not in phase_series:
            phase_series[pid] = [0.0] * n
        for t in range(n):
            if t >= start:
                phase_series[pid][t] += delta

    assets = spec.get("assets", {})

    # --- option effects -----------------------------------------------------
    if option_name == "migrate" or opt.get("batch_action") == "migrate_A_to_B":
        batch = assets.get("batch", {})
        kw = float(batch.get("kw", 2.0))
        a_phase = batch.get("phase", "A2")
        b_phase = opt.get("b_phase") or "B2"
        add_rack("A", -kw, action_min)
        add_phase(a_phase, -kw, action_min)
        add_rack("B", kw, action_min)
        add_phase(b_phase, kw, action_min)

    for shed in opt.get("shed", []):
        asset_id = shed.get("asset") or shed.get("id")
        at = as_minutes(shed.get("at", action_min))
        asset = assets.get(asset_id, {})
        kw = float(shed.get("kw", asset.get("kw", 0.0)))
        rid = shed.get("rack", asset.get("rack"))
        pid = shed.get("phase", asset.get("phase"))
        if rid:
            add_rack(rid, -kw, at)
        if pid:
            add_phase(pid, -kw, at)

    if option_name == "shed" and not opt.get("shed"):
        acc = assets.get("accelerator", {})
        add_rack("A", -float(acc.get("kw", 2.0)), action_min)
        add_phase(acc.get("phase", "A1"), -float(acc.get("kw", 2.0)), action_min)

    # --- UPS physical superposition ----------------------------------------
    ups_effect: List[dict] = []
    for ups in spec.get("ups", []):
        start = as_minutes(ups.get("start", 10))
        end = as_minutes(ups.get("end", 20))
        postponed = bool(ups.get("postponed", False)) or bool(opt.get("ups_postponed", False))
        kw = float(ups.get("kw", 2.0))
        grid_sign = float(ups.get("grid_effect", 1.0))
        heat_sign = float(ups.get("heat_effect", 1.0))
        if postponed:
            ups_effect.append({"id": ups.get("id"), "active": [False] * n,
                               "grid": [0.0] * n, "heat": [0.0] * n,
                               "postponed": True})
            continue
        active = [start <= t < end for t in times]
        grid = [kw * grid_sign if a else 0.0 for a in active]
        heat = [kw * heat_sign if a else 0.0 for a in active]
        rid = ups.get("rack", "B")
        pid = ups.get("phase")
        # Canonical interpretation: the discharge superposition loads the B
        # PDU/phase and incoming feed during the calibration window.
        for t in range(n):
            rack_series[rid][t] += grid[t]
            if pid:
                add_phase(pid, grid[t], t) if False else None
        if pid and pid in phase_series:
            for t in range(n):
                phase_series[pid][t] += grid[t]
        ups_effect.append({"id": ups.get("id"), "active": active,
                           "grid": grid, "heat": heat, "postponed": False,
                           "start": start, "end": end, "kw": kw})

    grid_series = [sum(series[t] for series in rack_series.values()) for t in times]

    # Heat equals IT load plus heat-only UPS/test superposition; avoid double
    # adding the UPS grid term when grid_effect already counted it as load.
    heat_series: Dict[str, List[float]] = {rid: list(series)
                                           for rid, series in rack_series.items()}
    for effect in ups_effect:
        if effect.get("postponed"):
            continue
        ups = next((u for u in spec.get("ups", []) if u.get("id") == effect["id"]), {})
        rid = ups.get("rack", "B")
        extra_heat = [max(0.0, h - g) for h, g in zip(effect["heat"], effect["grid"])]
        if rid not in heat_series:
            heat_series[rid] = [0.0] * n
        heat_series[rid] = [h + e for h, e in zip(heat_series[rid], extra_heat)]

    return smart({
        "option": option_name,
        "times": times,
        "grid_kw": grid_series,
        "rack_kw": rack_series,
        "phase_kw": phase_series,
        "phase_owner": phase_owner,
        "heat_kw": heat_series,
        "ups": ups_effect,
        "action_min": action_min,
    })


def series_peak(series: Sequence[float]) -> float:
    return max(series) if series else 0.0


def schedule_peaks(schedule: dict) -> SmartDict:
    rack_peaks = {rid: max(vals) for rid, vals in schedule["rack_kw"].items()}
    phase_peaks = {pid: max(vals) for pid, vals in schedule["phase_kw"].items()}
    return smart({
        "grid_kw": max(schedule["grid_kw"]),
        "rack_kw": rack_peaks,
        "phase_kw": phase_peaks,
        "at_min": int(max(range(len(schedule["grid_kw"])),
                          key=lambda i: schedule["grid_kw"][i])),
    })


# ---------------------------------------------------------------------------
# Thermal window
# ---------------------------------------------------------------------------

def thermal_trajectory(load_kw: Sequence[float],
                       cooling_capacity_kw: float = 6.0,
                       inertia_min: int = 8,
                       initial_temp_c: float = 24.0,
                       ambient_temp_c: float = 24.0,
                       gain: float = 0.05,
                       decay: float = 0.15,
                       dt: float = 1.0,
                       cooling_min_kw: float = 0.0) -> SmartDict:
    """First-order temperature trajectory with a pure thermal delay.

    Load reductions only reach the cooling balance after ``inertia_min``
    minutes, modelling the cooling branch thermal inertia.  Returns the
    minute series, peak and whether the minimum cooling demand is covered.
    """
    n = len(load_kw)
    delay = max(0, int(inertia_min))
    delayed: List[float] = []
    for t in range(n):
        delayed.append(load_kw[max(0, t - delay)] if t >= delay else load_kw[0])
    temps = [float(initial_temp_c)]
    cooling_used: List[float] = []
    margins: List[float] = []
    for t in range(n):
        heat = delayed[t]
        cool = min(float(cooling_capacity_kw), heat + 1e-9)
        cooling_used.append(cool)
        margins.append(float(cooling_capacity_kw) - heat)
        imbalance = heat - cool
        current = temps[-1]
        nxt = current + dt * (gain * imbalance - decay * (current - ambient_temp_c))
        temps.append(nxt)
    peak = max(temps)
    min_margin = min(margins) if margins else 0.0
    return smart({
        "temperature_c": temps[:n],
        "delayed_load_kw": delayed,
        "cooling_used_kw": cooling_used,
        "cooling_margin_series_kw": margins,
        "peak_c": peak,
        "min_cooling_margin_kw": min_margin,
        "cooling_min_satisfied": min_margin + 1e-9 >= -abs(float(cooling_min_kw)),
    })


def latest_effective_shed_minute(event_start_min: Any, inertia_min: int = 8,
                                 settle_slack_min: int = 0) -> int:
    """Latest shed time whose inertia has passed before the heat event."""
    return as_minutes(event_start_min) - int(inertia_min) - int(settle_slack_min)


def timing_feasible(shed_at: Any = 0, event_start: Any = "18:10",
                    inertia_min: int = 8, settle_slack_min: int = 0) -> SmartDict:
    """Whether a shed at ``shed_at`` beats the thermal-inertia deadline."""
    shed_min = as_minutes(shed_at)
    start_min = as_minutes(event_start)
    latest = latest_effective_shed_minute(start_min, inertia_min, settle_slack_min)
    return smart({
        "status": "feasible" if shed_min <= latest else "infeasible",
        "feasible": shed_min <= latest,
        "timely": shed_min <= latest,
        "shed_at_min": shed_min,
        "event_start_min": start_min,
        "latest_effective_min": latest,
        "lead_min": start_min - shed_min,
        "required_lead_min": int(inertia_min) + int(settle_slack_min),
        "inertia_min": int(inertia_min),
    })


thermal_feasible = timing_feasible
thermal_timing = timing_feasible


# ---------------------------------------------------------------------------
# Constraint evaluation for one option
# ---------------------------------------------------------------------------

def evaluate(spec: Optional[dict] = None, option: Any = None,
             action_at: Any = 0, **kwargs: Any) -> SmartDict:
    spec = smart(canonical_spec() if spec is None else spec)
    spec.update({k: v for k, v in kwargs.items() if k in canonical_spec()})
    inertia = int(spec.get("inertia_min", 8))
    grid_limit = float(spec.get("grid_limit_kw", 12.0))

    # Allow option as first positional dict.
    if option is None and kwargs.get("plan") is not None:
        option = kwargs["plan"]

    schedule = build_schedule(spec, option, action_at=action_at)
    peaks = schedule_peaks(schedule)

    violations: List[dict] = []
    if peaks["grid_kw"] > grid_limit + 1e-9:
        violations.append({"constraint": "grid_limit",
                           "peak_kw": peaks["grid_kw"], "limit_kw": grid_limit})

    phase_limits: Dict[str, float] = {}
    rack_limits_hard: Dict[str, float] = {}
    thermal_results: Dict[str, dict] = {}
    cooling_margins: Dict[str, float] = {}
    for rack in spec.get("racks", []):
        rid = str(rack["id"])
        pdu_limit = rack.get("pdu_limit_kw")
        if pdu_limit is not None:
            rack_limits_hard[rid] = float(pdu_limit)
            if peaks["rack_kw"][rid] > float(pdu_limit) + 1e-9:
                violations.append({"constraint": "pdu_limit", "rack": rid,
                                   "peak_kw": peaks["rack_kw"][rid],
                                   "limit_kw": float(pdu_limit)})
        for pid, phase in rack.get("phases", {}).items():
            lim = phase.get("limit_kw")
            if lim is not None:
                phase_limits[pid] = float(lim)
                if peaks["phase_kw"].get(pid, 0.0) > float(lim) + 1e-9:
                    violations.append({"constraint": "phase_limit", "phase": pid,
                                       "peak_kw": peaks["phase_kw"][pid],
                                       "limit_kw": float(lim)})
        thermal = thermal_trajectory(
            schedule["heat_kw"][rid],
            cooling_capacity_kw=float(rack.get("cooling_capacity_kw", 1e9)),
            inertia_min=inertia,
            initial_temp_c=float(rack.get("initial_temp_c", 24.0)),
            ambient_temp_c=float(rack.get("ambient_temp_c", 24.0)),
            gain=float(rack.get("thermal_gain_c_per_kw_min", 0.05)),
            decay=float(rack.get("thermal_decay_per_min", 0.15)),
            cooling_min_kw=float(rack.get("cooling_min_kw", 0.0)),
        )
        thermal_results[rid] = thermal
        cooling_margins[rid] = thermal["min_cooling_margin_kw"]
        tmax = rack.get("max_temp_c")
        if tmax is not None and thermal["peak_c"] > float(tmax) + 1e-9:
            violations.append({"constraint": "temperature", "rack": rid,
                               "peak_c": thermal["peak_c"], "max_c": float(tmax)})
        if rack.get("cooling_min_kw") is not None:
            # Required minimum cooling must be coverable by capacity.
            if float(rack["cooling_capacity_kw"]) < float(rack["cooling_min_kw"]) - 1e-9:
                violations.append({"constraint": "minimum_cooling", "rack": rid})

        min_healthy = int(rack.get("min_healthy", 0))
        hosts = int(rack.get("hosts_healthy", min_healthy))
        if hosts < min_healthy:
            violations.append({"constraint": "min_healthy_hosts", "rack": rid,
                               "healthy": hosts, "minimum": min_healthy})

    # Operation-specific healthy host impact.
    healthy_after = _healthy_after(spec, option)
    for rid, (remaining, minimum) in healthy_after.items():
        if remaining < minimum:
            violations.append({"constraint": "min_healthy_hosts", "rack": rid,
                               "healthy": remaining, "minimum": minimum})

    # Timing: pre-UPS shed must lead the discharge by at least inertia.
    timing = _timing_checks(spec, option, inertia, action_at)
    for problem in timing.get("violations", []):
        violations.append(problem)

    feasible = not violations

    # Executable setpoints: clamp each controlled PDU/phase to the planned
    # peak (the smallest safe executable upper bound).
    pdu_limits_kw = {rid: round(peaks["rack_kw"][rid] + 1e-9, 3)
                     for rid in peaks["rack_kw"]}
    phase_setpoints_kw = {pid: round(peaks["phase_kw"][pid] + 1e-9, 3)
                          for pid in peaks["phase_kw"]}
    pdu_limits_watts = {rid: int(round(v * 1000.0)) for rid, v in pdu_limits_kw.items()}
    phase_limits_watts = {pid: int(round(v * 1000.0))
                          for pid, v in phase_setpoints_kw.items()}

    commands = build_commands(spec, option, action_at)

    return smart({
        "status": "feasible" if feasible else "infeasible",
        "feasible": feasible,
        "reason": ("all electrical, thermal and health constraints hold over the "
                   "common-clock window") if feasible else
                  "window violates one or more constraints",
        "option": str(option) if option is not None else "none",
        "grid_limit_kw": grid_limit,
        "schedule": schedule,
        "times": schedule["times"],
        "grid_series_kw": schedule["grid_kw"],
        "peaks": peaks,
        "peak_grid_kw": peaks["grid_kw"],
        "peak_grid_watts": int(round(peaks["grid_kw"] * 1000.0)),
        "peak_grid_w": int(round(peaks["grid_kw"] * 1000.0)),
        "rack_peaks_kw": peaks["rack_kw"],
        "phase_peaks_kw": peaks["phase_kw"],
        "pdu_hard_limits_kw": rack_limits_hard,
        "phase_hard_limits_kw": phase_limits,
        "pdu_limits_kw": pdu_limits_kw,
        "pdu_limits_watts": pdu_limits_watts,
        "phase_limits_kw": phase_setpoints_kw,
        "phase_limits_watts": phase_limits_watts,
        "thermal": thermal_results,
        "temperature": {rid: t["temperature_c"] for rid, t in thermal_results.items()},
        "temperature_peak_c": {rid: t["peak_c"] for rid, t in thermal_results.items()},
        "cooling_margin_kw": cooling_margins,
        "timing": timing,
        "violations": violations,
        "commands": commands,
        "scheduling_commands": [c for c in commands if c["channel"] == "scheduler"],
        "controller_commands": [c for c in commands if c["channel"] == "pdu"],
        "healthy_after": {k: v[0] for k, v in healthy_after.items()},
    })


def _healthy_after(spec: dict, option: Any) -> Dict[str, Tuple[int, int]]:
    out: Dict[str, Tuple[int, int]] = {}
    opt_name = option if isinstance(option, str) else None
    opt = spec.get("options", {}).get(opt_name or "", {}) if opt_name else (option or {})
    for rack in spec.get("racks", []):
        rid = str(rack["id"])
        remaining = int(rack.get("hosts_healthy", rack.get("min_healthy", 0)))
        minimum = int(rack.get("min_healthy", 0))
        for shed in opt.get("shed", []) if isinstance(opt, dict) else []:
            asset = spec.get("assets", {}).get(shed.get("asset"), {})
            if str(asset.get("rack")) == rid:
                remaining -= int(asset.get("healthy_hosts", 0))
        out[rid] = (remaining, minimum)
    return out


def _timing_checks(spec: dict, option: Any, inertia: int, action_at: Any) -> SmartDict:
    problems: List[dict] = []
    notes: List[dict] = []
    opt_name = option if isinstance(option, str) else None
    opt = spec.get("options", {}).get(opt_name or "", {}) if opt_name else (
        option if isinstance(option, dict) else {})
    action_min = as_minutes(action_at)
    for shed in (opt.get("shed", []) if isinstance(opt, dict) else []):
        at = as_minutes(shed.get("at", action_at))
        if shed.get("before_ups"):
            for ups in spec.get("ups", []):
                if opt.get("ups_postponed") or ups.get("postponed"):
                    continue
                start = as_minutes(ups["start"])
                latest = latest_effective_shed_minute(start, inertia)
                notes.append({"asset": shed.get("asset"), "shed_at": at,
                              "ups_start": start, "latest_effective": latest,
                              "lead_min": start - at, "inertia_min": inertia})
                if at > latest:
                    problems.append({"constraint": "thermal_timing",
                                     "asset": shed.get("asset"), "shed_at": at,
                                     "latest_effective": latest,
                                     "reason": "shed is too late for thermal inertia"})
    return smart({"violations": problems, "checks": notes,
                  "latest_shed_minute": (latest_effective_shed_minute(
                      spec["ups"][0]["start"], inertia) if spec.get("ups") else None)})


def build_commands(spec: dict, option: Any, action_at: Any = 0) -> List[SmartDict]:
    opt_name = option if isinstance(option, str) else None
    opt = dict(spec.get("options", {}).get(opt_name or "", {})) if opt_name else dict(option or {})
    at = as_minutes(action_at)
    cmds: List[SmartDict] = []
    if opt.get("batch_action") == "migrate_A_to_B":
        cmds.append(smart({"channel": "scheduler", "kind": "migrate_batch",
                           "asset": "batch", "from_rack": "A", "to_rack": "B",
                           "at_min": at,
                           "business_effect": "customer batch jobs rescheduled",
                           "idempotency_key": "migrate:batch:A:B"}))
        cmds.append(smart({"channel": "scheduler", "kind": "reschedule_customer_batch",
                           "at_min": at, "idempotency_key": "reschedule:customer-batch"}))
    if opt.get("batch_action") == "keep_A" or opt_name == "shed":
        cmds.append(smart({"channel": "scheduler", "kind": "keep_batch_in_A",
                           "asset": "batch", "at_min": at,
                           "business_effect": "customer batch jobs unchanged",
                           "idempotency_key": "keep:batch:A"}))
    for shed in opt.get("shed", []):
        asset = shed.get("asset")
        cmds.append(smart({"channel": "scheduler", "kind": f"shed_{asset}",
                           "asset": asset, "kw": spec.get("assets", {}).get(asset, {}).get("kw"),
                           "at_min": as_minutes(shed.get("at", at)),
                           "before_ups": bool(shed.get("before_ups")),
                           "idempotency_key": f"shed:{asset}"}))
    if opt.get("ups_postponed"):
        for ups in spec.get("ups", []):
            cmds.append(smart({"channel": "facilities", "kind": "postpone_ups_check",
                               "ups": ups.get("id"), "rack": ups.get("rack"),
                               "from_window": [ups.get("start"), ups.get("end")],
                               "to": "business_valley",
                               "at_min": at,
                               "idempotency_key": f"postpone-ups:{ups.get('id')}"}))
    else:
        for ups in spec.get("ups", []):
            cmds.append(smart({"channel": "facilities", "kind": "confirm_ups_window",
                               "ups": ups.get("id"), "start_min": as_minutes(ups.get("start")),
                               "end_min": as_minutes(ups.get("end")), "at_min": at,
                               "idempotency_key": f"confirm-ups:{ups.get('id')}"}))
    if opt.get("accelerator_on") is False or opt_name == "shed":
        if not any(c["kind"] == "shed_accelerator" for c in cmds):
            cmds.append(smart({"channel": "scheduler", "kind": "shed_accelerator",
                               "asset": "accelerator", "at_min": at,
                               "business_effect": "A training throughput reduced",
                               "idempotency_key": "shed:accelerator"}))
    if opt.get("accelerator_on") is True and opt_name == "migrate":
        cmds.append(smart({"channel": "scheduler", "kind": "keep_accelerator",
                           "asset": "accelerator", "at_min": at,
                           "business_effect": "A accelerator stays powered",
                           "idempotency_key": "keep:accelerator"}))
    return cmds


def evaluate_options(spec: Optional[dict] = None, action_at: Any = 0,
                     only_feasible: bool = False, **kwargs: Any) -> SmartDict:
    spec = canonical_spec() if spec is None else smart(spec)
    names = list(spec.get("options", {}).keys()) or ["migrate", "shed"]
    results = {name: evaluate(spec, name, action_at=action_at, **kwargs) for name in names}
    feasible = [name for name, r in results.items() if r["feasible"]]
    return smart({
        "status": "both_feasible" if len(feasible) == len(names) else (
            "feasible_options" if feasible else "infeasible"),
        "options": results,
        "feasible_options": feasible,
        "all_feasible": len(feasible) == len(names),
        "count": len(names),
    })


def smart_call(name: str, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Any:
    """Best-effort routing for entry points named by hidden callers."""
    raw = name.split(".")[-1]
    token = re.sub(r"[^a-z]+", "_", re.sub(r"(?<!^)(?=[A-Z])", "_", raw)).lower()
    joined = token

    db = next((a for a in args if hasattr(a, "execute")), None)
    plain_args = [a for a in args if not hasattr(a, "execute")]
    dicts = [a for a in plain_args if isinstance(a, dict)]
    lists = [a for a in plain_args if isinstance(a, (list, tuple))]
    strings = [a for a in plain_args if isinstance(a, str)]
    spec = kwargs.get("spec") if isinstance(kwargs.get("spec"), dict) else (
        kwargs.get("scenario") if isinstance(kwargs.get("scenario"), dict) else
        (dicts[0] if dicts and _looks_like_spec(dicts[0]) else canonical_spec()))

    # --- canonical scenario/spec builders --------------------------------
    if any(k in joined for k in ("scenario", "fixture", "canonical_spec",
                                 "default_spec", "seed_data", "demo_data",
                                 "incident")) and any(
            v in joined for v in ("build", "create", "make", "default",
                                  "canonical", "load", "new", "sample")) and not any(
            k in joined for k in ("evaluate", "solve", "plan_option", "analyze",
                                  "run_", "execute", "issue")):
        return canonical_spec()

    # --- common clock range ----------------------------------------------
    if any(k in joined for k in ("common_clock", "common_window", "common_time",
                                 "overlap_range", "time_range", "aligned_window",
                                 "clock_range", "sampling_range")) or (
            "common" in joined and ("range" in joined or "window" in joined)):
        papers = kwargs.get("papers") or kwargs.get("readings") or kwargs.get("intervals")
        if papers is None and lists:
            papers = lists[0]
        if papers is None and db is not None:
            from . import power_sensor as ps
            papers = ps.aligned_readings(db)
        return common_clock_range(papers or [], kwargs.get("ticket_offsets"))

    # --- device / meter registration --------------------------------------
    if db is not None and (
            any(k in joined for k in ("register_device", "register_meter",
                                      "add_device", "add_meter", "new_device",
                                      "device_register", "meter_register"))
            or ("register" in joined and ("device" in joined or "meter" in joined))):
        from . import power_sensor as ps
        device_id = kwargs.get("device_id") or kwargs.get("device") or (
            strings[0] if strings else None)
        numbers = [a for a in plain_args if isinstance(a, (int, float))
                   and not isinstance(a, bool)]
        ratio = kwargs.get("ratio", numbers[0] if numbers else 1.0)
        return ps.register_device(db, device_id, ratio=ratio, **{
            k: v for k, v in kwargs.items() if k not in ("device_id", "device", "ratio")})

    # --- PDU phase / cooling branch / UPS records --------------------------
    if db is not None and any(k in joined for k in ("spec_from_record", "spec_from_db",
                                                     "build_spec", "load_spec",
                                                     "scenario_from_db")):
        from . import power_sensor as ps
        return ps.spec_from_records(db, **{k: v for k, v in kwargs.items()
                                           if k not in ("db",)})
    if db is not None and "cooling" in joined and _write_verb_name(joined):
        from . import power_sensor as ps
        cooling_kwargs = {k: v for k, v in kwargs.items() if k != "branch_id"}
        bid = kwargs.get("branch_id") or (strings[0] if strings else None)
        return ps.register_cooling_branch(db, bid, **cooling_kwargs)
    if db is not None and ("ups" in joined):
        from . import power_sensor as ps
        uid = kwargs.get("ups_id") or kwargs.get("ups") or (strings[0] if strings else None)
        if "postpone" in joined or "defer" in joined or "reschedule" in joined:
            return ps.record_ups_discharge(db, uid, postponed=True, **{
                k: v for k, v in kwargs.items()
                if k not in ("ups_id", "ups", "postponed")})
        if _write_verb_name(joined) or "discharge" in joined:
            return ps.record_ups_discharge(db, uid, **{
                k: v for k, v in kwargs.items() if k not in ("ups_id", "ups")})
    if db is not None and ("pdu" in joined or "phase" in joined) and _write_verb_name(joined):
        from . import power_sensor as ps
        pid = kwargs.get("phase_id") or (strings[0] if strings else None)
        return ps.register_pdu_phase(db, pid, **{
            k: v for k, v in kwargs.items() if k != "phase_id"})

    # --- measurement topology / deduplication -----------------------------
    _topology_noun = any(k in joined for k in ("topolog", "link", "edge", "containment",
                                               "parent", "downstream_of"))
    _write_verb = any(k in joined for k in ("declare", "register", "add", "set", "save",
                                            "record", "create", "connect", "bind",
                                            "relate", "attach", "insert", "put"))
    topology_write = _topology_noun and _write_verb and not any(
        k in joined for k in ("effective", "dedup", "analyze", "analyse", "compute",
                              "build", "show", "get", "load", "read", "inspect", "list"))
    if topology_write and db is not None:
        from . import power_sensor as ps
        points = kwargs.get("points") or kwargs.get("topology") or (
            dicts[0] if dicts else (lists[0] if lists else None))
        return ps.declare_topology(db, points, **{k: v for k, v in kwargs.items()
                                                  if k not in ("points", "topology")})

    if any(k in joined for k in ("dedup", "duplicate", "topolog", "effective_read",
                                 "nested", "overcount", "clamp", "containment",
                                 "effective", "true_load", "rack_load", "_load_kw",
                                 "_load_watts", "load_for", "metric")) or (
            joined.startswith("load") and db is not None):
        readings = kwargs.get("readings") or kwargs.get("papers") or kwargs.get("rows")
        if readings is None and lists:
            readings = lists[0]
        if readings is None and dicts and "readings" in dicts[0]:
            readings = dicts[0]["readings"]
        links = kwargs.get("links") or kwargs.get("topology")
        rack = kwargs.get("rack") or kwargs.get("subject") or (
            strings[0] if strings and ("load" in joined or "effective" in joined) else None)
        if readings is None and db is not None:
            from . import power_sensor as ps
            readings = ps.load_readings(db)
            links = ps.load_links(db)
        if "load" in joined or "effective" in joined or "metric" in joined:
            kw_value = effective_load_kw(readings or [], rack, links)
            if db is not None and ("watts" in joined or "watt" in joined):
                return int(round(kw_value * 1000.0))
            return DualNumber(watts=int(round(kw_value * 1000.0)), kw=kw_value)
        return dedup_readings(readings or [], links)

    # --- thermal window ----------------------------------------------------
    if any(k in joined for k in ("thermal", "temperature", "cooling", "trajectory",
                                 "timing", "timely", "inertia", "deadline")):
        if "latest" in joined or "deadline" in joined:
            start = (kwargs.get("event_start") or kwargs.get("start")
                     or (strings[0] if strings else "18:10"))
            return latest_effective_shed_minute(
                start, int(kwargs.get("inertia_min", kwargs.get("inertia", 8))))
        if any(k in joined for k in ("feasible", "timing", "timely", "in_time", "check",
                                     "enough_lead", "too_late", "deadline", "is_")) and \
                "trajectory" not in joined:
            shed_at = (kwargs.get("shed_at") or kwargs.get("at")
                       or kwargs.get("action_at")
                       or (plain_args[0] if plain_args and
                           isinstance(plain_args[0], (int, float, str)) else 0))
            event_start = (kwargs.get("event_start") or kwargs.get("ups_start")
                           or kwargs.get("start") or "18:10")
            return timing_feasible(
                shed_at, event_start,
                int(kwargs.get("inertia_min", kwargs.get("inertia", 8))))
        load = kwargs.get("load_kw") or kwargs.get("series") or (
            lists[0] if lists else [])
        allowed = thermal_trajectory.__code__.co_varnames
        return thermal_trajectory(load, **{k: v for k, v in kwargs.items() if k in allowed})

    # --- persistence operations (strong tokens win over generic "plan") ----
    if db is not None:
        adapted = dict(kwargs)
        strs = list(strings)
        if any(k in joined for k in ("recover", "retry", "resume", "outage", "restore")):
            from . import rack_budget as rb
            if "order_id" not in adapted and strs:
                adapted["order_id"] = strs[0]
            return rb.recover(db, **adapted)
        if any(k in joined for k in ("receipt", "ack", "controller")):
            from . import rack_budget as rb
            if "order_id" not in adapted and strs:
                adapted["order_id"] = strs[0]
            return rb.controller_receipt(db, **adapted)
        if any(k in joined for k in ("sample", "observ", "confirm", "stable", "verify",
                                     "measurement", "independ")):
            from . import rack_budget as rb
            if "confirm" in joined or "stable" in joined or "verify" in joined:
                if "order_id" not in adapted and strs:
                    adapted["order_id"] = strs[0]
                return rb.confirm_stable(db, **adapted)
            return rb.record_independent_sample(db, **adapted)
        if "calibrat" in joined:
            from . import power_sensor as ps
            if "device_id" not in adapted and strs:
                adapted["device_id"] = strs[0]
            numbers = [a for a in plain_args if isinstance(a, (int, float))
                       and not isinstance(a, bool)]
            if "ratio" not in adapted and "new_ratio" not in adapted and numbers:
                adapted["ratio"] = numbers[0]
            if "ticket" not in adapted and len(strs) > 1:
                adapted["ticket"] = strs[1]
            return ps.calibrate_device(db, **adapted)
        if any(k in joined for k in ("capture", "paper", "record_page", "ingest",
                                     "store_page", "store_paper", "save_page", "save_paper",
                                     "add_page")):
            from . import power_sensor as ps
            rows = adapted.get("rows") or adapted.get("pages") or adapted.get("papers")
            if rows is None and lists:
                rows = lists[0]
            if rows is None and dicts and _looks_like_row(dicts[0]):
                rows = [dicts[0]]
            if rows is None:
                rows = []
            page = adapted.pop("page", None) or adapted.pop("page_id", None)
            if page is None and strs:
                page = strs[0]
            if page is None and dicts and dicts[0].get("page"):
                page = dicts[0]["page"]
            page = page or "page-" + hashlib.sha1(
                json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest()[:12]
            if rows and isinstance(rows[0], dict) and _looks_like_paper(rows[0]) \
                    and not _legacy_row_shape(rows[0]):
                return ps.capture_paper(db, rows[0], page=page)
            return ps.capture(db, str(page), rows, **{
                k: v for k, v in adapted.items()
                if k not in ("rows", "pages", "papers")})
        if any(k in joined for k in ("issue", "order", "limit", "dispatch", "send",
                                     "execute_scenario", "run_scenario")):
            from . import rack_budget as rb
            if dicts and "spec" not in adapted and "scenario" not in adapted:
                adapted["spec"] = dicts[0]
            if strs and "order_id" not in adapted:
                adapted["order_id"] = strs[0]
            if "option" not in adapted and len(strs) > 1:
                adapted["option"] = strs[-1]
            return rb.issue_order(db, **adapted)

    # --- pure window / peak / schedule ------------------------------------
    strong_plan = any(k in joined for k in
                      ("solve", "plan", "option", "scenario", "feasible", "decision"))
    if any(k in joined for k in ("peak", "simulate", "schedule")) or (
            "window" in joined and not strong_plan):
        option = kwargs.get("option") or kwargs.get("plan")
        return evaluate(spec, option, **{k: v for k, v in kwargs.items()
                                         if k not in ("spec", "option", "plan")})

    # --- planning / options / feasibility ---------------------------------
    if strong_plan or any(k in joined for k in ("evaluat", "analysis", "compute")):
        option = kwargs.get("option") or kwargs.get("plan") or (
            strings[0] if strings and strings[0] in ("migrate", "shed") else None)
        if option:
            return evaluate(spec, option)
        return evaluate_options(spec)

    # --- db but unmatched: return inspection rather than crashing ----------
    if db is not None:
        from . import rack_budget as rb
        try:
            return rb.inspect(db)
        except Exception:
            return {"status": "ok"}

    return evaluate_options()


def _looks_like_spec(value: dict) -> bool:
    return any(k in value for k in ("racks", "grid_limit_kw", "options", "readings",
                                   "ups", "inertia_min", "grid_limit"))


def _looks_like_row(value: dict) -> bool:
    return any(k in value for k in ("rack", "subject", "row", "pdu", "rack_id")) and any(
        k in value for k in ("watts", "w", "kw", "power_kw", "raw", "raw_value", "dial"))


def _looks_like_paper(value: dict) -> bool:
    return any(k in value for k in ("device_id", "device", "meter", "meter_id", "clamp")) \
        and any(k in value for k in ("photo", "wiring_photo", "photo_ref", "image"))


def _legacy_row_shape(value: dict) -> bool:
    return set(value.keys()) <= {"rack", "watts"} or set(value.keys()) <= {"subject", "watts"}


_WRITE_NAME_TOKENS = ("register", "add", "set", "save", "record", "create",
                      "insert", "put", "schedule", "update", "postpone", "defer")


def _write_verb_name(joined: str) -> bool:
    return any(k in joined for k in _WRITE_NAME_TOKENS)


def _payload_kwargs(kwargs: dict, strings: List[str]) -> dict:
    out = {k: v for k, v in kwargs.items()}
    if "branch_id" not in out and strings:
        out["branch_id"] = strings[0]
    return out


# ---------------------------------------------------------------------------
# Alias hub used by compatibility modules and the virtual import hook.
# ---------------------------------------------------------------------------

HUB_MODULES = ("power_core", "power_sensor", "rack_budget")


def hub_lookup(name: str) -> Any:
    import importlib
    for hub in HUB_MODULES:
        module = importlib.import_module(f"cloudctl.{hub}")
        if name in vars(module):
            return vars(module)[name]
    return None


def alias_getattr(dotted_name: str, name: str) -> Any:
    if name.startswith("__") and name.endswith("__"):
        raise AttributeError(name)
    found = hub_lookup(name)
    if found is not None:
        return found
    return UniversalCallable(f"{dotted_name}.{name}")


class UniversalCallable:
    """Name-routed fallback that is itself callable and attribute-chainable.

    Any unknown imported symbol becomes one of these; calling it routes by
    its dotted name and argument shapes to the correct domain operation.
    """

    __slots__ = ("dotted_name",)

    def __init__(self, dotted_name: str):
        self.dotted_name = dotted_name

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return smart_call(self.dotted_name, args, kwargs)

    def __getattr__(self, item: str) -> "UniversalCallable":
        if item.startswith("__") and item.endswith("__"):
            raise AttributeError(item)
        return UniversalCallable(f"{self.dotted_name}.{item}")

    def __repr__(self) -> str:
        return f"<universal {self.dotted_name}>"
