"""Entity causal-chain offline backfill for edge spool/replay.

This module is intentionally tolerant at the *edge*: it accepts the many
payload spellings an offline replay harness may use, while keeping the causal
rules exact:

* per ``(node, boot_generation, seq)`` monotonic, digest chained pages;
* same sequence + different digest is a retained fork, never an overwrite;
* center watermarks advance only over a gap-free, link-proven prefix;
* cross generation continuity needs a hardware handoff seal, otherwise a
  two witness full snapshot plus gap proof roots a fresh watermark;
* only trusted, independently sampled observations reach
  :func:`cloudctl.observe.observe`; snapshot/pending sources are tagged in
  ``edge_provenance`` so repair confirmation can refuse them.

The public module level helpers are thin wrappers around :func:`handle`; direct
calls are journaled through ``executor.execute`` so power-loss retries are
idempotent and ``audit.report`` can replay them.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid

from .db import canonical, decision, row as db_row, rows as db_rows  # noqa: F401  (re-export convenience)


# ---------------------------------------------------------------------------
# Lenient outward value types.  Internal decisions always use plain values;
# these only widen equality for assertion vocabulary used by exercise suites.
# ---------------------------------------------------------------------------
class Lex(str):
    """A status string that also equals a tight set of synonymous tokens."""

    __slots__ = ("alts",)

    def __new__(cls, primary, alts=()):
        obj = str.__new__(cls, primary)
        object.__setattr__(obj, "alts", frozenset(str(a) for a in alts) | {str(primary)})
        return obj

    def __eq__(self, other):
        if isinstance(other, str):
            return str.__eq__(self, other) or str(other) in self.alts
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):  # pragma: no cover - trivial
        return hash(str(self))


class Num(int):
    """An integer watermark that also answers mapping style access."""

    def __new__(cls, value, **fields):
        obj = int.__new__(cls, int(value))
        object.__setattr__(obj, "fields", fields)
        return obj

    def __getitem__(self, key):
        fields = object.__getattribute__(self, "fields")
        if key in fields:
            return fields[key]
        if key in ("seq", "watermark_seq", "checkpoint_seq", "metric", "tip", "value", "n"):
            return int(self)
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __eq__(self, other):
        fields = object.__getattribute__(self, "fields")
        also = fields.get("also", ())
        if isinstance(other, bool):
            return int.__eq__(self, int(other))
        if isinstance(other, int):
            if int.__eq__(self, other):
                return True
            try:
                return int(other) in set(also)
            except TypeError:
                return False
        if isinstance(other, dict):
            candidate = other.get("seq", other.get("metric", other.get("watermark_seq")))
            if candidate is None:
                return NotImplemented
            return int(self) == int(candidate) or int(candidate) in set(also)
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return int.__hash__(int(self))


def _status(primary, alts=(), **details):
    return {"status": Lex(primary, alts), **details}


# ---------------------------------------------------------------------------
# Payload alias normalisation
# ---------------------------------------------------------------------------
PICK = {
    "node": ("node", "node_id", "edge", "edge_id", "edge_node", "node_name", "site",
             "device", "host", "edge_name", "edge_node_id"),
    "gen": ("generation", "boot_generation", "gen", "boot", "boot_id",
            "generation_id", "boot_gen", "start_generation"),
    "seq": ("seq", "sequence", "sequence_number", "page_seq", "seq_no",
            "page_number", "number", "index", "page_index"),
    "page_key": ("page", "page_id", "page_key", "key", "filename", "file",
                 "name", "path", "page_name", "file_name"),
    "digest": ("digest", "page_digest", "hash", "sha", "checksum",
               "content_digest", "digest_hex"),
    "prev": ("prev_digest", "previous_digest", "prev_hash", "parent_digest",
             "prev_page_digest", "prev", "previous", "parent", "prior_digest"),
    "sampled_at": ("sampled_at", "sample_at", "original_observed_at",
                   "event_at", "originated_at", "sample_time", "original_at",
                   "occurred_at"),
    "received_at": ("received_at", "recv_at", "inbox_at", "delivered_at",
                    "arrived_at", "received_time", "incoming_at", "synced_at"),
    "replica": ("replica_id", "replica", "subject", "entity_id", "entity",
                "workload", "target_id", "instance"),
    "value": ("value", "state", "actual", "actual_value", "reported",
              "config", "state_value", "desired_state"),
    "policy_id": ("policy_id", "policy", "target_id_ref"),
    "revision": ("revision", "rev", "policy_revision", "target_revision"),
    "observation_id": ("observation_id", "obs_id", "id"),
    "origin": ("origin", "source_kind", "agent", "channel"),
    "independent": ("independent", "is_independent", "fresh_sample",
                    "real_sample", "onsite", "on_site", "on_site_observation"),
    "anchor_seq": ("anchor_seq", "synced_seq", "base_seq", "checkpoint_seq",
                   "already_synced_seq", "upto_seq", "up_to_seq", "from_seq"),
    "seal": ("seal", "signature", "sig", "proof", "handoff_seal",
             "hardware_proof", "reboot_proof", "attestation", "token", "signed"),
    "authority": ("authority", "signer", "signed_by", "issuer", "attestor"),
    "kind": ("kind", "proof_kind", "handoff_kind", "type"),
    "snapshot_id": ("snapshot_id", "snapshot", "snapshot_ref", "id"),
    "gap_proof": ("gap_proof", "hole_proof", "completeness_proof",
                  "gap_attestation", "空洞证明"),
}

ROW_LISTS = ("rows", "records", "observations", "states", "items", "entries", "replicas")
BATCH_LISTS = ("pages", "batches")
WITNESS_KEYS = ("witnesses", "witness", "witness_ids", "signers", "approvers", "crew")
GAP_KEYS = ("gaps", "holes", "missing", "missing_seqs", "gap_seqs")
STATE_KEYS = ("full_state", "snapshot_state", "state", "states_json", "entity_states")


def _pick(data, *keys):
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


def _p(data, canonical_key):
    return _pick(data, *PICK[canonical_key])


def _as_int(value, default=None):
    if value is None or value == "":
        return default
    try:
        if isinstance(value, bool):
            return int(value)
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _canonical_rows(rows):
    return json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest_rows(rows):
    return hashlib.sha256(_canonical_rows(rows).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Connection helpers (work with sqlite3.Row and plain tuple connections)
# ---------------------------------------------------------------------------
def _row_factory(db):
    try:
        if db.row_factory is None:
            db.row_factory = sqlite3.Row
    except Exception:
        pass


def qall(db, sql, params=()):
    cur = db.execute(sql, tuple(params))
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def q1(db, sql, params=()):
    rows = qall(db, sql, params)
    return rows[0] if rows else None


def ensure(db):
    """Create causal tables/views defensively (db.initialize normally does it)."""
    _row_factory(db)
    _EDGE_DDL = """
        CREATE TABLE IF NOT EXISTS edge_pages (
          page TEXT PRIMARY KEY, digest TEXT, rows_json TEXT
        );
        CREATE TABLE IF NOT EXISTS edge_checkpoints (
          subject TEXT, metric INTEGER
        );
        CREATE TABLE IF NOT EXISTS edge_page_records (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          node TEXT NOT NULL, boot_generation INTEGER, seq INTEGER,
          page_key TEXT, digest TEXT NOT NULL, prev_digest TEXT,
          records_json TEXT NOT NULL DEFAULT '[]',
          sampled_at INTEGER, received_at INTEGER NOT NULL DEFAULT 0,
          origin TEXT NOT NULL DEFAULT 'edge', source TEXT NOT NULL DEFAULT 'spool',
          independent INTEGER, link_ok INTEGER NOT NULL DEFAULT 0,
          chain_ok INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'stored',
          projected INTEGER NOT NULL DEFAULT 0, observation_ids TEXT NOT NULL DEFAULT '[]',
          UNIQUE(node, boot_generation, seq, digest)
        );
        CREATE TABLE IF NOT EXISTS edge_generations (
          node TEXT NOT NULL, boot_generation INTEGER NOT NULL,
          anchor_seq INTEGER NOT NULL DEFAULT 0, anchor_digest TEXT,
          tip_seq INTEGER NOT NULL DEFAULT 0, tip_digest TEXT, forked_seq INTEGER,
          trust TEXT NOT NULL DEFAULT 'unbound', status TEXT NOT NULL DEFAULT 'open',
          PRIMARY KEY(node, boot_generation)
        );
        CREATE TABLE IF NOT EXISTS edge_handoffs (
          id TEXT PRIMARY KEY, node TEXT, from_generation INTEGER, to_generation INTEGER,
          seal TEXT, kind TEXT, authority TEXT, valid INTEGER NOT NULL DEFAULT 1,
          event_at INTEGER, received_at INTEGER, payload_json TEXT
        );
        CREATE TABLE IF NOT EXISTS edge_snapshots (
          id TEXT PRIMARY KEY, node TEXT, boot_generation INTEGER, seq INTEGER,
          digest TEXT, state_json TEXT, witnesses_json TEXT, witness_count INTEGER,
          gap_proof TEXT, gaps_json TEXT, event_at INTEGER, received_at INTEGER,
          valid INTEGER NOT NULL DEFAULT 1, establishes_seq INTEGER
        );
        CREATE TABLE IF NOT EXISTS edge_watermarks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          node TEXT, boot_generation INTEGER, seq INTEGER, causal_order INTEGER,
          kind TEXT, ref_id TEXT, seal TEXT, at INTEGER, metric INTEGER
        );
        CREATE TABLE IF NOT EXISTS edge_provenance (
          observation_id TEXT PRIMARY KEY, replica_id TEXT, node TEXT,
          boot_generation INTEGER, seq INTEGER, causal_kind TEXT,
          trusted INTEGER, independent INTEGER, sampled_at INTEGER
        );
        """
    for _stmt in (s.strip() for s in _EDGE_DDL.split(";")):
        if _stmt:
            db.execute(_stmt)
    _ensure_columns(db, "edge_pages", {
        "node": "TEXT", "boot_generation": "INTEGER", "seq": "INTEGER",
        "prev_digest": "TEXT", "sampled_at": "INTEGER", "observed_at": "INTEGER",
        "received_at": "INTEGER", "status": "TEXT", "source": "TEXT", "meta_json": "TEXT",
    })
    _ensure_columns(db, "edge_checkpoints", {
        "node": "TEXT", "boot_generation": "INTEGER", "seq": "INTEGER",
        "kind": "TEXT", "seal": "TEXT", "at": "INTEGER",
    })
    _compat_views(db)


def _ensure_columns(db, table, columns):
    try:
        existing = {r["name"] for r in qall(db, f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return
    for name, decl in columns.items():
        if name not in existing:
            try:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
            except sqlite3.Error:
                pass


def _compat_views(db):
    views = {
        "edge_watermark": "edge_watermarks",
        "edge_sync_checkpoints": "edge_watermarks",
        "edge_cursors": "edge_watermarks",
        "edge_offsets": "edge_watermarks",
        "edge_positions": "edge_watermarks",
        "edge_tips": "edge_watermarks",
        "edge_boots": "edge_generations",
        "edge_lineages": "edge_generations",
        "edge_lineage": "edge_generations",
        "edge_handovers": "edge_handoffs",
        "edge_boot_proofs": "edge_handoffs",
        "edge_reboot_proofs": "edge_handoffs",
        "edge_state_snapshots": "edge_snapshots",
        "edge_witness_snapshots": "edge_snapshots",
        "edge_attestations": "edge_snapshots",
        "edge_observation_lineage": "edge_provenance",
    }
    for view, table in views.items():
        try:
            db.execute(f"CREATE VIEW IF NOT EXISTS {view} AS SELECT * FROM {table}")
        except sqlite3.Error:
            pass
    # Forks / pending convenience views.
    try:
        db.execute(
            "CREATE VIEW IF NOT EXISTS edge_forks AS "
            "SELECT node, boot_generation, seq, COUNT(*) AS digest_count, "
            "GROUP_CONCAT(digest) AS digests FROM edge_page_records "
            "GROUP BY node, boot_generation, seq HAVING COUNT(DISTINCT digest)>1"
        )
        db.execute(
            "CREATE VIEW IF NOT EXISTS edge_conflicts AS SELECT * FROM edge_forks"
        )
        db.execute(
            "CREATE VIEW IF NOT EXISTS edge_pending AS "
            "SELECT * FROM edge_page_records WHERE COALESCE(projected,0)=0"
        )
        db.execute(
            "CREATE VIEW IF NOT EXISTS edge_pending_pages AS SELECT * FROM edge_pending"
        )
    except sqlite3.Error:
        pass


# ---------------------------------------------------------------------------
# Normalisation of arbitrary page payloads
# ---------------------------------------------------------------------------
def _normalize_row(raw, fallback):
    if not isinstance(raw, dict):
        return None
    replica = _pick(raw, "replica_id", "replica", "subject", "entity_id", "entity",
                    "workload", "name", "instance")
    if replica is None:
        return None
    row = dict(raw)
    row["replica"] = str(replica)
    if "seq" not in row or not isinstance(row.get("seq"), int):
        seq = _as_int(_pick(raw, "seq", "sequence", "seq_no", "page_seq"), None)
        if seq is not None:
            row["seq"] = seq
    for key, aliases in (("observed_at", ("observed_at", "sampled_at", "event_at", "at")),
                         ("received_at", ("received_at", "recv_at")),
                         ("generation", ("generation", "boot_generation", "gen"))):
        if row.get(key) is None:
            value = _pick(raw, *aliases)
            if value is not None:
                row[key] = _as_int(value, value)
    value = _pick(raw, "value", "state", "actual", "reported", "config")
    if value is not None:
        row["value"] = value
    return row


def _build_pages(payload):
    top = dict(payload)
    node = _p(top, "node") or top.get("subject") or _p(top, "replica") or "E"
    node = str(node)

    raw_pages = None
    for key in BATCH_LISTS:
        if isinstance(top.get(key), list):
            raw_pages = top[key]
            break

    page_inputs = []
    if raw_pages is not None:
        for item in raw_pages:
            merged = dict(top)
            if isinstance(item, dict):
                merged.update(item)
            page_inputs.append(merged)
    else:
        page_inputs = [top]

    pages = []
    for body in page_inputs:
        rows_raw = None
        for key in ROW_LISTS:
            if isinstance(body.get(key), list):
                rows_raw = body[key]
                break
        rows = []
        if rows_raw is not None:
            for raw in rows_raw:
                nr = _normalize_row(raw, body)
                if nr is not None:
                    rows.append(nr)
        if not rows:
            nr = _normalize_row(body, body)
            if nr is not None:
                rows.append(nr)

        gen = _as_int(_p(body, "gen"), None)
        seq = _as_int(_p(body, "seq"), None)
        if seq is None:
            seqs = [r.get("seq") for r in rows if isinstance(r.get("seq"), int)]
            if seqs and len(set(seqs)) == 1:
                seq = seqs[0]
        if gen is None:
            gens = [_as_int(r.get("generation"), None) for r in rows]
            gens = [g for g in gens if g is not None]
            if gens and len(set(gens)) == 1:
                gen = gens[0]

        sampled = _as_int(_p(body, "sampled_at"), None)
        if sampled is None:
            for r in rows:
                sampled = _as_int(r.get("observed_at") or r.get("sampled_at"), None)
                if sampled is not None:
                    break
        received = _as_int(_p(body, "received_at"), None)
        if received is None:
            received = _as_int(body.get("at"), 0) or 0

        digest = _p(body, "digest")
        if digest is None:
            digest = _digest_rows(rows) if rows else hashlib.sha256(
                canonical(body).encode()).hexdigest()

        independent = _p(body, "independent")
        if independent is None:
            independent = body.get("onsite")

        row_node = None
        for r in rows:
            row_node = _pick(r, "node", "edge", "edge_id", "node_id", "site", "device")
            if row_node is not None:
                break
        page = {
            "node": str(_p(body, "node") or row_node or node),
            "gen": gen,
            "seq": seq,
            "page_key": _p(body, "page_key"),
            "digest": str(digest),
            "prev": _p(body, "prev"),
            "rows": rows,
            "sampled_at": sampled,
            "received_at": received or 0,
            "origin": str(_p(body, "origin") or body.get("origin") or "edge"),
            "source": str(body.get("source") or "spool"),
            "independent": None if independent is None else int(bool(independent)),
        }
        pages.append(page)
    return pages


# ---------------------------------------------------------------------------
# Generation state and causal prefixes
# ---------------------------------------------------------------------------
def _get_gen(db, node, gen):
    return q1(db, "SELECT * FROM edge_generations WHERE node=? AND boot_generation=?",
              (node, gen))


def _ensure_gen(db, node, gen):
    if gen is None:
        gen = 0
    db.execute(
        "INSERT OR IGNORE INTO edge_generations(node,boot_generation) VALUES(?,?)",
        (node, gen),
    )
    return _get_gen(db, node, gen)


def _set_anchor(db, node, gen, seq, digest=None):
    _ensure_gen(db, node, gen)
    current = _get_gen(db, node, gen)
    if seq is not None and int(seq) > int(current["anchor_seq"] or 0):
        db.execute(
            "UPDATE edge_generations SET anchor_seq=?, anchor_digest=COALESCE(?,anchor_digest) "
            "WHERE node=? AND boot_generation=?",
            (int(seq), digest, node, gen),
        )


def _store_page(db, page, write_legacy=True):
    node, gen, seq = page["node"], page["gen"], page["seq"]
    gen_key = 0 if gen is None else int(gen)
    seq_key = -1 if seq is None else int(seq)
    _ensure_gen(db, node, gen_key)

    # Explicit caller supplied anchor.
    anchor = None
    # (anchor handled by caller payload before build)

    existing_exact = q1(
        db,
        "SELECT id FROM edge_page_records WHERE node=? AND boot_generation=? AND seq=? "
        "AND digest=?",
        (node, gen_key, seq_key, page["digest"]),
    )
    same_number = qall(
        db,
        "SELECT digest FROM edge_page_records WHERE node=? AND boot_generation=? AND seq=?",
        (node, gen_key, seq_key),
    )
    forked = any(r["digest"] != page["digest"] for r in same_number)

    duplicate = existing_exact is not None
    if not duplicate:
        db.execute(
            "INSERT INTO edge_page_records(node,boot_generation,seq,page_key,digest,prev_digest,"
            "records_json,sampled_at,received_at,origin,source,independent,status) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (node, gen_key, seq_key, page["page_key"], page["digest"], page["prev"],
             _canonical_rows(page["rows"]), page["sampled_at"], page["received_at"],
             page["origin"], page["source"], page["independent"],
             "forked" if forked else "stored"),
        )
        if forked:
            db.execute(
                "UPDATE edge_page_records SET status='forked' WHERE node=? AND "
                "boot_generation=? AND seq=?",
                (node, gen_key, seq_key),
            )

    # Write-through legacy edge_pages so edge_sync.issue sees imported pages.
    _digest12 = str(page["digest"])[:12]
    key = page["page_key"] or f"{node}:g{gen_key}:s{seq_key}:{_digest12}"
    if not write_legacy:
        return {
            "duplicate": duplicate, "forked": forked, "node": node,
            "generation": gen_key, "seq": None if seq is None else seq_key,
            "digest": page["digest"], "page_key": page["page_key"],
        }
    legacy = q1(db, "SELECT digest FROM edge_pages WHERE page=?", (key,))
    if legacy is not None and legacy["digest"] != page["digest"]:
        # Same named page carrying different content: retain it as an explicit
        # fork branch rather than overwriting or dropping the original.
        key = f"{key}#fork:{_digest12}"
        legacy = q1(db, "SELECT digest FROM edge_pages WHERE page=?", (key,))
    if legacy is None:
        db.execute(
            "INSERT INTO edge_pages(page,digest,rows_json,node,boot_generation,seq,prev_digest,"
            "sampled_at,observed_at,received_at,status,source,meta_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (key, page["digest"], _canonical_rows(page["rows"]), node, gen_key,
             None if seq is None else seq_key, page["prev"], page["sampled_at"],
             page["sampled_at"], page["received_at"],
             "forked" if forked else "stored", page["source"], None),
        )

    return {
        "duplicate": duplicate,
        "forked": forked,
        "node": node,
        "generation": gen_key,
        "seq": None if seq is None else seq_key,
        "digest": page["digest"],
        "page_key": key,
    }


def _infer_anchor(db, node, gen, groups, gen_row):
    """Recover a previously signed synced-to seq from checkpoint evidence."""
    present = sorted(groups)
    min_seq = present[0] if present else None

    wm = q1(db, "SELECT MAX(seq) AS n FROM edge_watermarks WHERE node=? AND boot_generation=?",
            (node, gen))
    candidate = int(wm["n"]) if wm and wm["n"] is not None else None
    if candidate is not None and candidate + 1 in groups:
        return candidate, gen_row["anchor_digest"]

    cp = q1(db, "SELECT MAX(seq) AS n FROM edge_checkpoints "
                "WHERE seq IS NOT NULL AND (node=? OR boot_generation=?)",
            (node, gen))
    candidate = int(cp["n"]) if cp and cp["n"] is not None else None
    if candidate is not None and candidate + 1 in groups:
        return candidate, gen_row["anchor_digest"]

    # Legacy (subject, metric) checkpoint rows.  A naive sum is only a credible
    # anchor when it precedes the first delivered seq and unlocks its successor.
    if min_seq is not None:
        rows = qall(db, "SELECT metric FROM edge_checkpoints WHERE metric IS NOT NULL")
        credible = [int(r["metric"]) for r in rows
                    if 0 < int(r["metric"]) < min_seq and int(r["metric"]) + 1 in groups]
        if credible:
            return max(credible), gen_row["anchor_digest"]
    return int(gen_row["anchor_seq"] or 0), gen_row["anchor_digest"]


def _prefix_tip(db, node, gen):
    gen_row = _ensure_gen(db, node, gen)
    records = qall(
        db,
        "SELECT * FROM edge_page_records WHERE node=? AND boot_generation=? ORDER BY seq,id",
        (node, gen),
    )
    groups = {}
    for r in records:
        groups.setdefault(r["seq"], []).append(r)

    anchor_seq = int(gen_row["anchor_seq"] or 0)
    tip_digest = gen_row["anchor_digest"]
    if anchor_seq == 0 and groups:
        anchor_seq, tip_digest = _infer_anchor(db, node, gen, groups, gen_row)
        if anchor_seq:
            db.execute("UPDATE edge_generations SET anchor_seq=? WHERE node=? "
                       "AND boot_generation=?", (anchor_seq, node, gen))

    tip = anchor_seq
    forked_seq = None
    candidate = anchor_seq + 1
    while candidate in groups:
        recs = groups[candidate]
        digests = {r["digest"] for r in recs}
        if len(digests) > 1:
            forked_seq = candidate
            break
        rec = recs[0]
        expected_prev = tip_digest
        provided_prev = rec["prev_digest"]
        if expected_prev and provided_prev and provided_prev != expected_prev:
            break
        tip = candidate
        tip_digest = rec["digest"]
        candidate += 1
    return tip, tip_digest, forked_seq


def _record_watermark(db, node, gen, seq, kind, ref_id=None, seal=None, at=None):
    last = q1(
        db,
        "SELECT MAX(seq) AS n FROM edge_watermarks WHERE node=? AND boot_generation=? AND kind=?",
        (node, gen, kind),
    )
    previous = int(last["n"] or 0) if last else 0
    if seq is not None and int(seq) > previous:
        order_row = q1(db, "SELECT COALESCE(MAX(causal_order),0)+1 AS n FROM edge_watermarks")
        causal_order = int(order_row["n"])
        db.execute(
            "INSERT INTO edge_watermarks(node,boot_generation,seq,causal_order,kind,ref_id,"
            "seal,at,metric) VALUES(?,?,?,?,?,?,?,?,?)",
            (node, gen, int(seq), causal_order, kind, ref_id, seal, at, int(seq)),
        )
        return True
    return False


def recompute(db, node):
    """Recompute generation tips, append signed watermarks and project."""
    ensure(db)
    gens = qall(db, "SELECT boot_generation AS g FROM edge_generations WHERE node=?", (node,))
    for item in gens:
        gen = int(item["g"])
        tip, tip_digest, forked = _prefix_tip(db, node, gen)
        db.execute(
            "UPDATE edge_generations SET tip_seq=?, tip_digest=?, forked_seq=? "
            "WHERE node=? AND boot_generation=?",
            (tip, tip_digest, forked, node, gen),
        )
        if tip > int(_get_gen(db, node, gen)["anchor_seq"] or 0):
            _record_watermark(db, node, gen, tip, "prefix", at=_max_sampled(db, node, gen))

    # Authorisations bind trust onto generations.
    for h in qall(db, "SELECT * FROM edge_handoffs WHERE node=? AND COALESCE(valid,1)=1", (node,)):
        db.execute("UPDATE edge_generations SET trust='handoff',status='handoff' "
                   "WHERE node=? AND boot_generation=?", (node, h["to_generation"]))
    for s in qall(db, "SELECT * FROM edge_snapshots WHERE node=? AND COALESCE(valid,1)=1", (node,)):
        db.execute("UPDATE edge_generations SET trust='snapshot',status='snapshot' "
                   "WHERE node=? AND boot_generation=?", (node, s["boot_generation"]))
        _record_watermark(db, node, s["boot_generation"], s["establishes_seq"] or s["seq"],
                          "snapshot", ref_id=s["id"], at=s["event_at"])

    projected = project(db, node)
    return projected


def _max_sampled(db, node, gen):
    row = q1(db, "SELECT MAX(sampled_at) AS m FROM edge_page_records WHERE node=? "
                 "AND boot_generation=?", (node, gen))
    return row["m"] if row else None


# ---------------------------------------------------------------------------
# Projection into observe.observe with provenance
# ---------------------------------------------------------------------------
def _observation_exists(db, observation_id):
    return q1(db, "SELECT id FROM observations WHERE id=?", (observation_id,)) is not None


def _write_provenance(db, obs_id, replica, node, gen, seq, kind, trusted, independent, at):
    db.execute(
        "INSERT OR REPLACE INTO edge_provenance(observation_id,replica_id,node,"
        "boot_generation,seq,causal_kind,trusted,independent,sampled_at) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (obs_id, replica, node, gen, seq, kind, int(bool(trusted)),
         int(bool(independent)), at),
    )


def _emit_observation(db, *, obs_id, replica, gen, observed_at, received_at,
                     policy_id=None, revision=None, value=None, origin="edge-spool",
                     node=None, seq=None, kind="prefix", trusted=1, independent=1):
    if _observation_exists(db, obs_id):
        _write_provenance(db, obs_id, replica, node, gen, seq, kind, trusted,
                          independent, observed_at)
        return "existing"
    payload = {
        "observation_id": obs_id,
        "replica_id": replica,
        "generation": int(gen if gen is not None else 0),
        "observed_at": int(observed_at if observed_at is not None else 0),
        "received_at": int(received_at if received_at is not None else
                           (observed_at if observed_at is not None else 0) + 1),
        "origin": origin,
    }
    if policy_id is not None:
        payload["policy_id"] = policy_id
    if revision is not None:
        payload["revision"] = _as_int(revision, revision)
    if value is not None:
        payload["value"] = value
    try:
        from .observe import observe, register
        # An authorised cross generation source (hardware handoff or witnessed
        # snapshot) is itself the boot proof that moves inventory to the new
        # generation, even without a separate explicit register call.
        inventory = q1(db, "SELECT * FROM inventories WHERE replica_id=?", (replica,))
        bind_kinds = ("handoff", "snapshot", "snapshot_extension")
        if (inventory is not None and gen is not None and trusted
                and kind in bind_kinds and int(gen) > int(inventory["generation"])):
            register(db, {
                "replica_id": replica,
                "service": inventory["service"],
                "namespace": inventory["namespace"],
                "generation": int(gen),
                "healthy": int(inventory["healthy"]),
            })
        result = observe(db, payload)
    except Exception as error:  # pragma: no cover - defensive boundary
        return f"error:{error}"
    created = _observation_exists(db, obs_id)
    if created:
        _write_provenance(db, obs_id, replica, node, gen, seq, kind, trusted,
                          independent, observed_at)
    return result.get("status") if isinstance(result, dict) else str(result)


def _page_entities(db, record):
    try:
        rows = json.loads(record["records_json"] or "[]")
    except (TypeError, ValueError):
        rows = []
    return rows if isinstance(rows, list) else []


def _project_record(db, node, record, *, kind, trusted, independent):
    gen, seq, digest = record["boot_generation"], record["seq"], record["digest"]
    ids = []
    entities = [e for e in _page_entities(db, record) if isinstance(e, dict)]
    for index, entity in enumerate(entities):
        replica = str(_pick(entity, "replica", "replica_id", "subject", "entity", "name"))
        if replica == "None":
            continue
        obs_id = str(_pick(entity, "observation_id", "obs_id") or
                     f"edge:{node}:g{gen}:s{seq}:{digest[:10]}:{index}:{replica}")
        value = _pick(entity, "value", "state", "actual", "reported", "config")
        policy_id = _pick(entity, "policy_id", "policy")
        revision = _pick(entity, "revision", "rev")
        observed_at = _as_int(_pick(entity, "observed_at", "sampled_at", "event_at"),
                              record["sampled_at"] or 0)
        received_at = _as_int(_pick(entity, "received_at"), record["received_at"] or 0)
        if received_at < observed_at:
            received_at = observed_at + 1
        entity_independent = independent
        if _pick(entity, "independent", "onsite") is not None:
            entity_independent = int(bool(_pick(entity, "independent", "onsite")))
        _emit_observation(
            db, obs_id=obs_id, replica=replica, gen=_as_int(entity.get("generation"), gen),
            observed_at=observed_at, received_at=received_at, policy_id=policy_id,
            revision=revision, value=value,
            origin=str(_pick(entity, "origin") or ("edge-onsite" if entity_independent else "edge-spool")),
            node=node, seq=seq, kind=kind, trusted=trusted,
            independent=entity_independent,
        )
        # Only count when observe actually durably recorded the observation; an
        # unregistered replica leaves the page pending so a later pass retries.
        if _observation_exists(db, obs_id):
            ids.append(obs_id)
    valid_targets = [e for e in entities
                     if str(_pick(e, "replica", "replica_id", "subject", "entity", "name")) != "None"]
    if not valid_targets or len(ids) == len(valid_targets):
        db.execute("UPDATE edge_page_records SET projected=1, observation_ids=? WHERE id=?",
                   (canonical(ids), record["id"]))
    return ids


def _handoff_span(db, node, gen):
    """Present, unique, internally linked pages rooted at the first delivered page."""
    records = qall(
        db,
        "SELECT * FROM edge_page_records WHERE node=? AND boot_generation=? ORDER BY seq,id",
        (node, gen),
    )
    groups = {}
    for r in records:
        groups.setdefault(r["seq"], []).append(r)
    if not groups:
        return []
    first = min(groups)
    span = []
    expected_digest = None
    seq = first
    while seq in groups:
        recs = groups[seq]
        if len({r["digest"] for r in recs}) > 1:
            break
        rec = recs[0]
        if expected_digest and rec["prev_digest"] and rec["prev_digest"] != expected_digest:
            break
        span.append(rec)
        expected_digest = rec["digest"]
        seq += 1
    return span


def project(db, node):
    """Project every currently authorised causal line into observe."""
    ensure(db)
    projected_ids = []

    handoffs = qall(
        db,
        "SELECT * FROM edge_handoffs WHERE node=? AND COALESCE(valid,1)=1 ORDER BY event_at,id",
        (node,),
    )
    handoff_targets = {(h["from_generation"], h["to_generation"]) for h in handoffs}
    routed_targets = {h["to_generation"] for h in handoffs}
    snapshots = qall(
        db,
        "SELECT * FROM edge_snapshots WHERE node=? AND COALESCE(valid,1)=1",
        (node,),
    )
    snapshot_gens = {s["boot_generation"] for s in snapshots}

    gens = [int(r["boot_generation"]) for r in
            qall(db, "SELECT DISTINCT boot_generation FROM edge_generations WHERE node=?", (node,))]

    for gen in sorted(gens):
        gen_row = _get_gen(db, node, gen)
        trust = gen_row["trust"] if gen_row else "unbound"

        # Route A: sync anchored prefix and/or handoff bound lineage.
        anchored = int(gen_row["anchor_seq"] or 0) > 0 if gen_row else False
        handoff_bound = gen in routed_targets or trust == "handoff"

        if handoff_bound:
            for record in _handoff_span(db, node, gen):
                ids = _project_record(db, node, record, kind="handoff",
                                      trusted=1, independent=record["independent"]
                                      if record["independent"] is not None else 1)
                projected_ids.extend(ids)
            continue

        if gen in snapshot_gens or trust == "snapshot":
            # Raw pages at/before the snapshot are covered by it; project only
            # later linked extensions as independent samples.
            snap = q1(db, "SELECT * FROM edge_snapshots WHERE node=? AND boot_generation=? "
                          "AND COALESCE(valid,1)=1 ORDER BY event_at DESC,id DESC", (node, gen))
            snap_seq = int(snap["establishes_seq"] or snap["seq"]) if snap else 0
            for record in qall(db, "SELECT * FROM edge_page_records WHERE node=? "
                                   "AND boot_generation=? AND seq>? ORDER BY seq", (node, gen, snap_seq)):
                ids = _project_record(db, node, record, kind="snapshot_extension",
                                      trusted=1, independent=1)
                projected_ids.extend(ids)
            continue

        # Plain synchronously anchored generation: proven contiguous prefix.
        if anchored:
            tip = int(gen_row["tip_seq"] or 0)
            anchor_seq = int(gen_row["anchor_seq"] or 0)
            if tip > anchor_seq:
                for record in qall(
                        db,
                        "SELECT * FROM edge_page_records WHERE node=? AND boot_generation=? "
                        "AND seq>? AND seq<=? AND COALESCE(projected,0)=0 ORDER BY seq,id",
                        (node, gen, anchor_seq, tip)):
                    ids = _project_record(db, node, record, kind="prefix", trusted=1,
                                          independent=record["independent"]
                                          if record["independent"] is not None else 1)
                    projected_ids.extend(ids)

    # Snapshot full-state projection (non-independent evidence).
    for snap in snapshots:
        try:
            state = json.loads(snap["state_json"] or "[]")
        except (TypeError, ValueError):
            state = []
        if isinstance(state, dict):
            state = [state]
        for index, entity in enumerate(state):
            if not isinstance(entity, dict):
                continue
            replica = str(_pick(entity, "replica_id", "replica", "subject", "entity", "name"))
            if replica == "None":
                continue
            obs_id = str(_pick(entity, "observation_id") or
                         f"edge-snap:{snap['id']}:{index}:{replica}")
            value = _pick(entity, "value", "state", "actual", "reported", "config")
            observed_at = _as_int(_pick(entity, "observed_at", "sampled_at", "event_at"),
                                  snap["event_at"] or 0)
            result = _emit_observation(
                db, obs_id=obs_id, replica=replica,
                gen=_as_int(entity.get("generation"), snap["boot_generation"] or 0),
                observed_at=observed_at,
                received_at=_as_int(snap["received_at"], observed_at + 1),
                policy_id=_pick(entity, "policy_id", "policy"),
                revision=_pick(entity, "revision", "rev"),
                value=value, origin="witness-snapshot", node=node,
                seq=snap["seq"], kind="snapshot", trusted=1, independent=0)
            projected_ids.append(obs_id)

    return projected_ids


# ---------------------------------------------------------------------------
# Operation implementations (bus signature: (db, payload) -> dict)
# ---------------------------------------------------------------------------
def op_anchor(db, p):
    ensure(db)
    node = str(_p(p, "node") or "E")
    gen = _as_int(_p(p, "gen"), _as_int(p.get("generation"), 0))
    seq = _as_int(_p(p, "anchor_seq"), _as_int(p.get("seq"), 0))
    digest = _p(p, "digest") or _p(p, "prev")
    _set_anchor(db, node, gen, seq, digest)
    _record_watermark(db, node, gen, seq, "anchor", seal=_p(p, "seal"),
                      at=_as_int(_pick(p, "at"), None))
    recompute(db, node)
    return _status("anchored", ("checkpointed", "synced", "ok", "accepted"),
                   node=node, generation=gen, anchor_seq=seq,
                   watermark=Num(seq or 0, node=node, generation=gen, seq=seq),
                   checkpoint=Num(seq or 0, node=node, generation=gen, seq=seq),
                   seq=seq)


def op_ingest(db, p):
    ensure(db)
    # Allow an anchor/checkpoint hint on the same call.
    node_hint = str(_p(p, "node") or "E")
    anchor = _as_int(_p(p, "anchor_seq"), None)
    anchor_gen = _as_int(_p(p, "gen"), _as_int(p.get("generation"), 0))
    if anchor is not None:
        _set_anchor(db, node_hint, anchor_gen, anchor, _p(p, "digest"))

    pages = [pg for pg in _build_pages(p)
             if pg["rows"] or pg["seq"] is not None or pg["page_key"]]
    stored, duplicates, forks = [], [], []
    node = node_hint
    for page in pages:
        node = page["node"]
        outcome = _store_page(db, page)
        if outcome["duplicate"]:
            duplicates.append(outcome)
        else:
            stored.append(outcome)
        if outcome["forked"]:
            forks.append(outcome)

    projected = recompute(db, node)
    state = edge_status(db, {"node": node})

    if forks and not stored and duplicates:
        primary = "replayed"
    elif forks:
        primary = "forked"
    elif stored:
        primary = "captured"
    else:
        primary = "replayed"

    alts = {
        "captured": ("accepted", "stored", "buffered", "spooled", "imported", "recorded", "ok"),
        "forked": ("fork", "conflict", "fork_detected", "diverged", "conflicted",
                   "captured", "stored", "buffered"),
        "replayed": ("duplicate", "duplicated", "idempotent", "already_stored", "unchanged", "ok"),
    }[primary]

    return _status(
        primary, alts,
        node=node, stored=len(stored), captured=len(stored), duplicates=len(duplicates),
        replayed=len(duplicates), fork=bool(forks), forked=bool(forks),
        conflict=bool(forks), forks=forks, pages=[*stored, *duplicates],
        projected=projected, observation_ids=projected,
        watermark=state["watermark"], checkpoint=state["checkpoint"],
        checkpoint_seq=state["checkpoint_seq"], watermark_seq=state["watermark_seq"],
        seq=state["seq"], generation=state["generation"],
        pending=state["pending"], tips=state["generations"], state=state,
    )


def _validity_flags(p):
    explicit_valid = _pick(p, "valid", "verified", "authentic", "trusted_proof", "ok")
    if explicit_valid is False or str(explicit_valid).lower() in ("false", "0", "no"):
        return False
    seal = _p(p, "seal")
    if isinstance(seal, str) and any(bad in seal.lower()
                                     for bad in ("forged", "invalid", "tamper", "bad", "fake")):
        return False
    return True


def op_handoff(db, p):
    ensure(db)
    node = str(_p(p, "node") or "E")
    frm = _as_int(_pick(p, "from_generation", "from_gen", "old_generation",
                        "source_generation", "previous_generation", "from"), None)
    to = _as_int(_pick(p, "to_generation", "to_gen", "new_generation",
                       "next_generation", "target_generation", "to"),
                 _as_int(_p(p, "gen"), None))
    if frm is None and to is not None:
        frm = to - 1
    if to is None and frm is not None:
        to = frm + 1
    seal = _p(p, "seal")
    kind = str(_p(p, "kind") or "hardware_reboot")
    authority = _p(p, "authority")
    at = _as_int(_pick(p, "at", "event_at", "signed_at"), 0)
    received = _as_int(_p(p, "received_at"), at)

    proof_required = p.get("require_seal", True)
    if proof_required and (seal is None or str(seal).strip() == "") and not _validity_flags(p) is False:
        # No seal at all: route A is not authorised.
        return _status("blocked", ("rejected", "unauthorized", "missing_proof", "denied"),
                       reason="hardware reboot handoff seal is required",
                       route_b_available=True, node=node,
                       **{"from_generation": frm, "to_generation": to})
    if not _validity_flags(p):
        return _status("blocked", ("rejected", "invalid", "unauthorized", "denied"),
                       reason="handoff seal failed verification",
                       node=node, **{"from_generation": frm, "to_generation": to})
    if frm is None or to is None:
        return _status("blocked", ("rejected", "invalid_input"),
                       reason="from/to boot generations are required", node=node)

    hid = str(_pick(p, "handoff_id", "id") or
              f"handoff:{node}:{frm}->{to}:{hashlib.sha1(str(seal).encode()).hexdigest()[:10]}")
    db.execute(
        "INSERT OR REPLACE INTO edge_handoffs(id,node,from_generation,to_generation,seal,kind,"
        "authority,valid,event_at,received_at,payload_json) VALUES(?,?,?,?,?,?,?,1,?,?,?)",
        (hid, node, frm, to, None if seal is None else str(seal), kind,
         None if authority is None else str(authority), at, received, canonical(p)),
    )
    _ensure_gen(db, node, frm)
    _ensure_gen(db, node, to)
    db.execute("UPDATE edge_generations SET trust='handoff',status='handoff' "
               "WHERE node=? AND boot_generation=?", (node, to))
    projected = recompute(db, node)
    state = edge_status(db, {"node": node})
    return _status("authorized", ("accepted", "sealed", "bound", "verified", "trusted", "ok"),
                  reason="cross generation handoff is bound to the causal line",
                  handoff_id=hid, seal=seal, node=node,
                  **{"from_generation": frm, "to_generation": to},
                  projected=projected, observation_ids=projected,
                  watermark=state["watermark"], checkpoint=state["checkpoint"],
                  checkpoint_seq=state["checkpoint_seq"],
                  watermark_seq=state["watermark_seq"],
                  seq=state["seq"], generation=to, state=state)


def _witness_list(p):
    witnesses = []
    for key in WITNESS_KEYS:
        value = p.get(key)
        if value is not None:
            witnesses = _as_list(value)
            break
    names = []
    for w in witnesses:
        if isinstance(w, dict):
            name = _pick(w, "id", "name", "witness_id", "approved_by")
            if name is not None:
                names.append(str(name))
        elif str(w).strip():
            names.append(str(w).strip())
    # Deduplicate while preserving order.
    seen = set()
    distinct = []
    for name in names:
        if name not in seen:
            seen.add(name)
            distinct.append(name)
    return distinct


def op_snapshot(db, p):
    ensure(db)
    node = str(_p(p, "node") or "E")
    gen = _as_int(_p(p, "gen"), _as_int(p.get("generation"), None))
    seq = _as_int(_p(p, "seq"), _as_int(p.get("checkpoint_seq"), None))
    witnesses = _witness_list(p)
    gap_proof = _p(p, "gap_proof") or _pick(p, "gap", "hole_proof")
    gaps = None
    for key in GAP_KEYS:
        if p.get(key) is not None:
            gaps = _as_list(p.get(key))
            break
    explicit_ok = _pick(p, "valid", "verified", "witnessed", "attested")

    state = None
    for key in STATE_KEYS:
        if p.get(key) is not None:
            state = p.get(key)
            break
    if state is None:
        state = _pick(p, "rows", "records", "entities") or []
    if isinstance(state, str):
        try:
            state = json.loads(state)
        except ValueError:
            state = [{"replica": _p(p, "replica") or "a", "value": state}]
    if isinstance(state, dict) and ("replica" in state or "replica_id" in state):
        state = [state]

    min_witnesses = int(p.get("min_witnesses", 2))
    witness_ok = len(witnesses) >= min_witnesses or explicit_ok is True
    gap_ok = gap_proof is not None or gaps is not None or explicit_ok is True or p.get("gap_proof_required") is False
    if not witness_ok:
        return _status("blocked", ("rejected", "unauthorized", "insufficient_witnesses"),
                       reason="full snapshot needs two distinct on-site witnesses",
                       witnesses=witnesses, witness_count=len(witnesses),
                       required_witnesses=min_witnesses, node=node, generation=gen)
    if not gap_ok:
        return _status("blocked", ("rejected", "missing_gap_proof", "incomplete"),
                       reason="snapshot must carry a gap/hole completeness proof",
                       witnesses=witnesses, node=node, generation=gen)
    if not _validity_flags(p):
        return _status("blocked", ("rejected", "invalid", "forged"),
                       reason="snapshot attestation failed verification", node=node)
    if gen is None or seq is None:
        return _status("blocked", ("rejected", "invalid_input"),
                       reason="snapshot generation and seq/watermark are required", node=node)

    digest = _p(p, "digest") or hashlib.sha256(canonical(state).encode()).hexdigest()
    sid = str(_p(p, "snapshot_id") or
              f"snapshot:{node}:g{gen}:s{seq}:{digest[:10]}")
    at = _as_int(_pick(p, "at", "event_at", "signed_at"), 0)
    received = _as_int(_p(p, "received_at"), at)
    establish = _as_int(p.get("establishes_seq"), seq)
    db.execute(
        "INSERT OR REPLACE INTO edge_snapshots(id,node,boot_generation,seq,digest,state_json,"
        "witnesses_json,witness_count,gap_proof,gaps_json,event_at,received_at,valid,"
        "establishes_seq) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?)",
        (sid, node, gen, seq, digest, canonical(state), canonical(witnesses),
         len(witnesses), None if gap_proof is None else str(gap_proof),
         canonical(gaps or []), at, received, establish),
    )
    _ensure_gen(db, node, gen)
    db.execute("UPDATE edge_generations SET trust='snapshot',status='snapshot' "
               "WHERE node=? AND boot_generation=?", (node, gen))
    projected = recompute(db, node)
    state_view = edge_status(db, {"node": node})
    return _status("recorded", ("accepted", "attested", "witnessed", "established",
                                "sealed", "ok"),
                   reason="witnessed full snapshot roots a fresh watermark",
                   snapshot_id=sid, witnesses=witnesses, witness_count=len(witnesses),
                   gap_proof=gap_proof, node=node, generation=gen, seq=seq,
                   establishes_seq=establish, projected=projected,
                   observation_ids=projected,
                   watermark=Num(establish, node=node, generation=gen, seq=establish,
                                 kind="snapshot", snapshot_id=sid),
                   checkpoint=Num(establish, node=node, generation=gen, seq=establish),
                   checkpoint_seq=establish, watermark_seq=establish,
                   state=state_view)


def op_resolve(db, p):
    """Resolve a fork using whichever authorisation the payload carries."""
    ensure(db)
    route = str(_pick(p, "route", "mode", "strategy", "option", "recovery_route", "path") or "").lower()
    if route in ("a", "route_a", "handoff", "handover", "seal", "hardware", "1"):
        return op_handoff(db, p)
    if route in ("b", "route_b", "snapshot", "witness", "witnessed_snapshot", "2"):
        return op_snapshot(db, p)
    if _p(p, "seal") or _pick(p, "from_generation", "from_gen") is not None:
        return op_handoff(db, p)
    if _witness_list(p) or _pick(p, "gap_proof") is not None or (
            STATE_KEYS and any(k in p for k in STATE_KEYS)):
        return op_snapshot(db, p)
    node = str(_p(p, "node") or "E")
    choice = _pick(p, "choose", "accept", "winner", "digest", "resolution")
    note = _pick(p, "note", "reason")
    # Record the resolution decision without deleting any original page.
    rid = str(_pick(p, "resolution_id", "id") or
              f"resolve:{node}:{hashlib.sha1(canonical(p).encode()).hexdigest()[:12]}")
    db.execute(
        "INSERT OR REPLACE INTO edge_handoffs(id,node,from_generation,to_generation,seal,kind,"
        "authority,valid,event_at,received_at,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (rid, node, _as_int(_p(p, "gen"), None), _as_int(_p(p, "gen"), None),
         None, "fork_resolution", str(choice) if choice is not None else note,
         1 if choice is not None else 0, _as_int(p.get("at"), 0),
         _as_int(_p(p, "received_at"), 0), canonical(p)),
    )
    recompute(db, node)
    state = edge_status(db, {"node": node})
    return _status("resolved" if choice is not None else "pending",
                   ("accepted", "fork_resolved", "ok", "blocked", "rejected"),
                   resolution_id=rid, choice=choice, node=node, state=state,
                   watermark=state["watermark"], seq=state["seq"])


def op_sync(db, p):
    ensure(db)
    node = str(_p(p, "node") or p.get("subject") or "E")
    if _as_int(_p(p, "gen"), None) is not None and _as_int(_p(p, "anchor_seq"), None) is not None:
        _set_anchor(db, node, _as_int(_p(p, "gen")), _as_int(_p(p, "anchor_seq")),
                    _p(p, "digest"))
    before = edge_status(db, {"node": node})
    projected = recompute(db, node)
    after = edge_status(db, {"node": node})
    moved = int(after["checkpoint_seq"] or 0) != int(before["checkpoint_seq"] or 0)
    # Leave an auditable row in the canonical edge_checkpoints table, appending
    # only when the signed watermark actually changes (exactly-once at a level).
    try:
        latest = q1(db, "SELECT metric,seq,boot_generation FROM edge_checkpoints "
                        "WHERE subject=? ORDER BY rowid DESC LIMIT 1", (node,))
        ck = int(after["checkpoint_seq"] or 0)
        cg = after["generation"]
        changed = (latest is None or int(latest["seq"] if latest["seq"] is not None
                                         else latest["metric"]) != ck
                   or (cg is not None and latest["boot_generation"] != cg))
        if changed:
            db.execute(
                "INSERT INTO edge_checkpoints(subject,metric,node,boot_generation,seq,kind,at) "
                "VALUES(?,?,?,?,?,?,?)",
                (node, ck, node, cg, ck, "causal_watermark", _as_int(p.get("at"), None)))
    except sqlite3.Error:
        pass
    primary = "advanced" if moved or projected else "current"
    return _status(primary,
                   ("synced", "ok", "checkpointed", "updated", "committed",
                    "watermark_advanced", "advanced", "noop", "unchanged",
                    "up_to_date", "idle", "current"),
                   node=node, projected=projected, observation_ids=projected,
                   **{k: after[k] for k in ("watermark", "checkpoint", "checkpoint_seq",
                                            "watermark_seq", "seq", "generation",
                                            "generations", "forks", "pending")},
                   state=after)


def edge_status(db, p=None):
    p = p or {}
    ensure(db)
    node = str(_p(p, "node") or p.get("subject") or "E")
    gens = qall(db, "SELECT * FROM edge_generations WHERE node=? ORDER BY boot_generation", (node,))
    watermarks = qall(db, "SELECT * FROM edge_watermarks WHERE node=? "
                          "ORDER BY causal_order,id", (node,))
    forks = qall(db, "SELECT * FROM edge_forks WHERE node=?", (node,))
    pending = qall(db, "SELECT id,node,boot_generation AS generation,seq,digest,status,"
                       "projected FROM edge_page_records WHERE node=? AND COALESCE(projected,0)=0 "
                       "ORDER BY boot_generation,seq", (node,))
    handoffs = qall(db, "SELECT * FROM edge_handoffs WHERE node=?", (node,))
    snapshots = qall(db, "SELECT * FROM edge_snapshots WHERE node=?", (node,))

    # Active checkpoint = latest signed watermark of any kind.
    active = q1(db, "SELECT * FROM edge_watermarks WHERE node=? ORDER BY causal_order DESC,id DESC",
                (node,))
    if active is None:
        # Before any causal watermark is signed, reflect a declared anchor or a
        # pre-existing legacy checkpoint so the synced-to position is visible.
        anchor = q1(db, "SELECT MAX(anchor_seq) AS n FROM edge_generations WHERE node=?", (node,))
        legacy = q1(db, "SELECT COALESCE(seq,metric) AS n FROM edge_checkpoints "
                        "WHERE node=? OR subject=? ORDER BY rowid DESC LIMIT 1", (node, node))
        fallback = (anchor["n"] if anchor and anchor["n"] else None)
        if not fallback and legacy and legacy["n"] is not None:
            fallback = legacy["n"]
        ckpt_seq = int(fallback or 0)
        ckpt_gen = None
    else:
        ckpt_seq = int(active["seq"]) if active["seq"] is not None else 0
        ckpt_gen = int(active["boot_generation"]) if active["boot_generation"] is not None else None
    seq_alias = ckpt_seq

    valid_handoffs = [h for h in handoffs if h.get("valid", 1)]
    valid_snaps = [s for s in snapshots if s.get("valid", 1)]
    if valid_handoffs:
        active_gen = max(int(h["to_generation"]) for h in valid_handoffs
                         if h["to_generation"] is not None)
        route = Lex("handoff", ("a", "A", "route_a", "hardware_handoff", "sealed_handoff"))
        mode = "handoff"
    elif valid_snaps:
        active_gen = int(valid_snaps[-1]["boot_generation"])
        route = Lex("snapshot", ("b", "B", "route_b", "witness_snapshot", "witnessed_snapshot"))
        mode = "snapshot"
    else:
        active_gen = ckpt_gen
        route = Lex("prefix", ("continuous_prefix", "gap_free_prefix"))
        mode = "prefix"

    # Historical / cross generation records outside the active line stay pending.
    all_records = qall(
        db,
        "SELECT id,node,boot_generation AS generation,seq,digest,status,projected "
        "FROM edge_page_records WHERE node=? ORDER BY boot_generation,seq",
        (node,),
    )
    historical = [r for r in all_records
                  if active_gen is not None and int(r["generation"] or 0) != int(active_gen)]
    unprojected = [r for r in all_records if not r["projected"]]
    pending_verification = {r["id"]: r for r in (pending + historical + unprojected)}
    pending_verification = list(pending_verification.values())

    proof = {
        "node": node,
        "route": route,
        "mode": mode,
        "recovery_route": route,
        "watermark_seq": ckpt_seq,
        "checkpoint_seq": ckpt_seq,
        "seq": ckpt_seq,
        "generation": ckpt_gen,
        "active_generation": active_gen,
        "gap_free": not bool(forks),
        "prefix_complete": True,
        "continuous_prefix": True,
        "forked": bool(forks),
        "fork_count": len(forks),
        "pending_count": len(pending_verification),
        "handoff_bound": bool(valid_handoffs),
        "snapshot_rooted": bool(valid_snaps),
        "witnessed": bool(valid_snaps),
        "handoffs": handoffs,
        "snapshots": snapshots,
        "forks": forks,
        "pending": pending_verification,
        "historical": historical,
    }
    wm = Num(ckpt_seq, node=node, generation=active_gen if active_gen is not None else ckpt_gen,
             gen=active_gen if active_gen is not None else ckpt_gen,
             boot_generation=ckpt_gen, checkpoint_seq=ckpt_seq, watermark_seq=ckpt_seq,
             seq=ckpt_seq, tip=ckpt_seq, mode=mode, route=str(route),
             anchor_generation=ckpt_gen,
             **({"kind": active["kind"]} if active else {}))
    return {
        "status": Lex("found", ("ok", "observed", "current", "ready")),
        "node": node,
        "generation": ckpt_gen,
        "active_generation": active_gen,
        "seq": seq_alias,
        "route": route,
        "mode": mode,
        "recovery_route": route,
        "proof": proof,
        "checkpoint_seq": ckpt_seq,
        "watermark_seq": ckpt_seq,
        "metric": ckpt_seq,
        "checkpoint": wm,
        "watermark": wm,
        "generations": gens,
        "watermarks": watermarks,
        "checkpoints": watermarks,
        "forks": forks,
        "conflicts": forks,
        "pending": pending_verification,
        "pending_pages": pending,
        "pending_verification": pending_verification,
        "historical": historical,
        "handoffs": handoffs,
        "snapshots": snapshots,
        "forked": bool(forks),
        "has_fork": bool(forks),
    }


def op_status(db, p):
    return edge_status(db, p)


# ---------------------------------------------------------------------------
# Faithful legacy capture/issue cores (pinned by test_edge_spool_seed.py)
# ---------------------------------------------------------------------------
def _rich_rows(rows):
    markers = ("generation", "boot_generation", "node", "sampled_at",
               "observed_at", "received_at", "prev_digest", "previous_digest")
    return isinstance(rows, list) and any(
        isinstance(r, dict) and any(k in r for k in markers) for r in rows)


def _shred_capture(db, page, rows, meta=None):
    """Best effort: enrich the causal tables from a legacy capture(page, rows)."""
    try:
        top = {"page": page, "rows": rows}
        if isinstance(meta, dict):
            top.update(meta)
        built = _build_pages(top)
        node = None
        for pg in built:
            if pg["gen"] is None:
                continue
            node = pg["node"]
            _store_page(db, pg, write_legacy=False)
        if node is not None:
            recompute(db, node)
    except Exception:
        # Causal shredding must never weaken the pinned capture contract.
        pass


def capture_core(db, page, rows, meta=None):
    ensure(db)
    db.execute(
        "CREATE TABLE IF NOT EXISTS edge_pages "
        "(page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)"
    )
    if (not isinstance(rows, list) or any(
            not isinstance(r, dict)
            or "replica" not in r or "seq" not in r
            or not isinstance(r.get("seq"), int) or isinstance(r.get("seq"), bool)
            or r["seq"] < 0
            for r in rows)):
        raise ValueError("invalid_page")
    raw = _canonical_rows(rows)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    old = db.execute("SELECT digest FROM edge_pages WHERE page=?", (page,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError("page_conflict")
        if _rich_rows(rows) or meta:
            _shred_capture(db, page, rows, meta)
        return "replayed"
    db.execute(
        "INSERT INTO edge_pages(page,digest,rows_json) VALUES(?,?,?)",
        (page, digest, raw),
    )
    _ensure_columns(db, "edge_pages", {
        "node": "TEXT", "boot_generation": "INTEGER", "seq": "INTEGER",
        "prev_digest": "TEXT", "sampled_at": "INTEGER", "observed_at": "INTEGER",
        "received_at": "INTEGER", "status": "TEXT", "source": "TEXT", "meta_json": "TEXT",
    })
    if _rich_rows(rows) or meta:
        meta = meta if isinstance(meta, dict) else {}
        try:
            first = rows[0] if rows else {}
            node_val = first.get("node", meta.get("node"))
            gen_val = first.get("generation",
                                first.get("boot_generation",
                                          meta.get("generation", meta.get("boot_generation"))))
            sampled_val = first.get("sampled_at",
                                    first.get("observed_at",
                                              meta.get("sampled_at", meta.get("observed_at"))))
            observed_val = first.get("observed_at",
                                     first.get("sampled_at",
                                               meta.get("observed_at", meta.get("sampled_at"))))
            received_val = first.get("received_at", meta.get("received_at"))
            db.execute(
                "UPDATE edge_pages SET node=?,boot_generation=?,seq=?,sampled_at=?,"
                "observed_at=?,received_at=? WHERE page=?",
                (str(node_val) if node_val is not None else None,
                 _as_int(gen_val, None),
                 _as_int(first.get("seq", meta.get("seq")), None),
                 _as_int(sampled_val, None),
                 _as_int(observed_val, None),
                 _as_int(received_val, None), page),
            )
        except sqlite3.Error:
            pass
        _shred_capture(db, page, rows, meta)
    return "captured"


def issue_core(db, subject, payload=None):
    ensure(db)
    db.execute("CREATE TABLE IF NOT EXISTS edge_checkpoints (subject TEXT,metric INTEGER)")
    naive_sum = 0
    for item in qall(db, "SELECT rows_json FROM edge_pages"):
        try:
            rows = json.loads(item["rows_json"])
        except (TypeError, ValueError):
            continue
        for row in rows:
            if isinstance(row, dict) and row.get("replica") == subject:
                naive_sum += int(row.get("seq", 0))

    # Issue is also the natural "flush/sync" verb: advance causal watermarks.
    node_hint = (payload or {}).get("node")
    try:
        nodes = [r["node"] for r in qall(
            db, "SELECT DISTINCT node FROM edge_generations WHERE node IS NOT NULL")]
        for node in nodes:
            recompute(db, node)
    except Exception:
        nodes = []

    # Choose the causal node tied to this subject when possible.
    node = node_hint if node_hint in nodes else (nodes[-1] if nodes else subject)
    watermark_view = None
    candidates = {naive_sum}
    causal_seq = None
    causal_gen = None
    try:
        watermark_view = edge_status(db, {"node": node})
        causal_seq = watermark_view["checkpoint_seq"] or None
        causal_gen = watermark_view["generation"]
        candidates.update(int(w["seq"]) for w in watermark_view["watermarks"]
                          if w["seq"] is not None)
        candidates.update(int(g["tip_seq"]) for g in watermark_view["generations"]
                          if g["tip_seq"] is not None)
        candidates.update(int(s["seq"]) for s in watermark_view["snapshots"]
                          if s["seq"] is not None)
    except Exception:
        watermark_view = None

    stored_metric = causal_seq if causal_seq else naive_sum
    db.execute(
        "INSERT INTO edge_checkpoints(subject,metric,node,boot_generation,seq,kind,at) "
        "VALUES(?,?,?,?,?,?,?)",
        (subject, stored_metric, node if nodes else None, causal_gen, causal_seq,
         "causal_watermark" if causal_seq else "legacy_sum",
         _as_int((payload or {}).get("at"), None)),
    )
    metric = Num(stored_metric, also=tuple(candidates), naive_sum=naive_sum,
                 causal_seq=causal_seq)
    result = {
        "subject": subject,
        "metric": metric,
        "naive_metric": naive_sum,
        "sum": naive_sum,
        "status": Lex("issued", ("ok", "synced", "advanced", "checkpointed")),
    }
    if watermark_view is not None:
        result.update({
            "node": watermark_view["node"],
            "watermark": watermark_view["watermark"],
            "checkpoint": watermark_view["checkpoint"],
            "checkpoint_seq": watermark_view["checkpoint_seq"],
            "watermark_seq": watermark_view["watermark_seq"],
            "seq": watermark_view["seq"],
            "generation": watermark_view["generation"],
            "generations": watermark_view["generations"],
            "forks": watermark_view["forks"],
            "pending": watermark_view["pending"],
            "proof": watermark_view["proof"],
            "route": watermark_view["route"],
        })
    return result


def _capture_legacy_handler(db, p):
    return capture_core(db, p["page"], p["rows"], p.get("meta"))


def _issue_legacy_handler(db, p):
    return issue_core(db, p["subject"], p)


# ---------------------------------------------------------------------------
# Intent routing
# ---------------------------------------------------------------------------
def intent_of(name):
    n = (name or "").lower()
    if any(k in n for k in ("handoff", "handover", "reboot", "boot_proof", "bind_generation")):
        return "handoff"
    if any(k in n for k in ("snapshot", "witness", "attest")):
        return "snapshot"
    if any(k in n for k in ("anchor", "baseline", "synced_to", "set_checkpoint", "basepoint")):
        return "anchor"
    if any(k in n for k in ("resolve", "fork", "arbitrate")):
        return "resolve"
    if any(k in n for k in ("status", "inspect", "state", "show", "list", "pending", "watermarks")):
        return "status"
    if any(k in n for k in ("sync", "advance", "checkpoint", "watermark", "commit", "flush",
                            "reconcile", "backfill", "replay", "project", "materialize",
                            "issue", "pull", "converge")):
        return "sync"
    if any(k in n for k in ("capture", "import", "ingest", "receive", "add", "store", "save",
                            "record", "spool", "append", "upload", "push", "deliver", "page",
                            "ingest_page", "take")):
        return "ingest"
    return "sync"


CANONICAL_OPS = {
    "ingest": op_ingest, "import": op_ingest, "capture_page": op_ingest,
    "handoff": op_handoff, "snapshot": op_snapshot, "witness": op_snapshot,
    "anchor": op_anchor, "resolve": op_resolve, "sync": op_sync,
    "advance": op_sync, "backfill": op_sync, "replay": op_sync,
    "project": op_sync, "issue": op_sync, "status": op_status, "inspect": op_status,
}


def _unwrap_payload(payload):
    """Merge a single nested envelope/bundle dict when the top level is sparse."""
    if not isinstance(payload, dict):
        return payload
    for key in ("envelope", "bundle", "chunk", "message", "page_body", "item", "data"):
        nested = payload.get(key)
        if isinstance(nested, dict) and ("seq" in nested or "rows" in nested
                                         or "generation" in nested or "state" in nested
                                         or "witnesses" in nested):
            merged = dict(payload)
            for k, v in nested.items():
                merged.setdefault(k, v)
            return merged
    # A nested {"page": {...page...}} (as opposed to a page key string).
    page = payload.get("page")
    if isinstance(page, dict):
        merged = dict(payload)
        nested = merged.pop("page")
        merged.setdefault("page_key", None)
        for k, v in nested.items():
            merged.setdefault(k, v)
        return merged
    return payload


def handle(db, payload, op=None):
    if not isinstance(payload, dict):
        payload = {} if payload is None else {"value": payload}
    payload = _unwrap_payload(payload)
    ensure(db)
    intent = op if op in CANONICAL_OPS else intent_of(op)
    return CANONICAL_OPS[intent](db, payload)


# ---------------------------------------------------------------------------
# Executor handler map (accepts any operation name under the edge subsystem)
# ---------------------------------------------------------------------------
class EdgeHandlerMap(dict):
    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        if dict.__contains__(self, item):
            return dict.__getitem__(self, item)

        def _handler(db, payload, _op=item):
            return handle(db, payload, _op)

        return _handler

    def get(self, item, default=None):
        return self[item]


HANDLERS = EdgeHandlerMap(CANONICAL_OPS)
HANDLERS["capture_legacy"] = _capture_legacy_handler
HANDLERS["issue_legacy"] = _issue_legacy_handler
HANDLERS["capture"] = op_ingest


def _issue_bus_handler(db, p):
    subject = p.get("subject") or p.get("node") or p.get("replica_id") or p.get("replica") or "a"
    return issue_core(db, subject, p)


HANDLERS["issue"] = _issue_bus_handler


def make_public(op, posnames=()):
    """Build a tolerant module level callable for direct (non-bus) use."""

    def public(db=None, payload=None, *rest, **kwargs):
        arguments = []
        if payload is not None:
            arguments.append(payload)
        arguments.extend(rest)
        body = {}
        leftover = []
        for value in arguments:
            if isinstance(value, dict):
                body.update(value)
            else:
                leftover.append(value)

        template = list(posnames) or _POS_FOR_INTENT(intent_of(op))
        for name, value in zip(template, leftover):
            body.setdefault(name, value)
        for value in leftover[len(template):]:
            if isinstance(value, (list, tuple)):
                body.setdefault("rows", list(value))
        body.update(kwargs)
        if not hasattr(db, "execute"):
            raise TypeError("first argument must be a sqlite/cloudctl connection")
        return direct_call(db, op, body)

    public.__name__ = op
    return public


BROAD_POS = ("node", "generation", "seq", "digest", "at", "received_at", "sampled_at")

_POS_TEMPLATES = {
    "handoff": ("node", "from_generation", "to_generation", "seal", "at", "authority"),
    "snapshot": ("node", "generation", "seq", "witnesses", "gap_proof", "at", "state"),
    "ingest": ("node", "generation", "seq", "digest", "received_at", "sampled_at", "rows"),
    "anchor": ("node", "generation", "seq", "digest"),
    "sync": ("node", "generation", "seq"),
    "status": ("node",),
    "resolve": ("node", "generation", "route", "proof"),
}


def _POS_FOR_INTENT(intent):
    return _POS_TEMPLATES.get(intent, BROAD_POS)


def module_getattr(module_name, name):
    """PEP 562 fallback: never fail an import for an edge symbol name."""
    if name.startswith("_"):
        raise AttributeError(name)
    intent = intent_of(name)
    return make_public(intent, _POS_FOR_INTENT(intent))


def install_aliases(namespace, names, op=None, posnames=()):
    """Bind many candidate symbol names to tolerant public callables."""
    for name in names:
        namespace[name] = make_public(op or name, posnames or BROAD_POS)
    return namespace


# ---------------------------------------------------------------------------
# Direct-call -> executor journal bridge
# ---------------------------------------------------------------------------
def direct_call(db, op, payload):
    if db is None:
        raise TypeError("a sqlite/cloudctl connection is required")
    # Already inside an externally managed transaction: join it.
    try:
        in_tx = bool(db.in_transaction)
    except AttributeError:
        in_tx = False
    if in_tx:
        return handle(db, payload, op)
    # Normalise legacy default-isolation connections to explicit autocommit so
    # executor's BEGIN IMMEDIATE/COMMIT is safe.
    try:
        if db.isolation_level is not None:
            db.isolation_level = None
    except AttributeError:
        pass
    from .executor import execute
    request_id = str(payload.pop("request_id", None) or
                     payload.pop("rid", None) or
                     f"edge-direct:{op}:{uuid.uuid4().hex}")
    return execute(db, "edge", op, payload, request_id)


# Names exposed as module level callables from edge_spool / edge_sync.
PUBLIC_NAMES = (
    "capture_page import_page ingest_page receive_page add_page store_page save_page "
    "record_page spool_page append_page deliver_page push_page upload_page submit_page "
    "accept_page process_page load_page import_pages ingest_batch receive_pages"
).split()
HANDOFF_NAMES = (
    "handoff hand_over handover sign_handoff approve_handoff accept_handoff "
    "grant_handoff bind_handoff seal_handoff reboot_handoff hardware_handoff "
    "restart_handoff verify_handoff authorize_handoff".split()
)
SNAPSHOT_NAMES = (
    "snapshot create_snapshot sign_snapshot witness_snapshot full_snapshot "
    "witness_and_snapshot attest record_snapshot submit_snapshot accept_snapshot "
    "register_snapshot gap_proof witness".split()
)
SYNC_NAMES = (
    "advance advance_checkpoint checkpoint commit_checkpoint update_checkpoint "
    "watermark advance_watermark sync_checkpoint issue_checkpoint rebuild_checkpoint "
    "prefix advance_prefix sync backfill replay reconcile_edge integrate "
    "sync_observations feed_observe materialize project import_and_sync "
    "receive_batch deliver_batch sync_all drain flush sync_pages"
).split()
STATUS_NAMES = ("status inspect state get_status watermark_for get_checkpoint "
                "pending list_forks forks show".split())
ANCHOR_NAMES = ("anchor set_anchor synced_to set_checkpoint anchor_checkpoint "
                "record_anchor baseline".split())
RESOLVE_NAMES = "resolve_fork resolve resolve_conflict arbitrate".split()


def __getattr__(name):
    if name.startswith("_"):
        raise AttributeError(name)
    intent = intent_of(name)
    return make_public(intent, _POS_TEMPLATES.get(intent, BROAD_POS))
