"""Reviewable time-window sealing, late-evidence appendices and selective disclosure.

A seal fixes the *causal closure* of the events whose business time lies in
[start, end) for one service: window events plus the minimal pre-window events
they causally depend on (drafts, plans, dispatches ...).  The event prefix
known at signing time is recorded explicitly, so an event sampled inside the
window but received after sealing can never rewrite the original seal; it is
bound into a separate appendix volume instead.

Everything is committed to Merkle manifests keyed by stable leaf keys, so the
externally verifiable root depends only on (key, digest) pairs and survives
redaction, leaf archiving and later compression.
"""

import hashlib
import hmac
import json
import secrets

from .db import canonical, transaction
from . import merkle

SCHEMA = """
CREATE TABLE IF NOT EXISTS seal_registry (
  seal_id TEXT PRIMARY KEY, service TEXT NOT NULL,
  start_at INTEGER NOT NULL, end_at INTEGER NOT NULL, signed_at INTEGER NOT NULL,
  prefix_event_id INTEGER NOT NULL, window_event_ids TEXT NOT NULL,
  prereq_event_ids TEXT NOT NULL, page_names TEXT NOT NULL,
  manifest_json TEXT NOT NULL, root TEXT NOT NULL, seq INTEGER NOT NULL,
  UNIQUE(service, start_at, end_at)
);
CREATE TABLE IF NOT EXISTS seal_leaves (
  seal_id TEXT NOT NULL, leaf_key TEXT PRIMARY KEY,
  kind TEXT NOT NULL, ref TEXT NOT NULL, content_json TEXT,
  digest TEXT NOT NULL, in_window INTEGER NOT NULL, sort_index INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS seal_attachments (
  attachment_id TEXT PRIMARY KEY, seal_id TEXT NOT NULL, seq INTEGER NOT NULL,
  attached_at INTEGER NOT NULL, prefix_event_id INTEGER NOT NULL,
  event_ids TEXT NOT NULL, anchor_key TEXT NOT NULL,
  manifest_json TEXT NOT NULL, root TEXT NOT NULL, UNIQUE(seal_id, seq)
);
CREATE TABLE IF NOT EXISTS seal_attachment_leaves (
  attachment_id TEXT NOT NULL, leaf_key TEXT NOT NULL,
  kind TEXT NOT NULL, ref TEXT NOT NULL, content_json TEXT, digest TEXT NOT NULL,
  PRIMARY KEY(attachment_id, leaf_key)
);
CREATE TABLE IF NOT EXISTS seal_keys (
  key_id TEXT PRIMARY KEY, secret_hex TEXT NOT NULL, role TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', revoked_at INTEGER, reason TEXT
);
CREATE TABLE IF NOT EXISTS seal_certificates (
  certificate_id TEXT PRIMARY KEY, seal_id TEXT NOT NULL, audience TEXT NOT NULL,
  role TEXT NOT NULL, attachment_ids TEXT NOT NULL, bundle_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS seal_credentials (
  credential_id TEXT PRIMARY KEY, seal_id TEXT NOT NULL, audience TEXT,
  kind TEXT NOT NULL, bundle_json TEXT NOT NULL, issued_at INTEGER NOT NULL,
  revoked_key_id TEXT
);
"""


def initialize(db):
    db.executescript(SCHEMA)


# --------------------------------------------------------------------------
# Event interpretation: business time, service ownership, causal references
# --------------------------------------------------------------------------

def _load_events(db, prefix_id=None):
    sql = "SELECT * FROM events ORDER BY id"
    if prefix_id is not None:
        sql += f" LIMIT {int(prefix_id)}"
    out = []
    for row in db.execute(sql):
        item = dict(row)
        item["input"] = json.loads(item["input_json"])
        item["result"] = json.loads(item["result_json"])
        out.append(item)
    return out


def _event_service(db, event):
    kind, payload = event["kind"], event["input"]
    if "service" in payload:
        return str(payload["service"])
    if kind.startswith("policy.") and "policy_id" in payload:
        row = db.execute("SELECT scope FROM policies WHERE id=?", (payload["policy_id"],)).fetchone()
        if row:
            return row[0]
    if "replica_id" in payload:
        row = db.execute("SELECT service FROM inventories WHERE replica_id=?",
                         (payload["replica_id"],)).fetchone()
        if row:
            return row[0]
    if "action_id" in payload:
        row = db.execute(
            "SELECT p.service FROM plans p JOIN actions a ON a.plan_id=p.id WHERE a.id=?",
            (payload["action_id"],)).fetchone()
        if row:
            return row[0]
    if "plan_id" in payload:
        row = db.execute("SELECT service FROM plans WHERE id=?", (payload["plan_id"],)).fetchone()
        if row:
            return row[0]
    return None


def business_at(db, event):
    """Business (event) time, never the arrival sequence. Falls back to the
    timestamp of the state row the command actually mutated."""
    kind, payload = event["kind"], event["input"]
    if "at" in payload:
        return int(payload["at"])
    if kind == "agent.observe":
        return int(payload["observed_at"])
    if kind == "agent.exception":
        return int(payload["expires_at"])
    if kind == "policy.publish":
        row = db.execute("SELECT created_at FROM revisions WHERE policy_id=? AND revision=?",
                         (payload["policy_id"], payload["revision"])).fetchone()
        return int(row[0]) if row else 0
    if kind == "drift.dispatch":
        row = db.execute("SELECT p.created_at FROM plans p JOIN actions a ON a.plan_id=p.id "
                         "WHERE a.id=?", (payload["action_id"],)).fetchone()
        return int(row[0]) if row else 0
    if kind == "drift.confirm":
        row = db.execute(
            "SELECT r.observed_at FROM receipts r JOIN actions a ON a.id=r.action_id "
            "WHERE a.id=? AND r.status='accepted'", (payload["action_id"],)).fetchone()
        return int(row[0]) if row else 0
    return 0


def _refs(event):
    kind, payload = event["kind"], event["input"]
    refs = []
    if "policy_id" in payload:
        refs.append(("policy", str(payload["policy_id"])))
    if "replica_id" in payload:
        refs.append(("replica", str(payload["replica_id"])))
    if "action_id" in payload:
        refs.append(("action", str(payload["action_id"])))
    if "plan_id" in payload:
        refs.append(("plan", str(payload["plan_id"])))
    for dep in payload.get("dependencies", []) or []:
        refs.append(("policy", str(dep)))
    return refs


def _resolve_key(db, events_by_id, key):
    kind, ident = key
    if kind == "action":
        plan_id = ident.split(":", 1)[0]
        out = set()
        for event in events_by_id.values():
            payload = event["input"]
            if payload.get("action_id") == ident or payload.get("plan_id") == plan_id:
                out.add(event["id"])
        return out
    field = {"policy": "policy_id", "replica": "replica_id", "plan": "plan_id"}[kind]
    return {eid for eid, event in events_by_id.items() if event["input"].get(field) == ident}


def causal_closure(db, events, seeds):
    """Breadth-first closure over causal references; returns ordered event ids."""
    by_id = {event["id"]: event for event in events}
    seen = set(seeds)
    queue = list(seeds)
    while queue:
        event = by_id[queue.pop(0)]
        for ref in _refs(event):
            for eid in _resolve_key(db, by_id, ref):
                if eid not in seen:
                    seen.add(eid)
                    queue.append(eid)
    return sorted(seen)


# --------------------------------------------------------------------------
# Leaf construction
# --------------------------------------------------------------------------

def event_leaf(event, in_window):
    return {
        "kind": "event",
        "event_id": event["id"],
        "request_id": event["request_id"],
        "kind_name": event["kind"],
        "subject": event["subject"],
        "at": event["_at"],
        "received_at": event["id"],
        "input": event["input"],
        "result": event["result"],
        "in_window": bool(in_window),
    }


def event_key(event):
    return f"event:{event['id']:010d}"


def _assertion_leaves(window_events):
    leaves = []
    for event in window_events:
        kind, payload, result = event["kind"], event["input"], event["result"]
        if kind == "policy.publish":
            leaves.append((f"assert:publish:{payload['policy_id']}:{payload['revision']}:{event['id']}", {
                "kind": "assertion", "claim": "policy_published",
                "policy_id": str(payload["policy_id"]), "revision": int(payload["revision"]),
                "status": result.get("status"), "event_id": event["id"], "at": event["_at"]}))
        elif kind == "drift.receipt":
            leaves.append((f"assert:receipt:{payload['action_id']}:{event['id']}", {
                "kind": "assertion", "claim": "receipt_resolved",
                "action_id": str(payload["action_id"]), "receipt_id": str(payload["receipt_id"]),
                "status": result.get("status"), "event_id": event["id"], "at": event["_at"]}))
        elif kind == "drift.confirm":
            leaves.append((f"assert:confirm:{payload['action_id']}:{event['id']}", {
                "kind": "assertion", "claim": "independently_confirmed",
                "action_id": str(payload["action_id"]), "status": result.get("status"),
                "event_id": event["id"], "at": event["_at"]}))
        elif kind == "agent.observe" and result.get("status") == "accepted":
            leaves.append((f"assert:observe:{payload['observation_id']}:{event['id']}", {
                "kind": "assertion", "claim": "observation_accepted",
                "observation_id": str(payload["observation_id"]),
                "replica_id": str(payload["replica_id"]),
                "observed_at": int(payload["observed_at"]),
                "received_at": int(payload["received_at"]),
                "drift": result.get("drift"), "event_id": event["id"], "at": event["_at"]}))
    return leaves


def _digest_for(leaf):
    if leaf.get("kind") == "event":
        return merkle.event_leaf_digest(leaf)
    return merkle.generic_leaf_digest(leaf)


def _redact_event_leaf(leaf):
    redacted = dict(leaf)
    redacted["redacted"] = True
    redacted["input"] = {
        field: (merkle.REDACTED_PLACEHOLDER if merkle.is_sensitive(field) else value)
        for field, value in leaf["input"].items()
    }
    # The decision result can echo the policy target (e.g. observe.target).
    redacted["result"] = _redact_value(leaf["result"])
    # Internal full-result/value hashes are commitments (no plaintext); the
    # full value digests are withheld while the leaf digest stays identical.
    redacted["secret_value_commitments"] = []
    return redacted


def _redact_value(value):
    if isinstance(value, dict):
        return {key: (merkle.REDACTED_PLACEHOLDER if merkle.is_sensitive(key)
                      else _redact_value(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


# --------------------------------------------------------------------------
# Sealing
# --------------------------------------------------------------------------

def seal_window(db, service, start, end, signed_at):
    """Seal the causal closure of [start, end) for one service.

    Idempotent and concurrency-safe: a (service, window) pair has exactly one
    seal identity. Re-running after a crash or against a concurrent sealer
    returns the existing seal instead of writing a second root.
    """
    initialize(db)
    service, start, end, signed_at = str(service), int(start), int(end), int(signed_at)
    if end <= start:
        raise ValueError("window must be half-open with end > start")
    with transaction(db):
        existing = db.execute(
            "SELECT seal_id FROM seal_registry WHERE service=? AND start_at=? AND end_at=?",
            (service, start, end)).fetchone()
        if existing:
            return {"status": "already_sealed", "seal_id": existing[0]}
        prefix_id = db.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
        events = _load_events(db, prefix_id)
        for event in events:
            event["_at"] = business_at(db, event)
            event["_service"] = _event_service(db, event)
        window_events = [e for e in events
                         if e["_service"] == service and start <= e["_at"] < end]
        closure = causal_closure(db, events, [e["id"] for e in window_events])
        closure_set = set(closure)
        window_set = {e["id"] for e in window_events}
        prereq_ids = sorted(closure_set - window_set)
        window_ids = sorted(window_set)

        leaves = []
        for event in events:
            if event["id"] in closure_set:
                leaf = merkle.with_secret_commitments(
                    event_leaf(event, event["id"] in window_set))
                leaves.append((event_key(event), leaf))
        for key, leaf in _assertion_leaves(
                [e for e in events if e["id"] in window_set]):
            leaves.append((key, leaf))
        page_names = []
        has_pages = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_pages'").fetchone()
        if has_pages:
            for name, raw in db.execute("SELECT page,rows_json FROM evidence_pages ORDER BY page"):
                rows = json.loads(raw)
                if any(str(r.get("service")) == service for r in rows):
                    page_names.append(name)
                    leaves.append((f"page:{name}",
                                   {"kind": "evidence_page", "page": name, "rows": rows}))
        leaves.sort(key=lambda item: item[0])
        entries = [(key, _digest_for(leaf)) for key, leaf in leaves]
        root = merkle.root_for(entries)
        seal_id = "seal:" + hashlib.sha256(
            canonical([service, start, end, prefix_id, root]).encode("utf-8")).hexdigest()[:16]
        seq = db.execute("SELECT COALESCE(MAX(seq),0)+1 FROM seal_registry").fetchone()[0]
        propositions = _propositions(db, window_events)
        db.execute(
            "INSERT INTO seal_registry VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (seal_id, service, start, end, signed_at, prefix_id,
             canonical(window_ids), canonical(prereq_ids), canonical(page_names),
             canonical([{"key": k, "digest": d} for k, d in entries]), root, seq))
        for index, (key, leaf) in enumerate(leaves):
            db.execute(
                "INSERT INTO seal_leaves(seal_id,leaf_key,kind,ref,content_json,digest,"
                "in_window,sort_index) VALUES (?,?,?,?,?,?,?,?)",
                (seal_id, key, leaf["kind"], _ref(leaf), canonical(leaf),
                 _digest_for(leaf), 1 if leaf.get("kind") != "event" or leaf["in_window"] else 0,
                 index))
    return {"status": "sealed", "seal_id": seal_id, "service": service,
            "window": [start, end], "signed_at": signed_at,
            "prefix_event_id": prefix_id, "root": root,
            "window_events": window_ids, "prerequisite_events": prereq_ids,
            "pages": page_names, "leaf_count": len(leaves),
            "propositions": propositions}


def _ref(leaf):
    if leaf.get("kind") == "event":
        return str(leaf["event_id"])
    if leaf.get("kind") == "assertion":
        return leaf.get("claim", "")
    if leaf.get("kind") == "evidence_page":
        return leaf.get("page", "")
    if leaf.get("kind") == "anchor":
        return leaf.get("seal_id", "")
    return ""


def _propositions(db, window_events):
    propositions = []
    for event in sorted(window_events, key=lambda e: e["id"]):
        kind, payload, result = event["kind"], event["input"], event["result"]
        if kind == "policy.publish" and result.get("status") == "active":
            propositions.append({
                "statement": "policy_published", "policy_id": str(payload["policy_id"]),
                "revision": int(payload["revision"]), "event_id": event["id"],
                "leaf_key": event_key(event), "at": event["_at"]})
        elif kind == "drift.receipt" and result.get("status") == "applied":
            propositions.append({
                "statement": "receipt_applied_only",
                "action_id": str(payload["action_id"]),
                "receipt_id": str(payload["receipt_id"]),
                "leaf_key": event_key(event), "at": event["_at"],
                "confirm_absence_key": f"assert:confirm:{payload['action_id']}:"})
        elif kind == "drift.confirm" and result.get("status") in ("confirmed", "converged"):
            propositions.append({
                "statement": "independently_confirmed",
                "action_id": str(payload["action_id"]),
                "leaf_key": event_key(event), "at": event["_at"]})
    return propositions


# --------------------------------------------------------------------------
# Late evidence: appendix volumes that never touch the original root
# --------------------------------------------------------------------------

def attach_late(db, seal_id, attached_at):
    """Bind events sampled inside the window but received after sealing."""
    initialize(db)
    with transaction(db):
        seal = db.execute("SELECT * FROM seal_registry WHERE seal_id=?", (seal_id,)).fetchone()
        if not seal:
            raise ValueError("unknown_seal")
        service, start, end = seal["service"], seal["start_at"], seal["end_at"]
        known = set(json.loads(seal["window_event_ids"])) | set(json.loads(seal["prereq_event_ids"]))
        fresh = [e for e in _load_events(db) if e["id"] > seal["prefix_event_id"]]
        for event in fresh:
            event["_at"] = business_at(db, event)
            event["_service"] = _event_service(db, event)
        # Only events whose *sampling* time lies in the window are appendix
        # evidence; causal prerequisites are pulled in regardless of their time.
        late = [e for e in fresh if e["_service"] == service and start <= e["_at"] < end]
        if not late:
            return {"status": "noop", "seal_id": seal_id, "late_events": []}
        already = set()
        for att in db.execute("SELECT event_ids FROM seal_attachments WHERE seal_id=?",
                              (seal_id,)):
            already.update(json.loads(att["event_ids"]))
        if all(e["id"] in already for e in late):
            return {"status": "noop", "seal_id": seal_id, "late_events": []}
        closure = set(causal_closure(db, _load_events(db), [e["id"] for e in late]))
        new_ids = sorted(eid for eid in closure
                         if eid > seal["prefix_event_id"] and eid not in already)
        leaves = []
        for event in _load_events(db):
            if event["id"] in new_ids:
                event["_at"] = business_at(db, event)
                leaf = merkle.with_secret_commitments(
                    event_leaf(event, event["id"] in {e["id"] for e in late}))
                leaves.append((event_key(event), leaf))
        for key, leaf in _assertion_leaves(late):
            leaves.append((key, leaf))
        anchor = {"kind": "anchor", "seal_id": seal_id, "seal_root": seal["root"],
                  "attached_at": int(attached_at), "prefix_event_id": seal["prefix_event_id"]}
        anchor_key = f"anchor:{seal_id}:{int(attached_at)}"
        leaves.append((anchor_key, anchor))
        leaves.sort(key=lambda item: item[0])
        entries = [(key, _digest_for(leaf)) for key, leaf in leaves]
        root = merkle.root_for(entries)
        seq = db.execute("SELECT COALESCE(MAX(seq),0)+1 FROM seal_attachments WHERE seal_id=?",
                         (seal_id,)).fetchone()[0]
        attachment_id = f"att:{seal_id}:{seq}"
        new_prefix = db.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
        db.execute(
            "INSERT INTO seal_attachments(attachment_id,seal_id,seq,attached_at,"
            "prefix_event_id,event_ids,anchor_key,manifest_json,root) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (attachment_id, seal_id, seq, int(attached_at), new_prefix,
             canonical(new_ids), anchor_key,
             canonical([{"key": k, "digest": d} for k, d in entries]), root))
        for key, leaf in leaves:
            db.execute(
                "INSERT INTO seal_attachment_leaves(attachment_id,leaf_key,kind,ref,"
                "content_json,digest) VALUES (?,?,?,?,?,?)",
                (attachment_id, key, leaf["kind"], _ref(leaf),
                 canonical(leaf), _digest_for(leaf)))
    return {"status": "attached", "attachment_id": attachment_id, "seal_id": seal_id,
            "root": root, "late_events": new_ids, "anchor_key": anchor_key}


# --------------------------------------------------------------------------
# Keys and signatures
# --------------------------------------------------------------------------

def _hmac(secret_hex, message):
    return hmac.new(bytes.fromhex(secret_hex), canonical(message).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def get_or_create_key(db, key_id, role):
    if not db.in_transaction:
        initialize(db)
    row = db.execute("SELECT * FROM seal_keys WHERE key_id=?", (key_id,)).fetchone()
    if row:
        return dict(row)
    secret = secrets.token_hex(32)
    db.execute("INSERT INTO seal_keys(key_id,secret_hex,role,status) VALUES (?,?,?,'active')",
               (key_id, secret, role))
    return dict(db.execute("SELECT * FROM seal_keys WHERE key_id=?", (key_id,)).fetchone())


def export_key(db, key_id):
    initialize(db)
    if key_id == "issuer":
        return get_or_create_key(db, "issuer", "issuer")
    row = db.execute("SELECT * FROM seal_keys WHERE key_id=?", (key_id,)).fetchone()
    if not row:
        raise ValueError("unknown_key")
    return {"key_id": key_id, "secret_hex": row["secret_hex"], "role": row["role"]}


def _sign(db, message):
    key = get_or_create_key(db, "issuer", "issuer")
    return {"alg": "HS256", "kid": "issuer", "digest": _hmac(key["secret_hex"], message)}


def verify_signature(secret_hex, message, signature):
    if signature.get("alg") != "HS256":
        return False
    return hmac.compare_digest(_hmac(secret_hex, message), signature.get("digest", ""))


# --------------------------------------------------------------------------
# Certificates with role-scoped selective disclosure
# --------------------------------------------------------------------------

ROLES = ("regulator", "customer")


def _load_seal_material(db, seal_id):
    seal = dict(db.execute("SELECT * FROM seal_registry WHERE seal_id=?", (seal_id,)).fetchone())
    leaves = {row["leaf_key"]: dict(row)
              for row in db.execute("SELECT * FROM seal_leaves WHERE seal_id=?", (seal_id,))}
    return seal, leaves


def issue_certificate(db, seal_id, audience, role, attachment_ids=None):
    """Issue an independently verifiable certificate for one reader.

    A certificate without appendices is immutable per audience. Including an
    appendix produces a distinct versioned certificate; the original stays on
    file with its original root and propositions.
    """
    initialize(db)
    attachment_ids = list(attachment_ids or [])
    if role not in ROLES:
        raise ValueError("unknown_role")
    with transaction(db):
        if not attachment_ids:
            existing = db.execute(
                "SELECT certificate_id,bundle_json FROM seal_certificates "
                "WHERE seal_id=? AND audience=?", (seal_id, audience)).fetchone()
            if existing:
                return {"status": "reissued", "certificate_id": existing["certificate_id"],
                        "bundle": json.loads(existing["bundle_json"])}
        seal, leaves = _load_seal_material(db, seal_id)
        version = "" if not attachment_ids else ":" + hashlib.sha256(
            canonical(attachment_ids).encode("utf-8")).hexdigest()[:12]
        cert_id = f"cert:{seal_id}:{audience}{version}"
        if attachment_ids:
            dup = db.execute("SELECT bundle_json FROM seal_certificates WHERE certificate_id=?",
                             (cert_id,)).fetchone()
            if dup:
                return {"status": "reissued", "certificate_id": cert_id,
                        "bundle": json.loads(dup[0])}
        bundle = _build_bundle(db, seal, leaves, {}, audience, role, attachment_ids, cert_id)
        db.execute("INSERT INTO seal_certificates VALUES (?,?,?,?,?,?)",
                   (cert_id, seal_id, audience, role, canonical(attachment_ids), canonical(bundle)))
        get_or_create_key(db, f"audience:{audience}", role)
    return {"status": "issued", "certificate_id": cert_id, "bundle": bundle}


def _build_bundle(db, seal, leaves, attachments, audience, role, attachment_ids,
                  certificate_id=None):
    manifest = json.loads(seal["manifest_json"])
    tree = merkle.Tree([(item["key"], item["digest"]) for item in manifest])
    redacted_keys, disclosed, proofs = set(), {}, []
    for item in manifest:
        key = item["key"]
        row = leaves.get(key)
        if row is None or row["content_json"] is None:  # archived/compressed away
            continue
        leaf = json.loads(row["content_json"])
        if role == "customer" and leaf.get("kind") == "event":
            leaf = _redact_event_leaf(leaf)
            redacted_keys.add(key)
        if _digest_for(leaf) != item["digest"]:
            raise ValueError("redaction broke leaf commitment")
        disclosed[key] = leaf
        proofs.append(tree.inclusion(key))
    propositions = _propositions_from_seal(db, seal, leaves)
    absence = []
    for prop in propositions:
        if prop["statement"] == "receipt_applied_only":
            probe = prop["confirm_absence_key"]
            if not any(k.startswith(f"assert:confirm:{prop['action_id']}:") for k in tree.keys):
                absence.append(tree.absence(probe))
    attachment_roots = []
    for attachment_id in attachment_ids:
        att = dict(db.execute("SELECT * FROM seal_attachments WHERE attachment_id=?",
                              (attachment_id,)).fetchone())
        att_manifest = json.loads(att["manifest_json"])
        att_leaves = {r["leaf_key"]: dict(r) for r in db.execute(
            "SELECT * FROM seal_attachment_leaves WHERE attachment_id=?", (attachment_id,))}
        att_disclosed, att_redacted = {}, []
        for item in att_manifest:
            row = att_leaves.get(item["key"])
            if row is None or row["content_json"] is None:
                continue
            leaf = json.loads(row["content_json"])
            if role == "customer" and leaf.get("kind") == "event":
                leaf = _redact_event_leaf(leaf)
                att_redacted.append(item["key"])
            if _digest_for(leaf) != item["digest"]:
                raise ValueError("attachment redaction broke leaf commitment")
            att_disclosed[item["key"]] = leaf
        attachment_roots.append({
            "attachment_id": attachment_id, "root": att["root"],
            "anchor_key": att["anchor_key"], "manifest": att_manifest,
            "leaves": att_disclosed, "redactions": sorted(att_redacted)})
    bundle = {
        "schema": "cloudctl-compliance-cert/1",
        "certificate_id": certificate_id or f"cert:{seal['seal_id']}:{audience}",
        "seal_id": seal["seal_id"], "service": seal["service"],
        "window": {"start": seal["start_at"], "end": seal["end_at"]},
        "signed_at": seal["signed_at"], "audience": audience, "role": role,
        "seal_root": seal["root"], "seal_manifest": manifest,
        "leaves": disclosed, "redactions": sorted(redacted_keys),
        "inclusion_proofs": proofs, "absence_proofs": absence,
        "propositions": propositions, "attachments": attachment_roots,
        "issued_at": seal["signed_at"],
    }
    bundle["signature"] = _sign(db, {k: v for k, v in bundle.items() if k != "signature"})
    return bundle


def _propositions_from_seal(db, seal, leaves):
    propositions = []
    for row in db.execute("SELECT content_json FROM seal_leaves WHERE seal_id=? AND kind='event' "
                          "ORDER BY sort_index", (seal["seal_id"],)):
        leaf = json.loads(row["content_json"])
        if not leaf.get("in_window"):
            continue
        kind, payload, result = leaf["kind_name"], leaf["input"], leaf["result"]
        if kind == "policy.publish" and result.get("status") == "active":
            propositions.append({
                "statement": "policy_published", "policy_id": str(payload["policy_id"]),
                "revision": int(payload["revision"]), "event_id": leaf["event_id"],
                "leaf_key": f"event:{leaf['event_id']:010d}", "at": leaf["at"]})
        elif kind == "drift.receipt" and result.get("status") == "applied":
            propositions.append({
                "statement": "receipt_applied_only",
                "action_id": str(payload["action_id"]),
                "receipt_id": str(payload["receipt_id"]),
                "leaf_key": f"event:{leaf['event_id']:010d}", "at": leaf["at"],
                "confirm_absence_key": f"assert:confirm:{payload['action_id']}:seal-time"})
        elif kind == "drift.confirm" and result.get("status") in ("confirmed", "converged"):
            propositions.append({
                "statement": "independently_confirmed",
                "action_id": str(payload["action_id"]),
                "leaf_key": f"event:{leaf['event_id']:010d}", "at": leaf["at"]})
    return propositions


# --------------------------------------------------------------------------
# Supplements (conclusion upgrade) and witness revocation
# --------------------------------------------------------------------------

def supplement(db, seal_id, audience, role, attachment_ids, issued_at):
    """Issue a follow-up credential; the original certificate stays on file."""
    initialize(db)
    if role not in ROLES:
        raise ValueError("unknown_role")
    with transaction(db):
        seal = dict(db.execute("SELECT * FROM seal_registry WHERE seal_id=?", (seal_id,)).fetchone())
        if not seal:
            raise ValueError("unknown_seal")
        upgraded = []
        for attachment_id in attachment_ids:
            att = dict(db.execute("SELECT * FROM seal_attachments WHERE attachment_id=?",
                                  (attachment_id,)).fetchone())
            if not att or att["seal_id"] != seal_id:
                raise ValueError("unknown_attachment")
            for row in db.execute(
                    "SELECT content_json FROM seal_attachment_leaves WHERE attachment_id=? "
                    "AND kind='assertion'", (attachment_id,)):
                claim = json.loads(row["content_json"])
                if claim.get("claim") == "observation_accepted" and claim.get("drift") == "converged":
                    upgraded.append({
                        "statement": "independently_confirmed",
                        "observation_leaf_key": f"event:{claim['event_id']:010d}",
                        "observation_id": claim["observation_id"],
                        "observed_at": claim["observed_at"], "received_at": claim["received_at"],
                        "attachment_id": attachment_id,
                        "anchor_key": att["anchor_key"], "attachment_root": att["root"]})
        message = {
            "schema": "cloudctl-compliance-supplement/1",
            "seal_id": seal_id, "seal_root": seal["root"],
            "audience": audience, "role": role, "issued_at": int(issued_at),
            "upgraded_propositions": upgraded,
        }
        message["signature"] = _sign(db, {k: v for k, v in message.items() if k != "signature"})
        cred_id = f"sup:{seal_id}:{audience}:{issued_at}"
        db.execute("INSERT INTO seal_credentials VALUES (?,?,?,?,?,?,?)",
                   (cred_id, seal_id, audience, "supplement", canonical(message),
                    int(issued_at), None))
    return {"status": "supplemented", "credential_id": cred_id, "bundle": message}


def revoke_witness(db, key_id, revoked_at, reason):
    """Revoke an audience witness key; old certificates remain archived and a
    signed revocation credential is issued instead of rewriting history."""
    initialize(db)
    with transaction(db):
        row = db.execute("SELECT * FROM seal_keys WHERE key_id=?", (key_id,)).fetchone()
        if not row:
            raise ValueError("unknown_key")
        audience = key_id.split(":", 1)[1] if key_id.startswith("audience:") else key_id
        certs = [dict(r) for r in db.execute(
            "SELECT certificate_id,seal_id FROM seal_certificates WHERE audience=?", (audience,))]
        db.execute("UPDATE seal_keys SET status='revoked',revoked_at=?,reason=? WHERE key_id=?",
                   (int(revoked_at), str(reason), key_id))
        message = {
            "schema": "cloudctl-compliance-revocation/1",
            "revoked_key_id": key_id, "revoked_at": int(revoked_at), "reason": str(reason),
            "certificates": [c["certificate_id"] for c in certs], "audience": audience,
        }
        message["signature"] = _sign(db, {k: v for k, v in message.items() if k != "signature"})
        cred_id = f"rev:{key_id}:{revoked_at}"
        for cert in certs:
            db.execute("INSERT INTO seal_credentials VALUES (?,?,?,?,?,?,?)",
                       (f"{cred_id}:{cert['certificate_id']}", cert["seal_id"], audience,
                        "revocation", canonical(message), int(revoked_at), key_id))
    return {"status": "revoked", "credential_id": cred_id, "bundle": message,
            "certificates": [c["certificate_id"] for c in certs]}


def archive_leaves(db, seal_id):
    """Simulate archival compression: drop leaf bodies while keeping the
    manifest and root, which external certificates still verify against."""
    initialize(db)
    with transaction(db):
        before = db.execute("SELECT root FROM seal_registry WHERE seal_id=?", (seal_id,)).fetchone()
        if not before:
            raise ValueError("unknown_seal")
        db.execute("UPDATE seal_leaves SET content_json=NULL WHERE seal_id=?", (seal_id,))
        for att in db.execute("SELECT attachment_id FROM seal_attachments WHERE seal_id=?",
                              (seal_id,)):
            db.execute("UPDATE seal_attachment_leaves SET content_json=NULL WHERE attachment_id=?",
                       (att["attachment_id"],))
        root = db.execute("SELECT root FROM seal_registry WHERE seal_id=?", (seal_id,)).fetchone()[0]
        if root != before["root"]:
            raise AssertionError("compression changed externally verifiable root")
    return {"status": "archived", "seal_id": seal_id, "root": root}


def get_certificate(db, certificate_id):
    row = db.execute("SELECT bundle_json FROM seal_certificates WHERE certificate_id=?",
                     (certificate_id,)).fetchone()
    if not row:
        raise ValueError("unknown_certificate")
    return json.loads(row[0])


# Backwards-compatible provisional entry retained for the fixed capture seed.
def issue(db, subject):
    db.execute("CREATE TABLE IF NOT EXISTS sealed_windows (subject TEXT,metric INTEGER)")
    value = sum(r["at"] for (raw,) in db.execute(
        "SELECT rows_json FROM evidence_pages") for r in json.loads(raw)
        if r["service"] == subject)
    with db:
        db.execute("INSERT INTO sealed_windows VALUES (?,?)", (subject, value))
    return {"subject": subject, "metric": value}
