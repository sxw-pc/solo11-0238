"""Activation ledger for opened sealed envelopes.

``activate`` preserves the original provisional ledger behavior used by the
seeded enhanced tests: a replica without a registered device generation opens
its latest captured envelope and appends an activation row. When a current
device generation is known, the envelope's sealed generation must match it -- a
valid seal addressed to an older generation cannot be opened.

The ledger is append-only; activations are never updated or deleted. Key
material is never stored or returned, only the key identity.
"""
from contextlib import contextmanager


@contextmanager
def _write(db):
    if db.in_transaction:
        yield
    else:
        with db:
            yield


def _ensure_table(db):
    db.execute(
        "CREATE TABLE IF NOT EXISTS secret_activations (replica TEXT,key_id TEXT)"
    )
    existing = [column[1] for column in
                db.execute("PRAGMA table_info(secret_activations)").fetchall()]
    for column, declaration in (("generation", "INTEGER"), ("at", "INTEGER"),
                                ("source", "TEXT"), ("command_id", "TEXT")):
        if column not in existing:
            db.execute(f"ALTER TABLE secret_activations ADD COLUMN {column} {declaration}")


def append_activation(db, replica, key_id, generation, at, source, command_id=None):
    _ensure_table(db)
    with _write(db):
        db.execute(
            "INSERT INTO secret_activations(replica,key_id,generation,at,source,command_id) "
            "VALUES (?,?,?,?,?,?)",
            (replica, key_id, generation, at, source, command_id),
        )


def activate(db, replica, generation=None, at=None):
    _ensure_table(db)
    row = db.execute(
        "SELECT key_id,generation FROM secret_envelopes WHERE replica=? ORDER BY rowid DESC LIMIT 1",
        (replica,),
    ).fetchone()
    if not row:
        raise ValueError("missing_envelope")
    sealed_generation = row[1] if len(row) > 1 else None
    if generation is not None and sealed_generation is not None \
            and int(generation) != int(sealed_generation):
        raise ValueError("stale_device_generation")
    key_id = row[0]
    with _write(db):
        db.execute("INSERT INTO secret_activations(replica,key_id) VALUES (?,?)",
                   (replica, key_id))
    return {"replica": replica, "key_id": key_id}
