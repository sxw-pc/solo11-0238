"""Offline sealed secret envelope capture.

An envelope is only openable by the declared replica's *current* device
generation, so the sealed generation is captured next to the bundle identity
and material digest. Only the digest is ever stored: key material never enters
the database, the event log, reports or test output. Re-sending the exact same
bundle bytes stays idempotent; the same bundle id with different content,
replica or generation is rejected.
"""
import hashlib
from contextlib import contextmanager


@contextmanager
def _write(db):
    """Join a caller-owned transaction (the command executor); commit only
    when this module is used standalone."""
    if db.in_transaction:
        yield
    else:
        with db:
            yield


def capture(db, bundle, replica, key_id, material, generation=None):
    db.execute(
        "CREATE TABLE IF NOT EXISTS secret_envelopes ("
        "bundle TEXT PRIMARY KEY, replica TEXT, key_id TEXT, digest TEXT, "
        "generation INTEGER)"
    )
    digest = hashlib.sha256(material.encode()).hexdigest()
    old = db.execute(
        "SELECT replica,key_id,digest,generation FROM secret_envelopes WHERE bundle=?",
        (bundle,),
    ).fetchone()
    if old:
        if tuple(old) != (replica, key_id, digest, generation):
            raise ValueError("envelope_conflict")
        return "replayed"
    with _write(db):
        db.execute(
            "INSERT INTO secret_envelopes VALUES (?,?,?,?,?)",
            (bundle, replica, key_id, digest, generation),
        )
    return "captured"
