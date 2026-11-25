"""Minimal offline sealed secret envelope capture."""
import hashlib,json

def capture(db,bundle,replica,key_id,material):
    db.execute('CREATE TABLE IF NOT EXISTS secret_envelopes (bundle TEXT PRIMARY KEY, replica TEXT, key_id TEXT, digest TEXT)')
    digest=hashlib.sha256(material.encode()).hexdigest()
    old=db.execute('SELECT replica,key_id,digest FROM secret_envelopes WHERE bundle=?',(bundle,)).fetchone()
    if old:
        if tuple(old)!=(replica,key_id,digest):raise ValueError('envelope_conflict')
        return 'replayed'
    with db:db.execute('INSERT INTO secret_envelopes VALUES (?,?,?,?)',(bundle,replica,key_id,digest))
    return 'captured'
