"""Provisional written business result for offline edge observation replay."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS edge_checkpoints (subject TEXT,metric INTEGER)')
    value=sum(r['seq'] for (raw,) in db.execute('SELECT rows_json FROM edge_pages') for r in json.loads(raw) if r['replica']==subject)
    with db:db.execute('INSERT INTO edge_checkpoints VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
