"""Provisional written business result for compliance time window seal."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS sealed_windows (subject TEXT,metric INTEGER)')
    value=sum(r['at'] for (raw,) in db.execute('SELECT rows_json FROM evidence_pages') for r in json.loads(raw) if r['service']==subject)
    with db:db.execute('INSERT INTO sealed_windows VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
