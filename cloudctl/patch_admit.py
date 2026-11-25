"""Provisional written business result for node patch admission."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS patch_orders (subject TEXT,metric INTEGER)')
    value=sum(r['revision'] for (raw,) in db.execute('SELECT rows_json FROM patch_pages') for r in json.loads(raw) if r['host']==subject)
    with db:db.execute('INSERT INTO patch_orders VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
