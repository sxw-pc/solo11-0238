"""Provisional written business result for tenant resource billing."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS tenant_charges (subject TEXT,metric INTEGER)')
    value=sum(r['units'] for (raw,) in db.execute('SELECT rows_json FROM usage_pages') for r in json.loads(raw) if r['tenant']==subject)
    with db:db.execute('INSERT INTO tenant_charges VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
