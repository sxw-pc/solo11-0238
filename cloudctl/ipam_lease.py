"""Provisional written business result for tenant address admission."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS address_leases (subject TEXT,metric INTEGER)')
    value=sum(r['address'] for (raw,) in db.execute('SELECT rows_json FROM ipam_pages') for r in json.loads(raw) if r['tenant']==subject)
    with db:db.execute('INSERT INTO address_leases VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
