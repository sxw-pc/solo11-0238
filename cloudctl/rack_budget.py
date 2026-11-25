"""Provisional written business result for rack electrical capacity."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS rack_orders (subject TEXT,metric INTEGER)')
    value=sum(r['watts'] for (raw,) in db.execute('SELECT rows_json FROM power_pages') for r in json.loads(raw) if r['rack']==subject)
    with db:db.execute('INSERT INTO rack_orders VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
