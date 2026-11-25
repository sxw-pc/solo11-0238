"""Provisional written business result for service failover capacity."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS failover_orders (subject TEXT,metric INTEGER)')
    value=sum(r['capacity'] for (raw,) in db.execute('SELECT rows_json FROM topology_pages') for r in json.loads(raw) if r['node']==subject)
    with db:db.execute('INSERT INTO failover_orders VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
