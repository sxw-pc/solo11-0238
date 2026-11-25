"""Provisional written business result for disaster restore selection."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS restore_orders (subject TEXT,metric INTEGER)')
    value=sum(r['generation'] for (raw,) in db.execute('SELECT rows_json FROM backup_pages') for r in json.loads(raw) if r['volume']==subject)
    with db:db.execute('INSERT INTO restore_orders VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
