"""Provisional deletion issue based on imported notices."""
import json

def issue(db,object_id,at):
    db.execute('CREATE TABLE IF NOT EXISTS delete_orders (object_id TEXT,at INTEGER)')
    rows=[r for (raw,) in db.execute('SELECT rows_json FROM retention_notices') for r in json.loads(raw) if r['object']==object_id]
    if not rows or rows[-1]['hold'] or rows[-1]['expires']>at:raise ValueError('deletion_blocked')
    with db:db.execute('INSERT INTO delete_orders VALUES (?,?)',(object_id,at))
    return {'object_id':object_id,'at':at}
