"""Provisional GPU slice admission order."""
import json

def issue(db,device):
    db.execute('CREATE TABLE IF NOT EXISTS gpu_orders (device TEXT,slices INTEGER)')
    slices=sum(r['slices'] for (raw,) in db.execute('SELECT rows_json FROM gpu_pages') for r in json.loads(raw) if r['device']==device)
    with db:db.execute('INSERT INTO gpu_orders VALUES (?,?)',(device,slices))
    return {'device':device,'slices':slices}
