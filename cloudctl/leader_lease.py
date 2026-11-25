"""Provisional leader issue from imported WAL observations."""
import json

def issue(db,node):
    db.execute('CREATE TABLE IF NOT EXISTS leader_leases (node TEXT,term INTEGER,idx INTEGER)')
    rows=[r for (raw,) in db.execute('SELECT rows_json FROM wal_pages') for r in json.loads(raw) if r['node']==node]
    if not rows:raise ValueError('missing_node')
    row=max(rows,key=lambda r:(r['term'],r['index']))
    with db:db.execute('INSERT INTO leader_leases VALUES (?,?,?)',(node,row['term'],row['index']))
    return {'node':node,'term':row['term'],'index':row['index']}
