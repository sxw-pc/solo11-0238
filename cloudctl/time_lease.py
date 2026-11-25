"""Provisional time certificate from offline clock slips."""
import json

def issue(db,source):
    db.execute('CREATE TABLE IF NOT EXISTS time_certificates (source TEXT,offset INTEGER)')
    rows=[r for (raw,) in db.execute('SELECT rows_json FROM clock_pages') for r in json.loads(raw) if r['source']==source]
    if not rows:raise ValueError('missing_clock')
    offset=rows[-1]['reference_tick']-rows[-1]['local_tick']
    with db:db.execute('INSERT INTO time_certificates VALUES (?,?)',(source,offset))
    return {'source':source,'offset':offset}
