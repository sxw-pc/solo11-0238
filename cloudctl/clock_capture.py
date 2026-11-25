"""Capture offline reference clock slips."""
import hashlib,json

def capture(db,page,rows):
    db.execute('CREATE TABLE IF NOT EXISTS clock_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    keys={'source','local_tick','reference_tick','uncertainty'}
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!=keys or any(type(r[k]) is not int for k in ('local_tick','reference_tick','uncertainty')) for r in rows):raise ValueError('invalid_clock_page')
    raw=json.dumps(rows,sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    old=db.execute('SELECT digest FROM clock_pages WHERE page=?',(page,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('clock_page_conflict')
        return 'replayed'
    with db:db.execute('INSERT INTO clock_pages VALUES (?,?,?)',(page,digest,raw))
    return 'captured'
