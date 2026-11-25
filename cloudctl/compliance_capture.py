"""Offline capture for compliance time window seal."""
import hashlib,json

def capture(db,page,rows):
    db.execute('CREATE TABLE IF NOT EXISTS evidence_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!={'service','at'} or not isinstance(r['at'],int) or r['at']<0 for r in rows):raise ValueError('invalid_page')
    raw=json.dumps(rows,sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    old=db.execute('SELECT digest FROM evidence_pages WHERE page=?',(page,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('page_conflict')
        return 'replayed'
    with db:db.execute('INSERT INTO evidence_pages VALUES (?,?,?)',(page,digest,raw))
    return 'captured'
