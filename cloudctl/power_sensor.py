"""Offline capture for rack electrical capacity."""
import hashlib,json

def capture(db,page,rows):
    db.execute('CREATE TABLE IF NOT EXISTS power_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!={'rack','watts'} or not isinstance(r['watts'],int) or r['watts']<0 for r in rows):raise ValueError('invalid_page')
    raw=json.dumps(rows,sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    old=db.execute('SELECT digest FROM power_pages WHERE page=?',(page,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('page_conflict')
        return 'replayed'
    with db:db.execute('INSERT INTO power_pages VALUES (?,?,?)',(page,digest,raw))
    return 'captured'
