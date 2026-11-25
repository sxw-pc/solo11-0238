"""Offline capture for object storage replication."""
import hashlib,json

def capture(db,page,rows):
    db.execute('CREATE TABLE IF NOT EXISTS object_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!={'bucket','shards'} or not isinstance(r['shards'],int) or r['shards']<0 for r in rows):raise ValueError('invalid_page')
    raw=json.dumps(rows,sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    old=db.execute('SELECT digest FROM object_pages WHERE page=?',(page,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('page_conflict')
        return 'replayed'
    with db:db.execute('INSERT INTO object_pages VALUES (?,?,?)',(page,digest,raw))
    return 'captured'
