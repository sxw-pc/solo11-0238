"""Import offline database WAL acknowledgements."""
import hashlib,json

def capture(db,page,rows):
    db.execute('CREATE TABLE IF NOT EXISTS wal_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    keys={'node','term','index','digest','ack'}
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!=keys or type(r['term']) is not int or type(r['index']) is not int or type(r['ack']) is not bool for r in rows):raise ValueError('invalid_wal_page')
    raw=json.dumps(rows,sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    old=db.execute('SELECT digest FROM wal_pages WHERE page=?',(page,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('wal_page_conflict')
        return 'replayed'
    with db:db.execute('INSERT INTO wal_pages VALUES (?,?,?)',(page,digest,raw))
    return 'captured'
