"""Capture device slice inventory."""
import hashlib,json

def capture(db,page,rows):
    db.execute('CREATE TABLE IF NOT EXISTS gpu_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    if not isinstance(rows,list) or any(set(r)!={'device','memory','slices'} or type(r['memory']) is not int or type(r['slices']) is not int for r in rows):raise ValueError('invalid_gpu_page')
    raw=json.dumps(rows,sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    old=db.execute('SELECT digest FROM gpu_pages WHERE page=?',(page,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('gpu_page_conflict')
        return 'replayed'
    with db:db.execute('INSERT INTO gpu_pages VALUES (?,?,?)',(page,digest,raw))
    return 'captured'
