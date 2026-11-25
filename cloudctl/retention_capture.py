"""Capture retention and legal-hold notices."""
import hashlib,json

def capture(db,notice,rows):
    db.execute('CREATE TABLE IF NOT EXISTS retention_notices (notice TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    if not isinstance(rows,list) or any(set(r)!={'object','expires','hold'} or type(r['expires']) is not int or type(r['hold']) is not bool for r in rows):raise ValueError('invalid_notice')
    raw=json.dumps(rows,sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    old=db.execute('SELECT digest FROM retention_notices WHERE notice=?',(notice,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('notice_conflict')
        return 'replayed'
    with db:db.execute('INSERT INTO retention_notices VALUES (?,?,?)',(notice,digest,raw))
    return 'captured'
