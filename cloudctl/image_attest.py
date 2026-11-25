"""Capture immutable offline build attestations."""
import hashlib,json

def capture(db,packet,rows):
    db.execute('CREATE TABLE IF NOT EXISTS image_packets (packet TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    if not isinstance(rows,list) or any(set(r)!={'image','build','builder','digest'} for r in rows):raise ValueError('invalid_packet')
    raw=json.dumps(rows,sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    old=db.execute('SELECT digest FROM image_packets WHERE packet=?',(packet,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('packet_conflict')
        return 'replayed'
    with db:db.execute('INSERT INTO image_packets VALUES (?,?,?)',(packet,digest,raw))
    return 'captured'
