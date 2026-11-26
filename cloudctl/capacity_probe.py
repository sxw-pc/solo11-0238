"""Offline capture for service failover capacity."""
import hashlib,json

from .physical_topology import record_link_probe as capture_link_evidence


def capture(db,page,rows):
    db.execute('CREATE TABLE IF NOT EXISTS topology_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!={'node','capacity'} or not isinstance(r['capacity'],int) or r['capacity']<0 for r in rows):raise ValueError('invalid_page')
    raw=json.dumps(rows,sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    old=db.execute('SELECT digest FROM topology_pages WHERE page=?',(page,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('page_conflict')
        return 'replayed'
    with db:db.execute('INSERT INTO topology_pages VALUES (?,?,?)',(page,digest,raw))
    return 'captured'


def pages(db):
    """Return all immutable probe pages with their content digests."""
    db.execute('CREATE TABLE IF NOT EXISTS topology_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    result=[]
    for page,digest,raw in db.execute('SELECT page,digest,rows_json FROM topology_pages ORDER BY page'):
        result.append({'page':page,'digest':digest,'rows':json.loads(raw)})
    return result


def summary(db):
    """Summarize probe originals without treating port names as physical links."""
    items=pages(db)
    claims=[]
    for item in items:
        for row in item['rows']:
            claims.append({'page':item['page'],'node':row['node'],'capacity':row['capacity'],
                           'digest':item['digest']})
    return {'page_count':len(items),'claims':claims,'pages':items}


def capture_link_probe(db,probe_id,target_id,passed=True,generation=1,at=0,**kwargs):
    """Persist an independent physical-link probe original."""
    return capture_link_evidence(db,{
        'probe_id':probe_id,'target_id':target_id,'passed':passed,
        'generation':generation,'at':at,**kwargs,
    })
