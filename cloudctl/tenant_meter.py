"""Offline capture for tenant resource billing.

Raw {tenant, units} label pages are still accepted for the pinned legacy
entry, but real CPU seconds are rebuilt from physical host counters (see
host_counter) and from the scheduling-migration originals captured here.
Each original attributes host seconds to one or more candidate tenants; a
PID reuse can leave a slice disputed between candidates, and every
compatible attribution is kept until later scheduling-signature evidence
resolves it.  Unknown attribution is never guessed from the last received
label or from averages.
"""
import hashlib, itertools, json

from . import host_counter


def capture(db,page,rows):
    db.execute('CREATE TABLE IF NOT EXISTS usage_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!={'tenant','units'} or not isinstance(r['units'],int) or r['units']<0 for r in rows):raise ValueError('invalid_page')
    raw=json.dumps(rows,sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(raw.encode()).hexdigest()
    old=db.execute('SELECT digest FROM usage_pages WHERE page=?',(page,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('page_conflict')
        return 'replayed'
    with db:db.execute('INSERT INTO usage_pages VALUES (?,?,?)',(page,digest,raw))
    return 'captured'


SLICE_KEYS = {'id', 'host', 'seconds', 'candidates'}


def _valid_slice(record):
    return (isinstance(record, dict) and set(record) == SLICE_KEYS
            and isinstance(record['id'], str) and record['id']
            and isinstance(record['host'], str) and record['host']
            and isinstance(record['seconds'], int) and record['seconds'] >= 0
            and isinstance(record['candidates'], list) and record['candidates']
            and all(isinstance(t, str) and t for t in record['candidates'])
            and len(set(record['candidates'])) == len(record['candidates']))


def _pages(db, table):
    db.execute(f'CREATE TABLE IF NOT EXISTS {table} (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    out = []
    for (raw,) in db.execute(f'SELECT rows_json FROM {table}'):
        out.extend(json.loads(raw))
    return out


def _originals(db):
    return _pages(db, 'lifecycle_pages')


def _resolutions(db):
    return _pages(db, 'resolution_pages')


def capture_originals(db, page, records):
    """Capture scheduling/lifecycle originals: attribution slices on a host.

    A slice with one candidate is definitive; a slice with several
    candidates (for example after PID reuse) stays disputed until later
    scheduling-signature evidence resolves it."""
    db.execute('CREATE TABLE IF NOT EXISTS lifecycle_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    if not isinstance(records, list) or any(not _valid_slice(r) for r in records):
        raise ValueError('invalid_page')
    raw = json.dumps(records, sort_keys=True, separators=(',', ':'))
    digest = hashlib.sha256(raw.encode()).hexdigest()
    old = db.execute('SELECT digest FROM lifecycle_pages WHERE page=?', (page,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError('page_conflict')
        return 'replayed'
    ids = [r['id'] for r in records]
    if len(set(ids)) != len(ids) or {r['id'] for r in _originals(db)} & set(ids):
        raise ValueError('slice_conflict')
    with db:
        db.execute('INSERT INTO lifecycle_pages VALUES (?,?,?)', (page, digest, raw))
    return 'captured'


RESOLUTION_KEYS = {'slice', 'tenant', 'inode', 'signature'}


def _valid_resolution(record):
    return (isinstance(record, dict) and set(record) == RESOLUTION_KEYS
            and all(isinstance(record[key], str) and record[key] for key in RESOLUTION_KEYS))


def resolve(db, page, records):
    """Capture later scheduling-signature evidence resolving disputed slices.

    A resolution carries the container namespace inode and the dual
    scheduler signature; it only narrows a dispute to one tenant that was
    already a candidate and never rewrites the original slice."""
    db.execute('CREATE TABLE IF NOT EXISTS resolution_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    if not isinstance(records, list) or any(not _valid_resolution(r) for r in records):
        raise ValueError('invalid_page')
    raw = json.dumps(records, sort_keys=True, separators=(',', ':'))
    digest = hashlib.sha256(raw.encode()).hexdigest()
    old = db.execute('SELECT digest FROM resolution_pages WHERE page=?', (page,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError('page_conflict')
        return 'replayed'
    originals = {r['id']: r for r in _originals(db)}
    resolved = {r['slice']: r['tenant'] for r in _resolutions(db)}
    seen = {}
    for record in records:
        target = originals.get(record['slice'])
        if target is None:
            raise ValueError('unknown_slice')
        if len(target['candidates']) < 2:
            raise ValueError('not_disputed')
        if record['tenant'] not in target['candidates']:
            raise ValueError('invalid_resolution')
        prior = resolved.get(record['slice'], seen.get(record['slice']))
        if prior is not None and prior != record['tenant']:
            raise ValueError('resolution_conflict')
        seen[record['slice']] = record['tenant']
    with db:
        db.execute('INSERT INTO resolution_pages VALUES (?,?,?)', (page, digest, raw))
    return 'captured'


def slices(db, host=None):
    """Effective attribution slices after applying every captured resolution."""
    resolved = {r['slice']: r['tenant'] for r in _resolutions(db)}
    out = []
    for record in _originals(db):
        if host is not None and record['host'] != host:
            continue
        candidates = [resolved[record['id']]] if record['id'] in resolved else list(record['candidates'])
        out.append({'id': record['id'], 'host': record['host'],
                    'seconds': record['seconds'], 'candidates': candidates})
    return out


def interpretations(db, host=None):
    """Every tenant attribution compatible with the captured originals.

    Disputed slices are assigned to each candidate in turn, so the list
    covers all compatible readings; in every reading each second belongs to
    exactly one tenant, never to two tenants at once."""
    effective = slices(db, host)
    base = {}
    disputed = []
    for record in effective:
        if len(record['candidates']) == 1:
            tenant = record['candidates'][0]
            base[tenant] = base.get(tenant, 0) + record['seconds']
        else:
            disputed.append(record)
    readings = []
    for choice in itertools.product(*(record['candidates'] for record in disputed)):
        reading = dict(base)
        for record, tenant in zip(disputed, choice):
            reading[tenant] = reading.get(tenant, 0) + record['seconds']
        readings.append(reading)
    return readings


def proven(db):
    """CPU seconds that belong to a tenant in every compatible reading."""
    certain = {}
    for record in slices(db):
        if len(record['candidates']) == 1:
            tenant = record['candidates'][0]
            certain[tenant] = certain.get(tenant, 0) + record['seconds']
    return certain


def common_total(db, host=None):
    """Physical seconds present in every compatible reading."""
    return sum(record['seconds'] for record in slices(db, host))


def verified_usage(db):
    """Per-host physical CPU seconds reconciled between counters and originals.

    Counter reconstruction is the physical truth.  Every attributed second
    must sit on a host with counter evidence, and the slices on a host must
    sum to its counter total, otherwise the evidence cannot be settled."""
    usage = {host: host_counter.cpu_seconds(db, host) for host in host_counter.hosts(db)}
    for record in slices(db):
        if record['host'] not in usage:
            raise ValueError('unverified_host')
    for host in usage:
        attributed = common_total(db, host)
        if attributed and attributed != usage[host]:
            raise ValueError('usage_mismatch')
    return usage
