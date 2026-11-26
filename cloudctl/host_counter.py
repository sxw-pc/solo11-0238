"""Physical host monotonic counter capture and CPU-second reconstruction.

Host meters are cumulative monotonic counters that may reset to zero on
reboot, so real CPU seconds are rebuilt by differencing samples inside one
device boot generation, one sampling interval, one metering multiplier and
one migration slice.  The multiplier of the sample opening an interval
applies to that interval.  A sample repeated as the last row of one page
and the first row of the next is the same boundary point and yields its
interval only once.
"""
import hashlib, json

KEYS = {'host', 'boot', 'at', 'counter', 'multiplier', 'slice'}


def _valid(sample):
    return (isinstance(sample, dict)
            and {'host', 'boot', 'at', 'counter'} <= set(sample) <= KEYS
            and isinstance(sample['host'], str) and sample['host']
            and all(isinstance(sample[key], int) and sample[key] >= 0
                    for key in ('boot', 'at', 'counter'))
            and isinstance(sample.get('multiplier', 1), int) and sample.get('multiplier', 1) >= 1
            and isinstance(sample.get('slice', 0), int) and sample.get('slice', 0) >= 0)


def capture(db, page, samples):
    db.execute('CREATE TABLE IF NOT EXISTS counter_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    if not isinstance(samples, list) or any(not _valid(s) for s in samples):
        raise ValueError('invalid_page')
    raw = json.dumps(samples, sort_keys=True, separators=(',', ':'))
    digest = hashlib.sha256(raw.encode()).hexdigest()
    old = db.execute('SELECT digest FROM counter_pages WHERE page=?', (page,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError('page_conflict')
        return 'replayed'
    with db:
        db.execute('INSERT INTO counter_pages VALUES (?,?,?)', (page, digest, raw))
    return 'captured'


def _points(db, host):
    db.execute('CREATE TABLE IF NOT EXISTS counter_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    points = {}
    for (raw,) in db.execute('SELECT rows_json FROM counter_pages'):
        for sample in json.loads(raw):
            if sample['host'] != host:
                continue
            key = (sample['boot'], sample.get('slice', 0), sample['at'])
            point = (sample['counter'], sample.get('multiplier', 1))
            if key in points and points[key] != point:
                raise ValueError('sample_conflict')
            points[key] = point
    return points


def hosts(db):
    db.execute('CREATE TABLE IF NOT EXISTS counter_pages (page TEXT PRIMARY KEY,digest TEXT,rows_json TEXT)')
    found = set()
    for (raw,) in db.execute('SELECT rows_json FROM counter_pages'):
        for sample in json.loads(raw):
            found.add(sample['host'])
    return sorted(found)


def cpu_seconds(db, host):
    """Verified CPU seconds consumed on one host over all captured intervals."""
    segments = {}
    for (boot, slice_id, at), point in _points(db, host).items():
        segments.setdefault((boot, slice_id), []).append((at, point))
    total = 0
    for segment in segments.values():
        segment.sort()
        for (_, (start, multiplier)), (_, (end, _)) in zip(segment, segment[1:]):
            if end < start:
                raise ValueError('counter_regression')
            total += (end - start) * multiplier
    return total
