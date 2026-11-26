"""Failover-grade WAL page import.

The legacy :func:`cloudctl.wal_capture.capture` keeps its exact 5-field
contract for the seed regression test.  This importer accepts the chained,
signed pages produced by :mod:`cloudctl.wal_chain`, which additionally retain
the physical writer node, boot generation, previous-item digest and signer.

It deliberately persists into the same append-only ``wal_pages`` evidence
table with the same captured/replayed/conflict semantics.
"""

from __future__ import annotations

import hashlib
import json
from typing import Mapping, Optional

from .wal_chain import validate_page, verify_signature


def capture_rich(db, page, rows, *, secrets: Optional[Mapping[str, str]] = None,
                 verify: bool = True):
    db.execute('CREATE TABLE IF NOT EXISTS wal_pages (page TEXT PRIMARY KEY,'
               'digest TEXT,rows_json TEXT)')
    if not isinstance(rows, list) or not rows:
        raise ValueError('invalid_rich_wal_page')
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('invalid_rich_wal_page')
        problems = validate_page(row)
        if problems:
            raise ValueError('invalid_rich_wal_page:' + ','.join(problems))
        if verify and secrets is not None:
            secret = secrets.get(str(row['signer']))
            if secret is None or not verify_signature(row, secret):
                raise ValueError('invalid_rich_signature')
    raw = json.dumps(rows, sort_keys=True, separators=(',', ':'))
    digest = hashlib.sha256(raw.encode()).hexdigest()
    old = db.execute('SELECT digest FROM wal_pages WHERE page=?',
                     (page,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError('wal_page_conflict')
        return 'replayed'
    with db:
        db.execute('INSERT INTO wal_pages VALUES (?,?,?)',
                   (page, digest, raw))
    return 'captured'
