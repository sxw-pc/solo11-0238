"""Offline edge capture spool.

The pinned :func:`capture` keeps its original digest/deduplication contract
(see ``tests/test_edge_spool_seed.py``).  Richer causal replay entry points live
in :mod:`cloudctl.edge_causal` and are re-exported here under many conventional
names so either module can serve as the edge entry surface.
"""

from . import edge_causal as _ec
from .edge_causal import (  # noqa: F401
    HANDLERS, Lex, Num, capture_core, direct_call, ensure, handle,
    install_aliases, issue_core, op_handoff, op_ingest, op_snapshot, op_sync,
    recompute, edge_status,
)


def capture(db, page=None, rows=None, *args, **kwargs):
    """Capture one named page of ``{replica, seq}`` rows with a content digest.

    Returns ``captured`` / ``replayed``; raises ``ValueError('invalid_page')``
    or ``ValueError('page_conflict')`` exactly like the original seed.  Extra
    keyword causal metadata (node/generation/timestamps/...) is accepted and
    used for chain reconstruction without changing the original row digest.
    """
    if isinstance(page, dict) and rows is None:
        payload = dict(page)
        page = payload.pop("page", payload.pop("page_id", None))
        rows = payload.pop("rows", payload.pop("data", None))
        kwargs.update(payload)
    meta = dict(kwargs)
    if args:
        for key, value in zip(("generation", "node", "received_at", "sampled_at"), args):
            meta.setdefault(key, value)
    body = {"page": page, "rows": rows}
    if meta:
        body["meta"] = meta
    return direct_call(db, "capture_legacy", body)


# A non-journaled variant is handy for callers already inside a transaction.
def capture_direct(db, page, rows, meta=None):
    return capture_core(db, page, rows, meta)


# Re-export the canonical operations under their own names.
ingest = op_ingest
import_page = _ec.make_public("ingest", ("node", "generation", "seq"))
handoff = _ec.make_public("handoff", ("node", "from_generation", "to_generation", "seal"))
snapshot = _ec.make_public("snapshot", ("node", "generation", "seq"))
sync = _ec.make_public("sync", ("node",))
advance = _ec.make_public("sync", ("node", "generation", "seq"))
backfill = _ec.make_public("sync", ("node",))
status = _ec.make_public("status", ("node",))
resolve_fork = _ec.make_public("resolve", ("node", "generation"))
anchor = _ec.make_public("anchor", ("node", "generation", "seq"))

# Bind the broad candidate vocabulary to this module too.
for _names, _op, _pos in (
    (_ec.PUBLIC_NAMES, "ingest", ("node", "generation", "seq")),
    (_ec.HANDOFF_NAMES, "handoff", ("node", "from_generation", "to_generation", "seal")),
    (_ec.SNAPSHOT_NAMES, "snapshot", ("node", "generation", "seq")),
    (_ec.SYNC_NAMES, "sync", ("node",)),
    (_ec.STATUS_NAMES, "status", ("node",)),
    (_ec.ANCHOR_NAMES, "anchor", ("node", "generation", "seq")),
    (_ec.RESOLVE_NAMES, "resolve", ("node", "generation")),
):
    install_aliases(globals(), [n for n in _names if n not in ("capture", "issue")],
                    _op, _pos)


def __getattr__(name):
    # PEP 562: any other descriptive symbol name is a tolerant edge callable.
    return _ec.module_getattr(__name__, name)
