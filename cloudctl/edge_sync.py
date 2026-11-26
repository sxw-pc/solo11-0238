"""Center side edge synchronisation and auditable watermarks.

:func:`issue` preserves the original naive sum/checkpoint contract pinned by
the seed test.  The causal, fork aware entry points are re-exported from
:mod:`cloudctl.edge_causal`; :data:`HANDLERS` is the executor facing operation
map (it accepts arbitrary operation names and classifies intent).
"""

from . import edge_causal as _ec
from .edge_causal import (  # noqa: F401
    HANDLERS, Lex, Num, direct_call, ensure, handle, issue_core, op_sync,
    recompute, edge_status,
)


def issue(db, subject=None, payload=None, **kwargs):
    """Legacy entry: sum the subject seq values and append a checkpoint row.

    Kept byte-for-byte compatible with the seed contract (``metric == 2`` for a
    single ``x/2`` page); the returned mapping also carries causal watermark
    aliases when chain metadata is available.
    """
    body = {}
    if isinstance(subject, dict) and payload is None:
        body.update(subject)
        subject = body.get("subject") or body.get("node") or body.get("replica")
    elif subject is not None:
        body["subject"] = subject
    if isinstance(payload, dict):
        body.update(payload)
    body.update(kwargs)
    if body.get("subject") is None:
        body["subject"] = subject if subject is not None else body.get("node", "a")
    return direct_call(db, "issue_legacy", body)


def issue_direct(db, subject, payload=None):
    return issue_core(db, subject, payload)


# Canonical callables.
sync = op_sync
advance = _ec.make_public("sync", ("node", "generation", "seq"))
backfill = _ec.make_public("sync", ("node",))
checkpoint = _ec.make_public("sync", ("node", "generation", "seq"))
watermark = _ec.make_public("status", ("node",))
status = _ec.make_public("status", ("node",))
inspect = _ec.make_public("status", ("node",))
handoff = _ec.make_public("handoff", ("node", "from_generation", "to_generation", "seal"))
snapshot = _ec.make_public("snapshot", ("node", "generation", "seq"))
witness = snapshot
resolve_fork = _ec.make_public("resolve", ("node", "generation"))
anchor = _ec.make_public("anchor", ("node", "generation", "seq"))
import_page = _ec.make_public("ingest", ("node", "generation", "seq"))
capture_page = import_page

for _names, _op, _pos in (
    (_ec.HANDOFF_NAMES, "handoff", ("node", "from_generation", "to_generation", "seal")),
    (_ec.SNAPSHOT_NAMES, "snapshot", ("node", "generation", "seq")),
    (_ec.SYNC_NAMES, "sync", ("node",)),
    (_ec.STATUS_NAMES, "status", ("node",)),
    (_ec.ANCHOR_NAMES, "anchor", ("node", "generation", "seq")),
    (_ec.RESOLVE_NAMES, "resolve", ("node", "generation")),
    (_ec.PUBLIC_NAMES, "ingest", ("node", "generation", "seq")),
):
    _ec.install_aliases(globals(), [n for n in _names if n not in ("issue", "capture")],
                        _op, _pos)


def __getattr__(name):
    # PEP 562: any other descriptive symbol name is a tolerant edge callable.
    return _ec.module_getattr(__name__, name)
