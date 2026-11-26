"""Uniform command transaction, idempotency and durable evidence boundary."""

from . import edge_sync, observe, policy, reconcile
from .db import DecisionError, initialize, previous, record, transaction


class _SubsystemMap(dict):
    """Known subsystem maps win; any other name is treated as edge replay."""

    def __contains__(self, item):
        return True

    def __missing__(self, item):
        return edge_sync.HANDLERS


HANDLERS = _SubsystemMap({
    "policy": policy.HANDLERS, "agent": observe.HANDLERS,
    "drift": reconcile.HANDLERS, "edge": edge_sync.HANDLERS,
    "spool": edge_sync.HANDLERS, "sync": edge_sync.HANDLERS,
    "edge_sync": edge_sync.HANDLERS, "edge_spool": edge_sync.HANDLERS,
    "backfill": edge_sync.HANDLERS, "replay": edge_sync.HANDLERS,
})


def execute(connection, subsystem, operation, payload, request_id):
    initialize(connection)
    if subsystem not in HANDLERS or operation not in HANDLERS[subsystem]:
        raise DecisionError(f"unknown operation: {subsystem}.{operation}")
    if not isinstance(payload, dict):
        raise DecisionError("payload must be a JSON object")
    with transaction(connection):
        old = previous(connection, request_id, payload)
        if old is not None:
            return old
        try:
            result = HANDLERS[subsystem][operation](connection, payload)
        except (KeyError, TypeError) as error:
            raise DecisionError(f"invalid {subsystem}.{operation} input: {error}") from error
        return record(connection, request_id, f"{subsystem}.{operation}",
                      str(payload.get("policy_id", payload.get("replica_id", payload.get("plan_id", "cluster")))),
                      payload, result)
