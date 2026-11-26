"""Uniform command transaction, idempotency and durable evidence boundary."""

from . import observe, policy, reconcile, physical_topology, traffic_switch
from .db import DecisionError, initialize, previous, record, transaction


HANDLERS = {"policy": policy.HANDLERS, "agent": observe.HANDLERS,
            "drift": reconcile.HANDLERS,
            "topology": physical_topology.HANDLERS,
            "physical_topology": physical_topology.HANDLERS,
            "link_topology": physical_topology.HANDLERS,
            "link_probe": physical_topology.HANDLERS,
            "traffic": traffic_switch.HANDLERS,
            "failover": traffic_switch.HANDLERS,
            "switchover": traffic_switch.HANDLERS}


def execute(connection, subsystem, operation, payload, request_id):
    initialize(connection)
    # New subsystems own additive tables.  Create them before opening the
    # executor transaction because sqlite executescript() commits open DDL.
    traffic_switch.init_switch(connection)
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
