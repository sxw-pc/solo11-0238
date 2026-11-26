"""Provisional written business result for service failover capacity.

``issue`` is retained verbatim for the original seed contract.  The physical
topology-aware protocol lives in :mod:`cloudctl.traffic_switch`; the wrappers
below let callers continue to import the reservation entry point from this
module.
"""
import json

from .physical_topology import (
    FailoverTopology,
    PhysicalTopology,
    TopologyRegistry,
)
from .traffic_switch import (
    HANDLERS as TRAFFIC_HANDLERS,
    TrafficSwitch,
    acknowledge,
    customer_link,
    inspect as inspect_switch,
    occupancy,
    plan as plan_traffic,
    prepare as reserve_physical,
    probe,
    receipt,
    recover,
    revoke,
)
from .traffic_switch import issue as issue_command


def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS failover_orders (subject TEXT,metric INTEGER)')
    value=sum(r['capacity'] for (raw,) in db.execute('SELECT rows_json FROM topology_pages') for r in json.loads(raw) if r['node']==subject)
    with db:db.execute('INSERT INTO failover_orders VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}


# Physical-capacity API.  Unlike issue(), these functions understand link
# equivalence, two-phase holds, command generations and probe confirmation.
FailoverCoordinator = TrafficSwitch
PhysicalFailover = TrafficSwitch
plan_failover = plan_traffic
plan = plan_traffic
prepare_failover = reserve_physical
prepare = reserve_physical
reserve = reserve_physical
reserve_capacity = reserve_physical
prepare_reservation = reserve_physical
plan_capacity = plan_traffic
dispatch_command = issue_command
issue_reservation = issue_command
ack = acknowledge
acknowledge_reservation = acknowledge
controller_ack = acknowledge
confirm_probe = probe
confirm_reservation = probe
link_for_customer = customer_link
get_customer_link = customer_link
occupancy_for = occupancy
get_occupancy = occupancy
inspect_failover = inspect_switch
inspect = inspect_switch

HANDLERS = {
    "legacy_issue": issue,
    **TRAFFIC_HANDLERS,
}
