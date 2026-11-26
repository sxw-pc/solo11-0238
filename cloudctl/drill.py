"""Canonical offline drill artifacts for the E/N1/N2 recovery scenario."""

from __future__ import annotations

import sqlite3

from .capacity_probe import capture
from .physical_topology import TopologyRegistry
from .traffic_switch import TrafficSwitch


DRILL = {
    "failed_entry": "E",
    "failed_domain": "fd-edge-e",
    "customers": {
        "A": {"demand": 5, "minimum_bandwidth": 5},
        "B": {"demand": 3, "minimum_bandwidth": 3},
    },
    "pages": {
        "Eth1/1": [{"node": "N1", "capacity": 6}],
        "Eth1/2": [{"node": "N2", "capacity": 4}],
    },
}


def build_drill(db: sqlite3.Connection | None = None, adopt_old: bool = True,
                fail: bool = True, at: int = 0):
    """Create the exact ambiguous Jia/Yi physical topology evidence."""
    if db is None:
        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
    topo = TopologyRegistry(db)
    switch = TrafficSwitch(db)

    domain_e = DRILL["failed_domain"]
    topo.domain(domain_e, "E edge failure domain")
    topo.domain("fd-n1", "N1 zone")
    topo.domain("fd-n2", "N2 zone")
    topo.domain("fd-proxy", "independent metered emergency zone")
    topo.domain("fd-core", "core")

    topo.node("E", capacity=8, domain_id=domain_e, healthy=not fail, role="failed-entry")
    # A healthy-looking standby is still not independent when it shares E's domain.
    topo.node("ES", capacity=8, domain_id=domain_e, healthy=True, role="same-domain-standby")
    topo.node("N1", capacity=6, domain_id="fd-n1", healthy=True, role="backup-entry")
    topo.node("N2", capacity=4, domain_id="fd-n2", healthy=True, role="backup-entry")

    topo.resource("uplink-E", capacity=8, kind="observed-uplink", domain_id=domain_e)
    topo.resource("uplink-N1", capacity=6, kind="observed-uplink", domain_id="fd-n1")
    topo.resource("uplink-N2", capacity=4, kind="observed-uplink", domain_id="fd-n2")
    topo.resource("CORE", capacity=100, kind="core", domain_id="fd-core", authoritative=True)

    # Candidate Jia: N1 and N2 terminate on one shared 6-unit upstream.
    topo.resource("U-shared", capacity=6, kind="physical-upstream",
                  domain_id="fd-shared-upstream", authoritative=True)
    jia = {
        "topology_id": "jia-shared-upstream",
        "capacities": {"N1": 6, "N2": 4, "U-shared": 6, "CORE": 100},
        "failure_domains": {"N1": "fd-n1", "N2": "fd-n2", "U-shared": "fd-shared-upstream"},
        "aliases": {"uplink-N1": "U-shared", "uplink-N2": "U-shared"},
        "paths": {
            "N1": ["N1", "uplink-N1", "CORE"],
            "N2": ["N2", "uplink-N2", "CORE"],
        },
        "confirm_equivalence": [["uplink-N1", "U-shared"], ["uplink-N2", "U-shared"]],
    }
    topo.add_hypothesis("jia", jia, evidence="two port pages; fibre label missing", at=at)

    # Candidate Yi: two physically independent upstreams.
    topo.resource("U1", capacity=6, kind="physical-upstream", domain_id="fd-n1", authoritative=True)
    topo.resource("U2", capacity=4, kind="physical-upstream", domain_id="fd-n2", authoritative=True)
    yi = {
        "topology_id": "yi-independent-upstreams",
        "capacities": {"N1": 6, "N2": 4, "U1": 6, "U2": 4, "CORE": 100},
        "failure_domains": {"N1": "fd-n1", "N2": "fd-n2", "U1": "fd-n1", "U2": "fd-n2"},
        "aliases": {"uplink-N1": "U1", "uplink-N2": "U2"},
        "paths": {
            "N1": ["N1", "uplink-N1", "CORE"],
            "N2": ["N2", "uplink-N2", "CORE"],
        },
        "confirm_equivalence": [["uplink-N1", "U1"], ["uplink-N2", "U2"]],
    }
    topo.add_hypothesis("yi", yi, evidence="two port pages; fibre label missing", at=at)

    # Independently metered low-speed emergency proxy for B.
    topo.resource("PROXY-B", capacity=3, kind="emergency-proxy",
                  domain_id="fd-proxy", metered=True, authoritative=True)

    # Raw probe pages remain untouched evidence with their SHA-256 digests.
    capture(db, "Eth1/1", [{"node": "N1", "capacity": 6}])
    capture(db, "Eth1/2", [{"node": "N2", "capacity": 4}])
    topo.alias_port("Eth1/1", "uplink-N1", node_id="N1", page_id="Eth1/1", reported_capacity=6)
    topo.alias_port("GigabitEthernet1/0/1", "uplink-N1", node_id="N1", page_id="Eth1/1")
    topo.alias_port("Eth1/2", "uplink-N2", node_id="N2", page_id="Eth1/2", reported_capacity=4)

    switch.add_customer({"customer_id": "A", "demand": 5, "minimum_bandwidth": 5})
    switch.add_customer({"customer_id": "B", "demand": 3, "minimum_bandwidth": 3})

    if adopt_old:
        switch.adopt_active_route({
            "route_id": "old-E-A", "customer_id": "A", "demand": 5,
            "path": ["E", "uplink-E", "CORE"], "latency_ms": 4, "at": at,
        })
        switch.adopt_active_route({
            "route_id": "old-E-B", "customer_id": "B", "demand": 3,
            "path": ["E", "uplink-E", "CORE"], "latency_ms": 4, "at": at,
        })

    if fail:
        topo.fail_domain(domain_e, at=at + 1)
        switch.mark_domain_failed({"domain_id": domain_e, "failed_node": "E", "at": at + 1})

    return {
        "db": db,
        "topology": topo,
        "switch": switch,
        "failed_domain": domain_e,
        "failed_node": "E",
        "pages": DRILL["pages"],
        "routes": {
            "A_n1": {"customer_id": "A", "demand": 5, "path_id": "N1",
                     "path": ["N1", "uplink-N1", "CORE"], "latency_ms": 4,
                     "old_route_id": "old-E-A"},
            "B_n2": {"customer_id": "B", "demand": 3, "path_id": "N2",
                     "path": ["N2", "uplink-N2", "CORE"], "latency_ms": 2,
                     "old_route_id": "old-E-B"},
            "B_proxy": {"customer_id": "B", "demand": 3,
                        "path": ["PROXY-B", "CORE"], "latency_ms": 20,
                        "latency_increase_ms": 20, "kind": "emergency",
                        "old_route_id": "old-E-B"},
            "same_domain_standby": {"customer_id": "A", "demand": 5,
                                    "path": ["ES", "uplink-E", "CORE"]},
        },
    }


def build_file_drill(path: str, **kwargs):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    return db, build_drill(db, **kwargs)
