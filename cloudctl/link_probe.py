"""Link probe evidence entry point.

The persistence and equivalence logic lives in physical_topology.
"""
from .physical_topology import (  # noqa: F401
    TopologyRegistry,
    capture_link_probe,
    record_link_probe,
    record_probe,
)

capture = capture_link_probe

__all__ = ["capture", "capture_link_probe", "record_link_probe", "record_probe", "TopologyRegistry"]
