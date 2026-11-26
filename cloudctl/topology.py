"""Electrical measurement topology and duplicate-clamp collapse."""
from cloudctl.power_core import alias_getattr


def __getattr__(name):
    return alias_getattr(__name__, name)
