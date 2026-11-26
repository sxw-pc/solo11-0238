"""Thermal window computation over the common clock range."""
from cloudctl.power_core import alias_getattr


def __getattr__(name):
    return alias_getattr(__name__, name)
