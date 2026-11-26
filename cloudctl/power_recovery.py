"""Recoverable command generations after outage or terminal retry."""
from cloudctl.power_core import alias_getattr


def __getattr__(name):
    return alias_getattr(__name__, name)
