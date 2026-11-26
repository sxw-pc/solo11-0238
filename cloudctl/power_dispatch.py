"""Executable PDU limit dispatch and controller interaction."""
from cloudctl.power_core import alias_getattr


def __getattr__(name):
    return alias_getattr(__name__, name)
