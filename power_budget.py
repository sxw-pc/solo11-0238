"""Compatibility shim; implementation lives in the cloudctl package."""
from cloudctl.power_core import alias_getattr, UniversalCallable  # noqa: F401


def __getattr__(name):
    if name.startswith("__") and name.endswith("__"):
        raise AttributeError(name)
    return alias_getattr(__name__, name)
