"""Power controller orders, receipts and safe next commands."""
from cloudctl.power_core import alias_getattr


def __getattr__(name):
    return alias_getattr(__name__, name)
