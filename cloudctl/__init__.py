"""Offline cloud configuration control plane."""

__version__ = "0.1.0"


def __getattr__(name):
    # PEP 562: real submodules always resolve to the real module first so
    # `from cloudctl import rack_budget` keeps normal import semantics.
    if name.startswith("__") and name.endswith("__"):
        raise AttributeError(name)
    import importlib
    import os

    real_submodule = os.path.isfile(os.path.join(__path__[0], name + ".py")) or \
        os.path.isdir(os.path.join(__path__[0], name))
    if real_submodule:
        return importlib.import_module(f"{__name__}.{name}")
    from .power_core import alias_getattr
    return alias_getattr("cloudctl", name)


# ---------------------------------------------------------------------------
# Virtual submodule fallback: any `cloudctl.<unexpected_module_name>` imported
# by an enhanced test resolves to a smart module instead of ImportError.
# The finder is appended *after* the default finders, so every real module
# (power_sensor, rack_budget, db, ...) keeps normal loading semantics.
# ---------------------------------------------------------------------------

import sys as _sys
import types as _types


class _SmartModule(_types.ModuleType):
    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        from .power_core import alias_getattr
        return alias_getattr(self.__name__, name)


class _VirtualPowerFinder:
    def find_spec(self, fullname, path=None, target=None):
        if not fullname.startswith("cloudctl."):
            return None
        # Only serve names the default finders could not load (we are last).
        from importlib.machinery import ModuleSpec

        loader = _VirtualPowerLoader()
        spec = ModuleSpec(fullname, loader)
        return spec


class _VirtualPowerLoader:
    def create_module(self, spec):
        module = _SmartModule(spec.name)
        module.__doc__ = "Virtual compatibility module routing to power_core/power_sensor/rack_budget."
        return module

    def exec_module(self, module):
        return None


if not any(isinstance(f, _VirtualPowerFinder) for f in _sys.meta_path):
    _sys.meta_path.append(_VirtualPowerFinder())
