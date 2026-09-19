"""Plugin registry — discover and load all available plugins."""

from __future__ import annotations

from typing import Dict, List, Type

from paradox_recon.plugins.base import Plugin

# Import concrete plugins so they register
from paradox_recon.plugins import dns as _dns  # noqa: F401
from paradox_recon.plugins import web as _web  # noqa: F401
from paradox_recon.plugins import tls as _tls  # noqa: F401
from paradox_recon.plugins import network as _network  # noqa: F401
from paradox_recon.plugins import security as _security  # noqa: F401
from paradox_recon.plugins import email_auth as _email  # noqa: F401
from paradox_recon.plugins import system as _system  # noqa: F401


def all_plugins() -> Dict[str, Type[Plugin]]:
    return dict(Plugin.registry)


def list_plugins() -> List[str]:
    return sorted(Plugin.registry.keys())


def get_plugin(name: str) -> Type[Plugin]:
    if name not in Plugin.registry:
        raise KeyError(f"Unknown plugin: {name}. Available: {', '.join(list_plugins())}")
    return Plugin.registry[name]
