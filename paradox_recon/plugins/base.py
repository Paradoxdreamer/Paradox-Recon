"""Plugin base class — every capability is a Plugin."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import ClassVar, Dict, List, Type

from paradox_recon.config import Config
from paradox_recon.schema import Finding, PluginResult, Target


class Plugin(ABC):
    """
    Base class for all Paradox Recon plugins.

    Subclass, set `name` / `phase` / `description`, implement `run()`.
    Plugins auto-register on import.
    """

    name: ClassVar[str] = ""
    phase: ClassVar[str] = "diagnostics"  # discovery | diagnostics
    description: ClassVar[str] = ""
    registry: ClassVar[Dict[str, Type["Plugin"]]] = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.name:
            Plugin.registry[cls.name] = cls

    def __init__(self, config: Config):
        self.config = config

    @abstractmethod
    def run(self, target: Target) -> PluginResult:
        """Execute against a target and return structured findings."""

    def execute(self, target: Target) -> PluginResult:
        """Timed wrapper around run()."""
        t0 = time.time()
        try:
            result = self.run(target)
            result.duration_ms = round((time.time() - t0) * 1000, 1)
            result.plugin = self.name
            result.target = target.raw
            for f in result.findings:
                f.plugin = self.name
                f.target = target.raw
            return result
        except Exception as e:
            return PluginResult(
                plugin=self.name,
                target=target.raw,
                success=False,
                error=str(e),
                duration_ms=round((time.time() - t0) * 1000, 1),
            )
