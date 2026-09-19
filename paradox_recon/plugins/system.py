"""Local system diagnostics — device context for the scanner host."""

from __future__ import annotations

import platform
import socket
from pathlib import Path

from paradox_recon.plugins.base import Plugin
from paradox_recon.schema import Category, Finding, PluginResult, Severity, Target


class SystemPlugin(Plugin):
    name = "system"
    phase = "discovery"
    description = "Local host context (OS, CPU, RAM) — runs against scanner, not remote target"

    def run(self, target: Target) -> PluginResult:
        info = {
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        }
        if Path("/proc/meminfo").exists():
            mem = Path("/proc/meminfo").read_text()
            import re
            total = re.search(r"MemTotal:\s+(\d+)", mem)
            if total:
                info["ram_total_mb"] = int(total.group(1)) // 1024

        findings = [
            Finding(
                title=f"Scanner host: {info['hostname']} ({info['platform']} {info['machine']})",
                category=Category.SYSTEM,
                severity=Severity.INFO,
                evidence=info,
                tags=["system"],
                score=0.0,
            )
        ]
        return PluginResult(plugin=self.name, target="local", findings=findings, raw=info)
