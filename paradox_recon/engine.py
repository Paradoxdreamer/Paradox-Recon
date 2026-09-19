"""
Scan engine — the pipeline core.

    Target → Discovery plugins → Diagnostics plugins → Correlation → Report
"""

from __future__ import annotations

import datetime as dt
from typing import List, Optional, Sequence
from uuid import uuid4

from paradox_recon import __version__
from paradox_recon.config import Config
from paradox_recon.correlation import correlate
from paradox_recon.plugins import all_plugins, get_plugin, list_plugins
from paradox_recon.schema import ScanReport, Target
from paradox_recon.utils import color, C, parse_target


class ScanEngine:
    """
    Orchestrates plugins against one or more targets.

    Pipeline phases:
      1. discovery  — map the surface
      2. diagnostics — probe and measure
      3. correlation — risk from combined evidence
      4. (report handled by callers)
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()

    def resolve_plugins(self) -> List[str]:
        available = list_plugins()
        selected = self.config.plugins or available
        skip = set(self.config.skip_plugins or [])
        return [p for p in selected if p in available and p not in skip]

    def build_target(self, raw: str) -> Target:
        info = parse_target(raw)
        return Target(
            raw=info["raw"],
            hostname=info.get("hostname"),
            ip=info.get("ip"),
            port=info.get("port"),
            scheme=info.get("scheme"),
            kind=info.get("kind", "host"),
        )

    def run(
        self,
        targets: Sequence[str],
        plugins: Optional[Sequence[str]] = None,
    ) -> ScanReport:
        started = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        scan_id = str(uuid4())[:8]

        plugin_names = list(plugins) if plugins else self.resolve_plugins()
        registry = all_plugins()
        discovery = [n for n in plugin_names if registry[n].phase == "discovery"]
        diagnostics = [n for n in plugin_names if registry[n].phase == "diagnostics"]
        ordered = discovery + diagnostics

        target_objs = [self.build_target(t) for t in targets]
        report = ScanReport(
            scan_id=scan_id,
            version=__version__,
            started_at=started,
            targets=target_objs,
            plugins_run=ordered,
            meta={"config": self.config.to_dict()},
        )

        if not self.config.quiet:
            print(color(f"\n  ◆ Paradox Recon v{__version__}  scan={scan_id}", C.CYAN, C.BOLD))
            print(color(f"  targets={len(target_objs)}  plugins={', '.join(ordered)}\n", C.DIM))

        for t in target_objs:
            for name in ordered:
                cls = get_plugin(name)
                plugin = cls(self.config)
                if not self.config.quiet:
                    print(color(f"  → [{plugin.phase}] {name} @ {t.raw}", C.DIM))
                result = plugin.execute(t)
                report.results.append(result)
                if not self.config.quiet:
                    status = color("ok", C.GREEN) if result.success else color("fail", C.RED)
                    n = len(result.findings)
                    print(f"    {status}  {n} finding(s)  {result.duration_ms} ms")
                    if result.error and self.config.verbose:
                        print(color(f"    error: {result.error}", C.YELLOW))

        if not self.config.quiet:
            print(color("\n  → correlating findings…", C.DIM))
        report = correlate(report)
        report.finished_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if not self.config.quiet:
            rs = report.risk_summary
            grade = rs.get("grade", "?")
            print(color(f"\n  ◆ Risk grade: {grade}  score={rs.get('total_score')}  findings={rs.get('finding_count')}", C.BOLD))
            for sev, count in (rs.get("counts") or {}).items():
                if count:
                    print(f"    {sev}: {count}")
            print()

        return report
