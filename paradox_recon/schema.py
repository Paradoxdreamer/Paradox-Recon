"""
Structured result schema used by every plugin and the scan engine.

Every module emits Findings. The engine collects them, correlation
enriches them, and reporters render them. One schema end-to-end.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    NETWORK = "network"
    DNS = "dns"
    WEB = "web"
    TLS = "tls"
    SECURITY = "security"
    EMAIL = "email"
    SYSTEM = "system"
    CLOUD = "cloud"
    CORRELATION = "correlation"


@dataclass
class Target:
    """Scan target — host, URL, IP, or domain."""

    raw: str
    hostname: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    scheme: Optional[str] = None
    kind: str = "host"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """Single atomic observation or risk signal. Plugins MUST emit Findings."""

    title: str
    category: Category
    severity: Severity = Severity.INFO
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    plugin: str = ""
    target: Optional[str] = None
    id: str = field(default_factory=lambda: str(uuid4())[:8])
    timestamp: str = field(
        default_factory=lambda: dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    tags: List[str] = field(default_factory=list)
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value if isinstance(self.category, Category) else self.category
        d["severity"] = self.severity.value if isinstance(self.severity, Severity) else self.severity
        return d


@dataclass
class PluginResult:
    """Output of one plugin run."""

    plugin: str
    target: str
    success: bool = True
    error: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin": self.plugin,
            "target": self.target,
            "success": self.success,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
            "raw": self.raw,
            "duration_ms": self.duration_ms,
        }


@dataclass
class ScanReport:
    """Full pipeline output — the single artifact every reporter consumes."""

    scan_id: str
    version: str
    started_at: str
    finished_at: str = ""
    targets: List[Target] = field(default_factory=list)
    plugins_run: List[str] = field(default_factory=list)
    results: List[PluginResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    risk_summary: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "version": self.version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "targets": [t.to_dict() for t in self.targets],
            "plugins_run": self.plugins_run,
            "results": [r.to_dict() for r in self.results],
            "findings": [f.to_dict() for f in self.findings],
            "risk_summary": self.risk_summary,
            "meta": self.meta,
        }

    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        buckets: Dict[str, List[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
            buckets.setdefault(sev, []).append(f)
        return buckets
