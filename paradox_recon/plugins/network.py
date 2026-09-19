"""Network discovery — public IP, interfaces, basic port probe."""

from __future__ import annotations

import concurrent.futures
import socket
from typing import List

from paradox_recon.plugins.base import Plugin
from paradox_recon.schema import Category, Finding, PluginResult, Severity, Target
from paradox_recon.utils import http_get, which, run_cmd

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443]


class NetworkPlugin(Plugin):
    name = "network"
    phase = "discovery"
    description = "Public IP, open common ports, basic connectivity"

    def run(self, target: Target) -> PluginResult:
        findings: List[Finding] = []
        raw = {}

        try:
            r = http_get("https://api.ipify.org?format=json", timeout=5,
                         headers={"User-Agent": self.config.user_agent})
            if r.get("body"):
                import json
                try:
                    ip = json.loads(r["body"]).get("ip")
                    raw["public_ip"] = ip
                    findings.append(Finding(
                        title=f"Scanner public IP: {ip}",
                        category=Category.NETWORK,
                        severity=Severity.INFO,
                        evidence={"public_ip": ip},
                        tags=["network", "egress"],
                        score=0.0,
                    ))
                except Exception:
                    pass
        except Exception:
            pass

        host = target.hostname or target.ip or target.raw
        ports = COMMON_PORTS[: self.config.max_ports]
        open_ports = []

        def check(port: int):
            try:
                with socket.create_connection((host, port), timeout=1.2):
                    return port
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.config.workers, 50)) as ex:
            for p in ex.map(check, ports):
                if p:
                    open_ports.append(p)
        open_ports.sort()
        raw["open_ports"] = open_ports

        if open_ports:
            risky = [p for p in open_ports if p in (21, 23, 445, 3389, 6379, 27017)]
            sev = Severity.HIGH if risky else Severity.INFO
            score = 5.0 if risky else 1.0
            findings.append(Finding(
                title=f"Open ports on {host}: {', '.join(map(str, open_ports))}",
                category=Category.NETWORK,
                severity=sev,
                description="Common-port probe results",
                evidence={"open_ports": open_ports, "risky": risky},
                remediation="Close unused services; restrict management ports",
                tags=["network", "ports"] + ([f"port-{p}" for p in risky]),
                score=score + len(risky) * 1.5,
            ))
        else:
            findings.append(Finding(
                title=f"No common ports open on {host}",
                category=Category.NETWORK,
                severity=Severity.INFO,
                evidence={"probed": ports},
                tags=["network", "ports"],
                score=0.0,
            ))

        return PluginResult(plugin=self.name, target=target.raw, findings=findings, raw=raw)
