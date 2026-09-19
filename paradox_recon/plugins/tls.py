"""TLS certificate diagnostics."""

from __future__ import annotations

from paradox_recon.plugins.base import Plugin
from paradox_recon.schema import Category, Finding, PluginResult, Severity, Target
from paradox_recon.utils import tls_cert


class TLSPlugin(Plugin):
    name = "tls"
    phase = "diagnostics"
    description = "TLS certificate validity, expiry, SANs, protocol"

    def run(self, target: Target) -> PluginResult:
        host = target.hostname or target.raw
        port = target.port or 443
        info = tls_cert(host, port, timeout=self.config.timeout)
        findings = []

        if info.get("error"):
            findings.append(Finding(
                title=f"TLS handshake failed for {host}:{port}",
                category=Category.TLS,
                severity=Severity.HIGH,
                description=info["error"],
                evidence=info,
                remediation="Ensure a valid certificate is installed and the port is reachable",
                tags=["tls", "error"],
                score=7.0,
            ))
            return PluginResult(plugin=self.name, target=target.raw, findings=findings, raw=info)

        days = info.get("days_remaining")
        if days is not None:
            if days < 0:
                findings.append(Finding(
                    title="TLS certificate EXPIRED",
                    category=Category.TLS,
                    severity=Severity.CRITICAL,
                    description=f"Certificate expired {abs(days)} day(s) ago",
                    evidence=info,
                    remediation="Renew the certificate immediately",
                    tags=["tls", "expired"],
                    score=10.0,
                ))
            elif days <= 7:
                findings.append(Finding(
                    title=f"TLS certificate expires in {days} day(s)",
                    category=Category.TLS,
                    severity=Severity.HIGH,
                    description=f"Not after: {info.get('not_after')}",
                    evidence=info,
                    remediation="Renew the certificate before expiry",
                    tags=["tls", "expiring"],
                    score=8.0,
                ))
            elif days <= 30:
                findings.append(Finding(
                    title=f"TLS certificate expires in {days} day(s)",
                    category=Category.TLS,
                    severity=Severity.MEDIUM,
                    description=f"Not after: {info.get('not_after')}",
                    evidence=info,
                    remediation="Plan certificate renewal",
                    tags=["tls", "expiring"],
                    score=4.0,
                ))
            else:
                findings.append(Finding(
                    title=f"TLS certificate valid ({days} days remaining)",
                    category=Category.TLS,
                    severity=Severity.INFO,
                    evidence={
                        "version": info.get("version"),
                        "issuer": info.get("issuer"),
                        "sans_count": len(info.get("sans") or []),
                        "days_remaining": days,
                    },
                    tags=["tls", "ok"],
                    score=0.0,
                ))

        if info.get("version") and info["version"] in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            findings.append(Finding(
                title=f"Weak TLS protocol: {info['version']}",
                category=Category.TLS,
                severity=Severity.HIGH,
                description="Legacy protocol in use",
                evidence={"version": info["version"]},
                remediation="Disable TLS < 1.2 on the server",
                tags=["tls", "weak-protocol"],
                score=7.0,
            ))

        return PluginResult(plugin=self.name, target=target.raw, findings=findings, raw=info)
