"""DNS discovery plugin."""

from __future__ import annotations

from paradox_recon.plugins.base import Plugin
from paradox_recon.schema import Category, Finding, PluginResult, Severity, Target
from paradox_recon.utils import dns_query


class DNSPlugin(Plugin):
    name = "dns"
    phase = "discovery"
    description = "DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)"

    def run(self, target: Target) -> PluginResult:
        host = target.hostname or target.raw
        findings = []
        raw = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            vals = dns_query(host, rtype)
            raw[rtype] = vals
            if vals:
                findings.append(Finding(
                    title=f"DNS {rtype} records for {host}",
                    category=Category.DNS,
                    severity=Severity.INFO,
                    description=f"Found {len(vals)} {rtype} record(s)",
                    evidence={"type": rtype, "records": vals},
                    tags=["dns", rtype.lower()],
                    score=0.0,
                ))
        if not any(raw.values()):
            findings.append(Finding(
                title=f"No DNS records resolved for {host}",
                category=Category.DNS,
                severity=Severity.LOW,
                description="Host may be unreachable or not registered in DNS",
                evidence={"host": host},
                tags=["dns", "unresolved"],
                score=1.0,
            ))
        txts = raw.get("TXT") or []
        has_spf = any("v=spf1" in t.lower() for t in txts)
        if not has_spf and target.kind in ("domain", "host", "url"):
            findings.append(Finding(
                title="No SPF record in TXT",
                category=Category.EMAIL,
                severity=Severity.LOW,
                description="Domain TXT records do not include an SPF policy",
                evidence={"txt": txts},
                remediation="Publish a v=spf1 TXT record for the domain",
                tags=["email", "spf"],
                score=2.0,
            ))
        return PluginResult(plugin=self.name, target=target.raw, findings=findings, raw=raw)
