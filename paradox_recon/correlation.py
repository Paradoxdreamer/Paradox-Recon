"""
Correlation layer — turn raw findings into risk.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from paradox_recon.schema import Category, Finding, ScanReport, Severity


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def correlate(report: ScanReport) -> ScanReport:
    all_findings: List[Finding] = []
    for result in report.results:
        all_findings.extend(result.findings)

    extra = _cross_rules(all_findings)
    all_findings.extend(extra)

    def sort_key(f: Finding):
        sev = f.severity if isinstance(f.severity, Severity) else Severity.INFO
        return (-SEVERITY_ORDER.get(sev, 0), -f.score)

    all_findings.sort(key=sort_key)
    report.findings = all_findings
    report.risk_summary = _risk_summary(all_findings)
    return report


def _cross_rules(findings: List[Finding]) -> List[Finding]:
    extra: List[Finding] = []
    has_expired = any("expired" in f.tags for f in findings)
    if has_expired:
        extra.append(Finding(
            title="Correlated: expired certificate on live service",
            category=Category.CORRELATION,
            severity=Severity.CRITICAL,
            description="TLS expiry combined with reachable service increases interception risk",
            tags=["correlation", "tls"],
            score=9.5,
            plugin="correlation",
        ))

    risky_ports = any("port-3389" in f.tags or "port-445" in f.tags or "port-6379" in f.tags for f in findings)
    if risky_ports:
        extra.append(Finding(
            title="Correlated: high-risk management/database ports exposed",
            category=Category.CORRELATION,
            severity=Severity.HIGH,
            description="RDP, SMB, or Redis-like ports appear open — restrict to trusted networks",
            tags=["correlation", "network"],
            score=8.0,
            plugin="correlation",
        ))

    email_issues = [f for f in findings if "email" in f.tags and f.severity in (Severity.MEDIUM, Severity.HIGH)]
    if len(email_issues) >= 2:
        extra.append(Finding(
            title="Correlated: weak email authentication posture",
            category=Category.CORRELATION,
            severity=Severity.MEDIUM,
            description="Multiple SPF/DMARC/DKIM gaps increase spoofing risk",
            evidence={"related": [f.title for f in email_issues]},
            remediation="Deploy SPF (-all), DMARC (p=quarantine+), and DKIM",
            tags=["correlation", "email"],
            score=5.5,
            plugin="correlation",
        ))

    return extra


def _risk_summary(findings: List[Finding]) -> Dict:
    counts = defaultdict(int)
    total_score = 0.0
    top = []
    for f in findings:
        sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
        counts[sev] += 1
        total_score += f.score
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
            top.append({"title": f.title, "severity": sev, "score": f.score, "plugin": f.plugin})

    if counts.get("critical", 0) > 0 or total_score >= 25:
        grade = "F"
    elif counts.get("high", 0) >= 2 or total_score >= 15:
        grade = "D"
    elif counts.get("high", 0) >= 1 or total_score >= 10:
        grade = "C"
    elif counts.get("medium", 0) >= 2 or total_score >= 5:
        grade = "B"
    else:
        grade = "A"

    return {
        "grade": grade,
        "total_score": round(total_score, 1),
        "counts": dict(counts),
        "finding_count": len(findings),
        "top_risks": top[:10],
    }
