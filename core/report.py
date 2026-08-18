"""
core/report.py
Requirement 5: generates a report matching real industry assessment
structure — cover page, scope & methodology, executive summary with a
security score, a risk matrix, CVSS vector+score per finding, CWE/OWASP
mapping, evidence, remediation, and a raw request/response appendix.

Requirement 3 (hardening): uses Jinja2 with autoescape=True, so all
finding-derived strings (which may originate from a malicious target's
responses) are HTML-escaped before rendering — a hostile target cannot
plant stored XSS into our own report.
"""
from __future__ import annotations

import datetime
import os

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.config import ScanConfig
from core.correlator import AttackChain
from core.schema import SEVERITY_ORDER, Finding, Severity

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates", "report")

LIKELIHOOD_LEVELS = ["low", "medium", "high"]
SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]


def compute_security_score(findings: list[Finding]) -> int:
    """
    100 minus weighted deductions per confirmed/high finding, floored at 0.
    Intentionally conservative and explained plainly in the report so the
    number cannot be mistaken for a formal risk-quantification standard.
    """
    weights = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
    conf_multiplier = {"confirmed": 1.0, "high": 0.75, "medium": 0.4, "low": 0.15}
    score = 100.0
    for f in findings:
        score -= weights.get(f.severity.value, 0) * conf_multiplier.get(f.confidence.value, 0.5)
    return max(0, round(score))


def build_risk_matrix(findings: list[Finding]) -> dict:
    matrix = {sev: {lik: 0 for lik in LIKELIHOOD_LEVELS} for sev in SEVERITY_LEVELS}
    for f in findings:
        sev = f.severity.value
        lik = f.likelihood if f.likelihood in LIKELIHOOD_LEVELS else "medium"
        matrix[sev][lik] += 1
    return matrix


def generate_html_report(
    findings: list[Finding],
    chains: list[AttackChain],
    config: ScanConfig,
    tool_availability_summary: str,
) -> str:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")

    security_score = compute_security_score(findings)
    risk_matrix = build_risk_matrix(findings)
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)

    counts_by_severity = {sev: sum(1 for f in findings if f.severity.value == sev) for sev in SEVERITY_LEVELS}
    counts_by_confidence = {
        c: sum(1 for f in findings if f.confidence.value == c)
        for c in ["confirmed", "high", "medium", "low"]
    }

    return template.render(
        target=config.target,
        generated_at=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        safe_mode=config.safe_mode,
        security_score=security_score,
        findings=findings_sorted,
        chains=chains,
        risk_matrix=risk_matrix,
        severity_levels=SEVERITY_LEVELS,
        likelihood_levels=LIKELIHOOD_LEVELS,
        counts_by_severity=counts_by_severity,
        counts_by_confidence=counts_by_confidence,
        tool_availability_summary=tool_availability_summary,
        total_findings=len(findings),
    )
