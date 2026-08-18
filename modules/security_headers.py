"""
modules/security_headers.py
Checks baseline HTTP security headers. Single-signal checks (header present
or absent) top out at "high" confidence, never "confirmed", since a header
being absent is objectively verifiable but its real-world impact needs
context a human should confirm.
"""
from __future__ import annotations

from core.config import ScanConfig
from core.cvss import score_profile
from core.http_client import HttpClient
from core.schema import Confidence, Evidence, Finding, Severity

REQUIRED_HEADERS = {
    "Content-Security-Policy": ("CWE-693", Severity.MEDIUM),
    "Strict-Transport-Security": ("CWE-319", Severity.MEDIUM),
    "X-Content-Type-Options": ("CWE-693", Severity.LOW),
    "X-Frame-Options": ("CWE-1021", Severity.MEDIUM),
    "Referrer-Policy": ("CWE-200", Severity.LOW),
    "Permissions-Policy": ("CWE-693", Severity.LOW),
}


def run(client: HttpClient, config: ScanConfig, baseline_hook=None) -> list[Finding]:
    findings: list[Finding] = []
    resp = client.get(config.target)
    if baseline_hook:
        baseline_hook(config.target, resp.elapsed_ms, len(resp.text), resp.status_code)

    present = {k.lower() for k in resp.headers.keys()}

    for header, (cwe, severity) in REQUIRED_HEADERS.items():
        if header.lower() not in present:
            vector, score = score_profile("missing_header")
            findings.append(Finding(
                vulnerability_type="missing_security_header",
                title=f"Missing {header} header",
                endpoint=config.target,
                parameter=None,
                root_cause=f"missing_header:{header}",
                module="security_headers",
                severity=severity,
                confidence=Confidence.HIGH,
                description=f"The response from {config.target} does not include a {header} header.",
                remediation=f"Add a properly scoped {header} header to all HTTP responses.",
                cwe=cwe,
                owasp="A05:2025-Security Misconfiguration",
                cvss_vector=vector,
                cvss_score=score,
                likelihood="medium",
                evidence=Evidence(
                    request_summary=resp.request_summary,
                    response_summary=resp.response_summary,
                    signal_1=f"header_absent:{header}",
                ),
            ))

    server_hdr = resp.headers.get("Server", "")
    if server_hdr and any(c.isdigit() for c in server_hdr):
        vector, score = score_profile("missing_header")
        findings.append(Finding(
            vulnerability_type="information_disclosure",
            title="Server header discloses version information",
            endpoint=config.target,
            parameter=None,
            root_cause="server_header_version_disclosure",
            module="security_headers",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            description=f"The Server header ('{server_hdr}') discloses specific software/version information.",
            remediation="Suppress or generalize the Server header at the reverse proxy / web server level.",
            cwe="CWE-200",
            owasp="A05:2025-Security Misconfiguration",
            cvss_vector=vector,
            cvss_score=score,
            likelihood="low",
            evidence=Evidence(
                request_summary=resp.request_summary,
                response_summary=resp.response_summary,
                signal_1="server_header_contains_version",
            ),
        ))

    return findings
