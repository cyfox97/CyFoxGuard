"""
modules/rate_limiting.py
Requirement 7 (--safe): this module's flood test is entirely SKIPPED in
--safe mode (config.run_rate_limit_flood is False), since it is the one
check with real potential to disrupt a live production target. In normal
mode it sends a bounded burst and checks for 429/Retry-After enforcement.
"""
from __future__ import annotations

from core.config import ScanConfig
from core.cvss import score_profile
from core.http_client import HttpClient
from core.schema import Confidence, Evidence, Finding, Severity

BURST_SIZE = 25  # bounded burst, not an unbounded flood


def run(client: HttpClient, config: ScanConfig, baseline_hook=None) -> list[Finding]:
    findings: list[Finding] = []

    if not config.run_rate_limit_flood:
        findings.append(Finding(
            vulnerability_type="rate_limit_skipped",
            title="Rate-limit flood test skipped (--safe mode)",
            endpoint=config.target,
            parameter=None,
            root_cause="safe_mode_skip",
            module="rate_limiting",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            description="--safe mode is active; the rate-limit burst test was not run to avoid any risk of disrupting a live, authorized production target.",
            remediation="Re-run without --safe against a non-production or explicitly rate-limit-test-approved target to evaluate throttling.",
            cwe="",
            owasp="",
            likelihood="low",
            evidence=Evidence(
                request_summary="N/A - test skipped",
                response_summary="N/A - test skipped",
                signal_1="safe_mode_active",
            ),
        ))
        return findings

    statuses = []
    last_resp = None
    for _ in range(BURST_SIZE):
        resp = client.get(config.target)
        statuses.append(resp.status_code)
        last_resp = resp
        if baseline_hook:
            baseline_hook(config.target, resp.elapsed_ms, len(resp.text), resp.status_code)

    throttled = any(s == 429 for s in statuses)
    has_retry_after = bool(last_resp and "Retry-After" in last_resp.headers)

    if not throttled:
        vector, score = score_profile("rate_limit_missing")
        findings.append(Finding(
            vulnerability_type="rate_limit_missing",
            title="No rate limiting observed under burst load",
            endpoint=config.target,
            parameter=None,
            root_cause="rate_limit_absent_burst_test",
            module="rate_limiting",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description=f"A bounded burst of {BURST_SIZE} requests completed with no HTTP 429 response, suggesting no rate limiting is enforced on this endpoint.",
            remediation="Implement per-identity and per-IP rate limiting with 429 responses and a Retry-After header on this and equivalent endpoints.",
            cwe="CWE-770",
            owasp="API4:2023-Unrestricted Resource Consumption",
            cvss_vector=vector,
            cvss_score=score,
            likelihood="medium",
            evidence=Evidence(
                request_summary=f"{BURST_SIZE}x GET {config.target}",
                response_summary=f"status codes observed: {sorted(set(statuses))}",
                signal_1="no_429_in_burst",
            ),
        ))
    elif not has_retry_after:
        vector, score = score_profile("missing_header")
        findings.append(Finding(
            vulnerability_type="rate_limit_missing",
            title="Rate limiting enforced but no Retry-After header",
            endpoint=config.target,
            parameter=None,
            root_cause="rate_limit_missing_retry_after",
            module="rate_limiting",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            description="429 responses were observed but did not include a Retry-After header, making it harder for well-behaved clients to back off correctly.",
            remediation="Include a Retry-After header on all 429 responses.",
            cwe="CWE-770",
            owasp="API4:2023-Unrestricted Resource Consumption",
            cvss_vector=vector,
            cvss_score=score,
            likelihood="low",
            evidence=Evidence(
                request_summary=f"{BURST_SIZE}x GET {config.target}",
                response_summary=f"status codes observed: {sorted(set(statuses))}",
                signal_1="429_without_retry_after",
            ),
        ))

    return findings
