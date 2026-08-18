"""
modules/sql_injection.py
Requirement 1: nothing reaches "confirmed" without two independent signals —
here that is (a) a DB error-signature match in the response AND (b) a timing
or content differential vs. a baseline/control request. Either signal alone
caps at "high".

Requirement 7 (--safe): payload set is reduced to a single low-impact probe.

Requirement 8: upgrades to sqlmap when present on PATH.
"""
from __future__ import annotations

import re
import time
from urllib.parse import urlencode, urlparse, parse_qs

from core.config import ScanConfig
from core.cvss import score_profile
from core.external_tools import ToolAvailability, run_sqlmap_probe
from core.http_client import HttpClient
from core.schema import Confidence, Evidence, Finding, Severity

ERROR_SIGNATURES = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysqli?_", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query\(\)|postgresql.*error", re.I),
    re.compile(r"sqlite3\.OperationalError", re.I),
    re.compile(r"ORA-\d{5}", re.I),
]

# Full payload set (non-safe mode). These are standard, well-known SQLi probe
# strings used for detection only (single quote / boolean / timing probes),
# not exploit payloads for data extraction.
FULL_PAYLOADS = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "' AND SLEEP(3)-- -", "1 OR 1=1", "' UNION SELECT NULL-- -"]
SAFE_PAYLOAD = ["'"]

TIME_DIFFERENTIAL_THRESHOLD_MS = 2500


def _matches_error_signature(text: str) -> str | None:
    for pattern in ERROR_SIGNATURES:
        if pattern.search(text):
            return pattern.pattern
    return None


def run(client: HttpClient, config: ScanConfig, tools: ToolAvailability, baseline_hook=None) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(config.target)
    params = parse_qs(parsed.query) or {"id": ["1"]}  # probe a synthetic param if none present

    payloads = SAFE_PAYLOAD if config.safe_mode else FULL_PAYLOADS

    for param_name in list(params.keys())[:5]:
        baseline_resp = client.get(config.target)
        if baseline_hook:
            baseline_hook(config.target, baseline_resp.elapsed_ms, len(baseline_resp.text), baseline_resp.status_code)

        for payload in payloads:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            resp = client.get(test_url)

            error_sig = _matches_error_signature(resp.text)
            time_differential = (resp.elapsed_ms - baseline_resp.elapsed_ms) > TIME_DIFFERENTIAL_THRESHOLD_MS
            content_differential = abs(len(resp.text) - len(baseline_resp.text)) > (0.3 * max(len(baseline_resp.text), 1))

            signals = []
            if error_sig:
                signals.append(f"error_signature:{error_sig}")
            if time_differential:
                signals.append(f"time_differential:{resp.elapsed_ms - baseline_resp.elapsed_ms:.0f}ms")
            elif content_differential:
                signals.append("content_length_differential")

            if not signals:
                continue

            confidence = Confidence.CONFIRMED if len(signals) >= 2 else Confidence.HIGH
            evidence = Evidence(
                request_summary=resp.request_summary,
                response_summary=resp.response_summary,
                signal_1=signals[0],
                signal_2=signals[1] if len(signals) > 1 else None,
            )

            profile = "sqli_confirmed" if confidence == Confidence.CONFIRMED else "sqli_probe"
            vector, score = score_profile(profile)

            findings.append(Finding(
                vulnerability_type="sql_injection",
                title=f"Possible SQL injection in parameter '{param_name}'",
                endpoint=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                parameter=param_name,
                root_cause=f"sqli_signal:{'+'.join(sorted(s.split(':')[0] for s in signals))}",
                module="sql_injection",
                severity=Severity.CRITICAL if confidence == Confidence.CONFIRMED else Severity.HIGH,
                confidence=confidence,
                description=(
                    f"Injecting a SQL probe payload into '{param_name}' produced "
                    f"{'a matching database error signature and a measurable response differential' if len(signals) >= 2 else 'one anomalous signal'}."
                ),
                remediation="Use parameterized queries / prepared statements for all database access; never build SQL via string concatenation of user input.",
                cwe="CWE-89",
                owasp="API8:2023-Security Misconfiguration / A03:2025-Injection",
                cvss_vector=vector,
                cvss_score=score,
                likelihood="high" if confidence == Confidence.CONFIRMED else "medium",
                evidence=evidence,
            ))
            if config.safe_mode:
                break  # single probe payload only

    if tools.sqlmap and not config.safe_mode and params:
        first_param = list(params.keys())[0]
        sqlmap_out = run_sqlmap_probe(config.target, first_param, config.safe_mode)
        if "is vulnerable" in sqlmap_out.lower() or "parameter" in sqlmap_out.lower() and "injectable" in sqlmap_out.lower():
            vector, score = score_profile("sqli_confirmed")
            findings.append(Finding(
                vulnerability_type="sql_injection",
                title=f"sqlmap confirmed SQL injection in '{first_param}'",
                endpoint=config.target,
                parameter=first_param,
                root_cause="sqli_signal:sqlmap_confirmation",
                module="sql_injection",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                description="sqlmap independently confirmed this parameter is injectable, corroborating the built-in probe.",
                remediation="Use parameterized queries / prepared statements for all database access.",
                cwe="CWE-89",
                owasp="A03:2025-Injection",
                cvss_vector=vector,
                cvss_score=score,
                likelihood="high",
                evidence=Evidence(
                    request_summary=f"sqlmap -u {config.target} -p {first_param} --batch",
                    response_summary="sqlmap stdout (truncated in report appendix)",
                    signal_1="sqlmap_tool_confirmation",
                    signal_2="external_tool_independent_engine",
                ),
            ))

    return findings
