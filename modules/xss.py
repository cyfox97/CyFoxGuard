"""
modules/xss.py
Reflected XSS detection via a unique canary marker: signal 1 = payload
reflected unescaped in the response; signal 2 = reflection occurs in an
HTML-executable context (inside a tag/attribute/script, not inside an
already-escaped text node). Both together => confirmed.
"""
from __future__ import annotations

import re
import uuid
from urllib.parse import urlencode, urlparse, parse_qs

from core.config import ScanConfig
from core.cvss import score_profile
from core.external_tools import ToolAvailability, run_dalfox_probe
from core.http_client import HttpClient
from core.schema import Confidence, Evidence, Finding, Severity

FULL_TAGS = ["<script>", "<img src=x onerror=", "<svg onload=", "'\"><script>", "javascript:"]
SAFE_TAGS = ["<script>"]

EXECUTABLE_CONTEXT_PATTERNS = [
    re.compile(r"<script[^>]*>[^<]*{marker}", re.I),
    re.compile(r"on\w+\s*=\s*[\"']?[^\"'>]*{marker}", re.I),
    re.compile(r"<[a-z]+[^>]*\s(src|href)\s*=\s*[\"']?javascript:[^\"'>]*{marker}", re.I),
]


def run(client: HttpClient, config: ScanConfig, tools: ToolAvailability, baseline_hook=None) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(config.target)
    params = parse_qs(parsed.query) or {"q": ["test"]}

    tags = SAFE_TAGS if config.safe_mode else FULL_TAGS

    for param_name in list(params.keys())[:5]:
        for tag in tags:
            marker = f"cfx{uuid.uuid4().hex[:8]}"
            payload = f"{tag}{marker}"
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            resp = client.get(test_url)
            if baseline_hook:
                baseline_hook(config.target, resp.elapsed_ms, len(resp.text), resp.status_code)

            reflected_raw = payload in resp.text
            reflected_unescaped = marker in resp.text and f"&lt;" not in resp.text.split(marker)[0][-20:]

            if not reflected_raw and not reflected_unescaped:
                continue

            executable_context = any(
                pat.pattern.format(marker=re.escape(marker)) and re.search(pat.pattern.replace("{marker}", re.escape(marker)), resp.text, re.I)
                for pat in EXECUTABLE_CONTEXT_PATTERNS
            )

            signals = ["unescaped_reflection"]
            if executable_context:
                signals.append("html_executable_context")

            confidence = Confidence.CONFIRMED if len(signals) >= 2 else Confidence.HIGH
            profile = "xss_reflected"
            vector, score = score_profile(profile)

            findings.append(Finding(
                vulnerability_type="xss",
                title=f"Reflected XSS in parameter '{param_name}'",
                endpoint=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                parameter=param_name,
                root_cause=f"xss_signal:{'+'.join(signals)}",
                module="xss",
                severity=Severity.HIGH if confidence == Confidence.CONFIRMED else Severity.MEDIUM,
                confidence=confidence,
                description=(
                    f"A unique marker injected via '{param_name}' was reflected "
                    f"{'in an HTML-executable context' if executable_context else 'without HTML-encoding'} in the response."
                ),
                remediation="Context-aware output encoding on every reflection point; adopt a strict Content-Security-Policy as defense in depth.",
                cwe="CWE-79",
                owasp="A03:2025-Injection",
                cvss_vector=vector,
                cvss_score=score,
                likelihood="high" if confidence == Confidence.CONFIRMED else "medium",
                evidence=Evidence(
                    request_summary=resp.request_summary,
                    response_summary=resp.response_summary,
                    signal_1=signals[0],
                    signal_2=signals[1] if len(signals) > 1 else None,
                ),
            ))
            if config.safe_mode:
                break

    if tools.dalfox and not config.safe_mode:
        dalfox_out = run_dalfox_probe(config.target, config.safe_mode)
        if "[POC]" in dalfox_out or "vulnerable" in dalfox_out.lower():
            vector, score = score_profile("xss_reflected")
            findings.append(Finding(
                vulnerability_type="xss",
                title="dalfox confirmed reflected XSS",
                endpoint=config.target,
                parameter=None,
                root_cause="xss_signal:dalfox_confirmation",
                module="xss",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description="dalfox independently confirmed a reflected XSS, corroborating the built-in probe.",
                remediation="Context-aware output encoding on every reflection point.",
                cwe="CWE-79",
                owasp="A03:2025-Injection",
                cvss_vector=vector,
                cvss_score=score,
                likelihood="high",
                evidence=Evidence(
                    request_summary=f"dalfox url {config.target}",
                    response_summary="dalfox stdout (truncated in report appendix)",
                    signal_1="dalfox_tool_confirmation",
                    signal_2="external_tool_independent_engine",
                ),
            ))

    return findings
