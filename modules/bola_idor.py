"""
modules/bola_idor.py
Multi-identity BOLA/IDOR testing: with 2+ configured identities (e.g. userA,
userB), fetch a resource as identity A, then request the SAME resource ID
using identity B's credentials. Signal 1 = HTTP 200 with identity B's
creds; signal 2 = the returned body contains identity-A-owned data (not a
generic/empty/error payload) confirmed via a simple content-overlap check.
Requires config.identities: list of {"name": str, "headers": dict}.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from core.config import ScanConfig
from core.cvss import score_profile
from core.http_client import HttpClient
from core.schema import Confidence, Evidence, Finding, Severity

ID_IN_PATH_RE = re.compile(r"/(\d{1,10})(?:/|$)")


def run(client: HttpClient, config: ScanConfig, baseline_hook=None) -> list[Finding]:
    findings: list[Finding] = []
    if len(config.identities) < 2:
        return findings  # requires at least two identities to test cross-access

    identity_a, identity_b = config.identities[0], config.identities[1]

    resp_a = client.get(config.target, identity_headers=identity_a.get("headers", {}))
    if baseline_hook:
        baseline_hook(config.target, resp_a.elapsed_ms, len(resp_a.text), resp_a.status_code)
    if resp_a.status_code not in (200, 201):
        return findings

    match = ID_IN_PATH_RE.search(urlparse(config.target).path)
    resource_id = match.group(1) if match else None

    resp_b = client.get(config.target, identity_headers=identity_b.get("headers", {}))

    if resp_b.status_code not in (200, 201):
        return findings

    # Signal 1: identity B, who should not own this resource, gets a
    # successful response for identity A's resource.
    signal_1 = f"identity_{identity_b.get('name','B')}_received_http_{resp_b.status_code}"

    # Signal 2: substantive content overlap between the two responses,
    # indicating the same underlying record was actually returned (not just
    # a coincidental 200 with an empty/error body).
    overlap_ratio = _content_overlap(resp_a.text, resp_b.text)
    signal_2 = f"content_overlap_{overlap_ratio:.0%}" if overlap_ratio > 0.6 else None

    signals = [signal_1] + ([signal_2] if signal_2 else [])
    confidence = Confidence.CONFIRMED if signal_2 else Confidence.MEDIUM
    profile = "bola_confirmed" if confidence == Confidence.CONFIRMED else "bola_suspected"
    vector, score = score_profile(profile)

    findings.append(Finding(
        vulnerability_type="bola_idor",
        title=f"Possible BOLA/IDOR{f' on resource {resource_id}' if resource_id else ''}",
        endpoint=config.target,
        parameter=resource_id,
        root_cause=f"bola_signal:{'+'.join(s.split('_')[0] for s in signals)}",
        module="bola_idor",
        severity=Severity.CRITICAL if confidence == Confidence.CONFIRMED else Severity.HIGH,
        confidence=confidence,
        description=(
            f"Identity '{identity_b.get('name','B')}' was able to retrieve a resource "
            f"{'and its content matched what identity ' + identity_a.get('name','A') + ' owns' if signal_2 else 'that returned a successful status code'} "
            f"at {config.target}, despite not being the resource owner."
        ),
        remediation="Enforce object-level authorization checks server-side on every request, verifying the authenticated identity owns or is permitted to access the requested resource ID.",
        cwe="CWE-639",
        owasp="API1:2023-Broken Object Level Authorization",
        cvss_vector=vector,
        cvss_score=score,
        likelihood="high" if confidence == Confidence.CONFIRMED else "medium",
        evidence=Evidence(
            request_summary=resp_b.request_summary,
            response_summary=resp_b.response_summary,
            signal_1=signal_1,
            signal_2=signal_2,
        ),
    ))
    return findings


def _content_overlap(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    set_a, set_b = set(a.split()), set(b.split())
    if not set_a or not set_b:
        return 0.0
    return len(set_a & set_b) / len(set_a | set_b)
