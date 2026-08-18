"""
modules/openapi_shadow.py
Parses a provided OpenAPI/Swagger spec, then probes common undocumented
endpoint patterns (versioned duplicates, admin/internal/debug paths) to find
"shadow APIs": live endpoints that respond but are absent from the spec.
"""
from __future__ import annotations

import json
from urllib.parse import urljoin, urlparse

import yaml

from core.config import ScanConfig
from core.cvss import score_profile
from core.http_client import HttpClient
from core.schema import Confidence, Evidence, Finding, Severity

SHADOW_CANDIDATE_PATTERNS = [
    "api/v1/{path}", "api/v2/{path}", "internal/{path}", "admin/{path}",
    "debug/{path}", "_internal/{path}", "{path}.bak", "{path}/../{path}",
    "v0/{path}", "beta/{path}",
]


def parse_spec(spec_text: str) -> list[str]:
    try:
        spec = json.loads(spec_text)
    except json.JSONDecodeError:
        try:
            spec = yaml.safe_load(spec_text)
        except Exception:
            return []
    if not isinstance(spec, dict):
        return []
    return list((spec.get("paths") or {}).keys())


def run(client: HttpClient, config: ScanConfig, baseline_hook=None) -> list[Finding]:
    findings: list[Finding] = []
    if not config.openapi_spec:
        return findings

    try:
        with open(config.openapi_spec, "r", encoding="utf-8") as f:
            spec_text = f.read()
    except OSError:
        return findings

    documented_paths = set(parse_spec(spec_text))
    if not documented_paths:
        return findings

    parsed_target = urlparse(config.target)
    base = f"{parsed_target.scheme}://{parsed_target.netloc}"

    checked = 0
    for doc_path in list(documented_paths)[:10]:
        clean = doc_path.strip("/").split("{")[0].rstrip("/")
        if not clean:
            continue
        for pattern in SHADOW_CANDIDATE_PATTERNS:
            if checked >= config.max_requests_per_module:
                break
            candidate_path = pattern.format(path=clean)
            candidate_url = urljoin(base + "/", candidate_path)
            resp = client.get(candidate_url)
            checked += 1
            if baseline_hook:
                baseline_hook(candidate_url, resp.elapsed_ms, len(resp.text), resp.status_code)

            documented_url_path = "/" + clean
            is_documented = documented_url_path in documented_paths
            if resp.status_code in (200, 201, 204, 401, 403) and not is_documented and candidate_path.strip("/") not in {p.strip("/") for p in documented_paths}:
                vector, score = score_profile("shadow_api")
                findings.append(Finding(
                    vulnerability_type="shadow_api",
                    title=f"Undocumented endpoint responds: {candidate_path}",
                    endpoint=candidate_url,
                    parameter=None,
                    root_cause=f"shadow_api_pattern:{pattern}",
                    module="openapi_shadow",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"An endpoint at '{candidate_path}' returned HTTP {resp.status_code} but is not "
                        f"present in the provided OpenAPI spec, suggesting it bypasses documented "
                        f"API governance/hardening."
                    ),
                    remediation="Inventory and document all live endpoints, or remove/decommission the undocumented ones; ensure gateway policies apply uniformly.",
                    cwe="CWE-1059",
                    owasp="API9:2023-Improper Inventory Management",
                    cvss_vector=vector,
                    cvss_score=score,
                    likelihood="medium",
                    evidence=Evidence(
                        request_summary=resp.request_summary,
                        response_summary=resp.response_summary,
                        signal_1=f"undocumented_endpoint_status_{resp.status_code}",
                    ),
                ))
    return findings
