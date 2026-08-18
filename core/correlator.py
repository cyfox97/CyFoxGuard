"""
core/correlator.py
Requirement 10: deterministic, rule-based attack-chain correlation
(e.g. weak JWT + confirmed BOLA = account-takeover chain), risk-scored 0-100.
Optional AI narrative enrichment via ANTHROPIC_API_KEY that ONLY rewrites the
text of an already-confirmed chain — it never decides whether a chain exists
or what its risk score is. That decision is 100% rule-based, on purpose.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from core.schema import Confidence, Finding
from core.cvss import score_profile
from core.logging_utils import get_logger

log = get_logger("correlator")


@dataclass
class AttackChain:
    name: str
    description: str
    finding_ids: list[str]
    risk_score: int  # 0-100
    cvss_vector: str
    cvss_score: float
    narrative: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "finding_ids": self.finding_ids,
            "risk_score": self.risk_score,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "narrative": self.narrative,
        }


def _is(f: Finding, vuln_type: str, min_confidence: Confidence = Confidence.MEDIUM) -> bool:
    order = {"low": 0, "medium": 1, "high": 2, "confirmed": 3}
    return f.vulnerability_type == vuln_type and order[f.confidence.value] >= order[min_confidence.value]


# --- Deterministic chain rules -------------------------------------------------
# Each rule is a pure function: (findings) -> list[AttackChain]. Adding a rule
# never requires touching the AI enrichment step.

def rule_jwt_bola_account_takeover(findings: list[Finding]) -> list[AttackChain]:
    jwt_weak = [f for f in findings if _is(f, "jwt_alg_none", Confidence.HIGH) or _is(f, "jwt_weak_secret", Confidence.HIGH)]
    bola = [f for f in findings if _is(f, "bola_idor", Confidence.CONFIRMED)]
    chains = []
    if jwt_weak and bola:
        vector, score = score_profile("account_takeover_chain")
        chains.append(AttackChain(
            name="Unauthenticated Account Takeover",
            description=(
                "A forgeable/weak JWT combined with a confirmed BOLA/IDOR vulnerability means "
                "an attacker can mint or tamper with a token to assume another user's identity "
                "and then access that user's resources directly by ID."
            ),
            finding_ids=[f.id for f in jwt_weak[:1] + bola[:1]],
            risk_score=95,
            cvss_vector=vector,
            cvss_score=score,
        ))
    return chains


def rule_shadow_api_missing_auth(findings: list[Finding]) -> list[AttackChain]:
    shadow = [f for f in findings if _is(f, "shadow_api", Confidence.MEDIUM)]
    missing_headers = [f for f in findings if _is(f, "missing_security_header", Confidence.MEDIUM)]
    chains = []
    if shadow and missing_headers:
        vector, score = score_profile("shadow_api")
        chains.append(AttackChain(
            name="Undocumented Endpoint Exposure",
            description=(
                "An undocumented (shadow) API endpoint was discovered that also lacks baseline "
                "security headers, suggesting it bypassed the normal API gateway/hardening path "
                "applied to documented endpoints."
            ),
            finding_ids=[f.id for f in shadow[:1] + missing_headers[:1]],
            risk_score=55,
            cvss_vector=vector,
            cvss_score=score,
        ))
    return chains


def rule_sqli_rate_limit_exfil(findings: list[Finding]) -> list[AttackChain]:
    sqli = [f for f in findings if _is(f, "sql_injection", Confidence.CONFIRMED)]
    rate = [f for f in findings if _is(f, "rate_limit_missing", Confidence.MEDIUM)]
    chains = []
    if sqli and rate:
        vector, score = score_profile("sqli_confirmed")
        chains.append(AttackChain(
            name="Bulk Data Exfiltration via Unthrottled SQLi",
            description=(
                "A confirmed SQL injection point combined with the absence of rate limiting "
                "means an attacker can automate high-volume extraction queries without being "
                "throttled or easily detected by volume-based alerting."
            ),
            finding_ids=[f.id for f in sqli[:1] + rate[:1]],
            risk_score=90,
            cvss_vector=vector,
            cvss_score=score,
        ))
    return chains


ALL_RULES = [rule_jwt_bola_account_takeover, rule_shadow_api_missing_auth, rule_sqli_rate_limit_exfil]


def correlate(findings: list[Finding]) -> list[AttackChain]:
    chains: list[AttackChain] = []
    for rule in ALL_RULES:
        chains.extend(rule(findings))
    if os.environ.get("ANTHROPIC_API_KEY"):
        _enrich_with_ai_narrative(chains)
    return chains


def _enrich_with_ai_narrative(chains: list[AttackChain]) -> None:
    """
    Optional narrative rewrite. Deliberately narrow: it receives an
    ALREADY-DECIDED chain (name, description, risk_score, finding ids) and is
    only allowed to produce prose explaining it for a report reader. It
    cannot add, remove, or re-score chains, and its output is never used to
    decide whether a vulnerability exists.
    """
    try:
        import anthropic
    except ImportError:
        log.info("ANTHROPIC_API_KEY set but 'anthropic' package not installed; skipping AI narrative.")
        return

    client = anthropic.Anthropic()
    for chain in chains:
        prompt = (
            "Rewrite the following ALREADY-CONFIRMED penetration test attack-chain finding as "
            "a 2-3 sentence narrative for a report's executive audience. Do not invent facts, "
            "do not change the severity or claim anything not stated below.\n\n"
            f"Chain name: {chain.name}\n"
            f"Technical description: {chain.description}\n"
            f"Risk score: {chain.risk_score}/100\n"
        )
        try:
            resp = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=300,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")
            if text.strip():
                chain.narrative = text.strip()
        except Exception as e:
            log.warning(f"AI narrative enrichment failed for chain '{chain.name}': {e}")
