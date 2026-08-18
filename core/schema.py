"""
core/schema.py
Canonical Finding schema used by every module, the correlator, the report
generator, and the dashboard. This is the single source of truth for what
a "finding" looks like in CyFoxGuard.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Confidence(str, Enum):
    CONFIRMED = "confirmed"   # 2+ independent signals
    HIGH = "high"             # 1 strong signal, low ambiguity
    MEDIUM = "medium"         # 1 signal, some ambiguity
    LOW = "low"               # heuristic / anomaly, needs manual verification


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Ordering used for --fail-on comparisons and risk-matrix sorting.
SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

LIKELIHOOD_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Evidence:
    """Raw request/response evidence for a finding's appendix entry."""
    request_summary: str
    response_summary: str
    signal_1: str                 # e.g. "error-signature match"
    signal_2: Optional[str] = None  # e.g. "response differential" -> required for confirmed
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None


@dataclass
class Finding:
    vulnerability_type: str        # e.g. "sql_injection"
    title: str
    endpoint: str
    parameter: Optional[str]
    root_cause: str                # short machine-stable string used in fingerprint
    module: str                    # module name that produced it
    severity: Severity
    confidence: Confidence
    description: str
    remediation: str
    cwe: str = ""                  # e.g. "CWE-89"
    owasp: str = ""                # e.g. "API3:2023 / A03:2025"
    cvss_vector: str = ""
    cvss_score: float = 0.0
    likelihood: str = "medium"     # low/medium/high, used in the risk matrix
    evidence: Optional[Evidence] = None
    instance_count: int = 1
    needs_manual_verification: bool = False
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    fingerprint: str = field(init=False, default="")

    def __post_init__(self):
        self.fingerprint = self.compute_fingerprint(
            self.vulnerability_type, self.endpoint, self.parameter, self.root_cause
        )
        # Requirement 1: nothing reaches "confirmed" without two independent signals.
        if self.confidence == Confidence.CONFIRMED:
            if not (self.evidence and self.evidence.signal_1 and self.evidence.signal_2):
                self.confidence = Confidence.HIGH
        if self.confidence in (Confidence.LOW,):
            self.needs_manual_verification = True
            if not self.description.endswith("needs manual verification."):
                self.description = self.description.rstrip(".") + " — needs manual verification."

    @staticmethod
    def compute_fingerprint(vuln_type: str, endpoint: str, parameter: Optional[str], root_cause: str) -> str:
        key = f"{vuln_type}|{endpoint}|{parameter or ''}|{root_cause}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


class FindingStore:
    """
    Requirement 2: no duplicate findings. Fingerprint on
    (vulnerability_type, endpoint, parameter, root_cause); collapse collisions
    into one finding with an instance_count instead of reporting N times.
    """

    def __init__(self):
        self._by_fingerprint: dict[str, Finding] = {}

    def add(self, finding: Finding) -> Finding:
        existing = self._by_fingerprint.get(finding.fingerprint)
        if existing:
            existing.instance_count += 1
            # Keep the highest-confidence version of the description/evidence.
            conf_rank = {"low": 0, "medium": 1, "high": 2, "confirmed": 3}
            if conf_rank[finding.confidence.value] > conf_rank[existing.confidence.value]:
                existing.confidence = finding.confidence
                existing.description = finding.description
                existing.evidence = finding.evidence or existing.evidence
            return existing
        self._by_fingerprint[finding.fingerprint] = finding
        return finding

    def all(self) -> list[Finding]:
        return sorted(
            self._by_fingerprint.values(),
            key=lambda f: (SEVERITY_ORDER[f.severity], f.confidence.value),
            reverse=True,
        )

    def __len__(self):
        return len(self._by_fingerprint)
