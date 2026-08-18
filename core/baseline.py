"""
core/baseline.py
Requirement 4: the honest version of "AI zero-day detection." We do NOT claim
to find unknown vulnerability classes. Instead: baseline normal response
timing/size/status per endpoint during recon, then flag statistically
significant deviations as category=anomaly, confidence=low, with a
description that explicitly says this requires manual review and does not
match a known signature.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from core.schema import Confidence, Evidence, Finding, Severity
from core.cvss import score_profile

Z_SCORE_THRESHOLD = 3.0  # ~99.7th percentile, conservative to limit false positives


@dataclass
class EndpointBaseline:
    endpoint: str
    timings_ms: list[float] = field(default_factory=list)
    sizes: list[int] = field(default_factory=list)
    statuses: list[int] = field(default_factory=list)

    def record(self, elapsed_ms: float, size: int, status: int) -> None:
        self.timings_ms.append(elapsed_ms)
        self.sizes.append(size)
        self.statuses.append(status)

    def _z(self, values: list[float], x: float) -> float:
        if len(values) < 3:
            return 0.0
        mean = statistics.mean(values)
        stdev = statistics.pstdev(values)
        if stdev == 0:
            return 0.0
        return abs(x - mean) / stdev


class BaselineTracker:
    def __init__(self):
        self._baselines: dict[str, EndpointBaseline] = {}

    def observe(self, endpoint: str, elapsed_ms: float, size: int, status: int) -> None:
        b = self._baselines.setdefault(endpoint, EndpointBaseline(endpoint))
        b.record(elapsed_ms, size, status)

    def check_deviation(self, endpoint: str, elapsed_ms: float, size: int, status: int) -> Finding | None:
        """
        Compares a later observation against the recon-time baseline for the
        same endpoint. Returns a low-confidence anomaly Finding if the
        deviation crosses the z-score threshold on timing or size, or if the
        status code was never observed during baselining.
        """
        b = self._baselines.get(endpoint)
        if not b or len(b.timings_ms) < 3:
            return None

        z_time = b._z(b.timings_ms, elapsed_ms)
        z_size = b._z(b.sizes, size)
        unseen_status = status not in b.statuses

        if z_time < Z_SCORE_THRESHOLD and z_size < Z_SCORE_THRESHOLD and not unseen_status:
            return None

        reasons = []
        if z_time >= Z_SCORE_THRESHOLD:
            reasons.append(f"response time deviated {z_time:.1f} std-dev from baseline")
        if z_size >= Z_SCORE_THRESHOLD:
            reasons.append(f"response size deviated {z_size:.1f} std-dev from baseline")
        if unseen_status:
            reasons.append(f"status code {status} was not observed during baselining")

        vector, cvss_score = score_profile("anomaly")
        return Finding(
            vulnerability_type="anomaly",
            title=f"Statistical anomaly at {endpoint}",
            endpoint=endpoint,
            parameter=None,
            root_cause="baseline_deviation:" + "+".join(sorted(reasons)),
            module="anomaly_detection",
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            description=(
                "This response deviates from the statistical baseline established during "
                "reconnaissance (" + "; ".join(reasons) + "). This does not match any known "
                "vulnerability signature and is not a confirmed finding of any kind — it is a "
                "heuristic aid only."
            ),
            remediation=(
                "Manually review the request/response pair. Statistical anomalies can indicate "
                "everything from an unrelated backend hiccup to a genuine unknown-class issue; "
                "only a human tester can make that determination."
            ),
            cwe="",
            owasp="",
            cvss_vector=vector,
            cvss_score=cvss_score,
            likelihood="low",
            evidence=Evidence(
                request_summary=f"Request to {endpoint}",
                response_summary=f"status={status} size={size}B elapsed={elapsed_ms:.1f}ms",
                signal_1="statistical_baseline_deviation",
            ),
        )
