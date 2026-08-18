"""
core/config.py
Central scan configuration, including --safe mode (requirement 7): same
schema, same modules, lower blast radius. --safe skips the rate-limit flood
test and reduces SQLi/XSS to a single low-impact probe payload.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    target: str
    safe_mode: bool = False
    ci_mode: bool = False
    fail_on: str = "critical"
    timeout: float = 10.0
    max_requests_per_module: int = 40
    output_dir: str = "cyfoxguard_output"
    identities: list[dict] = field(default_factory=list)  # for BOLA/IDOR multi-identity testing
    openapi_spec: str | None = None
    use_external_tools: bool = True
    ai_narrative: bool = False

    @property
    def sqli_payload_limit(self) -> int:
        return 1 if self.safe_mode else 12

    @property
    def xss_payload_limit(self) -> int:
        return 1 if self.safe_mode else 10

    @property
    def run_rate_limit_flood(self) -> bool:
        return not self.safe_mode
