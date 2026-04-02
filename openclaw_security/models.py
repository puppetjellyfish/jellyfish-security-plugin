from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class RiskFinding:
    category: str
    severity: str
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    action: str = "log"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatIntelResult:
    source: str
    observable: str
    observable_type: str
    verdict: str
    malicious: bool
    score: int
    confidence: float
    categories: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityDecision:
    status: str
    action: str
    summary: str
    findings: list[RiskFinding] = field(default_factory=list)
    ti_results: list[ThreatIntelResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "action": self.action,
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "ti_results": [result.to_dict() for result in self.ti_results],
        }
