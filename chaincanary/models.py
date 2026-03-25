"""
Data models for chaincanary risk reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Weight used for risk score calculation
SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 4.0,
    "HIGH": 2.5,
    "MEDIUM": 1.0,
    "LOW": 0.3,
    "INFO": 0.0,
}


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    source: str = "static"  # "static" | "dynamic"


@dataclass
class BehaviorSnapshot:
    """Recorded behaviors of a package version (for diffing)."""

    package: str
    version: str
    network_calls: list[str] = field(default_factory=list)
    file_writes: list[str] = field(default_factory=list)
    subprocesses: list[str] = field(default_factory=list)
    env_reads: list[str] = field(default_factory=list)
    pth_files: list[str] = field(default_factory=list)


@dataclass
class RiskReport:
    package: str
    version: str
    findings: list[Finding] = field(default_factory=list)
    score: float = 0.0
    verdict: str = "SAFE"  # SAFE | LOW_RISK | HIGH_RISK | MALICIOUS
    safe_version: str | None = None
    behavior: BehaviorSnapshot | None = None
    behavior_diff: dict | None = None  # new behaviors vs prev version

    def calculate_score(self) -> None:
        # LOW findings are capped at 8 to prevent noise inflation
        low_findings = [f for f in self.findings if f.severity == Severity.LOW]
        other_findings = [f for f in self.findings if f.severity != Severity.LOW]
        capped_low = low_findings[:8]

        raw = sum(SEVERITY_WEIGHTS.get(f.severity.value, 0) for f in other_findings + capped_low)
        self.score = min(10.0, raw)

        # Numeric threshold baseline
        if self.score <= 2.0:
            self.verdict = "SAFE"
        elif self.score <= 4.0:
            self.verdict = "LOW_RISK"
        elif self.score <= 7.0:
            self.verdict = "HIGH_RISK"
        else:
            self.verdict = "MALICIOUS"

        # Severity-based floor overrides (prevents score gaming)
        critical_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)

        _VERDICTS = ["SAFE", "LOW_RISK", "HIGH_RISK", "MALICIOUS"]

        def _bump(current: str, floor: str) -> str:
            return floor if _VERDICTS.index(floor) > _VERDICTS.index(current) else current

        # Any CRITICAL → at minimum HIGH_RISK; 2+ CRITICAL → MALICIOUS
        if critical_count >= 2:
            self.verdict = _bump(self.verdict, "MALICIOUS")
        elif critical_count == 1:
            self.verdict = _bump(self.verdict, "HIGH_RISK")

        # 3+ HIGH without CRITICAL → HIGH_RISK minimum
        if high_count >= 3:
            self.verdict = _bump(self.verdict, "HIGH_RISK")

    @property
    def is_blocked(self) -> bool:
        return self.score > 7.0

    @property
    def should_warn(self) -> bool:
        return 2.0 < self.score <= 7.0
