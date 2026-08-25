"""Service-layer result types of the risk engine.

These are plain dataclasses used between the engine and its callers —
NOT the ORM EventRisk model (which is what Step 5.3 persists).
"""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RiskFactor:
    """One explainable contribution to the total risk score."""

    name: str
    score: int
    reason: str

    def to_dict(self) -> dict:
        return {"name": self.name, "score": self.score, "reason": self.reason}


@dataclass
class RiskResult:
    """Outcome of scoring one event: capped score + level + factor trail."""

    score: int
    level: str
    factors: list[RiskFactor] = field(default_factory=list)

    def factors_as_dicts(self) -> list[dict]:
        """JSON-ready form, stored as-is into EventRisk.factors."""
        return [f.to_dict() for f in self.factors]
