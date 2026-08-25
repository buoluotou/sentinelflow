"""Risk engine: deterministic, explainable event scoring.

Phase 1 Step 5.2: the engine computes a RiskResult from an AlertGroup and
its evidence alerts. It does NOT persist anything — saving/updating the
EventRisk row is the RiskService's job (Step 5.3), keeping calculation and
storage cleanly separated.
"""

from app.models import Alert, AlertGroup
from app.services.risk.factors import (
    frequency_factor,
    public_source_factor,
    severity_factor,
)
from app.services.risk.models import RiskFactor, RiskResult
from app.services.risk.rules import MAX_SCORE, level_for_score


class RiskEngine:
    """Scores one aggregated event (AlertGroup) with rule-based factors."""

    def calculate(self, group: AlertGroup, alerts: list[Alert]) -> RiskResult:
        factors: list[RiskFactor] = [
            severity_factor(group),
            frequency_factor(group),
            public_source_factor(alerts),
        ]

        total = sum(f.score for f in factors)
        score = max(0, min(total, MAX_SCORE))
        return RiskResult(
            score=score,
            level=level_for_score(score),
            factors=factors,
        )


#: shared engine instance
engine = RiskEngine()
