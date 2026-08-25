"""RiskService: persists the current risk snapshot for an event.

Phase 1 Step 5.3: the engine computes, the service stores. Every event
(AlertGroup) keeps exactly ONE EventRisk row (enforced by the unique
constraint) — the "current risk" snapshot:

    first scoring      -> CREATE EventRisk
    subsequent scoring -> UPDATE in place (score / level / factors)

Never call this from a read path (GET /events): risk is recalculated when
the event changes (after deduplication), so queries stay pure reads.
"""
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import AlertGroup, EventRisk
from app.services.risk.engine import RiskEngine, engine as risk_engine
from app.services.risk.models import RiskResult


class RiskService:
    """Creates or updates the current EventRisk snapshot of an event."""

    def __init__(self, engine: RiskEngine = risk_engine):
        self._engine = engine

    def recalculate(self, db: Session, group: AlertGroup) -> EventRisk:
        """Recompute the group's risk and persist it (create or update).

        Meant to run inside the caller's transaction (the deduplication
        engine calls this right before its own commit); commits on its own
        only when invoked standalone.
        """
        result = self._engine.calculate(group, list(group.alerts))

        risk = group.risk
        if risk is None:
            risk = EventRisk(alert_group=group)
            db.add(risk)
        self._apply(risk, result)
        db.commit()
        db.refresh(risk)
        return risk

    @staticmethod
    def _apply(risk: EventRisk, result: RiskResult) -> None:
        risk.score = result.score
        risk.level = result.level
        risk.factors = result.factors_as_dicts()
        # Refresh explicitly so the snapshot timestamp advances even when
        # the recalculated values happen to be unchanged.
        risk.updated_at = datetime.now(timezone.utc)


#: service shared by the pipeline
service = RiskService()
