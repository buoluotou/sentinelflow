"""AI risk-summary orchestration (Phase 2 Step 11.3).

    Event -> EventRisk + evidence + optional Step 10 explanation
          -> build_risk_summary_request -> provider.generate()
          -> RiskSummary (validated) -> persisted ai_risk_summaries row

Mirrors the Step 10 service contract: flushes, never commits (the API
layer owns the transaction boundary), and AI output is advisory only —
nothing here touches EventRisk.score/level or Incident status/disposition.
No execution actions are ever produced.

Error taxonomy is identical to Step 10: AIEventNotFound (404), typed
provider errors (503) and AIResponseParseError (502). A broken answer is
never faked into a persisted row.
"""
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.models import AIRiskSummary, AlertGroup
from app.services.ai.base import AIProvider
from app.services.ai.exceptions import AIResponseParseError
from app.services.ai.models import RiskSummary
from app.services.ai.registry import create_provider
from app.services.ai.request_builder import build_risk_summary_request
from app.services.ai.service import AIEventNotFound, latest_analysis_for


class AIRiskSummaryService:
    """Runs the risk_summary task against an event and records it."""

    def __init__(self, provider: AIProvider | None = None):
        # Default: build the configured provider from .env (mock unless the
        # deployment opts into ollama/cloud). Tests inject MockProvider.
        self._provider = provider if provider is not None else create_provider(settings)

    @property
    def provider(self) -> AIProvider:
        return self._provider

    def generate_risk_summary(self, db: Session, event_id: uuid.UUID) -> AIRiskSummary:
        """Generate one SOC-level risk summary and append it to the history.

        The Step 10 explanation is optional enrichment — an event that was
        never explained still gets a summary. Repeated calls append records
        (ai_risk_summaries is a history, not a snapshot).
        """
        group = db.execute(
            select(AlertGroup)
            .options(
                selectinload(AlertGroup.risk),
                selectinload(AlertGroup.alerts),
            )
            .where(AlertGroup.id == event_id)
        ).scalar_one_or_none()
        if group is None:
            raise AIEventNotFound(f"Event {event_id} does not exist")

        # Deterministic representative sample: earliest evidence first.
        alerts = sorted(group.alerts, key=lambda a: a.first_seen_at)
        request = build_risk_summary_request(
            group,
            group.risk,
            alerts,
            latest_analysis=latest_analysis_for(db, event_id),
        )

        result = self._provider.generate(request)

        # Task/type guard: a provider that answers with the wrong protocol
        # must surface as a parse failure (502), never a persisted row.
        if not isinstance(result, RiskSummary):
            raise AIResponseParseError(
                f"Provider returned {type(result).__name__} for task risk_summary"
            )

        record = AIRiskSummary(
            alert_group=group,  # relationship object, not the (maybe unflushed) id
            provider=self._provider.name,
            model=self._provider.model,
            summary=result.summary,
            key_findings=result.key_findings,
            risk_drivers=result.risk_drivers,
            analyst_priority=result.analyst_priority,
            confidence=result.confidence,
        )
        db.add(record)
        db.flush()  # transaction boundary stays with the caller
        return record

    def latest_summary(self, db: Session, event_id: uuid.UUID) -> AIRiskSummary | None:
        """Most recent risk summary of an event; None when never generated."""
        return db.execute(
            select(AIRiskSummary)
            .where(AIRiskSummary.alert_group_id == event_id)
            .order_by(AIRiskSummary.created_at.desc(), AIRiskSummary.id.desc())
            .limit(1)
        ).scalar_one_or_none()
