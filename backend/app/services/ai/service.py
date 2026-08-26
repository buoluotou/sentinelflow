"""AI analysis orchestration (Phase 2 Step 10.3).

    Event -> EventRisk + evidence -> AIRequest -> provider.explain()
          -> AIAnalysis (validated) -> persisted ai_analyses row

The service follows the SentinelFlow transaction rule: it flushes, never
commits — the API layer owns the transaction boundary. AI output is
advisory only: nothing here touches EventRisk, Incident or group status.

AI-layer failures propagate typed (AIProviderConfigError /
AIProviderUnavailable / AIResponseParseError) for the API to map to
503/503/502; a broken answer is never faked into a success.
"""
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.models import AIAnalysis, AlertGroup
from app.services.ai.base import AIProvider
from app.services.ai.registry import create_provider
from app.services.ai.request_builder import build_alert_explanation


class AIEventNotFound(Exception):
    """The requested event (AlertGroup) does not exist — API maps to 404."""


def latest_analysis_for(db: Session, event_id: uuid.UUID) -> AIAnalysis | None:
    """Most recent analysis of an event; None when never analysed.

    Module-level so other services (risk summary) reuse the exact same
    latest-record semantics without constructing a provider.
    """
    return db.execute(
        select(AIAnalysis)
        .where(AIAnalysis.alert_group_id == event_id)
        .order_by(AIAnalysis.created_at.desc(), AIAnalysis.id.desc())
        .limit(1)
    ).scalar_one_or_none()


class AIAnalysisService:
    """Runs one analysis capability against an event and records it."""

    def __init__(self, provider: AIProvider | None = None):
        # Default: build the configured provider from .env (mock unless the
        # deployment opts into ollama/cloud). Tests inject MockProvider.
        self._provider = provider if provider is not None else create_provider(settings)

    @property
    def provider(self) -> AIProvider:
        return self._provider

    def explain_event(self, db: Session, event_id: uuid.UUID) -> AIAnalysis:
        """Explain one event and append the analysis to its history.

        Repeated calls append records (models change, re-analysis is
        expected) — ai_analyses is an analysis history, not a snapshot.
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
        request = build_alert_explanation(group, group.risk, alerts)

        result = self._provider.explain(request)

        record = AIAnalysis(
            alert_group=group,  # relationship object, not the (maybe unflushed) id
            provider=self._provider.name,
            model=self._provider.model,
            summary=result.summary,
            attack_type=result.attack_type,
            why_risky=result.why_risky,
            confidence=result.confidence,
        )
        db.add(record)
        db.flush()  # transaction boundary stays with the caller
        return record

    def latest_analysis(self, db: Session, event_id: uuid.UUID) -> AIAnalysis | None:
        """Most recent analysis of an event; None when never analysed."""
        return latest_analysis_for(db, event_id)
