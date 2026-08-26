"""AI response-recommendation orchestration (Phase 2 Step 12.2).

    Event -> EventRisk + evidence + optional Step 11 risk summary
          -> build_response_recommendation_request -> provider.generate()
          -> ResponseRecommendation (validated)
          -> persisted ai_response_recommendations row

Mirrors the Step 10/11 service contract: flushes, never commits (the API
layer owns the transaction boundary). Advisory only end-to-end: actions
like block_source_ip / escalate_to_incident are RECORDED SUGGESTIONS here
— nothing is executed, no Incident is created and no EventRisk field is
touched; human approval lands in Step 13.

Error taxonomy is identical to Step 10/11: AIEventNotFound (404), typed
provider errors (503) and AIResponseParseError (502). A broken answer is
never faked into a persisted row — validation happens strictly before
any ORM object is constructed.
"""
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.models import AIResponseRecommendation, AlertGroup
from app.services.ai.base import AIProvider
from app.services.ai.exceptions import AIResponseParseError
from app.services.ai.models import RESPONSE_ACTIONS, ResponseRecommendation
from app.services.ai.registry import create_provider
from app.services.ai.request_builder import build_response_recommendation_request
from app.services.ai.risk_summary_service import latest_summary_for
from app.services.ai.service import AIEventNotFound


class AIResponseRecommendationService:
    """Runs the response_recommendation task against an event and records it."""

    def __init__(self, provider: AIProvider | None = None):
        # Default: build the configured provider from .env (mock unless the
        # deployment opts into ollama/cloud). Tests inject MockProvider.
        self._provider = provider if provider is not None else create_provider(settings)

    @property
    def provider(self) -> AIProvider:
        return self._provider

    def generate_response_recommendation(
        self, db: Session, event_id: uuid.UUID
    ) -> AIResponseRecommendation:
        """Generate response advice for one event and append it to the history.

        Neither the Step 10 explanation nor the Step 11 risk summary is a
        hard dependency — each layer stays independently generatable.
        Repeated calls append records (ai_response_recommendations is a
        history, not a snapshot): the service never updates the latest row.
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
        request = build_response_recommendation_request(
            group,
            group.risk,
            alerts,
            latest_summary=latest_summary_for(db, event_id),
        )

        result = self._provider.generate(request)

        # Task/type guard: a provider that answers with the wrong protocol
        # must surface as a parse failure (502), never a persisted row.
        if not isinstance(result, ResponseRecommendation):
            raise AIResponseParseError(
                f"Provider returned {type(result).__name__} for task response_recommendation"
            )
        # Defense in depth: typed-object providers bypass the raw-output
        # parser, so the frozen action vocabulary is re-enforced here.
        unknown = sorted({item.action for item in result.recommendations} - RESPONSE_ACTIONS)
        if unknown:
            raise AIResponseParseError(
                f"Provider output contains unknown response actions: {', '.join(unknown)}"
            )

        record = AIResponseRecommendation(
            alert_group=group,  # relationship object, not the (maybe unflushed) id
            provider=self._provider.name,
            model=self._provider.model,
            overall_rationale=result.overall_rationale,
            recommendations=[item.model_dump() for item in result.recommendations],
            confidence=result.confidence,
        )
        db.add(record)
        db.flush()  # transaction boundary stays with the caller
        return record

    def latest_recommendation(
        self, db: Session, event_id: uuid.UUID
    ) -> AIResponseRecommendation | None:
        """Most recent recommendation of an event; None when never generated."""
        return db.execute(
            select(AIResponseRecommendation)
            .where(AIResponseRecommendation.alert_group_id == event_id)
            .order_by(
                AIResponseRecommendation.created_at.desc(),
                AIResponseRecommendation.id.desc(),
            )
            .limit(1)
        ).scalar_one_or_none()
