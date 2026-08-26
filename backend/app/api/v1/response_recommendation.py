"""AI response-recommendation API (Phase 2 Step 12.3).

Explicit-trigger response advice for one event — thin HTTP layer over
AIResponseRecommendationService; the frozen error contract (identical to
the Step 10/11 AI APIs) is mapped here:

    AIEventNotFound             -> 404
    AIProviderConfigError       -> 503
    AIProviderUnavailable       -> 503
    AIResponseParseError        -> 502

A failed recommendation NEVER produces a row: the service raises before
any add(), so a 5xx response always leaves ai_response_recommendations
untouched. Advisory only — this endpoint cannot alter EventRisk.score /
level or Incident.status / disposition, and never executes anything:
every action stays a suggestion until human approval (Step 13).
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import AlertGroup
from app.schemas.response_recommendation import AIResponseRecommendationRead
from app.services.ai import (
    AIResponseRecommendationService,
    AIEventNotFound,
    AIProviderConfigError,
    AIProviderUnavailable,
    AIResponseParseError,
)

router = APIRouter(prefix="/events", tags=["response-recommendation"])


def get_ai_response_recommendation_service() -> AIResponseRecommendationService:
    """Deployment seam: the service builds its provider from settings
    (AI_PROVIDER, default mock). Tests override this dependency to inject
    failing providers."""
    return AIResponseRecommendationService()


@router.post(
    "/{event_id}/response-recommendation",
    response_model=AIResponseRecommendationRead,
    status_code=201,
)
def response_recommendation_create(
    event_id: str,
    db: Session = Depends(get_db),
    service: AIResponseRecommendationService = Depends(
        get_ai_response_recommendation_service
    ),
) -> AIResponseRecommendationRead:
    """Run one AI response recommendation of the event and append it to the
    event's recommendation history (repeated calls keep every record)."""
    record = _generate(db, service, event_id)
    db.commit()
    db.refresh(record)
    return AIResponseRecommendationRead.model_validate(record)


@router.get(
    "/{event_id}/response-recommendation",
    response_model=AIResponseRecommendationRead,
)
def response_recommendation_latest(
    event_id: str,
    db: Session = Depends(get_db),
    service: AIResponseRecommendationService = Depends(
        get_ai_response_recommendation_service
    ),
) -> AIResponseRecommendationRead:
    """Most recent recommendation of the event; 404 when the event is
    unknown or has never received advice (the history listing is deferred)."""
    _validate_event(db, event_id)
    record = service.latest_recommendation(db, _to_uuid(event_id))
    if record is None:
        raise HTTPException(
            status_code=404, detail="No response recommendation recorded for this event"
        )
    return AIResponseRecommendationRead.model_validate(record)


def _generate(db: Session, service: AIResponseRecommendationService, event_id: str):
    """Call the service and translate the frozen error taxonomy to HTTP."""
    try:
        return service.generate_response_recommendation(db, _to_uuid(event_id))
    except AIEventNotFound as exc:
        raise HTTPException(status_code=404, detail="Event not found") from exc
    except AIProviderConfigError as exc:
        raise HTTPException(
            status_code=503, detail=f"AI provider misconfigured: {exc}"
        ) from exc
    except AIProviderUnavailable as exc:
        raise HTTPException(
            status_code=503, detail=f"AI provider unavailable: {exc}"
        ) from exc
    except AIResponseParseError as exc:
        raise HTTPException(
            status_code=502, detail=f"AI response did not match the expected protocol: {exc}"
        ) from exc


def _validate_event(db: Session, event_id: str) -> None:
    """404 for malformed or unknown event ids (same style as the events API)."""
    group = db.get(AlertGroup, _to_uuid(event_id))
    if group is None:
        raise HTTPException(status_code=404, detail="Event not found")


def _to_uuid(event_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(event_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Event not found") from exc
