"""AI risk-summary API (Phase 2 Step 11.4).

Explicit-trigger SOC-level risk summary for one event — thin HTTP layer
over AIRiskSummaryService; the frozen error contract (identical to the
Step 10 analysis API) is mapped here:

    AIEventNotFound             -> 404
    AIProviderConfigError       -> 503
    AIProviderUnavailable       -> 503
    AIResponseParseError        -> 502

A failed summary NEVER produces a row: the service raises before any
add(), so a 5xx response always leaves ai_risk_summaries untouched. The
summary is advisory only — this endpoint cannot alter EventRisk.score /
level, Incident.status / disposition, and never produces execution actions.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import AlertGroup
from app.schemas.ai_risk_summary import AIRiskSummaryRead
from app.services.ai import (
    AIRiskSummaryService,
    AIEventNotFound,
    AIProviderConfigError,
    AIProviderUnavailable,
    AIResponseParseError,
)

router = APIRouter(prefix="/events", tags=["ai-risk-summary"])


def get_ai_risk_summary_service() -> AIRiskSummaryService:
    """Deployment seam: the service builds its provider from settings
    (AI_PROVIDER, default mock). Tests override this dependency to inject
    failing providers."""
    return AIRiskSummaryService()


@router.post("/{event_id}/ai-risk-summary", response_model=AIRiskSummaryRead, status_code=201)
def ai_risk_summary_create(
    event_id: str,
    db: Session = Depends(get_db),
    service: AIRiskSummaryService = Depends(get_ai_risk_summary_service),
) -> AIRiskSummaryRead:
    """Run one AI risk summary of the event and append it to the event's
    summary history (repeated calls keep every record)."""
    record = _generate(db, service, event_id)
    db.commit()
    db.refresh(record)
    return AIRiskSummaryRead.model_validate(record)


@router.get("/{event_id}/ai-risk-summary", response_model=AIRiskSummaryRead)
def ai_risk_summary_latest(
    event_id: str,
    db: Session = Depends(get_db),
    service: AIRiskSummaryService = Depends(get_ai_risk_summary_service),
) -> AIRiskSummaryRead:
    """Most recent risk summary of the event; 404 when the event is unknown
    or has never been summarised (the history listing is deferred)."""
    _validate_event(db, event_id)
    record = service.latest_summary(db, _to_uuid(event_id))
    if record is None:
        raise HTTPException(
            status_code=404, detail="No AI risk summary recorded for this event"
        )
    return AIRiskSummaryRead.model_validate(record)


def _generate(db: Session, service: AIRiskSummaryService, event_id: str):
    """Call the service and translate the frozen error taxonomy to HTTP."""
    try:
        return service.generate_risk_summary(db, _to_uuid(event_id))
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
