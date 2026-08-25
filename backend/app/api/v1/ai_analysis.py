"""AI analysis API (Phase 2 Step 10.5).

Explicit-trigger alert explanation for one event — thin HTTP layer over
AIAnalysisService; the frozen error contract is mapped here:

    AIEventNotFound             -> 404
    AIProviderConfigError       -> 503
    AIProviderUnavailable       -> 503
    AIResponseParseError        -> 502

A failed analysis NEVER produces a row: the service raises before any
add(), so a 5xx response always leaves ai_analyses untouched. Analysis is
advisory only — this endpoint cannot alter risk, status or incidents.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import AlertGroup
from app.schemas.ai_analysis import AIAnalysisRead
from app.services.ai import (
    AIAnalysisService,
    AIEventNotFound,
    AIProviderConfigError,
    AIProviderUnavailable,
    AIResponseParseError,
)

router = APIRouter(prefix="/events", tags=["ai-analysis"])


def get_ai_analysis_service() -> AIAnalysisService:
    """Deployment seam: the service builds its provider from settings
    (AI_PROVIDER, default mock). Tests override this dependency to inject
    failing providers."""
    return AIAnalysisService()


@router.post("/{event_id}/ai-analysis", response_model=AIAnalysisRead, status_code=201)
def ai_analysis_create(
    event_id: str,
    db: Session = Depends(get_db),
    service: AIAnalysisService = Depends(get_ai_analysis_service),
) -> AIAnalysisRead:
    """Run one AI alert-explanation of the event and append it to the
    event's analysis history (repeated calls keep every record)."""
    record = _explain(db, service, event_id)
    db.commit()
    db.refresh(record)
    return AIAnalysisRead.model_validate(record)


@router.get("/{event_id}/ai-analysis", response_model=AIAnalysisRead)
def ai_analysis_latest(
    event_id: str,
    db: Session = Depends(get_db),
    service: AIAnalysisService = Depends(get_ai_analysis_service),
) -> AIAnalysisRead:
    """Most recent analysis of the event; 404 when the event is unknown or
    has never been analysed (the history listing is deferred)."""
    _validate_event(db, event_id)
    record = service.latest_analysis(db, _to_uuid(event_id))
    if record is None:
        raise HTTPException(
            status_code=404, detail="No AI analysis recorded for this event"
        )
    return AIAnalysisRead.model_validate(record)


def _explain(db: Session, service: AIAnalysisService, event_id: str):
    """Call the service and translate the frozen error taxonomy to HTTP."""
    try:
        return service.explain_event(db, _to_uuid(event_id))
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
