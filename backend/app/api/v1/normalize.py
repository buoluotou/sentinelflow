import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.deduplication import engine as dedup_engine
from app.services.normalization import (
    AdapterNotImplementedError,
    MalformedRawEventError,
    NormalizedAlert,
    UnknownSourceError,
    engine,
)

router = APIRouter(prefix="/normalize", tags=["normalization"])


class NormalizeRequest(BaseModel):
    """Raw alert from any source, to be normalized."""

    source: str = Field(min_length=1, max_length=128)
    raw_data: dict


class NormalizeResponse(NormalizedAlert):
    """Normalized alert plus the ids of the Alert and AlertGroup persisted
    downstream by the deduplication engine."""

    alert_id: uuid.UUID | None = None
    group_id: uuid.UUID | None = None
    group_alert_count: int | None = None
    created_group: bool | None = None


@router.post("", response_model=NormalizeResponse)
def normalize_alert(
    payload: NormalizeRequest, db: Session = Depends(get_db)
) -> NormalizeResponse:
    """Normalize a raw source event, deduplicate and ingest the result.

    Pipeline: Raw Alert -> Normalization -> Deduplication -> DB.
    """
    try:
        normalized = engine.normalize(payload.source, payload.raw_data)
    except UnknownSourceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except AdapterNotImplementedError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    except MalformedRawEventError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    result = dedup_engine.process(db, normalized, engine.to_alert_create(normalized))
    return NormalizeResponse(
        **normalized.model_dump(),
        alert_id=result.alert.id,
        group_id=result.group.id,
        group_alert_count=result.group.alert_count,
        created_group=result.created_group,
    )
