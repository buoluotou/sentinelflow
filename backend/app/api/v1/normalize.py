import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.ingestion import ingest_alert
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
    """Normalized alert plus the id of the Alert persisted downstream."""

    alert_id: uuid.UUID | None = None


@router.post("", response_model=NormalizeResponse)
def normalize_alert(
    payload: NormalizeRequest, db: Session = Depends(get_db)
) -> NormalizeResponse:
    """Normalize a raw source event and ingest the result.

    Pipeline: Raw Alert -> Normalization Engine -> Normalized Alert -> DB.
    """
    try:
        normalized = engine.normalize(payload.source, payload.raw_data)
    except UnknownSourceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except AdapterNotImplementedError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    except MalformedRawEventError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    alert = ingest_alert(db, engine.to_alert_create(normalized))
    return NormalizeResponse(**normalized.model_dump(), alert_id=alert.id)
