"""Approval-queue API.

Thin HTTP layer over AIResponseApprovalService; the error contract:

AIEventNotFound             -> 404  "Recommendation not found"
AIResponseApprovalNotFound  -> 404  "Approval not found"
AIResponseAlreadyReviewed   -> 409  "already reviewed"

GET /approvals is the Approval Queue backend entry: it returns pending
recommendations — pending is a derived state (no approval row), never a
stored status value. Queue ordering comes straight from the service
(created_at ASC, id ASC — first in, first reviewed); this layer never
re-sorts.

Approving and rejecting are decisions, not executions: POST
.../approve and .../reject record one decision row each. They never
block an IP, create an Incident, touch EventRisk or call any
orchestrator — response execution is handled by the execution API.

The approval auth boundary: demo mode (the default) keeps the simple
local UX, where the body ``reviewer`` is display-only. Production mode
forbids tokenless approval: the recorded reviewer is the Bearer token's
server-side principal, and viewer / executor roles get 403 because the
approval permission is separate. The body identity field is ignored, so
a caller cannot record someone else as the reviewer.
"""
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.api.v1.response_execution import _extract_bearer
from app.core.config import settings
from app.core.database import get_db
from app.core.runtime_mode import is_production
from app.models import AIResponseRecommendation
from app.schemas.response_approval import (
    AIResponseApprovalRead,
    ApprovalDecisionRequest,
    PendingApprovalRead,
)
from app.services.ai import (
    AIEventNotFound,
    AIResponseAlreadyReviewed,
    AIResponseApprovalNotFound,
    AIResponseApprovalService,
)
from app.services.executions.operators import Operator, get_operator_registry

router = APIRouter(tags=["approval-queue"])


def get_ai_response_approval_service() -> AIResponseApprovalService:
    """Deployment seam: tests override this dependency, as with the other
AI APIs."""
    return AIResponseApprovalService()


def authenticate_approval_principal(
    authorization: str | None = Header(default=None),
) -> Operator | None:
    """the approval write-path auth boundary.

DEMO MODE (default): returns ``None`` — the simple local Approval UX
stays tokenless; the request-body ``reviewer`` remains DISPLAY-ONLY
(loopback binding is the exposure control).

PRODUCTION MODE: tokenless / unknown tokens are 401; an authenticated
operator WITHOUT the approval permission (viewer / executor) is 403.
The recorded reviewer is the TOKEN's principal — never the body field.
"""
    if not is_production(settings):
        return None
    token = _extract_bearer(authorization)
    if token is None:
        raise HTTPException(status_code=401, detail="Approval credentials required")
    operator = get_operator_registry().lookup(
        token, legacy_token=settings.EXECUTION_TOKEN
    )
    if operator is None:
        raise HTTPException(status_code=401, detail="Invalid approval credentials")
    if not operator.role.can_approve:
        raise HTTPException(
            status_code=403,
            detail=f"Operator '{operator.name}' (role={operator.role.value}) "
            "may not approve or reject recommendations",
        )
    return operator


@router.get("/approvals", response_model=list[PendingApprovalRead])
def approval_queue(
    db: Session = Depends(get_db),
    service: AIResponseApprovalService = Depends(get_ai_response_approval_service),
) -> list[PendingApprovalRead]:
    """The Approval Queue: every recommendation without a decision yet,
oldest first (service ordering, never re-sorted here)."""
    records = service.get_pending_approvals(db)
    return [_to_pending(record) for record in records]


@router.get("/approvals/{approval_id}", response_model=AIResponseApprovalRead)
def approval_detail(
    approval_id: str,
    db: Session = Depends(get_db),
    service: AIResponseApprovalService = Depends(get_ai_response_approval_service),
) -> AIResponseApprovalRead:
    """One recorded decision by id; 404 when the approval does not exist."""
    try:
        approval = service.get_approval(db, _to_uuid(approval_id, "Approval not found"))
    except AIResponseApprovalNotFound as exc:
        raise HTTPException(status_code=404, detail="Approval not found") from exc
    return AIResponseApprovalRead.model_validate(approval)


@router.post(
    "/response-recommendations/{recommendation_id}/approve",
    response_model=AIResponseApprovalRead,
    status_code=201,
)
def approve_recommendation(
    recommendation_id: str,
    payload: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
    service: AIResponseApprovalService = Depends(get_ai_response_approval_service),
    principal: Operator | None = Depends(authenticate_approval_principal),
) -> AIResponseApprovalRead:
    """Record a human APPROVE decision. Records only — executes nothing.

in production the reviewer is the authenticated principal; in
demo mode the endpoint stays tokenless (display-only reviewer)."""
    approval = _decide(db, service, recommendation_id, payload, service.approve, principal)
    db.commit()
    db.refresh(approval)
    return AIResponseApprovalRead.model_validate(approval)


@router.post(
    "/response-recommendations/{recommendation_id}/reject",
    response_model=AIResponseApprovalRead,
    status_code=201,
)
def reject_recommendation(
    recommendation_id: str,
    payload: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
    service: AIResponseApprovalService = Depends(get_ai_response_approval_service),
    principal: Operator | None = Depends(authenticate_approval_principal),
) -> AIResponseApprovalRead:
    """Record a human REJECT decision. Records only — executes nothing.

same reviewer rule as approve (production principal / demo
display-only)."""
    approval = _decide(db, service, recommendation_id, payload, service.reject, principal)
    db.commit()
    db.refresh(approval)
    return AIResponseApprovalRead.model_validate(approval)


def _decide(db, service, recommendation_id: str, payload: ApprovalDecisionRequest, decide, principal):
    """Call approve/reject and translate the error taxonomy to HTTP.
A raised error aborts before commit(), so nothing is ever persisted.

the recorded reviewer is the AUTHENTICATED principal in
production; only in demo mode does the display-only body reviewer apply.
"""
    reviewer = principal.name if principal is not None else payload.reviewer
    try:
        return decide(
            db,
            _to_uuid(recommendation_id, "Recommendation not found"),
            reviewer=reviewer,
            review_comment=payload.review_comment,
        )
    except AIEventNotFound as exc:
        raise HTTPException(status_code=404, detail="Recommendation not found") from exc
    except AIResponseAlreadyReviewed as exc:
        raise HTTPException(status_code=409, detail="Recommendation already reviewed") from exc


def _to_pending(record: AIResponseRecommendation) -> PendingApprovalRead:
    """Project a queue entry; the alert_group title is already eager-loaded
by the service, so this reads no lazy relationship."""
    return PendingApprovalRead.model_validate(
        {
            "id": record.id,
            "event_id": record.alert_group_id,
            "event_title": record.alert_group.title,
            "provider": record.provider,
            "model": record.model,
            "overall_rationale": record.overall_rationale,
            "recommendations": record.recommendations,
            "confidence": record.confidence,
            "created_at": record.created_at,
        }
    )


def _to_uuid(value: str, detail: str) -> uuid.UUID:
    """Malformed ids map to the same 404 as unknown ids (style)."""
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=detail) from exc
