"""Approval-queue API (Phase 2 Step 13.3).

Thin HTTP layer over AIResponseApprovalService; the frozen error contract:

    AIEventNotFound             -> 404  "Recommendation not found"
    AIResponseApprovalNotFound  -> 404  "Approval not found"
    AIResponseAlreadyReviewed   -> 409  "already reviewed"

GET /approvals is the Approval Queue backend entry: it returns pending
RECOMMENDATIONS — pending is the 13.2 derived state (no approval row),
never a stored status value. Queue ordering comes straight from the
service (created_at ASC, id ASC — first in, first reviewed); this layer
never re-sorts.

Approve != Execute: POST .../approve and .../reject record one decision
row each. They never block an IP, create an Incident, touch EventRisk or
call any orchestrator — response execution belongs to Step 14.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
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

router = APIRouter(tags=["approval-queue"])


def get_ai_response_approval_service() -> AIResponseApprovalService:
    """Deployment seam: tests override this dependency, mirroring the
    Step 10/11/12 AI APIs."""
    return AIResponseApprovalService()


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
) -> AIResponseApprovalRead:
    """Record a human APPROVE decision. Records only — executes nothing."""
    approval = _decide(db, service, recommendation_id, payload, service.approve)
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
) -> AIResponseApprovalRead:
    """Record a human REJECT decision. Records only — executes nothing."""
    approval = _decide(db, service, recommendation_id, payload, service.reject)
    db.commit()
    db.refresh(approval)
    return AIResponseApprovalRead.model_validate(approval)


def _decide(db, service, recommendation_id: str, payload: ApprovalDecisionRequest, decide):
    """Call approve/reject and translate the frozen error taxonomy to HTTP.
    A raised error aborts before commit(), so nothing is ever persisted."""
    try:
        return decide(
            db,
            _to_uuid(recommendation_id, "Recommendation not found"),
            reviewer=payload.reviewer,
            review_comment=payload.review_comment,
        )
    except AIEventNotFound as exc:
        raise HTTPException(status_code=404, detail="Recommendation not found") from exc
    except AIResponseAlreadyReviewed as exc:
        raise HTTPException(status_code=409, detail="Recommendation already reviewed") from exc


def _to_pending(record: AIResponseRecommendation) -> PendingApprovalRead:
    """Project a queue entry; the alert_group relationship carries the
    human-readable event title without a second query per row."""
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
    """Malformed ids map to the same 404 as unknown ids (Step 12.3 style)."""
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=detail) from exc
