"""Human approval gate over AI response recommendations (Phase 2 Step 13.2).

    Recommendation (no approval row)   -> pending (DERIVED, never stored)
    Recommendation + approval row      -> approved | rejected (final)

Approve != Execute: this service only records what a human decided. It
never blocks an IP, creates an Incident, touches EventRisk or calls any
orchestrator — response execution belongs to Step 14.

Frozen semantics:
- pending is derived from ABSENCE (LEFT JOIN ... WHERE approval IS NULL),
  never a stored status value (the 13.1 CHECK constraint would reject it)
- approve()/reject() are one-shot INSERTs; a decision is final and the
  UNIQUE(recommendation_id) constraint is the last line of defense
- reviewed_at is stamped with the server clock here — the signature does
  not accept it, so a client can never backdate the audit trail
- flushes, never commits (the API layer owns the transaction boundary,
  same discipline as the Step 10/11/12 services)
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import AIResponseApproval, AIResponseRecommendation
from app.services.ai.service import AIEventNotFound


class AIResponseApprovalNotFound(Exception):
    """No approval row exists for the requested id — API maps to 404."""


class AIResponseAlreadyReviewed(Exception):
    """The recommendation already has a final decision. Decisions are
    INSERT-only and immutable: to change the outcome, regenerate the
    recommendation and review the fresh record."""


class AIResponseApprovalService:
    """Approval queue over AI response recommendations."""

    def get_pending_approvals(self, db: Session) -> list[AIResponseRecommendation]:
        """Recommendations awaiting a human decision, first-in-first-reviewed.

        Derived semantics: pending == recommendation with NO approval row
        (outer join, not a status lookup). Ordered created_at ASC, id ASC
        so the oldest item tops the queue.
        """
        return list(
            db.execute(
                select(AIResponseRecommendation)
                .outerjoin(
                    AIResponseApproval,
                    AIResponseApproval.recommendation_id
                    == AIResponseRecommendation.id,
                )
                .where(AIResponseApproval.id.is_(None))
                .order_by(
                    AIResponseRecommendation.created_at.asc(),
                    AIResponseRecommendation.id.asc(),
                )
            ).scalars()
        )

    def get_approval(self, db: Session, approval_id: uuid.UUID) -> AIResponseApproval:
        """One approval by id; AIResponseApprovalNotFound when absent."""
        approval = db.get(AIResponseApproval, approval_id)
        if approval is None:
            raise AIResponseApprovalNotFound(f"Approval {approval_id} does not exist")
        return approval

    def approve(
        self,
        db: Session,
        recommendation_id: uuid.UUID,
        reviewer: str,
        review_comment: str | None = None,
    ) -> AIResponseApproval:
        """Record a human APPROVE decision. Records only — executes nothing."""
        return self._decide(db, recommendation_id, "approved", reviewer, review_comment)

    def reject(
        self,
        db: Session,
        recommendation_id: uuid.UUID,
        reviewer: str,
        review_comment: str | None = None,
    ) -> AIResponseApproval:
        """Record a human REJECT decision. Records only — executes nothing."""
        return self._decide(db, recommendation_id, "rejected", reviewer, review_comment)

    def _decide(
        self,
        db: Session,
        recommendation_id: uuid.UUID,
        status: str,
        reviewer: str,
        review_comment: str | None,
    ) -> AIResponseApproval:
        """One-shot INSERT of a terminal decision; no UPDATE path exists."""
        record = db.get(AIResponseRecommendation, recommendation_id)
        if record is None:
            # Same not-found semantics as the other AI services: the
            # recommendation is anchored to an event that must exist.
            raise AIEventNotFound(f"Recommendation {recommendation_id} does not exist")
        if record.approval is not None:
            raise AIResponseAlreadyReviewed(
                f"Recommendation {recommendation_id} already reviewed as "
                f"'{record.approval.status}'"
            )

        approval = AIResponseApproval(
            recommendation_id=record.id,
            status=status,
            reviewer=reviewer,
            # Server-stamped audit time — intentionally not a parameter.
            reviewed_at=datetime.now(timezone.utc),
            review_comment=review_comment,
        )
        db.add(approval)
        try:
            db.flush()  # transaction boundary stays with the caller
        except IntegrityError as exc:
            # Concurrency last line of defense: a racing request may have
            # inserted between the pre-check and the flush. The UNIQUE
            # constraint wins; surface the typed domain error, never a raw
            # SQL failure (the API layer maps it to its HTTP status).
            raise AIResponseAlreadyReviewed(
                f"Recommendation {recommendation_id} was reviewed concurrently"
            ) from exc
        return approval
