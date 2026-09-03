import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    String,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.types import JSONVariant

# Outcome vocabulary (Phase 3.4, frozen — design doc
# docs/design/phase3.4-execution-outcome-lifecycle.md §4, adjudication O1):
# five words describing what the EXTERNAL WORLD eventually did, never what
# the platform dispatched. Boundary (O1): `reconciliation_failed` = the
# reconcile action itself failed (external state unreadable — fact source
# is the reconciliation process); `confirmed_failure` = the external
# effect was confirmed as NOT achieved (fact source is the outside
# world). The two sources of fact are different and never merge.
OUTCOME_STATUSES = frozenset(
    {
        "unknown",
        "pending",
        "confirmed_success",
        "confirmed_failure",
        "reconciliation_failed",
    }
)
# The subset that carries a confirmed external verdict (3.4.2 derivation
# and 3.4.7 outcome metrics build on this split).
CONFIRMED_OUTCOME_STATUSES = frozenset({"confirmed_success", "confirmed_failure"})

# Fact ingress channels (design §6, frozen): webhook = push-first realtime
# source; manual_reconcile = operator-explicit pull fallback. No third
# channel exists — background polling / schedulers are forbidden (D3.4-03).
OUTCOME_SOURCES = frozenset({"webhook", "manual_reconcile"})


class ExecutionOutcome(Base):
    """One append-only external-outcome fact (Phase 3.4, design §4).

    INDEPENDENT fact layer over execution_log — NOT an extension of
    `execution_log.decision` (user adjudication 2026-09-01): the dispatch
    log answers "what happened to the execution request" (platform view),
    this table answers "what the external world later did" (outside view).

    Two-layer semantics (D3.4-04 / D3.4-05): `execution_log.succeeded` /
    `failed` remain Dispatch Outcome forever; this table records External
    Effect Outcome. Neither layer reinterprets or rewrites the other
    (D3.4-09 / O5):
      - dispatch=succeeded + outcome=confirmed_failure is LEGAL (command
        delivered, effect not achieved);
      - dispatch=failed NEVER auto-creates confirmed_success, but a manual
        reconcile MAY record it when the outside world says so (lost
        responses / network breaks make the layers disagree) — the Outcome
        layer records facts, it does not rewrite Dispatch history.

    Append-only (D3.4-06): INSERT only, no UPDATE, no DELETE. Multiple
    facts per execution_id form a time series; the derived outcome state
    is the fact with the latest `observed_at` (O2) — derivation lives in
    3.4.2, the model deliberately stores no derived state. Deliberately
    NO unique index: late/reordered facts are appended, never rejected
    or overwritten; replay produces no new fact and is therefore inert.

    Fact ≠ intent (D3.4-01): a row here can never trigger execution,
    retry, or compensation — those paths do not read this table as an
    input to any write action.
    """

    __tablename__ = "execution_outcome"
    __table_args__ = (
        # Storage-level vocabulary guard (project-wide principle: the CHECK
        # is the last integrity line). Dispatch-layer words like
        # `succeeded` / `failed` are deliberately NOT legal here — the two
        # vocabularies must never cross-contaminate (D3.4-04).
        CheckConstraint(
            "outcome_status IN ("
            "'unknown', 'pending', 'confirmed_success', "
            "'confirmed_failure', 'reconciliation_failed')",
            name="ck_execution_outcome_status",
        ),
        # Ingress channel guard: exactly the two frozen sources (§6).
        CheckConstraint(
            "source IN ('webhook', 'manual_reconcile')",
            name="ck_execution_outcome_source",
        ),
        # Derivation query path (O2): latest observed fact per execution.
        # Non-unique BY DESIGN — the time series is the audit trail.
        Index(
            "ix_execution_outcome_execution_id_observed_at",
            "execution_id",
            "observed_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # The execution chain this fact belongs to. Plain column, NOT an FK
    # (same precedent as execution_log.compensates_execution_id):
    # execution_id is a caller-supplied chain key spread over multiple
    # execution_log rows, not a primary key. The link is read-only —
    # outcome facts never write back into the dispatch log.
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)

    # Frozen five-word outcome vocabulary (O1); CHECK above is the last
    # line of defense.
    outcome_status: Mapped[str] = mapped_column(String(32), nullable=False)

    # Which ingress channel recorded the fact: webhook (push) or
    # manual_reconcile (operator-explicit pull). Frozen two words (§6).
    source: Mapped[str] = mapped_column(String(16), nullable=False)

    # Recorder identity, per trust domain (D3.4-07): for manual_reconcile
    # the AUTHENTICATED operator (token → operator → role, never a
    # client-declared string); for webhook the adapter callback identity.
    # Human and machine identities stay distinguishable in the audit
    # trail, exactly as execution_log.operator does for dispatch.
    operator: Mapped[str] = mapped_column(String(128), nullable=False)

    # When the external world was observed (fact time — NOT ingest time).
    # Derivation orders by this column (O2): the latest observation is the
    # current outcome state. Validation / normalization rules for this
    # timestamp belong to the Reconciliation Contract (3.4.3); the model
    # only requires that every fact carries one.
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Normalized evidence: source-system raw status, mapping notes,
    # reconcile diagnostics. NEVER contains callback credentials (frozen
    # security discipline inherited from execution_log.detail).
    detail: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)

    # Server clock only (same discipline as execution_log.created_at):
    # ingest time cannot be backdated from the client. Append-only facts
    # never update, so there is deliberately no updated_at.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ExecutionOutcome id={self.id} execution={self.execution_id} "
            f"status={self.outcome_status} source={self.source}>"
        )
