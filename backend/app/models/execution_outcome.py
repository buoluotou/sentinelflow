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

# Outcome vocabulary: five words describing what the external world
# eventually did, never what the platform dispatched. The boundary between
# the two failure words: `reconciliation_failed` means the reconcile action
# itself failed and the external state could not be read, so its fact source
# is the reconciliation process; `confirmed_failure` means the external
# effect was confirmed not to have been achieved, so its fact source is the
# outside world. The two sources of fact are different and never merge.
OUTCOME_STATUSES = frozenset(
    {
        "unknown",
        "pending",
        "confirmed_success",
        "confirmed_failure",
        "reconciliation_failed",
    }
)
# The subset that carries a confirmed external verdict; both the outcome
# derivation and the outcome metrics build on this split.
CONFIRMED_OUTCOME_STATUSES = frozenset({"confirmed_success", "confirmed_failure"})

# Fact ingress channels: webhook is the push-first realtime source;
# manual_reconcile is the operator-explicit pull fallback. No third channel
# exists — background polling and schedulers never write outcome facts.
OUTCOME_SOURCES = frozenset({"webhook", "manual_reconcile"})


class ExecutionOutcome(Base):
    """One row of the append-only external-outcome fact log.

An independent fact layer over execution_log, not an extension of
`execution_log.decision`: the dispatch log answers what happened to the
execution request (platform view), while this table answers what the
external world later did (outside view).

The two layers keep separate vocabularies. `execution_log.succeeded` /
`failed` remain the dispatch outcome; this table records the external
effect outcome. Neither layer reinterprets or rewrites the other:
- dispatch=succeeded with outcome=confirmed_failure is legal: the
command was delivered but the effect was not achieved;
- dispatch=failed never creates confirmed_success by itself, but a
manual reconcile may record it when the outside world reports it
(lost responses and network breaks make the layers disagree). The
outcome layer records facts; it does not rewrite dispatch history.

Append-only: INSERT only, no UPDATE, no DELETE. Several facts per
execution_id form a time series, and the derived outcome state is the
fact with the latest `observed_at`; the model stores no derived state.
There is no unique index here on purpose: late or reordered facts are
appended rather than rejected or overwritten, and a replay produces no
new fact.

An observation is not an intent: a row here can never trigger execution,
retry or compensation, because those paths never read this table as an
input to a write action.
"""

    __tablename__ = "execution_outcome"
    __table_args__ = (
        # Storage-level vocabulary guard, and the last line of defence.
        # Dispatch-layer words such as `succeeded` / `failed` are not legal
        # here: the two vocabularies must never cross-contaminate.
        CheckConstraint(
            "outcome_status IN ("
            "'unknown', 'pending', 'confirmed_success', "
            "'confirmed_failure', 'reconciliation_failed')",
            name="ck_execution_outcome_status",
        ),
        # Ingress channel guard: exactly the two known sources.
        CheckConstraint(
            "source IN ('webhook', 'manual_reconcile')",
            name="ck_execution_outcome_source",
        ),
        # Derivation query path: the latest observed fact per execution.
        # Non-unique on purpose — the time series is the audit trail.
        Index(
            "ix_execution_outcome_execution_id_observed_at",
            "execution_id",
            "observed_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # The execution chain this fact belongs to. A plain column, not a foreign
    # key, for the same reason as execution_log.compensates_execution_id:
    # execution_id is a caller-supplied chain key spread over several
    # execution_log rows, not a primary key. The link is read-only — outcome
    # facts never write back into the dispatch log.
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)

    # The five-word outcome vocabulary; the CHECK above is the last line of
    # defence.
    outcome_status: Mapped[str] = mapped_column(String(32), nullable=False)

    # Which ingress channel recorded the fact: webhook (push) or
    # manual_reconcile (operator-explicit pull).
    source: Mapped[str] = mapped_column(String(16), nullable=False)

    # Recorder identity, per trust domain: for manual_reconcile it is the
    # authenticated operator taken from the token (token → operator → role),
    # never a client-declared string; for webhook it is the adapter callback
    # identity. Human and machine identities stay distinguishable in the
    # audit trail, as execution_log.operator does for dispatch.
    operator: Mapped[str] = mapped_column(String(128), nullable=False)

    # When the external world was observed (fact time, not ingest time).
    # Derivation orders by this column, so the latest observation is the
    # current outcome state. Validation and normalization rules for this
    # timestamp belong to the reconciliation layer; the model only requires
    # that every fact carries one.
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Normalized evidence: source-system raw status, mapping notes and
    # reconcile diagnostics. It never contains callback credentials, the same
    # rule as execution_log.detail.
    detail: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)

    # Server clock only (the same rule as execution_log.created_at): ingest
    # time cannot be backdated from the client. Append-only facts are never
    # updated, so there is no updated_at column.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ExecutionOutcome id={self.id} execution={self.execution_id} "
            f"status={self.outcome_status} source={self.source}>"
        )
