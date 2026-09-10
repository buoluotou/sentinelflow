"""Durable pre-compensation attempt store (RC2 / C-1 — the reverse of durable_dispatch).

THE PROBLEM. The forward path has M4-F §1 / M4-G §2: the immutable dispatch
binding commits on its OWN transaction BEFORE ``executor.execute()``. The
reverse path had no equivalent — ``compensate_response`` fired
``executor.compensate()`` with only a flushed ``compensation_requested`` row,
so a caller rollback, a terminal-write failure or a process crash AFTER the
external reverse request could erase every durable trace of the attempt while
the external effect may already have applied.

THE FIX. This store commits the compensation intent + reverse binding on its
OWN transaction (a SEPARATE Session/connection derived from the caller's bind)
BEFORE the external compensation request is sent. Because it is committed
independently of the caller's execution_log transaction, it SURVIVES a caller
rollback, a terminal-write failure or a process crash. Recovery then correlates
a committed attempt that has no terminal compensation row -> a MANUAL
reconciliation candidate (NEVER an auto-retry).

FROZEN-CONTRACT SAFE. This does NOT violate "the Service NEVER calls commit()":
that clause protects the CALLER's business transaction. This store owns a
SEPARATE session and commits ONLY that one — the exact precedent already set by
``durable_dispatch`` and the outcomes services. The caller's execution_log
transaction is untouched; its commit boundary stays in the API layer.

SECRET-GATED. The binding projection passes ``redact_detail`` at this single
write point, and no binding field IS a credential (the endpoint is the
validated secret-free base URL; the version is a config declaration, never a
liveness proof).
"""
from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import CompensationAttempt
from app.models.execution_log import ExecutionLog
from app.services.executions.compensation_binding import (
    COMPENSATION_REFERENCE_KEY,
    CompensationBinding,
)
from app.services.executions.secrets import redact_detail


class DurableCompensationAttemptStore:
    """Commits the pre-compensation reverse binding on its OWN durable transaction.

    Constructed with a SQLAlchemy ``bind`` (an Engine — in production the API
    layer passes ``db.get_bind()``; in tests a file-backed engine). ``record``
    opens an INDEPENDENT Session on that bind, INSERTs the append-only
    ``CompensationAttempt`` row and COMMITS it, then closes. A duplicate
    ``original_execution_id`` (a replay / concurrent race — the C-1
    reservation) raises ``IntegrityError`` — the caller MUST treat that as
    "do not emit the external reverse request".
    """

    def __init__(self, bind) -> None:
        self._bind = bind

    def record(self, binding: CompensationBinding) -> None:
        """Durably commit ``binding`` BEFORE the external compensation request is sent.

        Returns ``None`` (the row is committed and the session closed, so there
        is deliberately no ORM object handed back). On ANY failure the
        independent session is rolled back and the exception propagates, so the
        caller NEVER proceeds to the external adapter when the durable
        pre-compensation fact did not commit.
        """
        detail = redact_detail(binding.to_detail())
        prepared = binding.prepared_instant() or datetime.now(timezone.utc)
        started_at = binding.started_at() or prepared
        row = CompensationAttempt(
            compensation_attempt_id=uuid.UUID(binding.compensation_attempt_id),
            execution_id=uuid.UUID(binding.execution_id),
            original_execution_id=uuid.UUID(binding.original_execution_id),
            original_dispatch_attempt_id=(
                uuid.UUID(binding.original_dispatch_attempt_id)
                if binding.original_dispatch_attempt_id
                else None
            ),
            approval_id=uuid.UUID(binding.approval_id),
            adapter=binding.adapter,
            reverse_action=binding.reverse_action,
            target=binding.target,
            endpoint=binding.endpoint,
            operator=binding.operator,
            reason=binding.reason,
            original_outcome_state=binding.original_outcome_state,
            prepared_at=prepared,
            dispatch_started_at=started_at,
            detail=detail,
            # id / recorded_at intentionally unset -> model defaults (append-only).
        )
        # An INDEPENDENT Session on its own connection: committing HERE (not on
        # the caller's session) is what makes the attempt durable across the
        # caller's rollback / terminal-write failure / crash. The original
        # IntegrityError is re-raised UNWRAPPED so the Execution Service can
        # translate a duplicate original_execution_id into its typed 409 — the
        # store never hides it.
        session = Session(self._bind)
        try:
            session.add(row)
            session.flush()
            session.commit()
        except SQLAlchemyError:
            session.rollback()
            raise
        finally:
            session.close()


#: execution_log decisions of the COMPENSATION chain that carry a TERMINAL
#: audit for an attempt's reverse dispatch. A terminal SETTLES a compensation
#: attempt ONLY when ALL of the attempt's IMMUTABLE durable facts agree — its
#: ``detail`` REFERENCES that attempt's ``compensation_attempt_id``
#: (``COMPENSATION_REFERENCE_KEY``) AND the terminal row's ``execution_id``
#: equals the attempt's AND its ``approval_id`` equals the attempt's. NEVER by
#: the attempt id alone, so a stale / mis-attributed / cross-execution terminal
#: cannot mask a still-pending compensation attempt. ``compensation_requested``
#: rows are NOT terminal and never settle an attempt.
_COMPENSATION_TERMINAL_DECISIONS = ("compensation_succeeded", "compensation_failed")


class CompensationRecoveryDisposition(str, Enum):
    """The READ-ONLY epistemic classification of a committed compensation
    attempt during recovery. The three states are KEPT DISTINCT and are NEVER
    collapsed into one another:

    * ``TERMINAL_AUDIT_PRESENT`` — a committed terminal compensation row
      REFERENCES this attempt's ``compensation_attempt_id`` AND shares its
      ``execution_id`` + ``approval_id``. The compensation AUDIT is settled
      (``compensation_succeeded`` / ``compensation_failed``), but this is an
      AUDIT fact about what the SERVICE recorded, NOT a confirmation of the
      external world's reverse effect. A ``compensation_failed`` terminal is
      NEVER ``confirmed_failure``: the external reverse action may still have
      landed (a timeout AFTER the effect applied, a lost response).
    * ``DISPATCH_STATUS_UNKNOWN`` — a committed attempt with NO terminal that
      agrees on ALL its immutable facts: "emitted but no reliable terminal".
      The external reverse effect is UNKNOWN; this is a MANUAL, read-only
      human-reconciliation candidate, NEVER an auto-retry / re-compensation /
      re-dispatch, and NEVER a fabricated ``compensation_succeeded`` row.
    * ``EXTERNAL_EFFECT_CONFIRMED`` — the external reverse effect was
      authoritatively confirmed. This state lives ONLY in the Outcome layer,
      produced ONLY by the authoritative Manual Reconcile / trusted-reader
      proof path. The recovery read NEVER produces it.
    """

    TERMINAL_AUDIT_PRESENT = "terminal_audit_present"
    DISPATCH_STATUS_UNKNOWN = "dispatch_status_unknown"
    EXTERNAL_EFFECT_CONFIRMED = "external_effect_confirmed"


@dataclass(frozen=True, slots=True)
class CompensationRecovery:
    """The READ-ONLY recovery classification of ONE committed compensation attempt.

    The identity facts (``adapter`` / ``reverse_action`` / ``target``) are the
    durable attempt's IMMUTABLE snapshot, NEVER back-filled from the current
    config. This record carries NO authorization power: it is evidence for a
    human operator, who reconciles through the EXISTING Manual Reconcile path.
    """

    compensation_attempt_id: uuid.UUID
    execution_id: uuid.UUID
    original_execution_id: uuid.UUID
    approval_id: uuid.UUID
    adapter: str
    reverse_action: str
    target: str
    disposition: CompensationRecoveryDisposition
    #: The terminal AUDIT decision (``compensation_succeeded`` /
    #: ``compensation_failed``) when a terminal agrees on ALL this attempt's
    #: immutable facts, else ``None``. An AUDIT fact only — NEVER an
    #: external-effect confirmation.
    audit_decision: str | None


@dataclass(frozen=True, slots=True)
class _CompensationTerminalRef:
    """One committed terminal compensation row's IMMUTABLE correlation facts,
    as read for recovery: the ``execution_id`` / ``approval_id`` the row was
    written under and its terminal ``decision``. Whether the ref actually
    SETTLES a given ``CompensationAttempt`` is decided by
    :func:`_settling_compensation_decision`."""

    execution_id: uuid.UUID
    approval_id: uuid.UUID | None
    decision: str


def _compensation_terminal_refs_by_attempt(
    session: Session,
) -> dict[str, list[_CompensationTerminalRef]]:
    """Group every committed terminal compensation row that REFERENCES an
    attempt (via ``COMPENSATION_REFERENCE_KEY``) by its canonical referenced
    ``compensation_attempt_id`` (str).

    READ-ONLY. A non-str / malformed reference is skipped (fail-closed —
    settles nothing). Rows scan oldest-first so the latest matching terminal
    wins.
    """
    refs: dict[str, list[_CompensationTerminalRef]] = {}
    terminals = session.scalars(
        select(ExecutionLog)
        .where(ExecutionLog.decision.in_(_COMPENSATION_TERMINAL_DECISIONS))
        .order_by(ExecutionLog.created_at, ExecutionLog.id)
    ).all()
    for row in terminals:
        detail = row.detail if isinstance(row.detail, dict) else {}
        reference = detail.get(COMPENSATION_REFERENCE_KEY)
        if not isinstance(reference, str):
            continue
        try:
            key = str(uuid.UUID(reference))  # canonicalize the reference
        except (ValueError, AttributeError, TypeError):
            continue  # a malformed reference settles nothing (fail-closed)
        refs.setdefault(key, []).append(
            _CompensationTerminalRef(
                execution_id=row.execution_id,
                approval_id=row.approval_id,
                decision=row.decision,
            )
        )
    return refs


def _settling_compensation_decision(
    attempt: CompensationAttempt, refs: dict[str, list[_CompensationTerminalRef]]
) -> str | None:
    """The terminal AUDIT decision that SETTLES ``attempt``, else ``None``.

    A terminal settles the attempt ONLY when ALL of the attempt's IMMUTABLE
    durable facts agree with the terminal row:

    * ``terminal.execution_id == attempt.execution_id`` — a cross-execution
      terminal that merely references this ``compensation_attempt_id`` CANNOT
      settle it;
    * the referenced ``compensation_attempt_id`` equals
      ``attempt.compensation_attempt_id`` (the dict key); AND
    * when the terminal carries an ``approval_id`` (a committed
      ``execution_log`` row always does), ``terminal.approval_id ==
      attempt.approval_id``.

    Any missing / malformed / cross-execution / cross-approval / wrong-attempt
    reference is fail-closed -> ``None`` -> DISPATCH_STATUS_UNKNOWN (the safe
    direction). Oldest-first scan, so the latest fully-matching terminal's
    decision wins.
    """
    candidates = refs.get(str(attempt.compensation_attempt_id))
    if not candidates:
        return None
    decision: str | None = None
    for ref in candidates:
        if ref.execution_id != attempt.execution_id:
            continue  # cross-execution mis-reference cannot settle
        if ref.approval_id is not None and ref.approval_id != attempt.approval_id:
            continue  # cross-approval mis-reference cannot settle
        decision = ref.decision  # all immutable facts agree; latest match wins
    return decision


def _committed_compensations(session: Session) -> Sequence[CompensationAttempt]:
    """Every committed durable compensation attempt, oldest-first (a stable
    recovery order)."""
    return session.scalars(
        select(CompensationAttempt).order_by(
            CompensationAttempt.recorded_at, CompensationAttempt.id
        )
    ).all()


def find_unreconciled_compensations(session: Session) -> Sequence[CompensationAttempt]:
    """Committed pre-compensation attempts with NO committed terminal
    compensation row that agrees on ALL their immutable facts —
    ``execution_id`` + ``compensation_attempt_id`` + ``approval_id``.

    RECOVERY READ. After a crash / lost response / terminal-write failure /
    caller rollback, the durably committed ``CompensationAttempt`` SURVIVES
    while the caller's terminal compensation row (``compensation_succeeded`` /
    ``compensation_failed``) may never have committed. An attempt with no
    agreeing terminal is "emitted but no reliable terminal" ->
    DISPATCH_STATUS_UNKNOWN, surfaced for MANUAL human reconciliation.

    It NEVER re-dispatches, retries or compensates: the external reverse effect
    of such an attempt is UNKNOWN, and an absent terminal is NOT proof the
    external call failed. Pure read of committed data on the caller's session.
    """
    refs = _compensation_terminal_refs_by_attempt(session)
    return [
        attempt
        for attempt in _committed_compensations(session)
        if _settling_compensation_decision(attempt, refs) is None
    ]


def classify_compensation_recovery(
    session: Session,
) -> Sequence[CompensationRecovery]:
    """Classify EVERY committed compensation attempt (READ-ONLY) into its disposition.

    Surfaces the controlled, read-only manual-recovery view: each attempt is
    TERMINAL_AUDIT_PRESENT (a terminal agrees on ALL its immutable facts;
    ``audit_decision`` carries the compensation_succeeded/failed AUDIT) or
    DISPATCH_STATUS_UNKNOWN (no terminal agrees on all of them -> a
    human-check candidate). It NEVER yields EXTERNAL_EFFECT_CONFIRMED and NEVER
    interprets a ``compensation_failed`` audit as ``confirmed_failure`` —
    external-effect confirmation is the Outcome layer's, reachable ONLY through
    the authoritative reconcile / trusted-reader proof path.

    Pure read: NO write, NO re-dispatch, NO retry, NO re-compensation, NO
    Outcome fact, NO fabricated ``compensation_succeeded`` row. Recovery
    identity comes from the immutable durable attempt, never back-filled from
    the current config.
    """
    refs = _compensation_terminal_refs_by_attempt(session)
    classified: list[CompensationRecovery] = []
    for attempt in _committed_compensations(session):
        decision = _settling_compensation_decision(attempt, refs)
        disposition = (
            CompensationRecoveryDisposition.TERMINAL_AUDIT_PRESENT
            if decision is not None
            else CompensationRecoveryDisposition.DISPATCH_STATUS_UNKNOWN
        )
        classified.append(
            CompensationRecovery(
                compensation_attempt_id=attempt.compensation_attempt_id,
                execution_id=attempt.execution_id,
                original_execution_id=attempt.original_execution_id,
                approval_id=attempt.approval_id,
                adapter=attempt.adapter,
                reverse_action=attempt.reverse_action,
                target=attempt.target,
                disposition=disposition,
                audit_decision=decision,
            )
        )
    return classified
