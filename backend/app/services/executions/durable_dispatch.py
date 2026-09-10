"""Durable pre-dispatch attempt store (M4-F §1 — "flush 不等于持久提交" fix).

THE PROBLEM. M4-A persisted the forward dispatch binding inside the ``dispatched``
execution_log row and flushed it BEFORE ``executor.execute()``. But the Execution
Service NEVER commits (frozen discipline in ``service.py``: ``add() + flush()``
only — the API caller owns the ONE business transaction and commits AFTER the
external request returns). A flush is NOT a durable commit: if the process
crashes, the terminal write fails, or the caller rolls back AFTER the external
request already fired, the flushed binding vanishes with the aborted transaction.

THE FIX. This store commits the dispatch intent + target binding on its OWN
transaction (a SEPARATE Session/connection derived from the caller's bind)
BEFORE the external request is sent. Because it is committed independently of the
caller's execution_log transaction, it SURVIVES a caller rollback, a terminal-write
failure or a process crash. Recovery then correlates a committed attempt that has
no terminal execution_log row -> a MANUAL reconciliation candidate (NEVER an
auto-retry: constraint 5 — an "emitted but no reliable terminal" attempt keeps its
uncertainty and a human-check path).

FROZEN-CONTRACT SAFE. This does NOT violate "the Service NEVER calls commit()":
that clause protects the CALLER's business transaction. This store owns a
SEPARATE session and commits ONLY that one — the exact precedent already set by
the outcomes services (webhook / manual_reconcile / manual_persist /
verified_proof), each of which manages its own flush+commit+rollback. The caller's
execution_log transaction is untouched; its commit boundary stays in the API layer.

SECRET-GATED. The binding projection passes ``redact_detail`` at this single write
point, and no binding field IS a credential (the endpoint is the validated
secret-free base URL; the version is a config declaration, never a liveness proof).
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

from app.models import DispatchAttempt
from app.models.execution_log import ExecutionLog
from app.services.executions.binding import TERMINAL_REFERENCE_KEY, DispatchBinding
from app.services.executions.secrets import redact_detail


class DurableDispatchAttemptStore:
    """Commits the pre-dispatch attempt binding on its OWN durable transaction.

    Constructed with a SQLAlchemy ``bind`` (an Engine — in production the API
    layer passes ``db.get_bind()``; in tests a file-backed engine). ``record``
    opens an INDEPENDENT Session on that bind, INSERTs the append-only
    ``DispatchAttempt`` row and COMMITS it, then closes. A duplicate
    ``execution_id`` (a replay/concurrent race) raises ``IntegrityError`` — the
    caller MUST treat that as "do not emit the external request".
    """

    def __init__(self, bind) -> None:
        self._bind = bind

    def record(self, binding: DispatchBinding) -> None:
        """Durably commit ``binding`` BEFORE the external request is sent.

        Returns ``None`` (the row is committed and the session closed, so there is
        deliberately no ORM object handed back — reading it after close would
        raise ``DetachedInstanceError``). On ANY failure the independent session
        is rolled back and the exception propagates, so the caller NEVER proceeds
        to the external adapter when the durable pre-dispatch fact did not commit.
        """
        detail = redact_detail(binding.to_detail())
        started_at = binding.started_at() or datetime.now(timezone.utc)
        row = DispatchAttempt(
            attempt_id=uuid.UUID(binding.attempt_id),
            execution_id=uuid.UUID(binding.execution_id),
            approval_id=uuid.UUID(binding.approval_id),
            adapter=binding.adapter,
            action=binding.action,
            target=binding.target,
            dispatch_started_at=started_at,
            detail=detail,
            # id / recorded_at intentionally unset -> model defaults (append-only).
        )
        # An INDEPENDENT Session on its own connection: committing HERE (not on the
        # caller's session) is what makes the attempt durable across the caller's
        # rollback / terminal-write failure / crash. The original IntegrityError is
        # re-raised UNWRAPPED so the Execution Service can translate a duplicate
        # execution_id into its typed 409 conflict (D14) — the store never hides it.
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


#: execution_log decisions that carry a TERMINAL audit for an attempt's dispatch.
#: M4-G §3 / M4-GR: a terminal SETTLES an attempt ONLY when ALL of the attempt's
#: IMMUTABLE durable facts agree — its ``detail`` REFERENCES that attempt's
#: ``attempt_id`` (``TERMINAL_REFERENCE_KEY``) AND the terminal row's ``execution_id``
#: equals the attempt's AND (a committed ``execution_log`` row always carries a
#: non-null ``approval_id``) its ``approval_id`` equals the attempt's. NEVER by
#: ``attempt_id`` or ``execution_id`` alone, so a stale / mis-attributed / cross-execution
#: / cross-approval terminal cannot mask a still-pending attempt. ``requested`` /
#: ``dispatched`` rows are NOT terminal and never settle an attempt.
_TERMINAL_DECISIONS = ("succeeded", "failed")


class RecoveryDisposition(str, Enum):
    """M4-G §3: the READ-ONLY epistemic classification of a committed dispatch
    attempt during recovery. The three states are KEPT DISTINCT and are NEVER
    collapsed into one another:

    * ``TERMINAL_AUDIT_PRESENT`` — a committed terminal execution_log row REFERENCES
      this attempt's ``attempt_id`` AND shares its ``execution_id`` + ``approval_id``
      (M4-GR: all three immutable facts must agree). The dispatch AUDIT is settled
      (``succeeded`` / ``failed``), but this is an AUDIT fact about what the SERVICE
      recorded, NOT a confirmation of the external world's effect. A ``failed`` terminal
      is NEVER ``confirmed_failure``: the external action may still have landed (a
      timeout AFTER the effect applied, a lost response).
    * ``DISPATCH_STATUS_UNKNOWN`` — a committed attempt with NO terminal row that
      agrees on ALL its immutable facts (execution_id + attempt_id + approval_id):
      "emitted but no reliable terminal". The external effect is UNKNOWN; this is a
      MANUAL, read-only human-reconciliation candidate, NEVER an auto-retry /
      re-dispatch / compensation, and NEVER a fabricated ``succeeded`` row.
    * ``EXTERNAL_EFFECT_CONFIRMED`` — the external effect was authoritatively
      confirmed. This state lives ONLY in the Outcome layer (``confirmed_success`` /
      ``confirmed_failure``), produced ONLY by the authoritative Manual Reconcile /
      trusted-reader proof path (``verify_creation_effect``) with a verified external
      reference. The recovery read NEVER produces it: neither a durable attempt, nor a
      terminal audit, nor any external JSON / ordinary internal object can authorize a
      confirmed effect here.
    """

    TERMINAL_AUDIT_PRESENT = "terminal_audit_present"
    DISPATCH_STATUS_UNKNOWN = "dispatch_status_unknown"
    EXTERNAL_EFFECT_CONFIRMED = "external_effect_confirmed"


@dataclass(frozen=True, slots=True)
class AttemptRecovery:
    """The READ-ONLY §3 recovery classification of ONE committed dispatch attempt.

    The identity facts (``adapter`` / ``action`` / ``target``) are the durable
    attempt's IMMUTABLE snapshot, NEVER back-filled from the current config. This
    record carries NO authorization power: it is evidence for a human operator, who
    reconciles through the EXISTING Manual Reconcile path (operator auth + RBAC +
    append-only Outcome + whitelist audit) — it can NEVER itself authorize a
    ``confirmed_success`` / ``confirmed_failure``.
    """

    attempt_id: uuid.UUID
    execution_id: uuid.UUID
    approval_id: uuid.UUID
    adapter: str
    action: str
    target: str
    disposition: RecoveryDisposition
    #: The terminal AUDIT decision (``succeeded`` / ``failed``) when a terminal agrees
    #: on ALL this attempt's immutable facts (execution_id + attempt_id + approval_id),
    #: else ``None``. An AUDIT fact only — NEVER an external-effect confirmation (a
    #: ``failed`` audit is NOT ``confirmed_failure``).
    audit_decision: str | None


@dataclass(frozen=True, slots=True)
class _TerminalRef:
    """One committed terminal execution_log row's IMMUTABLE correlation facts, as read
    for recovery: the ``execution_id`` / ``approval_id`` the row was written under and its
    terminal ``decision``. The referenced ``attempt_id`` (the dict key carrying this ref)
    is validated at parse time; whether the ref actually SETTLES a given
    ``DispatchAttempt`` is decided by :func:`_settling_decision`, which ALSO requires the
    ``execution_id`` + ``approval_id`` to equal the attempt's own immutable facts."""

    execution_id: uuid.UUID
    approval_id: uuid.UUID | None
    decision: str


def _terminal_refs_by_attempt(session: Session) -> dict[str, list[_TerminalRef]]:
    """Group every committed terminal execution_log row that REFERENCES an attempt (via
    ``TERMINAL_REFERENCE_KEY``) by its canonical referenced ``attempt_id`` (str).

    READ-ONLY. The dict key is ONLY the referenced attempt_id the REAL service stamps on
    the terminal row (``detail["dispatch_attempt_id"] = binding.attempt_id``); whether
    that reference actually SETTLES a given ``DispatchAttempt`` is decided by
    :func:`_settling_decision`, which ALSO requires the terminal's ``execution_id`` (and
    ``approval_id``) to equal the attempt's IMMUTABLE facts. A non-str / malformed
    reference is skipped (fail-closed — settles nothing). Rows scan oldest-first so the
    latest matching terminal wins (an attempt carries at most one terminal in practice —
    the service writes exactly one — but a corrupted history may carry several).
    """
    refs: dict[str, list[_TerminalRef]] = {}
    terminals = session.scalars(
        select(ExecutionLog)
        .where(ExecutionLog.decision.in_(_TERMINAL_DECISIONS))
        .order_by(ExecutionLog.created_at, ExecutionLog.id)
    ).all()
    for row in terminals:
        detail = row.detail if isinstance(row.detail, dict) else {}
        reference = detail.get(TERMINAL_REFERENCE_KEY)
        if not isinstance(reference, str):
            continue
        try:
            key = str(uuid.UUID(reference))  # canonicalize the reference
        except (ValueError, AttributeError, TypeError):
            continue  # a malformed reference settles nothing (fail-closed)
        refs.setdefault(key, []).append(
            _TerminalRef(
                execution_id=row.execution_id,
                approval_id=row.approval_id,
                decision=row.decision,
            )
        )
    return refs


def _settling_decision(
    attempt: DispatchAttempt, refs: dict[str, list[_TerminalRef]]
) -> str | None:
    """The terminal AUDIT decision that SETTLES ``attempt``, else ``None`` (M4-GR).

    A terminal settles the attempt ONLY when ALL of the attempt's IMMUTABLE durable facts
    agree with the terminal row:

    * ``terminal.execution_id == attempt.execution_id`` — a cross-execution terminal that
      merely references this ``attempt_id`` CANNOT settle it (the Final Review gap);
    * the referenced ``attempt_id`` equals ``attempt.attempt_id`` (the dict key); AND
    * when the terminal carries an ``approval_id`` (a committed ``execution_log`` row
      always does — it is non-nullable), ``terminal.approval_id == attempt.approval_id``.

    Any missing / malformed / cross-execution / cross-approval / wrong-attempt_id
    reference is fail-closed -> ``None`` -> DISPATCH_STATUS_UNKNOWN (the safe direction).
    The facts come from the immutable durable attempt and the committed terminal row ONLY
    — NEVER back-filled from the current config or another log. Oldest-first scan, so the
    latest fully-matching terminal's decision wins.
    """
    candidates = refs.get(str(attempt.attempt_id))
    if not candidates:
        return None
    decision: str | None = None
    for ref in candidates:
        if ref.execution_id != attempt.execution_id:
            continue  # cross-execution mis-reference cannot settle (M4-GR)
        if ref.approval_id is not None and ref.approval_id != attempt.approval_id:
            continue  # cross-approval mis-reference cannot settle (M4-GR)
        decision = ref.decision  # all immutable facts agree; latest match wins
    return decision


def _committed_attempts(session: Session) -> Sequence[DispatchAttempt]:
    """Every committed durable attempt, oldest-first (a stable recovery order)."""
    return session.scalars(
        select(DispatchAttempt).order_by(
            DispatchAttempt.recorded_at, DispatchAttempt.id
        )
    ).all()


def find_unreconciled_attempts(session: Session) -> Sequence[DispatchAttempt]:
    """Committed pre-dispatch attempts with NO committed terminal execution_log row that
    agrees on ALL their immutable facts — ``execution_id`` + ``attempt_id`` +
    ``approval_id`` (M4-G §3 / M4-GR).

    RECOVERY READ. After a crash / lost response / terminal-write failure / caller
    rollback, the durably committed ``DispatchAttempt`` SURVIVES while the caller's
    execution_log terminal (``succeeded`` / ``failed``) may never have committed. A
    terminal SETTLES an attempt ONLY when every immutable fact agrees (see
    :func:`_settling_decision`) — never by ``attempt_id`` or ``execution_id`` alone — so a
    stale / wrong-attempt / cross-execution / cross-approval terminal cannot mask a
    still-pending attempt. An attempt with no such terminal is "emitted but no reliable
    terminal" -> DISPATCH_STATUS_UNKNOWN, surfaced for MANUAL human reconciliation.

    It NEVER re-dispatches, retries or compensates (constraint 5): the external effect
    of such an attempt is UNKNOWN, and an absent terminal is NOT proof the external
    call failed. Pure read of committed data on the caller's session.
    """
    refs = _terminal_refs_by_attempt(session)
    return [
        attempt
        for attempt in _committed_attempts(session)
        if _settling_decision(attempt, refs) is None
    ]


def classify_attempt_recovery(session: Session) -> Sequence[AttemptRecovery]:
    """Classify EVERY committed dispatch attempt (READ-ONLY) into its §3 disposition.

    Surfaces the controlled, read-only manual-recovery view: each attempt is
    TERMINAL_AUDIT_PRESENT (a terminal agrees on ALL its immutable facts —
    execution_id + attempt_id + approval_id; ``audit_decision`` carries the
    succeeded/failed AUDIT) or DISPATCH_STATUS_UNKNOWN (no terminal agrees on all of
    them -> a human-check candidate). It NEVER yields EXTERNAL_EFFECT_CONFIRMED and
    NEVER interprets a ``failed`` audit as ``confirmed_failure`` — external-effect
    confirmation is the Outcome layer's, reachable ONLY through the authoritative
    reconcile / trusted-reader proof path.

    Pure read: NO write, NO re-dispatch, NO retry, NO compensation, NO Outcome fact,
    NO fabricated ``succeeded`` row. Recovery identity comes from the immutable
    durable attempt, never back-filled from the current config.
    """
    refs = _terminal_refs_by_attempt(session)
    classified: list[AttemptRecovery] = []
    for attempt in _committed_attempts(session):
        decision = _settling_decision(attempt, refs)
        disposition = (
            RecoveryDisposition.TERMINAL_AUDIT_PRESENT
            if decision is not None
            else RecoveryDisposition.DISPATCH_STATUS_UNKNOWN
        )
        classified.append(
            AttemptRecovery(
                attempt_id=attempt.attempt_id,
                execution_id=attempt.execution_id,
                approval_id=attempt.approval_id,
                adapter=attempt.adapter,
                action=attempt.action,
                target=attempt.target,
                disposition=disposition,
                audit_decision=decision,
            )
        )
    return classified
