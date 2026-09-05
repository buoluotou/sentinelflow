"""Webhook Gate 3 — Correlation (Phase 3.4.4-C).

The four-gate webhook inbound pipeline (design doc
``docs/design/phase3.4-reconciliation-contract.md``; 3.4.4 spec):

    HTTP JSON body
        -> Gate 1 Authentication    (3.4.4-A, sealed f35852b)
        -> Gate 2 Schema            (3.4.4-B, sealed 716a152)
        -> Gate 3 Correlation       (THIS MODULE, 3.4.4-C)
        -> Gate 4 Semantic Mapping  (3.4.4-D)
        -> Outcome Fact Append      (3.4.4-E)

Gate 1 proved WHO is calling; Gate 2 proved the body is a well-formed
``ExternalObservation`` shape (and 3.4.3-A proved ``execution_id`` is a
well-FORMED UUID). This gate answers the next — and
only the next — question:

    "Does the execution_id this callback claims actually correspond to an
     execution chain that ALREADY EXISTS on the platform?"

That is an EXISTENCE check against ``ExecutionLog.execution_id`` — the
CHAIN key, never the row primary key ``ExecutionLog.id`` (spec §3 / §17).
It is the first gate to touch the database, and it is STRICTLY READ-ONLY:

  - ``>= 1`` row for the execution_id  -> ``CorrelatedExecution`` (a trusted,
    correlated execution identity handed downstream);
  - ``0`` rows                         -> ``UnmappableExecutionId`` (the name
    FROZEN in design §13's Contract-Validation-Failure family).

Two rules bound this gate and are enforced by tests/test_correlation.py:

1. CORRELATION IS NOT VERDICT (spec §7 + the 3.4.4-C closing rule). A PASS
   proves ONLY that the chain EXISTS — never that the external effect
   succeeded. Even when the chain holds ``execution_log.succeeded``, this
   gate emits NO outcome word: ``confirmed_success`` and every other status
   belong to Gate 4 Semantic Mapping (3.4.4-D) + persistence (3.4.4-E). A
   FAIL is a pure REJECTION — it NEVER degrades to ``unknown`` /
   ``reconciliation_failed`` / ``confirmed_failure`` and NEVER writes an
   Outcome Fact.

2. READ-ONLY (spec §10 / §11). SELECT only — no INSERT / UPDATE / DELETE /
   COMMIT, no row lock, no mutation of ``execution_log``. Correlation reads
   the existing Dispatch Facts; it never rewrites them.

SCOPE — this module deliberately does NOT (spec §2 / §9 / §15):
  - map ``external_state`` onto an outcome word (Gate 4, 3.4.4-D);
  - persist an Outcome Fact / open a write transaction (3.4.4-E);
  - deep-check ``external_reference`` against the adapter's external system
    (the Shuffle / TheHive / Wazuh read paths do not exist yet — that is
    3.4.5 Manual Reconcile; inventing an external-identity mapping here is
    forbidden, spec §9);
  - raise ``HTTPException`` / import FastAPI — the domain layer stays
    transport-agnostic; the router maps ``UnmappableExecutionId`` to HTTP 404
    at final wiring (3.4.4-E), spec §15.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.execution_log import ExecutionLog
from app.services.outcomes.reconciliation import ContractValidationFailure


class UnmappableExecutionId(ContractValidationFailure):
    """``execution_id`` is a well-formed UUID but maps to NO existing
    execution chain (design §13 — frozen name, frozen semantics).

    It is a ``ContractValidationFailure``, so — exactly like every other R —
    it produces NO Outcome Fact and NEVER degrades to ``unknown`` /
    ``reconciliation_failed`` / ``confirmed_failure`` (spec §7): the callback
    is refused, audit-only.

    This is the EXISTENCE half of execution_id validation. 3.4.3-A already
    proved the FORMAT (``MissingExecutionId`` — present and a real UUID);
    this proves the chain EXISTS in the database. The two are deliberately
    distinct exceptions in ONE family — not a second exception system
    (spec §6 / §8).
    """


@dataclass(frozen=True, slots=True)
class CorrelatedExecution:
    """The trusted, correlated execution identity handed downstream.

    Fields:
      - ``execution_id``: the chain key CONFIRMED to exist (``>= 1``
        ``ExecutionLog`` row). Downstream consumes THIS trusted identity,
        never the raw untrusted callback input.
      - ``row_count``: existence evidence (``>= 1``). Deliberately NOT the
        dispatch decisions and NOT any derived state — correlation proves the
        chain EXISTS, never what the external effect was. Reading meaning
        into the rows is Gate 4 / 3.4.2's job, never this gate's.
    """

    execution_id: uuid.UUID
    row_count: int


def correlate_execution(
    session: Session, execution_id: uuid.UUID
) -> CorrelatedExecution:
    """Correlate a validated ``execution_id`` to its existing execution chain.

    READ-ONLY existence check (spec §4 / §10): SELECT the chain rows keyed on
    ``ExecutionLog.execution_id`` (the CHAIN key — NOT the row primary key
    ``id``, spec §17). ``>= 1`` row -> ``CorrelatedExecution``; ``0`` rows ->
    raise ``UnmappableExecutionId``.

    FORMAT is assumed already validated (3.4.3-A); this gate does NOT re-check
    "is it a UUID" (spec §8) — it checks EXISTENCE only.

    Pure read: it never mutates a row, never writes an Outcome Fact, and never
    interprets a dispatch decision into an outcome word (spec §7 + the closing
    rule). No executor, no adapter client, no external transport, no retry, no
    compensation (spec §2 / §13).
    """
    rows = list(
        session.scalars(
            select(ExecutionLog).where(ExecutionLog.execution_id == execution_id)
        )
    )
    if not rows:
        raise UnmappableExecutionId(
            f"execution_id {execution_id} maps to no existing execution chain"
        )
    return CorrelatedExecution(execution_id=execution_id, row_count=len(rows))
