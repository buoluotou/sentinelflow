"""Webhook Outcome Fact Persistence (Phase 3.4.4-E).

The four frozen webhook inbound gates have now all passed, and this module is
the closing edge that turns a fully-validated callback into durable fact:

    External System -> HTTP Webhook
        -> Gate 1 Authentication    (3.4.4-A, sealed f35852b)
        -> Gate 2 Schema            (3.4.4-B, sealed 716a152)
        -> Gate 3 Correlation       (3.4.4-C, sealed b3753b5)
        -> Gate 4 Semantic Mapping  (3.4.4-D, sealed 192f615)
        -> Outcome Fact Append      (THIS MODULE, 3.4.4-E)
        -> commit -> HTTP 200 {"accepted": true}

This is the FIRST step allowed to write, and it writes EXACTLY ONE thing: an
append-only INSERT into ``execution_outcome`` (the External Outcome Fact
layer). It is the last edge of the
``callback -> validated observation -> correlated execution -> mapped outcome
-> ExecutionOutcome INSERT -> commit -> 200`` chain.

THE FACT BOUNDARY (spec §2). Two independent fact layers, never merged:
  - ``execution_log``   = Dispatch Fact ("what happened to the execution
    request", platform view). READ-ONLY here — Gate 3 SELECTs it to prove the
    chain exists; this module NEVER UPDATEs / DELETEs it, never rewrites a
    dispatch decision, never touches dispatch history.
  - ``execution_outcome`` = External Outcome Fact ("what the outside world
    later did"). The ONLY table this module writes.

APPEND-ONLY (spec §3 / §17 / §18). Every legal callback INSERTs ONE fact. No
UPDATE, no UPSERT, no MERGE, no DELETE, no dedup, no overwrite of a prior
observation, no ``unique(execution_id, external_reference, outcome_status)``. A
``pending`` callback followed by a ``confirmed_success`` callback leaves TWO
rows; a replayed identical callback leaves a new row too. The time series IS
the audit trail (the model deliberately has no unique index). Appending never
mutates the N rows already there.

FIELD PROVENANCE (spec §5 / §6 / §7 / §8):
  - ``execution_id``   <- the TRUSTED identity Gate 3 confirmed exists
    (``CorrelatedExecution.execution_id``), never the raw client value;
  - ``outcome_status`` <- Gate 4 ONLY (``StateMapping.outcome_status``, i.e.
    3.4.4-D). NEVER derived from a dispatch result, an ``execution_log``
    decision, the endpoint adapter name, or a self-judged external_state
    string — D is the single semantic-mapping source;
  - ``source``         <- the validated observation's frozen ingress channel
    (``"webhook"``);
  - ``operator``       <- ``"adapter:{authenticated_adapter}"``, the
    SERVER-SIDE trusted callback identity from Gate 1 — NEVER a client-supplied
    operator;
  - ``observed_at``    <- the contract-normalized UTC fact time;
  - ``detail``         <- normalized evidence / mapping diagnostics passed
    through ``redact_detail()`` before it reaches the ORM;
  - ``created_at`` / ``id`` <- DB / server-side defaults, never set here.

``external_state`` is preserved RAW (spec §8): persistence is fact storage,
NOT a second normalization layer — no lower / upper / trim / semantic rewrite.

TRANSACTION (spec §9 / §10 / §24). Fixed order: every gate runs BEFORE
``session.add``; then add -> flush -> commit. If flush or commit fails, the
transaction is ROLLED BACK (so NO partial fact survives) and an
``OutcomePersistenceError`` is raised. A DB persistence failure is NOT an
external reconciliation state: it is NEVER returned as ``accepted=true`` and
NEVER laundered into ``reconciliation_failed`` (that word is the 3.4.5
read-failure verdict). The router maps ``OutcomePersistenceError`` to a 5xx.

NO DERIVED STATE (spec §16). This module never UPDATEs a derived outcome and
never stores a ``derived_outcome`` snapshot. The current state is still
computed on read by 3.4.2 ``derive_outcome_state()`` over the fact series; the
DB stores observations, not a "latest state".

ORM IDENTITY (spec §4 / §23). The fact is
``app.models.execution_outcome.ExecutionOutcome`` — imported under the explicit
alias ``ExecutionOutcomeFact`` so it can NEVER be shadowed by the Pydantic
dispatch DTO ``app.services.executions.models.ExecutionOutcome`` (whose
vocabulary is only ``succeeded`` / ``failed``). Confusing the two is the single
largest engineering risk of this step.

SECURITY (spec §20 / §21). The callback token, the Authorization header, any
Bearer value and any operator credential NEVER reach this module (they live
only at the HTTP edge and are structurally absent from the body), and are
additionally masked by ``redact_detail()``. NO adapter read / ``get_status`` /
``query_status`` / outbound HTTP happens here (spec §29 — that is 3.4.5). NO
executor, no retry, no compensation, no execution is triggered (spec §22.H): a
fact row is never an input to a write action.

This module DOES touch the database (unlike the pure Gate 3 / Gate 4 domains),
but only to INSERT one ``execution_outcome`` row and to let Gate 3 SELECT
``execution_log``. It never imports FastAPI (spec §12): HTTP status mapping
belongs to the router.
"""

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.execution_outcome import (
    ExecutionOutcome as ExecutionOutcomeFact,
)
from app.services.executions.secrets import redact_detail
from app.services.outcomes.correlation import correlate_execution
from app.services.outcomes.mapping import map_external_state
from app.services.outcomes.reconciliation import (
    ExternalObservation,
    validate_observation,
)


class OutcomePersistenceError(Exception):
    """The single Outcome Fact append FAILED at the database layer.

    Raised only AFTER a ``rollback()`` (spec §10 / §24), so no partial fact
    survives. This is an INFRASTRUCTURE failure, deliberately NOT a member of
    the ``ContractValidationFailure`` family and NOT an external reconciliation
    state: it must never become ``reconciliation_failed`` (the 3.4.5
    read-failure verdict) nor a 4xx contract rejection. The router maps it to a
    5xx. Domain layer — never imports FastAPI (spec §12).
    """


def persist_callback_outcome(
    session: Session, observation: ExternalObservation
) -> ExecutionOutcomeFact:
    """Run Gates 2-4 over one authenticated callback observation and append the
    resulting External Outcome Fact (spec §1 / §9 / §13).

    Order is fixed and every gate completes BEFORE ``session.add`` (spec §9):

      - Gate 2 (contract semantics): ``validate_observation`` -> a frozen
        ``NormalizedObservation``. (The Gate-2 TYPE/presence check is the
        router's Pydantic body; ``to_external_observation`` is the
        Schema->Contract edge.) Raises a ``ContractValidationFailure`` -> no
        fact;
      - Gate 3 (correlation): ``correlate_execution`` SELECTs ``execution_log``
        (READ-ONLY) and returns the TRUSTED ``execution_id``. Raises
        ``UnmappableExecutionId`` -> no fact;
      - Gate 4 (semantic mapping): ``map_external_state`` -> the frozen
        ``StateMapping`` whose ``outcome_status`` is the ONLY source of the
        fact's outcome word (spec §6). Raises ``UnrecognizedExternalState`` ->
        no fact;
      - Persist: build the ``ExecutionOutcomeFact``, redact its ``detail``, then
        add -> flush -> commit. On any ``SQLAlchemyError``: rollback and raise
        ``OutcomePersistenceError`` (spec §10).

    Returns the committed fact (callers/tests may inspect it; the router
    returns ONLY ``{"accepted": true}`` and never echoes the ORM, spec §16 /
    §25). Append-only: never UPDATEs / DELETEs / dedups an existing row
    (spec §3 / §17), never writes ``execution_log`` (spec §2), never stores a
    derived state (spec §16).
    """
    normalized = validate_observation(observation)
    correlated = correlate_execution(session, normalized.execution_id)
    mapping = map_external_state(normalized)

    # detail = normalized evidence / mapping diagnostics (spec §7), redacted
    # before it reaches the ORM (spec §20 / §21). external_state is echoed RAW
    # via mapping.observed_state — no second normalization here (spec §8).
    detail = redact_detail(
        {
            "adapter": mapping.adapter,
            "external_reference": normalized.external_reference,
            "observed_state": mapping.observed_state,
            "normalized_state": mapping.normalized_state,
            "outcome_status": mapping.outcome_status,
            "mapping_reason": mapping.mapping_reason,
        }
    )

    fact = ExecutionOutcomeFact(
        execution_id=correlated.execution_id,
        outcome_status=mapping.outcome_status,
        source=normalized.source,
        operator=f"adapter:{normalized.adapter}",
        observed_at=normalized.observed_at,
        detail=detail,
        # id / created_at intentionally unset -> model defaults (spec §5).
    )

    try:
        session.add(fact)
        session.flush()
        session.commit()
    except SQLAlchemyError as exc:
        # spec §10 / §24: a persistence failure rolls back (no partial fact)
        # and surfaces as a domain error the router maps to a 5xx — never
        # accepted=true, never reconciliation_failed.
        session.rollback()
        raise OutcomePersistenceError(
            "outcome fact persistence failed; the transaction was rolled back "
            "and no fact was written"
        ) from exc
    return fact
