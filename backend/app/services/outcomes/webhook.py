"""Webhook Outcome Fact Persistence.

The four inbound webhook gates have all passed; this module is the closing edge
that turns a fully-validated callback into a durable fact:

External System -> HTTP Webhook
-> Gate 1 Authentication
-> Gate 2 Schema
-> Gate 3 Correlation
-> Gate 4 Semantic Mapping
-> Outcome Fact Append           (this module)
-> commit -> HTTP 200 {"accepted": true}

This is the first stage allowed to write, and it writes exactly one thing: an
append-only INSERT into ``execution_outcome``. It is the last edge of the
``callback -> validated observation -> correlated execution -> mapped outcome
-> ExecutionOutcome INSERT -> commit -> 200`` chain.

The fact boundary. Two independent fact layers, never merged:
- ``execution_log``   = Dispatch Fact ("what happened to the execution
request", platform view). Read-only here — Gate 3 selects it to prove the
chain exists; this module never updates or deletes it, never rewrites a
dispatch decision, never touches dispatch history.
- ``execution_outcome`` = External Outcome Fact ("what the outside world later
did"). The only table this module writes.

Append-only. Every legal callback inserts one fact. No UPDATE, no UPSERT, no
MERGE, no DELETE, no dedup, no overwrite of a prior observation, no
``unique(execution_id, external_reference, outcome_status)``. A ``pending``
callback followed by a ``confirmed_success`` callback leaves two rows; a replayed
identical callback leaves a new row too. The time series is the audit trail (the
model has no unique index). Appending never mutates the rows already there.

Field provenance:
- ``execution_id``   <- the trusted identity Gate 3 confirmed exists
(``CorrelatedExecution.execution_id``), never the raw client value;
- ``outcome_status`` <- Gate 4 only (``StateMapping.outcome_status``). Never
derived from a dispatch result, an ``execution_log`` decision, the endpoint
adapter name, or a self-judged ``external_state`` string — Gate 4 is the
single semantic-mapping source;
- ``source``         <- the validated observation's ingress channel
(``"webhook"``);
- ``operator``       <- ``"adapter:{authenticated_adapter}"``, the server-side
trusted callback identity from Gate 1 — never a client-supplied operator;
- ``observed_at``    <- the contract-normalized UTC fact time;
- ``detail``         <- normalized evidence / mapping diagnostics passed
through ``redact_detail()`` before it reaches the ORM;
- ``created_at`` / ``id`` <- DB / server-side defaults, never set here.

``external_state`` is preserved raw: persistence is fact storage, not a second
normalization layer — no lower / upper / trim / semantic rewrite.

Transaction. Fixed order: every gate runs before ``session.add``; then add ->
flush -> commit. If flush or commit fails, the transaction is rolled back (so no
partial fact survives) and an ``OutcomePersistenceError`` is raised. A DB
persistence failure is not an external reconciliation state: it is never returned
as ``accepted=true`` and never laundered into ``reconciliation_failed`` (that word
belongs to the read-failure path). The router maps ``OutcomePersistenceError`` to
a 5xx.

No derived state. This module never updates a derived outcome and never stores a
``derived_outcome`` snapshot. The current state is computed on read by
``derive_outcome_state()`` over the fact series; the DB stores observations, not a
"latest state".

ORM identity. The fact is
``app.models.execution_outcome.ExecutionOutcome`` — imported under the explicit
alias ``ExecutionOutcomeFact`` so it can never be shadowed by the Pydantic
dispatch DTO ``app.services.executions.models.ExecutionOutcome`` (whose
vocabulary is only ``succeeded`` / ``failed``). Confusing the two is the largest
engineering risk here.

Security. The callback token, the Authorization header, any Bearer value and any
operator credential never reach this module (they live only at the HTTP edge and
are structurally absent from the body), and are additionally masked by
``redact_detail()``. No adapter read / ``get_status`` / ``query_status`` /
outbound HTTP happens here. No executor, no retry, no compensation, no execution
is triggered: a fact row is never an input to a write action.

This module does touch the database (unlike the pure Gate 3 / Gate 4 domains), but
only to insert one ``execution_outcome`` row and to let Gate 3 select
``execution_log``. It never imports FastAPI: HTTP status mapping belongs to the
router.
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
    """The single Outcome Fact append failed at the database layer.

Raised only after a ``rollback()``, so no partial fact survives. This is an
infrastructure failure, not a member of the ``ContractValidationFailure``
family and not an external reconciliation state: it must never become
``reconciliation_failed`` nor a 4xx contract rejection. The router maps it to
a 5xx. Domain layer — never imports FastAPI.
"""


def persist_callback_outcome(
    session: Session, observation: ExternalObservation
) -> ExecutionOutcomeFact:
    """Run Gates 2-4 over one authenticated callback observation and append the
resulting External Outcome Fact.

Order is fixed and every gate completes before ``session.add``:

- Gate 2 (contract semantics): ``validate_observation`` -> a
``NormalizedObservation``. (The Gate-2 type/presence check is the
router's Pydantic body; ``to_external_observation`` is the
schema->contract edge.) Raises a ``ContractValidationFailure`` -> no
fact;
- Gate 3 (correlation): ``correlate_execution`` selects ``execution_log``
(read-only) and returns the trusted ``execution_id``. Raises
``UnmappableExecutionId`` -> no fact;
- Gate 4 (semantic mapping): ``map_external_state`` -> the ``StateMapping``
whose ``outcome_status`` is the only source of the fact's outcome word.
Raises ``UnrecognizedExternalState`` -> no fact;
- Persist: build the ``ExecutionOutcomeFact``, redact its ``detail``, then
add -> flush -> commit. On any ``SQLAlchemyError``: rollback and raise
``OutcomePersistenceError``.

Returns the committed fact (callers and tests may inspect it; the router
returns only ``{"accepted": true}`` and never echoes the ORM). Append-only:
never updates / deletes / dedups an existing row, never writes
``execution_log``, never stores a derived state.
"""
    normalized = validate_observation(observation)
    correlated = correlate_execution(session, normalized.execution_id)
    mapping = map_external_state(normalized)

    # detail = normalized evidence / mapping diagnostics, redacted
    # before it reaches the ORM. external_state is echoed RAW
    # via mapping.observed_state — no second normalization here.
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
        # id / created_at intentionally unset -> model defaults.
    )

    try:
        session.add(fact)
        session.flush()
        session.commit()
    except SQLAlchemyError as exc:
        # / : a persistence failure rolls back (no partial fact)
        # and surfaces as a domain error the router maps to a 5xx — never
        # accepted=true, never reconciliation_failed.
        session.rollback()
        raise OutcomePersistenceError(
            "outcome fact persistence failed; the transaction was rolled back "
            "and no fact was written"
        ) from exc
    return fact
