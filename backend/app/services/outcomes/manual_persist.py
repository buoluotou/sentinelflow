"""Manual Reconcile SUCCESS Outcome Persistence (Phase 3.4.5-A2-E).

The PULL-side sibling of ``webhook.py``'s ``persist_callback_outcome``. Where the
webhook persists an outcome an EXTERNAL SYSTEM pushed, this module persists the
outcome of a SUCCESSFUL external READ that an authenticated human operator asked
the platform to perform (``source="manual_reconcile"``). It is the closing edge of
the A2-E success chain::

    Manual Reconcile -> Correlation -> Reference Extraction -> Read (SUCCESS)
        -> ExternalObservation
        -> validate_observation()   (3.4.3-A, REUSED — never skipped)
        -> map_external_state()     (3.4.3-B via mapping.py, the ONLY mapping source)
        -> StateMapping.outcome_status
        -> redact_detail()          (the final secret gate)
        -> ExecutionOutcomeFact INSERT (append-only)
        -> commit

WHY A SEPARATE MODULE (the A2-E placement decision). ``manual_reconcile.py`` is
the pipeline orchestrator, but its import surface is AST-audited by the SEALED
A2-C / A2-B acceptance tests — ``test_manual_reconcile_reader.py::test_18_no_mapping``
and ``test_manual_reconcile_correlation.py::test_20_no_mapping`` /
``test_21_no_outcome_persistence`` — which forbid THAT module from binding
``map_external_state`` / ``normalize_external_state`` / ``validate_observation`` /
the ``ExecutionOutcome`` ORM directly. Those assertions encode a REAL invariant
(the read-only orchestrator must not itself become the mapper/writer), so A2-E does
NOT weaken them. Instead the SUCCESS ``validate -> map -> append`` edge lives HERE
and ``manual_reconcile.py`` delegates through the single non-forbidden function
name ``persist_reconcile_outcome``. The dependency is one-way (orchestrator -> this
module), exactly as ``webhook.py`` sits beside the webhook router. This module is
NOT inside the sealed A1 read-contract package (``app/services/manual_reconcile/read/``,
AST-audited by ``test_adapter_read_contract.py``) — it lives in ``outcomes/`` beside
``webhook.py``, so it MAY own a DB transaction and import the persistence vocabulary.

TWO TRUST-DOMAIN DIFFERENCES from ``webhook.py`` (spec §七 / §十一 — the reason this
is NOT a call to ``persist_callback_outcome``):
  - ``operator`` is the AUTHENTICATED HUMAN operator (``Operator.name``), NEVER the
    webhook's machine-domain ``adapter:{identity}``;
  - ``source`` is ``"manual_reconcile"``, never ``"webhook"``.
Everything else (validate -> map -> redact -> append-only INSERT -> rollback on
failure) mirrors the sealed webhook persister, so the two ingress channels append
the SAME fact shape and never diverge.

OBSERVED_AT (spec §七 / §十一 + the A1 contract). ``AdapterReadResult.observed_at``
is ``datetime | None`` (A1 ``read/base.py``): when the external system supplies a
reliable timestamp it is used (``observed_at_kind="external"``); when it is absent
the PLATFORM supplies the SERVER OBSERVATION time (``datetime.now(timezone.utc)``,
``observed_at_kind="server-observation"``) — the A1 contract explicitly requires
this, and it matches how the read-FAILURE path stamps its fact (A2-D §9). Either
way ``validate_observation`` re-normalizes it to aware UTC and rejects a naive /
excessive-future value (``InvalidObservedAt`` -> the router's 422), so NO fact ever
carries an unvalidated time.

READ FAILURE IS NOT THIS MODULE (spec §五). A read that FAILS in transit has NO
``external_state``, so it NEVER enters ``validate_observation`` / ``map_external_state``
here — ``manual_reconcile.py`` converts it to ``reconciliation_failed`` inline
(A2-D, sealed). This module ONLY persists a SUCCESSFUL read's mapped outcome; it
never fabricates an ``external_state=None`` observation to feed the mapper.

APPEND-ONLY + NO DERIVED STATE (spec §九 / §十 / §十一). ONE INSERT, never UPDATE /
UPSERT / MERGE / DELETE; historical facts are untouched (a prior ``confirmed_success``
survives a later reconcile that appends a new observation). NO ``derived_state`` is
stored — the current state is computed on read by ``derive_outcome_state()`` (3.4.2)
over ``observed_at DESC, id DESC``.

TRANSACTION + SECURITY (spec §十五 / §十六 / §二十三). Every step runs BEFORE
``session.add``; then add -> flush -> commit; on ``SQLAlchemyError`` rollback (NO
partial fact survives) and raise ``OutcomePersistenceError`` (REUSED from
``webhook.py`` — never a second error type) -> the router maps a 5xx, never
``accepted=true``. The ``detail`` passes through ``redact_detail()`` so NO API key /
password / Authorization / token / raw external payload survives into the fact; the
raw ``AdapterReadResult.raw_evidence`` payload is deliberately NOT persisted (only
the mapped ``observed_state`` / ``normalized_state`` evidence is — spec §十五 lists
exactly those, and §二十三 forbids echoing a raw external payload). NO executor, NO
retry, NO compensation, NO HTTP, NO write adapter, NO background worker: a fact row
is never an input to a write action.

ORM IDENTITY (spec §六). The fact is ``app.models.execution_outcome.ExecutionOutcome``
imported under the explicit alias ``ExecutionOutcomeFact`` (REUSED from
``webhook.py``), NEVER the Pydantic dispatch DTO
``app.services.executions.models.ExecutionOutcome`` (whose vocabulary is only
``succeeded`` / ``failed``). Confusing the two is the single largest risk of this
step; the alias makes the ORM identity unambiguous.
"""
from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.schemas.reconcile import MANUAL_RECONCILE_SOURCE
from app.services.executions.secrets import redact_detail
from app.services.outcomes.mapping import map_external_state
from app.services.outcomes.reconciliation import (
    ExternalObservation,
    validate_observation,
)
from app.services.outcomes.webhook import (
    ExecutionOutcomeFact,
    OutcomePersistenceError,
)


@dataclass(frozen=True, slots=True)
class ReconciledOutcome:
    """The SUCCESS result of one manual-reconcile read (spec §七 / §十一).

    Carries ONLY what ``manual_reconcile.py`` needs to build the frozen
    ``ManualReconcileResponse`` envelope: the mapped ``outcome_status`` (3.4.3-B),
    the AWARE ``observed_at`` actually persisted, and the ``observed_at_kind`` that
    tells a caller whether that timestamp came from the external system or from our
    own server clock. ``observed_at`` is the VALIDATED observation time (the local
    aware value), NOT a re-read of ``fact.observed_at`` — a SQLite
    ``DateTime(timezone=True)`` round-trip drops ``tzinfo`` and yields a naive
    value, so echoing the in-hand aware datetime keeps the response correct on the
    test backend. NO derived state (computed on read, spec §十一), NO ORM row (never
    echoed to the client, spec §二十三).
    """

    outcome_status: str
    observed_at: datetime
    observed_at_kind: str


def persist_reconcile_outcome(
    session: Session,
    *,
    execution_id: uuid.UUID,
    adapter: str,
    external_reference: str | None,
    external_state: str | Mapping,
    observed_at: datetime | None,
    operator: str,
) -> ReconciledOutcome:
    """Validate + map + append ONE Outcome Fact for a SUCCESSFUL manual read.

    Called ONLY after ``read_external_state`` returned an ``AdapterReadResult``
    (A2-C) and ``manual_reconcile.py`` re-extracted the trusted context (A2-B), so
    ``execution_id`` / ``adapter`` / ``external_reference`` are already correlated —
    this module does NOT re-run correlation (that would be a redundant gate); it
    picks up at the 3.4.3 contract edge.

    Fixed order (spec §三 / §十六), every step BEFORE ``session.add``:

      1. resolve ``observed_at`` — the external timestamp when present, else the
         SERVER OBSERVATION time (the A1 contract's ``None`` branch, spec §七);
      2. build the ``ExternalObservation`` (``source="manual_reconcile"``);
      3. ``validate_observation`` (3.4.3-A) -> ``NormalizedObservation`` — NEVER
         skipped, NEVER a direct ``external_state -> outcome_status`` shortcut
         (spec §三). Raises a ``ContractValidationFailure`` (e.g. ``InvalidObservedAt``)
         -> NO fact;
      4. ``map_external_state`` (3.4.3-B, the ONLY mapping source) -> the frozen
         ``StateMapping``. Raises ``UnrecognizedExternalState`` (a shuffle / thehive
         evidence gap, or any unevidenced word) -> NO fact (spec §四 / §十四);
      5. ``redact_detail`` the mapping evidence (spec §十五);
      6. build the ``ExecutionOutcomeFact`` (``operator`` = the HUMAN recorder,
         spec §七 / §十一) and add -> flush -> commit. On ``SQLAlchemyError``:
         rollback + ``OutcomePersistenceError`` (spec §十六) — never a partial fact,
         never ``accepted=true``.

    Returns a ``ReconciledOutcome`` (the mapped word + the aware fact time + its
    kind). Append-only: never UPDATEs / DELETEs / dedups an existing row (spec §九),
    never writes ``execution_log``, never stores a derived state (spec §十一). NO
    executor / retry / compensation / HTTP / write adapter (spec §二十三).
    """
    # 1. observed_at — the A1 contract's ``datetime | None``: a present external
    #    timestamp is the fact time ("external"); an absent one is supplied by the
    #    platform as the SERVER OBSERVATION time ("server-observation"), exactly as
    #    the read-FAILURE path stamps it (A2-D §9). validate_observation then
    #    re-normalizes to aware UTC either way (a naive / excessive-future external
    #    value is refused there, never silently trusted).
    if observed_at is None:
        resolved_observed_at = datetime.now(timezone.utc)
        observed_at_kind = "server-observation"
    else:
        resolved_observed_at = observed_at
        observed_at_kind = "external"

    # 2. the frozen contract input. source is ALWAYS manual_reconcile (spec §七 /
    #    §八); external_reference is ``str | None`` because ``mock`` carries no
    #    external object — validate_observation refuses a None/empty reference as
    #    MissingExternalReference (mock can never produce an external outcome).
    observation = ExternalObservation(
        execution_id=execution_id,
        adapter=adapter,
        external_reference=external_reference,  # type: ignore[arg-type]
        external_state=external_state,
        observed_at=resolved_observed_at,
        source=MANUAL_RECONCILE_SOURCE,
    )

    # 3. 3.4.3-A validation — NEVER skipped (spec §三): a well-shaped observation
    #    becomes a NormalizedObservation (external_state preserved RAW, no outcome
    #    word yet); a malformed one raises a ContractValidationFailure -> no fact.
    normalized = validate_observation(observation)

    # 4. 3.4.3-B mapping — the ONLY source of the outcome word (spec §四). A
    #    StateMapping can never be ``reconciliation_failed`` (structurally refused
    #    by StateMapping.__post_init__), so a SUCCESS read never fabricates the
    #    read-failure verdict; an unevidenced word raises UnrecognizedExternalState.
    mapping = map_external_state(normalized)

    # 5. detail = the mapping evidence, redacted before it reaches the ORM (spec
    #    §十五). external_state is echoed RAW via mapping.observed_state — no second
    #    normalization here; the raw ``raw_evidence`` payload is NOT persisted.
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

    # 6. the append-only INSERT. operator is the AUTHENTICATED HUMAN (spec §七 /
    #    §十一) — the human trust domain, NEVER the webhook's ``adapter:{identity}``
    #    machine domain. id / created_at intentionally unset -> model defaults.
    fact = ExecutionOutcomeFact(
        execution_id=execution_id,
        outcome_status=mapping.outcome_status,
        source=MANUAL_RECONCILE_SOURCE,
        operator=operator,
        observed_at=normalized.observed_at,
        detail=detail,
    )
    try:
        session.add(fact)
        session.flush()
        session.commit()
    except SQLAlchemyError as exc:
        # spec §十六: a persistence failure rolls back (NO partial fact survives) and
        # surfaces as the REUSED OutcomePersistenceError -> the router maps a 5xx,
        # never accepted=true, never laundered into reconciliation_failed.
        session.rollback()
        raise OutcomePersistenceError(
            "manual reconcile outcome fact persistence failed; the transaction "
            "was rolled back and no fact was written"
        ) from exc

    return ReconciledOutcome(
        outcome_status=mapping.outcome_status,
        # the AWARE fact time from the validated observation, NOT ``fact.observed_at``
        # (a SQLite DateTime(timezone=True) round-trip drops tzinfo -> naive).
        observed_at=normalized.observed_at,
        observed_at_kind=observed_at_kind,
    )
