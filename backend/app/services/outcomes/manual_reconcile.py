"""Manual Reconcile Outcome Pipeline (Phase 3.4.5-A2, pull-side sibling of webhook.py).

WHERE THIS LIVES — AND WHY (evidence-driven placement, reported in the A2-A
acceptance). ``webhook.py`` in this same package is the PUSH side: an external
system reports an outcome. This module is the PULL side: an authenticated human
operator asks the platform to go READ the external system's current state for a
past execution and append what it finds. Both feed the SAME 3.4.3 reconciliation
contract and append the SAME ``execution_outcome`` fact — only ``source`` differs
(``"webhook"`` vs ``"manual_reconcile"``) and only the recorder identity differs
(``adapter:{identity}`` vs the authenticated ``Operator.name``).

The pipeline lives HERE (``app/services/outcomes/manual_reconcile.py``), NOT in
``app/services/manual_reconcile/`` as design §26 literally sketched, because that
package is the 3.4.5-A1 SEALED pure read-contract layer:
``test_adapter_read_contract.py`` AST-audits its ENTIRE import surface and
forbids ``sqlalchemy`` / ``app.models`` / ``app.services.outcomes`` /
``app.services.executions`` / ``fastapi`` / ``pydantic``, plus a runtime
subprocess import check. A pipeline that owns a DB transaction CANNOT live inside
that package without breaking the sealed A1 purity tests, and §31 forbids editing
A1. Design §26 authorizes "具体目录可依现有 repo pattern 微调" as long as Read/Write
stay PHYSICALLY separated — so the orchestrating pipeline sits in ``outcomes/``
beside ``webhook.py`` and will IMPORT the read contract from
``app/services/manual_reconcile/read/`` in A2-C. The dependency direction is
one-way: pipeline -> read contract, NEVER the reverse.

3.4.5-A2-E SCOPE: correlation + read-only external-reference extraction (A2-B,
REUSED unchanged) wired into the A1 ``ReadAdapterRegistry`` (A2-C, REUSED
unchanged), the READ TRANSPORT FAILURE -> ``reconciliation_failed`` verdict (A2-D,
REUSED unchanged), PLUS the closing edge — a SUCCESSFUL read is now validated
(3.4.3-A), mapped (3.4.3-B) and appended as ONE Outcome Fact. BOTH exits are
append-only; the success ``validate -> map -> append`` edge is DELEGATED to
``manual_persist.persist_reconcile_outcome`` so this orchestrator's audited import
surface never binds the mapper / validator / ORM directly (see that module).

    execution_id -> correlate_execution (REUSE 3.4.4-C) -> the ExecutionLog chain
        -> adapter identity (detail["executor"]) -> external_reference    (A2-B)
        -> ReadAdapterRegistry.get(adapter)                               (A1)
        -> reader.read(AdapterReadRequest) -> AdapterReadResult           (A2-C)
        -> read() RAISED a transport failure -> reconciliation_failed      (A2-D)
        -> read() SUCCEEDED -> validate -> map -> Outcome Fact INSERT       (A2-E)

``extract_context`` (A2-B) answers "which adapter and which external object does
this execution_id's historical chain refer to". ``read_external_state`` (A2-C)
hands that context to the registry and returns the RAW ``AdapterReadResult``; it
is a PURE PROPAGATOR — a transport failure raised by ``read()`` surfaces
UNCHANGED there (the A2-C ``TestReadFailureSignal`` locks it), so the conversion
lives ONLY in ``reconcile_execution``. That entrypoint now has TWO real exits: a
read that FAILS in transit (timeout / connection / DNS / 5xx / unavailable) is
caught INLINE and appended as ONE ``reconciliation_failed`` fact -> HTTP 200
(design §4.3, A2-D); a read that SUCCEEDS is handed to
``persist_reconcile_outcome`` (validate -> map -> append) -> HTTP 200 with the
mapped outcome word, OR — when the external_state is outside 3.4.3-B's evidenced
vocabulary (EVERY shuffle / thehive / mock state today) — refused as
``UnrecognizedExternalState`` -> HTTP 422 with ZERO facts (spec §四 / §十四), NEVER
a fabricated verdict. The PRODUCTION registry stays EMPTY, so EVERY adapter
(shuffle / wazuh / thehive / mock / unknown) still rejects at ``registry.get``
with ``UnsupportedAdapterRead`` (the router's 404, spec §3 / §8) BEFORE any read —
a CAPABILITY rejection that is NEVER ``reconciliation_failed`` and writes ZERO
facts (A2-D §6).

DETERMINISTIC ROW SELECTION (spec §7 — the crux of this step, DERIVED from the
existing frozen execution service, never invented here). One execution_id maps to
MULTIPLE ``execution_log`` rows, so "which row carries the adapter / the
reference" MUST follow the platform's frozen ordering, not list position:

  - adapter <- ``detail["executor"]`` of the FIRST chronological row (the
    ``requested`` / ``compensation_requested`` row ``_intent_detail`` writes).
    FROZEN precedent: ``metrics.py::_adapter_of`` reads ``rows[0].detail
    ["executor"]`` — "recorded by the Server in the requested row, never
    reconstructed from client input". That row is guaranteed present and first
    (constraint 10: every execute chain holds exactly one ``requested`` row, and
    it is the chain's first row).
  - external_reference <- the adapter-specific key of the TERMINAL row (the latest
    by ``created_at DESC, id DESC`` — ``derive_execution_state``'s frozen
    ordering, constraint 8). The reference is written ONLY there, by
    ``_terminal_outcome_detail(outcome)`` on ``succeeded`` / ``failed`` (the
    executor's response); ``requested`` / ``dispatched`` / ``guard_rejected``
    never carry it. So a chain that never dispatched (``guard_rejected``) or
    failed without a handle yields NO reference -> ``MissingExternalReference``
    (spec §8), never a fabricated one.

Chronological order here is ``created_at ASC, id ASC`` (the ordering
``service._result`` and ``metrics`` use — the exact reverse of
``derive_execution_state``'s latest-row DESC), so ``rows[0]`` is the requested row
and ``rows[-1]`` is the terminal row. Compensation is a FRESH execution_id
(``compensate_response``), so a chain is homogeneous in direction and the two
selections never mix a forward dispatch with its undo.

WRITE SURFACE (A2-E, spec §二十二 / §二十三): BOTH exits now write, each exactly ONE
APPEND-ONLY INSERT into ``execution_outcome``. The read-FAILURE path persists a
``reconciliation_failed`` fact INLINE (A2-D, unchanged); the SUCCESS path delegates
to ``manual_persist.persist_reconcile_outcome`` (validate -> map -> append). BOTH
REUSE the EXISTING persistence vocabulary from ``webhook.py`` (the
``ExecutionOutcomeFact`` alias + ``OutcomePersistenceError``) — never a second ORM
writer. Every gate (auth -> correlation -> external reference -> registry -> the
read attempt -> 3.4.3 validation -> 3.4.3-B mapping) runs BEFORE ``session.add``;
then add -> flush -> commit; on ``SQLAlchemyError`` rollback so NO partial fact
survives and raise ``OutcomePersistenceError`` -> the router maps a 5xx, never
accepted=true. ``execution_log`` stays byte-identical (SELECT only — never UPDATE /
DELETE), the fact INSERT is never UPDATE / UPSERT / MERGE / DELETE (spec §九), and
NO derived state is stored (computed on read by ``derive_outcome_state()``, spec
§十一). The read side stays PHYSICALLY isolated from the WRITE side (spec §21): this
module imports the A1 read contract + the outcomes persistence helpers and NEVER
``app.services.executions`` — no ``ResponseExecutor`` / ``create_executor`` / write
adapter is reachable, proven by an AST import-surface test (the success path's
``redact_detail`` / mapper / ORM live in ``manual_persist.py``, NOT here, so this
module's audited surface stays mapping-free and persistence-free).
STILL FORBIDDEN in E (AST- + runtime-proven): a REAL Shuffle/Wazuh/TheHive read
adapter (§二十 — those are 3.4.5-B/C/D) / HTTP (urllib / requests / httpx) /
``FakeReadAdapter`` in app code (test-only, spec §22) / retry / sleep / backoff
(spec §十七 — ONE ``read()`` per POST) / compensation / execution. A SUCCESS read
writes exactly ONE mapped fact — never ``reconciliation_failed`` (that is the
read-FAILURE verdict, structurally impossible for a ``StateMapping``); a FAILURE
read writes exactly ONE ``reconciliation_failed`` fact — never ``confirmed_failure``
(a mapped external state, 3.4.3-B).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.execution_log import ExecutionLog
from app.schemas.reconcile import MANUAL_RECONCILE_SOURCE, ManualReconcileResponse
from app.services.manual_reconcile import ReadTransportError
from app.services.manual_reconcile.read import (
    AdapterReadRequest,
    AdapterReadResult,
    ReadAdapterRegistry,
    default_read_adapter_registry,
)
from app.services.outcomes.correlation import correlate_execution
from app.services.outcomes.derivation import derive_outcome_state
from app.services.outcomes.manual_persist import persist_reconcile_outcome
from app.services.outcomes.reconciliation import MissingExternalReference
from app.services.outcomes.webhook import (
    ExecutionOutcomeFact,
    OutcomePersistenceError,
)

#: The per-adapter external-reference key inside the TERMINAL dispatch row's
#: ``detail`` (design §6.2, FROZEN — the three key names differ). ``mock`` is
#: deliberately ABSENT: it has no external object, so its context carries
#: ``external_reference=None`` (spec §14) and A2-C decides UnsupportedAdapterRead
#: — B never fabricates a reference and never treats mock's absence as
#: MissingExternalReference. NOTE the traps the spec calls out: Shuffle's
#: ``workflow_id`` is the workflow TEMPLATE id, NOT the execution handle
#: (spec §11), and Wazuh's ``command`` is NOT ``command_id`` (spec §10) — only the
#: exact keys below are ever read.
_EXTERNAL_REFERENCE_KEYS = {
    "shuffle": "external_execution_id",
    "wazuh": "command_id",
    "thehive": "case_id",
}


@dataclass(frozen=True, slots=True)
class CorrelatedExecutionContext:
    """A2-B read-only result: WHICH adapter + WHICH external object one
    execution_id's historical dispatch chain refers to (spec §12).

    Pure facts lifted from ``execution_log`` — deliberately carries NO
    ``outcome_status`` (that is derived state, A2-E), NO API credential, NO
    operator token and NO callback token (spec §12). ``external_reference`` is
    ``None`` ONLY for ``mock`` (no external object, spec §14); for
    shuffle/wazuh/thehive a missing handle raises ``MissingExternalReference``
    rather than yielding ``None``.
    """

    execution_id: uuid.UUID
    adapter: str
    external_reference: str | None


def _select_chain(session: Session, execution_id: uuid.UUID) -> list[ExecutionLog]:
    """The execution_id's rows in FROZEN chronological order (``created_at ASC,
    id ASC`` — the ordering ``service._result`` / ``metrics`` use; the reverse of
    ``derive_execution_state``'s latest-row DESC). READ-ONLY SELECT (spec §16).
    Non-empty: ``correlate_execution`` already raised ``UnmappableExecutionId``
    for an absent chain, so ``rows[0]`` / ``rows[-1]`` are safe."""
    return list(
        session.scalars(
            select(ExecutionLog)
            .where(ExecutionLog.execution_id == execution_id)
            .order_by(ExecutionLog.created_at.asc(), ExecutionLog.id.asc())
        )
    )


def _detail_of(row: ExecutionLog) -> dict:
    """A row's detail as a dict (defensive: a corrupted non-dict detail reads as
    empty, never raises — mirrors ``metrics._classification_of``)."""
    return row.detail if isinstance(row.detail, dict) else {}


def _extract_adapter(rows: list[ExecutionLog]) -> str:
    """The chain's adapter identity = ``detail["executor"]`` of the FIRST
    chronological row (spec §6 — execution-history driven, NEVER the client, the
    path, or the operator). Follows the frozen ``metrics.py::_adapter_of``
    precedent (the requested row).

    A2-C (spec §10): the adapter is returned AS-IS (any non-empty string). The
    ``ReadAdapterRegistry`` is now the SOLE adapter-capability boundary, so an
    identity it has no reader for — ``mock`` / ``shuffle`` / ``wazuh`` /
    ``thehive`` in the EMPTY production registry, or an unknown name — rejects
    THERE with ``UnsupportedAdapterRead``, NOT here. The A2-B ``ADAPTER_NAMES``
    vocabulary gate is deliberately GONE: it pre-empted the registry the spec now
    routes through. Only a STRUCTURALLY absent / non-string executor (a corrupt
    chain with no adapter identity to hand the registry at all) is fail-closed here
    as ``MissingExternalReference`` (spec §13), never a guessed adapter."""
    executor = _detail_of(rows[0]).get("executor")
    if not isinstance(executor, str) or not executor:
        raise MissingExternalReference(
            "execution chain carries no reconcilable adapter identity"
        )
    return executor


def _extract_reference(rows: list[ExecutionLog], adapter: str) -> str | None:
    """The adapter-specific external reference from the TERMINAL row (the latest
    by ``created_at, id`` = ``rows[-1]`` chronologically — the row
    ``_terminal_outcome_detail`` wrote the executor's response onto, spec §7).

    ``mock`` (no key) -> ``None`` (spec §14: recognized, no external object; A2-C
    decides capability). shuffle/wazuh/thehive -> the exact §6.2 key on the
    terminal row; absent / empty / non-str -> ``MissingExternalReference``
    (spec §8-§11): a chain that never dispatched, failed without a handle, or
    (Shuffle) returned only a ``workflow_id`` is NOT reconcilable and B never
    fabricates a reference."""
    key = _EXTERNAL_REFERENCE_KEYS.get(adapter)
    if key is None:
        return None  # mock — no external object by design (spec §14)
    reference = _detail_of(rows[-1]).get(key)
    if not isinstance(reference, str) or not reference:
        raise MissingExternalReference(
            f"execution chain carries no external reference for adapter {adapter}"
        )
    return reference


def extract_context(
    session: Session, execution_id: uuid.UUID
) -> CorrelatedExecutionContext:
    """A2-B: correlate (REUSE ``correlate_execution``, spec §3) then read-only
    extract the adapter + external_reference (spec §5 / §6).

    Two READ-ONLY SELECTs, no writes (spec §16): ``correlate_execution`` is the
    mandated existence gate (0 rows -> ``UnmappableExecutionId``, spec §4); the
    chain rows are then re-selected for extraction because ``CorrelatedExecution``
    deliberately exposes neither the rows nor their ``detail`` (design §5). This is
    the "额外只读 SELECT" design §5 / §6 sanctions — NOT a second correlation and
    NOT a re-implemented existence query.

    Raises ``UnmappableExecutionId`` (no chain -> router 404) or
    ``MissingExternalReference`` (no reconcilable adapter / reference -> router
    422). Performs NO external read, NO mapping, NO persistence and produces NO
    ``reconciliation_failed`` (spec §2 / §23 — there is no read attempt yet).
    """
    correlate_execution(session, execution_id)
    rows = _select_chain(session, execution_id)
    adapter = _extract_adapter(rows)
    external_reference = _extract_reference(rows, adapter)
    return CorrelatedExecutionContext(
        execution_id=execution_id,
        adapter=adapter,
        external_reference=external_reference,
    )


def read_external_state(
    session: Session,
    execution_id: uuid.UUID,
    registry: ReadAdapterRegistry,
) -> AdapterReadResult:
    """A2-C (spec §7): correlation + reference extraction (REUSE ``extract_context``,
    spec §19) -> ``registry.get(adapter)`` -> ``reader.read(request)`` -> the RAW
    ``AdapterReadResult``. The platform chain this step proves end to end::

        execution_id -> CorrelatedExecutionContext (A2-B)
                     -> registry.get(context.adapter)          (A1 read contract)
                     -> AdapterReadRequest(execution_id, adapter, external_reference)
                     -> reader.read(request) -> AdapterReadResult

    ORDER is load-bearing (spec §10 / §17 item 14): ``extract_context`` runs FIRST,
    so a chain missing its external reference rejects with
    ``MissingExternalReference`` BEFORE the registry is consulted; only a
    reference-bearing context reaches ``registry.get``. The registry is the SOLE
    adapter-capability gate: the EMPTY production registry (or ``mock`` / an unknown
    adapter) raises ``UnsupportedAdapterRead`` (spec §8 / §11) — a rejection, NO
    Outcome Fact, and NEVER ``reconciliation_failed`` (that needs a real ``read()``
    failing at transport level, spec §9 / §25 — A2-D).

    ``external_reference`` is a non-empty ``str`` by the time the request is built:
    ``mock`` / unknown adapters carry ``None`` and reject at ``registry.get`` first
    (no reader), and shuffle / wazuh / thehive reject earlier still if the handle is
    absent. The ``AdapterReadRequest`` is built ONLY from the historical context —
    NO operator, NO credential, NO client value (spec §12 / §18); this function does
    not even take an ``operator``. C performs NO mapping (spec §15) and NO
    persistence (spec §14): the raw result is returned untouched.
    """
    context = extract_context(session, execution_id)
    reader = registry.get(context.adapter)
    request = AdapterReadRequest(
        execution_id=context.execution_id,
        adapter=context.adapter,
        external_reference=context.external_reference,
    )
    return reader.read(request)


def reconcile_execution(
    session: Session,
    execution_id: uuid.UUID,
    operator: str,
    registry: ReadAdapterRegistry | None = None,
) -> ManualReconcileResponse:
    """Manual Reconcile pipeline entrypoint — 3.4.5-A2-E.

    Correlation + external-reference extraction (``extract_context``, A2-B) ->
    ``ReadAdapterRegistry`` -> ``reader.read()`` (``read_external_state``, A2-C).
    With the EMPTY production registry EVERY adapter rejects at ``registry.get``
    with ``UnsupportedAdapterRead`` (the router's 404, spec §8 / §16) BEFORE any
    read; only a test-injected ``FakeReadAdapter`` (spec §4 / §22 — NEVER the
    production default) reaches ``read()``.

    TWO real exits once a reader is actually invoked (A2-D + A2-E):

      - the read FAILS at the TRANSPORT layer — a ``ReadTransportError`` or a
        builtin ``TimeoutError`` / ``ConnectionError`` / ``OSError`` raised by
        ``read()`` (A2-D §7) — is caught HERE and turned into ONE
        ``reconciliation_failed`` Outcome Fact INLINE, then a 200
        ``ManualReconcileResponse`` (design §4.3). This is the ONLY path that
        produces ``reconciliation_failed``, and it is NEVER ``confirmed_failure``
        (that word is a mapped EXTERNAL state, 3.4.3-B);
      - the read SUCCEEDS -> the raw ``AdapterReadResult`` is DELEGATED to
        ``manual_persist.persist_reconcile_outcome`` (validate 3.4.3-A -> map
        3.4.3-B -> append ONE fact) and returns a 200 ``ManualReconcileResponse``
        carrying the mapped outcome word (spec §三 / §七). When the external_state
        is outside 3.4.3-B's evidenced vocabulary — EVERY shuffle / thehive / mock
        state today (an evidence gap, §四) — ``map_external_state`` raises
        ``UnrecognizedExternalState`` (a ``ContractValidationFailure``) which
        propagates to the router's 422 with ZERO facts (spec §十四), NEVER a
        fabricated verdict and NEVER downgraded to ``unknown``.

    ``UnsupportedAdapterRead`` (NO reader — a CAPABILITY failure) is a
    ``ReadAdapterError`` SIBLING of ``ReadTransportError`` and is NEVER caught
    here, so it still propagates to the router's 404 with ZERO facts (A2-D §6:
    capability != transport — "no reader exists" must never masquerade as "reader
    tried and failed"). ONE read attempt, NO retry / sleep / backoff / loop
    (A2-D §15).

    ``registry`` defaults to ``default_read_adapter_registry()`` (EMPTY) so the
    router — and production — always fail closed; a test passes an EXPLICIT
    registry instance (constructor injection, spec §22), never a global mutation.

    ``operator`` is the AUTHENTICATED human recorder identity (``Operator.name``).
    On BOTH paths it becomes the appended fact's ``operator`` (A2-D §11 / A2-E §七
    — the human trust domain, NEVER the webhook's ``adapter:{identity}`` machine
    domain). It NEVER reaches the read: ``read_external_state`` takes no operator
    and ``AdapterReadRequest`` has no operator / credential field (spec §12 / §18).
    """
    resolved = registry if registry is not None else default_read_adapter_registry()
    try:
        result = read_external_state(session, execution_id, resolved)
    except (ReadTransportError, TimeoutError, ConnectionError, OSError) as exc:
        # A2-D §7: a reader EXISTED and read() was ACTUALLY invoked, then failed in
        # transit — this, and ONLY this, is reconciliation_failed. UnsupportedAdapterRead
        # is a ReadAdapterError SIBLING (never a builtin, never a ReadTransportError), so
        # it is NOT caught here and still rejects 404 / zero-fact (§6). ONE attempt, no
        # retry (§15). read_external_state stays a PURE PROPAGATOR; the conversion lives
        # here alone (the A2-C TestReadFailureSignal locks that split).
        #
        # Re-extract the context for the fact's provenance. extract_context is READ-ONLY
        # and idempotent and performs NO read, so reader.read() was called EXACTLY once.
        context = extract_context(session, execution_id)
        # §9: a read failure carries NO trustworthy external timestamp, so the fact time
        # is the SERVER OBSERVATION time — never dressed up as an external event time
        # (observed_at_kind="server-observation" declares this to the caller).
        #
        # §9 "然后仍然 validate_observation()": the TIMESTAMP discipline that validator
        # enforces (_normalize_observed_at: aware / UTC / within MAX_FUTURE_SKEW) is
        # honored BY CONSTRUCTION — datetime.now(timezone.utc) is aware and is the
        # present instant, so it is never naive nor excessively future. The validator
        # FUNCTION is deliberately NOT called: it validates an ExternalObservation whose
        # contract REQUIRES a present external_state, and a READ FAILURE has NONE (§21 —
        # it never reaches mapping). Fabricating a state to satisfy it would break the §0
        # anti-fabrication 铁律; a read failure is the ABSENCE of an observation, not a
        # malformed one. The sealed A2-B boundary also forbids importing it here.
        observed_at = datetime.now(timezone.utc)
        # §10 / §25: a SAFE STATIC classification only — never str(exc), never a callback
        # token / operator token / adapter API key / Authorization header / password. The
        # secret never enters detail because it is never read from the exception at all.
        if isinstance(exc, ReadTransportError) and exc.category:
            failure_category = exc.category
        elif isinstance(exc, TimeoutError):
            failure_category = "timeout"
        elif isinstance(exc, ConnectionError):
            failure_category = "connection_failure"
        else:
            failure_category = "transport_error"
        detail = {
            "adapter": context.adapter,
            "external_reference": context.external_reference,
            "failure_category": failure_category,
            "reason": "read_transport_failure",
        }
        fact = ExecutionOutcomeFact(
            execution_id=context.execution_id,
            outcome_status="reconciliation_failed",
            source=MANUAL_RECONCILE_SOURCE,
            operator=operator,
            observed_at=observed_at,
            detail=detail,
            # id / created_at intentionally unset -> model defaults (§8, append-only).
        )
        # §22 / §23: REUSE webhook.py's persistence vocabulary (the ExecutionOutcomeFact
        # alias + OutcomePersistenceError) — ONE append-only INSERT, never a second ORM
        # writer. Every gate ran BEFORE session.add; on SQLAlchemyError rollback so NO
        # partial fact survives and surface a 5xx (never accepted=true).
        try:
            session.add(fact)
            session.flush()
            session.commit()
        except SQLAlchemyError as persist_exc:
            session.rollback()
            raise OutcomePersistenceError(
                "reconciliation_failed fact persistence failed; the transaction was "
                "rolled back and no fact was written"
            ) from persist_exc
        # §13 / §20: the current state is DERIVED over the whole fact series (latest by
        # observed_at DESC, id DESC wins) — never stored. The historical facts (e.g. a
        # prior confirmed_success) are untouched; this only APPENDED one row.
        observations = list(
            session.scalars(
                select(ExecutionOutcomeFact).where(
                    ExecutionOutcomeFact.execution_id == context.execution_id
                )
            )
        )
        return ManualReconcileResponse(
            accepted=True,
            execution_id=context.execution_id,
            adapter=context.adapter,
            outcome_status="reconciliation_failed",
            observed_at=observed_at,
            source=MANUAL_RECONCILE_SOURCE,
            derived_outcome_status=derive_outcome_state(observations),
            observed_at_kind="server-observation",
        )
    # A2-E: the read SUCCEEDED — a raw AdapterReadResult is in hand. Delegate the
    # SUCCESS pipeline (validate 3.4.3-A -> map 3.4.3-B -> append ONE Outcome Fact)
    # to manual_persist.persist_reconcile_outcome, which lives in a SEPARATE module
    # so THIS orchestrator's import surface stays free of the mapper / validator /
    # ORM the SEALED A2-C / A2-B tests forbid it to bind (test_18_no_mapping /
    # test_20_no_mapping / test_21_no_outcome_persistence). Re-extract the context
    # for provenance: extract_context is READ-ONLY, idempotent and performs NO read,
    # so reader.read() was still invoked EXACTLY once (spec §十六 / §十七). An
    # unevidenced external_state (a shuffle / thehive evidence gap, or any word
    # outside 3.4.3-B's vocabulary) raises UnrecognizedExternalState HERE -> the
    # router's 422 with ZERO facts (spec §四 / §十四); a persistence failure raises
    # OutcomePersistenceError -> 500 (spec §十六) — NEVER accepted=true.
    context = extract_context(session, execution_id)
    persisted = persist_reconcile_outcome(
        session,
        execution_id=context.execution_id,
        adapter=context.adapter,
        external_reference=context.external_reference,
        external_state=result.external_state,
        observed_at=result.observed_at,
        operator=operator,
    )
    # §十一: the current state is DERIVED over the whole fact series (latest by
    # observed_at DESC, id DESC wins) — never stored. The historical facts (e.g. a
    # prior reconciliation_failed) are untouched; this only APPENDED one row.
    observations = list(
        session.scalars(
            select(ExecutionOutcomeFact).where(
                ExecutionOutcomeFact.execution_id == context.execution_id
            )
        )
    )
    return ManualReconcileResponse(
        accepted=True,
        execution_id=context.execution_id,
        adapter=context.adapter,
        outcome_status=persisted.outcome_status,
        observed_at=persisted.observed_at,
        source=MANUAL_RECONCILE_SOURCE,
        derived_outcome_status=derive_outcome_state(observations),
        observed_at_kind=persisted.observed_at_kind,
    )
