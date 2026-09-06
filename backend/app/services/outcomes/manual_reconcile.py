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

3.4.5-A2-B SCOPE (spec §1-§17): correlation + read-only external-reference
extraction, and NOTHING more.

    execution_id -> correlate_execution (REUSE 3.4.4-C) -> the ExecutionLog
    chain -> adapter identity (detail["executor"]) -> external_reference

``extract_context`` answers "which adapter and which external object does this
execution_id's historical dispatch chain refer to" and returns a pure
``CorrelatedExecutionContext``. ``reconcile_execution`` calls it, then STOPS with
``NotImplementedError`` (the router's 501): there is NO read adapter yet, so B
NEVER reads an external system, NEVER maps a state, NEVER persists a fact, and
NEVER fabricates a reconciliation success (spec §2 / §15 / §20 / §23).

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

READ-ONLY (spec §16 / §17): SELECT only — no INSERT / UPDATE / DELETE / COMMIT, no
mutation of ``execution_log`` (byte-identical before/after), no Outcome Fact.
FORBIDDEN in B (spec §2, proven by an AST import-surface test):
ReadAdapterRegistry / AdapterReadRequest / adapter.read / HTTP /
Shuffle-Wazuh-TheHive read / FakeReadAdapter / Mapping / Outcome persistence /
reconciliation_failed / derived state / retry / compensation / execution.

FORWARD TRANSACTION CONTRACT (mirrors webhook.py, spec §17 / §24): when the
pipeline completes (A2-E), the SERVICE will own the transaction (every gate runs
BEFORE ``session.add``; then add -> flush -> commit; on ``SQLAlchemyError``
rollback so NO partial fact survives and raise ``OutcomePersistenceError`` -> the
router maps a 5xx). The write is an APPEND-ONLY INSERT into ``execution_outcome``
— never UPDATE / UPSERT / MERGE / DELETE, never a rewrite of ``execution_log``,
never a stored derived state (computed on read by ``derive_outcome_state()``).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import NoReturn

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.execution_log import ExecutionLog
from app.services.executions.registry import ADAPTER_NAMES
from app.services.outcomes.correlation import correlate_execution
from app.services.outcomes.reconciliation import MissingExternalReference

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
    precedent (the requested row). Validated against ``ADAPTER_NAMES`` (the
    registry vocabulary 3.4.3-B already reuses, spec §13 — NOT a copied
    registry): an identity outside it has no reference-key mapping, so the chain
    is not reconcilable -> fail-closed ``MissingExternalReference`` (spec §13 /
    §17), never a guessed adapter."""
    executor = _detail_of(rows[0]).get("executor")
    if not isinstance(executor, str) or executor not in ADAPTER_NAMES:
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


def reconcile_execution(
    session: Session, execution_id: uuid.UUID, operator: str
) -> NoReturn:
    """Manual Reconcile pipeline entrypoint — 3.4.5-A2-B.

    Runs correlation + external-reference extraction (``extract_context``), then
    STOPS: with no read adapter yet, it raises ``NotImplementedError`` (the
    router's static 501) — NEVER a 200 ``accepted`` and NEVER a fabricated
    reconciliation success (spec §20 / §36). A2-C resolves a reader and reads the
    external state EXACTLY ONCE; A2-D maps a read transport failure to a
    ``reconciliation_failed`` fact; A2-E validates + maps + appends the Outcome
    Fact and owns the transaction.

    ``operator`` is the AUTHENTICATED recorder identity (``Operator.name``)
    carried for the future fact (A2-E). It NEVER influences the adapter or the
    reference, which come ONLY from ``execution_log`` (spec §6 / §15) — that
    ``extract_context`` does not even take ``operator`` is the structural proof
    (spec §18 item 15).
    """
    extract_context(session, execution_id)
    raise NotImplementedError(
        "Manual Reconcile external read lands in 3.4.5-A2-C; "
        "3.4.5-A2-B establishes correlation + external-reference extraction only"
    )
