"""Manual Reconcile Outcome Pipeline (Phase 3.4.5-A2, pull-side sibling of webhook.py).

WHERE THIS LIVES — AND WHY (evidence-driven placement, reported in the A2-A
acceptance). ``webhook.py`` in this same package is the PUSH side: an external
system reports an outcome. This module is the PULL side: an authenticated human
operator asks the platform to go READ the external system's current state for a
past execution and append what it finds. Both feed the SAME 3.4.3 reconciliation
contract and append the SAME ``execution_outcome`` fact — only ``source``
differs (``"webhook"`` vs ``"manual_reconcile"``) and only the recorder identity
differs (``adapter:{identity}`` vs the authenticated ``Operator.name``).

The pipeline lives HERE (``app/services/outcomes/manual_reconcile.py``), NOT in
``app/services/manual_reconcile/`` as design §26 literally sketched, because
that package is the 3.4.5-A1 SEALED pure read-contract layer:
``test_adapter_read_contract.py`` AST-audits its ENTIRE import surface
(``rglob("*.py")``) and forbids ``sqlalchemy`` / ``app.models`` / ``app.db`` /
``fastapi`` / ``pydantic`` / ``app.services.outcomes`` / ``app.services.executions``,
plus a runtime subprocess import check. A pipeline that owns a DB transaction
CANNOT live inside that package without breaking the sealed A1 purity tests,
and §31 forbids editing A1. Design §26 explicitly authorizes "具体目录可依现有
repo pattern 微调" as long as Read/Write stay PHYSICALLY separated — so the
orchestrating pipeline sits in ``outcomes/`` beside ``webhook.py`` and will
IMPORT the read contract from ``app/services/manual_reconcile/read/`` in A2-C.
The dependency direction is one-way: pipeline -> read contract, NEVER the
reverse (which is exactly what keeps the read layer pure).

3.4.5-A2-A SCOPE (spec §35): THIS MODULE IS A STUB. ``reconcile_execution``
raises ``NotImplementedError`` unconditionally; the router maps that to ONE
static HTTP 501 — an honest placeholder that is NEVER a 200 ``accepted`` and
NEVER a fabricated reconciliation success (spec §36). A2-A performs NO external
read, NO ``ReadAdapterRegistry`` access, NO correlation, NO Outcome persistence,
NO execution / dispatch / compensation (spec §25 / §35). The real pull pipeline
lands incrementally, each step stopping for acceptance (spec §33):

    A2-B  correlation (reuse correlate_execution) + read-only external_reference
          extraction from execution_log (detail["executor"] / the per-adapter
          reference key);
    A2-C  ReadAdapterRegistry.get(adapter) + ONE ReadAdapter.read (test-only
          fake readers; the production registry stays EMPTY);
    A2-D  read transport failure -> append a ``reconciliation_failed`` fact
          (server observation time), distinct from UnsupportedAdapterRead;
    A2-E  3.4.3-A validate_observation -> 3.4.3-B map_external_state -> the
          append-only ExecutionOutcome INSERT -> 3.4.2 derivation on read.

FORWARD TRANSACTION CONTRACT (mirrors webhook.py, spec §17 / §18 / §24): when
implemented, the SERVICE will own the transaction (every gate runs BEFORE
``session.add``; then add -> flush -> commit; on ``SQLAlchemyError`` rollback so
NO partial fact survives and raise ``OutcomePersistenceError`` -> the router maps
a 5xx). The router carries NO persistence surface. The write is an APPEND-ONLY
INSERT into ``execution_outcome`` — never UPDATE / UPSERT / MERGE / DELETE, never
a rewrite of ``execution_log`` (spec §17 / §20). It never stores a derived state
(spec §20): the current state is computed on read by ``derive_outcome_state()``.
"""
from __future__ import annotations

from typing import NoReturn

from sqlalchemy.orm import Session


def reconcile_execution(
    session: Session, execution_id: str, operator: str
) -> NoReturn:
    """Manual Reconcile pipeline entrypoint — 3.4.5-A2-A STUB (always raises).

    A2-A establishes the secured seam only; the pipeline is NOT implemented.
    This raises ``NotImplementedError`` unconditionally, which the router maps to
    HTTP 501 (Not Implemented) — an honest placeholder that is NEVER a 200
    ``accepted`` and NEVER a fabricated reconciliation success (spec §36). It
    touches NO database row, NO external system, NO registry.

    Args (forward contract — UNUSED in A2-A):
      - ``session``: the DB session; the service will own the transaction when
        the pipeline lands (A2-E), mirroring ``persist_callback_outcome``;
      - ``execution_id``: the PATH identity, taken as a RAW string. A2-A does
        NOT parse or correlate it (spec §35); UUID validation + correlation
        (malformed / unknown -> 404) land in A2-B;
      - ``operator``: the AUTHENTICATED operator name resolved by
        ``authenticate_operator`` (``Operator.name``) — NEVER a client-supplied
        string (spec §7). This is the future fact's recorder identity, the
        pull-side analogue of the webhook's ``adapter:{identity}``.

    The real implementation (A2-B..E) will correlate the execution, extract the
    ``external_reference`` read-only from ``execution_log``, resolve a reader
    from ``ReadAdapterRegistry``, read the external state EXACTLY ONCE (no
    retry / backoff, spec §24), validate + map it through 3.4.3, and append ONE
    ``execution_outcome`` fact — or append a ``reconciliation_failed`` fact when
    the read itself fails (spec §13). NONE of that happens in A2-A.
    """
    raise NotImplementedError(
        "Manual Reconcile pipeline lands in 3.4.5-A2-B..E; "
        "3.4.5-A2-A establishes the secured route + schema + RBAC seam only"
    )
