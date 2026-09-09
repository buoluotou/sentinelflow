"""Trusted creation-proof ORCHESTRATION + whitelisted persistence (Phase 3.4.5-M3 §3/§4).

This is the DB-OWNING half of the M3 source-isolated trusted-proof channel. The PURE
half — the typed proof shapes and the SINGLE six-gate verifier ``verify_creation_effect``
— lives in ``app.services.read_adapters.verified`` (side-effect-free, no DB / no HTTP).
This module owns the transaction: it DERIVES the immutable correlation context from
history, drives ONE trusted read, adjudicates it with the pure verifier, and appends the
resulting Outcome Fact. The dependency direction is one-way (this module -> the pure
kernel), never the reverse.

PLACEMENT REFINEMENT vs Amendment §11.4 (documented for the reviewer). §11.4's table
listed ``verify_creation_effect`` under this module. The implementation instead keeps the
verifier in ``read_adapters.verified`` BESIDE the pure types it adjudicates, so the ENTIRE
proof kernel (shapes + the single adjudicator) is one pure, independently Component-
testable unit, and THIS module is purely the DB-owning glue (derive / orchestrate /
persist). This is a cleaner pure-vs-side-effecting split than the table sketched; it
changes NO ruling (still ONE verifier, still PULL-only, still no second vocabulary).

WHERE THIS LIVES — AND WHY. ``outcomes/manual_reconcile.py`` is the A2 PULL orchestrator,
but its import surface is AST-audited by the SEALED A2-B / A2-C acceptance tests
(``test_manual_reconcile_reader.py`` / ``test_manual_reconcile_correlation.py``) which
forbid THAT module binding the mapper / validator / ORM directly. This module is a
SEPARATE, ADDITIVE orchestrator for the trusted channel; it lives in ``outcomes/`` beside
``webhook.py`` / ``manual_persist.py`` (NOT inside the sealed A1 read-contract package
``app/services/manual_reconcile/``), so it MAY own a DB transaction and import the
persistence vocabulary. It does NOT modify ``manual_reconcile.py`` / ``manual_persist.py``;
it REUSES their frozen row-selection helpers (``_select_chain`` / ``_extract_adapter`` /
``_extract_reference``) so the verified channel derives the adapter + reference
IDENTICALLY to the sealed pipeline — single source of truth, zero drift.

THE CONTROLLED CALL CHAIN (Amendment §11.2 constraint #1 — an internal type is NOT a
magic credential). ``reconcile_verified_execution`` is the ONLY caller of the verifier,
and it is reachable ONLY as an authenticated-operator PULL orchestration:
  - the proof context is DERIVED HERE from the immutable ``execution_log`` chain
    (``derive_read_correlation_context``), NEVER accepted from an HTTP body;
  - the observation comes ONLY from a registry-resolved reader's real ``read_creation``
    ``GET`` (the production registry is EMPTY, so production fails closed at ``registry.get``
    with ``UnsupportedAdapterRead`` — the channel is NOT wired, Amendment §5);
  - ``ManualReconcileRequest`` is EMPTY with ``extra="forbid"``, so a client cannot inject
    ANY proof / context / verified / provenance field;
  - NO route accepts a client-constructed ``VerifiedReadResult`` / ``VerifiedCreationEffect``
    / ``ReadCorrelationContext``;
  - the WEBHOOK path (``webhook.py`` + its router) is a SEPARATE function graph that never
    imports this module, never imports the proof kernel, and never reaches the verifier
    (proven by AST + runtime tests in the M3 suite). "Do not import" is NOT the only
    defense — the call-chain reachability is.

WHY THE TRUSTED CHANNEL CANNOT USE ``persist_reconcile_outcome`` (Amendment §11.4). That
function calls ``map_external_state``, whose thehive vocabulary is EMPTY (M2-R §2
fail-closed), so ANY word — including the synthesized ``case_created`` — raises
``UnrecognizedExternalState`` (-> 422, zero fact). The trusted channel's ``confirmed_success``
is authorized by the SIX-GATE VERIFIER, NOT by the shared vocabulary, so
``_persist_verified_creation_outcome`` appends DIRECTLY (reusing the ``ExecutionOutcomeFact``
alias + ``OutcomePersistenceError`` + ``MANUAL_RECONCILE_SOURCE`` + append-only discipline
from ``webhook.py`` / ``manual_persist.py``) — this is exactly "source isolation lives
OUTSIDE the shared vocabulary". No second external-state vocabulary is created.

M4-C PROOF-CHANNEL CLOSURE. ``_persist_verified_creation_outcome`` is MODULE-PRIVATE and
SEALED: it is the ONLY ``confirmed_success`` persistence path on this channel, its ONLY
caller is ``reconcile_verified_execution`` (AST-proven), and it FIRST verifies the effect
carries ``verify_creation_effect``'s private mint seal (``effect.is_sealed()``) — so a PLAIN
hand-constructed ``VerifiedCreationEffect`` can NEVER be fed straight to persist (the
boundary the M4-C ruling closes; Amendment §11.2 constraint #1: persist does NOT trust the
TYPE NAME). The verify -> authorize -> persist triad CONVERGES into the ONE controlled
service ``reconcile_verified_execution``. A FUTURE HTTP wiring MUST reuse the operator
authentication, RBAC and Manual Reconcile permission of the sealed A2 reconcile route (it
MUST NOT expose a new unauthenticated persist entry); this milestone wires NO production
router (Amendment §5 / §11.4 — the channel stays PULL-only and unwired).

PERSISTENCE WHITELIST (Amendment §3 / §11.4). ``raw_evidence`` / ``raw_response`` are NEVER
written. Only whitelisted, non-secret fields enter ``ExecutionOutcome.detail`` (through
``redact_detail``, the final secret gate): the resource reference, the proof scope, the
trusted EXTERNAL creation time (ISO), the source, the correlation marker, the gate-5
verification BOOLEANS (``instance_verified`` / ``tenant_verified`` — NEVER the raw instance
/ tenant VALUES, §3), the audit-only case number, and the HONEST
``version_assertion_kind="config-declaration"`` (constraint #3: a version CONFIG is NOT a
liveness proof, so no version literal is stamped as if certified-live). NO secret, NO raw
response body, NO unnecessary tenant-sensitive value.

GATE 5 FAILS CLOSED FOR ALL REAL HISTORY (Amendment §12). ``derive_read_correlation_context``
sets ``instance_binding`` / ``tenant_binding`` to ``None`` (UNKNOWN) for EVERY real execution
— the target instance / tenant binding DOES NOT EXIST in ``ExecutionLog`` (no column) nor in
the TheHive 4.1.24-1 ``OutputCase`` (no organisation), and is NEVER back-filled from the
current config (constraint #2). The verifier's gate 5 therefore refuses
(``instance_binding_unknown``) -> ``VerifiedCreationRefused`` -> 422, ZERO fact. NO real
historical execution can reach ``confirmed_success`` until the §12 forward-binding Amendment
lands. The ``confirmed_success`` arm below is delivered + composition-tested (the pure
verifier positive + ``_persist_verified_creation_outcome`` direct) but is UNREACHABLE for real
history by design — that is the correct, honest fail-closed state, not a gap to paper over.

APPEND-ONLY + NO SIDE EFFECTS. ONE INSERT per reconcile, never UPDATE / UPSERT / MERGE /
DELETE; historical facts are untouched (a repeat reconcile APPENDS a new observation). NO
executor, NO retry, NO poll, NO sleep, NO compensation, NO background worker, NO write
adapter is ever called: the ONLY external interaction is the single ``read_creation`` GET.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.schemas.reconcile import MANUAL_RECONCILE_SOURCE, ManualReconcileResponse
from app.services.executions.binding import parse_dispatch_binding
from app.services.executions.secrets import redact_detail
from app.services.manual_reconcile import ReadTransportError, UnsupportedAdapterRead
from app.services.manual_reconcile.read import (
    AdapterReadRequest,
    ReadAdapterRegistry,
    default_read_adapter_registry,
)
from app.services.outcomes.correlation import correlate_execution
from app.services.outcomes.derivation import derive_outcome_state
from app.services.outcomes.manual_persist import ReconciledOutcome
from app.services.outcomes.manual_reconcile import (
    _extract_adapter,
    _extract_reference,
    _select_chain,
)
from app.services.outcomes.reconciliation import ContractValidationFailure
from app.services.outcomes.webhook import (
    ExecutionOutcomeFact,
    OutcomePersistenceError,
)
from app.services.read_adapters.verified import (
    GATE_IDENTITY,
    PROOF_SCOPE_VERIFIED_CREATION,
    REASON_REFERENCE_UNKNOWN,
    CreationRefusal,
    ReadCorrelationContext,
    TrustedCreationReader,
    VerifiedCreationEffect,
    created_at_millis,
    created_at_to_datetime,
    verify_creation_effect,
)


class VerifiedCreationRefused(ContractValidationFailure):
    """The trusted creation-proof verifier REFUSED the read (Amendment §4 — fail-closed).

    A ``ContractValidationFailure``, so a (future) wired router maps it to HTTP 422 with
    ZERO Outcome Facts — exactly like the shared-vocabulary refusal
    ``UnrecognizedExternalState``. This is the SOURCE-ISOLATED channel's refusal: the read
    did NOT prove a verified creation (a conjunctive gate failed), so NEITHER
    ``confirmed_success`` NOR ``confirmed_failure`` is written — a refused proof is NOT
    proof of failure (the case may exist but be unprovable as THIS execution's effect, or
    may have been created then re-tagged / deleted). It is ALSO NEVER ``reconciliation_failed``
    (that is the read-TRANSPORT-failure verdict, a separate arm below).

    Carries the SAFE STATIC ``gate`` + ``reason`` (never a secret, never a raw reference
    value) for diagnostics.
    """

    def __init__(self, message: str, *, gate: str, reason: str):
        super().__init__(message)
        self.gate = gate
        self.reason = reason


class UnsealedCreationEffect(RuntimeError):
    """M4-C: ``_persist_verified_creation_outcome`` was handed a ``VerifiedCreationEffect``
    NOT minted by ``verify_creation_effect`` (its ``is_sealed()`` is False).

    This is the CLOSED boundary the M4-C ruling requires: persist no longer trusts the TYPE
    NAME alone, so a PLAIN hand-constructed internal object can never be fed straight to
    persist to write a ``confirmed_success``. In the controlled chain this NEVER fires
    (``reconcile_verified_execution`` only ever passes the verifier's own return value); it is
    a fail-closed integrity guard against a future caller bypassing the six-gate verifier. A
    ``RuntimeError`` (an internal integrity violation, NOT a client-facing 4xx): ZERO fact is
    written. The seal is NOT a magic credential (constraint #1) — the real boundary is the
    AST-proven single construction site + single persist caller.
    """


def _aware_utc(value: datetime | None) -> datetime | None:
    """Normalize a server-stamped timestamp to aware UTC (or ``None`` -> ``None``).

    A SQLite ``DateTime(timezone=True)`` round-trip DROPS ``tzinfo`` and yields a naive
    value; the stored value IS UTC (``ExecutionLog.created_at`` is ``server_default
    CURRENT_TIMESTAMP``, the server clock, never client-supplied), so attaching
    ``timezone.utc`` is a FAITHFUL normalization, NOT a fabrication (constraint #2). ``None``
    stays ``None`` so gate 4 fails closed on an unknown dispatch time.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def derive_read_correlation_context(
    session: Session, execution_id: uuid.UUID
) -> ReadCorrelationContext:
    """Derive the IMMUTABLE dispatch facts for the strict-correlation half of the proof
    (Amendment §6.2) — the half the frozen ``AdapterReadRequest`` deliberately does NOT carry.

    READ-ONLY (existence gate + SELECTs; NO write, NO external read, NO mapping). It REUSES
    the frozen A2-B row-selection helpers so the adapter + reference are derived IDENTICALLY
    to the sealed pipeline (``correlate_execution`` -> ``UnmappableExecutionId`` for an absent
    chain, the router's 404; ``_extract_adapter`` / ``_extract_reference`` ->
    ``MissingExternalReference`` for a corrupt / never-dispatched chain, the router's 422).

    M4-D: the immutable PRE-DISPATCH BINDING (M4-A, in the ``dispatched`` row's detail) is the
    AUTHORITATIVE source for the real dispatch START, the dispatch-time approval snapshot and
    the target instance / tenant. ``parse_dispatch_binding`` is FAIL-CLOSED: old history has NO
    binding -> those facts stay ``None`` and gates 4 / 5 / 6 refuse exactly as before, NEVER
    back-filled. EVERY field is an immutable historical fact or ``None`` (UNKNOWN). Per
    constraint #2 a missing fact is NEVER fabricated, NEVER back-filled and NEVER taken from
    the CURRENT config:
      - ``instance_binding`` / ``tenant_binding`` come from the binding's ``target_instance`` /
        ``target_tenant``; TheHive 4.1.24-1 records ``None`` (no authoritative source) and old
        history has no binding, so they are ALWAYS ``None`` for real history -> gate 5 FAILS
        CLOSED (Amendment §12). NEVER back-filled from the binding's config-declared endpoint.
      - ``dispatch_created_at_millis`` is the ``createdAt`` the platform PERSISTED into the
        terminal row's ``raw_response`` at dispatch time (``_terminal_outcome_detail``,
        source-verified §11.3) — the authoritative gate-4 exact-match source; ``None`` if that
        immutable fact is absent (gate 4 then fails closed, NEVER re-derived from the live read).
    """
    # Existence gate (REUSE 3.4.4-C): 0 rows -> UnmappableExecutionId (the router's 404).
    correlate_execution(session, execution_id)
    # The chain in FROZEN chronological order (created_at ASC, id ASC): rows[0] is the
    # requested row, rows[-1] the terminal row (the frozen A2-B discipline, reused verbatim).
    rows = _select_chain(session, execution_id)
    adapter = _extract_adapter(rows)
    external_reference = _extract_reference(rows, adapter)

    requested = rows[0]
    terminal = rows[-1]
    terminal_detail = terminal.detail if isinstance(terminal.detail, dict) else {}

    # M4-D: the immutable PRE-DISPATCH BINDING (M4-A) rides in the ``dispatched`` row's
    # detail. It is the AUTHORITATIVE source for the real dispatch START, the dispatch-time
    # approval snapshot and the target instance / tenant. FAIL-CLOSED: old history has NO
    # binding (``parse_dispatch_binding`` -> None), so those facts stay UNKNOWN and gates
    # 4 / 5 / 6 refuse exactly as Amendment §12 requires — NEVER back-filled from config.
    dispatched = next((r for r in rows if r.decision == "dispatched"), None)
    binding = parse_dispatch_binding(dispatched.detail) if dispatched is not None else None
    # Integrity (defense-in-depth): a binding whose execution_id is not THIS execution is
    # not this chain's binding -> treat as absent (fail-closed, never trust a stray binding).
    if binding is not None and binding.execution_id != str(execution_id):
        binding = None

    # gate 6 — the SERVER-SNAPSHOTTED approved action / target (the immutable ``action`` /
    # ``target`` columns, never accepted from a request body) + the chain's approval_id.
    approved_action = (
        requested.action
        if isinstance(requested.action, str) and requested.action
        else None
    )
    chain_target = (
        requested.target
        if isinstance(requested.target, str) and requested.target
        else None
    )
    chain_approval_id = (
        str(requested.approval_id) if requested.approval_id is not None else None
    )
    # gate 6 — reference provenance: did the reference come from a TERMINAL ``succeeded`` row?
    reference_from_terminal_success = terminal.decision == "succeeded"

    # gate 4 — DISTINCT time semantics (M4-D). The REAL dispatch START comes from the
    # binding (recorded BEFORE the external request); the TERMINAL-RECORD time is the
    # terminal row's ``created_at`` (stamped AFTER the response). The terminal created_at
    # is NEVER passed off as the request start.
    dispatch_started_at = binding.started_at() if binding is not None else None
    terminal_recorded_at = _aware_utc(terminal.created_at)
    # gate 4 — the EXTERNAL createdAt PERSISTED at dispatch time (the exact-match source).
    dispatch_created_at_millis: int | None = None
    dispatch_created_at: datetime | None = None
    raw_response = terminal_detail.get("raw_response")
    if isinstance(raw_response, dict):
        raw_created = raw_response.get("createdAt")
        dispatch_created_at_millis = created_at_millis(raw_created)
        dispatch_created_at = created_at_to_datetime(raw_created)

    # gate 6 — the DISPATCH-TIME approval snapshot + execution snapshot from the binding
    # (NEVER the live approval.status re-read at reconcile time — M4-D).
    approval_status_at_dispatch = (
        binding.approval_status_at_dispatch if binding is not None else None
    )
    bound_approval_id = binding.approval_id if binding is not None else None
    bound_action = binding.action if binding is not None else None
    bound_target = binding.target if binding is not None else None
    # gate 5 — the dispatch-time target instance / tenant from the binding. TheHive
    # 4.1.24-1 records None (no authoritative source) -> gate 5 STILL fails closed; old
    # history (no binding) -> None -> fails closed. NEVER back-filled from the binding's
    # config-declared endpoint / version, NEVER from the current config (constraint #2).
    instance_binding = binding.target_instance if binding is not None else None
    tenant_binding = binding.target_tenant if binding is not None else None

    return ReadCorrelationContext(
        execution_id=execution_id,
        adapter=adapter,
        external_reference=external_reference,
        approved_action=approved_action,
        approval_status_at_dispatch=approval_status_at_dispatch,
        bound_approval_id=bound_approval_id,
        bound_action=bound_action,
        bound_target=bound_target,
        chain_approval_id=chain_approval_id,
        chain_target=chain_target,
        dispatch_started_at=dispatch_started_at,
        terminal_recorded_at=terminal_recorded_at,
        dispatch_created_at=dispatch_created_at,
        dispatch_created_at_millis=dispatch_created_at_millis,
        instance_binding=instance_binding,
        tenant_binding=tenant_binding,
        reference_from_terminal_success=reference_from_terminal_success,
    )


def _persist_verified_creation_outcome(
    session: Session, effect: VerifiedCreationEffect, operator: str
) -> ReconciledOutcome:
    """Append ONE ``confirmed_success`` Outcome Fact authorized by a ``VerifiedCreationEffect``.

    M4-C PRIVATE + SEALED. MODULE-PRIVATE (``_`` prefix): the controlled service
    ``reconcile_verified_execution`` is its ONLY caller (AST-proven), so the verify ->
    authorize -> persist triad converges into ONE controlled entrypoint. It FIRST checks
    ``effect.is_sealed()`` — an effect NOT minted by ``verify_creation_effect`` raises
    ``UnsealedCreationEffect`` with ZERO fact, so a PLAIN hand-constructed internal object can
    never be fed straight here to write ``confirmed_success`` (the M4-C boundary fix; persist
    does NOT trust the TYPE NAME alone — Amendment §11.2 constraint #1).

    Called ONLY after ``verify_creation_effect`` returned the POSITIVE verdict (all six gates
    passed). It BYPASSES the shared (empty) vocabulary deliberately (see the module docstring):
    the verifier — NOT ``map_external_state`` — is the authorization, so this appends DIRECTLY
    while REUSING the sealed persistence vocabulary (``ExecutionOutcomeFact`` alias +
    ``OutcomePersistenceError`` + ``MANUAL_RECONCILE_SOURCE``) and the append-only / rollback
    discipline of ``manual_persist.persist_reconcile_outcome``.

    ``observed_at`` is the authoritative EXTERNAL creation time (``effect.external_created_at``,
    already gate-3 aware + gate-4 bounded), so ``observed_at_kind="external"`` — NEVER a server
    observation time substituted for the historical creation time (Amendment §6.1). The
    ``detail`` is the WHITELIST (module docstring): no raw response, no secret, no tenant value.
    ``operator`` is the AUTHENTICATED HUMAN (the human trust domain, never the webhook's
    ``adapter:{identity}`` machine domain). ONE INSERT; on ``SQLAlchemyError`` rollback (no
    partial fact) + ``OutcomePersistenceError`` -> the router maps a 5xx, never ``accepted=true``.
    """
    # M4-C seal gate: refuse an effect NOT minted by the six-gate verifier (fail-closed, ZERO
    # fact). In the controlled chain this never fires (reconcile passes the verifier's own
    # return value); it closes the "persist accepts a plain internal object" boundary.
    if not effect.is_sealed():
        raise UnsealedCreationEffect(
            "the VerifiedCreationEffect was not minted by verify_creation_effect; refusing to "
            "persist a confirmed_success from an unsealed (plain) internal object"
        )
    detail = redact_detail(
        {
            "adapter": effect.adapter,
            "external_reference": effect.external_reference,
            "outcome_status": "confirmed_success",
            "proof_scope": PROOF_SCOPE_VERIFIED_CREATION,
            "source": MANUAL_RECONCILE_SOURCE,
            "correlation": "execution_tag_present",
            # the trusted EXTERNAL creation time (ISO) — the fact's authoritative observed_at.
            "verified_created_at": effect.external_created_at.isoformat(),
            # gate-5 verification BOOLEANS, NEVER the raw instance / tenant VALUES (§3).
            "instance_verified": effect.instance_verified,
            "tenant_verified": effect.tenant_verified,
            # constraint #3: a version CONFIG is NOT a liveness proof — record the ASSERTION
            # KIND honestly, never a version literal stamped as certified-live.
            "version_assertion_kind": "config-declaration",
            # audit-only human case number; NEVER the reference, NEVER required.
            **({"case_number": effect.case_number} if effect.case_number is not None else {}),
        }
    )
    fact = ExecutionOutcomeFact(
        execution_id=effect.execution_id,
        outcome_status="confirmed_success",
        source=MANUAL_RECONCILE_SOURCE,
        operator=operator,
        observed_at=effect.external_created_at,
        detail=detail,
        # id / created_at intentionally unset -> model defaults (append-only).
    )
    try:
        session.add(fact)
        session.flush()
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        raise OutcomePersistenceError(
            "verified creation outcome fact persistence failed; the transaction was "
            "rolled back and no fact was written"
        ) from exc
    return ReconciledOutcome(
        outcome_status="confirmed_success",
        # the AWARE fact time in hand, NOT ``fact.observed_at`` (a SQLite
        # DateTime(timezone=True) round-trip drops tzinfo -> naive).
        observed_at=effect.external_created_at,
        observed_at_kind="external",
    )


def _reconciliation_failed_response(
    session: Session,
    context: ReadCorrelationContext,
    operator: str,
    exc: Exception,
) -> ManualReconcileResponse:
    """The trusted channel's read-TRANSPORT-failure arm — MIRRORS ``reconcile_execution``'s
    sealed A2-D arm. A ``read_creation`` that FAILED in transit (timeout / connection / 401 /
    403 / 404 / 5xx / a refused redirect) -> ONE ``reconciliation_failed`` fact stamped with
    the SERVER OBSERVATION time, NEVER ``confirmed_failure`` (a failed READ cannot prove the
    CREATION failed — the case may exist but be unreadable, or be cross-tenant invisible).

    Records ONLY a SAFE STATIC category (never ``str(exc)``, never a callback token / operator
    token / API key / Authorization header / password). Append-only; rollback +
    ``OutcomePersistenceError`` on ``SQLAlchemyError``.
    """
    observed_at = datetime.now(timezone.utc)
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
    )
    try:
        session.add(fact)
        session.flush()
        session.commit()
    except SQLAlchemyError as persist_exc:
        session.rollback()
        raise OutcomePersistenceError(
            "reconciliation_failed fact persistence failed; the transaction was rolled "
            "back and no fact was written"
        ) from persist_exc
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


def reconcile_verified_execution(
    session: Session,
    execution_id: uuid.UUID,
    operator: str,
    registry: ReadAdapterRegistry | None = None,
) -> ManualReconcileResponse:
    """The PULL-only trusted creation-proof orchestration (Amendment §3 / §5.3 / §6.2).

    The ONLY caller of the single verifier — the crux of the source-isolated channel::

        execution_id -> derive_read_correlation_context (READ-ONLY immutable facts)
                     -> registry.get(adapter) -> the trusted reader
                     -> reader.read_creation(AdapterReadRequest) -> VerifiedReadResult
                     -> verify_creation_effect(context, observed)  (the SIX gates)
                     -> VerifiedCreationEffect -> persist confirmed_success (whitelist)
                     -> CreationRefusal        -> VerifiedCreationRefused (422, ZERO fact)
                     -> read_creation RAISED   -> reconciliation_failed (ONE fact)

    THREE exits, all fail-closed:
      - a read that FAILS in transit -> ``reconciliation_failed`` (ONE fact, server-observation
        time), the INDEPENDENT read-failure semantics Amendment §4 requires — NEVER
        ``confirmed_failure``;
      - a read the verifier REFUSES (any gate fails) -> ``VerifiedCreationRefused`` (a
        ``ContractValidationFailure`` -> 422, ZERO fact) — NEVER ``confirmed_failure``, NEVER
        ``reconciliation_failed``;
      - all six gates pass -> ONE ``confirmed_success`` fact (the whitelisted persist). For
        REAL history gate 5 always refuses (instance/tenant UNKNOWN, Amendment §12), so this
        arm is UNREACHABLE until §12 lands — the correct fail-closed state.

    ``registry`` defaults to the SEALED EMPTY ``default_read_adapter_registry()`` so production
    (and the unwired router) fail closed at ``registry.get`` with ``UnsupportedAdapterRead``
    (404, ZERO fact); a test passes an EXPLICIT registry (constructor injection, the sanctioned
    seam), never a global mutation. ``operator`` is the AUTHENTICATED human recorder; it becomes
    the fact's ``operator`` and NEVER reaches the read (``AdapterReadRequest`` has no operator /
    credential field). ONE read attempt — NO retry / sleep / backoff / poll / loop.
    """
    resolved = registry if registry is not None else default_read_adapter_registry()

    # 1. DERIVE the immutable correlation context (READ-ONLY). Existence gate ->
    #    UnmappableExecutionId (404); a chain with no reconcilable adapter / reference ->
    #    MissingExternalReference (422). Both are the frozen pipeline's own rejections.
    context = derive_read_correlation_context(session, execution_id)

    # 2. RESOLVE the reader. The EMPTY production registry -> UnsupportedAdapterRead (404,
    #    ZERO fact): the trusted channel is NOT wired, so production fails closed HERE.
    reader = resolved.get(context.adapter)

    # 3. CAPABILITY gate: the reader MUST expose the internal trusted creation verb. The
    #    runtime_checkable Protocol isinstance checks ONLY ``read_creation``'s PRESENCE —
    #    constraint #1: the TRUST is the controlled call chain + the factory-gated reader,
    #    NOT the type name. A reader without the verb is not a trusted creation reader.
    if not isinstance(reader, TrustedCreationReader):
        raise UnsupportedAdapterRead(
            f"no trusted creation reader for adapter {context.adapter}",
            context.adapter,
        )

    # 4. An UNKNOWN immutable reference -> gate 1 ``reference_unknown``, ZERO fact, and NO GET
    #    (never build a request with a non-str reference, never fabricate one). ``_extract_reference``
    #    already raised for a missing thehive handle, so this guards the ``None`` (e.g. mock) case.
    if not isinstance(context.external_reference, str) or not context.external_reference:
        raise VerifiedCreationRefused(
            "the immutable dispatch chain carries no external reference to verify",
            gate=GATE_IDENTITY,
            reason=REASON_REFERENCE_UNKNOWN,
        )

    request = AdapterReadRequest(
        execution_id=context.execution_id,
        adapter=context.adapter,
        external_reference=context.external_reference,
    )

    # 5. ONE trusted read. A transport failure -> reconciliation_failed (mirrors the sealed
    #    A2-D arm). UnsupportedAdapterRead is a ReadAdapterError SIBLING (never a builtin,
    #    never a ReadTransportError) so it is NOT caught here — capability != transport.
    try:
        observed = reader.read_creation(request)
    except (ReadTransportError, TimeoutError, ConnectionError, OSError) as exc:
        return _reconciliation_failed_response(session, context, operator, exc)

    # 6. The SINGLE verifier adjudicates the trusted observation against the immutable context.
    verdict = verify_creation_effect(context, observed)
    if isinstance(verdict, CreationRefusal):
        # fail-closed: a refused proof is ZERO fact (never confirmed_failure, never
        # reconciliation_failed) -> the router's 422.
        raise VerifiedCreationRefused(
            "trusted creation proof refused by the six-gate verifier",
            gate=verdict.gate,
            reason=verdict.reason,
        )

    # 7. ALL SIX gates passed -> the ONLY authorization for a confirmed_success on the
    #    source-isolated channel. Persist the whitelisted fact (bypassing the EMPTY shared
    #    vocabulary) and return the success envelope (observed_at = the EXTERNAL creation time).
    persisted = _persist_verified_creation_outcome(session, verdict, operator)
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
