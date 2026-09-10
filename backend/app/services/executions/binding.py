"""Forward Dispatch Binding (M4-A, Amendment §12.2 A1-REVISED).

THE PROBLEM THIS SOLVES. Before M4 the immutable target facts of a dispatch lived
ONLY in the terminal ``succeeded`` row (the external ``createdAt`` inside
``raw_response``) plus the chain's ``action`` / ``target`` columns. Amendment
§12.2's A1 option sketched writing a ``dispatch_binding`` into the terminal
``succeeded`` row. M4-A REVISES A1: the binding is persisted BEFORE the external
request — inside the ``dispatched`` row, which the Execution Service appends +
flushes BEFORE ``executor.execute()`` runs (``service.py``). The terminal row then
REFERENCES the SAME binding (``dispatch_attempt_id``); it never re-writes it.

WHY PRE-DISPATCH. A binding written only at a ``succeeded`` terminal is lost
exactly when it is most needed: a timeout, a connection failure, an HTTP error or a
lost response leaves NO ``succeeded`` row, so the target facts of the attempt would
vanish. The ``dispatched`` row ALWAYS lands before the adapter runs, so the binding
survives EVERY outcome (success / timeout / connection failure / HTTP error /
response loss) — the task's hard requirement.

WHAT IT RECORDS — AND WHAT IT NEVER RECORDS. The binding is the immutable target
identity of THIS attempt: execution / approval identity, adapter, the server-side
action / target snapshot, the dispatch START time (server clock), a unique attempt
identifier, the dispatch-time approval-status snapshot, and — from an OPTIONAL
adapter contributor — the config-declared endpoint / version-evidence reference and
the target instance / tenant. It NEVER records a secret: every field passes the
``redact_detail`` gate at the single ``_append`` write point, no field IS a
credential, and the contributor keys are merged through an explicit whitelist (the
endpoint is the validated secret-free base URL; the version is a config declaration,
never a liveness proof).

HONEST FAIL-CLOSED IDENTITY (constraint #2 / #3, M4-B). For TheHive 4.1.24-1 there
is NO authoritative dispatch-time instance / tenant source (the write config carries
a base URL, not a certified instance identity; the ``OutputCase`` has no
organisation), so the TheHive contributor records ``target_instance`` /
``target_tenant`` as ``None`` (UNKNOWN) and the endpoint / version as CONFIG
DECLARATIONS (``version_assertion_kind="config-declaration"``). A base URL or a
config string is NEVER passed off as a verified identity. Gate 5 therefore STILL
fails closed for every real execution — M4-A makes the binding FORWARD-READY (a
future authenticated instance / tenant source populates these fields), it does NOT
manufacture a binding that does not exist.

NO SCHEMA MIGRATION. ``ExecutionLog.detail`` is a JSON column, so the binding rides
inside the ``dispatched`` row's ``detail`` (``detail["dispatch_binding"]``) and the
terminal reference inside the terminal row's ``detail``
(``detail["dispatch_attempt_id"]``). NO new column, NO Alembic migration, NO
back-fill of old records. Old history simply has NO binding -> ``parse_dispatch_binding``
returns ``None`` -> the proof derivation fails closed exactly as before.

FROZEN-CONTRACT SAFE. The ``ResponseExecutor`` ABC (``base.py``) is UNCHANGED — the
contributor capability is a SEPARATE ``runtime_checkable`` Protocol
(``DispatchBindingContributor``) an adapter MAY satisfy; ``dispatched`` stays a
platform log state, never an adapter product (D8). The ``created_at`` audit-stamp
frozen clause is UNTOUCHED: ``dispatch_started_at`` is a server-clock FACT recorded
in ``detail`` (the same precedent as the policy-evaluation time ``service.py``
already computes with ``datetime.now(timezone.utc)``), NOT the ``created_at`` column —
which is stamped by the DATABASE at INSERT since RC2 / H-2 (see ``service.py``'s
frozen-clause note).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from app.services.executions.models import ExecutionDispatch

#: The ``dispatched`` row's detail key the binding is persisted under.
BINDING_DETAIL_KEY = "dispatch_binding"

#: The terminal row's detail key carrying the binding's ``attempt_id`` — the
#: explicit "the terminal REFERENCES the same binding" link (task M4-A). A terminal
#: never re-writes the binding; it points back at the ONE pre-dispatch attempt.
TERMINAL_REFERENCE_KEY = "dispatch_attempt_id"

#: Shape version, so a forward parser refuses an UNKNOWN binding shape fail-closed
#: rather than mis-reading a future field layout.
BINDING_SCHEMA = "sentinelflow.dispatch_binding.v1"

#: The honest marker for a version that is a CONFIG DECLARATION, never a
#: certified-live liveness proof (constraint #3).
VERSION_ASSERTION_CONFIG = "config-declaration"


@runtime_checkable
class DispatchBindingContributor(Protocol):
    """An OPTIONAL adapter capability: contribute the adapter-specific target
    identity facts to the pre-dispatch binding.

    This is a SEPARATE ``runtime_checkable`` Protocol, NOT a method on the frozen
    ``ResponseExecutor`` ABC (``base.py``) — ``dispatched`` is a platform log state,
    never part of the adapter contract (D8), so the ABC stays UNCHANGED. An adapter
    that makes a real external request (TheHive) MAY satisfy it; the offline mock
    does not, and its binding simply carries the platform facts alone.

    ``isinstance`` against this ``runtime_checkable`` Protocol checks ONLY the
    PRESENCE of ``dispatch_binding_facts`` (same caveat the codebase already documents
    for ``TrustedCreationReader``) — the trust is the controlled call chain, not the
    type name. The returned dict is merged through an explicit whitelist: only the
    adapter-specific identity keys are read, never a platform fact, never an
    arbitrary key. A contributor returns CONFIG-DECLARED evidence HONESTLY — for
    TheHive 4.1.24-1 ``target_instance`` / ``target_tenant`` are ``None`` (no
    authoritative dispatch-time identity source) and the version is marked
    ``config-declaration`` (never a liveness proof).
    """

    def dispatch_binding_facts(self, dispatch: ExecutionDispatch) -> dict[str, Any]:
        """The adapter-specific target identity facts for THIS dispatch (never a
        secret; the endpoint is the validated secret-free base URL)."""
        ...


@dataclass(frozen=True, slots=True)
class DispatchBinding:
    """The immutable pre-dispatch target binding (typed shape).

    Written into the ``dispatched`` row's ``detail`` BEFORE the external request;
    read back by the proof derivation (``outcomes/verified_proof``) to populate the
    immutable correlation context. Frozen + slots: immutable, no attribute surprise.
    Every field is a server-side fact or an honest ``None`` (UNKNOWN) — NEVER a
    secret, NEVER back-filled from the current config.
    """

    schema: str
    execution_id: str
    approval_id: str
    adapter: str
    action: str
    target: str
    #: Fresh uuid4 minted by ``build_dispatch_binding`` — the unique identifier of
    #: THIS dispatch attempt; the terminal row references it (``TERMINAL_REFERENCE_KEY``).
    attempt_id: str
    #: ISO-8601 server-clock dispatch START, recorded in ``detail`` — NOT the
    #: ``created_at`` audit column (see the module docstring's frozen-clause note).
    dispatch_started_at: str
    #: The linked approval's status AT DISPATCH TIME (immutable snapshot for gate 6) —
    #: NEVER the live status re-read at reconcile time. ``None`` when unknown.
    approval_status_at_dispatch: str | None
    #: Adapter-contributed CONFIG-DECLARED target identity. ``None`` for a
    #: non-contributor (mock) and for TheHive 4.1.24-1's absent authoritative
    #: instance / tenant source — an honest UNKNOWN, never a base-URL substitute.
    endpoint: str | None
    version_evidence_ref: str | None
    version_assertion_kind: str | None
    target_instance: str | None
    target_tenant: str | None

    def to_detail(self) -> dict[str, Any]:
        """Project to the JSON-storable detail dict (``dispatch_started_at`` is
        already an ISO string, so the result is pure JSON scalars)."""
        return {
            "schema": self.schema,
            "execution_id": self.execution_id,
            "approval_id": self.approval_id,
            "adapter": self.adapter,
            "action": self.action,
            "target": self.target,
            "attempt_id": self.attempt_id,
            "dispatch_started_at": self.dispatch_started_at,
            "approval_status_at_dispatch": self.approval_status_at_dispatch,
            "endpoint": self.endpoint,
            "version_evidence_ref": self.version_evidence_ref,
            "version_assertion_kind": self.version_assertion_kind,
            "target_instance": self.target_instance,
            "target_tenant": self.target_tenant,
        }

    def started_at(self) -> datetime | None:
        """The dispatch START as an aware UTC datetime, or ``None`` when the stored
        ISO string is malformed (fail-closed — the derivation never substitutes a
        server time for the historical dispatch start, constraint #2)."""
        try:
            value = datetime.fromisoformat(self.dispatch_started_at)
        except (ValueError, TypeError):
            return None
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _optional_str(value: Any) -> str | None:
    """A non-empty ``str`` or ``None`` (an absent / blank / non-string adapter fact
    is an honest UNKNOWN, never coerced)."""
    return value if isinstance(value, str) and value else None


def build_dispatch_binding(
    *,
    execution_id: uuid.UUID,
    approval_id: uuid.UUID,
    adapter: str,
    action: str,
    target: str,
    approval_status: str | None,
    dispatch_started_at: datetime,
    contributor_facts: dict[str, Any] | None = None,
) -> DispatchBinding:
    """Assemble the immutable pre-dispatch binding from SERVER-SIDE facts only.

    ``attempt_id`` is minted HERE (a fresh uuid4 — the unique identifier of THIS
    dispatch attempt); the terminal row references it via ``TERMINAL_REFERENCE_KEY``.
    ``dispatch_started_at`` is the caller's server-clock instant (the policy-time
    precedent in ``service.py``), stored as an ISO string. ``approval_status`` is the
    linked approval's status AT DISPATCH TIME (the immutable gate-6 snapshot).

    Contributor facts are merged through an EXPLICIT WHITELIST — only the five
    adapter-specific identity keys are read (``endpoint`` / ``version_evidence_ref``
    / ``version_assertion_kind`` / ``target_instance`` / ``target_tenant``), so a
    contributor can NEVER override a platform fact (execution_id / attempt_id /
    dispatch_started_at / ...) or smuggle an arbitrary key into the binding.
    """
    facts = contributor_facts or {}
    return DispatchBinding(
        schema=BINDING_SCHEMA,
        execution_id=str(execution_id),
        approval_id=str(approval_id),
        adapter=adapter,
        action=action,
        target=target,
        attempt_id=str(uuid.uuid4()),
        dispatch_started_at=dispatch_started_at.isoformat(),
        approval_status_at_dispatch=_optional_str(approval_status),
        endpoint=_optional_str(facts.get("endpoint")),
        version_evidence_ref=_optional_str(facts.get("version_evidence_ref")),
        version_assertion_kind=_optional_str(facts.get("version_assertion_kind")),
        target_instance=_optional_str(facts.get("target_instance")),
        target_tenant=_optional_str(facts.get("target_tenant")),
    )


def parse_dispatch_binding(detail: Any) -> DispatchBinding | None:
    """Read the binding back from a ``dispatched`` row's ``detail`` — FAIL-CLOSED.

    Returns ``None`` when the detail is absent / not a dict / carries no binding /
    has an unknown ``schema`` / is missing any platform-identity fact. NEVER raises,
    NEVER fabricates a field: old history (no binding) and a corrupt binding BOTH
    yield ``None``, so the proof derivation fails closed exactly as it did before
    M4-A (constraint #2 — a missing immutable fact is never back-filled).
    """
    if not isinstance(detail, dict):
        return None
    raw = detail.get(BINDING_DETAIL_KEY)
    if not isinstance(raw, dict):
        return None
    if raw.get("schema") != BINDING_SCHEMA:
        return None
    execution_id = raw.get("execution_id")
    approval_id = raw.get("approval_id")
    adapter = raw.get("adapter")
    action = raw.get("action")
    target = raw.get("target")
    attempt_id = raw.get("attempt_id")
    dispatch_started_at = raw.get("dispatch_started_at")
    # The platform-identity facts MUST all be present non-empty strings; a binding
    # missing ANY of them is corrupt -> None (fail-closed, never partially trusted).
    required = (
        execution_id,
        approval_id,
        adapter,
        action,
        target,
        attempt_id,
        dispatch_started_at,
    )
    if not all(isinstance(value, str) and value for value in required):
        return None
    return DispatchBinding(
        schema=BINDING_SCHEMA,
        execution_id=execution_id,
        approval_id=approval_id,
        adapter=adapter,
        action=action,
        target=target,
        attempt_id=attempt_id,
        dispatch_started_at=dispatch_started_at,
        approval_status_at_dispatch=_optional_str(raw.get("approval_status_at_dispatch")),
        endpoint=_optional_str(raw.get("endpoint")),
        version_evidence_ref=_optional_str(raw.get("version_evidence_ref")),
        version_assertion_kind=_optional_str(raw.get("version_assertion_kind")),
        target_instance=_optional_str(raw.get("target_instance")),
        target_tenant=_optional_str(raw.get("target_tenant")),
    )
