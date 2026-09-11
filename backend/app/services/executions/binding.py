"""Forward dispatch binding: the immutable target facts of one dispatch attempt.

WHY PRE-DISPATCH. Historically the immutable target facts of a dispatch lived only
in the terminal ``succeeded`` row (the external ``createdAt`` inside
``raw_response``) plus the chain's ``action`` / ``target`` columns. Such a binding
is lost exactly when it is most needed: a timeout, a connection failure, an HTTP
error or a lost response leaves no ``succeeded`` row, so the target facts of the
attempt would vanish. The binding is therefore persisted BEFORE the external
request — inside the ``dispatched`` row, which the Execution Service appends and
flushes BEFORE ``executor.execute()`` runs (``service.py``). That row always lands
before the adapter runs, so the binding survives every outcome (success / timeout /
connection failure / HTTP error / response loss). The terminal row then references
the same binding (``dispatch_attempt_id``); it never re-writes it.

WHAT IT RECORDS. The immutable target identity of one attempt: execution /
approval identity, adapter, the server-side action / target snapshot, the dispatch
start time (server clock), a unique attempt identifier, the dispatch-time
approval-status snapshot, and — from an optional adapter contributor — the
config-declared endpoint / version-evidence reference and the target instance /
tenant. It never records a secret: every field passes the ``redact_detail`` gate at
the single ``_append`` write point, no field is a credential, and the contributor
keys are merged through an explicit whitelist (the endpoint is the validated
secret-free base URL; the version is a config declaration, never a liveness
proof).

UNKNOWN IDENTITY FAILS CLOSED. For TheHive 4.1.24-1 there is no authoritative
dispatch-time instance / tenant source (the write config carries a base URL, not a
certified instance identity; the ``OutputCase`` has no organisation), so the TheHive
contributor records ``target_instance`` / ``target_tenant`` as ``None`` (unknown) and
the endpoint / version as config declarations
(``version_assertion_kind="config-declaration"``). A base URL or a config string is
never passed off as a verified identity, so gate 5 still fails closed for every real
execution. The binding is forward-ready — a future authenticated instance / tenant
source populates these fields — but it does not manufacture a binding that does not
exist.

NO SCHEMA MIGRATION. ``ExecutionLog.detail`` is a JSON column, so the binding rides
inside the ``dispatched`` row's ``detail`` (``detail["dispatch_binding"]``) and the
terminal reference inside the terminal row's ``detail``
(``detail["dispatch_attempt_id"]``). No new column, no Alembic migration, no
back-fill of old records: old history simply has no binding, so
``parse_dispatch_binding`` returns ``None`` and the proof derivation fails closed
exactly as before.

ADAPTER CONTRACT UNCHANGED. The ``ResponseExecutor`` ABC (``base.py``) is unchanged:
the contributor capability is a separate ``runtime_checkable`` Protocol
(``DispatchBindingContributor``) an adapter may satisfy, and ``dispatched`` stays a
platform log state, never an adapter product. The ``created_at`` audit-stamp rule is
untouched — ``dispatch_started_at`` is a server-clock fact recorded in ``detail``
(the same precedent as the policy-evaluation time ``service.py`` computes with
``datetime.now(timezone.utc)``), not the ``created_at`` column, which the database
stamps at INSERT (see ``service.py``).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from app.services.executions.models import ExecutionDispatch

# The ``dispatched`` row's detail key the binding is persisted under.
BINDING_DETAIL_KEY = "dispatch_binding"

# The terminal row's detail key carrying the binding's ``attempt_id`` — the
# explicit "the terminal references the same binding" link. A terminal never
# re-writes the binding; it points back at the one pre-dispatch attempt.
TERMINAL_REFERENCE_KEY = "dispatch_attempt_id"

# Shape version, so a forward parser refuses an unknown binding shape fail-closed
# rather than mis-reading a future field layout.
BINDING_SCHEMA = "sentinelflow.dispatch_binding.v1"

# Marker for a version that is a config declaration, never a certified-live
# liveness proof.
VERSION_ASSERTION_CONFIG = "config-declaration"


@runtime_checkable
class DispatchBindingContributor(Protocol):
    """An optional adapter capability: contribute the adapter-specific target
identity facts to the pre-dispatch binding.

This is a separate ``runtime_checkable`` Protocol, not a method on the
``ResponseExecutor`` ABC (``base.py``) — ``dispatched`` is a platform log state,
never part of the adapter contract, so the ABC stays unchanged. An adapter
that makes a real external request (TheHive) may satisfy it; the offline mock
does not, and its binding carries the platform facts alone.

``isinstance`` against this ``runtime_checkable`` Protocol checks only the
presence of ``dispatch_binding_facts`` (the same caveat the codebase already
documents for ``TrustedCreationReader``) — the trust is the controlled call
chain, not the type name. The returned dict is merged through an explicit
whitelist: only the adapter-specific identity keys are read, never a platform
fact, never an arbitrary key. A contributor reports config-declared evidence
as such — for TheHive 4.1.24-1 ``target_instance`` / ``target_tenant`` are
``None`` (no authoritative dispatch-time identity source) and the version is
marked ``config-declaration`` (never a liveness proof).
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
immutable correlation context. The dataclass is and slotted, so fields
cannot be reassigned and no attribute appears by accident. Every field is a
server-side fact or ``None`` (unknown) — never a secret, never back-filled from
the current config.
"""

    schema: str
    execution_id: str
    approval_id: str
    adapter: str
    action: str
    target: str
    # Fresh uuid4 minted by ``build_dispatch_binding`` — the unique identifier of
    # this dispatch attempt; the terminal row references it (``TERMINAL_REFERENCE_KEY``).
    attempt_id: str
    # ISO-8601 server-clock dispatch start, recorded in ``detail`` — not the
    # ``created_at`` audit column (see the module docstring note).
    dispatch_started_at: str
    # The linked approval's status at dispatch time (immutable snapshot for gate 6) —
    # never the live status re-read at reconcile time. ``None`` when unknown.
    approval_status_at_dispatch: str | None
    # Adapter-contributed, config-declared target identity. ``None`` for a
    # non-contributor (mock) and for TheHive 4.1.24-1's absent authoritative
    # instance / tenant source — unknown, never a base-URL substitute.
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
        """The dispatch start as an aware UTC datetime, or ``None`` when the stored
ISO string is malformed (fail-closed — the derivation never substitutes a
server time for the historical dispatch start)."""
        try:
            value = datetime.fromisoformat(self.dispatch_started_at)
        except (ValueError, TypeError):
            return None
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _optional_str(value: Any) -> str | None:
    """A non-empty ``str`` or ``None`` (an absent / blank / non-string adapter fact
is unknown, never coerced)."""
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
    """Assemble the immutable pre-dispatch binding from server-side facts only.

``attempt_id`` is minted here (a fresh uuid4 — the unique identifier of this
dispatch attempt); the terminal row references it via ``TERMINAL_REFERENCE_KEY``.
``dispatch_started_at`` is the caller's server-clock instant (the policy-time
precedent in ``service.py``), stored as an ISO string. ``approval_status`` is the
linked approval's status at dispatch time (the immutable gate-6 snapshot).

Contributor facts are merged through an explicit whitelist — only the five
adapter-specific identity keys are read (``endpoint`` / ``version_evidence_ref``
/ ``version_assertion_kind`` / ``target_instance`` / ``target_tenant``), so a
contributor can never override a platform fact (execution_id / attempt_id /
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
    """Read the binding back from a ``dispatched`` row's ``detail`` — fail-closed.

Returns ``None`` when the detail is absent / not a dict / carries no binding /
has an unknown ``schema`` / is missing any platform-identity fact. It never
raises and """
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
    # The platform-identity facts must all be present as non-empty strings; a
    # binding missing any of them is corrupt -> None (fail-closed, never
    # partially trusted).
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
