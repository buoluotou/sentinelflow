"""Compensation attempt binding: the reverse of the forward dispatch binding.

WHY IT EXISTS. The forward path persists its immutable target binding BEFORE the
external request (the dispatch binding plus the durable commit). The reverse path
had no equivalent: ``compensate_response`` fired ``executor.compensate()`` with
only a flushed — not committed — intent row, so a caller rollback / crash could
erase the target facts of an external reverse request that had already been sent.
This binding is the immutable typed shape that the durable compensation record
(``compensation_attempt``, migration 0013) commits on its own transaction BEFORE
the wire call; the terminal compensation row then references the same
``compensation_attempt_id`` and never re-writes it.

WHAT IT RECORDS. The immutable reverse identity of one compensation attempt: the
compensation chain's own execution identity, the original (compensated) execution
identity, the original's forward durable attempt reference when it exists,
approval, adapter, the reversed action / target, the adapter-declared endpoint
(validated secret-free base URL), the reverse operation identity
(``reverse_operation_ref``: the workflow id / command that the reverse call will
actually request, e.g. ``workflow:<id>`` or ``command:unblock-source-ip``), the
authenticated operator principal, the server-clock prepared / dispatch-start
instants, and the original outcome state being undone. It never records a secret:
no field is a credential, and the durable store passes every field through
``redact_detail`` at its single write point. Version evidence is a config
declaration (``version_assertion_kind``), never a liveness proof;
``target_instance`` / ``target_tenant`` stay ``None`` unless an adapter
contributor provides an authoritative source (the offline mock does not
contribute; TheHive 4.1.24-1 has no authoritative source and never compensates) —
unknown, never a base-URL substitute.

``CompensationBindingContributor``. A separate optional protocol (never on the
``ResponseExecutor`` ABC, mirroring ``DispatchBindingContributor``): the adapter
contributes the reverse-target facts at bind time
(``compensation_binding_facts``) and consumes the committed binding at send time
(``compensate_with_binding``) — the wire call uses the bound operation identity
and endpoint, never a re-read of mutable settings; a config drift between the
durable commit and the wire call refuses fail-closed with zero outbound.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from app.services.executions.models import ExecutionDispatch, ExecutionOutcome

# The terminal compensation row's detail key carrying the binding's
# ``compensation_attempt_id`` — the explicit "the terminal references the same
# durable attempt" link (the reverse mirror of ``TERMINAL_REFERENCE_KEY``). A
# terminal never re-writes the binding; it points back at the one
# pre-compensation attempt.
COMPENSATION_REFERENCE_KEY = "compensation_attempt_id"

# Shape version, so a forward parser refuses an unknown binding shape
# fail-closed rather than mis-reading a future field layout. v2 adds
# ``reverse_operation_ref`` (the real reverse operation identity). A v1 record
# is not parsed as v2 and is never back-filled from current config — a v1
# detail simply yields ``None`` (legacy insufficient evidence, unknown).
COMPENSATION_BINDING_SCHEMA = "sentinelflow.compensation_binding.v2"


@runtime_checkable
class CompensationBindingContributor(Protocol):
    """An optional adapter capability: bind and consume the immutable reverse
target facts (the reverse mirror of ``DispatchBindingContributor``, a separate
``runtime_checkable`` Protocol, not a method on the ``ResponseExecutor`` ABC).

Two halves, one contract:
* ``compensation_binding_facts`` runs at bind time and returns only
server-side facts (server-side adapter configuration / server-side
action mapping — never a client request-body field): the
``reverse_operation_ref`` naming the reverse operation the wire call
will actually use, and the exact ``endpoint`` it will target.
* ``compensate_with_binding`` runs at send time and consumes the
committed binding — the outbound request uses the bound operation
identity and endpoint, never a re-resolution from mutable settings. If
the binding cannot be consumed (missing / mismatched facts) it refuses
fail-closed before any outbound (zero external call).

``isinstance`` against this ``runtime_checkable`` Protocol checks only the
presence of the methods (the same caveat the codebase documents for
``DispatchBindingContributor`` / ``TrustedCreationReader``) — the trust is
the controlled call chain, not the type name.
"""

    def compensation_binding_facts(self, dispatch: ExecutionDispatch) -> dict[str, Any]:
        """The adapter-specific reverse target facts for this compensation
(server-side only, never a secret): ``reverse_operation_ref`` +
``endpoint`` (+ optional identity facts)."""
        ...

    def compensate_with_binding(
        self, dispatch: ExecutionDispatch, binding: "CompensationBinding"
    ) -> ExecutionOutcome:
        """Reverse call that consumes the committed binding; config / mapping
drift refuses fail-closed with zero outbound."""
        ...


@dataclass(frozen=True, slots=True)
class CompensationBinding:
    """The immutable pre-compensation binding (typed shape).

Assembled from server-side facts only and committed by the durable
compensation store BEFORE the external reverse request; the dataclass is
and slotted, so fields cannot be reassigned and no attribute appears
by accident. Every field is a server-side fact or ``None`` (unknown) — never
a secret, never back-filled from the current config.
"""

    schema: str
    # The compensation chain's own execution_id (a fresh identity undoing the
    # original; the chain the terminal reference lives in).
    execution_id: str
    # Fresh uuid4 minted by ``build_compensation_binding`` — the unique
    # identifier of this compensation attempt; the terminal compensation row
    # references it (``COMPENSATION_REFERENCE_KEY``).
    compensation_attempt_id: str
    # The compensated forward execution.
    original_execution_id: str
    # The original chain's forward durable-attempt reference
    # (detail["dispatch_attempt_id"] on its terminal row) when the original
    # executed through a durable store; ``None`` for old history / store-less
    # mock runs — unknown, never back-filled.
    original_dispatch_attempt_id: str | None
    approval_id: str
    adapter: str
    # The action whose reverse effect is being applied (the action inherited
    # server-side from the original chain — e.g. ``block_source_ip``; the
    # adapter maps it to its reverse operation internally). Informational:
    # the real reverse operation identity lives in ``reverse_operation_ref``.
    reverse_action: str
    # The real reverse operation the wire call requests, in the adapter's own
    # namespace: e.g. ``workflow:<workflow-id>`` (Shuffle) or
    # ``command:unblock-source-ip`` (Wazuh). ``None`` for a non-contributor
    # (mock / TheHive never compensates) or a legacy v1 record — unknown, never
    # back-filled, and never ``reverse_action`` masquerading as the reverse
    # operation.
    reverse_operation_ref: str | None
    target: str
    # ISO-8601 server-clock instants (see the model docstring for the exact
    # meaning of each): when the binding was prepared, and the last instant
    # before the durable commit at which no external request could have fired.
    prepared_at: str
    dispatch_started_at: str
    # The authenticated operator principal (derived from the token by the API;
    # never from the request body).
    operator: str
    # The operator's comment / reason, when provided.
    reason: str | None
    # The original chain's derived state being undone ("succeeded" / "failed").
    original_outcome_state: str
    # Adapter-contributed, config-declared target identity. ``None`` for a
    # non-contributor (mock / wazuh / shuffle today) — unknown, never a
    # substitute.
    endpoint: str | None
    version_evidence_ref: str | None
    version_assertion_kind: str | None
    target_instance: str | None
    target_tenant: str | None

    def to_detail(self) -> dict[str, Any]:
        """Project to the JSON-storable detail dict (both instants are already
ISO strings, so the result is pure JSON scalars)."""
        return {
            "schema": self.schema,
            "execution_id": self.execution_id,
            "compensation_attempt_id": self.compensation_attempt_id,
            "original_execution_id": self.original_execution_id,
            "original_dispatch_attempt_id": self.original_dispatch_attempt_id,
            "approval_id": self.approval_id,
            "adapter": self.adapter,
            "reverse_action": self.reverse_action,
            "reverse_operation_ref": self.reverse_operation_ref,
            "target": self.target,
            "prepared_at": self.prepared_at,
            "dispatch_started_at": self.dispatch_started_at,
            "operator": self.operator,
            "reason": self.reason,
            "original_outcome_state": self.original_outcome_state,
            "endpoint": self.endpoint,
            "version_evidence_ref": self.version_evidence_ref,
            "version_assertion_kind": self.version_assertion_kind,
            "target_instance": self.target_instance,
            "target_tenant": self.target_tenant,
        }

    def prepared_instant(self) -> datetime | None:
        """The prepared instant as an aware UTC datetime, or ``None`` when the
stored ISO string is malformed (fail-closed — the store never
substitutes a server time for the historical instant)."""
        return _parse_iso(self.prepared_at)

    def started_at(self) -> datetime | None:
        """The dispatch-start instant as an aware UTC datetime, or ``None``
(fail-closed, same rule as ``prepared_instant``)."""
        return _parse_iso(self.dispatch_started_at)


def _parse_iso(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _optional_str(value: Any) -> str | None:
    """A non-empty ``str`` or ``None`` (an absent / blank / non-string adapter
fact is unknown, never coerced)."""
    return value if isinstance(value, str) and value else None


def build_compensation_binding(
    *,
    execution_id: uuid.UUID,
    original_execution_id: uuid.UUID,
    original_dispatch_attempt_id: uuid.UUID | None,
    approval_id: uuid.UUID,
    adapter: str,
    action: str,
    target: str,
    operator: str,
    reason: str | None,
    original_outcome_state: str,
    prepared_at: datetime,
    dispatch_started_at: datetime,
    contributor_facts: dict[str, Any] | None = None,
) -> CompensationBinding:
    """Assemble the immutable pre-compensation binding from server-side facts only.

``compensation_attempt_id`` is minted here (a fresh uuid4 — the unique
identifier of this compensation attempt); the terminal compensation row
references it via ``COMPENSATION_REFERENCE_KEY``. Contributor facts are
merged through an explicit whitelist — only the six adapter-specific
identity keys are read (``reverse_operation_ref`` / ``endpoint`` /
``version_evidence_ref`` / ``version_assertion_kind`` / ``target_instance``
/ ``target_tenant``), so a contributor can never override a platform fact
or smuggle an arbitrary key into the binding.
"""
    facts = contributor_facts or {}
    return CompensationBinding(
        schema=COMPENSATION_BINDING_SCHEMA,
        execution_id=str(execution_id),
        compensation_attempt_id=str(uuid.uuid4()),
        original_execution_id=str(original_execution_id),
        original_dispatch_attempt_id=(
            str(original_dispatch_attempt_id)
            if original_dispatch_attempt_id is not None
            else None
        ),
        approval_id=str(approval_id),
        adapter=adapter,
        reverse_action=action,
        reverse_operation_ref=_optional_str(facts.get("reverse_operation_ref")),
        target=target,
        prepared_at=prepared_at.isoformat(),
        dispatch_started_at=dispatch_started_at.isoformat(),
        operator=operator,
        reason=reason,
        original_outcome_state=original_outcome_state,
        endpoint=_optional_str(facts.get("endpoint")),
        version_evidence_ref=_optional_str(facts.get("version_evidence_ref")),
        version_assertion_kind=_optional_str(facts.get("version_assertion_kind")),
        target_instance=_optional_str(facts.get("target_instance")),
        target_tenant=_optional_str(facts.get("target_tenant")),
    )


def parse_compensation_binding(detail: Any) -> CompensationBinding | None:
    """Read the binding back from a durable record's ``detail`` — fail-closed.

Returns ``None`` when the detail is absent / not a dict / has an unknown
``schema`` / is missing any platform-identity fact. It never raises and """
    if not isinstance(detail, dict):
        return None
    if detail.get("schema") != COMPENSATION_BINDING_SCHEMA:
        return None
    required = (
        detail.get("execution_id"),
        detail.get("compensation_attempt_id"),
        detail.get("original_execution_id"),
        detail.get("approval_id"),
        detail.get("adapter"),
        detail.get("reverse_action"),
        detail.get("target"),
        detail.get("prepared_at"),
        detail.get("dispatch_started_at"),
        detail.get("operator"),
        detail.get("original_outcome_state"),
    )
    if not all(isinstance(value, str) and value for value in required):
        return None
    return CompensationBinding(
        schema=COMPENSATION_BINDING_SCHEMA,
        execution_id=detail["execution_id"],
        compensation_attempt_id=detail["compensation_attempt_id"],
        original_execution_id=detail["original_execution_id"],
        original_dispatch_attempt_id=_optional_str(
            detail.get("original_dispatch_attempt_id")
        ),
        approval_id=detail["approval_id"],
        adapter=detail["adapter"],
        reverse_action=detail["reverse_action"],
        reverse_operation_ref=_optional_str(detail.get("reverse_operation_ref")),
        target=detail["target"],
        prepared_at=detail["prepared_at"],
        dispatch_started_at=detail["dispatch_started_at"],
        operator=detail["operator"],
        reason=_optional_str(detail.get("reason")),
        original_outcome_state=detail["original_outcome_state"],
        endpoint=_optional_str(detail.get("endpoint")),
        version_evidence_ref=_optional_str(detail.get("version_evidence_ref")),
        version_assertion_kind=_optional_str(detail.get("version_assertion_kind")),
        target_instance=_optional_str(detail.get("target_instance")),
        target_tenant=_optional_str(detail.get("target_tenant")),
    )
