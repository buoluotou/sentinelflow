"""Execution Guard / Policy service.

Guards answer exactly one question — allow or refuse, with a reason.
They never touch the database: loading entities is the Execute Service's
job, and so is appending the ``guard_rejected`` row after a business
rejection (same transaction as the rejection).

Three checks live here, split by responsibility:

- Approval binding: approval exists -> status approved -> recommendation
exists -> action comes from the server-side snapshot and is
machine-executable.
- Lifecycle / idempotency pre-check: the approval has no forward
execution yet and the execution_id is unbound. A failure here is a
409-style conflict with no log row (write-before validation), which is
why it is a different exception family than the business rejections.
- Executor capability: minimal ``ExecutorCapability`` protocol only. The
Guard refuses to know more than supports() / supports_compensation(),
so any full executor implementation satisfies it structurally.

Auth (401) and Schema (422) are API-layer guards and stay out of this
module entirely.
"""
from __future__ import annotations

from typing import Protocol, Sequence

from app.services.ai.models import RESPONSE_ACTIONS
from app.services.executions.state import (
    ExecutionDirectionMismatch,
    ExecutionLogRow,
    derive_execution_state,
)

# Machine-executable action vocabulary. Strict subset of the six-word
# RESPONSE_ACTIONS: escalate_to_incident is a controlled
# machine-executable capability (TheHive case creation, full
# Approval -> Execute -> Guard -> Executor chain, no data migration).
# The remaining two words (hunt_related_activity / monitor_only) are
# advisory and must never be treated as executable by any Guard.
EXECUTABLE_ACTIONS = frozenset(
    {"block_source_ip", "isolate_host", "disable_account", "escalate_to_incident"}
)
assert EXECUTABLE_ACTIONS < RESPONSE_ACTIONS, (
    "executable vocabulary must stay a strict subset of RESPONSE_ACTIONS"
)

# Executable actions with no machine reversal: escalating to a case
# cannot be automatically undone — the case lifecycle belongs to human
# investigation and cases are never auto-closed by the platform.
NON_COMPENSATABLE_ACTIONS = frozenset({"escalate_to_incident"})
assert NON_COMPENSATABLE_ACTIONS <= EXECUTABLE_ACTIONS

# Rejection-code vocabulary. Every GuardRejection carries one of these;
# the guard_rejected row's detail records it verbatim.
GUARD_REJECTION_CODES = frozenset(
    {
        "approval_not_approved",
        "recommendation_missing",
        "action_not_in_snapshot",
        "action_not_executable",
        "executor_unsupported",
    }
)


class ExecutionGuardError(Exception):
    """Base class of all Guard verdicts (never silent failures)."""


class GuardRejection(ExecutionGuardError):
    """A business rejection: the request formed a legal Execute Intent but
policy refuses it. This is an audit fact — the Execute Service appends
a ``guard_rejected`` row in the same transaction, with ``code`` /
``reason`` in its detail.

Carries ``code`` (from the rejection-code vocabulary) + ``reason``
(stable, human-readable, rendered verbatim by the API layer)."""

    def __init__(self, code: str, reason: str):
        super().__init__(f"Execution guard rejected: {code} — {reason}")
        assert code in GUARD_REJECTION_CODES, f"unknown rejection code: {code}"
        self.code = code
        self.reason = reason


class ApprovalNotFound(ExecutionGuardError):
    """The requested approval does not exist — 404, NO log row. Checked
before any `requested` row can land: that row carries the approval_id
foreign key, so existence is a precondition of the execution fact
itself, not a business rejection."""

    http_status = 404


class ApprovalAlreadyExecuted(ExecutionGuardError):
    """The approval already has a forward execution (any derived state —
requested / guard_rejected / dispatched / succeeded / failed).
Re-execution is forbidden even after `failed`: the recovery path is
compensation, never a fresh execute. 409, no log row; the unique index
on the placeholder row is the database's second line of defence."""

    http_status = 409

    def __init__(self, message: str, derived_state: str | None = None):
        super().__init__(message)
        self.derived_state = derived_state


class ExecutionIdAlreadyBound(ExecutionGuardError):
    """The execution_id already has log rows — any replay (same or
different facts) is a conflict. 409, no log row; the partial unique
index is the database's second line of defence."""

    http_status = 409


class ExecutorCapability(Protocol):
    """The only executor surface the Guard may depend on.

The Guard never sees the full ResponseExecutor contract (name /
execute / compensate / ExecutionDispatch / ExecutionOutcome). Every
real executor satisfies this protocol structurally, so the Guard needs
no changes as executors gain capability."""

    def supports(self, action: str) -> bool: ...

    def supports_compensation(self, action: str) -> bool: ...


def check_approval_binding(approval, recommendation, action: str) -> None:
    """Approval binding + snapshot provenance + executability.

The ``action`` argument must be the value the Execute Service read
from the approved recommendation's server-side snapshot — clients
never supply it (the request schema is extra=forbid). The provenance
check below is the service-layer half of that promise: even a
perfectly executable-looking word is refused unless it literally
appears in the snapshot.

Returns silently on pass; raises ApprovalNotFound (404, no row) or
GuardRejection (business rejection -> guard_rejected row) otherwise.
"""
    if approval is None:
        raise ApprovalNotFound("Approval not found")
    if approval.status != "approved":
        raise GuardRejection(
            "approval_not_approved",
            f"Approval {approval.id} has status '{approval.status}'; "
            f"only approved decisions can be executed",
        )
    if recommendation is None:
        raise GuardRejection(
            "recommendation_missing",
            f"Approval {approval.id} has no recommendation snapshot to "
            f"assemble action/target from",
        )
    snapshot_actions = {
        item.get("action") for item in (recommendation.recommendations or [])
    }
    if action not in snapshot_actions:
        raise GuardRejection(
            "action_not_in_snapshot",
            f"Action '{action}' is not part of the approved recommendation "
            f"snapshot; action/target are server-side facts only",
        )
    if action not in EXECUTABLE_ACTIONS:
        raise GuardRejection(
            "action_not_executable",
            f"Action '{action}' is advisory, not machine-executable; only "
            f"block_source_ip / isolate_host / disable_account / "
            f"escalate_to_incident can execute",
        )


def check_lifecycle(
    approval_rows: Sequence[ExecutionLogRow],
    execution_id_rows: Sequence[ExecutionLogRow],
) -> None:
    """Lifecycle + idempotency pre-check (409 family, no log rows).

``approval_rows``: every execution_log row bound to this approval
(both directions — compensation inherits the approval_id);
``execution_id_rows``: every row carrying this execution_id. The
caller loads them; this function is pure.

The forward-execution verdict goes through the derived-state rule: the
approval slot is occupied iff the derived state of its
direction='execute' rows is anything at all. Compensation rows alone
never occupy the forward slot."""
    forward_rows = [row for row in approval_rows if row.direction == "execute"]
    derived = derive_execution_state(forward_rows)
    if derived is not None:
        raise ApprovalAlreadyExecuted(
            f"Approval already has a forward execution "
            f"(derived state '{derived}'); the recovery path is "
            f"compensation, not re-execution",
            derived_state=derived,
        )
    if execution_id_rows:
        raise ExecutionIdAlreadyBound(
            "execution_id is already bound; replays are refused and the "
            "database keeps the first execution's complete facts"
        )


def check_executor_capability(
    executor: ExecutorCapability, action: str, direction: str
) -> None:
    """Adapter capability — supports() for execute,
supports_compensation() for compensate. A capability miss is a
business rejection (guard_rejected row, not a 409): the request was a
legal Intent that policy refuses on adapter grounds."""
    if direction == "execute":
        capable = executor.supports(action)
    elif direction == "compensate":
        capable = executor.supports_compensation(action)
    else:
        raise ExecutionDirectionMismatch(
            f"Unknown execution direction: {direction}",
            decision=None,
            direction=direction,
        )
    if not capable:
        raise GuardRejection(
            "executor_unsupported",
            f"Executor '{getattr(executor, 'name', '?')}' does not support "
            f"{'compensation of ' if direction == 'compensate' else ''}"
            f"action '{action}'",
        )
