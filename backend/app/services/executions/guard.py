"""Execution Guard / Policy service (Phase 3.1.4, design §7).

Guards answer exactly one question — allow or refuse, with a reason.
They NEVER touch the database (no read is their business either: the
3.1.6 Execute Service loads entities and hands them in), and they never
write execution_log: appending `guard_rejected` after a business
rejection is the Execute Service's job (same transaction, D13).

Three guards live here, matching the design's split of responsibilities:

- G2 approval binding: approval exists -> status approved ->
  recommendation exists -> action comes from the SERVER-SIDE snapshot
  and is machine-executable (D3).
- G3 lifecycle / idempotency pre-check: the approval has no forward
  execution yet and the execution_id is unbound. A failure here is a
  409-style conflict with NO log row (write-before validation) — this
  is deliberately a different exception family than G2/G4 rejections.
- G4 executor capability: minimal ``ExecutorCapability`` protocol only.
  The real ResponseExecutor / Mock / DryRun arrive in 3.1.5 — the Guard
  refuses to know more than supports() / supports_compensation().

Auth (401) and Schema (422) are API-layer guards by design and stay out
of this module entirely.
"""
from __future__ import annotations

from typing import Protocol, Sequence

from app.services.ai.models import RESPONSE_ACTIONS
from app.services.executions.state import (
    ExecutionDirectionMismatch,
    ExecutionLogRow,
    derive_execution_state,
)

#: Machine-executable action vocabulary (D3, frozen; 3.2.5 E1
#: extension). Strict subset of the Phase 2 six-word RESPONSE_ACTIONS:
#: the E1 adjudication promotes escalate_to_incident to a controlled
#: machine-executable capability (TheHive case creation, full
#: Approval -> Execute -> Guard -> Executor chain, zero data migration).
#: The remaining two words (hunt_related_activity / monitor_only) are
#: advisory and must NEVER be treated as executable by any Guard.
EXECUTABLE_ACTIONS = frozenset(
    {"block_source_ip", "isolate_host", "disable_account", "escalate_to_incident"}
)
assert EXECUTABLE_ACTIONS < RESPONSE_ACTIONS, (
    "executable vocabulary must stay a strict subset of RESPONSE_ACTIONS"
)

#: Executable actions with NO machine reversal (E1 capability policy):
#: escalating to a case cannot be automatically undone — the case
#: lifecycle belongs to human investigation and cases are never
#: auto-closed by the platform.
NON_COMPENSATABLE_ACTIONS = frozenset({"escalate_to_incident"})
assert NON_COMPENSATABLE_ACTIONS <= EXECUTABLE_ACTIONS

#: Frozen rejection-code vocabulary. Every GuardRejection carries one of
#: these; the guard_rejected row's detail records it verbatim (3.1.6).
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
    """A BUSINESS rejection (G2 / G4): the request formed a legal Execute
    Intent but policy refuses it. This is an audit fact — the 3.1.6
    Execute Service appends a ``guard_rejected`` row (same transaction,
    D13) with ``code`` / ``reason`` in its detail.

    Carries ``code`` (frozen vocabulary) + ``reason`` (stable,
    human-readable, rendered verbatim by the API layer)."""

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
    """G3 lifecycle: the approval already has a forward execution (any
    derived state — requested / guard_rejected / dispatched / succeeded /
    failed). Re-execution is forbidden even after `failed`: the recovery
    path is compensation, never a fresh execute. 409, NO log row
    (constraint 2's placeholder-row uniqueness is the DB second line)."""

    http_status = 409

    def __init__(self, message: str, derived_state: str | None = None):
        super().__init__(message)
        self.derived_state = derived_state


class ExecutionIdAlreadyBound(ExecutionGuardError):
    """G3 idempotency: the execution_id already has log rows — any replay
    (same or different facts) is a conflict. 409, NO log row; the partial
    unique index is the DB second line (D14)."""

    http_status = 409


class ExecutorCapability(Protocol):
    """The ONLY executor surface Phase 3.1.4 may depend on (G4).

    The full ResponseExecutor contract (name / execute / compensate /
    ExecutionDispatch / ExecutionOutcome) is 3.1.5 territory — every real
    executor will satisfy this protocol structurally, so the Guard needs
    zero changes when 3.1.5 lands."""

    def supports(self, action: str) -> bool: ...

    def supports_compensation(self, action: str) -> bool: ...


def check_approval_binding(approval, recommendation, action: str) -> None:
    """G2: approval binding + snapshot provenance + executability (D3).

    The ``action`` argument must be the value the Execute Service read
    from the approved recommendation's server-side snapshot — clients
    never supply it (request schema is extra=forbid, G1). The provenance
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
    """G3: lifecycle + idempotency pre-check (409 family, NO log rows).

    ``approval_rows``: every execution_log row bound to this approval
    (both directions — compensation inherits the approval_id, D11);
    ``execution_id_rows``: every row carrying this execution_id. The
    caller (3.1.6) loads them; this function is pure.

    The forward-execution verdict goes through the frozen derived-state
    rule of 3.1.3 — the approval slot is occupied iff the derived state
    of its direction='execute' rows is anything at all. Compensation rows
    alone never occupy the forward slot."""
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
    """G4: adapter capability — supports() for execute,
    supports_compensation() for compensate. A capability miss is a
    BUSINESS rejection (guard_rejected row, not a 409): the request was
    a legal Intent the platform's policy refuses on adapter grounds."""
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
