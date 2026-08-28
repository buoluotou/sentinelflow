"""Execution state machine + pure derived-state logic (Phase 3.1.3).

The execution layer is a pure append log (design D7): state is NEVER
stored — it is DERIVED as the latest row per execution_id. This module
is the single source of truth for two things:

1. ``derive_execution_state(rows)`` — a PURE function: log rows in,
   current state out. No INSERT / UPDATE / DELETE / flush / commit,
   ever. GET endpoints, the audit page and any dashboard reuse this
   one implementation.
2. ``validate_transition(...)`` — the frozen state machine. The Service
   is the primary arbiter of sequencing (DB CHECK only forbids illegal
   decision x direction combinations, constraint 9); constraint 10 is
   enforced here: the DB only knows a `requested` row is unique, NOT
   that it must be the FIRST row of its chain — only this matrix does.

Design references (docs/design/phase3-response-execution.md):
- §6 frozen state machine + transition matrix
- constraint 8: derived ordering ``created_at DESC, id DESC``
- constraint 10: every direction='execute' chain holds exactly one
  `requested` row and it MUST be the chain's first row

Vocabulary is imported from ``app.models.execution_log`` — one frozen
source, never duplicated here.
"""
from __future__ import annotations

from typing import Protocol, Sequence

from app.models.execution_log import (
    COMPENSATE_DECISIONS,
    EXECUTE_DECISIONS,
    EXECUTION_DECISIONS,
    EXECUTION_DIRECTIONS,
)

# The not-yet-started state. ``None`` is the empty-chain sentinel in the
# transition matrix — a chain can only be entered through `requested`
# (execute) or `compensation_requested` (compensate); nothing else.
DIRECTION_VOCABULARY: dict[str, frozenset[str]] = {
    "execute": EXECUTE_DECISIONS,
    "compensate": COMPENSATE_DECISIONS,
}

#: Frozen transition matrix (design §6). Keys are the derived current
#: state (``None`` = chain not started); values the legal next decisions.
#: Terminal states map to the empty frozenset — no transition out, ever.
ALLOWED_TRANSITIONS: dict[str | None, frozenset[str]] = {
    # execute direction
    None: frozenset({"requested", "compensation_requested"}),
    "requested": frozenset({"guard_rejected", "dispatched"}),
    "guard_rejected": frozenset(),
    "dispatched": frozenset({"succeeded", "failed"}),
    "succeeded": frozenset(),
    "failed": frozenset(),
    # compensate direction
    "compensation_requested": frozenset(
        {"compensation_succeeded", "compensation_failed"}
    ),
    "compensation_succeeded": frozenset(),
    "compensation_failed": frozenset(),
}

#: Decisions after which no further row may ever be appended.
TERMINAL_DECISIONS = frozenset(
    decision for decision, targets in ALLOWED_TRANSITIONS.items()
    if decision is not None and not targets
)

#: Legal entries out of the not-yet-started state, per direction — the
#: first-row invariant (constraint 10) as data.
FIRST_ROW_BY_DIRECTION: dict[str, str] = {
    "execute": "requested",
    "compensate": "compensation_requested",
}


class ExecutionStateError(Exception):
    """Base class of all execution state errors (never silent failures)."""


class InvalidExecutionTransition(ExecutionStateError):
    """The transition violates the frozen state machine — including the
    first-row invariant (constraint 10) and all terminal states.

    Carries ``current`` / ``target`` / ``direction`` so the API layer can
    render a stable message without re-parsing text (incidents precedent).
    ``current`` is None for a not-yet-started chain.
    """

    def __init__(
        self,
        message: str,
        current: str | None = None,
        target: str | None = None,
        direction: str | None = None,
    ):
        super().__init__(message)
        self.current = current
        self.target = target
        self.direction = direction


class ExecutionDirectionMismatch(ExecutionStateError):
    """A decision word was used with the wrong direction
    (execute word with compensate or vice versa), or the direction itself
    is unknown. The DB CHECK is only the last integrity line — the
    Service refuses first. Carries ``decision`` / ``direction``."""

    def __init__(
        self,
        message: str,
        decision: str | None = None,
        direction: str | None = None,
    ):
        super().__init__(message)
        self.decision = decision
        self.direction = direction


class ExecutionLogRow(Protocol):
    """Structural shape derive/validate need — ExecutionLog satisfies it,
    tests may supply lightweight stubs (the logic is pure and DB-free)."""

    id: object
    created_at: object
    decision: str
    direction: str


def derive_execution_state(rows: Sequence[ExecutionLogRow]) -> str | None:
    """Pure derived-state logic (constraint 8): the current state of ONE
    execution_id is the ``decision`` of its latest row.

    Latest is determined STRICTLY by ``ORDER BY created_at DESC, id DESC``
    — never by list position, never by id alone. Ties on created_at are
    broken deterministically by id. The input is expected to already be
    the rows of a single execution_id (mixing executions is a caller bug);
    ordering of the input itself does not matter.

    Returns None for an empty chain (not-yet-started). No DB access, no
    writes of any kind.
    """
    if not rows:
        return None
    latest = max(rows, key=lambda row: (row.created_at, row.id))
    return latest.decision


def is_terminal_state(state: str | None) -> bool:
    """True when the chain reached a terminal decision (or is unknown to
    the matrix — being conservative: only known non-terminal states are
    explicitly non-terminal)."""
    return state not in ALLOWED_TRANSITIONS or not ALLOWED_TRANSITIONS[state]


def validate_transition(
    current: str | None, target_decision: str, direction: str
) -> None:
    """Ruling of the frozen state machine (Service is the primary
    arbiter, design §6). Returns silently on a legal transition; raises
    a typed ExecutionStateError otherwise — never returns a boolean.

    Order of checks matters for stable errors:
    1. direction must be known;
    2. ``current`` must be a state this module knows (an unknown derived
       state means a corrupted/foreign row — refuse, never improvise);
    3. ``target_decision`` must belong to ``direction``'s vocabulary
       (direction isolation — the Service refuses cross-direction words
       itself even though the DB CHECK also catches them);
    4. the matrix decides (this is where constraint 10 lives: an empty
       chain may only enter through its direction's first row).
    """
    if direction not in EXECUTION_DIRECTIONS:
        raise ExecutionDirectionMismatch(
            f"Unknown execution direction: {direction}",
            decision=target_decision,
            direction=direction,
        )
    if current is not None and current not in ALLOWED_TRANSITIONS:
        raise InvalidExecutionTransition(
            f"Invalid execution transition: unknown current state {current}",
            current=current,
            target=target_decision,
            direction=direction,
        )
    if target_decision not in DIRECTION_VOCABULARY[direction]:
        if target_decision in EXECUTION_DECISIONS:
            raise ExecutionDirectionMismatch(
                f"Decision '{target_decision}' does not belong to "
                f"direction '{direction}'",
                decision=target_decision,
                direction=direction,
            )
        raise InvalidExecutionTransition(
            f"Invalid execution transition: unknown decision "
            f"{target_decision}",
            current=current,
            target=target_decision,
            direction=direction,
        )
    if target_decision not in ALLOWED_TRANSITIONS[current]:
        raise InvalidExecutionTransition(
            f"Invalid execution transition: {current or '(empty)'} -> "
            f"{target_decision}",
            current=current,
            target=target_decision,
            direction=direction,
        )
