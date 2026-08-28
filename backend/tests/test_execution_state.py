"""Phase 3.1.3: execution state machine + pure derived-state tests.

The whole later stack (Execute/Compensation services, API, audit UI)
derives state through these two functions, so this suite is deliberately
hard: every legal transition, an exhaustive illegal-transition matrix,
terminal-state protection, direction isolation, the constraint-10
first-row invariant, deterministic created_at+id derivation, and
per-execution isolation.

All tests are DB-free on purpose: derive_execution_state /
validate_transition must be PURE (no INSERT/UPDATE/DELETE/flush/commit)
and this file proves it — rows are lightweight stubs, no fixtures.
"""
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from app.models.execution_log import (
    COMPENSATE_DECISIONS,
    EXECUTE_DECISIONS,
    EXECUTION_LEGAL_COMBINATIONS,
)
from app.services.executions.state import (
    ALLOWED_TRANSITIONS,
    DIRECTION_VOCABULARY,
    FIRST_ROW_BY_DIRECTION,
    TERMINAL_DECISIONS,
    ExecutionDirectionMismatch,
    ExecutionStateError,
    InvalidExecutionTransition,
    derive_execution_state,
    is_terminal_state,
    validate_transition,
)

T0 = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
ALL_DECISIONS = sorted(EXECUTE_DECISIONS | COMPENSATE_DECISIONS)


@dataclass
class StubRow:
    """Minimal structural stand-in for ExecutionLog (Protocol conformance
    is the contract — derive/validate never need the DB)."""

    id: uuid.UUID
    created_at: datetime
    decision: str
    direction: str


def row(decision, direction, *, created_at=None, row_id=None):
    return StubRow(
        id=row_id or uuid.uuid4(),
        created_at=created_at or T0,
        decision=decision,
        direction=direction,
    )


def chain(*decisions, direction="execute", start=T0):
    """Rows of one execution chain, strictly increasing timestamps."""
    return [
        row(decision, direction, created_at=start + timedelta(seconds=i))
        for i, decision in enumerate(decisions)
    ]


def expect_ok(current, target, direction):
    assert validate_transition(current, target, direction) is None


def expect_invalid(current, target, direction):
    with pytest.raises(InvalidExecutionTransition) as exc_info:
        validate_transition(current, target, direction)
    exc = exc_info.value
    assert exc.current == current
    assert exc.target == target
    assert exc.direction == direction
    return exc


# ---------------------------------------------------------------------------
# Vocabulary / matrix freeze
# ---------------------------------------------------------------------------


class TestVocabularyFreeze:
    def test_direction_vocabulary_matches_model_constants(self):
        assert DIRECTION_VOCABULARY["execute"] == EXECUTE_DECISIONS
        assert DIRECTION_VOCABULARY["compensate"] == COMPENSATE_DECISIONS

    def test_matrix_covers_exactly_all_decisions_plus_empty(self):
        assert set(ALLOWED_TRANSITIONS) == (
            EXECUTE_DECISIONS | COMPENSATE_DECISIONS | {None}
        )

    def test_matrix_entries_match_legal_combinations(self):
        for current, targets in ALLOWED_TRANSITIONS.items():
            if current is None:
                assert targets == {"requested", "compensation_requested"}
                continue
            direction = (
                "execute" if current in EXECUTE_DECISIONS else "compensate"
            )
            # every legal target keeps the chain inside its direction
            for target in targets:
                assert (target, direction) in EXECUTION_LEGAL_COMBINATIONS

    def test_terminal_decisions_exact_set(self):
        assert TERMINAL_DECISIONS == frozenset(
            {
                "guard_rejected",
                "succeeded",
                "failed",
                "compensation_succeeded",
                "compensation_failed",
            }
        )

    def test_first_row_invariant_data(self):
        assert FIRST_ROW_BY_DIRECTION == {
            "execute": "requested",
            "compensate": "compensation_requested",
        }


# ---------------------------------------------------------------------------
# Legal transition matrix — one test per legal edge
# ---------------------------------------------------------------------------


class TestLegalExecuteTransitions:
    def test_empty_to_requested(self):
        expect_ok(None, "requested", "execute")

    def test_requested_to_guard_rejected(self):
        expect_ok("requested", "guard_rejected", "execute")

    def test_requested_to_dispatched(self):
        expect_ok("requested", "dispatched", "execute")

    def test_dispatched_to_succeeded(self):
        expect_ok("dispatched", "succeeded", "execute")

    def test_dispatched_to_failed(self):
        expect_ok("dispatched", "failed", "execute")


class TestLegalCompensateTransitions:
    def test_empty_to_compensation_requested(self):
        expect_ok(None, "compensation_requested", "compensate")

    def test_compensation_requested_to_succeeded(self):
        expect_ok("compensation_requested", "compensation_succeeded", "compensate")

    def test_compensation_requested_to_failed(self):
        expect_ok("compensation_requested", "compensation_failed", "compensate")


# ---------------------------------------------------------------------------
# Illegal transition matrix
# ---------------------------------------------------------------------------


class TestFirstRowInvariant:
    """Constraint 10: the DB only knows `requested` is unique — the
    Service alone enforces that it is the chain's FIRST row."""

    @pytest.mark.parametrize(
        "decision", ["dispatched", "succeeded", "failed", "guard_rejected"]
    )
    def test_empty_execute_chain_rejects_everything_but_requested(self, decision):
        exc = expect_invalid(None, decision, "execute")
        assert "(empty)" in str(exc)

    @pytest.mark.parametrize(
        "decision", ["compensation_succeeded", "compensation_failed"]
    )
    def test_empty_compensate_chain_rejects_terminal_words(self, decision):
        expect_invalid(None, decision, "compensate")

    def test_only_entry_words_legal_from_empty(self):
        for direction, entry in FIRST_ROW_BY_DIRECTION.items():
            expect_ok(None, entry, direction)
            for decision in DIRECTION_VOCABULARY[direction] - {entry}:
                expect_invalid(None, decision, direction)


class TestSkipLevelTransitions:
    def test_requested_cannot_jump_to_succeeded(self):
        expect_invalid("requested", "succeeded", "execute")

    def test_requested_cannot_jump_to_failed(self):
        expect_invalid("requested", "failed", "execute")

    def test_dispatched_cannot_go_back_to_requested(self):
        expect_invalid("dispatched", "requested", "execute")

    def test_dispatched_cannot_be_guard_rejected_anymore(self):
        expect_invalid("dispatched", "guard_rejected", "execute")

    def test_requested_cannot_repeat_requested(self):
        # exactly ONE requested per chain — a second one is a re-execution
        # attempt and is refused by the state machine too (the partial
        # unique index is the second line, D14).
        expect_invalid("requested", "requested", "execute")


class TestTerminalStateProtection:
    """Every terminal state x every decision word of its own direction
    must raise the typed exception — exhaustively."""

    @pytest.mark.parametrize("terminal", sorted(TERMINAL_DECISIONS))
    def test_terminal_rejects_every_same_direction_decision(self, terminal):
        direction = (
            "execute" if terminal in EXECUTE_DECISIONS else "compensate"
        )
        for decision in sorted(DIRECTION_VOCABULARY[direction]):
            expect_invalid(terminal, decision, direction)

    def test_is_terminal_state_flags(self):
        for terminal in TERMINAL_DECISIONS:
            assert is_terminal_state(terminal) is True
        for non_terminal in ("requested", "dispatched", "compensation_requested"):
            assert is_terminal_state(non_terminal) is False
        assert is_terminal_state(None) is False
        # unknown state: conservative — treated as terminal
        assert is_terminal_state("bogus") is True


class TestUnknownStateAndDecision:
    def test_unknown_current_state_refused(self):
        exc = expect_invalid("dispatched2", "succeeded", "execute")
        assert "unknown current state" in str(exc)

    def test_unknown_decision_refused_as_invalid_transition(self):
        exc = expect_invalid("requested", "bogus_decision", "execute")
        assert "unknown decision" in str(exc)

    def test_unknown_direction_refused(self):
        with pytest.raises(ExecutionDirectionMismatch) as exc_info:
            validate_transition(None, "requested", "rollback")
        assert exc_info.value.direction == "rollback"


# ---------------------------------------------------------------------------
# Direction isolation (Service refuses cross-direction words itself,
# even though the DB CHECK would also catch them)
# ---------------------------------------------------------------------------


class TestDirectionIsolation:
    @pytest.mark.parametrize("decision", sorted(COMPENSATE_DECISIONS))
    def test_execute_direction_rejects_compensate_words(self, decision):
        with pytest.raises(ExecutionDirectionMismatch) as exc_info:
            validate_transition(None, decision, "execute")
        exc = exc_info.value
        assert exc.decision == decision
        assert exc.direction == "execute"

    @pytest.mark.parametrize("decision", sorted(EXECUTE_DECISIONS))
    def test_compensate_direction_rejects_execute_words(self, decision):
        with pytest.raises(ExecutionDirectionMismatch) as exc_info:
            validate_transition(None, decision, "compensate")
        assert exc_info.value.decision == decision

    @pytest.mark.parametrize("decision", sorted(COMPENSATE_DECISIONS))
    def test_mid_chain_execute_still_rejects_compensate_words(self, decision):
        with pytest.raises(ExecutionDirectionMismatch):
            validate_transition("dispatched", decision, "execute")

    def test_all_exceptions_typed_under_base(self):
        for fn in (
            lambda: validate_transition("succeeded", "failed", "execute"),
            lambda: validate_transition(None, "succeeded", "compensate"),
            lambda: validate_transition(None, "requested", "sideways"),
        ):
            with pytest.raises(ExecutionStateError):
                fn()


# ---------------------------------------------------------------------------
# Derived state — pure, deterministic, per-execution
# ---------------------------------------------------------------------------


class TestDeriveBasics:
    def test_empty_log_is_not_started(self):
        assert derive_execution_state([]) is None

    @pytest.mark.parametrize(
        "decisions,expected",
        [
            (("requested",), "requested"),
            (("requested", "guard_rejected"), "guard_rejected"),
            (("requested", "dispatched"), "dispatched"),
            (("requested", "dispatched", "succeeded"), "succeeded"),
            (("requested", "dispatched", "failed"), "failed"),
        ],
    )
    def test_execute_chain_states(self, decisions, expected):
        assert derive_execution_state(chain(*decisions)) == expected

    @pytest.mark.parametrize(
        "decisions,expected",
        [
            (("compensation_requested",), "compensation_requested"),
            (
                ("compensation_requested", "compensation_succeeded"),
                "compensation_succeeded",
            ),
            (
                ("compensation_requested", "compensation_failed"),
                "compensation_failed",
            ),
        ],
    )
    def test_compensate_chain_states(self, decisions, expected):
        assert (
            derive_execution_state(chain(*decisions, direction="compensate"))
            == expected
        )

    def test_input_order_does_not_matter(self):
        rows = chain("requested", "dispatched", "succeeded")
        assert derive_execution_state(list(reversed(rows))) == "succeeded"
        assert derive_execution_state([rows[2], rows[0], rows[1]]) == "succeeded"


class TestDeriveOrderingDeterminism:
    """Constraint 8: ORDER BY created_at DESC, id DESC — never list
    position, never id alone."""

    def test_latest_by_created_at_wins_regardless_of_id(self):
        small_id = uuid.UUID(int=1)
        big_id = uuid.UUID(int=2**127)
        late = row("failed", "execute", created_at=T0 + timedelta(seconds=2), row_id=small_id)
        early = row("dispatched", "execute", created_at=T0, row_id=big_id)
        assert derive_execution_state([early, late]) == "failed"

    def test_same_timestamp_resolved_by_id_desc(self):
        low = uuid.UUID(int=10)
        high = uuid.UUID(int=20)
        first = row("dispatched", "execute", created_at=T0, row_id=low)
        second = row("succeeded", "execute", created_at=T0, row_id=high)
        assert derive_execution_state([first, second]) == "succeeded"
        assert derive_execution_state([second, first]) == "succeeded"

    def test_same_timestamp_all_rows_deterministic_permutations(self):
        import itertools

        ids = [uuid.UUID(int=n) for n in (5, 9, 3)]
        decisions = ["requested", "dispatched", "failed"]
        rows = [
            row(decision, "execute", created_at=T0, row_id=row_id)
            for decision, row_id in zip(decisions, ids)
        ]
        # id 9 is the largest -> 'dispatched' wins, in every input order
        for perm in itertools.permutations(rows):
            assert derive_execution_state(list(perm)) == "dispatched"


class TestDeriveIsolationAndPurity:
    def test_two_executions_derive_independently(self):
        chain_a = chain("requested", "dispatched", "succeeded")
        chain_b = chain("requested", "guard_rejected")
        assert derive_execution_state(chain_a) == "succeeded"
        assert derive_execution_state(chain_b) == "guard_rejected"

    def test_derive_never_looks_beyond_given_rows(self):
        # A caller bug (mixing executions) must not silently leak state:
        # derive only ever answers for the rows it was handed.
        chain_a = chain("requested", "dispatched", "failed")
        assert derive_execution_state(chain_a[:1]) == "requested"
        assert derive_execution_state(chain_a[:2]) == "dispatched"

    def test_derive_is_pure_no_writes(self):
        # Structural proof: frozen stub rows carry no session; the
        # function cannot touch a DB. Repeated calls give identical
        # results and leave the input untouched.
        rows = chain("requested", "dispatched")
        snapshot = [(r.id, r.created_at, r.decision, r.direction) for r in rows]
        first = derive_execution_state(rows)
        second = derive_execution_state(rows)
        assert first == second == "dispatched"
        assert [(r.id, r.created_at, r.decision, r.direction) for r in rows] == snapshot

    def test_derive_works_on_orm_rows_too(self):
        # The Protocol is satisfied by real ExecutionLog instances as
        # well (attribute access only — still no DB round-trip).
        from app.models.execution_log import ExecutionLog

        orm_rows = [
            ExecutionLog(
                execution_id=uuid.uuid4(),
                approval_id=uuid.uuid4(),
                decision=decision,
                direction="execute",
                action="block_source_ip",
                target="203.0.113.50",
                operator="op",
                detail={},
                created_at=T0 + timedelta(seconds=i),
            )
            for i, decision in enumerate(("requested", "dispatched"))
        ]
        assert derive_execution_state(orm_rows) == "dispatched"
