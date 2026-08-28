"""Phase 3.1.4: Execution Guard / Policy tests (G2 / G3 / G4).

Hard requirements this suite nails down:
- G2 approval binding: approved-only, snapshot provenance, D3 vocabulary
- G3 lifecycle/idempotency pre-check through the frozen derived-state
  rule of 3.1.3 (409 family, NO log row semantics)
- G4 capability via the minimal ExecutorCapability protocol ONLY — no
  Mock executor exists yet (that is 3.1.5), tests use a tiny stub
- Security attack: a client-tampered action is refused even when it
  looks executable — action is a server-side snapshot fact

All tests are DB-free: guards are pure verdict functions; ORM objects
are constructed without a session.
"""
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from app.models.ai_response_approval import AIResponseApproval
from app.models.ai_response_recommendation import AIResponseRecommendation
from app.services.ai.models import RESPONSE_ACTIONS
from app.services.executions.guard import (
    EXECUTABLE_ACTIONS,
    GUARD_REJECTION_CODES,
    ApprovalAlreadyExecuted,
    ApprovalNotFound,
    ExecutionGuardError,
    ExecutionIdAlreadyBound,
    GuardRejection,
    check_approval_binding,
    check_executor_capability,
    check_lifecycle,
)
from app.services.executions.state import ExecutionDirectionMismatch

T0 = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
ADVISORY_ONLY = RESPONSE_ACTIONS - EXECUTABLE_ACTIONS


def make_approval(status="approved"):
    return AIResponseApproval(
        id=uuid.uuid4(),
        recommendation_id=uuid.uuid4(),
        status=status,
        reviewer="reviewer-test",
        reviewed_at=T0,
    )


def make_recommendation(actions):
    return AIResponseRecommendation(
        id=uuid.uuid4(),
        alert_group_id=uuid.uuid4(),
        provider="mock",
        model="mock-deterministic",
        overall_rationale="test rationale",
        recommendations=[
            {"action": action, "target": "203.0.113.50", "rationale": "r"}
            for action in actions
        ],
        confidence=0.9,
    )


@dataclass
class StubRow:
    id: uuid.UUID
    created_at: datetime
    decision: str
    direction: str


def row(decision, direction, *, created_at=None):
    return StubRow(uuid.uuid4(), created_at or T0, decision, direction)


def forward_chain(*decisions):
    return [
        row(decision, "execute", created_at=T0 + timedelta(seconds=i))
        for i, decision in enumerate(decisions)
    ]


class StubExecutor:
    """Minimal test double satisfying ExecutorCapability — NOT the 3.1.5
    Mock adapter. Records calls so tests can prove the Guard uses only
    the protocol surface."""

    name = "stub-capability"

    def __init__(self, supports=True, supports_compensation=True):
        self._supports = supports
        self._supports_compensation = supports_compensation
        self.calls = []

    def supports(self, action):
        self.calls.append(("supports", action))
        return self._supports

    def supports_compensation(self, action):
        self.calls.append(("supports_compensation", action))
        return self._supports_compensation


def expect_rejection(fn, expected_code):
    with pytest.raises(GuardRejection) as exc_info:
        fn()
    exc = exc_info.value
    assert exc.code == expected_code
    assert exc.reason
    return exc


# ---------------------------------------------------------------------------
# Vocabulary freeze
# ---------------------------------------------------------------------------


class TestVocabularyFreeze:
    def test_executable_actions_exact_d3_vocabulary(self):
        assert EXECUTABLE_ACTIONS == frozenset(
            {"block_source_ip", "isolate_host", "disable_account"}
        )

    def test_executable_is_strict_subset_of_phase2_vocabulary(self):
        assert EXECUTABLE_ACTIONS < RESPONSE_ACTIONS

    def test_advisory_only_words_are_exactly_the_other_three(self):
        assert ADVISORY_ONLY == frozenset(
            {"escalate_to_incident", "hunt_related_activity", "monitor_only"}
        )

    def test_rejection_codes_frozen(self):
        assert GUARD_REJECTION_CODES == frozenset(
            {
                "approval_not_approved",
                "recommendation_missing",
                "action_not_in_snapshot",
                "action_not_executable",
                "executor_unsupported",
            }
        )


# ---------------------------------------------------------------------------
# G2: approval binding
# ---------------------------------------------------------------------------


class TestG2ApprovalBinding:
    @pytest.mark.parametrize("action", sorted(EXECUTABLE_ACTIONS))
    def test_approved_with_snapshot_action_passes(self, action):
        approval = make_approval("approved")
        recommendation = make_recommendation([action])
        assert check_approval_binding(approval, recommendation, action) is None

    def test_rejected_approval_refused(self):
        exc = expect_rejection(
            lambda: check_approval_binding(
                make_approval("rejected"),
                make_recommendation(["block_source_ip"]),
                "block_source_ip",
            ),
            "approval_not_approved",
        )
        assert "rejected" in exc.reason

    def test_pending_status_refused(self):
        # "pending" never persists (Step 13 CHECK) — but the Guard must
        # refuse ANY non-approved word, never improvise.
        expect_rejection(
            lambda: check_approval_binding(
                make_approval("pending"),
                make_recommendation(["block_source_ip"]),
                "block_source_ip",
            ),
            "approval_not_approved",
        )

    def test_missing_approval_is_404_family_not_rejection(self):
        with pytest.raises(ApprovalNotFound):
            check_approval_binding(
                None, make_recommendation(["block_source_ip"]), "block_source_ip"
            )

    def test_missing_recommendation_refused(self):
        expect_rejection(
            lambda: check_approval_binding(
                make_approval("approved"), None, "block_source_ip"
            ),
            "recommendation_missing",
        )

    @pytest.mark.parametrize("action", sorted(ADVISORY_ONLY))
    def test_advisory_actions_never_executable(self, action):
        approval = make_approval("approved")
        recommendation = make_recommendation([action])
        expect_rejection(
            lambda: check_approval_binding(approval, recommendation, action),
            "action_not_executable",
        )

    def test_unknown_action_refused(self):
        approval = make_approval("approved")
        recommendation = make_recommendation(["block_source_ip"])
        expect_rejection(
            lambda: check_approval_binding(approval, recommendation, "rm_everything"),
            "action_not_in_snapshot",
        )

    def test_empty_snapshot_refuses_everything(self):
        approval = make_approval("approved")
        recommendation = make_recommendation([])
        expect_rejection(
            lambda: check_approval_binding(
                approval, recommendation, "block_source_ip"
            ),
            "action_not_in_snapshot",
        )

    def test_rejection_carries_code_and_reason(self):
        exc = expect_rejection(
            lambda: check_approval_binding(
                make_approval("rejected"),
                make_recommendation(["block_source_ip"]),
                "block_source_ip",
            ),
            "approval_not_approved",
        )
        assert isinstance(exc, ExecutionGuardError)
        assert exc.code in GUARD_REJECTION_CODES
        assert "only approved" in exc.reason


class TestG2FactSmugglingAttack:
    """The client tries to steer the action. action/target are
    SERVER-SIDE snapshot facts — provenance is checked BEFORE the
    executability vocabulary."""

    def test_tampered_action_refused_despite_approved_approval(self):
        approval = make_approval("approved")
        # snapshot only ever suggested block_source_ip...
        recommendation = make_recommendation(["block_source_ip"])
        # ...the "client" now presents isolate_host (executable-looking!)
        expect_rejection(
            lambda: check_approval_binding(approval, recommendation, "isolate_host"),
            "action_not_in_snapshot",
        )

    def test_advisory_word_from_snapshot_still_not_executable(self):
        approval = make_approval("approved")
        recommendation = make_recommendation(["escalate_to_incident"])
        expect_rejection(
            lambda: check_approval_binding(
                approval, recommendation, "escalate_to_incident"
            ),
            "action_not_executable",
        )

    def test_arbitrary_string_never_passes(self):
        approval = make_approval("approved")
        recommendation = make_recommendation(["block_source_ip"])
        for forged in ("", "block_source_ip;reboot", "BLOCK_SOURCE_IP"):
            expect_rejection(
                lambda f=forged: check_approval_binding(
                    approval, recommendation, f
                ),
                "action_not_in_snapshot",
            )


# ---------------------------------------------------------------------------
# G3: lifecycle / idempotency (through the 3.1.3 derived-state rule)
# ---------------------------------------------------------------------------


class TestG3Lifecycle:
    def test_first_execution_allowed(self):
        assert check_lifecycle([], []) is None

    @pytest.mark.parametrize(
        "chain,expected_state",
        [
            (("requested",), "requested"),
            (("requested", "guard_rejected"), "guard_rejected"),
            (("requested", "dispatched"), "dispatched"),
            (("requested", "dispatched", "succeeded"), "succeeded"),
            (("requested", "dispatched", "failed"), "failed"),
        ],
    )
    def test_any_forward_execution_blocks_re_execution(self, chain, expected_state):
        # including after terminal failed: no retry, only compensation
        with pytest.raises(ApprovalAlreadyExecuted) as exc_info:
            check_lifecycle(forward_chain(*chain), [])
        assert exc_info.value.derived_state == expected_state

    def test_compensation_rows_alone_do_not_occupy_forward_slot(self):
        comp_rows = [
            row("compensation_requested", "compensate", created_at=T0),
            row("compensation_succeeded", "compensate", created_at=T0 + timedelta(seconds=1)),
        ]
        assert check_lifecycle(comp_rows, []) is None

    def test_mixed_approval_rows_use_execute_direction_only(self):
        rows = forward_chain("requested", "dispatched", "failed") + [
            row("compensation_requested", "compensate", created_at=T0 + timedelta(seconds=5))
        ]
        with pytest.raises(ApprovalAlreadyExecuted) as exc_info:
            check_lifecycle(rows, [])
        assert exc_info.value.derived_state == "failed"

    def test_input_order_does_not_matter(self):
        rows = list(reversed(forward_chain("requested", "dispatched", "succeeded")))
        with pytest.raises(ApprovalAlreadyExecuted) as exc_info:
            check_lifecycle(rows, [])
        assert exc_info.value.derived_state == "succeeded"


class TestG3Idempotency:
    @pytest.mark.parametrize("occupying_decision", ["requested", "dispatched", "failed"])
    def test_bound_execution_id_refused(self, occupying_decision):
        with pytest.raises(ExecutionIdAlreadyBound):
            check_lifecycle([], [row(occupying_decision, "execute")])

    def test_compensation_occupancy_also_refused(self):
        with pytest.raises(ExecutionIdAlreadyBound):
            check_lifecycle([], [row("compensation_requested", "compensate")])

    def test_conflicts_are_not_business_rejections(self):
        # 409 family never produces a guard_rejected audit row: the types
        # are separate by design (3.1.6 maps families differently).
        with pytest.raises(ExecutionGuardError) as exc_info:
            check_lifecycle(forward_chain("requested"), [])
        assert not isinstance(exc_info.value, GuardRejection)
        with pytest.raises(ExecutionGuardError) as exc_info:
            check_lifecycle([], [row("requested", "execute")])
        assert not isinstance(exc_info.value, GuardRejection)


# ---------------------------------------------------------------------------
# G4: executor capability (protocol surface ONLY)
# ---------------------------------------------------------------------------


class TestG4Capability:
    def test_supported_execute_passes(self):
        executor = StubExecutor(supports=True)
        assert check_executor_capability(executor, "block_source_ip", "execute") is None
        assert executor.calls == [("supports", "block_source_ip")]

    def test_unsupported_execute_rejected(self):
        exc = expect_rejection(
            lambda: check_executor_capability(
                StubExecutor(supports=False), "block_source_ip", "execute"
            ),
            "executor_unsupported",
        )
        assert "block_source_ip" in exc.reason

    def test_supported_compensation_passes(self):
        executor = StubExecutor(supports_compensation=True)
        assert (
            check_executor_capability(executor, "block_source_ip", "compensate")
            is None
        )
        assert executor.calls == [("supports_compensation", "block_source_ip")]

    def test_unsupported_compensation_rejected(self):
        exc = expect_rejection(
            lambda: check_executor_capability(
                StubExecutor(supports_compensation=False),
                "block_source_ip",
                "compensate",
            ),
            "executor_unsupported",
        )
        assert "compensation" in exc.reason

    def test_unknown_direction_refused(self):
        with pytest.raises(ExecutionDirectionMismatch):
            check_executor_capability(StubExecutor(), "block_source_ip", "sideways")

    def test_guard_only_uses_protocol_surface(self):
        # No execute()/compensate() exists on the stub — the Guard must
        # never reach beyond supports / supports_compensation in 3.1.4.
        executor = StubExecutor()
        check_executor_capability(executor, "isolate_host", "execute")
        check_executor_capability(executor, "isolate_host", "compensate")
        assert [name for name, _ in executor.calls] == [
            "supports",
            "supports_compensation",
        ]


# ---------------------------------------------------------------------------
# Exception family shape
# ---------------------------------------------------------------------------


class TestExceptionFamily:
    def test_all_guard_verdicts_typed_under_base(self):
        for fn in (
            lambda: check_approval_binding(None, None, "x"),
            lambda: check_approval_binding(
                make_approval("rejected"),
                make_recommendation(["block_source_ip"]),
                "block_source_ip",
            ),
            lambda: check_lifecycle(forward_chain("requested"), []),
            lambda: check_lifecycle([], [row("requested", "execute")]),
            lambda: check_executor_capability(
                StubExecutor(supports=False), "block_source_ip", "execute"
            ),
        ):
            with pytest.raises(ExecutionGuardError):
                fn()

    def test_not_found_is_not_conflict_is_not_rejection(self):
        # Three disjoint families => three distinct HTTP behaviours later:
        # 404 (no row) / 409 (no row) / 201+guard_rejected (audit row).
        assert not issubclass(ApprovalNotFound, (ApprovalAlreadyExecuted, GuardRejection))
        assert not issubclass(ApprovalAlreadyExecuted, GuardRejection)
        assert not issubclass(ExecutionIdAlreadyBound, GuardRejection)
