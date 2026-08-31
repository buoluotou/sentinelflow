"""Mock executor — the only Phase 3.1 adapter, doubles as DryRun
(Phase 3.1.5, design §8).

Frozen behaviour:
- ZERO outbound traffic, zero real side-effects (no urllib/socket/http
  import anywhere in this module).
- Deterministic: identical dispatch -> identical outcome, byte for byte.
- ``name`` is always "mock" — never impersonates a real adapter.
- ``detail`` echoes exactly what a real execution would do (action /
  target / parameters), so the audit log answers "what WOULD have
  happened" (DryRun).
- ``fail_with`` (tests only) injects the three ADAPTER failure
  classifications: adapter_unavailable / timeout / adapter_error.
  protocol_violation is NOT injectable here — that word is reserved to
  the platform parse (D9).
"""
from app.services.executions.base import ResponseExecutor
from app.services.executions.guard import (
    EXECUTABLE_ACTIONS,
    NON_COMPENSATABLE_ACTIONS,
)
from app.services.executions.models import (
    ADAPTER_CLASSIFICATIONS,
    ExecutionDispatch,
    ExecutionOutcome,
)

#: Injectable failure classifications (test-only). protocol_violation is
#: deliberately NOT here (D9 — platform-judged only).
FAIL_WITH_CHOICES = ADAPTER_CLASSIFICATIONS


class MockExecutor(ResponseExecutor):
    """Deterministic offline executor. Constructor argument ``fail_with``
    forces every execute()/compensate() call to return a failed outcome
    classified with that word; None (default) behaves normally."""

    def __init__(self, fail_with: str | None = None):
        if fail_with is not None and fail_with not in FAIL_WITH_CHOICES:
            raise ValueError(
                f"fail_with must be one of {sorted(FAIL_WITH_CHOICES)} or "
                f"None (protocol_violation is platform-judged only, D9); "
                f"got '{fail_with}'"
            )
        self._fail_with = fail_with

    @property
    def name(self) -> str:
        return "mock"

    def supports(self, action: str) -> bool:
        return action in EXECUTABLE_ACTIONS

    def supports_compensation(self, action: str) -> bool:
        # The mock simulates the inverse operation of every executable
        # action EXCEPT the non-compensable ones (E1 policy): escalating
        # to a case has no machine reversal — the case lifecycle belongs
        # to human investigation and is never auto-closed.
        return (
            action in EXECUTABLE_ACTIONS
            and action not in NON_COMPENSATABLE_ACTIONS
        )

    def execute(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        if not self.supports(dispatch.action):
            raise ValueError(
                f"mock executor does not support action '{dispatch.action}'"
            )
        echo = self._dry_run_echo(dispatch, "execute")
        if self._fail_with is not None:
            return ExecutionOutcome(
                status="failed",
                detail={"classification": self._fail_with, "dry_run": echo},
                raw_response=None,
            )
        return ExecutionOutcome(
            status="succeeded",
            detail={"dry_run": echo},
            raw_response={"mock": "ok", "operation": "execute"},
        )

    def compensate(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        if not self.supports_compensation(dispatch.action):
            raise ValueError(
                f"mock executor cannot compensate action '{dispatch.action}'"
            )
        echo = self._dry_run_echo(dispatch, "compensate")
        if self._fail_with is not None:
            return ExecutionOutcome(
                status="failed",
                detail={"classification": self._fail_with, "dry_run": echo},
                raw_response=None,
            )
        return ExecutionOutcome(
            status="succeeded",
            detail={"dry_run": echo},
            raw_response={"mock": "ok", "operation": "compensate"},
        )

    @staticmethod
    def _dry_run_echo(dispatch: ExecutionDispatch, operation: str) -> dict:
        """Deterministic DryRun record — answers 'what would a real
        execution do'. No timestamps, no randomness."""
        return {
            "executor": "mock",
            "operation": operation,
            "action": dispatch.action,
            "target": dispatch.target,
            "execution_id": str(dispatch.execution_id),
            "approval_id": str(dispatch.approval_id),
        }
