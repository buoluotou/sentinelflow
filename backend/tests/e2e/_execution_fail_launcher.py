"""Test-only uvicorn target for the 3.1.11 browser E2E (adapter-failure
injection, user checklist item ③).

The production app deliberately exposes NO fault-injection surface:
EXECUTION_ADAPTER only supports ``mock`` (registry.py) and MockExecutor's
``fail_with`` knob is test-only. This module therefore swaps the executor
through the documented 3.1.7 test seam — ``get_response_executor`` exists
precisely so tests can override that dependency ("Tests override this
dependency to drive failure paths") — without touching production code.

Which classification fails is decided per boot via the environment:

    E2E_FAIL_WITH=timeout|adapter_unavailable|adapter_error

The value is validated by MockExecutor itself (protocol_violation is
refused — platform-judged only, D9), so a typo fails loudly at first
request instead of faking success.

3.3.4 addition — ``protocol_violation`` cannot be a MockExecutor knob
(D9), so it is injected the ONLY legal way: an executor that answers
the forbidden word `dispatched`, which the PLATFORM parse judges as
protocol_violation. Its name stays "mock" (same registry identity), so
the violation lands in the mock adapter's own health bucket.
"""
import os

from app.api.v1.response_execution import get_response_executor
from app.main import app
from app.services.executions.base import ResponseExecutor
from app.services.executions.mock import MockExecutor
from app.services.executions.models import ExecutionDispatch, ExecutionOutcome

_FAIL_WITH = os.environ.get("E2E_FAIL_WITH")


class _ProtocolViolatingMockExecutor(ResponseExecutor):
    """Test-only executor (3.3.4 journey ⑤): answers the forbidden word
    `dispatched` (D8) — the platform parse judges protocol_violation.
    name stays "mock" so the chain is attributed to the mock adapter."""

    @property
    def name(self) -> str:
        return "mock"

    def supports(self, action: str) -> bool:
        return True

    def supports_compensation(self, action: str) -> bool:
        return True

    def execute(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        return {"status": "dispatched"}  # type: ignore[return-value]

    def compensate(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        return {"status": "dispatched"}  # type: ignore[return-value]


def _failing_executor() -> ResponseExecutor:
    if _FAIL_WITH == "protocol_violation":
        return _ProtocolViolatingMockExecutor()
    return MockExecutor(fail_with=_FAIL_WITH)


app.dependency_overrides[get_response_executor] = _failing_executor
