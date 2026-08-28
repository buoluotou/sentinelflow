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
"""
import os

from app.api.v1.response_execution import get_response_executor
from app.main import app
from app.services.executions.mock import MockExecutor

_FAIL_WITH = os.environ.get("E2E_FAIL_WITH")


def _failing_executor() -> MockExecutor:
    return MockExecutor(fail_with=_FAIL_WITH)


app.dependency_overrides[get_response_executor] = _failing_executor
