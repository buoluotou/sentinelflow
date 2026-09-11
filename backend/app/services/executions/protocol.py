"""Platform-side outcome parse.

``protocol_violation`` is judged here and only here — adapters have no
right to self-declare it. The Execute Service feeds every adapter result
through this parse before writing the terminal log row:

bad adapter result  ->  ExecutorOutcomeViolation
->  failed row, classification=protocol_violation
->  never a fake success
"""
from typing import Any

from pydantic import ValidationError

from app.services.executions.exceptions import ExecutorOutcomeViolation
from app.services.executions.models import (
    FAILURE_CLASSIFICATIONS,
    ExecutionOutcome,
)


def parse_execution_outcome(raw: Any) -> ExecutionOutcome:
    """Validate one adapter result into a trusted ExecutionOutcome.

Accepts an ExecutionOutcome instance (re-checked) or a raw mapping;
anything else is a violation. Enforced rules:
- exact field set, extra fields forbidden (pydantic extra=forbid);
- status restricted to {succeeded, failed} — a `dispatched` answer
is impossible by construction and rejected here for raw dicts;
- detail.classification, when present, must be a known failure
classification and must not be protocol_violation, which only the
platform may assign.
"""
    if isinstance(raw, ExecutionOutcome):
        outcome = raw
    elif isinstance(raw, dict):
        try:
            outcome = ExecutionOutcome.model_validate(raw)
        except ValidationError as exc:
            raise ExecutorOutcomeViolation(
                f"Adapter returned a structurally invalid outcome: {exc}"
            ) from exc
    else:
        raise ExecutorOutcomeViolation(
            f"Adapter returned a non-outcome value of type {type(raw).__name__}"
        )
    classification = outcome.detail.get("classification")
    if classification is not None:
        if classification == "protocol_violation":
            raise ExecutorOutcomeViolation(
                "Adapter self-declared protocol_violation; only the "
                "platform parse may judge it (D9)"
            )
        if classification not in FAILURE_CLASSIFICATIONS:
            raise ExecutorOutcomeViolation(
                f"Adapter used unknown failure classification "
                f"'{classification}'"
            )
    return outcome
