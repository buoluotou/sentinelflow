"""Response execution services (Phase 3.1).

The controlled-execution layer on top of approved recommendations:
Approval -> Execute Intent -> Guard -> execution_log -> Executor.
3.1.3 delivered the state semantics, 3.1.4 the Guard / Policy verdicts,
3.1.5 the executor contract + Mock/DryRun adapter + registry, 3.1.6 the
Execute / Compensation Service that wires them into complete chains.
No API here yet.
"""

from app.services.executions.base import ResponseExecutor
from app.services.executions.exceptions import (
    ExecutorConfigError,
    ExecutorError,
    ExecutorOutcomeViolation,
)
from app.services.executions.guard import (
    EXECUTABLE_ACTIONS,
    GUARD_REJECTION_CODES,
    ApprovalAlreadyExecuted,
    ApprovalNotFound,
    ExecutionGuardError,
    ExecutionIdAlreadyBound,
    ExecutorCapability,
    GuardRejection,
    check_approval_binding,
    check_executor_capability,
    check_lifecycle,
)
from app.services.executions.mock import FAIL_WITH_CHOICES, MockExecutor
from app.services.executions.models import (
    ADAPTER_CLASSIFICATIONS,
    FAILURE_CLASSIFICATIONS,
    OUTCOME_STATUSES,
    ExecutionDispatch,
    ExecutionOutcome,
)
from app.services.executions.protocol import parse_execution_outcome
from app.services.executions.registry import (
    ADAPTER_NAMES,
    RESERVED_ADAPTER_NAMES,
    create_executor,
)
from app.services.executions.service import (
    COMPENSATABLE_STATES,
    ApprovalAlreadyExecuted,
    CompensationOfCompensation,
    ExecutionAlreadyCompensated,
    ExecutionConflictError,
    ExecutionIdAlreadyBound,
    ExecutionNotFound,
    ExecutionResult,
    ExecutionServiceError,
    OriginalExecutionNotTerminal,
    compensate_response,
    execute_response,
)
from app.services.executions.state import (
    ALLOWED_TRANSITIONS,
    DIRECTION_VOCABULARY,
    FIRST_ROW_BY_DIRECTION,
    TERMINAL_DECISIONS,
    ExecutionDirectionMismatch,
    ExecutionLogRow,
    ExecutionStateError,
    InvalidExecutionTransition,
    derive_execution_state,
    is_terminal_state,
    validate_transition,
)

__all__ = [
    "ADAPTER_CLASSIFICATIONS",
    "ADAPTER_NAMES",
    "ALLOWED_TRANSITIONS",
    "COMPENSATABLE_STATES",
    "DIRECTION_VOCABULARY",
    "EXECUTABLE_ACTIONS",
    "FAILURE_CLASSIFICATIONS",
    "FAIL_WITH_CHOICES",
    "FIRST_ROW_BY_DIRECTION",
    "GUARD_REJECTION_CODES",
    "OUTCOME_STATUSES",
    "RESERVED_ADAPTER_NAMES",
    "TERMINAL_DECISIONS",
    "ApprovalAlreadyExecuted",
    "ApprovalNotFound",
    "CompensationOfCompensation",
    "ExecutionAlreadyCompensated",
    "ExecutionConflictError",
    "ExecutionDirectionMismatch",
    "ExecutionDispatch",
    "ExecutionGuardError",
    "ExecutionIdAlreadyBound",
    "ExecutionLogRow",
    "ExecutionNotFound",
    "ExecutionOutcome",
    "ExecutionResult",
    "ExecutionServiceError",
    "ExecutionStateError",
    "ExecutorCapability",
    "ExecutorConfigError",
    "ExecutorError",
    "ExecutorOutcomeViolation",
    "GuardRejection",
    "InvalidExecutionTransition",
    "MockExecutor",
    "OriginalExecutionNotTerminal",
    "ResponseExecutor",
    "check_approval_binding",
    "check_executor_capability",
    "check_lifecycle",
    "compensate_response",
    "create_executor",
    "derive_execution_state",
    "execute_response",
    "is_terminal_state",
    "parse_execution_outcome",
    "validate_transition",
]
