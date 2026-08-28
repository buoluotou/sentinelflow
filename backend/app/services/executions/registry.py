"""Executor registry: settings -> configured ResponseExecutor
(Phase 3.1.5, mirrors the AI provider registry lineage).

Business code calls create_executor(settings) and only ever sees the
ResponseExecutor contract — which adapter runs is a deployment decision
living in .env:

    EXECUTION_ADAPTER=mock          (default; offline DryRun)

shuffle / wazuh / thehive are RESERVED registry values: configuring one
raises ExecutorConfigError right now — Phase 3.2 implements them, the
registry refuses to fake support in the meantime.
"""
from app.core.config import Settings
from app.services.executions.base import ResponseExecutor
from app.services.executions.exceptions import ExecutorConfigError
from app.services.executions.mock import MockExecutor

#: The only implemented adapter today.
ADAPTER_NAMES = ("mock",)

#: Phase 3.2 reservation — known names, deliberately unimplemented.
RESERVED_ADAPTER_NAMES = ("shuffle", "wazuh", "thehive")


def create_executor(settings: Settings) -> ResponseExecutor:
    name = settings.EXECUTION_ADAPTER.strip().lower()
    if name == "mock":
        return MockExecutor()
    if name in RESERVED_ADAPTER_NAMES:
        raise ExecutorConfigError(
            f"EXECUTION_ADAPTER '{settings.EXECUTION_ADAPTER}' is reserved "
            f"for Phase 3.2 and not implemented yet (only "
            f"{', '.join(ADAPTER_NAMES)} is available)"
        )
    raise ExecutorConfigError(
        f"Unknown EXECUTION_ADAPTER '{settings.EXECUTION_ADAPTER}' "
        f"(expected one of {', '.join(ADAPTER_NAMES + RESERVED_ADAPTER_NAMES)})"
    )
