"""ResponseExecutor abstract contract.

Business code only ever sees this contract, so swapping adapters never
touches Guard / state machine / Service. The Guard depends only on the
structural ``ExecutorCapability`` protocol — every ResponseExecutor
satisfies it structurally, but the dependency arrow never reverses.

``dispatched`` is NOT part of this contract: it is a platform log state
the Execution Service writes; adapters only ever answer succeeded /
failed via ExecutionOutcome.
"""
from abc import ABC, abstractmethod

from app.services.executions.models import ExecutionDispatch, ExecutionOutcome


class ResponseExecutor(ABC):
    """One response-execution adapter (Mock today; the Shuffle / Wazuh /
TheHive names are reserved — their registry values exist but raise
ConfigError until implemented)."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Adapter identity — never impersonated (mock is always "mock")."""

    @abstractmethod
    def supports(self, action: str) -> bool:
        """Whether this adapter can execute the action — the sole basis
for the Guard's capability check."""

    @abstractmethod
    def supports_compensation(self, action: str) -> bool:
        """Whether this adapter can compensate (undo) the action — the
basis for the compensation pre-check."""

    @abstractmethod
    def execute(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        """Perform the action. Returns an ExecutionOutcome — adapters
never return `dispatched` and never self-declare
protocol_violation."""

    @abstractmethod
    def compensate(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        """Perform the compensating (undo) operation for the dispatch's
action. Same outcome contract as execute()."""
