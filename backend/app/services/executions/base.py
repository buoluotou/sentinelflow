"""ResponseExecutor abstract contract (Phase 3.1.5, design §8).

Replicates the AIProvider lineage: business code only ever sees this
contract; swapping adapters never touches Guard / state machine /
Service. Layering promise kept from 3.1.4: the Guard depends only on
the structural ``ExecutorCapability`` protocol — every ResponseExecutor
satisfies it structurally, but the dependency arrow never reverses.

``dispatched`` is NOT part of this contract (D8): it is a platform log
state the Execution Service writes; adapters only ever answer
succeeded / failed via ExecutionOutcome.
"""
from abc import ABC, abstractmethod

from app.services.executions.models import ExecutionDispatch, ExecutionOutcome


class ResponseExecutor(ABC):
    """One response-execution adapter (Mock today; Shuffle / Wazuh /
    TheHive reserved for Phase 3.2 — their registry values exist but
    raise ConfigError until implemented)."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Adapter identity — never impersonated (mock is always "mock")."""

    @abstractmethod
    def supports(self, action: str) -> bool:
        """Whether this adapter can execute the action — the SOLE basis
        for Guard G4."""

    @abstractmethod
    def supports_compensation(self, action: str) -> bool:
        """Whether this adapter can compensate (undo) the action — the
        basis for the compensation pre-check."""

    @abstractmethod
    def execute(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        """Perform the action. Returns an ExecutionOutcome — adapters
        never return `dispatched` and never self-declare
        protocol_violation (D9)."""

    @abstractmethod
    def compensate(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        """Perform the compensating (undo) operation for the dispatch's
        action. Same outcome contract as execute()."""
