"""Outcome services (Phase 3.4).

The External Outcome Fact layer beside the dispatch log: where
``execution_log`` records what the platform dispatched (Dispatch Fact),
``execution_outcome`` records what the external world later did (External
Outcome Fact) — two independent layers that never rewrite each other
(D3.4-04 / O5).

3.4.1 delivered the append-only fact model + migration 0010; 3.4.2 adds
the PURE derivation of the current outcome state from those facts
(``derive_outcome_state`` / ``latest_observation``) — observations in,
derived state out, no side effects. No webhook, no callback, no API, no
manual reconcile here yet: those are later steps and stay closed until
this one is accepted.
"""

from app.services.outcomes.derivation import (
    UNKNOWN_OUTCOME,
    ForeignOutcomeVocabulary,
    OutcomeDerivationError,
    OutcomeObservation,
    derive_outcome_state,
    latest_observation,
)

__all__ = [
    "UNKNOWN_OUTCOME",
    "ForeignOutcomeVocabulary",
    "OutcomeDerivationError",
    "OutcomeObservation",
    "derive_outcome_state",
    "latest_observation",
]
