"""Outcome services.

The External Outcome Fact layer beside the dispatch log: where
``execution_log`` records what the platform dispatched (Dispatch Fact),
``execution_outcome`` records what the external world later did (External
Outcome Fact) — two independent layers that never rewrite each other.

The append-only fact model lives in migration 0010.
``derive_outcome_state`` / ``latest_observation`` derive the current outcome
state from those facts — observations in, derived state out, no side effects.
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
