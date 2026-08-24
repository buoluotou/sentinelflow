"""Aggregation rules for the deduplication engine.

Phase 1 Step 4.3: alerts sharing the same fingerprint are aggregated into
one AlertGroup as long as they arrive within the aggregation window.
The window length is configurable via DEDUP_WINDOW_SECONDS (.env).
"""
from dataclasses import dataclass

from app.core.config import settings

#: default aggregation window: 5 minutes
DEFAULT_WINDOW_SECONDS = settings.DEDUP_WINDOW_SECONDS


@dataclass(frozen=True)
class AggregationRule:
    """Decides whether an event still belongs to an existing group."""

    window_seconds: int = DEFAULT_WINDOW_SECONDS

    def is_within_window(self, elapsed_seconds: float) -> bool:
        """True if the event arrived within the aggregation window."""
        return elapsed_seconds <= self.window_seconds


#: rule shared by the deduplication engine
DEFAULT_RULE = AggregationRule()
