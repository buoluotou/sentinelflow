"""Deduplication & aggregation services (Phase 1 Step 4)."""

from app.services.deduplication.engine import DeduplicationEngine, engine
from app.services.deduplication.fingerprint import FingerprintGenerator
from app.services.deduplication.models import DeduplicationResult
from app.services.deduplication.rules import (
    DEFAULT_RULE,
    DEFAULT_WINDOW_SECONDS,
    AggregationRule,
)

__all__ = [
    "AggregationRule",
    "DEFAULT_RULE",
    "DEFAULT_WINDOW_SECONDS",
    "DeduplicationEngine",
    "DeduplicationResult",
    "FingerprintGenerator",
    "engine",
]
