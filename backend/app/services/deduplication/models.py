"""Result types returned by the deduplication engine."""
from dataclasses import dataclass

from app.models import Alert, AlertGroup


@dataclass
class DeduplicationResult:
    """Outcome of processing one normalized alert."""

    group: AlertGroup
    alert: Alert
    #: True when a brand new AlertGroup had to be created for this event
    created_group: bool
