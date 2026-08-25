"""Service-layer vocabulary of the incident lifecycle (Phase 1 Step 7.2).

Plain enums + the frozen transition matrix — ORM strings never scatter
through business code. The Incident model only stores the current status;
the state machine lives here and is enforced by ``service.py``.
"""
from enum import Enum


class IncidentStatus(str, Enum):
    """Lifecycle position of an incident."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class IncidentDisposition(str, Enum):
    """Analyst's call on the case; always kept consistent with the status
    (a transition is the only way to set it — never independently)."""

    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


#: Frozen transition matrix (Phase 1 Step 7). CLOSED is terminal — reopening
#: (closed -> open) is intentionally NOT allowed in v1.0.
ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset(
        {IncidentStatus.IN_PROGRESS, IncidentStatus.FALSE_POSITIVE, IncidentStatus.CLOSED}
    ),
    IncidentStatus.IN_PROGRESS: frozenset(
        {IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE, IncidentStatus.CLOSED}
    ),
    IncidentStatus.RESOLVED: frozenset({IncidentStatus.CLOSED}),
    IncidentStatus.FALSE_POSITIVE: frozenset({IncidentStatus.CLOSED}),
    IncidentStatus.CLOSED: frozenset(),
}


class IncidentError(Exception):
    """Base class of all incident business errors (never silent failures)."""


class IncidentNotFound(IncidentError):
    """No AlertGroup / Incident exists for the given id."""


class IncidentAlreadyExists(IncidentError):
    """The event already has a current incident (unique alert_group_id)."""


class IncidentRiskMissing(IncidentError):
    """The event has no EventRisk snapshot — creating a score=0 case would
    hide a risk-pipeline problem, so creation is refused."""


class InvalidIncidentTransition(IncidentError):
    """The requested status change violates the lifecycle matrix."""
