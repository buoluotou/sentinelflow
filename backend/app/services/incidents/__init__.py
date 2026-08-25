"""Incident management services (Phase 1 Step 7).

The SOC case layer on top of events: Alert -> AlertGroup -> EventRisk ->
Incident. EventRisk is the automatic assessment, the Incident is the
human-driven investigation/disposition context.
"""

from app.services.incidents.models import (
    ALLOWED_TRANSITIONS,
    IncidentAlreadyExists,
    IncidentDisposition,
    IncidentError,
    IncidentNotFound,
    IncidentRiskMissing,
    IncidentStatus,
    InvalidIncidentTransition,
)
from app.services.incidents.service import (
    create_incident,
    get_incident,
    list_incidents,
    transition_status,
)

__all__ = [
    "ALLOWED_TRANSITIONS",
    "IncidentAlreadyExists",
    "IncidentDisposition",
    "IncidentError",
    "IncidentNotFound",
    "IncidentRiskMissing",
    "IncidentStatus",
    "InvalidIncidentTransition",
    "create_incident",
    "get_incident",
    "list_incidents",
    "transition_status",
]
