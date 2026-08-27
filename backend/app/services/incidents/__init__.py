"""Incident management services (Phase 1 Step 7).

The SOC case layer on top of events: Alert -> AlertGroup -> EventRisk ->
Incident. EventRisk is the automatic assessment, the Incident is the
human-driven investigation/disposition context.
"""

from app.services.incidents.ai_context import get_incident_ai_context
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
from app.services.incidents.policy import AUTO_CREATE_THRESHOLD, should_create_incident
from app.services.incidents.service import (
    auto_create_from_risk,
    create_incident,
    get_incident,
    list_incidents,
    transition_status,
)

__all__ = [
    "ALLOWED_TRANSITIONS",
    "AUTO_CREATE_THRESHOLD",
    "IncidentAlreadyExists",
    "IncidentDisposition",
    "IncidentError",
    "IncidentNotFound",
    "IncidentRiskMissing",
    "IncidentStatus",
    "InvalidIncidentTransition",
    "auto_create_from_risk",
    "create_incident",
    "get_incident",
    "get_incident_ai_context",
    "list_incidents",
    "should_create_incident",
    "transition_status",
]
