"""Incident AI context service: read-only aggregation (Phase 2 Step 14.2).

Composes the incident-centric AI case view from the Step 14.1 viewonly
traversals. This is a pure READ service:

- consumes ``incident.ai_analyses / ai_risk_summaries /
  ai_response_recommendations`` directly — no second query layer, no new
  association table, no JSON copied into a context table
- never generates AI data (no provider/Ollama calls)
- never writes: no add/flush/commit, no UPDATE, and "pending" stays a
  derived state (``approval is None``) instead of a persisted value
- an approved decision surfaces as audit information on its recommendation;
  it is never auto-consumed (no Shuffle/Wazuh/TheHive, no incident
  transition, no risk recompute)
"""
import uuid

from sqlalchemy.orm import Session

from app.models import Incident
from app.schemas.ai_analysis import AIAnalysisRead
from app.schemas.ai_risk_summary import AIRiskSummaryRead
from app.schemas.incident_ai_context import (
    IncidentAIContext,
    IncidentSnapshot,
    RecommendationWithApproval,
)
from app.schemas.response_approval import AIResponseApprovalRead
from app.schemas.response_recommendation import AIResponseRecommendationRead
from app.services.incidents.models import IncidentNotFound


def get_incident_ai_context(db: Session, incident_id: uuid.UUID) -> IncidentAIContext:
    """The complete AI history of one incident, oldest first.

    Raises IncidentNotFound for an unknown id — nothing is returned, so no
    AI data of other cases can leak through the error path.
    """
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise IncidentNotFound(f"Incident {incident_id} does not exist")

    return IncidentAIContext(
        incident=IncidentSnapshot(
            id=incident.id,
            status=incident.status,
            severity=incident.severity,
            # Creation-time snapshot of EventRisk.score — never recomputed.
            risk_score_snapshot=incident.risk_score,
        ),
        analyses=[AIAnalysisRead.model_validate(a) for a in incident.ai_analyses],
        risk_summaries=[
            AIRiskSummaryRead.model_validate(s) for s in incident.ai_risk_summaries
        ],
        response_recommendations=[
            RecommendationWithApproval(
                recommendation=AIResponseRecommendationRead.model_validate(rec),
                approval=(
                    AIResponseApprovalRead.model_validate(rec.approval)
                    if rec.approval is not None
                    else None
                ),
            )
            for rec in incident.ai_response_recommendations
        ],
    )
