"""Build the provider-agnostic AIRequest from database state (Step 10.2).

The AI layer never sees ORM objects directly: this module is the single
translation point AlertGroup + EventRisk + evidence alerts -> AIRequest.

Evidence is bounded (MAX_EVIDENCE representative alerts, earliest first) —
a 100k-alert event must never be fed to a model whole. Richer evidence
sampling / summarization is deliberately deferred.
"""
import json

from app.models import Alert, AlertGroup, EventRisk
from app.services.ai.models import AIRequest

#: Hard cap on evidence alerts handed to the model.
MAX_EVIDENCE = 20


def build_alert_explanation(
    group: AlertGroup,
    risk: EventRisk | None,
    alerts: list[Alert],
) -> AIRequest:
    """Assemble the frozen alert-explanation request for one event.

    ``risk`` may be None (event not scored yet): the request degrades to
    score 0 / level "unassessed" with no factors rather than failing — the
    AI can still explain the event itself.
    """
    return AIRequest(
        task="alert_explanation",
        event_title=group.title,
        event_category=group.category,
        severity=group.severity,
        risk_score=risk.score if risk is not None else 0,
        risk_level=risk.level if risk is not None else "unassessed",
        risk_factors=_factors(risk),
        evidence=[
            json.dumps(_evidence_item(alert), ensure_ascii=False, default=str)
            for alert in alerts[:MAX_EVIDENCE]
        ],
    )


def _factors(risk: EventRisk | None) -> list[dict]:
    """Risk Engine factor trail [{name, score, reason}] as stored per event."""
    if risk is None or not isinstance(risk.factors, list):
        return []
    return risk.factors


def _evidence_item(alert: Alert) -> dict:
    """Compact, field-stable projection of one evidence alert.

    Only analyst-meaningful fields are forwarded (no internal ids), and None
    values are dropped so the prompt stays dense.
    """
    item = {
        "event_type": alert.event_type,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "user_name": alert.user_name,
        "host_name": alert.host_name,
        "host_ip": alert.host_ip,
        "message": alert.message,
        "event_count": alert.event_count,
        "first_seen_at": alert.first_seen_at,
    }
    return {key: value for key, value in item.items() if value is not None}
