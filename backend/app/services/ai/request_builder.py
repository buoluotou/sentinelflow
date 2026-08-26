"""Build the provider-agnostic AIRequest from database state (Step 10.2).

The AI layer never sees ORM objects directly: this module is the single
translation point AlertGroup + EventRisk + evidence alerts -> AIRequest.

Evidence is bounded (MAX_EVIDENCE representative alerts, earliest first) —
a 100k-alert event must never be fed to a model whole. Richer evidence
sampling / summarization is deliberately deferred. Both tasks share the
same evidence projection (_build_evidence) so the cap/sampling semantics
live in exactly one place.
"""
import json

from app.models import AIAnalysis, Alert, AlertGroup, EventRisk
from app.services.ai.models import AIRequest, TASK_RISK_SUMMARY

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
        evidence=_build_evidence(alerts),
    )


def build_risk_summary_request(
    group: AlertGroup,
    risk: EventRisk | None,
    alerts: list[Alert],
    latest_analysis: AIAnalysis | None = None,
) -> AIRequest:
    """Assemble the risk-summary request for one event (Step 11.2).

    Same degradation as alert explanation when ``risk`` is None. The Step 10
    explanation is an optional enrichment — a missing analysis must never
    block risk-summary generation. The task is fixed here: callers cannot
    steer the task vocabulary.
    """
    return AIRequest(
        task=TASK_RISK_SUMMARY,
        event_title=group.title,
        event_category=group.category,
        severity=group.severity,
        risk_score=risk.score if risk is not None else 0,
        risk_level=risk.level if risk is not None else "unassessed",
        risk_factors=_factors(risk),
        evidence=_build_evidence(alerts),
        prior_explanation=_prior_explanation(latest_analysis),
    )


def _build_evidence(alerts: list[Alert]) -> list[str]:
    """Bounded evidence sample: earliest MAX_EVIDENCE alerts, JSON projection.

    The caller is responsible for ordering (earliest first) — see the
    services that feed this. One implementation for every AI task.
    """
    return [
        json.dumps(_evidence_item(alert), ensure_ascii=False, default=str)
        for alert in alerts[:MAX_EVIDENCE]
    ]


def _prior_explanation(analysis: AIAnalysis | None) -> dict | None:
    """Structured projection of the latest Step 10 analysis, or None.

    Only the protocol fields are forwarded — never ids, timestamps or
    provider metadata, so the model cannot echo internal state back.
    """
    if analysis is None:
        return None
    return {
        "summary": analysis.summary,
        "attack_type": analysis.attack_type,
        "why_risky": list(analysis.why_risky or []),
        "confidence": analysis.confidence,
    }


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
