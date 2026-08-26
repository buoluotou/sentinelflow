"""Step 11.2: risk-summary AIRequest builder tests.

AlertGroup + EventRisk + evidence (+ optional latest Step 10 analysis)
-> the risk_summary AIRequest. Pure translation rules: no provider, no
database, no model call. Reuses the Step 10 evidence projection — the
MAX_EVIDENCE cap and None-dropping must behave identically for both tasks.
"""
import inspect
import json
from datetime import datetime, timezone

from app.models import AIAnalysis, Alert, AlertGroup, EventRisk
from app.services.ai import (
    MAX_EVIDENCE,
    build_alert_explanation,
    build_risk_summary_request,
)


def _group() -> AlertGroup:
    now = datetime.now(timezone.utc)
    return AlertGroup(
        fingerprint="a" * 64,
        title="Suspicious process execution detected",
        category="endpoint",
        severity="high",
        first_seen=now,
        last_seen=now,
    )


def _risk(group: AlertGroup, score: int = 70, level: str = "medium") -> EventRisk:
    return EventRisk(
        alert_group=group,
        score=score,
        level=level,
        factors=[
            {"name": "severity", "score": 50, "reason": "Alert severity is high"},
            {"name": "frequency", "score": 20, "reason": "30 alerts observed"},
        ],
    )


def _alert(index: int, seen: datetime | None = None) -> Alert:
    ts = seen or datetime.now(timezone.utc)
    return Alert(
        source="scenario-simulator",
        event_type="suspicious_process",
        severity="high",
        source_ip=f"10.0.0.{index % 250}",
        user_name="jsmith" if index % 2 == 0 else None,
        first_seen_at=ts,
        last_seen_at=ts,
    )


def _analysis(summary: str = "Reverse shell activity.", confidence: float = 0.95) -> AIAnalysis:
    return AIAnalysis(
        provider="ollama",
        model="qwen3:4b",
        summary=summary,
        attack_type="intrusion",
        why_risky=["known reverse-shell pattern", "outbound connection to rare port"],
        confidence=confidence,
    )


# ------------------------------------------------------- Case 1: no analysis


def test_no_prior_explanation_when_never_analysed():
    request = build_risk_summary_request(_group(), _risk(_group()), [_alert(0)], None)

    assert request.prior_explanation is None
    # Everything else must still be fully populated — Step 10 is optional.
    assert request.event_title == "Suspicious process execution detected"
    assert request.risk_score == 70
    assert len(request.evidence) == 1


# ------------------------------------------------ Case 2: analysis injected


def test_latest_analysis_injected_as_structured_projection():
    analysis = _analysis()
    request = build_risk_summary_request(_group(), None, [_alert(0)], analysis)

    assert request.prior_explanation == {
        "summary": "Reverse shell activity.",
        "attack_type": "intrusion",
        "why_risky": ["known reverse-shell pattern", "outbound connection to rare port"],
        "confidence": 0.95,
    }
    # No internal state leaks into the AI context.
    dumped = json.dumps(request.model_dump(exclude_none=True), default=str)
    assert "qwen3:4b" not in dumped  # model/provider metadata excluded
    assert "alert_group_id" not in dumped


# --------------------------------------- Case 3: multiple analyses, one wins


def test_only_the_single_latest_analysis_is_carried():
    """The builder consumes exactly the (service-selected) latest record;
    older history rows must not appear in the request."""
    older = _analysis(summary="Older hypothesis.", confidence=0.40)
    latest = _analysis(summary="Refined conclusion.", confidence=0.91)

    # Service semantics: it hands the builder only the latest one.
    request = build_risk_summary_request(_group(), None, [_alert(0)], latest)

    assert request.prior_explanation["summary"] == "Refined conclusion."
    assert request.prior_explanation["confidence"] == 0.91
    dumped = json.dumps(request.model_dump(exclude_none=True), default=str)
    assert "Older hypothesis." not in dumped


# ------------------------------------------------------ Case 4: evidence cap


def test_evidence_capped_at_max_like_step10():
    alerts = [_alert(i) for i in range(50)]

    request = build_risk_summary_request(_group(), None, alerts)

    assert len(request.evidence) == MAX_EVIDENCE == 20
    # Earliest-first order preserved (caller sorts, builder truncates).
    assert json.loads(request.evidence[0])["source_ip"] == "10.0.0.0"
    assert json.loads(request.evidence[-1])["source_ip"] == "10.0.0.19"


# ------------------------------------------------- Case 5: None-field cleanup


def test_none_fields_dropped_with_step10_projection_rules():
    request = build_risk_summary_request(_group(), None, [_alert(1)])  # user_name None

    item = json.loads(request.evidence[0])
    assert "user_name" not in item
    assert "destination_ip" not in item
    assert "event_count" not in item
    assert item["event_type"] == "suspicious_process"


# ------------------------------------------------- Case 6: factors preserved


def test_risk_factors_fully_preserved():
    group = _group()
    risk = EventRisk(
        alert_group=group,
        score=90,
        level="high",
        factors=[
            {"name": "severity", "score": 50, "reason": "critical base"},
            {"name": "frequency", "score": 20, "reason": "21-50 alerts"},
            {"name": "public_source", "score": 20, "reason": "public source IP"},
        ],
    )

    request = build_risk_summary_request(group, risk, [_alert(0)])

    assert request.risk_factors == risk.factors
    assert {f["name"] for f in request.risk_factors} == {
        "severity",
        "frequency",
        "public_source",
    }
    assert request.risk_score == 90
    assert request.risk_level == "high"


def test_missing_risk_degrades_like_step10():
    request = build_risk_summary_request(_group(), None, [_alert(0)])

    assert request.risk_score == 0
    assert request.risk_level == "unassessed"
    assert request.risk_factors == []


# ------------------------------------------------------ Case 7: task is fixed


def test_task_is_fixed_to_risk_summary():
    request = build_risk_summary_request(_group(), None, [_alert(0)])
    assert request.task == "risk_summary"

    # Callers cannot steer the task: the builder exposes no task parameter.
    params = inspect.signature(build_risk_summary_request).parameters
    assert "task" not in params


# --------------------------------------- Case 8: Step 10 builder untouched


def test_alert_explanation_builder_behaviour_frozen():
    group = _group()
    alerts = [_alert(0)]  # one shared alert: timestamps must not drift between calls
    request = build_alert_explanation(group, _risk(group), alerts)

    assert request.task == "alert_explanation"
    assert request.prior_explanation is None  # never leaks into Step 10
    # Both tasks share the exact same evidence projection.
    risk_summary = build_risk_summary_request(group, _risk(group), alerts)
    assert risk_summary.evidence == request.evidence
