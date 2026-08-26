"""Step 12.2: AIResponseRecommendationService tests.

Event -> EventRisk + evidence (+ optional Step 11 risk summary) -> Mock
provider -> persisted ai_response_recommendations row. CI-stable: only the
deterministic MockProvider (or spies on top of it) is used, never a real
model. Covers the flush-not-commit rule, history semantics, the error
taxonomy, the "never persist a broken answer" rule and the advisory-only
boundary (no EventRisk/Incident mutation, no execution of any action).
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models import (
    AIResponseRecommendation,
    AIRiskSummary,
    Alert,
    AlertGroup,
    EventRisk,
    Incident,
)
from app.services.ai import (
    AIEventNotFound,
    AIProviderConfigError,
    AIProviderUnavailable,
    AIRequest,
    AIResponseParseError,
    AIResponseRecommendationService,
    MockProvider,
    RecommendationItem,
    ResponseRecommendation,
    parse_response_recommendation,
)


class RecordingMock(MockProvider):
    """MockProvider that keeps the last AIRequest for inspection."""

    def __init__(self):
        super().__init__()
        self.last_request: AIRequest | None = None

    def generate(self, request):
        self.last_request = request
        return super().generate(request)


class WrongProtocolProvider(MockProvider):
    """Answers the response_recommendation task with the Step 11 protocol —
    must be rejected by the service, never persisted."""

    def generate(self, request):
        return self._risk_summary(request)  # RiskSummary, wrong for this task


class UnknownActionProvider(MockProvider):
    """Returns a typed ResponseRecommendation carrying an out-of-vocabulary
    action — the service must re-enforce the frozen vocabulary."""

    def generate(self, request):
        return ResponseRecommendation(
            overall_rationale="Do everything.",
            recommendations=[
                RecommendationItem(
                    action="block_ip_everywhere",
                    target="",
                    rationale="Because we can.",
                )
            ],
            confidence=0.5,
        )


def _seed(db_session, score: int = 85, level: str = "high", alert_count: int = 3) -> AlertGroup:
    """AlertGroup (+ EventRisk + evidence alerts), committed."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint="b" * 64,
        title="SSH Brute Force on edge-gateway",
        category="authentication",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db_session.add(group)
    db_session.add(
        EventRisk(
            alert_group=group,
            score=score,
            level=level,
            factors=[
                {"name": "severity", "score": 30, "reason": "High-severity alerts in the group"},
                {"name": "frequency", "score": 20, "reason": "Repeated alerts within a short window"},
            ],
        )
    )
    for i in range(alert_count):
        db_session.add(
            Alert(
                source="scenario-simulator",
                event_type="ssh_failed_login",
                severity="high",
                source_ip=f"203.0.113.{i}",
                user_name="root",
                first_seen_at=now + timedelta(seconds=i),
                last_seen_at=now + timedelta(seconds=i),
                alert_group=group,
            )
        )
    db_session.commit()
    return group


def _add_summary(db_session, group: AlertGroup, summary: str, minutes_ago: int) -> AIRiskSummary:
    record = AIRiskSummary(
        alert_group=group,
        provider="mock",
        model="mock-deterministic",
        summary=summary,
        key_findings=["30 failed logins"],
        risk_drivers=["high_frequency"],
        analyst_priority="high",
        confidence=0.95,
    )
    db_session.add(record)
    db_session.flush()
    record.created_at = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    db_session.commit()
    return record


# --------------------------------------------------------------- Case 1: happy


def test_generate_persists_full_recommendation_from_mock(db_session):
    group = _seed(db_session, score=85)
    service = AIResponseRecommendationService(provider=MockProvider())

    record = service.generate_response_recommendation(db_session, group.id)
    db_session.commit()

    assert record.id is not None
    assert record.alert_group_id == group.id
    assert record.provider == "mock"
    assert record.model == "mock-deterministic"
    assert "SSH Brute Force on edge-gateway" in record.overall_rationale
    actions = [item["action"] for item in record.recommendations]
    assert actions == ["block_source_ip", "escalate_to_incident"]
    # Structured target surfaces the observed source, analyst-readable only.
    assert record.recommendations[0]["target"] == "203.0.113.0"
    assert all(item["rationale"] for item in record.recommendations)
    assert record.confidence == pytest.approx(0.85)


# ---------------------------------------------------- Case 2: mock bands reach the service


def test_high_score_contains_and_escalates(db_session):
    group = _seed(db_session, score=85)
    record = AIResponseRecommendationService(provider=MockProvider()).generate_response_recommendation(
        db_session, group.id
    )
    assert [item["action"] for item in record.recommendations] == [
        "block_source_ip", "escalate_to_incident",
    ]


def test_mid_score_investigates_only(db_session):
    group = _seed(db_session, score=55, level="medium")
    record = AIResponseRecommendationService(provider=MockProvider()).generate_response_recommendation(
        db_session, group.id
    )
    assert [item["action"] for item in record.recommendations] == ["hunt_related_activity"]


def test_low_score_returns_first_class_no_action(db_session):
    group = _seed(db_session, score=20, level="low")
    record = AIResponseRecommendationService(provider=MockProvider()).generate_response_recommendation(
        db_session, group.id
    )
    db_session.commit()

    assert record.recommendations == []  # empty list is a valid record
    assert "No response action warranted" in record.overall_rationale


# ----------------------------------------- Case 3: three-layer chain independence


def test_succeeds_without_prior_risk_summary(db_session):
    group = _seed(db_session)
    provider = RecordingMock()
    service = AIResponseRecommendationService(provider=provider)

    record = service.generate_response_recommendation(db_session, group.id)
    db_session.commit()

    assert provider.last_request is not None
    assert provider.last_request.task == "response_recommendation"
    assert provider.last_request.prior_summary is None
    assert record.id is not None


def test_succeeds_without_step10_explanation(db_session):
    """Event + Risk + Risk Summary but NO Explanation: still generatable."""
    group = _seed(db_session)
    _add_summary(db_session, group, "Brute force from a public IP.", minutes_ago=1)

    record = AIResponseRecommendationService(provider=MockProvider()).generate_response_recommendation(
        db_session, group.id
    )
    db_session.commit()
    assert record.id is not None


def test_latest_risk_summary_is_injected(db_session):
    group = _seed(db_session)
    _add_summary(db_session, group, "Older synthesis.", minutes_ago=10)
    latest = _add_summary(db_session, group, "Refined synthesis.", minutes_ago=1)
    provider = RecordingMock()
    service = AIResponseRecommendationService(provider=provider)

    service.generate_response_recommendation(db_session, group.id)
    db_session.commit()

    # Structured projection only — no ids, timestamps or provider metadata.
    assert provider.last_request.prior_summary == {
        "summary": "Refined synthesis.",
        "key_findings": ["30 failed logins"],
        "risk_drivers": ["high_frequency"],
        "analyst_priority": "high",
        "confidence": 0.95,
    }
    assert service.provider is provider
    # Consistency with the shared Step 11 latest-record semantics.
    from app.services.ai import AIRiskSummaryService

    assert AIRiskSummaryService(provider=MockProvider()).latest_summary(
        db_session, group.id
    ).id == latest.id


# ------------------------------------------------------- Case 4: history append


def test_repeated_generation_appends_history(db_session):
    group = _seed(db_session)
    service = AIResponseRecommendationService(provider=MockProvider())

    first = service.generate_response_recommendation(db_session, group.id)
    second = service.generate_response_recommendation(db_session, group.id)
    first.created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.commit()

    rows = (
        db_session.query(AIResponseRecommendation)
        .filter(AIResponseRecommendation.alert_group_id == group.id)
        .all()
    )
    assert len(rows) == 2  # no unique constraint — history, not snapshot
    assert first.id != second.id

    latest = service.latest_recommendation(db_session, group.id)
    assert latest is not None and latest.id == second.id


# --------------------------------------------------------- Case 5: safety bounds


def test_event_risk_and_incident_stay_untouched(db_session):
    """Advisory only: generating advice never mutates risk or incidents,
    and escalate_to_incident is a suggestion — not an auto-created case."""
    group = _seed(db_session, score=85)
    service = AIResponseRecommendationService(provider=MockProvider())

    service.generate_response_recommendation(db_session, group.id)
    db_session.commit()

    risk = db_session.query(EventRisk).filter(EventRisk.alert_group_id == group.id).one()
    assert risk.score == 85 and risk.level == "high"
    assert db_session.query(Incident).count() == 0


# ---------------------------------------------------------- Case 6: 503/502 paths


def test_provider_config_error_propagates_and_persists_nothing(db_session):
    group = _seed(db_session)
    broken = MockProvider(fail_with=AIProviderConfigError("AI_PROVIDER unknown"))
    service = AIResponseRecommendationService(provider=broken)

    with pytest.raises(AIProviderConfigError):
        service.generate_response_recommendation(db_session, group.id)

    db_session.rollback()
    assert db_session.query(AIResponseRecommendation).count() == 0


def test_provider_unavailable_propagates_and_persists_nothing(db_session):
    group = _seed(db_session)
    broken = MockProvider(fail_with=AIProviderUnavailable("connection refused"))
    service = AIResponseRecommendationService(provider=broken)

    with pytest.raises(AIProviderUnavailable):
        service.generate_response_recommendation(db_session, group.id)

    db_session.rollback()
    assert db_session.query(AIResponseRecommendation).count() == 0


def test_response_parse_error_propagates_and_persists_nothing(db_session):
    group = _seed(db_session)
    broken = MockProvider(fail_with=AIResponseParseError("not the frozen protocol"))
    service = AIResponseRecommendationService(provider=broken)

    with pytest.raises(AIResponseParseError):
        service.generate_response_recommendation(db_session, group.id)

    db_session.rollback()
    assert db_session.query(AIResponseRecommendation).count() == 0


def test_wrong_protocol_for_task_is_never_persisted(db_session):
    """A provider answering response_recommendation with the Step 11 protocol
    must surface as a parse failure — never as a row."""
    group = _seed(db_session)
    service = AIResponseRecommendationService(provider=WrongProtocolProvider())

    with pytest.raises(AIResponseParseError, match="response_recommendation"):
        service.generate_response_recommendation(db_session, group.id)

    db_session.rollback()
    assert db_session.query(AIResponseRecommendation).count() == 0


def test_unknown_action_in_provider_output_is_never_persisted(db_session):
    group = _seed(db_session)
    service = AIResponseRecommendationService(provider=UnknownActionProvider())

    with pytest.raises(AIResponseParseError, match="unknown response actions"):
        service.generate_response_recommendation(db_session, group.id)

    db_session.rollback()
    assert db_session.query(AIResponseRecommendation).count() == 0


@pytest.mark.parametrize(
    "payload",
    [
        # Extra envelope field (e.g. an executable payload) is rejected.
        {"execute": True},
        # Confidence out of bounds is rejected.
        {"confidence": 1.5},
    ],
)
def test_protocol_strictness_at_the_real_provider_boundary(db_session, payload):
    """Raw-output providers (ollama/cloud) go through the strict parser:
    extra fields and out-of-bounds confidence raise before any persistence."""
    base = {
        "overall_rationale": "Advice.",
        "recommendations": [],
        "confidence": 0.5,
    }
    base.update(payload)
    with pytest.raises(AIResponseParseError):
        parse_response_recommendation(json.dumps(base))
    assert db_session.query(AIResponseRecommendation).count() == 0


# ----------------------------------------------------- Case 7: flush/rollback


def test_service_flushes_but_does_not_commit(db_session):
    """Transaction boundary stays with the caller: rollback discards it."""
    group = _seed(db_session)
    service = AIResponseRecommendationService(provider=MockProvider())

    record = service.generate_response_recommendation(db_session, group.id)
    assert record.id is not None  # flushed (id assigned)

    db_session.rollback()
    assert db_session.query(AIResponseRecommendation).count() == 0


# ------------------------------------------------------------- error boundary


def test_unknown_event_raises_not_found(db_session):
    service = AIResponseRecommendationService(provider=MockProvider())
    with pytest.raises(AIEventNotFound):
        service.generate_response_recommendation(db_session, uuid.uuid4())
    assert db_session.query(AIResponseRecommendation).count() == 0


def test_default_service_uses_settings_provider(db_session):
    # Default config is AI_PROVIDER=mock, so the platform always runs.
    service = AIResponseRecommendationService()
    assert service.provider.name == "mock"
