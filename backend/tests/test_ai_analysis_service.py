"""Phase 2 Step 10.3: AIAnalysisService tests.

Event -> EventRisk + evidence -> AIRequest -> Mock provider -> persisted
ai_analyses row. CI-stable: only the deterministic MockProvider is used,
never a real model. Error taxonomy, history semantics (no unique
constraint), the evidence cap and the flush-not-commit rule are covered.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models import AIAnalysis, Alert, AlertGroup, EventRisk
from app.services.ai import (
    MAX_EVIDENCE,
    AIAnalysisService,
    AIEventNotFound,
    AIProviderUnavailable,
    AIResponseParseError,
    MockProvider,
)


def _seed(db_session, alert_count: int = 3, with_risk: bool = True) -> AlertGroup:
    """AlertGroup (+ EventRisk + evidence alerts), committed."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint="a" * 64,
        title="SSH login failure detected",
        category="authentication",
        severity="medium",
        first_seen=now,
        last_seen=now,
    )
    db_session.add(group)
    if with_risk:
        db_session.add(
            EventRisk(
                alert_group=group,
                score=70,
                level="medium",
                factors=[
                    {"name": "severity", "score": 30, "reason": "Alert severity is medium"},
                    {"name": "frequency", "score": 40, "reason": "many alerts observed"},
                ],
            )
        )
    for i in range(alert_count):
        db_session.add(
            Alert(
                source="scenario-simulator",
                event_type="ssh_failed_login",
                severity="medium",
                source_ip=f"10.0.0.{i}",
                user_name="root",
                first_seen_at=now + timedelta(seconds=i),
                last_seen_at=now + timedelta(seconds=i),
                alert_group=group,
            )
        )
    db_session.commit()
    return group


# ------------------------------------------------------------------ happy path


def test_explain_event_persists_analysis_from_mock(db_session):
    group = _seed(db_session)
    service = AIAnalysisService(provider=MockProvider())

    record = service.explain_event(db_session, group.id)
    db_session.commit()

    assert record.id is not None
    assert record.alert_group_id == group.id
    assert record.provider == "mock"
    assert record.model == "mock-deterministic"
    assert record.attack_type == "authentication"  # mock echoes the category
    assert "SSH login failure detected" in record.summary
    assert record.confidence == pytest.approx(0.7)  # mock: score / 100
    # Mock builds why_risky from the factor reasons.
    assert record.why_risky == [
        "Alert severity is medium",
        "many alerts observed",
    ]


def test_default_service_uses_settings_provider(db_session):
    # Default config is AI_PROVIDER=mock, so the platform always runs.
    service = AIAnalysisService()
    assert service.provider.name == "mock"


def test_explain_without_risk_still_succeeds(db_session):
    group = _seed(db_session, with_risk=False)
    service = AIAnalysisService(provider=MockProvider())

    record = service.explain_event(db_session, group.id)
    db_session.commit()

    assert record.confidence == pytest.approx(0.0)  # unassessed -> score 0
    assert record.why_risky == ["[mock] no risk factors recorded"]


def test_evidence_is_bounded_for_large_events(db_session):
    group = _seed(db_session, alert_count=MAX_EVIDENCE + 5)
    service = AIAnalysisService(provider=MockProvider())

    record = service.explain_event(db_session, group.id)
    db_session.commit()

    # MockProvider reports how many evidence items it received.
    assert f"{MAX_EVIDENCE} evidence items" in record.summary


# ------------------------------------------------------------------ history


def test_repeated_analysis_appends_history(db_session):
    group = _seed(db_session)
    service = AIAnalysisService(provider=MockProvider())

    first = service.explain_event(db_session, group.id)
    second = service.explain_event(db_session, group.id)
    # Force a deterministic ordering: the first analysis is older.
    first.created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.commit()

    rows = (
        db_session.query(AIAnalysis)
        .filter(AIAnalysis.alert_group_id == group.id)
        .all()
    )
    assert len(rows) == 2  # no unique constraint — history, not snapshot
    assert first.id != second.id

    latest = service.latest_analysis(db_session, group.id)
    assert latest is not None and latest.id == second.id


def test_latest_analysis_none_when_never_analysed(db_session):
    group = _seed(db_session)
    service = AIAnalysisService(provider=MockProvider())
    assert service.latest_analysis(db_session, group.id) is None


# ------------------------------------------------------------------ errors


def test_unknown_event_raises_not_found(db_session):
    service = AIAnalysisService(provider=MockProvider())
    with pytest.raises(AIEventNotFound):
        service.explain_event(db_session, uuid.uuid4())


def test_provider_unavailable_propagates_and_persists_nothing(db_session):
    group = _seed(db_session)
    broken = MockProvider(fail_with=AIProviderUnavailable("connection refused"))
    service = AIAnalysisService(provider=broken)

    with pytest.raises(AIProviderUnavailable):
        service.explain_event(db_session, group.id)

    db_session.rollback()
    assert db_session.query(AIAnalysis).count() == 0


def test_response_parse_error_propagates_and_persists_nothing(db_session):
    group = _seed(db_session)
    broken = MockProvider(fail_with=AIResponseParseError("not the frozen protocol"))
    service = AIAnalysisService(provider=broken)

    with pytest.raises(AIResponseParseError):
        service.explain_event(db_session, group.id)

    db_session.rollback()
    assert db_session.query(AIAnalysis).count() == 0


def test_service_flushes_but_does_not_commit(db_session):
    """Transaction boundary stays with the caller: rollback discards it."""
    group = _seed(db_session)
    service = AIAnalysisService(provider=MockProvider())

    record = service.explain_event(db_session, group.id)
    assert record.id is not None  # flushed (id assigned)

    db_session.rollback()
    assert db_session.query(AIAnalysis).count() == 0
