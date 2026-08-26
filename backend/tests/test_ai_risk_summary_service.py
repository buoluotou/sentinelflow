"""Step 11.3: AIRiskSummaryService tests.

Event -> EventRisk + evidence (+ optional Step 10 analysis) -> Mock provider
-> persisted ai_risk_summaries row. CI-stable: only the deterministic
MockProvider (or spies on top of it) is used, never a real model. Covers
the flush-not-commit rule, history semantics, the error taxonomy and the
task/type guard that keeps alert_explanation output out of this table.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models import AIAnalysis, AIRiskSummary, Alert, AlertGroup, EventRisk
from app.services.ai import (
    AIAnalysisService,
    AIEventNotFound,
    AIProviderUnavailable,
    AIRequest,
    AIResponseParseError,
    AIRiskSummaryService,
    MockProvider,
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
    """Answers the risk_summary task with the Step 10 protocol — must be
    rejected by the service, never persisted."""

    def generate(self, request):
        return self._explanation(request)  # AIAnalysis, wrong for this task


def _seed(db_session, with_risk: bool = True, alert_count: int = 3) -> AlertGroup:
    """AlertGroup (+ EventRisk + evidence alerts), committed."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint="a" * 64,
        title="Suspicious process execution detected",
        category="endpoint",
        severity="high",
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
                    {"name": "severity", "score": 50, "reason": "Alert severity is high"},
                    {"name": "frequency", "score": 20, "reason": "30 alerts observed"},
                ],
            )
        )
    for i in range(alert_count):
        db_session.add(
            Alert(
                source="scenario-simulator",
                event_type="suspicious_process",
                severity="high",
                source_ip=f"10.0.0.{i}",
                user_name="jsmith",
                first_seen_at=now + timedelta(seconds=i),
                last_seen_at=now + timedelta(seconds=i),
                alert_group=group,
            )
        )
    db_session.commit()
    return group


def _add_analysis(db_session, group: AlertGroup, summary: str, minutes_ago: int) -> AIAnalysis:
    record = AIAnalysis(
        alert_group=group,
        provider="mock",
        model="mock-deterministic",
        summary=summary,
        attack_type="endpoint",
        why_risky=["suspicious process chain"],
        confidence=0.8,
    )
    db_session.add(record)
    db_session.flush()
    record.created_at = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    db_session.commit()
    return record


# --------------------------------------------------------------- Case 1: happy


def test_generate_persists_full_summary_from_mock(db_session):
    group = _seed(db_session)
    service = AIRiskSummaryService(provider=MockProvider())

    record = service.generate_risk_summary(db_session, group.id)
    db_session.commit()

    assert record.id is not None
    assert record.alert_group_id == group.id
    assert record.provider == "mock"
    assert record.model == "mock-deterministic"
    assert "Suspicious process execution detected" in record.summary
    assert record.key_findings == ["Alert severity is high", "30 alerts observed"]
    assert record.risk_drivers == ["severity", "high_frequency", "high_risk_score"]
    assert record.analyst_priority == "medium"
    assert record.confidence == pytest.approx(0.7)


# -------------------------------------------- Case 2: without Step 10 analysis


def test_succeeds_without_prior_explanation(db_session):
    group = _seed(db_session)
    provider = RecordingMock()
    service = AIRiskSummaryService(provider=provider)

    record = service.generate_risk_summary(db_session, group.id)
    db_session.commit()

    assert provider.last_request is not None
    assert provider.last_request.task == "risk_summary"
    assert provider.last_request.prior_explanation is None
    assert record.id is not None


# --------------------------------------------- Case 3: with Step 10 analyses


def test_latest_step10_analysis_is_injected(db_session):
    group = _seed(db_session)
    _add_analysis(db_session, group, "Older hypothesis.", minutes_ago=10)
    latest = _add_analysis(db_session, group, "Refined conclusion.", minutes_ago=1)
    provider = RecordingMock()
    service = AIRiskSummaryService(provider=provider)

    service.generate_risk_summary(db_session, group.id)
    db_session.commit()

    assert provider.last_request.prior_explanation == {
        "summary": "Refined conclusion.",
        "attack_type": "endpoint",
        "why_risky": ["suspicious process chain"],
        "confidence": 0.8,
    }
    # Consistency with the shared Step 10 latest-record semantics.
    assert AIAnalysisService(provider=MockProvider()).latest_analysis(
        db_session, group.id
    ).id == latest.id


# ------------------------------------------------------- Case 4: history append


def test_repeated_generation_appends_history(db_session):
    group = _seed(db_session)
    service = AIRiskSummaryService(provider=MockProvider())

    first = service.generate_risk_summary(db_session, group.id)
    second = service.generate_risk_summary(db_session, group.id)
    first.created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.commit()

    rows = (
        db_session.query(AIRiskSummary)
        .filter(AIRiskSummary.alert_group_id == group.id)
        .all()
    )
    assert len(rows) == 2  # no unique constraint — history, not snapshot
    assert first.id != second.id

    latest = service.latest_summary(db_session, group.id)
    assert latest is not None and latest.id == second.id


# ---------------------------------------------------- Case 5: risk missing


def test_without_risk_degrades_but_still_generates(db_session):
    group = _seed(db_session, with_risk=False)
    service = AIRiskSummaryService(provider=MockProvider())

    record = service.generate_risk_summary(db_session, group.id)
    db_session.commit()

    assert record.analyst_priority == "low"  # unassessed -> low
    assert record.confidence == pytest.approx(0.0)  # score 0
    assert record.key_findings == ["[mock] no risk factors recorded"]
    assert record.risk_drivers == ["severity"]  # fallback, never empty


# ------------------------------------------------------------ Case 6: 503 path


def test_provider_unavailable_propagates_and_persists_nothing(db_session):
    group = _seed(db_session)
    broken = MockProvider(fail_with=AIProviderUnavailable("connection refused"))
    service = AIRiskSummaryService(provider=broken)

    with pytest.raises(AIProviderUnavailable):
        service.generate_risk_summary(db_session, group.id)

    db_session.rollback()
    assert db_session.query(AIRiskSummary).count() == 0


# ------------------------------------------------------------ Case 7: 502 path


def test_response_parse_error_propagates_and_persists_nothing(db_session):
    group = _seed(db_session)
    broken = MockProvider(fail_with=AIResponseParseError("not the frozen protocol"))
    service = AIRiskSummaryService(provider=broken)

    with pytest.raises(AIResponseParseError):
        service.generate_risk_summary(db_session, group.id)

    db_session.rollback()
    assert db_session.query(AIRiskSummary).count() == 0


def test_wrong_protocol_for_task_is_never_persisted(db_session):
    """A provider answering risk_summary with the Step 10 protocol must
    surface as a parse failure — never as a row in ai_risk_summaries."""
    group = _seed(db_session)
    service = AIRiskSummaryService(provider=WrongProtocolProvider())

    with pytest.raises(AIResponseParseError, match="risk_summary"):
        service.generate_risk_summary(db_session, group.id)

    db_session.rollback()
    assert db_session.query(AIRiskSummary).count() == 0


# ----------------------------------------------------- Case 8: flush/rollback


def test_service_flushes_but_does_not_commit(db_session):
    """Transaction boundary stays with the caller: rollback discards it."""
    group = _seed(db_session)
    service = AIRiskSummaryService(provider=MockProvider())

    record = service.generate_risk_summary(db_session, group.id)
    assert record.id is not None  # flushed (id assigned)

    db_session.rollback()
    assert db_session.query(AIRiskSummary).count() == 0


# ------------------------------------------------------------- error boundary


def test_unknown_event_raises_not_found(db_session):
    service = AIRiskSummaryService(provider=MockProvider())
    with pytest.raises(AIEventNotFound):
        service.generate_risk_summary(db_session, uuid.uuid4())
    assert db_session.query(AIRiskSummary).count() == 0


def test_default_service_uses_settings_provider(db_session):
    # Default config is AI_PROVIDER=mock, so the platform always runs.
    service = AIRiskSummaryService()
    assert service.provider.name == "mock"
