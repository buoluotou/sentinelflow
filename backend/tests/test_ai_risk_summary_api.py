"""Step 11.4: AI risk-summary API tests.

HTTP contract over AIRiskSummaryService — still MockProvider only (CI runs
without any model). Covers the frozen error mapping (identical to Step 10):

    unknown event               -> 404
    AIProviderConfigError       -> 503
    AIProviderUnavailable       -> 503
    AIResponseParseError        -> 502
    wrong protocol object       -> 502 (service guard, mapped at the API)

and the hard rule: a failed summary never persists a row.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1.ai_risk_summary import get_ai_risk_summary_service
from app.main import app
from app.models import AIRiskSummary, Alert, AlertGroup, EventRisk
from app.services.ai import (
    AIRiskSummaryService,
    AIProviderConfigError,
    AIProviderUnavailable,
    AIResponseParseError,
    MockProvider,
)


class WrongProtocolProvider(MockProvider):
    """Answers the risk_summary task with the Step 10 protocol — the service
    guard must turn this into AIResponseParseError, the API into 502."""

    def generate(self, request):
        return self._explanation(request)


@pytest.fixture(autouse=True)
def _reset_service_override():
    """Every test starts from the default (settings-driven) service."""
    yield
    app.dependency_overrides.pop(get_ai_risk_summary_service, None)


def _override_service(provider: MockProvider) -> None:
    app.dependency_overrides[get_ai_risk_summary_service] = (
        lambda: AIRiskSummaryService(provider=provider)
    )


def _seed(db_session: Session) -> AlertGroup:
    """AlertGroup + EventRisk + one evidence alert, committed."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint="a" * 64,
        title="Suspicious process execution detected",
        category="endpoint",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db_session.add_all(
        [
            group,
            EventRisk(
                alert_group=group,
                score=70,
                level="medium",
                factors=[
                    {"name": "severity", "score": 50, "reason": "Alert severity is high"},
                    {"name": "frequency", "score": 20, "reason": "30 alerts observed"},
                ],
            ),
            Alert(
                source="scenario-simulator",
                event_type="suspicious_process",
                severity="high",
                source_ip="10.0.0.55",
                user_name="jsmith",
                first_seen_at=now,
                last_seen_at=now,
                alert_group=group,
            ),
        ]
    )
    db_session.commit()
    return group


# ------------------------------------------------------------------ creation


def test_create_summary_returns_201_with_frozen_fields(client, db_session):
    group = _seed(db_session)

    response = client.post(f"/api/v1/events/{group.id}/ai-risk-summary")

    assert response.status_code == 201
    body = response.json()
    assert body["provider"] == "mock"
    assert body["model"] == "mock-deterministic"
    assert body["alert_group_id"] == str(group.id)
    # The five frozen protocol outputs.
    assert "Suspicious process execution detected" in body["summary"]
    assert body["key_findings"] == ["Alert severity is high", "30 alerts observed"]
    assert body["risk_drivers"] == ["severity", "high_frequency", "high_risk_score"]
    assert body["analyst_priority"] == "medium"
    assert body["confidence"] == pytest.approx(0.7)
    # Envelope fields.
    uuid.UUID(body["id"])
    assert body["created_at"]
    assert body["updated_at"]
    # No risk score anywhere — EventRisk.score stays the only official score.
    assert "risk_score" not in body

    # Persisted exactly one row.
    rows = db_session.query(AIRiskSummary).all()
    assert len(rows) == 1 and str(rows[0].id) == body["id"]


# ------------------------------------------------------------------ latest


def test_get_returns_latest_of_history(client, db_session):
    group = _seed(db_session)

    first = client.post(f"/api/v1/events/{group.id}/ai-risk-summary").json()
    second = client.post(f"/api/v1/events/{group.id}/ai-risk-summary").json()
    assert first["id"] != second["id"]  # history, not overwrite

    # Make ordering deterministic: age the first record.
    row = db_session.get(AIRiskSummary, uuid.UUID(first["id"]))
    row.created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.commit()

    response = client.get(f"/api/v1/events/{group.id}/ai-risk-summary")
    assert response.status_code == 200
    assert response.json()["id"] == second["id"]


def test_get_without_any_summary_is_404(client, db_session):
    group = _seed(db_session)

    response = client.get(f"/api/v1/events/{group.id}/ai-risk-summary")
    assert response.status_code == 404
    assert "No AI risk summary" in response.json()["detail"]


# ------------------------------------------------------------------ 404s


@pytest.mark.parametrize(
    "event_id",
    [str(uuid.uuid4()), "not-a-uuid"],
    ids=["unknown-event", "malformed-id"],
)
def test_create_unknown_event_is_404(client, db_session, event_id):
    _seed(db_session)
    response = client.post(f"/api/v1/events/{event_id}/ai-risk-summary")
    assert response.status_code == 404
    assert response.json()["detail"] == "Event not found"


def test_get_unknown_event_is_404(client, db_session):
    _seed(db_session)
    response = client.get(f"/api/v1/events/{uuid.uuid4()}/ai-risk-summary")
    assert response.status_code == 404
    assert response.json()["detail"] == "Event not found"


# ------------------------------------------------------------------ 5xx


def test_provider_unavailable_maps_to_503_and_persists_nothing(client, db_session):
    group = _seed(db_session)
    _override_service(MockProvider(fail_with=AIProviderUnavailable("connection refused")))

    response = client.post(f"/api/v1/events/{group.id}/ai-risk-summary")

    assert response.status_code == 503
    assert "unavailable" in response.json()["detail"]
    assert db_session.query(AIRiskSummary).count() == 0


def test_config_error_maps_to_503_and_persists_nothing(client, db_session):
    group = _seed(db_session)
    _override_service(MockProvider(fail_with=AIProviderConfigError("missing AI_MODEL")))

    response = client.post(f"/api/v1/events/{group.id}/ai-risk-summary")

    assert response.status_code == 503
    assert "misconfigured" in response.json()["detail"]
    assert db_session.query(AIRiskSummary).count() == 0


def test_parse_error_maps_to_502_and_persists_nothing(client, db_session):
    group = _seed(db_session)
    _override_service(MockProvider(fail_with=AIResponseParseError("not JSON")))

    response = client.post(f"/api/v1/events/{group.id}/ai-risk-summary")

    assert response.status_code == 502
    assert "protocol" in response.json()["detail"]
    assert db_session.query(AIRiskSummary).count() == 0


def test_wrong_protocol_maps_to_502_and_persists_nothing(client, db_session):
    """Service guard + API mapping: an alert_explanation answer must never
    land in ai_risk_summaries."""
    group = _seed(db_session)
    _override_service(WrongProtocolProvider())

    response = client.post(f"/api/v1/events/{group.id}/ai-risk-summary")

    assert response.status_code == 502
    assert "protocol" in response.json()["detail"]
    assert db_session.query(AIRiskSummary).count() == 0


# ------------------------------------------------------------------ history


def test_repeated_posts_append_history(client, db_session):
    group = _seed(db_session)

    assert client.post(f"/api/v1/events/{group.id}/ai-risk-summary").status_code == 201
    assert client.post(f"/api/v1/events/{group.id}/ai-risk-summary").status_code == 201

    rows = (
        db_session.query(AIRiskSummary)
        .filter(AIRiskSummary.alert_group_id == group.id)
        .all()
    )
    assert len(rows) == 2  # append, never overwrite


def test_failed_then_successful_summary_leaves_one_row(client, db_session):
    """Failure never half-persists; the next healthy call works."""
    group = _seed(db_session)
    _override_service(MockProvider(fail_with=AIProviderUnavailable("down")))
    assert client.post(f"/api/v1/events/{group.id}/ai-risk-summary").status_code == 503

    app.dependency_overrides.pop(get_ai_risk_summary_service)
    assert client.post(f"/api/v1/events/{group.id}/ai-risk-summary").status_code == 201

    assert db_session.query(AIRiskSummary).count() == 1
