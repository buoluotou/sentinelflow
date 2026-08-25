"""Phase 2 Step 10.6: AI analysis API tests.

HTTP contract over AIAnalysisService — still MockProvider only (CI runs
without any model). Covers the frozen error mapping:

    unknown event               -> 404
    AIProviderConfigError       -> 503
    AIProviderUnavailable       -> 503
    AIResponseParseError        -> 502

and the hard rule: a failed analysis never persists a row.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1.ai_analysis import get_ai_analysis_service
from app.main import app
from app.models import AIAnalysis, Alert, AlertGroup, EventRisk
from app.services.ai import (
    AIAnalysisService,
    AIProviderConfigError,
    AIProviderUnavailable,
    AIResponseParseError,
    MockProvider,
)


@pytest.fixture(autouse=True)
def _reset_service_override():
    """Every test starts from the default (settings-driven) service."""
    yield
    app.dependency_overrides.pop(get_ai_analysis_service, None)


def _override_service(provider: MockProvider) -> None:
    app.dependency_overrides[get_ai_analysis_service] = (
        lambda: AIAnalysisService(provider=provider)
    )


def _seed(db_session: Session) -> AlertGroup:
    """AlertGroup + EventRisk + one evidence alert, committed."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint="a" * 64,
        title="SSH login failure detected",
        category="authentication",
        severity="medium",
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
                    {"name": "severity", "score": 30, "reason": "Alert severity is medium"},
                    {"name": "frequency", "score": 40, "reason": "many alerts observed"},
                ],
            ),
            Alert(
                source="scenario-simulator",
                event_type="ssh_failed_login",
                severity="medium",
                source_ip="10.0.0.55",
                user_name="root",
                first_seen_at=now,
                last_seen_at=now,
                alert_group=group,
            ),
        ]
    )
    db_session.commit()
    return group


# ------------------------------------------------------------------ creation


def test_create_analysis_returns_201_with_frozen_fields(client, db_session):
    group = _seed(db_session)

    response = client.post(f"/api/v1/events/{group.id}/ai-analysis")

    assert response.status_code == 201
    body = response.json()
    assert body["provider"] == "mock"
    assert body["model"] == "mock-deterministic"
    assert body["alert_group_id"] == str(group.id)
    assert "SSH login failure detected" in body["summary"]
    assert body["attack_type"] == "authentication"
    assert body["why_risky"] == ["Alert severity is medium", "many alerts observed"]
    assert body["confidence"] == pytest.approx(0.7)
    assert body["created_at"]
    uuid.UUID(body["id"])  # well-formed id

    # Persisted exactly one row.
    rows = db_session.query(AIAnalysis).all()
    assert len(rows) == 1 and str(rows[0].id) == body["id"]


# ------------------------------------------------------------------ latest


def test_get_returns_latest_of_history(client, db_session):
    group = _seed(db_session)

    first = client.post(f"/api/v1/events/{group.id}/ai-analysis").json()
    second = client.post(f"/api/v1/events/{group.id}/ai-analysis").json()
    assert first["id"] != second["id"]  # history, not overwrite

    # Make ordering deterministic: age the first record.
    row = db_session.get(AIAnalysis, uuid.UUID(first["id"]))
    row.created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.commit()

    response = client.get(f"/api/v1/events/{group.id}/ai-analysis")
    assert response.status_code == 200
    assert response.json()["id"] == second["id"]


def test_get_without_any_analysis_is_404(client, db_session):
    group = _seed(db_session)

    response = client.get(f"/api/v1/events/{group.id}/ai-analysis")
    assert response.status_code == 404
    assert "No AI analysis" in response.json()["detail"]


# ------------------------------------------------------------------ 404s


@pytest.mark.parametrize(
    "event_id",
    [str(uuid.uuid4()), "not-a-uuid"],
    ids=["unknown-event", "malformed-id"],
)
def test_create_unknown_event_is_404(client, db_session, event_id):
    _seed(db_session)
    response = client.post(f"/api/v1/events/{event_id}/ai-analysis")
    assert response.status_code == 404
    assert response.json()["detail"] == "Event not found"


def test_get_unknown_event_is_404(client, db_session):
    _seed(db_session)
    response = client.get(f"/api/v1/events/{uuid.uuid4()}/ai-analysis")
    assert response.status_code == 404
    assert response.json()["detail"] == "Event not found"


# ------------------------------------------------------------------ 5xx


def test_provider_unavailable_maps_to_503_and_persists_nothing(client, db_session):
    group = _seed(db_session)
    _override_service(MockProvider(fail_with=AIProviderUnavailable("connection refused")))

    response = client.post(f"/api/v1/events/{group.id}/ai-analysis")

    assert response.status_code == 503
    assert "unavailable" in response.json()["detail"]
    assert db_session.query(AIAnalysis).count() == 0


def test_config_error_maps_to_503_and_persists_nothing(client, db_session):
    group = _seed(db_session)
    _override_service(MockProvider(fail_with=AIProviderConfigError("missing AI_MODEL")))

    response = client.post(f"/api/v1/events/{group.id}/ai-analysis")

    assert response.status_code == 503
    assert "misconfigured" in response.json()["detail"]
    assert db_session.query(AIAnalysis).count() == 0


def test_parse_error_maps_to_502_and_persists_nothing(client, db_session):
    group = _seed(db_session)
    _override_service(MockProvider(fail_with=AIResponseParseError("not JSON")))

    response = client.post(f"/api/v1/events/{group.id}/ai-analysis")

    assert response.status_code == 502
    assert "protocol" in response.json()["detail"]
    assert db_session.query(AIAnalysis).count() == 0


def test_failed_then_successful_analysis_leaves_one_row(client, db_session):
    """Failure never half-persists; the next healthy call works."""
    group = _seed(db_session)
    _override_service(MockProvider(fail_with=AIProviderUnavailable("down")))
    assert client.post(f"/api/v1/events/{group.id}/ai-analysis").status_code == 503

    app.dependency_overrides.pop(get_ai_analysis_service)
    assert client.post(f"/api/v1/events/{group.id}/ai-analysis").status_code == 201

    assert db_session.query(AIAnalysis).count() == 1
