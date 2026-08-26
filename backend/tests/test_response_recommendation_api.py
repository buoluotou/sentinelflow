"""Step 12.3: AI response-recommendation API tests.

HTTP contract over AIResponseRecommendationService — still MockProvider
only (CI runs without any model). Covers the frozen error mapping
(identical to Step 10/11):

    unknown event               -> 404
    AIProviderConfigError       -> 503
    AIProviderUnavailable       -> 503
    AIResponseParseError        -> 502
    wrong protocol object       -> 502 (service guard, mapped at the API)
    unknown action vocabulary   -> 502 (service guard, mapped at the API)

plus the hard rules: a failed recommendation never persists a row, the
API owns commit + refresh, history is append-only, and no risk score ever
surfaces in the response.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1.response_recommendation import get_ai_response_recommendation_service
from app.main import app
from app.models import (
    AIResponseRecommendation,
    Alert,
    AlertGroup,
    EventRisk,
    Incident,
)
from app.services.ai import (
    AIResponseRecommendationService,
    AIProviderConfigError,
    AIProviderUnavailable,
    AIResponseParseError,
    MockProvider,
    RecommendationItem,
    ResponseRecommendation,
)


class WrongProtocolProvider(MockProvider):
    """Answers the response_recommendation task with the Step 11 protocol —
    the service guard must turn this into AIResponseParseError, the API
    into 502."""

    def generate(self, request):
        return self._risk_summary(request)


class UnknownActionProvider(MockProvider):
    """Returns an out-of-vocabulary action — the service vocabulary guard
    must turn this into AIResponseParseError, the API into 502."""

    def generate(self, request):
        return ResponseRecommendation(
            overall_rationale="Do everything.",
            recommendations=[
                RecommendationItem(
                    action="block_ip_everywhere", target="", rationale="Because we can."
                )
            ],
            confidence=0.5,
        )


@pytest.fixture(autouse=True)
def _reset_service_override():
    """Every test starts from the default (settings-driven) service."""
    yield
    app.dependency_overrides.pop(get_ai_response_recommendation_service, None)


def _override_service(provider: MockProvider) -> None:
    app.dependency_overrides[get_ai_response_recommendation_service] = (
        lambda: AIResponseRecommendationService(provider=provider)
    )


def _seed(db_session: Session) -> AlertGroup:
    """AlertGroup + EventRisk + one evidence alert, committed."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint="c" * 64,
        title="SSH Brute Force on edge-gateway",
        category="authentication",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db_session.add_all(
        [
            group,
            EventRisk(
                alert_group=group,
                score=85,
                level="high",
                factors=[
                    {"name": "severity", "score": 30, "reason": "High-severity alerts in the group"},
                    {"name": "frequency", "score": 20, "reason": "Repeated alerts within a short window"},
                ],
            ),
            Alert(
                source="scenario-simulator",
                event_type="ssh_failed_login",
                severity="high",
                source_ip="203.0.113.9",
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


def test_create_recommendation_returns_201_with_frozen_fields(client, db_session):
    group = _seed(db_session)

    response = client.post(f"/api/v1/events/{group.id}/response-recommendation")

    assert response.status_code == 201
    body = response.json()
    assert body["provider"] == "mock"
    assert body["model"] == "mock-deterministic"
    assert body["alert_group_id"] == str(group.id)
    # The three frozen protocol outputs.
    assert "SSH Brute Force on edge-gateway" in body["overall_rationale"]
    actions = [item["action"] for item in body["recommendations"]]
    assert actions == ["block_source_ip", "escalate_to_incident"]
    assert body["recommendations"][0]["target"] == "203.0.113.9"
    assert all(item["rationale"] for item in body["recommendations"])
    assert body["confidence"] == pytest.approx(0.85)
    # API commit + refresh proof: id and timestamps come from the database,
    # not from an in-memory object.
    uuid.UUID(body["id"])
    assert body["created_at"]
    assert body["updated_at"]
    # No risk score anywhere — EventRisk.score stays the only official score.
    assert "risk_score" not in body
    assert "risk_score" not in response.text

    # Persisted exactly one row (the API committed the service flush).
    rows = db_session.query(AIResponseRecommendation).all()
    assert len(rows) == 1 and str(rows[0].id) == body["id"]


# ------------------------------------------------------------------ latest


def test_get_returns_latest_of_history(client, db_session):
    group = _seed(db_session)

    first = client.post(f"/api/v1/events/{group.id}/response-recommendation").json()
    second = client.post(f"/api/v1/events/{group.id}/response-recommendation").json()
    assert first["id"] != second["id"]  # history, not overwrite

    # Make ordering deterministic: age the first record.
    row = db_session.get(AIResponseRecommendation, uuid.UUID(first["id"]))
    row.created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.commit()

    response = client.get(f"/api/v1/events/{group.id}/response-recommendation")
    assert response.status_code == 200
    assert response.json()["id"] == second["id"]
    # GET never overwrites: still exactly two rows.
    assert db_session.query(AIResponseRecommendation).count() == 2


def test_get_without_any_recommendation_is_404(client, db_session):
    group = _seed(db_session)

    response = client.get(f"/api/v1/events/{group.id}/response-recommendation")
    assert response.status_code == 404
    assert "No response recommendation" in response.json()["detail"]


# ------------------------------------------------------------------ 404s


@pytest.mark.parametrize(
    "event_id",
    [str(uuid.uuid4()), "not-a-uuid"],
    ids=["unknown-event", "malformed-id"],
)
def test_create_unknown_event_is_404(client, db_session, event_id):
    _seed(db_session)
    response = client.post(f"/api/v1/events/{event_id}/response-recommendation")
    assert response.status_code == 404
    assert response.json()["detail"] == "Event not found"


def test_get_unknown_event_is_404(client, db_session):
    _seed(db_session)
    response = client.get(f"/api/v1/events/{uuid.uuid4()}/response-recommendation")
    assert response.status_code == 404
    assert response.json()["detail"] == "Event not found"


# ------------------------------------------------------------------ 5xx


def test_provider_unavailable_maps_to_503_and_persists_nothing(client, db_session):
    group = _seed(db_session)
    _override_service(MockProvider(fail_with=AIProviderUnavailable("connection refused")))

    response = client.post(f"/api/v1/events/{group.id}/response-recommendation")

    assert response.status_code == 503
    assert "unavailable" in response.json()["detail"]
    assert db_session.query(AIResponseRecommendation).count() == 0


def test_config_error_maps_to_503_and_persists_nothing(client, db_session):
    group = _seed(db_session)
    _override_service(MockProvider(fail_with=AIProviderConfigError("missing AI_MODEL")))

    response = client.post(f"/api/v1/events/{group.id}/response-recommendation")

    assert response.status_code == 503
    assert "misconfigured" in response.json()["detail"]
    assert db_session.query(AIResponseRecommendation).count() == 0


def test_parse_error_maps_to_502_and_persists_nothing(client, db_session):
    group = _seed(db_session)
    _override_service(MockProvider(fail_with=AIResponseParseError("not JSON")))

    response = client.post(f"/api/v1/events/{group.id}/response-recommendation")

    assert response.status_code == 502
    assert "protocol" in response.json()["detail"]
    assert db_session.query(AIResponseRecommendation).count() == 0


def test_wrong_protocol_maps_to_502_and_persists_nothing(client, db_session):
    """Service guard + API mapping: a risk-summary answer must never land in
    ai_response_recommendations."""
    group = _seed(db_session)
    _override_service(WrongProtocolProvider())

    response = client.post(f"/api/v1/events/{group.id}/response-recommendation")

    assert response.status_code == 502
    assert "protocol" in response.json()["detail"]
    assert db_session.query(AIResponseRecommendation).count() == 0


def test_unknown_action_maps_to_502_and_persists_nothing(client, db_session):
    """Vocabulary guard + API mapping: an out-of-vocabulary action must never
    land in ai_response_recommendations."""
    group = _seed(db_session)
    _override_service(UnknownActionProvider())

    response = client.post(f"/api/v1/events/{group.id}/response-recommendation")

    assert response.status_code == 502
    assert "protocol" in response.json()["detail"]
    assert db_session.query(AIResponseRecommendation).count() == 0


# ------------------------------------------------------------------ history


def test_repeated_posts_append_history(client, db_session):
    group = _seed(db_session)

    assert client.post(f"/api/v1/events/{group.id}/response-recommendation").status_code == 201
    assert client.post(f"/api/v1/events/{group.id}/response-recommendation").status_code == 201

    rows = (
        db_session.query(AIResponseRecommendation)
        .filter(AIResponseRecommendation.alert_group_id == group.id)
        .all()
    )
    assert len(rows) == 2  # append, never overwrite


def test_failed_then_successful_recommendation_leaves_one_row(client, db_session):
    """Failure never half-persists; the next healthy call works."""
    group = _seed(db_session)
    _override_service(MockProvider(fail_with=AIProviderUnavailable("down")))
    assert client.post(f"/api/v1/events/{group.id}/response-recommendation").status_code == 503

    app.dependency_overrides.pop(get_ai_response_recommendation_service)
    assert client.post(f"/api/v1/events/{group.id}/response-recommendation").status_code == 201

    assert db_session.query(AIResponseRecommendation).count() == 1


# ------------------------------------------------------------------ safety


def test_generation_never_touches_risk_or_incidents(client, db_session):
    """Advisory only: the endpoint never mutates EventRisk, and
    escalate_to_incident stays a suggestion — no Incident is created."""
    group = _seed(db_session)

    response = client.post(f"/api/v1/events/{group.id}/response-recommendation")
    assert response.status_code == 201

    risk = db_session.query(EventRisk).filter(EventRisk.alert_group_id == group.id).one()
    assert risk.score == 85 and risk.level == "high"
    assert db_session.query(Incident).count() == 0
