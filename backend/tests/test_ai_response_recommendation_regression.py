"""Step 12.4: cross-layer regression for the response-recommendation pipeline.

12.1 (protocol) / 12.2 (service) / 12.3 (API) each have their own unit
suites; this file pins the whole pipeline as one module:

    MockProvider / scripted providers -> parser -> Service -> API -> SQLite

Four blocks, all at the API boundary so a regression in ANY layer trips:

1. the six frozen actions each round-trip through POST -> 201
2. the three deterministic Mock score bands (>=70 / 40..69 / <40), with
   the empty recommendation being a SUCCESS, not an error
3. protocol violations through the real raw-output path (OllamaProvider +
   injected transport): unknown action / extra field / risk_score smuggle /
   confidence out of bounds / broken structure -> 502 and 0 new rows
4. the closed loop: POST -> GET -> POST -> GET with append-only history
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from app.api.v1.response_recommendation import get_ai_response_recommendation_service
from app.main import app
from app.models import AIResponseRecommendation, Alert, AlertGroup, EventRisk
from app.services.ai import (
    RESPONSE_ACTIONS,
    AIResponseRecommendationService,
    MockProvider,
    OllamaProvider,
    RecommendationItem,
    ResponseRecommendation,
)


class ScriptedProvider(MockProvider):
    """Returns a fixed ResponseRecommendation — lets the regression drive
    every frozen action through the real API path."""

    def __init__(self, result: ResponseRecommendation):
        super().__init__()
        self._result = result

    def generate(self, request):
        return self._result


class FakeTransport:
    """Injected stand-in for the HTTP layer: returns a canned Ollama body,
    so the RAW-OUTPUT parser path runs inside the real pipeline."""

    def __init__(self, body: str):
        self.body = body

    def __call__(self, url: str, payload: dict, headers=None, **kwargs) -> str:
        return self.body


@pytest.fixture(autouse=True)
def _reset_service_override():
    """Every test starts from the default (settings-driven) service."""
    yield
    app.dependency_overrides.pop(get_ai_response_recommendation_service, None)


def _override(provider) -> None:
    app.dependency_overrides[get_ai_response_recommendation_service] = (
        lambda: AIResponseRecommendationService(provider=provider)
    )


def _seed(db_session: Session, score: int, level: str) -> AlertGroup:
    """AlertGroup + EventRisk + one evidence alert, committed."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint=f"{score:02d}" + "d" * 62,
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
                score=score,
                level=level,
                factors=[
                    {"name": "severity", "score": 30, "reason": "High-severity alerts"},
                    {"name": "frequency", "score": 20, "reason": "Repeated alerts"},
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


# ------------------------------------- Block 1: six actions through the API


@pytest.mark.parametrize("action", sorted(RESPONSE_ACTIONS))
def test_every_frozen_action_round_trips_via_api(client, db_session, action):
    group = _seed(db_session, score=85, level="high")
    _override(
        ScriptedProvider(
            ResponseRecommendation(
                overall_rationale=f"Advice centred on {action}.",
                recommendations=[
                    RecommendationItem(action=action, target="203.0.113.9", rationale="r")
                ],
                confidence=0.8,
            )
        )
    )

    response = client.post(f"/api/v1/events/{group.id}/response-recommendation")

    assert response.status_code == 201
    body = response.json()
    assert [item["action"] for item in body["recommendations"]] == [action]
    rows = db_session.query(AIResponseRecommendation).all()
    assert len(rows) == 1
    assert [item["action"] for item in rows[0].recommendations] == [action]


# -------------------------------------- Block 2: mock score bands via API


def test_high_score_band_contains_and_escalates_via_api(client, db_session):
    group = _seed(db_session, score=85, level="high")

    response = client.post(f"/api/v1/events/{group.id}/response-recommendation")

    assert response.status_code == 201
    assert [item["action"] for item in response.json()["recommendations"]] == [
        "block_source_ip", "escalate_to_incident",
    ]


def test_mid_score_band_investigates_via_api(client, db_session):
    group = _seed(db_session, score=55, level="medium")

    response = client.post(f"/api/v1/events/{group.id}/response-recommendation")

    assert response.status_code == 201
    assert [item["action"] for item in response.json()["recommendations"]] == [
        "hunt_related_activity",
    ]


def test_low_score_band_empty_is_a_success_via_api(client, db_session):
    """recommendations == [] is a first-class successful answer, persisted
    and readable back — never an error state."""
    group = _seed(db_session, score=20, level="low")

    response = client.post(f"/api/v1/events/{group.id}/response-recommendation")

    assert response.status_code == 201
    body = response.json()
    assert body["recommendations"] == []
    assert "No response action warranted" in body["overall_rationale"]

    latest = client.get(f"/api/v1/events/{group.id}/response-recommendation")
    assert latest.status_code == 200  # NOT 404: an empty record is a record
    assert latest.json()["recommendations"] == []


# --------------------------- Block 3: violations through the raw-output path


def _ollama_body(content: str) -> str:
    return json.dumps({"message": {"content": content}})


@pytest.mark.parametrize(
    "content",
    [
        # Unknown action outside the frozen vocabulary.
        json.dumps({
            "overall_rationale": "r",
            "recommendations": [{"action": "block_ip_everywhere", "target": "", "rationale": "r"}],
            "confidence": 0.5,
        }),
        # Extra envelope field (an executable payload must never sneak in).
        json.dumps({
            "overall_rationale": "r",
            "recommendations": [],
            "confidence": 0.5,
            "execute": True,
        }),
        # risk_score smuggle: the protocol has no such field.
        json.dumps({
            "overall_rationale": "r",
            "recommendations": [],
            "confidence": 0.5,
            "risk_score": 93,
        }),
        # Confidence out of bounds.
        json.dumps({"overall_rationale": "r", "recommendations": [], "confidence": 1.5}),
        # Broken structure: recommendations must be an array of items.
        json.dumps({"overall_rationale": "r", "recommendations": "block everything", "confidence": 0.5}),
        # Not JSON at all.
        "I refuse to recommend anything.",
    ],
    ids=[
        "unknown-action",
        "extra-field",
        "risk-score-smuggle",
        "confidence-out-of-bounds",
        "broken-structure",
        "not-json",
    ],
)
def test_protocol_violations_map_to_502_and_persist_nothing(
    client, db_session, content
):
    group = _seed(db_session, score=85, level="high")
    _override(OllamaProvider(model="qwen3:4b", transport=FakeTransport(_ollama_body(content))))

    response = client.post(f"/api/v1/events/{group.id}/response-recommendation")

    assert response.status_code == 502
    assert "protocol" in response.json()["detail"]
    assert db_session.query(AIResponseRecommendation).count() == 0


# ------------------------------------------------ Block 4: closed loop


def test_closed_loop_post_get_post_get_with_append_only_history(client, db_session):
    group = _seed(db_session, score=85, level="high")
    url = f"/api/v1/events/{group.id}/response-recommendation"

    # POST #1 -> 201, then GET returns it.
    first = client.post(url)
    assert first.status_code == 201
    assert client.get(url).json()["id"] == first.json()["id"]

    # Age the first record so ordering is deterministic.
    first_row = db_session.get(AIResponseRecommendation, uuid.UUID(first.json()["id"]))
    first_row.created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    first_snapshot = {
        "overall_rationale": first_row.overall_rationale,
        "recommendations": first_row.recommendations,
        "confidence": first_row.confidence,
    }
    db_session.commit()

    # POST #2 -> 201 with an independent id; GET now returns the second.
    second = client.post(url)
    assert second.status_code == 201
    assert second.json()["id"] != first.json()["id"]
    assert client.get(url).json()["id"] == second.json()["id"]

    # History has exactly two rows; GET never appends.
    rows = (
        db_session.query(AIResponseRecommendation)
        .filter(AIResponseRecommendation.alert_group_id == group.id)
        .all()
    )
    assert len(rows) == 2

    # The first record's content was never UPDATEd by the second POST or any
    # GET (updated_at is excluded: aging created_at above legitimately trips
    # the ORM onupdate hook — the protocol content is the frozen part).
    db_session.refresh(first_row)
    assert first_row.overall_rationale == first_snapshot["overall_rationale"]
    assert first_row.recommendations == first_snapshot["recommendations"]
    assert first_row.confidence == first_snapshot["confidence"]
