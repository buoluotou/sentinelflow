"""The approval auth boundary and the separation of approval from execution.

Demo mode (default) keeps the tokenless, display-only approval UX.
Production mode rejects tokenless approval, enforces a separate approval
permission (viewer / executor get 403) and records the Bearer token's
server-side principal — the request-body identity is ignored, so
impersonation is impossible. Execution and reconcile keep their own
(executor / admin) boundary: a reviewer token reaches neither.
"""
import json
import uuid
from datetime import datetime, timezone

import pytest

from app.core.config import settings
from app.models import AIResponseRecommendation, AlertGroup, EventRisk

TOKENS = {
    "viewer": "tok-viewer-01",
    "reviewer": "tok-reviewer-01",
    "executor": "tok-executor-01",
    "admin": "tok-admin-01",
}


def _operators_json() -> str:
    return json.dumps(
        [
            {"token": TOKENS["viewer"], "name": "vie-1", "role": "viewer"},
            {"token": TOKENS["reviewer"], "name": "rev-1", "role": "reviewer"},
            {"token": TOKENS["executor"], "name": "exe-1", "role": "executor"},
            {"token": TOKENS["admin"], "name": "adm-1", "role": "admin"},
        ]
    )


def _header(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKENS[role]}"}


@pytest.fixture()
def production(monkeypatch):
    """Switch the running app to production mode with a full operator set."""
    monkeypatch.setattr(settings, "DEPLOYMENT_MODE", "production")
    monkeypatch.setattr(settings, "OPERATORS_JSON", _operators_json())
    return settings


def _seed_pending(db_session) -> AIResponseRecommendation:
    """Committed AlertGroup + EventRisk + one pending recommendation."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint=uuid.uuid4().hex,
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
            score=85,
            level="high",
            factors=[{"name": "severity", "score": 50, "reason": "high severity"}],
        )
    )
    db_session.flush()
    record = AIResponseRecommendation(
        alert_group=group,
        provider="mock",
        model="mock-deterministic",
        overall_rationale="[mock] guidance",
        recommendations=[
            {"action": "block_source_ip", "target": "203.0.113.7", "rationale": "abuse"}
        ],
        confidence=0.7,
    )
    db_session.add(record)
    db_session.commit()
    return record


def _approve_url(record) -> str:
    return f"/api/v1/response-recommendations/{record.id}/approve"


class TestDemoModeApproval:
    def test_tokenless_approval_keeps_the_simple_ux(self, client, db_session):
        record = _seed_pending(db_session)
        response = client.post(
            _approve_url(record),
            json={"reviewer": "analyst-7", "review_comment": "contain it"},
        )
        assert response.status_code == 201
        body = response.json()
        # demo mode: the body reviewer is display-only metadata, UX unchanged.
        assert body["reviewer"] == "analyst-7"
        assert body["status"] == "approved"


class TestProductionModeApproval:
    def test_tokenless_approval_is_401(self, client, db_session, production):
        record = _seed_pending(db_session)
        response = client.post(_approve_url(record), json={"reviewer": "mallory"})
        assert response.status_code == 401

    def test_unknown_token_is_401(self, client, db_session, production):
        record = _seed_pending(db_session)
        response = client.post(
            _approve_url(record),
            json={"reviewer": "mallory"},
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert response.status_code == 401

    def test_viewer_token_is_403(self, client, db_session, production):
        record = _seed_pending(db_session)
        response = client.post(
            _approve_url(record),
            json={"reviewer": "mallory"},
            headers=_header("viewer"),
        )
        assert response.status_code == 403

    def test_executor_token_cannot_approve(self, client, db_session, production):
        """Permission separation: execution does not imply approval."""
        record = _seed_pending(db_session)
        response = client.post(
            _approve_url(record),
            json={"reviewer": "mallory"},
            headers=_header("executor"),
        )
        assert response.status_code == 403

    def test_reviewer_approves_and_the_body_identity_is_ignored(
        self, client, db_session, production
    ):
        record = _seed_pending(db_session)
        response = client.post(
            _approve_url(record),
            json={"reviewer": "mallory", "review_comment": "ok"},
            headers=_header("reviewer"),
        )
        assert response.status_code == 201
        body = response.json()
        # the token's principal is recorded; the body identity is not trusted.
        assert body["reviewer"] == "rev-1"
        assert "mallory" not in json.dumps(body)

    def test_admin_token_approves(self, client, db_session, production):
        record = _seed_pending(db_session)
        response = client.post(
            _approve_url(record),
            json={"reviewer": "someone-else"},
            headers=_header("admin"),
        )
        assert response.status_code == 201
        assert response.json()["reviewer"] == "adm-1"


class TestProductionPermissionSeparation:
    def test_reviewer_token_cannot_execute(self, client, production):
        response = client.post(
            "/api/v1/executions",
            json={"approval_id": str(uuid.uuid4()), "execution_id": str(uuid.uuid4())},
            headers=_header("reviewer"),
        )
        assert response.status_code == 403

    def test_reviewer_token_cannot_reconcile(self, client, production):
        response = client.post(
            f"/api/v1/executions/{uuid.uuid4()}/reconcile",
            json={},
            headers=_header("reviewer"),
        )
        assert response.status_code == 403
