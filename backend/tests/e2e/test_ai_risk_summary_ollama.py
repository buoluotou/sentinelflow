"""Step 11.5.8: REAL Ollama end-to-end test for the risk-summary chain.

    Event -> EventRisk -> Alerts -> build_risk_summary_request
          -> OllamaProvider -> /api/chat -> qwen3:4b -> JSON
          -> RiskSummary parser -> AIRiskSummary -> POST 201 + GET

NOT part of the default suite: tests/e2e/ is excluded from collection by
tests/conftest.py; run explicitly with:

    pytest tests/e2e/test_ai_risk_summary_ollama.py -m ollama -q

Requires a live local Ollama (``ollama list`` shows qwen3:4b). The whole
module skips when Ollama is unreachable, so an explicit run never fails
the developer machine. Assertions target the PROTOCOL, never the natural
language content — a generative model is not a fixture.
"""
import os
import urllib.error
import urllib.request
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

pytestmark = pytest.mark.ollama

OLLAMA_BASE_URL = os.environ.get("AI_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("AI_MODEL", "qwen3:4b")
# qwen3:4b needs ~25-45s per summary; never use the 60s default here.
OLLAMA_TIMEOUT = float(os.environ.get("AI_TIMEOUT_SECONDS", "180"))

FROZEN_DRIVERS = {
    "high_frequency",
    "severity",
    "public_source",
    "high_risk_score",
    "suspicious_process",
    "authentication_abuse",
    "file_integrity_change",
    "web_anomaly",
    "malicious_ioc",
    "multiple_observables",
}
FROZEN_PRIORITIES = {"low", "medium", "high", "critical"}


def _ollama_reachable() -> bool:
    try:
        with urllib.request.urlopen(f"{OLLAMA_BASE_URL}/api/tags", timeout=5) as resp:
            return resp.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


if not _ollama_reachable():
    pytest.skip(
        f"Ollama not reachable at {OLLAMA_BASE_URL} — real-model E2E skipped",
        allow_module_level=True,
    )

from app.core.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AIRiskSummary  # noqa: E402
from app.api.v1.ai_risk_summary import get_ai_risk_summary_service  # noqa: E402
from app.services.ai import AIRiskSummaryService, OllamaProvider  # noqa: E402


@pytest.fixture(scope="module")
def e2e_db() -> Generator[Session, None, None]:
    """Isolated throwaway SQLite DB — never the deployment database."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture(scope="module")
def e2e_client(e2e_db: Session) -> Generator[TestClient, None, None]:
    """Full app + DI overrides: real DB session + REAL OllamaProvider."""

    def override_get_db():
        yield e2e_db

    def override_service():
        return AIRiskSummaryService(
            provider=OllamaProvider(
                model=OLLAMA_MODEL,
                base_url=OLLAMA_BASE_URL,
                timeout=OLLAMA_TIMEOUT,
            )
        )

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_ai_risk_summary_service] = override_service
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(scope="module")
def event_id(e2e_client: TestClient) -> str:
    """Create a genuinely risky event: 30 high-severity SSH failures from a
    public source -> one AlertGroup with a high EventRisk and rich evidence."""
    for i in range(30):
        response = e2e_client.post(
            "/api/v1/alerts",
            json={
                "source": "e2e-ollama",
                "event_type": "ssh_failed_login",
                "severity": "high",
                "title": "SSH brute force attempt",
                "message": f"Repeated SSH login failure for root (attempt {i + 1})",
                "source_ip": "203.0.113.9",  # public TEST-NET-3 address
                "user": "root",
                "host": {"hostname": "edge-gw-01", "ip": "192.168.10.5"},
                "raw_data": {"attempts": i + 1},
            },
        )
        assert response.status_code in (200, 201), response.text

    listing = e2e_client.get("/api/v1/events", params={"size": 50}).json()
    candidates = [
        item for item in listing["items"] if item["title"] and "SSH" in item["title"]
    ]
    assert candidates, "expected a risky SSH event after seeding"
    return candidates[0]["id"]


def test_real_ollama_risk_summary_full_chain(e2e_client, e2e_db, event_id):
    """POST -> qwen3:4b -> 201 -> DB row -> GET returns the same record."""
    before = e2e_db.query(AIRiskSummary).count()

    response = e2e_client.post(f"/api/v1/events/{event_id}/ai-risk-summary")
    assert response.status_code == 201, response.text
    body = response.json()

    # Protocol determinism > natural-language determinism.
    assert isinstance(body["summary"], str) and body["summary"].strip()
    assert 1 <= len(body["key_findings"]) <= 5
    assert body["risk_drivers"] and set(body["risk_drivers"]) <= FROZEN_DRIVERS
    assert body["analyst_priority"] in FROZEN_PRIORITIES
    assert 0.0 <= body["confidence"] <= 1.0
    # The AI must never emit a risk score — EventRisk.score is the only one.
    assert "risk_score" not in body
    assert body["provider"] == "ollama"
    assert body["model"] == OLLAMA_MODEL

    assert e2e_db.query(AIRiskSummary).count() == before + 1

    latest = e2e_client.get(f"/api/v1/events/{event_id}/ai-risk-summary")
    assert latest.status_code == 200
    assert latest.json()["id"] == body["id"]


def test_real_ollama_unreachable_maps_to_503_and_persists_nothing(
    e2e_db, event_id
):
    """Fault injection via a dead URL — never by stopping the real service."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = TestingSessionLocal()
    try:

        def override_get_db():
            yield session

        def override_service():
            return AIRiskSummaryService(
                provider=OllamaProvider(
                    model=OLLAMA_MODEL,
                    base_url="http://localhost:11499",  # nothing listens here
                    timeout=10,
                )
            )

        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[get_ai_risk_summary_service] = override_service
        with TestClient(app) as test_client:
            # Seed a minimal event in this isolated DB.
            seed = test_client.post(
                "/api/v1/alerts",
                json={
                    "source": "e2e-ollama-fault",
                    "event_type": "ssh_failed_login",
                    "severity": "high",
                    "title": "SSH brute force attempt",
                    "source_ip": "203.0.113.9",
                    "user": "root",
                },
            )
            assert seed.status_code in (200, 201), seed.text
            group_id = test_client.get("/api/v1/events").json()["items"][0]["id"]

            response = test_client.post(f"/api/v1/events/{group_id}/ai-risk-summary")
            assert response.status_code == 503
            assert "unavailable" in response.json()["detail"]
            assert session.query(AIRiskSummary).count() == 0
    finally:
        app.dependency_overrides.clear()
        session.close()
        engine.dispose()
