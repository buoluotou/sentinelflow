import os
from collections.abc import Generator

# Tests must never call a real model, regardless of the deployment .env:
# force the deterministic mock before app/core/config builds the settings
# singleton (env vars win over .env in pydantic-settings).
os.environ["AI_PROVIDER"] = "mock"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.main import app
from app.services.executions.operators import reset_operator_registry

# Real-model E2E lives under tests/e2e/ and is never collected by the
# default run (explicit paths still work): plain `pytest tests` stays
# mock-only and offline-safe. The `ollama` marker selects the real-model
# chain; `browser` selects the Playwright browser E2E (Step 13.6).
collect_ignore_glob = ["e2e/*"]


@pytest.fixture(autouse=True)
def _reset_operator_registry_between_tests():
    """The operator registry is a module-level singleton; reset it
    between tests so monkeypatched OPERATORS_JSON / EXECUTION_TOKEN
    always take effect (Phase 3.3.1)."""
    reset_operator_registry()
    yield
    reset_operator_registry()


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "ollama: real-model end-to-end tests against a live local Ollama "
        "(qwen3:4b); never collected or run by the default suite",
    )
    config.addinivalue_line(
        "markers",
        "browser: real-browser (Playwright/Chromium) end-to-end tests of "
        "the console UI against a live uvicorn+vite stack; never collected "
        "or run by the default suite",
    )
    config.addinivalue_line(
        "markers",
        "external: tests that talk to REAL external systems (Shuffle / "
        "Wazuh / TheHive). Deselected unless the run explicitly opts in "
        "with -m external — the default suite stays zero-outbound",
    )


def pytest_collection_modifyitems(config, items):
    """Default runs never collect ``external``-marked tests (they are
    DESELECTED, not skipped, so the suite keeps 0 skipped). Opt in with
    ``pytest -m external``."""
    marker_expr = str(config.getoption("-m") or "")
    if "external" in marker_expr:
        return
    deselected = [item for item in items if item.get_closest_marker("external")]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = [item for item in items if item not in deselected]


@pytest.fixture()
def db_session() -> Generator[Session, None, None]:
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


@pytest.fixture()
def client(db_session: Session) -> Generator[TestClient, None, None]:
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def sample_payload() -> dict:
    return {
        "source": "scenario-simulator",
        "event_type": "ssh_failed_login",
        "severity": "medium",
        "timestamp": "2026-08-24T10:30:00Z",
        "host": {"hostname": "server-01", "ip": "192.168.1.10"},
        "source_ip": "10.0.0.55",
        "user": "root",
        "message": "Multiple SSH login failures detected",
        "raw_data": {"attempts": 8},
    }
