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

from app.api.v1.response_execution import (
    get_compensation_attempt_store,
    get_dispatch_attempt_store,
)
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
    # M4-F §1: the durable pre-dispatch store commits on an INDEPENDENT connection,
    # which cannot interleave with the in-memory StaticPool single shared connection
    # (a commit there would also flush the caller's pending chain). Override to None
    # so the existing endpoint journeys stay byte-identical; dedicated file-backed
    # tests (test_dispatch_endpoint_durability) re-override with the REAL store.
    app.dependency_overrides[get_dispatch_attempt_store] = lambda: None
    # RC2 / C-1: the reverse seam follows the same rule — the in-memory
    # StaticPool harness shares ONE connection, so the client fixture keeps the
    # pre-C-1 endpoint journeys byte-identical; dedicated file-backed tests
    # drive the REAL compensation store.
    app.dependency_overrides[get_compensation_attempt_store] = lambda: None
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


# ---------------------------------------------------------------------------
# G1-C / B0 §15.4 — TEST-ONLY fake adapter for platform success-pipeline proofs
# ---------------------------------------------------------------------------
#: A TEST-ONLY adapter identity — NOT a production adapter and NOT in
#: ``registry.ADAPTER_NAMES``. After G1-C emptied the REAL Wazuh external-state
#: vocabulary (fail-closed), NO production adapter has an evidenced success word.
#: The webhook (3.4.4-E) and manual-reconcile (A2-E/A2-F) suites previously used
#: the Wazuh ``success`` word as the vehicle to prove the PLATFORM pipeline
#: (validate -> map -> confirmed_success -> persist -> 200). B0 §15.4 requires
#: those pipeline proofs be PRESERVED (deleting them would weaken safety) but
#: re-based on an EXPLICIT test double — never on reopening the real Wazuh
#: vocabulary. This fake adapter is that double: a SEPARATE identity with a
#: test-only evidenced vocabulary, injected by ``monkeypatch`` (auto-rollback),
#: so the production four families stay EMPTY and every ``set(VOCAB) ==
#: set(ADAPTER_NAMES)`` / "all vocabularies empty" pin still runs in the
#: un-monkeypatched production state.
FAKE_ADAPTER = "fakesuccess"

#: The fake adapter's webhook callback channel reuses the DECLARED
#: ``WAZUH_CALLBACK_TOKEN`` setting for AUTH. Auth is orthogonal to mapping, so
#: reusing the token VALUE does NOT reopen the Wazuh vocabulary. Pydantic
#: ``Settings`` forbids undeclared fields (a dedicated ``*_CALLBACK_TOKEN`` cannot
#: be added), and reusing a declared setting keeps monkeypatch auto-rollback
#: clean. Webhook pipeline tests therefore send ``Bearer <WAZUH_TOKEN>`` to
#: ``/webhooks/fakesuccess``.
FAKE_TOKEN_SETTING = "WAZUH_CALLBACK_TOKEN"


@pytest.fixture()
def fake_adapter_vocab(monkeypatch) -> str:
    """Inject the TEST-ONLY fake adapter + an evidenced vocabulary into the
    reconciliation mapping layer (the UNIT layer). Returns the fake adapter name.

    The vocabulary MIRRORS the shape the platform pipeline needs to prove
    (success words -> confirmed_success, ``running`` -> pending, ``unknown`` ->
    unknown, case-insensitive, ``agent_status`` Mapping key) so a migrated test
    is a pure identity swap. It asserts NOTHING about any real external system —
    its evidence string is explicitly test-only. The production ``wazuh`` /
    ``shuffle`` / ``thehive`` / ``mock`` vocabularies are untouched (still empty),
    so Wazuh stays refused everywhere.
    """
    from app.services.outcomes import reconciliation as recon

    vocab = recon.AdapterStateVocabulary(
        adapter=FAKE_ADAPTER,
        terminal_success_states=frozenset(
            {"completed", "confirmed", "done", "success", "ok"}
        ),
        terminal_failure_states=frozenset(),
        pending_states=frozenset({"running"}),
        ambiguous_states=frozenset({"unknown"}),
        case_insensitive=True,
        state_key="agent_status",
        evidence=(
            "TEST-ONLY fake adapter (G1-C / B0 §15.4): a platform-pipeline "
            "proof double. NOT a production adapter; asserts NO real external "
            "system's command-effect vocabulary."
        ),
    )
    monkeypatch.setattr(recon, "ADAPTER_NAMES", recon.ADAPTER_NAMES + (FAKE_ADAPTER,))
    monkeypatch.setitem(recon.ADAPTER_STATE_VOCABULARIES, FAKE_ADAPTER, vocab)
    return FAKE_ADAPTER


@pytest.fixture()
def fake_adapter_channel(fake_adapter_vocab: str, monkeypatch) -> str:
    """Open a webhook callback channel for the TEST-ONLY fake adapter (the HTTP
    layer), composing the unit-layer vocabulary injection. Lets the webhook
    full-stack pipeline proofs authenticate ``/webhooks/fakesuccess``.

    Does NOT touch ``CALLBACK_ADAPTERS`` — the structural "exactly three external
    adapters" pin (test_webhook_authentication.py) stays in production state — and
    reuses the declared WAZUH_CALLBACK_TOKEN setting for auth (see
    ``FAKE_TOKEN_SETTING``).
    """
    from app.api.v1 import webhooks as wh

    monkeypatch.setitem(wh.CALLBACK_TOKEN_SETTINGS, FAKE_ADAPTER, FAKE_TOKEN_SETTING)
    return fake_adapter_vocab


@pytest.fixture()
def fake_read_adapter(fake_adapter_vocab: str, monkeypatch) -> str:
    """Make the TEST-ONLY fake adapter a REFERENCE-BEARING read adapter for the
    Manual Reconcile path (A2-B/A2-C), composing the unit-layer vocabulary.

    ``manual_reconcile._extract_reference`` resolves the terminal-row handle via
    ``_EXTERNAL_REFERENCE_KEYS[adapter]`` and ``validate_observation`` then REQUIRES
    a non-empty ``external_reference``, so the fake adapter needs a reference key
    exactly like a real one. Injected here (test-only, monkeypatch auto-rollback) so
    the manual success pipeline (correlate -> extract adapter+reference ->
    registry.get -> read -> map -> persist) is a pure identity swap from Wazuh,
    WITHOUT reopening the real (now-empty) Wazuh vocabulary. The production
    three-adapter ``_EXTERNAL_REFERENCE_KEYS`` shape is restored after each test, so
    the "production registry empty" pins still run in the un-monkeypatched state.
    """
    from app.services.outcomes import manual_reconcile as mr

    monkeypatch.setitem(mr._EXTERNAL_REFERENCE_KEYS, FAKE_ADAPTER, "command_id")
    return fake_adapter_vocab
