def test_health_reports_service_and_database(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "sentinelflow-backend"
    assert body["database"] == "connected"


def test_ready_reports_database_connected(client):
    response = client.get("/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["service"] == "sentinelflow-backend"
    assert body["database"] == "connected"


def test_startup_config_summary_never_leaks_secret_values(monkeypatch):
    # the startup summary states WHAT is enabled, never a secret
    # value. Only the DB driver scheme survives; credentials/tokens/keys
    # and the full DSN must never appear.
    from app.core.config import settings
    from app.main import _safe_config_summary

    monkeypatch.setattr(
        settings,
        "DATABASE_URL",
        "postgresql+psycopg://sf_user:SUPERSECRET_PW@db-host:5432/sentinelflow",
    )
    monkeypatch.setattr(settings, "EXECUTION_TOKEN", "TOKEN-SECRET-VALUE")
    monkeypatch.setattr(settings, "SHUFFLE_API_KEY", "SHUFFLE-SECRET-KEY")
    monkeypatch.setattr(settings, "WAZUH_API_PASSWORD", "WAZUH-SECRET-PW")

    summary = _safe_config_summary()

    for secret in (
        "SUPERSECRET_PW",
        "TOKEN-SECRET-VALUE",
        "SHUFFLE-SECRET-KEY",
        "WAZUH-SECRET-PW",
        "sf_user",
        "db-host",
    ):
        assert secret not in summary
    # only the driver scheme is emitted, never the credentials/host
    assert "db=postgresql+psycopg" in summary
