def test_health_reports_service_and_database(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "sentinelflow-backend"
    assert body["database"] == "connected"
