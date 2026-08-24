import uuid


def test_create_alert_returns_201(client, sample_payload):
    response = client.post("/api/v1/alerts", json=sample_payload)
    assert response.status_code == 201
    body = response.json()
    assert body["source"] == "scenario-simulator"
    assert body["event_type"] == "ssh_failed_login"
    assert body["severity"] == "medium"
    assert body["status"] == "open"
    assert body["event_count"] == 1
    assert body["host_name"] == "server-01"
    assert body["host_ip"] == "192.168.1.10"
    assert body["source_ip"] == "10.0.0.55"
    assert body["user_name"] == "root"


def test_list_alerts_returns_created_alert(client, sample_payload):
    client.post("/api/v1/alerts", json=sample_payload)

    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    alerts = response.json()
    assert len(alerts) == 1
    assert alerts[0]["event_type"] == "ssh_failed_login"


def test_list_alerts_pagination_bounds(client, sample_payload):
    client.post("/api/v1/alerts", json=sample_payload)

    # limit beyond the allowed maximum must be rejected
    assert client.get("/api/v1/alerts?limit=101").status_code == 422
    # skip beyond the dataset returns an empty list
    assert client.get("/api/v1/alerts?skip=10").json() == []


def test_get_alert_detail_includes_raw_event(client, sample_payload):
    alert_id = client.post("/api/v1/alerts", json=sample_payload).json()["id"]

    response = client.get(f"/api/v1/alerts/{alert_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == alert_id
    assert len(body["events"]) == 1
    event = body["events"][0]
    assert event["source"] == "scenario-simulator"
    assert event["raw_data"] == {"attempts": 8}


def test_get_missing_alert_returns_404(client):
    missing_id = uuid.uuid4()
    response = client.get(f"/api/v1/alerts/{missing_id}")
    assert response.status_code == 404


def test_invalid_severity_returns_422(client, sample_payload):
    sample_payload["severity"] = "catastrophic"
    response = client.post("/api/v1/alerts", json=sample_payload)
    assert response.status_code == 422


def test_missing_required_fields_return_422(client):
    response = client.post("/api/v1/alerts", json={"severity": "low"})
    assert response.status_code == 422


def test_alert_without_raw_data_keeps_full_payload(client):
    payload = {
        "source": "scenario-simulator",
        "event_type": "malicious_ioc",
    }
    response = client.post("/api/v1/alerts", json=payload)
    assert response.status_code == 201
    alert_id = response.json()["id"]

    detail = client.get(f"/api/v1/alerts/{alert_id}").json()
    assert detail["severity"] == "medium"  # default applied
    raw = detail["events"][0]["raw_data"]
    assert raw["source"] == "scenario-simulator"
    assert raw["event_type"] == "malicious_ioc"
