"""Step 3: Alert Normalization tests.

Covers: simulator input (minimal + full shapes), wazuh placeholder input,
malformed / unknown source handling, and the normalize -> ingest pipeline.
"""


def _normalize(client, source: str, raw_data: dict):
    return client.post(
        "/api/v1/normalize", json={"source": source, "raw_data": raw_data}
    )


# ---------------------------------------------------------------- simulator


def test_normalize_simulator_minimal_shape(client):
    response = _normalize(
        client, "simulator", {"type": "ssh_failed_login", "src_ip": "10.10.10.5"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "simulator"
    assert body["event_type"] == "ssh_failed_login"
    assert body["category"] == "authentication"
    assert body["severity"] == "medium"
    assert body["actor"]["ip"] == "10.10.10.5"
    assert {"type": "ip", "value": "10.10.10.5"} in body["observables"]
    assert body["raw_event"]["src_ip"] == "10.10.10.5"
    assert body["alert_id"] is not None


def test_normalize_simulator_full_shape(client):
    raw = {
        "event_type": "ssh_failed_login",
        "severity": "medium",
        "timestamp": "2026-08-24T10:30:00Z",
        "host": {"hostname": "server-01", "ip": "192.168.1.10"},
        "source_ip": "10.0.0.55",
        "user": "root",
        "message": "Multiple SSH login failures detected",
        "raw_data": {"attempts": 8},
    }
    response = _normalize(client, "simulator", raw)
    assert response.status_code == 200
    body = response.json()
    assert body["asset"] == {"hostname": "server-01", "ip": "192.168.1.10"}
    assert body["actor"] == {"ip": "10.0.0.55", "user": "root"}
    assert body["description"] == "Multiple SSH login failures detected"
    observable_types = {o["type"] for o in body["observables"]}
    assert {"ip", "hostname", "user"} <= observable_types


def test_normalize_simulator_malicious_ioc(client):
    raw = {
        "event_type": "malicious_ioc",
        "host": {"hostname": "db-server-01", "ip": "192.168.1.50"},
        "source_ip": "198.51.100.77",
        "message": "Outbound connection to known C2 server",
        "raw_data": {
            "ioc_type": "ip",
            "ioc_value": "198.51.100.77",
            "threat_feed": "abuse-ch",
        },
    }
    response = _normalize(client, "simulator", raw)
    assert response.status_code == 200
    body = response.json()
    assert body["category"] == "threat_intel"
    assert body["severity"] == "critical"
    assert {"type": "ip", "value": "198.51.100.77"} in body["observables"]


def test_normalize_simulator_file_integrity_extracts_file_and_hashes(client):
    raw = {
        "event_type": "file_integrity_change",
        "host": {"hostname": "web-server-02", "ip": "192.168.1.20"},
        "user": "www-data",
        "message": "System binary modified unexpectedly",
        "raw_data": {
            "file_path": "/usr/bin/sshd",
            "action": "modified",
            "hash_before": "abc123",
            "hash_after": "def456",
        },
    }
    response = _normalize(client, "simulator", raw)
    assert response.status_code == 200
    body = response.json()
    assert body["category"] == "file_integrity"
    assert body["severity"] == "high"
    observables = {(o["type"], o["value"]) for o in body["observables"]}
    assert ("file", "/usr/bin/sshd") in observables
    assert ("hash", "def456") in observables


def test_normalize_simulator_unknown_type_falls_back_to_generic(client):
    response = _normalize(client, "simulator", {"type": "brand_new_event"})
    assert response.status_code == 200
    body = response.json()
    assert body["category"] == "generic"
    assert body["severity"] == "low"


def test_normalize_persists_alert_into_database(client):
    response = _normalize(
        client, "simulator", {"type": "suspicious_process", "src_ip": "10.9.9.9"}
    )
    alert_id = response.json()["alert_id"]

    detail = client.get(f"/api/v1/alerts/{alert_id}")
    assert detail.status_code == 200
    alert = detail.json()
    assert alert["event_type"] == "suspicious_process"
    assert alert["severity"] == "high"
    assert alert["source_ip"] == "10.9.9.9"
    # the original raw event is preserved as JSONB
    assert alert["events"][0]["raw_data"]["type"] == "suspicious_process"


# ------------------------------------------------------------------- wazuh


def test_normalize_wazuh_returns_501_placeholder(client):
    response = _normalize(
        client,
        "wazuh",
        {"rule": {"level": 10, "description": "SSH brute force"}, "agent": {"name": "server01"}},
    )
    assert response.status_code == 501
    assert "Phase 2" in response.json()["detail"]


# ------------------------------------------------------- malformed / errors


def test_normalize_unknown_source_returns_400(client):
    response = _normalize(client, "suricata", {"event_type": "whatever"})
    assert response.status_code == 400
    assert "suricata" in response.json()["detail"]


def test_normalize_missing_event_type_returns_400(client):
    response = _normalize(client, "simulator", {"src_ip": "10.10.10.5"})
    assert response.status_code == 400
    assert "type" in response.json()["detail"]


def test_normalize_empty_raw_data_returns_400(client):
    response = _normalize(client, "simulator", {})
    assert response.status_code == 400


def test_normalize_missing_raw_data_field_returns_422(client):
    response = client.post("/api/v1/normalize", json={"source": "simulator"})
    assert response.status_code == 422


def test_scenario_simulator_alias_is_registered(client):
    response = _normalize(
        client, "scenario-simulator", {"type": "web_anomaly", "src_ip": "203.0.113.9"}
    )
    assert response.status_code == 200
    assert response.json()["category"] == "web"
