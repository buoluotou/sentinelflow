"""Phase 1 Step 6: Scenario Simulator Runner tests.

The runner is stdlib-only and lives in simulator/runner/; it is imported via
sys.path so its pure logic (discovery, validation, timestamp rewrite, HTTP
send) is covered without touching the real backend. A local fake HTTP server
exercises the request layer.
"""
import json
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

RUNNER_DIR = Path(__file__).resolve().parents[2] / "simulator" / "runner"
SCENARIOS_DIR = Path(__file__).resolve().parents[2] / "simulator" / "scenarios"
sys.path.insert(0, str(RUNNER_DIR))

import run as runner  # noqa: E402


# ---------------------------------------------------------------- discovery


def test_discover_finds_all_five_scenarios():
    paths = runner.discover_scenarios(SCENARIOS_DIR)
    names = {p.parent.name for p in paths}
    assert names == {
        "ssh_failed_login",
        "file_integrity",
        "web_anomaly",
        "suspicious_process",
        "malicious_ioc",
    }


def test_discover_single_scenario_by_name():
    paths = runner.discover_scenarios(SCENARIOS_DIR, "ssh_failed_login")
    assert len(paths) == 1 and paths[0].parent.name == "ssh_failed_login"


def test_discover_unknown_scenario_raises():
    with pytest.raises(runner.ScenarioError, match="scenario not found"):
        runner.discover_scenarios(SCENARIOS_DIR, "does_not_exist")


# --------------------------------------------------------------- validation


def test_load_scenario_requires_events_list(tmp_path):
    bad = tmp_path / "events.json"
    bad.write_text(json.dumps({"scenario": "x", "events": []}), encoding="utf-8")
    with pytest.raises(runner.ScenarioError, match="non-empty 'events'"):
        runner.load_scenario(bad)


def test_validate_event_rejects_missing_and_bad_severity():
    with pytest.raises(runner.ScenarioError, match="event_type"):
        runner.validate_event({"source": "s", "severity": "low"}, "x")
    with pytest.raises(runner.ScenarioError, match="invalid severity"):
        runner.validate_event(
            {"source": "s", "event_type": "t", "severity": "urgent"}, "x"
        )


def test_all_shipped_scenarios_pass_validation():
    for path in runner.discover_scenarios(SCENARIOS_DIR):
        data = runner.load_scenario(path)
        for event in data["events"]:
            runner.validate_event(event, data["scenario"])


# ---------------------------------------------------------------- timestamps


def test_prepare_event_now_rewrites_timestamp_and_keeps_original():
    original = {"event_type": "t", "timestamp": "2026-08-24T10:30:00Z"}
    prepared = runner.prepare_event(original, "now")
    assert prepared["timestamp"] != original["timestamp"]
    assert prepared["timestamp"].endswith("+00:00")  # aware UTC
    assert original["timestamp"] == "2026-08-24T10:30:00Z"  # not mutated


def test_prepare_event_file_replays_stored_timestamp():
    original = {"event_type": "t", "timestamp": "2026-08-24T10:30:00Z"}
    prepared = runner.prepare_event(original, "file")
    assert prepared["timestamp"] == "2026-08-24T10:30:00Z"


# --------------------------------------------------------------- HTTP layer


class _FakeBackend(BaseHTTPRequestHandler):
    """Records POSTs; replies 201 with a group id, or 500 when told to."""

    protocol_version = "HTTP/1.1"  # keep-alive, like the real uvicorn server

    received: list[dict] = []
    fail_next = False

    def _reply(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        type(self).received.append(body)
        if type(self).fail_next:
            type(self).fail_next = False
            self._reply(500, b'{"detail":"boom"}')
            return
        payload = {"id": str(uuid.uuid4()), "alert_group_id": str(uuid.uuid4())}
        self._reply(201, json.dumps(payload).encode("utf-8"))

    def do_GET(self):
        payload = {
            "total": 1,
            "page": 1,
            "size": 100,
            "items": [
                {
                    "title": "SSH login failure detected",
                    "alert_count": len(type(self).received),
                    "risk_score": 50,
                    "risk_level": "medium",
                }
            ],
        }
        self._reply(200, json.dumps(payload).encode("utf-8"))

    def log_message(self, format, *args):  # silence request logging
        pass


@pytest.fixture()
def fake_backend():
    _FakeBackend.received = []
    _FakeBackend.fail_next = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeBackend)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    thread.join(timeout=5)


def test_send_event_success(fake_backend):
    status, body = runner.send_event(fake_backend, {"event_type": "t"})
    assert status == 201
    assert "alert_group_id" in body


def test_send_event_error_status_returned(fake_backend):
    _FakeBackend.fail_next = True
    status, body = runner.send_event(fake_backend, {"event_type": "t"})
    assert status == 500
    assert body["detail"] == "boom"


def test_send_event_connection_failure_returns_zero():
    status, body = runner.send_event("http://127.0.0.1:1", {"event_type": "t"})
    assert status == 0
    assert "error" in body


# --------------------------------------------------------------------- CLI


def _run_cli(base_url: str, extra: list[str]) -> int:
    parser = runner.build_parser()
    args = parser.parse_args(
        ["--base-url", base_url, "--interval", "0", "--scenarios-dir", str(SCENARIOS_DIR), *extra]
    )
    return runner.run(args)


def test_full_run_sends_all_scenarios_and_exits_zero(fake_backend, capsys):
    exit_code = _run_cli(fake_backend, [])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert len(_FakeBackend.received) == 5  # one event per scenario
    assert "sent=5 failed=0" in out
    assert "risk_score=50 risk_level=medium" in out


def test_full_run_with_repeat_sends_n_times(fake_backend):
    assert _run_cli(fake_backend, ["--scenario", "ssh_failed_login", "--repeat", "3"]) == 0
    assert len(_FakeBackend.received) == 3


def test_full_run_returns_nonzero_when_a_send_fails(fake_backend, capsys):
    _FakeBackend.fail_next = True
    exit_code = _run_cli(fake_backend, ["--scenario", "ssh_failed_login"])
    assert exit_code == 1
    assert "sent=0 failed=1" in capsys.readouterr().out


def test_run_with_unknown_scenario_exits_two(capsys):
    exit_code = _run_cli("http://127.0.0.1:1", ["--scenario", "nope"])
    assert exit_code == 2
    assert "scenario not found" in capsys.readouterr().err
