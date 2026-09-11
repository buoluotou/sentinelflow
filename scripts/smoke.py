#!/usr/bin/env python3
"""SentinelFlow Demo smoke test — drives the FULL core chain over real HTTP.

This is a black-box acceptance probe: it talks ONLY to the running backend's
public HTTP API (never imports app services, never touches the database
directly) and walks the exact chain a first-time user follows in Demo Mode:

    health/ready -> dashboard -> submit an alert (simulator contract)
      -> event + risk -> incident -> AI analysis / risk summary /
      response recommendation (mock) -> approval -> mock execution
      -> execution audit / metrics / health -> dashboard reflects it

Demo Mode only: AI_PROVIDER=mock and EXECUTION_ADAPTER=mock, so NO external
system (Wazuh / Shuffle / TheHive / Ollama) is ever contacted. The one
write path that needs a credential (POST /executions) uses the Bearer
EXECUTION_TOKEN; the manual-reconcile probe is expected to fail CLOSED (404)
because the production read-adapter registry is intentionally empty.

Driver-aware: on PostgreSQL (Demo Mode) the FULL chain including the durable
dispatch execution must pass. On SQLite the durable-dispatch execution step is
PostgreSQL-only (it commits the attempt on an INDEPENDENT MVCC connection before
the external call), so the smoke proves the full business chain through human
approval and asserts the execution step FAILS CLOSED (no fabricated dispatch or
outcome) — reported as a distinct "core smoke test (SQLite): PASS" banner, never
the full-demo PASS.

Stdlib only. Exit code 0 on success (prints the PASS banner), non-zero on the
first failure.

Usage:
    python scripts/smoke.py --base-url http://127.0.0.1:8000
    python scripts/smoke.py --token "$EXECUTION_TOKEN"
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

# Corporate proxies often intercept localhost traffic; always talk direct.
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# A documentation-reserved IP (TEST-NET-3, RFC 5737): a critical alert on it
# scores >= 70 (auto-incident) and yields a block_source_ip recommendation with
# a non-empty target, without ever naming a real routable host.
_DEMO_SOURCE_IP = "203.0.113.10"


class SmokeError(Exception):
    """A smoke assertion or transport failure — aborts the run."""


def _json(raw: str):
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"_raw": raw}


def _request(method: str, url: str, body=None, token: str | None = None,
             timeout: float = 30.0) -> tuple[int, dict]:
    """One HTTP call -> (status, parsed-json-or-{'_raw': text})."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with _NO_PROXY_OPENER.open(req, timeout=timeout) as resp:
            return resp.status, _json(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except OSError:
            raw = ""
        return exc.code, _json(raw)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise SmokeError(f"{method} {url} -> connection failed: {reason}") from exc


def _url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}{path}"


def _expect(cond: bool, msg: str) -> None:
    if not cond:
        raise SmokeError(msg)


def _resolve_token(args: argparse.Namespace) -> str | None:
    """--token > $EXECUTION_TOKEN > EXECUTION_TOKEN in a .env file."""
    if args.token:
        return args.token
    env_token = os.environ.get("EXECUTION_TOKEN")
    if env_token:
        return env_token
    for candidate in (args.env_file, Path(__file__).resolve().parents[1] / ".env"):
        if candidate and Path(candidate).is_file():
            for line in Path(candidate).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("EXECUTION_TOKEN=") and not line.startswith("#"):
                    value = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if value:
                        return value
    return None


def _wait_ready(base: str, seconds: int) -> None:
    deadline = time.time() + seconds
    last = "not reached"
    while time.time() < deadline:
        try:
            status, body = _request("GET", _url(base, "/ready"), timeout=5)
            if status == 200:
                return
            last = f"HTTP {status} {body.get('detail', '')}".strip()
        except SmokeError as exc:
            last = str(exc)
        time.sleep(1.5)
    raise SmokeError(f"backend not ready after {seconds}s ({last})")


def run(base: str, token: str | None, wait: int) -> str:
    """Walk the chain over real HTTP. Returns the success banner to print.

    Driver-aware: on PostgreSQL (Demo Mode, MVCC) it proves the FULL chain
    including the durable-dispatch execution; on SQLite it proves the full
    business chain through human approval and asserts the execution step fails
    CLOSED (the durable dispatch needs MVCC — see the execution step below)."""
    step = 0

    def ok(label: str) -> None:
        nonlocal step
        step += 1
        print(f"  [{step:02d}] PASS  {label}")

    print(f"SentinelFlow demo smoke -> {base}")
    if wait > 0:
        _wait_ready(base, wait)
        ok(f"backend ready within {wait}s (GET /ready)")

    # 1. Liveness + platform detection (database_driver is non-sensitive).
    status, body = _request("GET", _url(base, "/health"))
    _expect(status == 200, f"/health expected 200, got {status}")
    _expect(body.get("service") == "sentinelflow-backend", f"/health body unexpected: {body}")
    driver = str(body.get("database_driver", "")).lower()
    is_sqlite = driver.startswith("sqlite")
    ok(f"GET /health -> 200 (service=sentinelflow-backend, database_driver={driver or 'unknown'})")

    # 2. Readiness (DB connected).
    status, body = _request("GET", _url(base, "/ready"))
    _expect(status == 200, f"/ready expected 200, got {status} ({body})")
    _expect(body.get("database") == "connected", f"/ready database not connected: {body}")
    ok("GET /ready -> 200 (database connected)")

    # 3. Dashboard baseline (readable, all counters present).
    status, dash0 = _request("GET", _url(base, "/api/v1/dashboard/summary"))
    _expect(status == 200, f"/dashboard/summary expected 200, got {status}")
    for field in ("open_incidents", "today_alerts", "today_events", "risk_distribution"):
        _expect(field in dash0, f"/dashboard/summary missing '{field}': {dash0}")
    ok("GET /api/v1/dashboard/summary -> 200 (counters present)")

    # 4. Submit an alert through the SAME contract the simulator uses. This
    # synchronously drives normalization -> dedup -> risk -> auto-incident.
    alert = {
        "source": "demo-smoke",
        "event_type": "malicious_ioc",
        "severity": "critical",
        "title": "Malicious IOC match detected",
        "message": "Outbound connection to a known C2 server (demo smoke)",
        "source_ip": _DEMO_SOURCE_IP,
        "host": {"hostname": "db-server-01", "ip": "192.0.2.50"},
        "raw_data": {"ioc_type": "ip", "ioc_value": _DEMO_SOURCE_IP},
    }
    status, created = _request("POST", _url(base, "/api/v1/alerts"), body=alert)
    _expect(status == 201, f"POST /alerts expected 201, got {status} ({created})")
    event_id = created.get("alert_group_id")
    _expect(bool(event_id), f"POST /alerts returned no alert_group_id: {created}")
    ok(f"POST /api/v1/alerts -> 201 (event_id={event_id})")

    # 5. Event detail carries a risk snapshot with score >= 70 (auto-incident).
    status, event = _request("GET", _url(base, f"/api/v1/events/{event_id}"))
    _expect(status == 200, f"GET /events/{{id}} expected 200, got {status}")
    risk = event.get("risk") or {}
    score = risk.get("score")
    _expect(isinstance(score, int) and score >= 70, f"risk score not >= 70: {risk}")
    ok(f"GET /api/v1/events/{{id}} -> 200 (risk score={score}, level={risk.get('level')})")

    # 6. The critical event auto-created an incident.
    status, incidents = _request("GET", _url(base, "/api/v1/incidents?page=1&size=100"))
    _expect(status == 200, f"GET /incidents expected 200, got {status}")
    _expect(incidents.get("total", 0) >= 1, f"no incident auto-created: {incidents}")
    ok(f"GET /api/v1/incidents -> 200 (total={incidents.get('total')}, auto-created)")

    # 7-9. AI chain (mock provider, empty body, explicit trigger).
    status, ai = _request("POST", _url(base, f"/api/v1/events/{event_id}/ai-analysis"), body={})
    _expect(status == 201, f"POST ai-analysis expected 201, got {status} ({ai})")
    _expect(ai.get("provider") == "mock", f"ai-analysis provider not mock: {ai}")
    ok("POST /api/v1/events/{id}/ai-analysis -> 201 (provider=mock)")

    status, summary = _request("POST", _url(base, f"/api/v1/events/{event_id}/ai-risk-summary"), body={})
    _expect(status == 201, f"POST ai-risk-summary expected 201, got {status} ({summary})")
    ok("POST /api/v1/events/{id}/ai-risk-summary -> 201")

    status, rec = _request("POST", _url(base, f"/api/v1/events/{event_id}/response-recommendation"), body={})
    _expect(status == 201, f"POST response-recommendation expected 201, got {status} ({rec})")
    rec_id = rec.get("id")
    _expect(bool(rec_id), f"recommendation has no id: {rec}")
    actions = [r.get("action") for r in rec.get("recommendations", [])]
    _expect("block_source_ip" in actions, f"expected block_source_ip in {actions}")
    ok(f"POST /api/v1/events/{{id}}/response-recommendation -> 201 (actions={actions})")

    # 10. The recommendation is pending in the approval queue.
    status, queue = _request("GET", _url(base, "/api/v1/approvals"))
    _expect(status == 200, f"GET /approvals expected 200, got {status}")
    _expect(any(item.get("id") == rec_id for item in queue),
            f"recommendation {rec_id} not in the pending queue ({len(queue)} items)")
    ok("GET /api/v1/approvals -> 200 (recommendation is pending)")

    # 11. A human approves it (no token on the approval path by design).
    status, approval = _request(
        "POST", _url(base, f"/api/v1/response-recommendations/{rec_id}/approve"),
        body={"reviewer": "demo-smoke", "review_comment": "approved by smoke"},
    )
    _expect(status == 201, f"POST approve expected 201, got {status} ({approval})")
    approval_id = approval.get("id")
    _expect(bool(approval_id), f"approval has no id: {approval}")
    _expect(approval.get("status") == "approved", f"approval status not approved: {approval}")
    ok(f"POST /api/v1/response-recommendations/{{id}}/approve -> 201 (approval_id={approval_id})")

    # 13. Execution — the durable-dispatch step. It commits the pre-dispatch
    # attempt on an INDEPENDENT connection BEFORE any external call (frozen
    # durability: "flush != durable commit"; the attempt must survive a
    # caller rollback / crash). That needs an MVCC database: PostgreSQL runs
    # the caller's open write transaction and the independent commit side by
    # side. SQLite serializes writes at the DATABASE level, so while the
    # caller's transaction is open the independent commit cannot proceed and
    # the store FAILS CLOSED — it rolls back, never reaches the adapter and
    # fabricates nothing. Both behaviours are asserted explicitly per driver.
    _expect(bool(token), "no EXECUTION_TOKEN available for the execute step "
                         "(pass --token, set $EXECUTION_TOKEN, or put it in .env)")
    execution_id = str(uuid.uuid4())
    status, execution = _request(
        "POST", _url(base, "/api/v1/executions"),
        body={"execution_id": execution_id, "approval_id": approval_id,
              "comment": "demo smoke execution"},
        token=token,
    )

    if is_sqlite:
        _expect(status >= 400, f"SQLite durable dispatch expected a fail-closed "
                               f"error (>=400), got {status} ({execution})")
        ok(f"POST /api/v1/executions -> {status} (fail-closed on SQLite: durable "
           "dispatch requires MVCC/PostgreSQL; no adapter call, nothing fabricated)")

        status, metrics = _request("GET", _url(base, "/api/v1/executions/metrics"))
        _expect(status == 200, f"GET /executions/metrics expected 200, got {status}")
        _expect(metrics.get("total_chains", -1) == 0 and metrics.get("succeeded", -1) == 0,
                f"SQLite fail-closed violated — a chain/outcome was fabricated: {metrics}")
        ok("GET /api/v1/executions/metrics -> 200 (total_chains=0, succeeded=0: "
           "no dispatch/outcome fabricated)")

        status, dash1 = _request("GET", _url(base, "/api/v1/dashboard/summary"))
        _expect(status == 200, f"/dashboard/summary (post) expected 200, got {status}")
        _expect(dash1.get("today_alerts", 0) >= dash0.get("today_alerts", 0) + 1,
                f"today_alerts did not increase: before={dash0.get('today_alerts')} "
                f"after={dash1.get('today_alerts')}")
        ok(f"GET /api/v1/dashboard/summary -> 200 (today_alerts={dash1.get('today_alerts')}, "
           "reflects the run)")
        return (
            "SentinelFlow core smoke test (SQLite): PASS\n"
            "  Full business chain verified over real HTTP: alert -> normalization ->\n"
            "  dedup -> risk -> auto-incident -> mock AI analysis/summary/recommendation\n"
            "  -> approval queue -> human approval.\n"
            "  The durable-dispatch execution step is PostgreSQL-only (it commits the\n"
            "  pre-dispatch attempt on an independent MVCC connection); on SQLite it was\n"
            "  verified to FAIL CLOSED (no dispatch, no external call, no fabricated\n"
            "  outcome). Run the Demo on PostgreSQL (docker compose quickstart) for the\n"
            "  complete end-to-end 'demo smoke test: PASS'."
        )

    # Full Demo Mode (PostgreSQL / MVCC): the complete chain executes. ---
    _expect(status == 201, f"POST /executions expected 201, got {status} ({execution})")
    state = execution.get("derived_state")
    _expect(state == "succeeded", f"mock execution derived_state != succeeded: {state} ({execution})")
    ok("POST /api/v1/executions -> 201 (derived_state=succeeded, adapter=mock DryRun)")

    # 14. The execution is auditable (append-only log, full history).
    status, detail = _request("GET", _url(base, f"/api/v1/executions/{execution_id}"))
    _expect(status == 200, f"GET /executions/{{id}} expected 200, got {status}")
    _expect(len(detail.get("history", [])) >= 1, f"execution has no audit history: {detail}")
    ok(f"GET /api/v1/executions/{{id}} -> 200 (history rows={len(detail.get('history', []))})")

    # 15. Observability read models.
    status, metrics = _request("GET", _url(base, "/api/v1/executions/metrics"))
    _expect(status == 200, f"GET /executions/metrics expected 200, got {status}")
    _expect(metrics.get("total_chains", 0) >= 1, f"metrics show no chains: {metrics}")
    ok(f"GET /api/v1/executions/metrics -> 200 (total_chains={metrics.get('total_chains')})")

    status, health = _request("GET", _url(base, "/api/v1/executions/health"))
    _expect(status == 200, f"GET /executions/health expected 200, got {status}")
    ok("GET /api/v1/executions/health -> 200 (observed adapter health)")

    # 16. Manual reconcile fails CLOSED in Demo Mode: the production read-adapter
    # registry is intentionally empty, so this is a clean 404 (never a 500,
    # never a fabricated outcome). This asserts the trust boundary.
    status, recon = _request("POST", _url(base, f"/api/v1/executions/{execution_id}/reconcile"),
                             body={}, token=token)
    _expect(status in (404, 200),
            f"reconcile expected fail-closed 404 (or 200 with a reader), got {status} ({recon})")
    if status == 404:
        ok("POST /api/v1/executions/{id}/reconcile -> 404 (fail-closed, no read adapter — expected in Demo)")
    else:
        ok("POST /api/v1/executions/{id}/reconcile -> 200 (a read adapter is configured)")

    # 17. Dashboard now reflects the alert we submitted.
    status, dash1 = _request("GET", _url(base, "/api/v1/dashboard/summary"))
    _expect(status == 200, f"/dashboard/summary (post) expected 200, got {status}")
    _expect(dash1.get("today_alerts", 0) >= dash0.get("today_alerts", 0) + 1,
            f"today_alerts did not increase: before={dash0.get('today_alerts')} after={dash1.get('today_alerts')}")
    ok(f"GET /api/v1/dashboard/summary -> 200 (today_alerts={dash1.get('today_alerts')}, reflects the run)")

    return "SentinelFlow demo smoke test: PASS"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SentinelFlow Demo smoke test (HTTP black box).")
    parser.add_argument("--base-url", default=os.environ.get("SF_BASE_URL", "http://127.0.0.1:8000"),
                        help="backend base URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--token", default=None,
                        help="execution Bearer token (else $EXECUTION_TOKEN, else .env)")
    parser.add_argument("--env-file", default=None, help="optional .env path to read EXECUTION_TOKEN from")
    parser.add_argument("--wait", type=int, default=30,
                        help="seconds to wait for /ready before starting (0 to skip)")
    args = parser.parse_args(argv)

    token = _resolve_token(args)
    try:
        banner = run(args.base_url, token, args.wait)
    except SmokeError as exc:
        print(f"\nSentinelFlow demo smoke test: FAIL\n  {exc}", file=sys.stderr)
        return 1
    print(f"\n{banner}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
