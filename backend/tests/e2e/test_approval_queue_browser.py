"""Step 13.6: REAL-BROWSER end-to-end test of the Approval Queue.

A genuine Chromium (Playwright) drives the real Vite app against the real
uvicorn backend over a throwaway SQLite database:

    Approval Queue page -> GET /approvals -> pending recommendations
    Analyst fills reviewer -> Approve/Reject -> 201 -> item leaves the queue
    -> Approval Detail readable from persisted storage (Browser -> API ->
    DB -> API closed loop)

Blocks, mirroring the frozen plan:
  A. queue first render: 3 pending, backend order shown as-is
  B. approve A  (request body carries ONLY reviewer + review_comment)
  C. reject B   (queue shrinks to [C])
  D. cross-layer: GET /api/v1/approvals/{approval_id} proves DB persistence
  E. page reload: decided items never reappear
  F. decide C -> 200 [] -> "No pending recommendations." (no 404, no banner)
  G. concurrency: D decided out-of-band first -> browser Reject gets 409
     -> the server queue is re-fetched as the source of truth
  H. double-click guard: REAL DOM state during an artificially delayed POST
     (network-level delay + real 201 — never a mock instant response)
  I. safety audit: EventRisk / Incident / recommendation body untouched;
     the browser network whitelist admits only the three approval endpoints

NOT part of the default suite: tests/e2e/ is excluded from collection by
tests/conftest.py; run explicitly with:

    pytest tests/e2e/test_approval_queue_browser.py -m browser -q

Requires: playwright + pytest-playwright in the backend venv and
``python -m playwright install chromium``. The module skips cleanly when
Playwright is missing, so an explicit run never breaks the machine.
Step 13.6-J: no Ollama call — the behaviour under test is human approval
of EXISTING recommendations, not AI generation (validated in Step 12).
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

try:
    import httpx
    from playwright.sync_api import Page, expect
except ImportError as exc:  # pragma: no cover - environment dependent
    pytest.skip(
        f"Playwright E2E dependencies missing ({exc}) — browser E2E skipped",
        allow_module_level=True,
    )

pytestmark = pytest.mark.browser

BACKEND_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIR = BACKEND_DIR.parent / "frontend"
PYTHON = sys.executable  # the backend venv interpreter running this suite

# The Vite dev proxy is frozen to http://localhost:8000 (vite.config.ts), so
# the E2E backend MUST bind 8000; the port-busy check below fails loudly
# instead of silently hitting a stray dev server.
BACKEND_PORT = 8000
FRONTEND_PORT = 5173
BASE = f"http://localhost:{FRONTEND_PORT}"
# Direct (non-browser) calls must pin IPv4: "localhost" may resolve to ::1,
# where an unrelated listener happily answers 502 Bad Gateway.
BACKEND_DIRECT = f"http://127.0.0.1:{BACKEND_PORT}"


def _port_busy(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex(("127.0.0.1", port)) == 0


if _port_busy(BACKEND_PORT) or _port_busy(FRONTEND_PORT):
    pytest.skip(
        f"Ports {BACKEND_PORT}/{FRONTEND_PORT} already in use — stop the dev "
        "servers (or any previous E2E run) before the browser E2E",
        allow_module_level=True,
    )


def _wait_http(url: str, timeout: float = 60.0) -> None:
    # ProxyHandler({}) disables ALL proxies: Windows registry proxies (VPN
    # clients etc.) silently hijack urllib localhost probes and answer 502.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + timeout
    last_error = "no attempt"
    while time.monotonic() < deadline:
        try:
            with opener.open(url, timeout=3) as resp:
                if resp.status < 500:
                    return
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_error = str(e)
        time.sleep(0.5)
    raise RuntimeError(f"{url} never came up: {last_error}")


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the whole process tree: `npm run dev` spawns cmd -> node ->
    esbuild children, and proc.terminate() only kills the shell, leaving an
    orphan vite that blocks the next run's port check."""
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True,
            check=False,
        )
    else:  # pragma: no cover - dev machines are Windows
        proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()


# ---------------------------------------------------------------------------
# Stack: throwaway SQLite DB -> seeded -> real uvicorn -> real vite -> Chromium
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def stack(tmp_path_factory) -> Generator[dict, None, None]:
    """Boot backend + frontend on a seeded throwaway DB; tear both down."""
    tmp = tmp_path_factory.mktemp("approval_e2e")
    db_path = tmp / "e2e_approvals.db"
    db_url = f"sqlite:///{db_path.as_posix()}"

    # Seed BEFORE the backend boots so both processes see the same rows.
    ids = _seed_database(db_url)

    backend_env = {
        **os.environ,
        "AI_PROVIDER": "mock",  # Step 13.6-J: this E2E never calls a model
        "DATABASE_URL": db_url,
    }
    # Proxy env vars silently hijack local HTTP probes (known session-switch
    # pitfall) — the browser stack must talk localhost only.
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        backend_env.pop(var, None)
    backend_env["NO_PROXY"] = "localhost,127.0.0.1"

    backend_proc = subprocess.Popen(
        [PYTHON, "-m", "uvicorn", "app.main:app", "--port", str(BACKEND_PORT)],
        cwd=str(BACKEND_DIR),
        env=backend_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    frontend_proc = subprocess.Popen(
        "npm run dev",  # npm is npm.cmd on Windows -> needs the shell
        cwd=str(FRONTEND_DIR),
        env=backend_env,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_http(f"http://localhost:{BACKEND_PORT}/health", timeout=60)
        _wait_http(BASE, timeout=90)
        yield {"ids": ids, "db_path": db_path, "db_url": db_url}
    finally:
        for proc in (frontend_proc, backend_proc):
            _kill_tree(proc)
        shutil.rmtree(tmp, ignore_errors=True)


def _seed_database(db_url: str) -> dict:
    """Four events A/B/C/D, each with an EventRisk and one recommendation.

    created_at is stamped explicitly (2-minute gaps): SQLite's
    CURRENT_TIMESTAMP is second-granular and the queue order assertion needs
    a deterministic created_at ASC, id ASC.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.core.database import Base
    from app.models import AIResponseRecommendation, AlertGroup, EventRisk

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    base = datetime.now(timezone.utc) - timedelta(hours=2)
    ids: dict = {}
    with Session() as session:
        for index, name in enumerate(("A", "B", "C", "D")):
            created = base + timedelta(minutes=2 * index)
            group = AlertGroup(
                fingerprint=f"e2e-approval-{name}" + "0" * 50,  # 64-char sha256 shape
                title=f"E2E Event {name}",
                category="brute_force",
                severity="high",
                alert_count=5,
                first_seen=created,
                last_seen=created,
                created_at=created,
                updated_at=created,
            )
            session.add(group)
            session.flush()
            session.add(
                EventRisk(
                    alert_group_id=group.id,
                    score=85,
                    level="high",
                    factors=[{"name": "high_frequency", "score": 30, "reason": "E2E"}],
                    created_at=created,
                    updated_at=created,
                )
            )
            rec = AIResponseRecommendation(
                alert_group_id=group.id,
                provider="mock",
                model="mock-response-recommender",
                overall_rationale=f"Coordinated response is recommended for event {name}.",
                recommendations=[
                    {
                        "action": "block_source_ip",
                        "target": f"203.0.113.{10 + index}",
                        "rationale": f"Repeated authentication abuse ({name}).",
                    }
                ],
                confidence=0.9,
                created_at=created,
                updated_at=created,
            )
            session.add(rec)
            session.flush()
            ids[name] = {"event": str(group.id), "rec": str(rec.id)}
        session.commit()
    engine.dispose()
    return ids


@pytest.fixture(scope="module")
def api() -> httpx.Client:
    """Direct backend access for out-of-band decisions and DB-level audits.
    proxy=None: trust_env would inherit the Windows system proxy and 502."""
    with httpx.Client(base_url=BACKEND_DIRECT, timeout=10, proxy=None) as c:
        yield c


def _audit_readonly(state: dict) -> dict:
    """Snapshot the must-not-change artefacts before any decision."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    engine = create_engine(state["db_url"], connect_args={"check_same_thread": False})
    with Session(engine) as session:
        from app.models import AIResponseRecommendation, EventRisk, Incident

        risks = {
            str(r.alert_group_id): (r.score, r.level)
            for r in session.query(EventRisk).all()
        }
        recs = {
            str(r.id): (r.overall_rationale, json.dumps(r.recommendations, sort_keys=True))
            for r in session.query(AIResponseRecommendation).all()
        }
        incidents = session.query(Incident).count()
    engine.dispose()
    return {"risks": risks, "recs": recs, "incidents": incidents}


# ---------------------------------------------------------------------------
# The browser journey (A-I run in order against one shared stack)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args) -> dict:
    """Chromium inherits the Windows system proxy (VPN clients etc.), which
    hijacks localhost traffic with 502s — the E2E stack is loopback-only."""
    return {**browser_type_launch_args, "args": ["--no-proxy-server"]}


@pytest.fixture(scope="module")
def browser_page(browser) -> Generator[Page, None, None]:
    """Module-scoped tab: the journey tests share ONE continuous browser
    session (a real reviewer workflow), mirroring the module-scoped stack."""
    ctx = browser.new_context()
    pg = ctx.new_page()
    yield pg
    ctx.close()


@pytest.fixture(scope="module")
def journey(stack, browser_page: Page) -> Generator[dict, None, None]:
    """Shared journey state across the ordered block tests."""
    requests: list = []
    browser_page.on("request", lambda r: requests.append({"url": r.url, "method": r.method}))
    before = _audit_readonly(stack)
    yield {"stack": stack, "page": browser_page, "requests": requests, "before": before}


def _goto_queue(page: Page) -> None:
    # No assertion on the transient "Loading approval queue…" text here: on a
    # localhost stack the queue can render before the assertion polls. The
    # loading/empty/error state machine is pinned by the 13.5 unit suite.
    page.goto(f"{BASE}/approvals")


def _panel(page: Page, title: str):
    """The card panel whose heading is `title`."""
    return page.locator(".panel", has=page.locator(f"h2:text-is('{title}')"))


def test_a_queue_first_render(journey):
    """13.6-A: 4 pending on the first screen (D is only decided later, in
    the block-G race), backend order rendered as-is."""
    page: Page = journey["page"]
    _goto_queue(page)

    expect(page.get_by_text("4 pending")).to_be_visible()
    titles = page.locator(".panel h2").all_text_contents()
    # The seed created A < B < C < D by created_at — the page must NOT re-sort.
    assert titles == ["E2E Event A", "E2E Event B", "E2E Event C", "E2E Event D"], titles

    gets = [r for r in journey["requests"] if r["method"] == "GET"]
    assert any(r["url"].endswith("/api/v1/approvals") for r in gets)


def test_b_approve(journey, api):
    """13.6-B: approve A — exact request body, local removal, no extra GET."""
    page: Page = journey["page"]
    ids = journey["stack"]["ids"]

    panel = _panel(page, "E2E Event A")
    panel.get_by_label("Review comment").fill("Confirmed malicious activity.")
    gets_before = len([r for r in journey["requests"] if r["method"] == "GET"])

    with page.expect_response(
        f"**/response-recommendations/{ids['A']['rec']}/approve"
    ) as info:
        panel.get_by_role("button", name="Approve").click()
    response = info.value
    assert response.status == 201

    expect(page.get_by_text("3 pending")).to_be_visible()
    expect(page.get_by_text("E2E Event A")).to_have_count(0)
    expect(page.get_by_text("E2E Event B")).to_be_visible()
    expect(page.get_by_text("E2E Event C")).to_be_visible()
    expect(page.get_by_text("E2E Event D")).to_be_visible()  # untouched by A's decision

    posts = [
        r for r in journey["requests"]
        if r["method"] == "POST" and r["url"].endswith("/approve")
    ]
    assert len(posts) == 1
    gets_after = len([r for r in journey["requests"] if r["method"] == "GET"])
    assert gets_after == gets_before  # 201 -> local removal, no follow-up GET
    journey["a_approval_id"] = response.json()["id"]


def test_b_request_body_is_minimal(journey):
    """13.6-B body contract: ONLY {reviewer, review_comment}; never
    reviewed_at / status / action / target."""
    page: Page = journey["page"]
    captured: list[dict] = []

    def capture(route):
        # post_data_json is a PROPERTY in Playwright Python (calling it raises
        # "'dict' object is not callable").
        captured.append(route.request.post_data_json)
        route.continue_()

    ids = journey["stack"]["ids"]
    page.route(f"**/response-recommendations/{ids['B']['rec']}/reject", capture)
    _panel(page, "E2E Event B").get_by_role("button", name="Reject").click()
    expect(page.get_by_text("2 pending")).to_be_visible()

    assert captured == [{"reviewer": "analyst-01", "review_comment": None}]
    for forbidden in ("reviewed_at", "status", "action", "target"):
        assert forbidden not in captured[0]


def test_c_queue_after_reject(journey):
    """13.6-C: after A approved + B rejected the queue is exactly [C, D]."""
    page: Page = journey["page"]
    expect(page.get_by_text("2 pending")).to_be_visible()
    titles = page.locator(".panel h2").all_text_contents()
    assert titles == ["E2E Event C", "E2E Event D"], titles


def test_d_approval_detail_persisted(journey, api):
    """13.6-D: Browser -> API -> DB -> API — the decision survives as a row."""
    approval_id = journey["a_approval_id"]
    resp = api.get(f"/api/v1/approvals/{approval_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "approved"
    assert body["reviewer"] == "analyst-01"
    assert body["review_comment"] == "Confirmed malicious activity."
    assert body["reviewed_at"] is not None  # stamped by the SERVER

    rejected = api.get("/api/v1/approvals")
    assert rejected.status_code == 200
    remaining = [item["id"] for item in rejected.json()]
    assert journey["stack"]["ids"]["C"]["rec"] in remaining


def test_e_refresh_never_resurrects_decided_items(journey):
    """13.6-E: reload the page — A and B must stay gone."""
    page: Page = journey["page"]
    page.reload()
    expect(page.get_by_text("2 pending")).to_be_visible()
    titles = page.locator(".panel h2").all_text_contents()
    assert titles == ["E2E Event C", "E2E Event D"], titles


def test_f_empty_queue_is_a_normal_state(journey):
    """13.6-F: decide C too; D stays pending until the block-G race."""
    page: Page = journey["page"]
    _panel(page, "E2E Event C").get_by_role("button", name="Approve").click()

    expect(page.get_by_text("1 pending")).to_be_visible()
    expect(page.locator(".error-banner")).to_have_count(0)
    # D still pending: the friendly empty text must NOT appear prematurely.
    expect(page.get_by_text("No pending recommendations.")).to_have_count(0)


def test_g_concurrent_409_resyncs_from_server(journey, api):
    """13.6-G: the browser loads the queue while D is still pending; THEN a
    rival reviewer decides D out-of-band. The browser's Reject must receive
    409 and resync — the server queue is the source of truth."""
    page: Page = journey["page"]
    ids = journey["stack"]["ids"]

    page.reload()
    expect(page.get_by_text("1 pending")).to_be_visible()  # D still listed locally

    rival = api.post(
        f"/api/v1/response-recommendations/{ids['D']['rec']}/approve",
        json={"reviewer": "analyst-02"},
    )
    assert rival.status_code == 201  # the other reviewer wins the race

    with page.expect_response(
        f"**/response-recommendations/{ids['D']['rec']}/reject"
    ) as info:
        _panel(page, "E2E Event D").get_by_role("button", name="Reject").click()
    assert info.value.status == 409

    # 409 -> re-GET /approvals -> D disappeared (server truth), no crash.
    expect(page.get_by_text("No pending recommendations.")).to_be_visible()
    expect(page.locator(".error-banner")).to_have_count(0)
    expect(page.get_by_text("E2E Event D")).to_have_count(0)


def test_h_double_click_guard_with_real_delay(journey):
    """13.6-H: reseed a pending item, delay the POST at the network level
    (real 201 behind the delay — never a mock instant response) and verify
    the true DOM state plus exactly ONE request reaching the backend."""
    page: Page = journey["page"]
    rec_id = _seed_extra_recommendation(journey["stack"]["db_url"], "H")

    api_posts = []
    page.on("request", lambda r: api_posts.append(r) if r.method == "POST" else None)

    route_errors: list[str] = []

    def slow_approve(route):
        # Artificial API latency, answered from a BACKGROUND thread: sleeping
        # inside the handler itself would stall the Playwright loop and defer
        # every assertion until after the response lands. The request stays
        # genuinely in flight for the whole window, then the REAL backend
        # answer (a real 201, never a mock) is fulfilled.
        request = route.request

        def answer():
            try:
                time.sleep(1.5)
                body = json.loads(request.post_data) if request.post_data else {}
                forwarded = httpx.post(
                    f"{BACKEND_DIRECT}/api/v1/response-recommendations/{rec_id}/approve",
                    json=body,
                    timeout=30,
                    proxy=None,
                )
                route.fulfill(
                    status=forwarded.status_code,
                    headers={"Content-Type": "application/json"},
                    body=forwarded.content,
                )
            except Exception as e:  # surface thread failures in the assertion
                route_errors.append(f"{type(e).__name__}: {e}")

        threading.Thread(target=answer, daemon=True).start()

    page.route(f"**/response-recommendations/{rec_id}/approve", slow_approve)

    page.reload()
    expect(page.get_by_text("1 pending")).to_be_visible()
    panel = _panel(page, "E2E Event H")
    # Regex names: while in flight the labels switch to "Approving…" /
    # "Rejecting…" and an exact-match locator would stop matching mid-busy.
    approve = panel.get_by_role("button", name=re.compile(r"^Approv"))
    reject = panel.get_by_role("button", name=re.compile(r"^Reject"))

    posts_before = len(api_posts)
    # no_wait_after: with the sync Playwright API, click() would otherwise
    # block through the whole (deliberately slow) route handler — the busy
    # state must be asserted WHILE the POST is still in flight.
    approve.click(no_wait_after=True)
    expect(panel.get_by_text("Approving…")).to_be_visible()  # real DOM state
    expect(approve).to_be_disabled()
    expect(reject).to_be_disabled()
    assert not route_errors, f"route thread failed: {route_errors}"
    approve.click(no_wait_after=True, force=True)  # hammer it — no second POST

    expect(page.get_by_text("No pending recommendations.")).to_be_visible(timeout=45_000)
    time.sleep(0.3)  # let any stray request flush into the listener
    assert len(api_posts) - posts_before == 1  # exactly one POST reached the wire

    detail = httpx.get(f"{BACKEND_DIRECT}/api/v1/approvals", timeout=10, proxy=None)
    assert detail.json() == []


def _seed_extra_recommendation(db_url: str, name: str) -> str:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.models import AIResponseRecommendation, AlertGroup

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    created = datetime.now(timezone.utc)
    with Session() as session:
        group = AlertGroup(
            fingerprint=f"e2e-approval-{name}" + "1" * 50,
            title=f"E2E Event {name}",
            category="brute_force",
            severity="high",
            alert_count=1,
            first_seen=created,
            last_seen=created,
            created_at=created,
            updated_at=created,
        )
        session.add(group)
        session.flush()
        rec = AIResponseRecommendation(
            alert_group_id=group.id,
            provider="mock",
            model="mock-response-recommender",
            overall_rationale=f"Late recommendation for event {name}.",
            recommendations=[
                {"action": "monitor_only", "target": f"host-{name}", "rationale": "Watch."}
            ],
            confidence=0.5,
            created_at=created,
            updated_at=created,
        )
        session.add(rec)
        session.commit()
        rec_id = str(rec.id)
    engine.dispose()
    return rec_id


def test_i_safety_audit(journey):
    """13.6-I: after the whole browser journey nothing executable happened,
    and the browser only ever talked to the three approval endpoints."""
    state = journey["stack"]
    before = journey["before"]
    after = _audit_readonly(state)

    # EventRisk untouched: score AND level of every event unchanged.
    assert after["risks"] == before["risks"]
    # Recommendation bodies untouched: approving never edits the AI advice.
    for rec_id, snapshot in before["recs"].items():
        assert after["recs"][rec_id] == snapshot, f"recommendation {rec_id} mutated"
    # No Incident was ever created by any approval decision.
    assert before["incidents"] == after["incidents"] == 0

    # Network whitelist: every API request the browser issues is queue or
    # decision traffic. Vite dev-server module URLs (/src/api/*.ts) are NOT
    # API calls — only paths under /api/v1 count.
    allowed = (
        "/api/v1/approvals",
        "/api/v1/response-recommendations/",
    )
    api_calls = [
        r for r in journey["requests"]
        if "/api/v1/" in r["url"].split(BASE)[-1]
    ]
    assert api_calls, "expected API traffic to have been recorded"
    for r in api_calls:
        path = r["url"].split(BASE)[-1].split("?")[0]
        assert path.startswith(allowed), f"forbidden endpoint hit: {r['url']}"
        for banned in ("/incidents", "/shuffle", "/wazuh", "/block", "/isolate"):
            assert banned not in r["url"]
