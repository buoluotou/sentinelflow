"""End-to-end test of the Approval Queue in a real browser.

A genuine Chromium (Playwright) drives the real Vite app against the real
uvicorn backend on the PostgreSQL database named by ``DATABASE_URL``:

    Approval Queue page -> GET /approvals -> pending recommendations
    Analyst fills reviewer -> Approve/Reject -> 201 -> item leaves the queue
    -> Approval Detail readable from persisted storage (Browser -> API ->
    DB -> API closed loop)

Journeys, in the order they run against the one shared stack:
  A. queue first render: 4 pending, backend order shown as-is
  B. approve A  (request body carries ONLY reviewer + review_comment)
  C. reject B   (queue shrinks to [C, D])
  D. cross-layer: GET /api/v1/approvals/{approval_id} proves DB persistence
  E. page reload: decided items never reappear
  F. approve C -> 1 pending, no error banner, no premature empty text
  G. concurrency: D decided out-of-band first -> browser Reject gets 409
     -> the server queue is re-fetched as the source of truth
  H. double-click guard: real DOM state during an artificially delayed POST
     (network-level delay + real 201 — never a mock instant response)
  I. safety audit: EventRisk / Incident / recommendation body untouched;
     the browser network whitelist admits only the approval endpoints

The stack comes from ``tests/e2e/harness.py``: it wipes the schema, runs
``alembic upgrade head``, seeds through ``stack_seed``, then boots uvicorn and
vite on the fixed ports 8000/5173 and tears the whole tree down again.

NOT part of the default suite: tests/e2e/ is excluded from collection by
tests/conftest.py; run explicitly with:

    SENTINELFLOW_BROWSER_E2E=1 \
    DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/sentinelflow \
    pytest tests/e2e/test_approval_queue_browser.py -m browser -q

Requires: playwright + pytest-playwright in the backend venv and
``python -m playwright install chromium``; a missing Playwright fails
collection instead of skipping. The harness pins AI_PROVIDER=mock, so no model
call is involved — the behaviour under test is human approval of existing
recommendations, not AI generation.
"""
import json
import re
import threading
import time
from collections.abc import Generator
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from playwright.sync_api import Page, expect

from tests.e2e import harness

pytestmark = pytest.mark.browser


def _seed_database(db_url: str) -> dict:
    """Four events A/B/C/D, each with an EventRisk and one recommendation.

    created_at is stamped explicitly with 2-minute gaps: the queue-order
    assertion needs a deterministic created_at ASC, id ASC instead of whatever
    the column default would stamp.
    """
    from app.models import AIResponseRecommendation, AlertGroup, EventRisk

    base = datetime.now(timezone.utc) - timedelta(hours=2)
    ids: dict = {}
    with harness.orm_session(db_url) as session:
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
    return ids


@pytest.fixture(scope="module")
def stack_seed():
    """Rows the module needs before uvicorn starts: (db_url) -> id map.

    Overrides the harness default; ``stack``, ``browser_page`` and
    ``browser_type_launch_args`` reach the journeys through the directory
    conftest, which re-exports the harness fixtures.
    """
    return _seed_database


@pytest.fixture(scope="module")
def api():
    """Direct backend access for out-of-band decisions and DB-level audits."""
    with harness.http_client() as client:
        yield client


def _audit_readonly(state: dict) -> dict:
    """Snapshot the must-not-change artefacts before any decision."""
    from app.models import AIResponseRecommendation, EventRisk, Incident

    with harness.orm_session(state["db_url"]) as session:
        risks = {
            str(r.alert_group_id): (r.score, r.level)
            for r in session.query(EventRisk).all()
        }
        recs = {
            str(r.id): (r.overall_rationale, json.dumps(r.recommendations, sort_keys=True))
            for r in session.query(AIResponseRecommendation).all()
        }
        incidents = session.query(Incident).count()
    return {"risks": risks, "recs": recs, "incidents": incidents}


# ---------------------------------------------------------------------------
# The browser journey (A-I run in order against one shared stack)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def journey(stack, browser_page: Page) -> Generator[dict, None, None]:
    """Shared journey state across the ordered journey tests."""
    network = harness.NetworkLog()
    network.attach(browser_page)
    before = _audit_readonly(stack)
    yield {
        "stack": stack,
        "page": browser_page,
        "requests": network.requests,
        "responses": network.responses,
        "before": before,
    }


def _goto_queue(page: Page) -> None:
    # No assertion on the transient "Loading approval queue…" text here: on a
    # localhost stack the queue can render before the assertion polls. The
    # loading/empty/error state machine is pinned by the unit suite.
    page.goto(f"{harness.BASE}/approvals")


def _panel(page: Page, title: str):
    """The card panel whose heading is `title`."""
    return page.locator(".panel", has=page.locator(f"h2:text-is('{title}')"))


def test_a_queue_first_render(journey):
    """4 pending on the first screen (D is only decided later, in the
    block-G race), backend order rendered as-is."""
    page: Page = journey["page"]
    _goto_queue(page)

    expect(page.get_by_text("4 pending")).to_be_visible()
    titles = page.locator(".panel h2").all_text_contents()
    # The seed created A < B < C < D by created_at — the page must NOT re-sort.
    assert titles == ["E2E Event A", "E2E Event B", "E2E Event C", "E2E Event D"], titles

    gets = [r for r in journey["requests"] if r["method"] == "GET"]
    assert any(r["url"].endswith("/api/v1/approvals") for r in gets)


def test_b_approve(journey, api):
    """Approve A — exact request body, local removal, no extra GET."""
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
    """Request body contract: ONLY {reviewer, review_comment}; never
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
    """After A approved + B rejected the queue is exactly [C, D]."""
    page: Page = journey["page"]
    expect(page.get_by_text("2 pending")).to_be_visible()
    titles = page.locator(".panel h2").all_text_contents()
    assert titles == ["E2E Event C", "E2E Event D"], titles


def test_d_approval_detail_persisted(journey, api):
    """Browser -> API -> DB -> API — the decision survives as a row."""
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
    """Reload the page — A and B must stay gone."""
    page: Page = journey["page"]
    page.reload()
    expect(page.get_by_text("2 pending")).to_be_visible()
    titles = page.locator(".panel h2").all_text_contents()
    assert titles == ["E2E Event C", "E2E Event D"], titles


def test_f_empty_queue_is_a_normal_state(journey):
    """Decide C too; D stays pending until the block-G race."""
    page: Page = journey["page"]
    _panel(page, "E2E Event C").get_by_role("button", name="Approve").click()

    expect(page.get_by_text("1 pending")).to_be_visible()
    expect(page.locator(".error-banner")).to_have_count(0)
    # D still pending: the friendly empty text must NOT appear prematurely.
    expect(page.get_by_text("No pending recommendations.")).to_have_count(0)


def test_g_concurrent_409_resyncs_from_server(journey, api):
    """The browser loads the queue while D is still pending; THEN a
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
    """Reseed a pending item, delay the POST at the network level
    (real 201 behind the delay — never a mock instant response) and verify
    the true DOM state plus exactly ONE request reaching the backend."""
    page: Page = journey["page"]
    rec_id = _seed_extra_recommendation(journey["stack"]["db_url"], "H")

    posts = harness.NetworkLog()
    posts.attach(page)

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
                    f"{harness.BACKEND_DIRECT}/api/v1/response-recommendations/{rec_id}/approve",
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

    posts_before = len(posts.posts())
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
    assert len(posts.posts()) - posts_before == 1  # exactly one POST reached the wire

    detail = httpx.get(f"{harness.BACKEND_DIRECT}/api/v1/approvals", timeout=10, proxy=None)
    assert detail.json() == []


def _seed_extra_recommendation(db_url: str, name: str) -> str:
    from app.models import AIResponseRecommendation, AlertGroup

    created = datetime.now(timezone.utc)
    with harness.orm_session(db_url) as session:
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
    return rec_id


def test_i_safety_audit(journey):
    """After the whole browser journey nothing executable happened,
    and the browser only ever talked to the approval endpoints."""
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
        if "/api/v1/" in r["url"].split(harness.BASE)[-1]
    ]
    assert api_calls, "expected API traffic to have been recorded"
    for r in api_calls:
        path = r["url"].split(harness.BASE)[-1].split("?")[0]
        assert path.startswith(allowed), f"forbidden endpoint hit: {r['url']}"
        for banned in ("/incidents", "/shuffle", "/wazuh", "/block", "/isolate"):
            assert banned not in r["url"]
