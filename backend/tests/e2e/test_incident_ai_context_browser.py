"""Real-browser end-to-end test of the Incident AI view.

A genuine Chromium (Playwright) drives the real Vite app against the real
uvicorn backend over PostgreSQL: the shared harness in ``tests/e2e/harness.py``
takes the database URL from ``DATABASE_URL`` and fails the run when it is
unset or unreachable, so there is no SQLite fallback.

    /incidents/{id} -> GET /incidents/{id}/ai-context -> AI Investigation
    (Explanation history + Risk Summary history + Recommendation history
    with Approval audit — Observe/Review/Audit only, never Decide/Execute)

The four cases are seeded the same way the API-level chain was proven: every AI
row is produced through the REAL production endpoints (mock provider):

    POST /events/{id}/ai-analysis | ai-risk-summary | response-recommendation
    POST /response-recommendations/{id}/approve | reject

Only the event skeleton (AlertGroup + EventRisk + Incident) is seeded into
the database before boot — UI test data is never hand-pushed as AI rows.

The blocks below run in file order against one shared stack:
  A. full AI context: incident info, risk snapshot, AI Investigation with
     Explanation / Risk Summary / Recommendation / Approval audit visible
  B. approval states in a real browser: Approved + Rejected chips, and
     approval=null renders ONLY as "Pending Review" (never a stored value)
  C. multiple histories: 3×3×3 all visible — the real browser never
     collapses to "latest only"
  D. empty AI context: "No AI analysis available yet." (no error banner)
  E. partial pipeline: explanation only — the page stays healthy
  F. 404: unknown incident -> "Incident not found", no fake AI view
  G. risk snapshot freeze: 80 stays 80 after more AI history lands
  H. safety audit: the AI Investigation panel has ZERO buttons and no
     Execute/Block Now/Isolate Now/... affordance anywhere
  I. network whitelist: a page load issues ONLY GET .../ai-context (the
     dev-mode StrictMode remount may repeat the read-only GET once) and
     no POST of any kind (no generate/approve/reject/execute)

NOT part of the default suite: tests/e2e/ is excluded from collection by
tests/conftest.py; run explicitly with:

    pytest tests/e2e/test_incident_ai_context_browser.py -m browser -q

Requires playwright + pytest-playwright in the backend venv and
``python -m playwright install chromium``. A missing Playwright is a
collection error, never a skip. No Ollama call — AI_PROVIDER=mock pins
generation to the deterministic provider; this suite observes display
semantics, not model output.
"""
import re
import uuid
from collections.abc import Generator
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from playwright.sync_api import Page, expect

from tests.e2e import harness

pytestmark = pytest.mark.browser

SNAPSHOT_SCORE = 80


def _seed_database(db_url: str) -> dict:
    """Four events with EventRisk + Incident — the case records the browser
    will open. AI history is NOT seeded here: AI rows only ever come from the
    production endpoints.

    FULL    : 3 analyses + 3 summaries + 3 recommendations (1 approved,
              1 rejected, 1 pending) — blocks A/B/C/H/I
    EMPTY   : no AI history at all — block D
    PARTIAL : analysis only — block E
    SNAPSHOT: full chain used for the risk-score freeze — block G
    """
    from app.models import AlertGroup, EventRisk, Incident

    base = datetime.now(timezone.utc) - timedelta(hours=2)
    ids: dict = {}
    with harness.orm_session(db_url) as session:
        for index, name in enumerate(("FULL", "EMPTY", "PARTIAL", "SNAPSHOT")):
            created = base + timedelta(minutes=2 * index)
            group = AlertGroup(
                fingerprint=f"e2e-incident-ai-{name.lower()}" + "0" * 40,  # 64-char shape
                title=f"E2E Incident {name}",
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
                    score=SNAPSHOT_SCORE,
                    level="high",
                    factors=[{"name": "high_frequency", "score": 30, "reason": "E2E"}],
                    created_at=created,
                    updated_at=created,
                )
            )
            incident = Incident(
                alert_group_id=group.id,
                title=group.title,
                severity=group.severity,
                risk_score=SNAPSHOT_SCORE,  # creation-time snapshot
                created_at=created,
                updated_at=created,
            )
            session.add(incident)
            session.flush()
            ids[name] = {"event": str(group.id), "incident": str(incident.id)}
        session.commit()
    return ids


@pytest.fixture(scope="module")
def stack_seed():
    """Rows the module needs before uvicorn starts: (db_url) -> id map."""
    return _seed_database


def _seed_ai_via_api(ids: dict) -> None:
    """Produce ALL AI rows through the real production endpoints (mock
    provider) — the suite never hand-pushes AI rows into the database."""
    with harness.http_client() as api:

        def run_full_chain(event_id: str, rounds: int) -> list[str]:
            """One round = explanation + summary + recommendation. Returns
            the recommendation ids in creation order."""
            rec_ids: list[str] = []
            for _ in range(rounds):
                assert api.post(f"/api/v1/events/{event_id}/ai-analysis").status_code == 201
                assert (
                    api.post(f"/api/v1/events/{event_id}/ai-risk-summary").status_code
                    == 201
                )
                rec = api.post(f"/api/v1/events/{event_id}/response-recommendation")
                assert rec.status_code == 201
                rec_ids.append(rec.json()["id"])
            return rec_ids

        # FULL + SNAPSHOT: three rounds each. The rounds are sequential, so
        # the history order the "all visible" assertions rely on is
        # deterministic.
        full_recs = run_full_chain(ids["FULL"]["event"], 3)
        # Decision rows carry only approved/rejected.
        approve = api.post(
            f"/api/v1/response-recommendations/{full_recs[0]}/approve",
            json={"reviewer": "alice", "review_comment": "confirmed abuse"},
        )
        assert approve.status_code == 201
        reject = api.post(
            f"/api/v1/response-recommendations/{full_recs[1]}/reject",
            json={"reviewer": "bob", "review_comment": "scope too broad"},
        )
        assert reject.status_code == 201
        # full_recs[2] intentionally stays pending (approval === null).
        ids["FULL"]["recs"] = full_recs

        # PARTIAL: exactly one explanation, nothing else — a mid-pipeline case.
        assert (
            api.post(f"/api/v1/events/{ids['PARTIAL']['event']}/ai-analysis").status_code
            == 201
        )

        # SNAPSHOT: one full round AFTER the incident existed — the snapshot
        # must survive the extra AI history (block G).
        snapshot_recs = run_full_chain(ids["SNAPSHOT"]["event"], 1)
        approve = api.post(
            f"/api/v1/response-recommendations/{snapshot_recs[0]}/approve",
            json={"reviewer": "alice"},
        )
        assert approve.status_code == 201
        ids["SNAPSHOT"]["recs"] = snapshot_recs


@pytest.fixture(scope="module", autouse=True)
def ai_history(stack) -> None:
    """The AI rows come from the production endpoints, so they can only be
    created once uvicorn is serving: seed them after ``stack`` and before the
    first block."""
    _seed_ai_via_api(stack["ids"])


@pytest.fixture(scope="module")
def api() -> httpx.Client:
    """Direct backend access for DB-level audits."""
    with harness.http_client() as client:
        yield client


def _approval_statuses(db_url: str) -> list[str]:
    """Every stored approval status anywhere in the database."""
    from app.models import AIResponseApproval

    with harness.orm_session(db_url) as session:
        return [row.status for row in session.query(AIResponseApproval).all()]


# ---------------------------------------------------------------------------
# The browser journey (A-I run in order against one shared stack)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def journey(stack, browser_page: Page) -> Generator[dict, None, None]:
    """Shared journey state across the ordered block tests."""
    log = harness.NetworkLog()
    log.attach(browser_page)
    yield {
        "stack": stack,
        "page": browser_page,
        "requests": log.requests,
        "responses": log.responses,
    }


def _goto_incident(page: Page, incident_id: str) -> None:
    page.goto(f"{harness.BASE}/incidents/{incident_id}")


def _panel(page: Page, title: str):
    """The card panel whose heading is `title`."""
    return page.locator(".panel", has=page.locator(f"h2:text-is('{title}')"))


def _ai_panel(page: Page):
    return _panel(page, "AI Investigation")


def test_a_full_context_renders_the_complete_chain(journey):
    """14.6-A: incident info + risk snapshot + every AI section visible."""
    page: Page = journey["page"]
    _goto_incident(page, journey["stack"]["ids"]["FULL"]["incident"])

    # Incident header + case record stay intact.
    expect(
        page.get_by_role("heading", name="E2E Incident FULL")
    ).to_be_visible(timeout=harness.NAV_TIMEOUT)
    expect(page.locator(".kv .k", has_text="Risk Score (snapshot)")).to_be_visible()

    # AI Investigation with all four sub-views.
    panel = _ai_panel(page)
    expect(panel).to_be_visible()
    snapshot_line = panel.locator("p", has_text=re.compile(r"Risk Score \(snapshot\):"))
    expect(snapshot_line).to_be_visible()
    expect(snapshot_line).to_contain_text("80")
    expect(panel.get_by_text(re.compile(r"AI Explanation History \(3\)"))).to_be_visible()
    expect(panel.get_by_text(re.compile(r"Risk Summary History \(3\)"))).to_be_visible()
    expect(
        panel.get_by_text(re.compile(r"Response Recommendation History \(3\)"))
    ).to_be_visible()
    # Recommendation content + approval audit details.
    expect(panel.get_by_text("Block Source IP").first).to_be_visible()
    expect(panel.get_by_text("Approved").first).to_be_visible()
    expect(panel.get_by_text("alice").first).to_be_visible()


def test_b_approval_states_approved_rejected_pending(journey):
    """14.6-B: the browser sees Approved + Rejected chips, and the undecided
    recommendation renders ONLY as 'Pending Review' — never a raw 'pending'
    status, and never a stored one either."""
    page: Page = journey["page"]
    panel = _ai_panel(page)  # still on the FULL incident from block A

    expect(panel.get_by_text("Approved").first).to_be_visible()
    expect(panel.get_by_text("Rejected").first).to_be_visible()
    expect(panel.get_by_text("Pending Review")).to_be_visible()
    # Reviewer audit trail is present for the decided rows.
    expect(panel.get_by_text("alice").first).to_be_visible()
    expect(panel.get_by_text("bob").first).to_be_visible()
    # The UI word is the derived label — no bare pending status text, and the
    # database never stored one either.
    assert panel.get_by_text("pending", exact=True).count() == 0
    statuses = _approval_statuses(journey["stack"]["db_url"])
    assert set(statuses) == {"approved", "rejected"}
    assert "pending" not in statuses


def test_c_multiple_histories_all_visible(journey):
    """14.6-C: 3×3×3 — the real browser never collapses to latest-only."""
    page: Page = journey["page"]
    panel = _ai_panel(page)  # still on the FULL incident

    # The mock provider's deterministic texts repeat per round; the history
    # COUNTS in the headings plus the numbered entries prove completeness.
    for label in ("Analysis #3", "Analysis #2", "Analysis #1"):
        expect(panel.get_by_text(label)).to_be_visible()
    for label in ("Summary #3", "Summary #2", "Summary #1"):
        expect(panel.get_by_text(label)).to_be_visible()
    for label in ("Recommendation #3", "Recommendation #2", "Recommendation #1"):
        expect(panel.get_by_text(label)).to_be_visible()


def test_h_ai_panel_has_zero_buttons_and_no_execution_affordance(journey):
    """14.6-H: Observe/Review/Audit only — the AI Investigation panel renders
    ZERO buttons (no Approve/Reject, no Execute/Block Now/Isolate Now/...)."""
    page: Page = journey["page"]
    panel = _ai_panel(page)  # still on the FULL incident

    assert panel.get_by_role("button").count() == 0

    text = panel.inner_text()
    for forbidden in (
        "Execute",
        "Execute Now",
        "Block Now",
        "Isolate Now",
        "Disable Now",
        "Run Response",
        "Retry Execution",
        "Approve",
        "Reject",
    ):
        assert forbidden not in text, f"forbidden affordance rendered: {forbidden}"


def test_i_network_whitelist_get_only_exactly_once(journey):
    """14.6-I: one fresh page load issues ONLY GET .../ai-context and no
    POST of any kind — the view never generates, decides or executes.

    Dev-mode note: main.tsx wraps the app in <StrictMode>, so React 18
    mounts the panel twice in the vite dev server and the identical
    read-only GET can fire 1..2 times. The security boundary under test
    is that ZERO mutating traffic exists — never the dev remount count.
    (A production build runs effects exactly once.)"""
    page: Page = journey["page"]
    incident_id = journey["stack"]["ids"]["FULL"]["incident"]
    requests = journey["requests"]
    mark = len(requests)

    _goto_incident(page, incident_id)
    expect(
        _ai_panel(page).get_by_text(re.compile(r"AI Explanation History \(3\)"))
    ).to_be_visible(timeout=harness.NAV_TIMEOUT)

    fresh = requests[mark:]
    context_gets = [
        r for r in fresh
        if r["method"] == "GET" and r["url"].endswith(f"/incidents/{incident_id}/ai-context")
    ]
    assert 1 <= len(context_gets) <= 2, context_gets
    posts = [r for r in fresh if r["method"] == "POST"]
    assert posts == [], posts
    for forbidden in ("/approve", "/reject", "/execute", "/ai-analysis", "/ai-risk-summary", "/response-recommendation"):
        assert not any(forbidden in r["url"] for r in fresh), forbidden


def test_d_empty_context_is_a_legal_state(journey):
    """14.6-D: no AI history -> the legal empty message, never an error."""
    page: Page = journey["page"]
    _goto_incident(page, journey["stack"]["ids"]["EMPTY"]["incident"])

    panel = _ai_panel(page)
    expect(
        panel.get_by_text("No AI analysis available yet.")
    ).to_be_visible(timeout=harness.NAV_TIMEOUT)
    assert panel.locator(".error-banner").count() == 0
    expect(panel.get_by_text("Risk Score (snapshot):")).to_be_visible()


def test_e_partial_context_renders_cleanly(journey):
    """14.6-E: explanation only — the page never assumes a finished pipeline."""
    page: Page = journey["page"]
    _goto_incident(page, journey["stack"]["ids"]["PARTIAL"]["incident"])

    panel = _ai_panel(page)
    expect(
        panel.get_by_text(re.compile(r"AI Explanation History \(1\)"))
    ).to_be_visible(timeout=harness.NAV_TIMEOUT)
    expect(panel.get_by_text("Analysis #1")).to_be_visible()
    assert panel.get_by_text(re.compile(r"Risk Summary History")).count() == 0
    assert panel.get_by_text(re.compile(r"Response Recommendation History")).count() == 0
    assert panel.locator(".error-banner").count() == 0


def test_f_unknown_incident_404_leaks_nothing(journey):
    """14.6-F: an unknown incident answers the unified 404 and never mounts
    a fake AI Investigation view."""
    page: Page = journey["page"]
    _goto_incident(page, str(uuid.uuid4()))

    # The detail page renders the 404 banner full-page (no Loading limbo).
    expect(
        page.locator(".error-banner", has_text="Incident not found")
    ).to_be_visible(timeout=harness.NAV_TIMEOUT)
    assert page.get_by_text("AI Investigation").count() == 0
    # No FULL-case AI data can surface through the error path.
    assert page.get_by_text("E2E Incident FULL").count() == 0


def test_g_risk_snapshot_stays_80_after_more_ai_history(journey):
    """14.6-G: EventRisk=80, snapshot=80, then a full AI round + approval —
    the browser still sees ONLY 80 (14.4's freeze, echoed in the UI)."""
    page: Page = journey["page"]
    _goto_incident(page, journey["stack"]["ids"]["SNAPSHOT"]["incident"])

    panel = _ai_panel(page)
    expect(
        panel.get_by_text(re.compile(r"AI Explanation History \(1\)"))
    ).to_be_visible(timeout=harness.NAV_TIMEOUT)
    expect(panel.get_by_text("Approved")).to_be_visible()
    snapshot_line = panel.locator("p", has_text=re.compile(r"Risk Score \(snapshot\):"))
    expect(snapshot_line).to_contain_text("80")
    # No AI-invented score anywhere in the panel: the snapshot sentence is
    # the only place a bare risk score appears (confidence is a percentage).
    assert snapshot_line.count() == 1
