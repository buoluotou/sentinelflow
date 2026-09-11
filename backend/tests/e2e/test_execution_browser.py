"""Browser E2E for the response-execution chain, on PostgreSQL.

Chromium drives the real vite console against a real uvicorn backend and a
PostgreSQL database built by ``alembic upgrade head``. The business chain runs
end to end through the UI:

    alert -> event -> incident -> recommendation -> approval -> execution
    (mock adapter) -> the execution in the audit list and its detail page

Journeys:
    a  the stack runs on PostgreSQL at the migration head
    b  an ingested alert reaches the dashboard, the event list and the case queue
    c  the event page generates the recommendation; the case shows it pending
    d  the approval queue approves it through the UI
    e  the case offers Execute only for the approved recommendation
    f  Execute in the browser succeeds through the mock adapter
    g  the execution appears in the audit list and its detail page
    h  the observability page reports the execution
    i  a compensation renders both relation directions
    j  a second execution of the same approval is refused
    k  a wrong token writes nothing
    l  a guard-rejected action renders as status
    m  adapter failures render Failed with their classification
    n  the token never leaves the modal and the one request header

The journeys share one module-scoped stack and one browser tab, and run in file
order; each records what it produced in ``CENTRAL`` for the next one.

Recommendations and approvals always come from the real endpoints. Only the
event skeletons behind the negative journeys (an advisory-only action, a
rejected credential, three adapter failures) are inserted directly, because the
mock provider cannot produce those shapes on demand.

The mock adapter is the only executor, so the run makes no external request and
needs no credential beyond the local execution token.

    SENTINELFLOW_BROWSER_E2E=1 DATABASE_URL=postgresql+psycopg://... \
        python -m pytest tests/e2e/test_execution_browser.py -m browser -q
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from playwright.sync_api import Page, expect

from tests.e2e import harness

pytestmark = pytest.mark.browser

EXECUTIONS_URL = "/api/v1/executions"
COMPENSATE_URL = "/api/v1/executions/compensate"

#: TEST-NET-3 (RFC 5737): the risk engine treats documentation ranges as
#: non-public, so the ingested alert scores exactly 70 — severity only.
TARGET_IP = "203.0.113.10"
#: The title of the event the central journey ingests; it also becomes the
#: incident title and the approval-queue heading.
ALERT_TITLE = "E2E response chain IOC match"
#: Typed into the Execute modal and never recorded: the server binds the
#: operator identity to the token instead.
CLIENT_TYPED_OPERATOR = "ops-e2e"
#: Credentials an operator confirms with. Journey f, l and the three inside m
#: each send it once, so the leakage audit expects exactly this many.
EXPECTED_TOKEN_POSTS = 5

#: Adapter failure classifications and the seeded case each is injected into.
FAILURE_CASES = (
    ("timeout", "FAIL_TIMEOUT"),
    ("adapter_unavailable", "FAIL_UNAVAILABLE"),
    ("adapter_error", "FAIL_ERROR"),
)

#: Ids produced by the central journey, read back by the later ones.
CENTRAL: dict[str, str] = {}

#: Event skeletons for the negative journeys: (case name, risk score). The
#: scores select what the mock provider recommends — 40..69 yields the advisory
#: hunt_related_activity, >= 70 the executable block_source_ip.
EVENT_CASES = (
    ("GUARD_API", 55),
    ("WRONG_TOKEN", 80),
    ("FAIL_TIMEOUT", 80),
    ("FAIL_UNAVAILABLE", 80),
    ("FAIL_ERROR", 80),
)


# ---------------------------------------------------------------------------
# API and database helpers
# ---------------------------------------------------------------------------


def _auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {harness.EXECUTION_TOKEN}"}


def _execution_rows(db_url: str, approval_id: str | None = None) -> list[tuple]:
    """execution_log rows in chain order as
    (decision, direction, operator, execution_id, action, target, detail)."""
    from sqlalchemy.orm import Session

    from app.models import ExecutionLog

    engine = harness.engine_for(db_url)
    try:
        with Session(engine) as session:
            query = session.query(ExecutionLog)
            if approval_id is not None:
                query = query.filter(ExecutionLog.approval_id == uuid.UUID(approval_id))
            return [
                (
                    row.decision,
                    row.direction,
                    row.operator,
                    str(row.execution_id),
                    row.action,
                    row.target,
                    row.detail,
                )
                for row in query.order_by(ExecutionLog.created_at, ExecutionLog.id).all()
            ]
    finally:
        engine.dispose()


def _execution_count(db_url: str) -> int:
    return len(_execution_rows(db_url))


def _approval_decision(db_url: str, approval_id: str) -> tuple[str, str]:
    """(status, reviewer) of one recorded decision."""
    from app.models import AIResponseApproval

    with harness.orm_session(db_url) as session:
        row = session.get(AIResponseApproval, uuid.UUID(approval_id))
        assert row is not None, f"no approval row {approval_id}"
        return row.status, row.reviewer


def _post_alert() -> str:
    """Submit one alert through the simulator contract; returns the event id.

    A critical alert scores 70, which is the auto-incident threshold, so the
    ingestion pipeline opens the case the console then shows.
    """
    payload = {
        "source": "e2e-browser",
        "event_type": "malicious_ioc",
        "severity": "critical",
        "title": ALERT_TITLE,
        "message": "Outbound connection to a known C2 server (browser E2E)",
        "source_ip": TARGET_IP,
        "host": {"hostname": "e2e-host-01", "ip": "192.0.2.50"},
        "raw_data": {"ioc_type": "ip", "ioc_value": TARGET_IP},
    }
    with harness.http_client() as api:
        response = api.post("/api/v1/alerts", json=payload)
        assert response.status_code == 201, response.text
        event_id = response.json()["alert_group_id"]
    assert event_id, "POST /api/v1/alerts returned no alert_group_id"
    return event_id


def _seed_event_skeleton(db_url: str) -> dict:
    """Event skeletons for the negative journeys.

    Each case gets an AlertGroup, an EventRisk snapshot at a fixed score, the
    incident the console opens and one evidence Alert carrying the source IP the
    Guard resolves as the execution target. Recommendations and approvals are
    still produced by the real endpoints after boot.
    """
    from app.models import Alert, AlertGroup, EventRisk, Incident

    base = datetime.now(timezone.utc) - timedelta(hours=2)
    ids: dict = {}
    with harness.orm_session(db_url) as session:
        for index, (name, score) in enumerate(EVENT_CASES):
            created = base + timedelta(minutes=2 * index)
            group = AlertGroup(
                fingerprint=f"e2e-exec-{name.lower()}".ljust(64, "0"),
                title=f"E2E Execution {name}",
                category="brute_force",
                severity="high",
                alert_count=3,
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
                    score=score,
                    level="high" if score >= 70 else "medium",
                    factors=[{"name": "high_frequency", "score": 30, "reason": "E2E"}],
                    created_at=created,
                    updated_at=created,
                )
            )
            incident = Incident(
                alert_group_id=group.id,
                title=group.title,
                severity=group.severity,
                risk_score=score,
                created_at=created,
                updated_at=created,
            )
            session.add(incident)
            session.add(
                Alert(
                    source="e2e",
                    event_type="ssh_brute_force",
                    severity="high",
                    status="open",
                    title=f"E2E evidence for {name}",
                    source_ip=TARGET_IP,
                    first_seen_at=created,
                    last_seen_at=created,
                    event_count=3,
                    alert_group_id=group.id,
                )
            )
            session.flush()
            ids[name] = {"event": str(group.id), "incident": str(incident.id)}
        session.commit()
    return ids


@pytest.fixture(scope="module")
def stack_seed():
    """Rows the module needs before uvicorn starts."""
    return _seed_event_skeleton


@pytest.fixture(scope="module")
def seeded(stack) -> dict:
    """Recommendations and approvals for the negative journeys, via the API."""
    ids = stack["ids"]
    with harness.http_client() as api:
        for name, _score in EVENT_CASES:
            created = api.post(
                f"/api/v1/events/{ids[name]['event']}/response-recommendation"
            )
            assert created.status_code == 201, created.text
            approved = api.post(
                f"/api/v1/response-recommendations/{created.json()['id']}/approve",
                json={"reviewer": "e2e-seed", "review_comment": "E2E seed approval"},
            )
            assert approved.status_code == 201, approved.text
            ids[name]["approval"] = approved.json()["id"]
    return ids


@pytest.fixture(scope="module")
def journey(seeded, stack, browser_page: Page):
    """The shared tab plus the full network record of the module."""
    log = harness.NetworkLog()
    log.attach(browser_page)
    yield {"stack": stack, "page": browser_page, "log": log}


# ---------------------------------------------------------------------------
# Page helpers
# ---------------------------------------------------------------------------


def _card_value(page: Page, label: str) -> str:
    """The value a stat card shows, addressed by its label."""
    card = page.locator(".stat-card").filter(has_text=label).first
    expect(card).to_be_visible(timeout=harness.NAV_TIMEOUT)
    return card.locator(".value").inner_text().strip()


def _dashboard_counts(page: Page) -> dict[str, int]:
    page.goto(f"{harness.BASE}/")
    expect(page.get_by_role("heading", name="Dashboard")).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    labels = ("Active Incidents", "Today's Alerts", "Today's Events")
    return {label: int(_card_value(page, label)) for label in labels}


def _panel(page: Page, title: str):
    """The panel whose own heading is `title`.

    Panels nest (the AI Investigation panel contains the execution console), so
    the heading is matched as a direct child.
    """
    return page.locator(".panel").filter(
        has=page.locator(f":scope > h2:text-is('{title}')")
    )


def _open_case(page: Page, title: str) -> None:
    """Open the incident queue and click the case titled `title`."""
    page.goto(f"{harness.BASE}/incidents")
    expect(page.get_by_role("heading", name="Incident Queue")).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    page.locator("tr.clickable", has_text=title).click()
    expect(page.get_by_role("heading", name=title, exact=True)).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )


def _execute_via_modal(
    page: Page, log: harness.NetworkLog, *, token: str, operator: str = CLIENT_TYPED_OPERATOR
) -> int:
    """Open the Execute modal, fill the fields by hand and confirm.

    Returns the request-log mark taken just before the Confirm click, which is
    the boundary the safety assertions read.
    """
    page.get_by_role("button", name="Execute", exact=True).click()
    modal = page.locator(
        "div.panel", has=page.locator("h3:text-is('Execute Response')")
    ).last
    expect(modal).to_be_visible(timeout=harness.NAV_TIMEOUT)
    modal.get_by_label("Operator").fill(operator)
    modal.get_by_label("Execution Token").fill(token)
    mark = log.mark()
    modal.get_by_role("button", name="Confirm Execute").click()
    return mark


# ---------------------------------------------------------------------------
# a: the stack itself
# ---------------------------------------------------------------------------


def test_a_stack_runs_on_postgresql_at_the_migration_head(stack):
    """The suite is PostgreSQL-only: the schema came from the migrations and the
    dialect is not SQLite, where the durable dispatch fails closed."""
    from sqlalchemy import inspect, text

    engine = harness.engine_for(stack["db_url"])
    try:
        with engine.connect() as connection:
            assert connection.dialect.name == "postgresql"
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            tables = set(inspect(connection).get_table_names())
    finally:
        engine.dispose()

    assert revision == harness.alembic_head()
    assert {"alert_groups", "event_risk", "incidents", "execution_log", "dispatch_attempt"} <= tables


# ---------------------------------------------------------------------------
# b: alert -> event -> incident, seen in the console
# ---------------------------------------------------------------------------


def test_b_alert_reaches_the_dashboard_events_and_case_queue(journey):
    """One ingested alert becomes an event with a risk snapshot and a case, and
    the console shows it: dashboard counters, the event list, the case queue."""
    page: Page = journey["page"]

    before = _dashboard_counts(page)
    event_id = _post_alert()
    CENTRAL["event"] = event_id

    after = _dashboard_counts(page)
    assert after["Today's Alerts"] >= before["Today's Alerts"] + 1
    assert after["Today's Events"] >= before["Today's Events"] + 1
    assert after["Active Incidents"] >= before["Active Incidents"] + 1

    with harness.http_client() as api:
        detail = api.get(f"/api/v1/events/{event_id}")
        assert detail.status_code == 200, detail.text
        risk = detail.json()["risk"]
    assert risk["score"] >= 70, risk

    page.goto(f"{harness.BASE}/events")
    expect(page.get_by_role("heading", name="Events")).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    row = page.locator("tr.clickable", has_text=ALERT_TITLE)
    expect(row).to_be_visible()
    # The list renders the API's own snapshot, never a recomputed one.
    expect(row.get_by_text(str(risk["score"]), exact=True)).to_be_visible()
    expect(row.get_by_text(risk["level"], exact=True)).to_be_visible()

    page.goto(f"{harness.BASE}/incidents")
    expect(page.get_by_role("heading", name="Incident Queue")).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    expect(page.locator("tr.clickable", has_text=ALERT_TITLE)).to_be_visible()


def test_c_event_page_generates_the_recommendation_and_the_case_shows_it_pending(journey):
    """The event detail page triggers the recommendation through the real
    endpoint; the case shows it as Pending Review with no execution affordance."""
    page: Page = journey["page"]
    log: harness.NetworkLog = journey["log"]

    page.goto(f"{harness.BASE}/events/{CENTRAL['event']}")
    expect(page.get_by_role("heading", name=ALERT_TITLE, exact=True)).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    panel = _panel(page, "Response Recommendation")
    expect(panel).to_be_visible(timeout=harness.NAV_TIMEOUT)
    expect(panel.get_by_text("No recommendation generated yet.")).to_be_visible()

    mark = log.mark()
    panel.get_by_role("button", name="Generate Response Recommendation").click()
    expect(panel.get_by_text("Block Source IP")).to_be_visible(timeout=harness.NAV_TIMEOUT)
    expect(panel.get_by_text(TARGET_IP)).to_be_visible()
    expect(panel.get_by_text("mock", exact=True).first).to_be_visible()
    assert len(log.posts_to(f"/events/{CENTRAL['event']}/response-recommendation", mark)) == 1

    with harness.http_client() as api:
        latest = api.get(f"/api/v1/events/{CENTRAL['event']}/response-recommendation")
        assert latest.status_code == 200, latest.text
        actions = [item["action"] for item in latest.json()["recommendations"]]
    assert actions == ["block_source_ip", "escalate_to_incident"], actions

    # The case is open with the incident the pipeline created, showing the
    # recommendation as pending and no way to execute it.
    mark = log.mark()
    _open_case(page, ALERT_TITLE)
    ai_panel = _panel(page, "AI Investigation")
    expect(
        ai_panel.get_by_role("heading", name="Response Recommendation History (1)")
    ).to_be_visible(timeout=harness.NAV_TIMEOUT)
    expect(ai_panel.get_by_text("Pending Review", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Execute", exact=True)).to_have_count(0)
    expect(page.get_by_role("button", name="Approve", exact=True)).to_have_count(0)
    assert log.posts(mark) == []


# ---------------------------------------------------------------------------
# d: approval queue
# ---------------------------------------------------------------------------


def test_d_approval_queue_approves_through_the_ui(journey):
    """The queue lists the pending recommendation, the analyst approves it and
    the item leaves the queue; the recorded reviewer is what the UI submitted."""
    page: Page = journey["page"]
    log: harness.NetworkLog = journey["log"]
    stack = journey["stack"]

    page.goto(f"{harness.BASE}/approvals")
    expect(page.get_by_role("heading", name="Approval Queue")).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    item = _panel(page, ALERT_TITLE)
    expect(item).to_be_visible(timeout=harness.NAV_TIMEOUT)
    expect(item.get_by_text("Block Source IP")).to_be_visible()
    expect(item.get_by_text(TARGET_IP)).to_be_visible()
    expect(item.get_by_role("button", name="Execute", exact=True)).to_have_count(0)

    page.get_by_label("Reviewer").fill("e2e-browser")
    mark = log.mark()
    item.get_by_role("button", name="Approve", exact=True).click()
    expect(item).to_have_count(0, timeout=harness.NAV_TIMEOUT)

    approvals = log.posts_to("/approve", mark)
    assert len(approvals) == 1, approvals

    with harness.http_client() as api:
        queue = api.get("/api/v1/approvals")
        assert queue.status_code == 200, queue.text
        assert [row["event_title"] for row in queue.json()] == []

    approval_id = _approval_id_of(stack["db_url"], CENTRAL["event"])
    CENTRAL["approval"] = approval_id
    status, reviewer = _approval_decision(stack["db_url"], approval_id)
    assert (status, reviewer) == ("approved", "e2e-browser")


def _approval_id_of(db_url: str, event_id: str) -> str:
    """The approval recorded for the event's latest recommendation."""
    from sqlalchemy import select

    from app.models import AIResponseApproval, AIResponseRecommendation

    with harness.orm_session(db_url) as session:
        recommendation_id = session.scalars(
            select(AIResponseRecommendation.id)
            .where(AIResponseRecommendation.alert_group_id == uuid.UUID(event_id))
            .order_by(AIResponseRecommendation.created_at.desc())
            .limit(1)
        ).one()
        approval_id = session.scalars(
            select(AIResponseApproval.id).where(
                AIResponseApproval.recommendation_id == recommendation_id
            )
        ).one()
    return str(approval_id)


# ---------------------------------------------------------------------------
# e / f: the case offers Execute, then the browser executes it
# ---------------------------------------------------------------------------


def test_e_case_offers_execute_only_for_the_approved_recommendation(journey):
    """Reloading the case after the approval shows the Approved chip and the
    Execute console; the page load itself still writes nothing."""
    page: Page = journey["page"]
    log: harness.NetworkLog = journey["log"]

    mark = log.mark()
    _open_case(page, ALERT_TITLE)
    ai_panel = _panel(page, "AI Investigation")
    expect(ai_panel.get_by_text("Approved", exact=True)).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    expect(page.get_by_role("button", name="Execute", exact=True)).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    # Page load is read-only: only the execution status GETs run.
    assert log.posts(mark) == []
    status_gets = [
        item
        for item in log.since(mark)
        if item["method"] == "GET" and EXECUTIONS_URL in item["url"]
    ]
    assert 1 <= len(status_gets) <= 2, status_gets


def test_f_execute_through_the_ui_succeeds_with_the_mock_adapter(journey):
    """Approved recommendation -> Execute -> token -> Confirm -> 201 ->
    Succeeded, backed by a requested -> dispatched -> succeeded chain."""
    page: Page = journey["page"]
    log: harness.NetworkLog = journey["log"]
    stack = journey["stack"]
    approval_id = CENTRAL["approval"]

    _open_case(page, ALERT_TITLE)
    expect(page.get_by_role("button", name="Execute", exact=True)).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    mark = _execute_via_modal(page, log, token=harness.EXECUTION_TOKEN)

    expect(page.get_by_text("Succeeded", exact=True)).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    expect(page.get_by_text("requested → dispatched → succeeded")).to_be_visible()
    expect(page.get_by_text(harness.OPERATOR).first).to_be_visible()

    posts = log.posts_to(EXECUTIONS_URL, mark)
    assert len(posts) == 1, posts
    assert posts[0]["headers"]["authorization"] == f"Bearer {harness.EXECUTION_TOKEN}"
    # The 201 body is authoritative: no follow-up GET after the POST.
    assert [item for item in log.since(mark) if item["method"] == "GET"] == []

    rows = _execution_rows(stack["db_url"], approval_id=approval_id)
    assert [row[0] for row in rows] == ["requested", "dispatched", "succeeded"]
    assert all(row[2] == harness.OPERATOR for row in rows)
    assert rows[0][4] == "block_source_ip" and rows[0][5] == TARGET_IP
    assert harness.EXECUTION_TOKEN not in repr(rows)
    CENTRAL["execution"] = rows[0][3]


# ---------------------------------------------------------------------------
# g / h: audit and observability
# ---------------------------------------------------------------------------


def test_g_execution_appears_in_the_audit_list_and_its_detail(journey):
    """/executions lists the chain and a row click lands on the detail page with
    state, timeline, action, target and operator. Both surfaces stay GET-only."""
    page: Page = journey["page"]
    log: harness.NetworkLog = journey["log"]
    execution_id = CENTRAL["execution"]

    mark = log.mark()
    page.goto(f"{harness.BASE}/executions")
    expect(page.get_by_role("heading", name="Execution Audit")).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    row = page.locator("tr.clickable", has_text=execution_id)
    expect(row).to_be_visible(timeout=harness.NAV_TIMEOUT)
    expect(row.get_by_text("Succeeded", exact=True)).to_be_visible()
    expect(row.get_by_text("block_source_ip", exact=True)).to_be_visible()
    expect(row.get_by_text(TARGET_IP, exact=True)).to_be_visible()
    expect(row.get_by_text(harness.OPERATOR, exact=True)).to_be_visible()
    expect(row.get_by_text("execute", exact=True)).to_be_visible()
    expect(page.get_by_label("State")).to_be_visible()
    expect(page.get_by_label("Direction")).to_be_visible()

    row.click()
    expect(
        page.get_by_role("heading", name=f"Execution {execution_id}", exact=True)
    ).to_be_visible(timeout=harness.NAV_TIMEOUT)
    detail_panel = _panel(page, "Execution")
    expect(detail_panel.get_by_text("Succeeded", exact=True)).to_be_visible()
    expect(detail_panel.locator(".kv", has_text="Action").locator(".v")).to_have_text(
        "block_source_ip"
    )
    expect(detail_panel.locator(".kv", has_text="Target").locator(".v")).to_have_text(
        TARGET_IP
    )
    expect(detail_panel.locator(".kv", has_text="Approval").locator(".v")).to_have_text(
        CENTRAL["approval"]
    )
    timeline = _panel(page, "Timeline").locator("li")
    assert timeline.count() == 3
    expect(timeline.get_by_text("requested", exact=True)).to_be_visible()
    expect(timeline.get_by_text("dispatched", exact=True)).to_be_visible()
    expect(timeline.get_by_text("succeeded", exact=True)).to_be_visible()

    assert log.posts(mark) == []


def test_h_observability_reports_the_execution(journey):
    """The observability page renders the metrics read model verbatim and the
    observed-health card of the mock adapter, with no write request."""
    page: Page = journey["page"]
    log: harness.NetworkLog = journey["log"]

    with harness.http_client() as api:
        metrics = api.get("/api/v1/executions/metrics")
        assert metrics.status_code == 200, metrics.text
        body = metrics.json()
    assert body["total_chains"] >= 1, body
    assert body["succeeded"] >= 1, body

    mark = log.mark()
    page.goto(f"{harness.BASE}/observability")
    expect(page.get_by_role("heading", name="Execution Observability")).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    assert _card_value(page, "Total Executions") == str(body["total_chains"])
    assert _card_value(page, "Succeeded") == str(body["succeeded"])
    adapter_card = page.get_by_test_id("adapter-mock")
    expect(adapter_card).to_be_visible()
    expect(adapter_card.get_by_text("Observed:")).to_be_visible()
    assert log.posts(mark) == []


# ---------------------------------------------------------------------------
# i / j: compensation and duplicate protection
# ---------------------------------------------------------------------------


def test_i_compensation_renders_both_relations(journey):
    """A compensation created over the real endpoint shows on both detail pages:
    the original points at it and it points back at the original."""
    page: Page = journey["page"]
    log: harness.NetworkLog = journey["log"]
    stack = journey["stack"]
    approval_id = CENTRAL["approval"]

    compensation_id = str(uuid.uuid4())
    with harness.http_client() as api:
        response = api.post(
            COMPENSATE_URL,
            json={
                "execution_id": compensation_id,
                "compensates_execution_id": CENTRAL["execution"],
            },
            headers=_auth_headers(),
        )
        assert response.status_code == 201, response.text
    rows = _execution_rows(stack["db_url"], approval_id=approval_id)
    assert {row[1] for row in rows} == {"execute", "compensate"}

    mark = log.mark()
    page.goto(f"{harness.BASE}/executions/{CENTRAL['execution']}")
    expect(
        page.get_by_role("heading", name=f"Execution {CENTRAL['execution']}", exact=True)
    ).to_be_visible(timeout=harness.NAV_TIMEOUT)
    relation = _panel(page, "Compensation Relation")
    expect(relation.get_by_role("link", name=compensation_id)).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )

    relation.get_by_role("link", name=compensation_id).click()
    expect(
        page.get_by_role("heading", name=f"Execution {compensation_id}", exact=True)
    ).to_be_visible(timeout=harness.NAV_TIMEOUT)
    back = _panel(page, "Compensation Relation")
    expect(back.get_by_role("link", name=CENTRAL["execution"])).to_be_visible()
    expect(page.get_by_text("compensation succeeded", exact=True).first).to_be_visible()
    timeline = _panel(page, "Timeline").locator("li")
    assert timeline.count() == 2
    for button in ("Execute", "Retry", "Compensate", "Approve", "Reject"):
        assert page.get_by_role("button", name=button, exact=True).count() == 0
    assert log.posts(mark) == []


def test_j_second_execution_of_the_same_approval_is_refused(journey):
    """The settled approval offers no second Execute, and both replays — the same
    execution id and a fresh one — are 409 with the stored facts untouched."""
    page: Page = journey["page"]
    stack = journey["stack"]
    approval_id = CENTRAL["approval"]

    _open_case(page, ALERT_TITLE)
    expect(page.get_by_text("Succeeded", exact=True)).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    assert page.get_by_role("button", name="Execute", exact=True).count() == 0
    assert page.get_by_role("button", name="Confirm Execute").count() == 0

    rows_before = _execution_rows(stack["db_url"], approval_id=approval_id)
    body = {
        "execution_id": CENTRAL["execution"],
        "approval_id": approval_id,
        "operator": CLIENT_TYPED_OPERATOR,
    }
    with harness.http_client() as api:
        replay = api.post(EXECUTIONS_URL, json=body, headers=_auth_headers())
        assert replay.status_code == 409, replay.text
        fresh = api.post(
            EXECUTIONS_URL,
            json={**body, "execution_id": str(uuid.uuid4())},
            headers=_auth_headers(),
        )
        assert fresh.status_code == 409, fresh.text
    assert _execution_rows(stack["db_url"], approval_id=approval_id) == rows_before


# ---------------------------------------------------------------------------
# k / l / m: refusals and failures
# ---------------------------------------------------------------------------


def test_k_wrong_token_writes_nothing(journey):
    """A wrong token in the real modal is a 401 with a static message, and the
    database keeps zero rows for that approval."""
    page: Page = journey["page"]
    log: harness.NetworkLog = journey["log"]
    stack = journey["stack"]
    approval_id = stack["ids"]["WRONG_TOKEN"]["approval"]
    total_before = _execution_count(stack["db_url"])

    _open_case(page, "E2E Execution WRONG_TOKEN")
    mark = _execute_via_modal(page, log, token="wrong-token-never-valid")
    expect(page.get_by_text("Execution credentials invalid")).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    expect(page.get_by_role("button", name="Confirm Execute")).to_be_visible()
    assert len(log.posts_to(EXECUTIONS_URL, mark)) == 1
    assert 401 in log.statuses(EXECUTIONS_URL)

    assert _execution_rows(stack["db_url"], approval_id=approval_id) == []
    assert _execution_count(stack["db_url"]) == total_before

    page.locator("div.panel", has=page.locator("h3:text-is('Execute Response')")).last.get_by_role(
        "button", name="Cancel"
    ).click()

    with harness.http_client() as api:
        payload = {"execution_id": str(uuid.uuid4()), "approval_id": approval_id}
        missing = api.post(EXECUTIONS_URL, json=payload)
        assert missing.status_code == 401
        assert missing.json()["detail"] == "Invalid execution credentials"
        wrong = api.post(
            EXECUTIONS_URL,
            json=payload,
            headers={"Authorization": "Bearer another-wrong-token"},
        )
        assert wrong.status_code == 401
        assert "another-wrong-token" not in wrong.text
    assert _execution_count(stack["db_url"]) == total_before


def test_l_guard_rejected_action_renders_as_status(journey):
    """Executing the mock provider's advisory action is refused by the Guard: the
    browser renders 201 + Guard Rejected as a status, never as an error."""
    page: Page = journey["page"]
    log: harness.NetworkLog = journey["log"]
    stack = journey["stack"]
    approval_id = stack["ids"]["GUARD_API"]["approval"]

    _open_case(page, "E2E Execution GUARD_API")
    mark = _execute_via_modal(page, log, token=harness.EXECUTION_TOKEN)

    expect(page.get_by_text("Guard Rejected", exact=True)).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    expect(page.get_by_text("advisory, not machine-executable")).to_be_visible()
    # 201 closed the modal, so this is a fact rendered as status.
    assert page.get_by_role("heading", name="Execute Response").count() == 0
    assert len(log.posts_to(EXECUTIONS_URL, mark)) == 1
    assert 201 in log.statuses(EXECUTIONS_URL)

    rows = _execution_rows(stack["db_url"], approval_id=approval_id)
    assert [row[0] for row in rows] == ["requested", "guard_rejected"]
    assert rows[1][4] == "hunt_related_activity"
    assert rows[1][6]["code"] == "action_not_executable"


def test_m_adapter_failures_render_failed_with_their_classification(journey):
    """Three adapter failures, each injected through the test-only launcher on the
    documented executor seam, render Failed with their classification and a
    requested -> dispatched -> failed chain."""
    page: Page = journey["page"]
    log: harness.NetworkLog = journey["log"]
    stack = journey["stack"]

    try:
        for classification, case in FAILURE_CASES:
            harness.swap_backend(stack, fail_with=classification)
            _open_case(page, f"E2E Execution {case}")
            mark = _execute_via_modal(page, log, token=harness.EXECUTION_TOKEN)

            expect(page.get_by_text("Failed", exact=True)).to_be_visible(
                timeout=harness.NAV_TIMEOUT
            )
            expect(
                page.locator(".kv", has_text="Classification").locator(".v")
            ).to_have_text(classification)
            assert len(log.posts_to(EXECUTIONS_URL, mark)) == 1

            rows = _execution_rows(stack["db_url"], approval_id=stack["ids"][case]["approval"])
            assert [row[0] for row in rows] == ["requested", "dispatched", "failed"]
            assert rows[2][6]["classification"] == classification
    finally:
        harness.swap_backend(stack, fail_with=None)


# ---------------------------------------------------------------------------
# n: the token stays where it belongs
# ---------------------------------------------------------------------------


def test_n_token_never_leaks(journey):
    """The token reaches the modal, the one request header per confirmation and
    nowhere else: no storage, no URL, no DOM, no response body."""
    page: Page = journey["page"]
    log: harness.NetworkLog = journey["log"]

    _open_case(page, ALERT_TITLE)
    expect(page.get_by_text("Succeeded", exact=True).first).to_be_visible(
        timeout=harness.NAV_TIMEOUT
    )
    assert page.evaluate("Object.keys(window.localStorage).length") == 0
    assert page.evaluate("Object.keys(window.sessionStorage).length") == 0
    assert harness.EXECUTION_TOKEN not in page.url
    assert harness.EXECUTION_TOKEN not in page.content()

    carried = 0
    for request in log.requests:
        assert harness.EXECUTION_TOKEN not in request["url"]
        authorization = request["headers"].get("authorization", "")
        if not authorization:
            continue
        # Credentials travel only on an explicit execution confirmation.
        assert request["method"] == "POST", request
        assert request["url"].rstrip("/").endswith(EXECUTIONS_URL), request
        if authorization == f"Bearer {harness.EXECUTION_TOKEN}":
            carried += 1
        else:
            # Journey k's rejected attempt: the payload never lands anywhere.
            assert authorization == "Bearer wrong-token-never-valid", authorization
    assert carried == EXPECTED_TOKEN_POSTS

    for record in log.responses:
        if "/api/" not in record["url"]:
            continue
        try:
            text = record["response"].text()
        except Exception:
            continue
        assert harness.EXECUTION_TOKEN not in text
