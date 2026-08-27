"""Step 14.6: REAL-BROWSER end-to-end test of the Incident AI view.

A genuine Chromium (Playwright) drives the real Vite app against the real
uvicorn backend over a throwaway SQLite database:

    /incidents/{id} -> GET /incidents/{id}/ai-context -> AI Investigation
    (Explanation history + Risk Summary history + Recommendation history
    with Approval audit — Observe/Review/Audit only, never Decide/Execute)

The four cases are seeded the SAME way 14.4 proved the chain: every AI row
is produced through the REAL production endpoints (mock provider):

    POST /events/{id}/ai-analysis | ai-risk-summary | response-recommendation
    POST /response-recommendations/{id}/approve | reject

Only the event skeleton (AlertGroup + EventRisk + Incident) is seeded into
the database before boot — UI test data is never hand-pushed as AI rows.

Blocks, mirroring the frozen plan:
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

Requires: playwright + pytest-playwright in the backend venv and
``python -m playwright install chromium``. The module skips cleanly when
Playwright is missing, so an explicit run never breaks the machine.
No Ollama call — AI_PROVIDER=mock pins generation to the deterministic
provider; 14.6 observes display semantics, not model output.
"""
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

SNAPSHOT_SCORE = 80

# First visibility assert after every navigation: vite cold-compiles modules
# on first hit, so the default 5 s expect timeout is too tight on Windows.
NAV_TIMEOUT = 30_000


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


def _drain(proc: subprocess.Popen) -> list[bytes]:
    """Read the child's stdout pipe in a daemon thread. Windows pipes hold
    only ~4 KB: without a reader, uvicorn/vite BLOCK on their very next log
    write once the buffer fills — the backend then hangs mid-run (the page
    stops leaving 'Loading…') while looking perfectly healthy otherwise."""
    chunks: list[bytes] = []

    def _reader() -> None:
        assert proc.stdout is not None
        while True:
            chunk = proc.stdout.read(4096)
            if not chunk:
                break
            chunks.append(chunk)

    threading.Thread(target=_reader, daemon=True).start()
    return chunks


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
# Stack: throwaway SQLite DB -> event skeleton -> uvicorn -> vite -> Chromium
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def stack(tmp_path_factory) -> Generator[dict, None, None]:
    """Boot backend + frontend on a seeded throwaway DB; tear both down."""
    tmp = tmp_path_factory.mktemp("incident_ai_e2e")
    db_path = tmp / "e2e_incident_ai.db"
    db_url = f"sqlite:///{db_path.as_posix()}"

    # Event skeleton BEFORE boot: the AI rows themselves are produced AFTER
    # boot through the real production endpoints (see _seed_ai_via_api).
    ids = _seed_event_skeleton(db_url)

    backend_env = {
        **os.environ,
        "AI_PROVIDER": "mock",  # this E2E never calls a real model
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
    backend_log = _drain(backend_proc)
    frontend_log = _drain(frontend_proc)
    success = False
    try:
        _wait_http(f"http://localhost:{BACKEND_PORT}/health", timeout=60)
        _wait_http(BASE, timeout=90)
        _seed_ai_via_api(ids)
        yield {"ids": ids, "db_path": db_path, "db_url": db_url}
        success = True
    finally:
        # On failure, keep the child logs + DB for post-mortem inspection.
        if not success:
            for name, log in (("backend", backend_log), ("frontend", frontend_log)):
                if log:
                    (tmp / f"{name}_e2e.log").write_bytes(b"".join(log))
        for proc in (frontend_proc, backend_proc):
            _kill_tree(proc)
        if success:
            shutil.rmtree(tmp, ignore_errors=True)


def _seed_event_skeleton(db_url: str) -> dict:
    """Four events with EventRisk + Incident — the case records the browser
    will open. AI history is NOT seeded here (14.4 standard: AI rows only
    ever come from the production endpoints).

    FULL    : 3 analyses + 3 summaries + 3 recommendations (1 approved,
              1 rejected, 1 pending) — blocks A/B/C/H/I
    EMPTY   : no AI history at all — block D
    PARTIAL : analysis only — block E
    SNAPSHOT: full chain used for the risk-score freeze — block G
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.core.database import Base
    from app.models import AlertGroup, EventRisk, Incident

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    base = datetime.now(timezone.utc) - timedelta(hours=2)
    ids: dict = {}
    with Session() as session:
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
                risk_score=SNAPSHOT_SCORE,  # Step 7 creation-time snapshot
                created_at=created,
                updated_at=created,
            )
            session.add(incident)
            session.flush()
            ids[name] = {"event": str(group.id), "incident": str(incident.id)}
        session.commit()
    engine.dispose()
    return ids


def _seed_ai_via_api(ids: dict) -> None:
    """Produce ALL AI rows through the real production endpoints (mock
    provider), exactly as 14.4 drove the cross-layer regression — the E2E
    never hand-pushes AI rows into the database."""
    with httpx.Client(base_url=BACKEND_DIRECT, timeout=30, proxy=None) as api:

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

        # FULL + SNAPSHOT: three rounds each (SQLite stamps second-granular
        # created_at; the mock rounds run sequentially so history order stays
        # deterministic enough for the "all visible" assertions).
        full_recs = run_full_chain(ids["FULL"]["event"], 3)
        # The 13.2 audit vocabulary: decisions record ONLY approved/rejected.
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


@pytest.fixture(scope="module")
def api() -> httpx.Client:
    """Direct backend access for DB-level audits. proxy=None: trust_env would
    inherit the Windows system proxy and 502."""
    with httpx.Client(base_url=BACKEND_DIRECT, timeout=10, proxy=None) as c:
        yield c


def _approval_statuses(db_url: str) -> list[str]:
    """Every stored approval status anywhere in the database."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from app.models import AIResponseApproval

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    with Session(engine) as session:
        statuses = [row.status for row in session.query(AIResponseApproval).all()]
    engine.dispose()
    return statuses


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
    session, mirroring the module-scoped stack."""
    ctx = browser.new_context()
    pg = ctx.new_page()
    yield pg
    ctx.close()


@pytest.fixture(scope="module")
def journey(stack, browser_page: Page) -> Generator[dict, None, None]:
    """Shared journey state across the ordered block tests."""
    requests: list = []
    browser_page.on("request", lambda r: requests.append({"url": r.url, "method": r.method}))
    yield {"stack": stack, "page": browser_page, "requests": requests}


def _goto_incident(page: Page, incident_id: str) -> None:
    page.goto(f"{BASE}/incidents/{incident_id}")


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
    ).to_be_visible(timeout=NAV_TIMEOUT)
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
    ).to_be_visible(timeout=NAV_TIMEOUT)

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
    ).to_be_visible(timeout=NAV_TIMEOUT)
    assert panel.locator(".error-banner").count() == 0
    expect(panel.get_by_text("Risk Score (snapshot):")).to_be_visible()


def test_e_partial_context_renders_cleanly(journey):
    """14.6-E: explanation only — the page never assumes a finished pipeline."""
    page: Page = journey["page"]
    _goto_incident(page, journey["stack"]["ids"]["PARTIAL"]["incident"])

    panel = _ai_panel(page)
    expect(
        panel.get_by_text(re.compile(r"AI Explanation History \(1\)"))
    ).to_be_visible(timeout=NAV_TIMEOUT)
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
    ).to_be_visible(timeout=NAV_TIMEOUT)
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
    ).to_be_visible(timeout=NAV_TIMEOUT)
    expect(panel.get_by_text("Approved")).to_be_visible()
    snapshot_line = panel.locator("p", has_text=re.compile(r"Risk Score \(snapshot\):"))
    expect(snapshot_line).to_contain_text("80")
    # No AI-invented score anywhere in the panel: the snapshot sentence is
    # the only place a bare risk score appears (confidence is a percentage).
    assert snapshot_line.count() == 1
