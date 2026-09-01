"""Browser E2E for the Phase 3.1 response-execution layer (Step 3.1.11).

A genuine Chromium (Playwright) drives the real Vite app against the real
uvicorn backend over a throwaway SQLite database — the SAME stack 14.6
proved (real SQLite + real uvicorn + real Vite + real Chromium). This
suite lifts the execution chain that 3.1.10 proved at API/Service/DB level
into a real browser, covering the frozen checklist:

  a. page-load safety boundary: Approval / Incident / Audit pages fire
     ZERO POSTs to /executions and /compensate — only an explicit
     Confirm Execute may ever produce the first POST (GETs may repeat
     1-2x under dev-mode StrictMode; side effects never may)
  b. happy path: Approved Recommendation -> Execute -> Token -> Confirm
     -> POST /executions -> Succeeded (201 body authoritative)
  c. duplicate protection: no second forward chain — no Execute button,
     replays (same or fresh execution_id) are 409, facts untouched
  d. unauthorized: wrong / missing token -> 401 + zero execution_log rows
  e. guard reject (pure API path): mock provider's 40..69 band yields the
     advisory action hunt_related_activity -> executed -> Guard Rejected
  f. guard reject (seeded path): one ORM-seeded monitor_only snapshot
     approved through the REAL approve endpoint -> Guard Rejected (the
     ONLY ORM deviation in this file, unavoidable: the mock provider
     never emits a single advisory-only executable-looking snapshot)
  g. compensation: created via the real POST /executions/compensate
     (httpx; the browser deliberately has NO compensation button in
     3.1.8/3.1.9), then viewed both ways in the Audit UI
  h. execution audit: /executions -> /executions/:id with state,
     timeline, operator, action, target, compensation link
  i. token leakage: localStorage / sessionStorage / URL / DOM / API
     response bodies never contain the token
  j. adapter failures: backend restarted through the test-only launcher
     (tests/e2e/_execution_fail_launcher.py overriding the documented
     get_response_executor seam) — timeout / adapter_unavailable /
     adapter_error each render Failed + Classification
  k. migration: 0009 -> 0008 -> base -> head on a scratch DB

NOT part of the default suite: tests/e2e/ is excluded from collection by
tests/conftest.py; run explicitly with:

    pytest tests/e2e/test_execution_browser.py -m browser -q

Requires: playwright + pytest-playwright + httpx in the backend venv and
``python -m playwright install chromium``. No Ollama call —
AI_PROVIDER=mock pins generation to the deterministic provider.
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

EXECUTIONS_URL = "/api/v1/executions"
COMPENSATE_URL = "/api/v1/executions/compensate"

# The deployment secret the E2E backend boots with (fail-closed otherwise).
# It doubles as the token typed into the modal by hand — exactly like a
# real operator.
EXECUTION_TOKEN = "e2e-exec-token-3.1.11"
# The RECORDED operator identity (3.3.1 frozen semantics): the server
# resolves the Bearer token to its authenticated Operator and ignores
# any client-supplied field — EXECUTION_TOKEN maps to "legacy-execution".
# The modal still types a client-side value below, but the facts (DB
# rows, timeline, audit table) always carry this authenticated name.
OPERATOR = "legacy-execution"
CLIENT_TYPED_OPERATOR = "ops-e2e"  # typed into the modal, never recorded
TARGET_IP = "203.0.113.10"

# First visibility assert after every navigation: vite cold-compiles modules
# on first hit, so the default 5 s expect timeout is too tight on Windows.
NAV_TIMEOUT = 30_000

FAIL_CLASSIFICATIONS = ("timeout", "adapter_unavailable", "adapter_error")


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
    write once the buffer fills."""
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
    """Kill the whole process tree (npm -> cmd -> node -> esbuild)."""
    if proc.poll() is not None:
        return
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


def _clean_env(extra: dict[str, str]) -> dict[str, str]:
    env = {**os.environ, **extra}
    # Proxy env vars silently hijack local HTTP probes (known session-switch
    # pitfall) — the browser stack must talk localhost only.
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env.pop(var, None)
    env["NO_PROXY"] = "localhost,127.0.0.1"
    return env


# ---------------------------------------------------------------------------
# Seeding: event skeleton (ORM) -> AI recommendations + approvals (REAL API)
# ---------------------------------------------------------------------------

#: (case name, risk score) — the mock provider bands: >=70 emits the
#: executable block_source_ip first, 40..69 the advisory hunt_related_activity.
EVENT_CASES = (
    ("SUCCESS", 80),        # b/c/g/h: happy path, duplicate, compensation, audit
    ("GUARD_API", 55),      # e: advisory action straight from the mock provider
    ("GUARD_SEED", 80),     # f: ORM-seeded monitor_only snapshot (reported)
    ("WRONG_TOKEN", 80),    # d: 401 journeys, zero facts
    ("FAIL_TIMEOUT", 80),   # j: adapter failure classifications
    ("FAIL_UNAVAILABLE", 80),
    ("FAIL_ERROR", 80),
)


def _seed_event_skeleton(db_url: str) -> dict:
    """Event skeletons (AlertGroup + EventRisk + Incident + one evidence
    Alert carrying source_ip) — the ONLY ORM rows in this E2E, plus the one
    reported monitor_only recommendation snapshot for path f. Every
    recommendation + approval the browser meets is produced through the
    real production endpoints after boot (see _seed_executions_via_api)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.core.database import Base
    from app.models import (
        AIResponseRecommendation,
        Alert,
        AlertGroup,
        EventRisk,
        Incident,
    )

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    base = datetime.now(timezone.utc) - timedelta(hours=2)
    ids: dict = {}
    with Session() as session:
        for index, (name, score) in enumerate(EVENT_CASES):
            created = base + timedelta(minutes=2 * index)
            group = AlertGroup(
                fingerprint=f"e2e-exec-{name.lower()}" + "0" * 64,  # trimmed below
                title=f"E2E Execution {name}",
                category="brute_force",
                severity="high",
                alert_count=3,
                first_seen=created,
                last_seen=created,
                created_at=created,
                updated_at=created,
            )
            group.fingerprint = group.fingerprint[:64]  # exact 64-char shape
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
            # Evidence alert: without a source_ip the mock recommendation's
            # target is "" and the execution Guard refuses to resolve it.
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
            ids[name] = {"event": group.id, "incident": incident.id}
        # UUID columns need real UUID objects: flush the skeleton first so
        # the seeded recommendation below can reference a generated id.
        session.flush()

        # Reported deviation (path f): the mock provider never emits a
        # single advisory-only snapshot, so ONE monitor_only recommendation
        # is seeded via ORM — it is then approved through the REAL approve
        # endpoint and executed through the REAL browser flow.
        seeded_rec = AIResponseRecommendation(
            alert_group_id=ids["GUARD_SEED"]["event"],
            provider="mock",
            model="mock-deterministic",
            overall_rationale="[e2e] advisory-only snapshot for the Guard Reject path",
            recommendations=[
                {
                    "action": "monitor_only",
                    "target": TARGET_IP,
                    "rationale": "[e2e] seeded advisory action",
                }
            ],
            confidence=0.8,
        )
        session.add(seeded_rec)
        session.commit()
        for name in ids:
            ids[name] = {key: str(value) for key, value in ids[name].items()}
        ids["GUARD_SEED"]["seeded_rec"] = str(seeded_rec.id)
    engine.dispose()
    return ids


def _seed_executions_via_api(ids: dict) -> None:
    """ALL recommendations and approvals come from the real production
    endpoints (mock provider) — the E2E never hand-pushes AI/approval
    rows. Approval ids are recorded for the DB-level audits."""
    with httpx.Client(base_url=BACKEND_DIRECT, timeout=30, proxy=None) as api:

        def recommend(event_id: str) -> str:
            resp = api.post(f"/api/v1/events/{event_id}/response-recommendation")
            assert resp.status_code == 201, resp.text
            return resp.json()["id"]

        def approve(rec_id: str) -> str:
            resp = api.post(
                f"/api/v1/response-recommendations/{rec_id}/approve",
                json={"reviewer": "e2e-seed", "review_comment": "E2E approval"},
            )
            assert resp.status_code == 201, resp.text
            return resp.json()["id"]

        # SUCCESS: two recommendations — the first approved (journey b),
        # the second deliberately left PENDING (journey a: a pending entry
        # must render with zero execution requests).
        rec1 = recommend(ids["SUCCESS"]["event"])
        recommend(ids["SUCCESS"]["event"])
        ids["SUCCESS"]["approval"] = approve(rec1)

        # GUARD_API: score 55 -> the mock emits only hunt_related_activity
        # (advisory) — a Guard Reject produced by the PURE API path.
        ids["GUARD_API"]["approval"] = approve(recommend(ids["GUARD_API"]["event"]))

        # GUARD_SEED: approve the ORM-seeded snapshot through the real
        # endpoint (the approve endpoint records a decision — it does not
        # validate executability; that stays the execution Guard's job).
        ids["GUARD_SEED"]["approval"] = approve(ids["GUARD_SEED"]["seeded_rec"])

        ids["WRONG_TOKEN"]["approval"] = approve(recommend(ids["WRONG_TOKEN"]["event"]))
        for name in ("FAIL_TIMEOUT", "FAIL_UNAVAILABLE", "FAIL_ERROR"):
            ids[name]["approval"] = approve(recommend(ids[name]["event"]))


# ---------------------------------------------------------------------------
# Backend / frontend process management
# ---------------------------------------------------------------------------


def _start_backend(env: dict[str, str], *, fail_with: str | None) -> subprocess.Popen:
    """Pure app.main:app for the real journeys; the test-only launcher
    (documented get_response_executor seam) for adapter-failure injection."""
    if fail_with is None:
        target = "app.main:app"
        env.pop("E2E_FAIL_WITH", None)
    else:
        target = "tests.e2e._execution_fail_launcher:app"
        env = {**env, "E2E_FAIL_WITH": fail_with}
    return subprocess.Popen(
        [PYTHON, "-m", "uvicorn", target, "--port", str(BACKEND_PORT)],
        cwd=str(BACKEND_DIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def _swap_backend(state: dict, *, fail_with: str | None) -> None:
    """Kill the running backend and boot a replacement on the same port
    (same DB, same vite). Windows may hold the listener briefly after the
    kill, so both the port-free wait and the health wait are generous."""
    _kill_tree(state["backend_proc"])
    deadline = time.monotonic() + 30
    while _port_busy(BACKEND_PORT) and time.monotonic() < deadline:
        time.sleep(0.3)
    proc = _start_backend(dict(state["env"]), fail_with=fail_with)
    log = _drain(proc)
    state.setdefault("backend_logs", []).append(log)
    try:
        _wait_http(f"http://localhost:{BACKEND_PORT}/health", timeout=60)
    except Exception:
        state["tmp"].joinpath("backend_swap.log").write_bytes(b"".join(log))
        _kill_tree(proc)
        raise
    state["backend_proc"] = proc


@pytest.fixture(scope="module")
def stack(tmp_path_factory) -> Generator[dict, None, None]:
    """Boot backend + frontend on a seeded throwaway DB; tear both down."""
    tmp = tmp_path_factory.mktemp("execution_e2e")
    db_path = tmp / "e2e_execution.db"
    db_url = f"sqlite:///{db_path.as_posix()}"

    ids = _seed_event_skeleton(db_url)
    env = _clean_env(
        {
            "AI_PROVIDER": "mock",  # this E2E never calls a real model
            "DATABASE_URL": db_url,
            "EXECUTION_TOKEN": EXECUTION_TOKEN,
        }
    )

    backend_proc = _start_backend(dict(env), fail_with=None)
    frontend_proc = subprocess.Popen(
        "npm run dev",  # npm is npm.cmd on Windows -> needs the shell
        cwd=str(FRONTEND_DIR),
        env=env,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    backend_log = _drain(backend_proc)
    frontend_log = _drain(frontend_proc)
    state = {
        "ids": ids,
        "db_url": db_url,
        "db_path": db_path,
        "env": env,
        "tmp": tmp,
        "backend_proc": backend_proc,
    }
    success = False
    try:
        _wait_http(f"http://localhost:{BACKEND_PORT}/health", timeout=60)
        _wait_http(BASE, timeout=90)
        _seed_executions_via_api(ids)
        yield state
        success = True
    finally:
        if not success:
            for name, log in (("backend", backend_log), ("frontend", frontend_log)):
                if log:
                    tmp.joinpath(f"{name}_e2e.log").write_bytes(b"".join(log))
        for proc in (frontend_proc, state["backend_proc"]):
            _kill_tree(proc)
        if success:
            shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture(scope="module")
def api() -> httpx.Client:
    """Direct backend access for DB-level audits. proxy=None: trust_env
    would inherit the Windows system proxy and 502."""
    with httpx.Client(base_url=BACKEND_DIRECT, timeout=10, proxy=None) as c:
        yield c


# ---------------------------------------------------------------------------
# DB-level audit helpers
# ---------------------------------------------------------------------------


def _execution_rows(db_url: str, approval_id: str | None = None) -> list:
    """execution_log rows (ascending chain order) as plain tuples:
    (decision, direction, operator, execution_id, action, target, detail)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from app.models import ExecutionLog

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    with Session(engine) as session:
        query = session.query(ExecutionLog)
        if approval_id is not None:
            query = query.filter(ExecutionLog.approval_id == uuid.UUID(approval_id))
        rows = [
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
    engine.dispose()
    return rows


def _execution_count(db_url: str) -> int:
    return len(_execution_rows(db_url))


# ---------------------------------------------------------------------------
# The browser journey (a-j run in order against one shared stack)
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
    """Shared journey state: every request/response the browser ever makes,
    so the safety boundary and token-leakage audits see the FULL record."""
    requests: list[dict] = []
    responses: list[dict] = []
    browser_page.on(
        "request",
        lambda r: requests.append(
            {"url": r.url, "method": r.method, "headers": dict(r.headers)}
        ),
    )
    browser_page.on(
        "response",
        lambda resp: responses.append(
            {"url": resp.url, "status": resp.status, "response": resp}
        ),
    )
    yield {"stack": stack, "page": browser_page, "requests": requests, "responses": responses}


def _exec_posts(requests: list[dict]) -> list[dict]:
    return [
        r
        for r in requests
        if r["method"] == "POST" and r["url"].rstrip("/").endswith(EXECUTIONS_URL)
    ]


def _compensate_posts(requests: list[dict]) -> list[dict]:
    return [
        r for r in requests if r["method"] == "POST" and COMPENSATE_URL in r["url"]
    ]


def _execute_via_modal(
    page: Page, requests: list[dict], *, token: str, operator: str = CLIENT_TYPED_OPERATOR
) -> int:
    """Open the Execute modal, fill Operator + Token by hand, and click
    Confirm Execute. Returns the request-list mark recorded JUST BEFORE the
    Confirm click (the network boundary for the safety assertions)."""
    page.get_by_role("button", name="Execute", exact=True).click()
    # Direct-child h3 match: the incident page's own "AI Investigation"
    # panel is also .panel and would swallow a descendant-style filter.
    modal = page.locator(".panel", has=page.locator("h3:text-is('Execute Response')")).last
    expect(modal).to_be_visible(timeout=NAV_TIMEOUT)
    modal.get_by_label("Operator").fill(operator)
    modal.get_by_label("Execution Token").fill(token)
    mark = len(requests)
    modal.get_by_role("button", name="Confirm Execute").click()
    return mark


def _goto_incident(page: Page, incident_id: str) -> None:
    page.goto(f"{BASE}/incidents/{incident_id}")


def _auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {EXECUTION_TOKEN}"}


def _panel_by_h2(page: Page, title: str):
    """Panel whose DIRECT-CHILD h2 is `title` (the AI Investigation panel
    on incident pages is itself a .panel — descendant filters match two)."""
    return page.locator(".panel", has=page.locator(f"h2:text-is('{title}')")).filter(
        has=page.locator(f":scope > h2:text-is('{title}')")
    )


def test_a_page_load_safety_boundary_zero_posts(journey):
    """⑧ THE core boundary: opening Incident / Approval Queue / Audit pages
    fires ZERO POSTs to /executions and /compensate — page load is strictly
    read-only. GETs may appear 1-2 times (dev-mode StrictMode remount); the
    assertion locks side-effect freedom, never GET multiplicity."""
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]
    ids = journey["stack"]["ids"]

    mark = len(requests)
    _goto_incident(page, ids["SUCCESS"]["incident"])
    # Approved entry offers Execute; the pending entry renders nothing.
    expect(
        page.get_by_role("heading", name="E2E Execution SUCCESS")
    ).to_be_visible(timeout=NAV_TIMEOUT)
    expect(page.get_by_role("button", name="Execute", exact=True)).to_be_visible(
        timeout=NAV_TIMEOUT
    )
    # Status lookup is GET-only (1-2x under StrictMode) — never a POST.
    exec_gets = [
        r
        for r in requests[mark:]
        if r["method"] == "GET" and EXECUTIONS_URL in r["url"]
    ]
    assert 1 <= len(exec_gets) <= 2

    _goto_incident(page, ids["GUARD_API"]["incident"])
    expect(
        page.get_by_role("heading", name="E2E Execution GUARD_API")
    ).to_be_visible(timeout=NAV_TIMEOUT)

    page.goto(f"{BASE}/approvals")
    # The queue renders the one still-pending recommendation (SUCCESS #2);
    # loading it fires only GETs — the zero-POST audit below covers it.
    expect(page.get_by_text("E2E Execution SUCCESS").first).to_be_visible(
        timeout=NAV_TIMEOUT
    )

    page.goto(f"{BASE}/executions")
    expect(page.get_by_role("heading", name="Execution Audit")).to_be_visible(
        timeout=NAV_TIMEOUT
    )

    # The whole page tour produced ZERO write traffic of any kind.
    assert _exec_posts(requests) == []
    assert _compensate_posts(requests) == []
    assert [r for r in requests if r["method"] == "POST"] == []


def test_b_execute_happy_path(journey):
    """① Approved Recommendation -> Execute -> Token -> Confirm ->
    POST /executions -> Succeeded. The FIRST POST /executions of the entire
    browser session lands exactly at the explicit Confirm click."""
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]
    ids = journey["stack"]["ids"]

    _goto_incident(page, ids["SUCCESS"]["incident"])
    expect(page.get_by_role("button", name="Execute", exact=True)).to_be_visible(
        timeout=NAV_TIMEOUT
    )

    assert _exec_posts(requests) == []  # no execution POST before intent
    mark = _execute_via_modal(page, requests, token=EXECUTION_TOKEN)

    expect(page.get_by_text("Succeeded", exact=True)).to_be_visible(
        timeout=NAV_TIMEOUT
    )
    expect(page.get_by_text("requested → dispatched → succeeded")).to_be_visible()
    expect(page.get_by_text(OPERATOR).first).to_be_visible()

    # Exactly one POST /executions, starting at the Confirm click, carrying
    # the Bearer token — and nothing else ever carried it.
    posts = _exec_posts(requests)
    assert len(posts) == 1
    assert posts[0] in requests[mark:]
    assert posts[0]["headers"]["authorization"] == f"Bearer {EXECUTION_TOKEN}"
    assert _compensate_posts(requests) == []

    # The fact block renders from the 201 body: no follow-up GET after POST.
    exec_gets_after = [
        r for r in requests[mark:] if r["method"] == "GET" and EXECUTIONS_URL in r["url"]
    ]
    assert exec_gets_after == []

    # DB mirrors the browser: exactly the 3-row chain, token never stored.
    rows = _execution_rows(
        journey["stack"]["db_url"], approval_id=ids["SUCCESS"]["approval"]
    )
    assert [r[0] for r in rows] == ["requested", "dispatched", "succeeded"]
    assert all(r[2] == OPERATOR for r in rows)
    assert rows[0][4] == "block_source_ip" and rows[0][5] == TARGET_IP
    assert EXECUTION_TOKEN not in repr(rows)


def test_c_duplicate_protection(journey):
    """⑤ No second forward chain — ever. The panel shows the execution fact
    instead of an Execute button; replays (same execution_id AND a fresh
    one) are 409 with the original facts untouched."""
    page: Page = journey["page"]
    stack = journey["stack"]
    approval_id = stack["ids"]["SUCCESS"]["approval"]

    # Reload the incident: the fact block stands, no Execute affordance.
    _goto_incident(page, stack["ids"]["SUCCESS"]["incident"])
    expect(page.get_by_text("Succeeded", exact=True)).to_be_visible(
        timeout=NAV_TIMEOUT
    )
    assert page.get_by_role("button", name="Execute", exact=True).count() == 0
    assert page.get_by_role("button", name="Confirm Execute").count() == 0
    body = page.locator("body").inner_text()
    for forbidden in ("Retry", "Compensate", "Execute Now"):
        assert forbidden not in body

    rows_before = _execution_rows(stack["db_url"], approval_id=approval_id)
    execution_id = rows_before[0][3]
    exec_body = {
        "execution_id": execution_id,
        "approval_id": approval_id,
        "operator": OPERATOR,
    }
    with httpx.Client(base_url=BACKEND_DIRECT, timeout=10, proxy=None) as api:
        # Replay of the identical Intent -> 409, facts byte-for-byte intact.
        replay = api.post(EXECUTIONS_URL, json=exec_body, headers=_auth_headers())
        assert replay.status_code == 409
        # A FRESH execution_id on the same approval -> 409 as well.
        dup = api.post(
            EXECUTIONS_URL,
            json={**exec_body, "execution_id": str(uuid.uuid4())},
            headers=_auth_headers(),
        )
        assert dup.status_code == 409
    assert _execution_rows(stack["db_url"], approval_id=approval_id) == rows_before


def test_d_unauthorized_zero_facts(journey):
    """⑦ Wrong token in the real modal -> static 401 message, zero
    execution_log rows; missing / wrong Bearer over httpx -> 401 too."""
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]
    stack = journey["stack"]
    approval_id = stack["ids"]["WRONG_TOKEN"]["approval"]
    total_before = _execution_count(stack["db_url"])

    _goto_incident(page, stack["ids"]["WRONG_TOKEN"]["incident"])
    mark = _execute_via_modal(page, requests, token="wrong-token-never-valid")

    # Static operator-facing message; the modal stays open for correction.
    expect(page.get_by_text("Execution credentials invalid")).to_be_visible(
        timeout=NAV_TIMEOUT
    )
    expect(page.get_by_role("button", name="Confirm Execute")).to_be_visible()
    posts = _exec_posts(requests[mark:])
    assert len(posts) == 1
    matched = [r for r in journey["responses"] if EXECUTIONS_URL in r["url"]]
    assert any(r["status"] == 401 for r in matched)

    # 401 writes NOTHING: zero rows for the approval, total unchanged.
    assert _execution_rows(stack["db_url"], approval_id=approval_id) == []
    assert _execution_count(stack["db_url"]) == total_before

    # Close the modal — the wrong token dies with the unmount.
    page.locator(".panel", has=page.locator("h3:text-is('Execute Response')")).last.get_by_role(
        "button", name="Cancel"
    ).click()

    with httpx.Client(base_url=BACKEND_DIRECT, timeout=10, proxy=None) as api:
        body = {
            "execution_id": str(uuid.uuid4()),
            "approval_id": approval_id,
            "operator": OPERATOR,
        }
        missing = api.post(EXECUTIONS_URL, json=body)  # no Authorization at all
        assert missing.status_code == 401
        assert missing.json()["detail"] == "Invalid execution credentials"
        wrong = api.post(
            EXECUTIONS_URL,
            json=body,
            headers={"Authorization": "Bearer another-wrong-token"},
        )
        assert wrong.status_code == 401
        assert wrong.json()["detail"] == "Invalid execution credentials"
        # Static detail: the presented (wrong) credential is never echoed.
        assert "another-wrong-token" not in wrong.text
    assert _execution_count(stack["db_url"]) == total_before


def test_e_guard_reject_pure_api_path(journey):
    """②A Guard Reject straight off the pure API path: the mock provider's
    40..69 band yields the advisory hunt_related_activity; executing it is
    a legal Intent the Guard refuses. The browser renders 201 + guard_rejected
    as a STATUS (Guard Rejected badge + Reason) — never an error banner."""
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]
    stack = journey["stack"]
    approval_id = stack["ids"]["GUARD_API"]["approval"]

    _goto_incident(page, stack["ids"]["GUARD_API"]["incident"])
    mark = _execute_via_modal(page, requests, token=EXECUTION_TOKEN)

    expect(page.get_by_text("Guard Rejected", exact=True)).to_be_visible(
        timeout=NAV_TIMEOUT
    )
    expect(
        page.get_by_text(re.compile("advisory, not machine-executable"))
    ).to_be_visible()
    # 201 closed the modal -> this is status rendering, not error rendering.
    assert page.get_by_role("heading", name="Execute Response").count() == 0
    posts = _exec_posts(requests[mark:])
    assert len(posts) == 1
    matched = [r for r in journey["responses"] if EXECUTIONS_URL in r["url"]]
    assert any(r["status"] == 201 for r in matched)

    rows = _execution_rows(stack["db_url"], approval_id=approval_id)
    assert [r[0] for r in rows] == ["requested", "guard_rejected"]
    assert rows[1][4] == "hunt_related_activity"
    assert rows[1][6]["code"] == "action_not_executable"


def test_f_guard_reject_seeded_path(journey):
    """②B Same verdict for the ORM-seeded monitor_only snapshot (the one
    reported deviation — approved through the REAL approve endpoint, then
    executed through the REAL browser flow)."""
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]
    stack = journey["stack"]
    approval_id = stack["ids"]["GUARD_SEED"]["approval"]

    _goto_incident(page, stack["ids"]["GUARD_SEED"]["incident"])
    mark = _execute_via_modal(page, requests, token=EXECUTION_TOKEN)

    expect(page.get_by_text("Guard Rejected", exact=True)).to_be_visible(
        timeout=NAV_TIMEOUT
    )
    expect(
        page.get_by_text(re.compile("advisory, not machine-executable"))
    ).to_be_visible()
    posts = _exec_posts(requests[mark:])
    assert len(posts) == 1

    rows = _execution_rows(stack["db_url"], approval_id=approval_id)
    assert [r[0] for r in rows] == ["requested", "guard_rejected"]
    assert rows[1][4] == "monitor_only"
    assert rows[1][6]["code"] == "action_not_executable"


def test_g_compensation_view_only(journey):
    """④ Compensation facts exist (created via the REAL
    POST /executions/compensate — the browser deliberately has NO
    compensation button in 3.1.8/3.1.9) and the Audit UI shows the relation
    BOTH ways: Original -> "Compensated by" and Compensation -> "Compensates"."""
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]
    stack = journey["stack"]
    approval_id = stack["ids"]["SUCCESS"]["approval"]

    exec_a = _execution_rows(stack["db_url"], approval_id=approval_id)[0][3]
    comp_execution_id = str(uuid.uuid4())
    with httpx.Client(base_url=BACKEND_DIRECT, timeout=10, proxy=None) as api:
        resp = api.post(
            COMPENSATE_URL,
            json={
                "execution_id": comp_execution_id,
                "compensates_execution_id": exec_a,
                "operator": OPERATOR,
            },
            headers=_auth_headers(),
        )
        assert resp.status_code == 201, resp.text
    comp_rows = _execution_rows(stack["db_url"], approval_id=approval_id)
    comp_directions = {r[1] for r in comp_rows}
    assert comp_directions == {"execute", "compensate"}

    # Original execution: "Compensated by: <comp>" as a real link.
    mark = len(requests)
    page.goto(f"{BASE}/executions/{exec_a}")
    expect(
        page.get_by_role("heading", name=f"Execution {exec_a}")
    ).to_be_visible(timeout=NAV_TIMEOUT)
    rel_panel = _panel_by_h2(page, "Compensation Relation")
    expect(rel_panel.get_by_text(re.compile("Compensated by:"))).to_be_visible()
    expect(rel_panel.get_by_role("link", name=comp_execution_id)).to_be_visible()

    # Follow the link: the compensation page points back to the original.
    rel_panel.get_by_role("link", name=comp_execution_id).click()
    expect(
        page.get_by_role("heading", name=f"Execution {comp_execution_id}")
    ).to_be_visible(timeout=NAV_TIMEOUT)
    comp_rel = _panel_by_h2(page, "Compensation Relation")
    expect(comp_rel.get_by_text(re.compile("Compensates:"))).to_be_visible()
    expect(comp_rel.get_by_role("link", name=exec_a)).to_be_visible()

    # The compensation's complete timeline + inherited facts. Its terminal
    # state renders the 8-word vocabulary word verbatim (only succeeded /
    # failed / guard_rejected get shortened badge labels).
    expect(page.get_by_text("compensation succeeded", exact=True).first).to_be_visible(
        timeout=NAV_TIMEOUT
    )
    expect(page.get_by_text(f"by {OPERATOR}").first).to_be_visible()
    # Compensation chains run compensation_requested -> compensation_succeeded
    # (no dispatched row — the 3.1.6 frozen shape, proven in 3.1.10).
    timeline = _panel_by_h2(page, "Timeline").locator("li")
    assert timeline.count() == 2
    expect(timeline.get_by_text("compensation requested")).to_be_visible()
    expect(timeline.get_by_text("compensation succeeded")).to_be_visible()
    expect(page.locator(".kv", has_text="Action").locator(".v")).to_have_text(
        "block_source_ip"
    )
    expect(page.locator(".kv", has_text="Target").locator(".v")).to_have_text(TARGET_IP)

    # Read-only boundary: NO action affordances anywhere on the detail page.
    for button_name in ("Execute", "Retry", "Compensate", "Approve", "Reject"):
        assert page.get_by_role("button", name=button_name, exact=True).count() == 0
    # And the audit navigation issued ZERO writes.
    assert _exec_posts(requests[mark:]) == []
    assert _compensate_posts(requests[mark:]) == []


def test_h_execution_audit_list_to_detail(journey):
    """⑥ /executions lists every execution fact; a row click lands on
    /executions/:id with state, timeline, operator, action, target and the
    compensation link. The audit surface is GET-only end to end."""
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]
    stack = journey["stack"]
    approval_id = stack["ids"]["SUCCESS"]["approval"]
    exec_a = _execution_rows(stack["db_url"], approval_id=approval_id)[0][3]

    mark = len(requests)
    page.goto(f"{BASE}/executions")
    expect(page.get_by_role("heading", name="Execution Audit")).to_be_visible(
        timeout=NAV_TIMEOUT
    )
    row = page.locator("tr.clickable", has_text=exec_a)
    expect(row).to_be_visible()
    expect(row.get_by_text("Succeeded")).to_be_visible()
    expect(row.get_by_text("block_source_ip")).to_be_visible()
    expect(row.get_by_text(OPERATOR)).to_be_visible()
    expect(row.get_by_text("execute")).to_be_visible()
    # Filter affordances exist; using them is GET-only (never asserted as
    # writes — the zero-POST check below covers the whole tour).
    expect(page.get_by_label("State")).to_be_visible()
    expect(page.get_by_label("Direction")).to_be_visible()

    row.click()
    expect(page.get_by_role("heading", name=f"Execution {exec_a}")).to_be_visible(
        timeout=NAV_TIMEOUT
    )
    # Current state + complete timeline + compensation link on the detail.
    expect(page.locator(".kv", has_text="State").get_by_text("Succeeded")).to_be_visible()
    timeline = _panel_by_h2(page, "Timeline").locator("li")
    assert timeline.count() == 3
    expect(page.get_by_text(re.compile("Compensated by:"))).to_be_visible()

    assert _exec_posts(requests[mark:]) == []
    assert _compensate_posts(requests[mark:]) == []
    assert [r for r in requests[mark:] if r["method"] == "POST"] == []


def test_i_token_never_leaks(journey):
    """⑨ The execution token touched ONLY the modal's memory and the one
    Bearer header: localStorage / sessionStorage / URLs / DOM / API response
    bodies stay clean."""
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]

    # Fresh settled view: the SUCCESS fact block persists across reloads,
    # so the DOM snapshot covers real post-execution content.
    _goto_incident(page, journey["stack"]["ids"]["SUCCESS"]["incident"])
    expect(page.get_by_text("Succeeded", exact=True).first).to_be_visible(
        timeout=NAV_TIMEOUT
    )

    assert page.evaluate("Object.keys(window.localStorage).length") == 0
    assert page.evaluate("Object.keys(window.sessionStorage).length") == 0
    assert EXECUTION_TOKEN not in page.url
    assert EXECUTION_TOKEN not in page.content()

    for request in journey["requests"]:
        assert EXECUTION_TOKEN not in request["url"]
        auth = request["headers"].get("authorization", "")
        if not auth:
            continue
        # Credentials only ever travel on explicit execution POSTs — GETs
        # and every other call go unauthenticated.
        assert request["method"] == "POST"
        assert request["url"].rstrip("/").endswith(EXECUTIONS_URL)
        if EXECUTION_TOKEN in auth:
            # The real secret: exactly one home — the single confirmed
            # execution POST of journey b.
            assert auth == f"Bearer {EXECUTION_TOKEN}"
        else:
            # Journey d's wrong-token attempt: server-refused (401, zero
            # facts). Whatever the operator typed never lands anywhere.
            assert auth == "Bearer wrong-token-never-valid"
    # Sanity: the authorized POSTs of journeys b / e / f really happened —
    # three explicit operator confirms, three credential bearers, nowhere
    # else.
    assert (
        len(
            [
                r
                for r in requests
                if r["headers"].get("authorization") == f"Bearer {EXECUTION_TOKEN}"
            ]
        )
        == 3
    )

    for record in journey["responses"]:
        if "/api/" not in record["url"]:
            continue
        try:
            body = record["response"].text()
        except Exception:
            continue
        assert EXECUTION_TOKEN not in body


def test_j_adapter_failures_render_failed_with_classification(journey):
    """③ The backend restarts through the test-only launcher (documented
    get_response_executor seam — production code carries NO failure knob);
    each adapter classification renders Failed + Classification in the real
    browser, backed by a requested -> dispatched -> failed chain."""
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]
    stack = journey["stack"]
    case_by_classification = {
        "timeout": "FAIL_TIMEOUT",
        "adapter_unavailable": "FAIL_UNAVAILABLE",
        "adapter_error": "FAIL_ERROR",
    }

    try:
        for classification, case in case_by_classification.items():
            _swap_backend(stack, fail_with=classification)
            approval_id = stack["ids"][case]["approval"]

            _goto_incident(page, stack["ids"][case]["incident"])
            mark = _execute_via_modal(page, requests, token=EXECUTION_TOKEN)

            expect(page.get_by_text("Failed", exact=True)).to_be_visible(
                timeout=NAV_TIMEOUT
            )
            expect(
                page.locator(".kv", has_text="Classification").locator(".v")
            ).to_have_text(classification)
            assert len(_exec_posts(requests[mark:])) == 1

            rows = _execution_rows(stack["db_url"], approval_id=approval_id)
            assert [r[0] for r in rows] == ["requested", "dispatched", "failed"]
            assert rows[2][6]["classification"] == classification
    finally:
        # Restore the PURE backend so the session ends exactly as it began.
        _swap_backend(stack, fail_with=None)


# ---------------------------------------------------------------------------
# ⑩ Migration: 0008 -> 0009 -> base -> head on a scratch DB (independent)
# ---------------------------------------------------------------------------


def _migration_facts(db_url: str) -> dict:
    from sqlalchemy import create_engine, inspect

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    with engine.connect() as conn:
        version_rows = conn.exec_driver_sql(
            "SELECT version_num FROM alembic_version"
        ).fetchall()
    versions = [row[0] for row in version_rows]
    indexes = (
        {ix["name"] for ix in inspector.get_indexes("execution_log")}
        if "execution_log" in tables
        else set()
    )
    engine.dispose()
    return {"tables": tables, "versions": versions, "indexes": indexes}


PARTIAL_UNIQUE_INDEXES = {
    "ux_execution_log_execution_id_requested",
    "ux_execution_log_approval_id_execute",
    "ux_execution_log_compensates_requested",
}


def test_k_migration_up_down_base_up(tmp_path):
    """0009 applies cleanly, downgrades to 0008 and base without residue,
    and upgrade head rebuilds the exact same execution_log shape."""
    db_path = tmp_path / "migration_e2e.db"
    db_url = f"sqlite:///{db_path.as_posix()}"
    env = _clean_env(
        {"AI_PROVIDER": "mock", "DATABASE_URL": db_url, "EXECUTION_TOKEN": EXECUTION_TOKEN}
    )

    def alembic(*args: str) -> None:
        proc = subprocess.run(
            [PYTHON, "-m", "alembic", *args],
            cwd=str(BACKEND_DIR),
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert proc.returncode == 0, f"alembic {' '.join(args)} failed:\n{proc.stderr}"

    alembic("upgrade", "0009")
    facts = _migration_facts(db_url)
    assert facts["versions"] == ["0009"]
    assert "execution_log" in facts["tables"]
    assert PARTIAL_UNIQUE_INDEXES <= facts["indexes"]

    alembic("downgrade", "0008")
    facts = _migration_facts(db_url)
    assert facts["versions"] == ["0008"]
    assert "execution_log" not in facts["tables"]

    alembic("downgrade", "base")
    facts = _migration_facts(db_url)
    assert facts["versions"] == []
    assert "execution_log" not in facts["tables"]
    assert "ai_response_approvals" not in facts["tables"]

    alembic("upgrade", "head")
    facts = _migration_facts(db_url)
    assert facts["versions"] == ["0009"]
    assert "execution_log" in facts["tables"]
    assert PARTIAL_UNIQUE_INDEXES <= facts["indexes"]
