"""Browser E2E for the Phase 3.3 observability layer (Step 3.3.4).

A genuine Chromium (Playwright) drives the real Vite app against the real
uvicorn backend over a throwaway SQLite database — the SAME stack the
3.1.11 execution E2E proved (real SQLite + real uvicorn + real Vite +
real Chromium). This suite lifts what 3.3.3 proved at Service / API /
React-unit / cross-layer level into real browser journeys:

  a. empty state: /observability renders N/A rates (never 0%) and
     "No adapter observations" on a fresh log — exactly two GETs
  b. governance flood in two beats: first one ORM crash-chain alone
     renders "Observed: unknown" (totals see it, the window does not);
     then 1 succeeded + 20 policy-rejected executions (REAL browser
     confirms, closed-window policy booted via env) — the flood NEVER
     enters the adapter window: verdict stays "Observed: healthy",
     only the governance counters move
  c. verdict ladder: two timeout-injected failures tip the window to
     1/3 -> "Observed: failing"; three direct successes lift it to 4/6
     -> "Observed: degraded"
  d. adapter failures: timeout / adapter_unavailable / protocol_violation
     (test-only launcher seam; protocol_violation platform-judged, D9;
     every boot synchronized by a one-shot PROBE execution through the
     same API) — Failed metrics rise, the verdict falls to
     "Observed: failing"
  e. page safety boundary: Incident / Execution Audit / Observability
     tour fires ZERO POST/PUT/PATCH/DELETE; the Observability page
     carries ZERO buttons
  f. the observability surface never touches an execution credential:
     localStorage / sessionStorage / URL / DOM empty of tokens; every
     metrics/health GET travels without an Authorization header
  g. browser == API: every displayed number is the field-for-field
     mirror of the real GET /executions/metrics + /executions/health
     responses — the UI never recomputes

NOT part of the default suite: tests/e2e/ is excluded from collection by
tests/conftest.py; run explicitly with:

    pytest tests/e2e/test_observability_browser.py -m browser -q

Requires: playwright + pytest-playwright + httpx in the backend venv and
``python -m playwright install chromium``. No Ollama call —
AI_PROVIDER=mock pins generation to the deterministic provider.
"""
import os
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

METRICS_URL = "/api/v1/executions/metrics"
HEALTH_URL = "/api/v1/executions/health"
EXECUTIONS_URL = "/api/v1/executions"

# The deployment secret the E2E backend boots with (fail-closed otherwise).
EXECUTION_TOKEN = "e2e-obs-token-3.3.4"
OPERATOR = "legacy-execution"  # EXECUTION_TOKEN maps to this identity (3.3.1)
TARGET_IP = "203.0.113.11"

# First visibility assert after every navigation: vite cold-compiles modules
# on first hit, so the default 5 s expect timeout is too tight on Windows.
NAV_TIMEOUT = 30_000

#: Governance flood (journey b): the SAME production policy settings, only
#: booted with a closed window — [05:00, 05:00) admits nothing, so every
#: flood Intent is refused by the Policy with detail.source = "policy".
#: No production code knob exists for this; settings ARE the config.
POLICY_FLOOD_ENV = {
    "EXECUTION_POLICY_ENABLED": "true",
    "EXECUTION_POLICY_WINDOW_START": "05:00",
    "EXECUTION_POLICY_WINDOW_END": "05:00",
}

FLOOD_COUNT = 20


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
    # The journey swaps decide policy / failure injection per boot; the
    # inherited environment must never pre-pollute them.
    for var in (
        "EXECUTION_POLICY_ENABLED",
        "EXECUTION_POLICY_WINDOW_START",
        "EXECUTION_POLICY_WINDOW_END",
        "E2E_FAIL_WITH",
    ):
        env.pop(var, None)
    return env


# ---------------------------------------------------------------------------
# Seeding: event skeleton (ORM) -> AI recommendations + approvals (REAL API)
# ---------------------------------------------------------------------------

#: (case name, risk score) — all 80 so the mock provider emits the
#: executable block_source_ip and the policy's risk rule stays satisfied.
EVENT_CASES = (
    ("CRASH_CHAIN", 80),   # b beat 1: approval hosting the ORM crash chain
    ("SUCCESS", 80),       # b: the single succeeded chain of the flood
    ("DEGRADED_A", 80),    # c: timeout-injected failures -> degraded
    ("DEGRADED_B", 80),
    ("RECOVER_A", 80),     # c: direct-API recovery successes (4/6 window)
    ("RECOVER_B", 80),
    ("RECOVER_C", 80),
    # d: per classification a one-shot PROBE approval (boot synchronizer:
    # the direct POST proves the failing seam is live BEFORE the browser
    # journey executes) plus the browser journey approval itself.
    ("PROBE_TIMEOUT", 80),
    ("FAILING_TIMEOUT", 80),
    ("PROBE_UNAVAILABLE", 80),
    ("FAILING_UNAVAILABLE", 80),
    ("PROBE_PROTOCOL", 80),
    ("FAILING_PROTOCOL", 80),
    *(
        (f"FLOOD_{index}", 80)  # b: 20 policy-rejected governance facts
        for index in range(1, FLOOD_COUNT + 1)
    ),
)


def _seed_event_skeleton(db_url: str) -> dict:
    """Event skeletons (AlertGroup + EventRisk + Incident + one evidence
    Alert carrying source_ip) — the ONLY ORM rows in this E2E. Every
    recommendation + approval the browser meets is produced through the
    real production endpoints after boot (see _seed_executions_via_api)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.core.database import Base
    from app.models import Alert, AlertGroup, EventRisk, Incident

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    base = datetime.now(timezone.utc) - timedelta(hours=2)
    ids: dict = {}
    with Session() as session:
        for index, (name, score) in enumerate(EVENT_CASES):
            created = base + timedelta(seconds=30 * index)
            group = AlertGroup(
                fingerprint=f"e2e-obs-{name.lower()}" + "0" * 64,  # trimmed below
                title=f"E2E Observability {name}",
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
        session.commit()
        for name in ids:
            ids[name] = {key: str(value) for key, value in ids[name].items()}
    engine.dispose()
    return ids


def _seed_executions_via_api(ids: dict) -> None:
    """ALL recommendations and approvals come from the real production
    endpoints (mock provider) — the E2E never hand-pushes AI/approval
    rows. One approved executable recommendation per journey case."""
    with httpx.Client(base_url=BACKEND_DIRECT, timeout=30, proxy=None) as api:
        for name in ids:
            resp = api.post(f"/api/v1/events/{ids[name]['event']}/response-recommendation")
            assert resp.status_code == 201, resp.text
            rec_id = resp.json()["id"]
            resp = api.post(
                f"/api/v1/response-recommendations/{rec_id}/approve",
                json={"reviewer": "e2e-seed", "review_comment": "E2E approval"},
            )
            assert resp.status_code == 201, resp.text
            ids[name]["approval"] = resp.json()["id"]


# ---------------------------------------------------------------------------
# Backend / frontend process management
# ---------------------------------------------------------------------------


def _start_backend(
    env: dict[str, str], *, fail_with: str | None
) -> subprocess.Popen:
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


def _swap_backend(
    state: dict, *, fail_with: str | None, extra_env: dict[str, str] | None = None
) -> None:
    """Kill the running backend and boot a replacement on the same port
    (same DB, same vite). Windows may hold the listener briefly after the
    kill, so both the port-free wait and the health wait are generous."""
    _kill_tree(state["backend_proc"])
    deadline = time.monotonic() + 30
    while _port_busy(BACKEND_PORT) and time.monotonic() < deadline:
        time.sleep(0.3)
    env = {**state["env"], **(extra_env or {})}
    proc = _start_backend(env, fail_with=fail_with)
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
    tmp = tmp_path_factory.mktemp("observability_e2e")
    db_path = tmp / "e2e_observability.db"
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
    """Direct backend access for journey ⑧ audits. proxy=None: trust_env
    would inherit the Windows system proxy and 502."""
    with httpx.Client(base_url=BACKEND_DIRECT, timeout=10, proxy=None) as c:
        yield c


# ---------------------------------------------------------------------------
# DB-level audit helpers
# ---------------------------------------------------------------------------


def _execution_rows(db_url: str) -> list:
    """execution_log rows (ascending) as plain tuples:
    (decision, direction, operator, execution_id, action, target, detail)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from app.models import ExecutionLog

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    with Session(engine) as session:
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
            for row in session.query(ExecutionLog)
            .order_by(ExecutionLog.created_at, ExecutionLog.id)
            .all()
        ]
    engine.dispose()
    return rows


def _add_in_flight_row(db_url: str, approval_id: str) -> str:
    """Journey b2: the documented crash simulation (frozen 3.3.3.1 pattern)
    — a hand-written requested-only row with a server-recorded adapter
    identity. Insert-only on the append log; the backend reads it on its
    NEXT read-model query."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from app.models import ExecutionLog

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    execution_id = str(uuid.uuid4())
    with Session(engine) as session:
        session.add(
            ExecutionLog(
                execution_id=uuid.UUID(execution_id),
                approval_id=uuid.UUID(approval_id),
                decision="requested",
                direction="execute",
                operator=OPERATOR,
                action="block_source_ip",
                target=TARGET_IP,
                detail={"executor": "mock"},
            )
        )
        session.commit()
    engine.dispose()
    return execution_id


# ---------------------------------------------------------------------------
# The browser journey (a-g run in order against one shared stack)
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
    """Shared journey state: every request the browser ever makes, so the
    safety boundary and token audits see the FULL record."""
    requests: list[dict] = []
    browser_page.on(
        "request",
        lambda r: requests.append(
            {"url": r.url, "method": r.method, "headers": dict(r.headers)}
        ),
    )
    yield {"stack": stack, "page": browser_page, "requests": requests}


def _goto_obs(page: Page) -> None:
    page.goto(f"{BASE}/observability")
    expect(page.get_by_role("heading", name="Execution Observability")).to_be_visible(
        timeout=NAV_TIMEOUT
    )


def _goto_incident(page: Page, incident_id: str) -> None:
    page.goto(f"{BASE}/incidents/{incident_id}")


def _stat_value(page: Page, label: str) -> str:
    """The displayed value of one Metrics StatCard — the exact text the
    operator sees next to the label."""
    card = page.locator(".stat-card", has_text=label).first
    return card.locator(".value").inner_text()


def _adapter_card(page: Page, adapter: str = "mock"):
    return page.locator(f'[data-testid="adapter-{adapter}"]')


def _execute_via_modal(page: Page, requests: list[dict], *, token: str) -> int:
    """Open the Execute modal, fill Operator + Token by hand, and click
    Confirm Execute. Returns the request-list mark recorded JUST BEFORE the
    Confirm click (the network boundary for the safety assertions)."""
    page.get_by_role("button", name="Execute", exact=True).click()
    modal = page.locator(".panel", has=page.locator("h3:text-is('Execute Response')")).last
    expect(modal).to_be_visible(timeout=NAV_TIMEOUT)
    modal.get_by_label("Operator").fill(OPERATOR)
    modal.get_by_label("Execution Token").fill(token)
    mark = len(requests)
    modal.get_by_role("button", name="Confirm Execute").click()
    return mark


def _auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {EXECUTION_TOKEN}"}


def _format_rate(rate: float | None) -> str:
    """The page's frozen display formatting (display only, never a
    re-derivation): null -> N/A, otherwise x100 + round to 2 decimals."""
    if rate is None:
        return "N/A"
    return f"{round(rate * 10000) / 100:g}%"


def _obs_gets(requests: list[dict]) -> tuple[list[dict], list[dict]]:
    """(metrics GETs, health GETs) — and ONLY GETs may ever hit them."""
    metrics = [r for r in requests if METRICS_URL in r["url"]]
    health = [r for r in requests if HEALTH_URL in r["url"]]
    assert all(r["method"] == "GET" for r in metrics + health)
    return metrics, health


def _swap_backend_sync(state: dict, **kwargs) -> None:
    """Swap + synchronize: after this returns the NEW uvicorn process is
    provably serving (health probe + one read-model request served), so
    the browser's next request can never land on the previous process."""
    _swap_backend(state, **kwargs)
    with httpx.Client(base_url=BACKEND_DIRECT, timeout=10, proxy=None) as client:
        assert client.get(METRICS_URL).status_code == 200


def _probe_failed_boot(stack: dict, probe_case: str, classification: str) -> None:
    """Boot synchronizer for failing seams (journey d): a one-shot
    throwaway execution through the REAL API proves the injected
    executor is live BEFORE the browser journey executes — a stale
    backend would SUCCEED here and fail this probe loudly."""
    with httpx.Client(base_url=BACKEND_DIRECT, timeout=30, proxy=None) as client:
        resp = client.post(
            EXECUTIONS_URL,
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": stack["ids"][probe_case]["approval"],
                "operator": OPERATOR,
            },
            headers=_auth_headers(),
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["derived_state"] == "failed", (
            f"probe {probe_case} did not fail with {classification!r} — "
            "the failing seam is not the process serving requests"
        )


def test_a_empty_state_renders_n_a_never_zero(journey):
    """①+③ A pristine log: the two GETs land, every rate renders N/A
    (never 0%), and the health area says "No adapter observations"
    (never a failing verdict invented from nothing). Zero buttons."""
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]

    mark = len(requests)
    _goto_obs(page)

    # Six metric cards: counts are real zeroes, rates are undefined.
    assert _stat_value(page, "Total Executions") == "0"
    assert _stat_value(page, "Succeeded") == "0"
    assert _stat_value(page, "Failed") == "0"
    assert _stat_value(page, "Guard Rejected") == "0"
    assert _stat_value(page, "Success Rate") == "N/A"
    assert _stat_value(page, "Guard Rejection Rate") == "N/A"

    body = page.locator("body").inner_text()
    assert "0%" not in body
    assert "No adapter observations" in body
    # Nothing may invent a verdict out of an empty log.
    for word in ("Observed: healthy", "Observed: degraded", "Observed: failing"):
        assert word not in body

    # Exactly the two read-model GETs (1-2x each under StrictMode).
    metrics_gets = [
        r for r in requests[mark:] if r["method"] == "GET" and METRICS_URL in r["url"]
    ]
    health_gets = [
        r for r in requests[mark:] if r["method"] == "GET" and HEALTH_URL in r["url"]
    ]
    assert 1 <= len(metrics_gets) <= 2
    assert 1 <= len(health_gets) <= 2

    # The page carries zero action affordances of any kind.
    assert page.get_by_role("button").count() == 0


def test_b_governance_flood_never_pollutes_health(journey):
    """②-unknown + ④ THE core semantic E2E, in two beats:

    Beat 1 (unknown): one ORM crash chain (requested-only) is the ONLY
    chain of the adapter — zero terminal outcomes -> "Observed: unknown"
    (never an invented healthy/degraded/failing out of nothing).
    Beat 2 (flood): 1 succeeded + 20 policy-rejected executions (all
    confirmed by hand in the real browser; the closed execution window
    is pure production configuration booted via env). The flood NEVER
    enters the adapter window: its one terminal chain keeps the verdict
    "Observed: healthy" while the flood only moves governance counters.
    """
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]
    stack = journey["stack"]
    ids = stack["ids"]

    # Beat 1 — the crash chain alone: totals see it, the window does not.
    _add_in_flight_row(stack["db_url"], ids["CRASH_CHAIN"]["approval"])
    _goto_obs(page)
    assert _stat_value(page, "Total Executions") == "1"
    assert _stat_value(page, "Success Rate") == "N/A"
    card = _adapter_card(page)
    expect(card.get_by_text("Observed: unknown", exact=True)).to_be_visible(
        timeout=NAV_TIMEOUT
    )
    card_text = card.inner_text()
    assert "Recent Success Rate: N/A" in card_text
    assert "Recent Failed: 0" in card_text

    # Beat 2 — the one chain that reaches the adapter, on the PURE
    # backend (policy disabled = the frozen 3.1/3.2 behavior).
    _goto_incident(page, ids["SUCCESS"]["incident"])
    expect(
        page.get_by_role("heading", name="E2E Observability SUCCESS")
    ).to_be_visible(timeout=NAV_TIMEOUT)
    _execute_via_modal(page, requests, token=EXECUTION_TOKEN)
    expect(page.get_by_text("Succeeded", exact=True)).to_be_visible(
        timeout=NAV_TIMEOUT
    )

    # Boot the closed-window policy and flood it with 20 real browser
    # confirms — every one a legal Intent the Policy refuses.
    _swap_backend_sync(stack, fail_with=None, extra_env=POLICY_FLOOD_ENV)
    try:
        for index in range(1, FLOOD_COUNT + 1):
            name = f"FLOOD_{index}"
            _goto_incident(page, ids[name]["incident"])
            expect(
                page.get_by_role("button", name="Execute", exact=True)
            ).to_be_visible(timeout=NAV_TIMEOUT)
            _execute_via_modal(page, requests, token=EXECUTION_TOKEN)
            expect(page.get_by_text("Guard Rejected", exact=True)).to_be_visible(
                timeout=NAV_TIMEOUT
            )
            expect(
                page.get_by_text(
                    "outside the allowed execution window 05:00-05:00 UTC"
                )
            ).to_be_visible()
    finally:
        # Restore the PURE backend so every later journey starts clean.
        _swap_backend_sync(stack, fail_with=None)

    # DB facts: exactly 22 execute chains; the flood rows are governance.
    rows = _execution_rows(stack["db_url"])
    assert len({r[3] for r in rows}) == FLOOD_COUNT + 2
    rejected = [r for r in rows if r[0] == "guard_rejected"]
    assert len(rejected) == FLOOD_COUNT
    assert all(r[6].get("source") == "policy" for r in rejected)

    # The browser verdict: the flood NEVER touched adapter health.
    _goto_obs(page)
    assert _stat_value(page, "Total Executions") == str(FLOOD_COUNT + 2)
    assert _stat_value(page, "Succeeded") == "1"
    assert _stat_value(page, "Failed") == "0"
    assert _stat_value(page, "Guard Rejected") == str(FLOOD_COUNT)
    assert _stat_value(page, "Success Rate") == "100%"
    assert _stat_value(page, "Guard Rejection Rate") == "90.91%"  # 20/22

    card = _adapter_card(page)
    expect(card).to_be_visible()
    # Window basis = terminal executor chains ONLY (the one success):
    # 20 governance refusals can never drag an adapter down.
    expect(card.get_by_text("Observed: healthy", exact=True)).to_be_visible()
    card_text = card.inner_text()
    assert "Recent Success Rate: 100%" in card_text
    assert "Recent Failed: 0" in card_text
    body = page.locator("body").inner_text()
    for word in ("Observed: degraded", "Observed: failing", "Observed: unknown"):
        assert word not in body


def test_c_degraded_status(journey):
    """② Two journeys of the verdict ladder in one: timeout-injected
    failures first tip the window to 1/3 -> "Observed: failing" (a
    real browser-visible verdict, never "healthy: true" / is_healthy);
    then three direct-API successes lift the window to 4/6 ->
    "Observed: degraded" — the recovery facts that journey d's probes
    + failures later tip back down to failing."""
    page: Page = journey["page"]
    stack = journey["stack"]

    # The two failures execute under a timeout-injected boot — the FIRST
    # direct POST doubles as the boot proof (a stale pure backend would
    # SUCCEED here and fail the test loudly; no browser is involved in
    # this journey, so there is no connection-reuse race).
    _swap_backend_sync(stack, fail_with="timeout")
    try:
        with httpx.Client(base_url=BACKEND_DIRECT, timeout=30, proxy=None) as client:
            for case in ("DEGRADED_A", "DEGRADED_B"):
                resp = client.post(
                    EXECUTIONS_URL,
                    json={
                        "execution_id": str(uuid.uuid4()),
                        "approval_id": stack["ids"][case]["approval"],
                        "operator": OPERATOR,
                    },
                    headers=_auth_headers(),
                )
                assert resp.status_code == 201, resp.text
                assert resp.json()["derived_state"] == "failed"
    finally:
        _swap_backend_sync(stack, fail_with=None)

    _goto_obs(page)
    # 1/3 window success rate -> BELOW the degraded band: failing first.
    expect(_adapter_card(page).get_by_text("Observed: failing")).to_be_visible(
        timeout=NAV_TIMEOUT
    )
    card_text = _adapter_card(page).inner_text()
    assert "Recent Success Rate: 33.33%" in card_text  # 1/3 window
    assert "Recent Failed: 2" in card_text
    assert "Timeout: 2" in card_text
    assert _stat_value(page, "Success Rate") == "33.33%"  # 1/3, server's fact

    body = page.locator("body").inner_text()
    assert "healthy: true" not in body
    assert "is_healthy" not in body

    # Recovery facts lift the window to 4/6 -> degraded — built via the
    # same real API the browser observes, so journey g's mirror check
    # stays exact.
    with httpx.Client(base_url=BACKEND_DIRECT, timeout=30, proxy=None) as client:
        for case in ("RECOVER_A", "RECOVER_B", "RECOVER_C"):
            resp = client.post(
                EXECUTIONS_URL,
                json={
                    "execution_id": str(uuid.uuid4()),
                    "approval_id": stack["ids"][case]["approval"],
                    "operator": OPERATOR,
                },
                headers=_auth_headers(),
            )
            assert resp.status_code == 201, resp.text
            assert resp.json()["derived_state"] == "succeeded"
    _goto_obs(page)
    expect(_adapter_card(page).get_by_text("Observed: degraded")).to_be_visible(
        timeout=NAV_TIMEOUT
    )
    card_text = _adapter_card(page).inner_text()
    assert "Recent Success Rate: 66.67%" in card_text  # 4/6 window
    assert _stat_value(page, "Success Rate") == "66.67%"  # 4/6


def test_d_adapter_failures_reach_failing(journey):
    """⑤ timeout / adapter_unavailable (test-only launcher seam) +
    protocol_violation (platform-judged, D9 — injected as an executor
    answering the forbidden word `dispatched`): every boot is
    synchronized by a one-shot PROBE execution through the same API,
    then the real browser confirms render Failed; the verdict falls to
    "Observed: failing"."""
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]
    stack = journey["stack"]
    ids = stack["ids"]

    try:
        for classification, probe, case in (
            ("timeout", "PROBE_TIMEOUT", "FAILING_TIMEOUT"),
            ("adapter_unavailable", "PROBE_UNAVAILABLE", "FAILING_UNAVAILABLE"),
            ("protocol_violation", "PROBE_PROTOCOL", "FAILING_PROTOCOL"),
        ):
            _swap_backend_sync(stack, fail_with=classification)
            _probe_failed_boot(stack, probe, classification)
            _goto_incident(page, ids[case]["incident"])
            _execute_via_modal(page, requests, token=EXECUTION_TOKEN)
            expect(page.get_by_text("Failed", exact=True)).to_be_visible(
                timeout=NAV_TIMEOUT
            )
    finally:
        _swap_backend_sync(stack, fail_with=None)

    # DB facts: all four classifications exist; the protocol word was
    # JUDGED by the platform parse — no adapter ever self-declares it.
    rows = _execution_rows(stack["db_url"])
    failed_rows = [r for r in rows if r[0] == "failed"]
    classifications = sorted(r[6]["classification"] for r in failed_rows)
    assert classifications.count("timeout") == 4  # 2 degraded + probe + browser
    assert classifications.count("adapter_unavailable") == 2
    assert classifications.count("protocol_violation") == 2
    assert "adapter_error" not in classifications
    protocol_rows = [
        r for r in failed_rows if r[6]["classification"] == "protocol_violation"
    ]
    assert len(protocol_rows) == 2

    _goto_obs(page)
    expect(_adapter_card(page).get_by_text("Observed: failing")).to_be_visible(
        timeout=NAV_TIMEOUT
    )
    card_text = _adapter_card(page).inner_text()
    assert "Recent Success Rate: 33.33%" in card_text  # 4/12 window
    assert "Recent Failed: 8" in card_text
    assert "Timeout: 4" in card_text
    assert "Unavailable: 2" in card_text
    assert _stat_value(page, "Failed") == "8"
    assert _stat_value(page, "Success Rate") == "33.33%"  # 4/12, server's fact


def test_e_page_safety_boundary_zero_writes(journey):
    """⑥ Incident / Execution Audit / Observability tour: ZERO
    POST / PUT / PATCH / DELETE of any kind; the Observability page
    carries ZERO buttons — opening pages never executes anything."""
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]
    ids = journey["stack"]["ids"]

    mark = len(requests)
    _goto_incident(page, ids["SUCCESS"]["incident"])
    expect(
        page.get_by_role("heading", name="E2E Observability SUCCESS")
    ).to_be_visible(timeout=NAV_TIMEOUT)

    page.goto(f"{BASE}/executions")
    expect(page.get_by_role("heading", name="Execution Audit")).to_be_visible(
        timeout=NAV_TIMEOUT
    )

    _goto_obs(page)
    assert page.get_by_role("button").count() == 0

    # The entire tour issued zero write traffic.
    writes = [
        r
        for r in requests[mark:]
        if r["method"] in ("POST", "PUT", "PATCH", "DELETE")
    ]
    assert writes == []


def test_f_token_never_participates_in_observability(journey):
    """⑦ The read models need no execution credential: localStorage /
    sessionStorage empty, no token in URL / DOM, every metrics + health
    GET travels without an Authorization header (and no GET anywhere in
    the whole session ever carried one)."""
    page: Page = journey["page"]
    requests: list[dict] = journey["requests"]

    _goto_obs(page)
    assert page.evaluate("Object.keys(window.localStorage).length") == 0
    assert page.evaluate("Object.keys(window.sessionStorage).length") == 0
    assert EXECUTION_TOKEN not in page.url
    assert EXECUTION_TOKEN not in page.content()

    metrics_gets, health_gets = _obs_gets(requests)
    assert metrics_gets and health_gets
    for record in metrics_gets + health_gets:
        assert "authorization" not in record["headers"]
    # The whole session: credentials ONLY ever travel on execution POSTs.
    for record in requests:
        if record["method"] == "GET":
            assert "authorization" not in record["headers"]


def test_g_browser_displays_api_facts_verbatim(journey):
    """⑧ Every number the operator sees is the field-for-field mirror of
    the real API responses — the UI never recomputes a second truth.
    Final world: 33 chains (1 crash + 1 flood-success + 20 flood
    rejections + 2 degraded failures + 3 recovery successes + 3 probe
    failures + 3 browser failures; 4/12 window -> 33.33% -> "Observed:
    failing"), exactly as the journeys built it."""
    page: Page = journey["page"]

    _goto_obs(page)
    expect(_adapter_card(page)).to_be_visible(timeout=NAV_TIMEOUT)

    with httpx.Client(base_url=BACKEND_DIRECT, timeout=10, proxy=None) as client:
        metrics = client.get(METRICS_URL).json()
        assert metrics["total_chains"] == 33
        assert metrics["succeeded"] == 4
        assert metrics["failed"] == 8
        assert metrics["guard_rejected"] == FLOOD_COUNT
        assert metrics["in_flight"] == 1
        assert sorted(metrics["failure_classifications"]) == [
            "adapter_unavailable",
            "protocol_violation",
            "timeout",
        ]
        assert metrics["failure_classifications"]["timeout"] == 4
        assert metrics["failure_classifications"]["adapter_unavailable"] == 2
        assert metrics["failure_classifications"]["protocol_violation"] == 2
        health = client.get(HEALTH_URL).json()
        adapter = health["adapters"]["mock"]
        # Window = ALL 12 terminal chains: 4 successes, then 8 failures
        # -> 33.33% success rate -> failing; the flood + crash chains
        # are outside the window basis entirely.
        assert adapter["observed_status"] == "failing"
        assert adapter["window_succeeded"] == 4
        assert adapter["window_failed"] == 8
        assert adapter["all_time_guard_rejected"] == FLOOD_COUNT
        assert adapter["all_time_in_flight"] == 1

    # Metrics cards mirror the response field-for-field.
    assert _stat_value(page, "Total Executions") == str(metrics["total_chains"])
    assert _stat_value(page, "Succeeded") == str(metrics["succeeded"])
    assert _stat_value(page, "Failed") == str(metrics["failed"])
    assert _stat_value(page, "Guard Rejected") == str(metrics["guard_rejected"])
    assert _stat_value(page, "Success Rate") == _format_rate(metrics["success_rate"])
    assert _stat_value(page, "Guard Rejection Rate") == _format_rate(
        metrics["guard_rejection_rate"]
    )

    # Adapter card mirrors the health response field-for-field.
    card = _adapter_card(page)
    expect(card.get_by_text(f"Observed: {adapter['observed_status']}")).to_be_visible()
    card_text = card.inner_text()
    assert (
        f"Recent Success Rate: {_format_rate(adapter['window_success_rate'])}"
        in card_text
    )
    assert f"Recent Failed: {adapter['window_failed']}" in card_text
    assert f"Timeout: {adapter['timeout_count']}" in card_text
    assert f"Unavailable: {adapter['unavailable_count']}" in card_text

    # Verdict words only ever appear with the "Observed:" prefix.
    body = page.locator("body").inner_text()
    for word in ("healthy", "degraded", "failing", "unknown"):
        assert page.get_by_text(word, exact=True).count() == 0
    assert "healthy: true" not in body
    assert "is_healthy" not in body

    # The whole session: observability traffic was exactly the two GETs.
    metrics_gets, health_gets = _obs_gets(journey["requests"])
    assert metrics_gets and health_gets
    assert all(
        r["url"].endswith(METRICS_URL) or r["url"].endswith(HEALTH_URL)
        for r in metrics_gets + health_gets
    )
