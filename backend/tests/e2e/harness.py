"""Shared runtime for the browser E2E suites in this directory.

Every suite here drives a real Chromium against a real uvicorn backend and the
real vite dev server. The stack requires PostgreSQL: ``execute_response`` commits
the dispatch attempt on an independent connection before the external call
(``app/services/executions/durable_dispatch.py``), and SQLite's single-writer lock
cannot interleave that commit with the caller's open transaction. The database URL
therefore comes from ``DATABASE_URL`` and nothing else — a missing or unreachable
server fails the run instead of degrading to SQLite.

Ports are fixed. ``frontend/vite.config.ts`` pins the dev server to 5173 and its
proxy targets to ``http://localhost:8000``, so the backend must bind 8000; a busy
port is a failed precondition, never a skip.

    SENTINELFLOW_BROWSER_E2E=1 \
    DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/sentinelflow \
    python -m pytest tests/e2e/test_execution_browser.py -m browser -q
"""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Generator, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

BACKEND_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIR = BACKEND_DIR.parent / "frontend"
PYTHON = sys.executable

BACKEND_PORT = 8000
FRONTEND_PORT = 5173
BASE = f"http://localhost:{FRONTEND_PORT}"
# Direct calls pin IPv4: "localhost" may resolve to ::1, where an unrelated
# listener answers instead of the backend under test.
BACKEND_DIRECT = f"http://127.0.0.1:{BACKEND_PORT}"

# vite cold-compiles modules on the first request, so the first visibility
# assertion after a navigation needs more than the 5 s default.
NAV_TIMEOUT = 30_000

BACKEND_BOOT_TIMEOUT = 90.0
FRONTEND_BOOT_TIMEOUT = 120.0
TEARDOWN_TIMEOUT = 30.0
#: Timeout for one alembic invocation.
ALEMBIC_TIMEOUT = 240.0

#: The local execution token: typed into the Execute modal by hand and read by
#: the backend from its own environment, so the run needs no other credential.
EXECUTION_TOKEN = "e2e-browser-execution-token"
#: The operator name the token resolves to (LEGACY_OPERATOR_NAME in
#: app/services/executions/operators.py); the server records this identity and
#: ignores whatever the operator types into the modal.
OPERATOR = "legacy-execution"

#: Set by the CI job; archived process logs land here so a failing run can dump
#: them even though pytest's tmp dirs are otherwise unlisted.
LOG_DIR_ENV = "SENTINELFLOW_E2E_LOG_DIR"

_PROXY_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


def database_url() -> str:
    """The PostgreSQL URL the stack runs on, from ``DATABASE_URL`` only."""
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. The browser E2E runs against PostgreSQL: "
            "the execution path commits the dispatch attempt on an independent "
            "connection, which SQLite cannot interleave with the caller's "
            "transaction. Point DATABASE_URL at a PostgreSQL 16 server, e.g. "
            "postgresql+psycopg://sentinelflow:password@localhost:5432/sentinelflow"
        )
    if not url.startswith("postgresql"):
        driver = url.split("://", 1)[0]
        raise RuntimeError(
            f"DATABASE_URL must be PostgreSQL, got driver '{driver}'. The "
            "durable-dispatch contract fails closed on SQLite, so this suite "
            "has no SQLite mode."
        )
    return url


def redacted_url(url: str) -> str:
    """The URL without its password — safe to put in an error message."""
    from sqlalchemy.engine import make_url

    try:
        return make_url(url).render_as_string(hide_password=True)
    except Exception:
        return "<unparseable DATABASE_URL>"


def engine_for(url: str):
    """Engine for test-side reads and schema work (no SQLite connect args)."""
    connect_args = {"connect_timeout": 10} if url.startswith("postgresql") else {}
    return create_engine(url, pool_pre_ping=True, connect_args=connect_args)


@contextmanager
def orm_session(url: str) -> Iterator:
    """A short-lived ORM session for seeding and DB-level audit reads."""
    from sqlalchemy.orm import Session

    engine = engine_for(url)
    try:
        with Session(engine) as session:
            yield session
    finally:
        engine.dispose()


def assert_database_reachable(url: str) -> None:
    """Fail with the sanitized URL when the server is down or not usable."""
    try:
        engine = engine_for(url)
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        finally:
            engine.dispose()
    except Exception as exc:
        raise RuntimeError(
            f"PostgreSQL at {redacted_url(url)} is unreachable or not usable: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def reset_schema(url: str) -> None:
    """Drop and recreate the public schema.

    Every run starts from an empty database, so neither a previous run's rows nor
    a developer's local data can change what the suite observes.
    """
    engine = engine_for(url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP SCHEMA public CASCADE")
            connection.exec_driver_sql("CREATE SCHEMA public")
    finally:
        engine.dispose()


def run_alembic(url: str, *args: str, timeout: float = ALEMBIC_TIMEOUT) -> str:
    """Run one alembic command against ``url``; raise on failure or timeout."""
    env = clean_env({"DATABASE_URL": url, "AI_PROVIDER": "mock"})
    try:
        proc = subprocess.run(
            [PYTHON, "-m", "alembic", *args],
            cwd=str(BACKEND_DIR),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"alembic {' '.join(args)} did not finish within {timeout}s"
        ) from exc
    if proc.returncode != 0:
        raise RuntimeError(
            f"alembic {' '.join(args)} failed with exit code {proc.returncode} "
            f"against {redacted_url(url)}:\n{proc.stdout}\n{proc.stderr}"
        )
    return proc.stdout


def prepare_database(url: str) -> None:
    """Verify the server, wipe the schema and rebuild it from the migrations."""
    assert_database_reachable(url)
    reset_schema(url)
    run_alembic(url, "upgrade", "head")


def alembic_head() -> str:
    """The current head revision, read from the migration scripts.

    Comparing against the live revision keeps the check independent of a version
    literal that rots as soon as a new migration lands.
    """
    import warnings

    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return ScriptDirectory.from_config(cfg).get_current_head()


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------


def port_is_busy(port: int) -> bool:
    """True when something already listens on the port on either loopback stack."""
    for family, address in (
        (socket.AF_INET, ("127.0.0.1", port)),
        (socket.AF_INET6, ("::1", port, 0, 0)),
    ):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                if sock.connect_ex(address) == 0:
                    return True
        except OSError:
            continue
    return False


def assert_ports_free() -> None:
    """Fail when the fixed ports are taken by a stray dev server or an old run."""
    busy = [port for port in (BACKEND_PORT, FRONTEND_PORT) if port_is_busy(port)]
    if busy:
        raise RuntimeError(
            f"port(s) {busy} are already in use. The browser E2E binds "
            f"{BACKEND_PORT} (uvicorn) and {FRONTEND_PORT} (vite); stop the "
            "processes holding them before running the suite."
        )


def wait_port_free(port: int, timeout: float = TEARDOWN_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not port_is_busy(port):
            return
        time.sleep(0.3)
    raise RuntimeError(f"port {port} is still in use {timeout}s after teardown")


def wait_ports_free(timeout: float = TEARDOWN_TIMEOUT) -> None:
    wait_port_free(BACKEND_PORT, timeout)
    wait_port_free(FRONTEND_PORT, timeout)


# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------


def clean_env(extra: dict[str, str]) -> dict[str, str]:
    """Child environment with proxy settings removed.

    A system proxy hijacks loopback HTTP, so the stack must talk to localhost
    directly.
    """
    env = {**os.environ, **extra}
    for var in _PROXY_VARS:
        env.pop(var, None)
    env["NO_PROXY"] = "localhost,127.0.0.1"
    return env


def execution_token() -> str:
    """The local token both sides use; pinned so no .env value can leak in."""
    return EXECUTION_TOKEN


def backend_env(url: str) -> dict[str, str]:
    """Environment for uvicorn and vite.

    ``DEPLOYMENT_MODE=demo`` keeps the approval path tokenless, which is the
    deployment the browser journeys exercise; ``AI_PROVIDER`` and
    ``EXECUTION_ADAPTER`` pin the mock implementations so the run stays offline.
    The execution policy is pinned to its default as well, so a policy window
    exported in the caller's shell cannot change what a plain boot does; the
    suite that needs a policy boot overrides these per process.
    """
    return clean_env(
        {
            "AI_PROVIDER": "mock",
            "EXECUTION_ADAPTER": "mock",
            "DEPLOYMENT_MODE": "demo",
            "DATABASE_URL": url,
            "EXECUTION_TOKEN": execution_token(),
            "EXECUTION_POLICY_ENABLED": "false",
            "EXECUTION_POLICY_WINDOW_START": "09:00",
            "EXECUTION_POLICY_WINDOW_END": "18:00",
        }
    )


def _popen(args, *, cwd: Path, env: dict[str, str], shell: bool) -> subprocess.Popen:
    """Start a child in its own process group.

    ``npm run dev`` spawns node, vite and esbuild below itself, so teardown has to
    signal the whole group; a plain terminate() would leave the tree running and
    the next module would find the ports busy.
    """
    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(
        args,
        cwd=str(cwd),
        env=env,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        **kwargs,
    )


def start_backend(env: dict[str, str], *, fail_with: str | None = None) -> subprocess.Popen:
    """Start uvicorn on the fixed backend port.

    ``fail_with`` selects the test-only launcher, which overrides the documented
    ``get_response_executor`` seam to make the mock adapter fail with one
    classification; the production app has no such knob.
    """
    process_env = dict(env)
    process_env.pop("E2E_FAIL_WITH", None)
    if fail_with is None:
        target = "app.main:app"
    else:
        target = "tests.e2e._execution_fail_launcher:app"
        process_env["E2E_FAIL_WITH"] = fail_with
    return _popen(
        [PYTHON, "-m", "uvicorn", target, "--port", str(BACKEND_PORT)],
        cwd=BACKEND_DIR,
        env=process_env,
        shell=False,
    )


def start_frontend(env: dict[str, str]) -> subprocess.Popen:
    """Start the vite dev server (``npm`` is ``npm.cmd`` on Windows -> shell)."""
    return _popen("npm run dev", cwd=FRONTEND_DIR, env=env, shell=True)


def drain(proc: subprocess.Popen) -> list[bytes]:
    """Collect a child's output in a daemon thread.

    A pipe holds only a few KB: without a reader, uvicorn or vite blocks on its
    next log line once the buffer fills.
    """
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


def _signal_group(proc: subprocess.Popen, sig: int) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def kill_tree(proc: subprocess.Popen | None) -> None:
    """Kill a child and every process below it, then wait for it to exit."""
    if proc is None or proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True,
            check=False,
        )
    else:
        _signal_group(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            _signal_group(proc, signal.SIGKILL)
        proc.kill()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            pass


def wait_http(url: str, timeout: float) -> None:
    """Wait for an HTTP endpoint to answer below 500, then give up loudly."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + timeout
    last_error = "no attempt"
    while time.monotonic() < deadline:
        try:
            with opener.open(url, timeout=3) as response:
                if response.status < 500:
                    return
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
        time.sleep(0.5)
    raise RuntimeError(f"{url} never came up within {timeout}s: {last_error}")


def swap_backend(state: dict, *, fail_with: str | None = None) -> None:
    """Restart uvicorn on the same port, optionally with a failing adapter."""
    kill_tree(state["backend_proc"])
    wait_port_free(BACKEND_PORT)
    proc = start_backend(dict(state["env"]), fail_with=fail_with)
    log = drain(proc)
    state.setdefault("backend_logs", []).append(log)
    state["backend_proc"] = proc
    try:
        wait_http(f"{BACKEND_DIRECT}/health", timeout=BACKEND_BOOT_TIMEOUT)
    except Exception:
        kill_tree(proc)
        raise


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


def archive_logs(name: str, tmp: Path, logs: dict[str, list[bytes]]) -> list[Path]:
    """Write the child logs to ``tmp`` (and to ``SENTINELFLOW_E2E_LOG_DIR``).

    The files are kept so a failed run can be diagnosed from the backend's and
    vite's own output.
    """
    written: list[Path] = []
    external = Path(os.environ[LOG_DIR_ENV]) if os.environ.get(LOG_DIR_ENV) else None
    if external is not None:
        external.mkdir(parents=True, exist_ok=True)
    for label, chunks in logs.items():
        if not chunks:
            continue
        payload = b"".join(chunks)
        target = tmp / f"{name}_{label}.log"
        target.write_bytes(payload)
        written.append(target)
        if external is not None:
            copy = external / f"{name}_{label}.log"
            copy.write_bytes(payload)
            written.append(copy)
    return written


def report_log_paths(request, paths: list[Path]) -> None:
    """Print the log locations outside pytest's capture so they are visible."""
    if not paths:
        return
    reporter = request.config.pluginmanager.get_plugin("terminalreporter")
    message = "browser E2E process logs: " + ", ".join(str(path) for path in paths)
    if reporter is not None:
        reporter.write_line(message)
    else:
        print(message, flush=True)


# ---------------------------------------------------------------------------
# Stack lifecycle
# ---------------------------------------------------------------------------


@contextmanager
def running_stack(
    tmp_path_factory,
    request,
    *,
    seed: Callable[[str], dict] | None = None,
    name: str | None = None,
) -> Iterator[dict]:
    """Bring up the full stack for one module and tear it down again.

    ``seed`` runs after ``alembic upgrade head`` and before uvicorn starts, so both
    processes see the same rows; it returns the module's id map.
    """
    module = name or Path(str(getattr(request.node, "name", "e2e"))).stem
    url = database_url()
    assert_ports_free()
    prepare_database(url)
    ids = seed(url) if seed is not None else {}

    tmp = tmp_path_factory.mktemp(module)
    env = backend_env(url)
    logs: dict[str, list[bytes]] = {}
    backend = start_backend(env)
    frontend = start_frontend(env)
    logs["backend"] = drain(backend)
    logs["frontend"] = drain(frontend)
    state: dict = {
        "ids": ids,
        "db_url": url,
        "env": env,
        "tmp": tmp,
        "backend_proc": backend,
        "frontend_proc": frontend,
        "logs": logs,
        "backend_logs": [logs["backend"]],
    }
    try:
        try:
            wait_http(f"{BACKEND_DIRECT}/health", timeout=BACKEND_BOOT_TIMEOUT)
            wait_http(BASE, timeout=FRONTEND_BOOT_TIMEOUT)
        except Exception as exc:
            paths = archive_logs(module, tmp, logs)
            raise RuntimeError(
                f"{exc} (process logs: {', '.join(str(p) for p in paths) or 'empty'})"
            ) from exc
        yield state
    finally:
        kill_tree(state["frontend_proc"])
        kill_tree(state["backend_proc"])
        # Every backend generation is archived: the journeys that restart uvicorn
        # to inject adapter failures write the diagnosis into their own log.
        collected: dict[str, list[bytes]] = {"frontend": logs["frontend"]}
        for index, chunks in enumerate(state.get("backend_logs", []), start=1):
            collected[f"backend{index}"] = chunks
        paths = archive_logs(module, tmp, collected)
        report_log_paths(request, paths)
        wait_ports_free()


# ---------------------------------------------------------------------------
# Browser helpers
# ---------------------------------------------------------------------------


class NetworkLog:
    """Every request and response the shared page made.

    The safety-boundary audits read this full record, so it is attached before the
    first navigation.
    """

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.responses: list[dict] = []

    def attach(self, page) -> None:
        page.on(
            "request",
            lambda request: self.requests.append(
                {
                    "url": request.url,
                    "method": request.method,
                    "headers": dict(request.headers),
                }
            ),
        )
        page.on(
            "response",
            lambda response: self.responses.append(
                {
                    "url": response.url,
                    "status": response.status,
                    "response": response,
                }
            ),
        )

    def mark(self) -> int:
        return len(self.requests)

    def since(self, mark: int) -> list[dict]:
        return self.requests[mark:]

    def posts(self, since: int = 0) -> list[dict]:
        return [item for item in self.requests[since:] if item["method"] == "POST"]

    def posts_to(self, path: str, since: int = 0) -> list[dict]:
        return [
            item
            for item in self.posts(since)
            if item["url"].rstrip("/").endswith(path.rstrip("/"))
        ]

    def statuses(self, url_fragment: str) -> list[int]:
        return [
            item["status"]
            for item in self.responses
            if url_fragment in item["url"]
        ]


# ---------------------------------------------------------------------------
# Fixtures shared by the suites
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args) -> dict:
    """Chromium must ignore the system proxy; the stack is loopback-only."""
    return {**browser_type_launch_args, "args": ["--no-proxy-server"]}


@pytest.fixture(scope="module")
def browser_page(browser) -> Generator:
    """One tab shared by the module's journeys (mirrors the module-scoped stack)."""
    context = browser.new_context()
    page = context.new_page()
    yield page
    context.close()


@pytest.fixture(scope="module")
def stack_seed():
    """Override in a module to seed rows before uvicorn starts.

    Returns a callable ``seed(db_url) -> ids`` or None.
    """
    return None


@pytest.fixture(scope="module")
def stack(tmp_path_factory, request, stack_seed) -> Generator[dict, None, None]:
    """PostgreSQL schema from the migrations + uvicorn + vite, torn down after."""
    with running_stack(tmp_path_factory, request, seed=stack_seed) as state:
        yield state


def http_client():
    """Direct backend client for API setup and DB-level audits.

    ``trust_env=False`` keeps a system proxy out of the loopback calls.
    """
    import httpx

    return httpx.Client(
        base_url=BACKEND_DIRECT, timeout=30, proxy=None, trust_env=False
    )
