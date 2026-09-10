# SentinelFlow Troubleshooting

**Start here, not with a wall of text.** Almost every install/startup problem is
identified in seconds by the doctor:

```powershell
# Windows
./scripts/doctor.ps1            # add -SkipHttp if the backend is not running yet
```
```bash
# Linux / macOS
./scripts/doctor.sh
```

Doctor prints one line per check as **PASS / WARN / FAIL** covering: Python,
Node, Docker, Docker Compose, PostgreSQL, the required ports, `.env`,
`DATABASE_URL`, the frontend API URL, migration head vs. current, backend
health, database connectivity, the AI provider and whether any external adapter
is enabled. **FAIL** = must fix; **WARN** = optional/absent tool (e.g. Docker or
Ollama you have not installed — harmless for Demo Mode on a machine that already
has PostgreSQL, but required for the Docker Quickstart).

---

## 1. Reading the logs

- **Docker:** `docker compose logs backend` (or `-f` to follow). The stack is
  `postgres -> migrate -> backend -> frontend`; `docker compose ps` shows each
  service's health and whether the one-shot `migrate` job exited `0`.
- **Native:** the `uvicorn` console prints the logs directly.
- **Log level:** controlled by `DEBUG` in `.env`.
  - `DEBUG=false` (default) → **INFO**: a short, meaningful startup line + a
    **safe configuration summary** (which providers/adapters are enabled, the DB
    *driver*, whether a token is set). It never prints secret **values**.
  - `DEBUG=true` → **DEBUG** with exception stack traces. Turn this on only to
    diagnose; turn it back off for normal use.
- **Secrets are never logged** at any level (API keys, tokens, passwords and the
  DB URL are masked in config repr and filtered from records).

A healthy Demo startup is a handful of lines — not hundreds. If you see a long
stack trace on boot, set `DEBUG=false` first and re-read the last real ERROR.

---

## 2. Docker Quickstart problems

| Symptom | Cause | Fix |
|---|---|---|
| `Docker not found` | Docker not installed / not on PATH | Install Docker Desktop (Windows) or Docker Engine + Compose plugin (Linux), then re-run `scripts/quickstart` |
| `the Docker daemon is not reachable` | Docker installed but not started | Start Docker Desktop / `systemctl start docker`, wait for the engine, re-run |
| `'docker compose' (v2) not available` | Old `docker-compose` (v1) or missing plugin | Update Docker; the stack needs Compose **v2** (`docker compose`, not `docker-compose`) |
| `port 5432 / 8000 / 5173 is already bound` | Another service holds the port | Set `POSTGRES_PORT` / `BACKEND_PORT` / `FRONTEND_PORT` in `.env` to free ports and re-run |
| compose refuses: `POSTGRES_PASSWORD ... required` | Empty DB password (fail-closed by design) | Run `scripts/quickstart` (it generates a random local password), or set `POSTGRES_PASSWORD` in `.env` manually |
| `docker compose config failed` | Malformed `.env` / compose override | Fix `.env` (doctor shows the offending key); ensure you copied `.env.example` |
| PyPI downloads slow / time out during the backend image build | The default index is the official `pypi.org`; some networks (e.g. in China) throttle it | Opt in to a trusted mirror: set `PIP_INDEX_URL=https://<mirror>/simple/` in `.env` and re-run `./scripts/quickstart.sh --rebuild` (or `docker compose build --build-arg PIP_INDEX_URL=...`). Default stays official PyPI |
| backend never becomes `healthy` | Migration failed, or DB unreachable | `docker compose logs migrate` then `docker compose logs backend`; confirm `migrate` exited `0` and `postgres` is `healthy` |
| frontend shows but API calls fail | backend not up yet, or port changed | `docker compose ps`; open `http://localhost:<BACKEND_PORT>/ready` — must be `200` |

**Data persistence:** the PostgreSQL data lives in a compose project-scoped
named volume — for the default project `sentinelflow` that is
`sentinelflow_pg-data` (`docker volume ls | grep pg-data` lists it).
`docker compose down` (or `scripts/quickstart -Down` / `--down`) **keeps** it —
restart without losing data. `docker compose down -v` **erases** it.

> **Upgrading a pre-RC2 checkout?** Older versions pinned the fixed volume name
> `sentinelflow-pg-data`. Your data is not lost — copy it once into the
> project-scoped volume, then start the stack and confirm the Dashboard
> counters:
> `docker run --rm -v sentinelflow-pg-data:/from -v sentinelflow_pg-data:/to alpine sh -c 'cp -a /from/. /to/'`

---

## 3. The most common Demo question: "execution returns 500 / database is locked" (SQLite)

**If your `DATABASE_URL` is a SQLite file (`sqlite:///...`), the response-execution
step (`POST /api/v1/executions`) fails CLOSED with `database is locked` (HTTP 500).**

This is **not a bug and not data loss** — it is a deliberate safety property:

- Before any external dispatch, SentinelFlow writes a **durable dispatch-attempt
  record on an independent database connection and commits it first** (so the
  attempt survives a later crash/rollback). PostgreSQL's MVCC lets that
  independent commit coexist with the caller's open transaction.
- **SQLite has a single database-level write lock**, so the independent commit
  cannot proceed while the caller's transaction is open → it fails **closed**:
  no dispatch, no external call, **no fabricated outcome**, execution metrics
  stay `total_chains = 0`.

**What to do:**

- **For the complete Demo (through execution → audit → outcome), use PostgreSQL** —
  that is exactly what the Docker Quickstart provisions (`postgres:16`). Run
  `scripts/quickstart.ps1` / `scripts/quickstart.sh`.
- **SQLite is fine** for zero-dependency development of the chain **up to human
  approval** (ingest → dedup → risk → incident → AI mock → approval). `scripts/smoke.py`
  is driver-aware: on SQLite it verifies the core chain and the fail-closed
  execution boundary and prints `SentinelFlow core smoke test (SQLite): PASS`;
  on PostgreSQL it runs the full chain and prints `SentinelFlow demo smoke test: PASS`.

Native PostgreSQL instead of Docker? Point `DATABASE_URL` at your local
PostgreSQL (`postgresql+psycopg://user:pass@localhost:5432/sentinelflow`), then
`alembic upgrade head` and start the backend.

---

## 4. Auth: 401 / 403 on approve / execute

| Symptom | Cause | Fix |
|---|---|---|
| **401** on the execution write path (execute / compensate / reconcile) | `EXECUTION_TOKEN` **and** `OPERATORS_JSON` are both empty → fail-closed by design | `scripts/quickstart` / `setup-dev` generate a random local `EXECUTION_TOKEN`. Natively, set `EXECUTION_TOKEN` in `.env` (or export it) and pass the same value to `smoke.py --token` |
| **403** on execute/dispatch | The operator's role is not `executor` / `admin` | In `OPERATORS_JSON`, give the dispatching operator `"role":"executor"` (or `admin`). `viewer` / `reviewer` may not dispatch |
| smoke says `no EXECUTION_TOKEN available` | Token not passed and not in `.env` | `--token <value>`, or `$env:EXECUTION_TOKEN` / `export EXECUTION_TOKEN`, or put it in `.env` |

On the **token-authenticated execution path** (execute / compensate / reconcile)
identity comes **only** from the Bearer token — any `operator` field in a request
body is ignored, so the execution operator cannot be impersonated. The
**approval reviewer** name (`POST /response-recommendations/{id}/approve|reject`)
carries **no token by design** ("Approve ≠ Execute") and is a display-only field
that is **not** production-authenticated in this evaluation build — expose the
service only behind trusted-network / SSO controls (see the README security
model). Read-only endpoints (dashboard, events, incidents, metrics, health) and
the approve/reject decision path need no token.

---

## 5. AI analysis: 503 / 502

| Symptom | Cause | Fix |
|---|---|---|
| **503** on an AI endpoint | Provider unreachable (e.g. `AI_PROVIDER=ollama` but Ollama is not running) | For Demo, set `AI_PROVIDER=mock` (instant, offline). For AI Local Mode, start Ollama (`docker compose --profile ollama up -d`, or a host Ollama) and set `AI_BASE_URL` (Docker: `http://ollama:11434`; host: `http://localhost:11434`) |
| AI is very slow / times out | Local models take tens of seconds per generation | Raise `AI_TIMEOUT_SECONDS`; pull a small model (e.g. `qwen3:4b`) |
| **502** on an AI endpoint | Provider returned malformed structured output | The typed error contract rejects it and **persists nothing**; retry, or use `mock` for a deterministic Demo |

A missing/unreachable Ollama degrades **only** the AI endpoints — the platform
still boots and the rest of the chain works. Ollama is **never** required for
Demo Mode.

---

## 6. Frontend cannot reach the backend / CORS

- The frontend has a **single** authoritative API base: `VITE_API_BASE_URL`
  (read by `frontend/src/api/client.ts`). **Leave it empty** for the default
  same-origin setup — dev uses the Vite proxy, Docker uses the nginx `/api`
  reverse proxy — so there is **no CORS** to configure.
- Set an absolute origin (e.g. `http://localhost:8000`) **only** if the frontend
  is served from a different host than the backend.
- `VITE_API_BASE_URL` is a **build-time** value. After changing it you must
  **rebuild** the frontend (`npm run build`, or re-run the Docker Quickstart with
  `-Rebuild` / `--rebuild`). The backend ignores it.
- **Blank page:** confirm the frontend is actually served (Docker: the
  `frontend` service shows `healthy` in `docker compose ps`, answering on
  `http://localhost:<FRONTEND_PORT>`; native: `npm run dev` running on `:5173`).
  The nginx config has an SPA fallback (`try_files $uri /index.html`).

---

## 7. Migrations

- The Docker stack runs migrations **once** through a dedicated one-shot `migrate`
  service (`postgres` healthy → `migrate` → `backend`). Do **not** also run
  `alembic` by hand against the compose database while the stack is up.
- `Base.metadata.create_all()` is **never** used in production — schema only comes
  from Alembic (`0001 … 0012`).
- Check state: `alembic current` (should read `0012 (head)`) vs `alembic heads`.
  Doctor compares them for you. The chain is reversible
  (`alembic downgrade base` → `upgrade head` verified).
- Native "database is locked" **during migration** usually means another process
  holds the SQLite file — stop the backend, delete the local `*.db`, re-run
  `alembic upgrade head`.

---

## 8. Still stuck?

1. `./scripts/doctor.ps1` (or `.sh`) — read the FAIL/WARN lines top to bottom.
2. `docker compose logs backend` (Docker) or the uvicorn console (native) with
   `DEBUG=true` for a stack trace.
3. Re-run the smoke: `./scripts/smoke.ps1` / `./scripts/smoke.sh` (or
   `python scripts/smoke.py --base-url http://127.0.0.1:8000 --token <token>`).
4. See [QUICKSTART](QUICKSTART.md) for a clean-slate install, [demo.md](demo.md)
   for the end-to-end walkthrough, and [SECURITY.md](../SECURITY.md) for the
   security model.
