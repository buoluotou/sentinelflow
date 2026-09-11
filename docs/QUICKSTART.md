# SentinelFlow Quickstart

Two supported install paths:

- **Docker Compose** needs only Docker. It provisions PostgreSQL, runs the migrations, starts the backend and the frontend, and runs a smoke test.
- **Native** runs the backend and the frontend from source with hot reload. It needs Python, Node and a database of your own.

| | Docker (recommended) | Native (developers) |
|---|---|---|
| You install | Docker only | Python 3.10+, Node 20.19+, PostgreSQL 16 (or SQLite for a partial chain) |
| Command | `scripts/quickstart.ps1` / `.sh` | `scripts/setup-dev.ps1` / `.sh` |
| Database | PostgreSQL 16 (container, managed) | Your PostgreSQL, or a local SQLite file |
| Full demo chain (incl. execution) | Yes | Yes on PostgreSQL; SQLite stops at approval (see [Troubleshooting](TROUBLESHOOTING.md#3-sqlite-execution-returns-500-database-is-locked)) |

Both paths start in Demo Mode: `AI_PROVIDER=mock`, `EXECUTION_ADAPTER=mock`, and every external system (Wazuh / Shuffle / TheHive / Ollama) disabled. Nothing is installed for you and no SOAR is contacted. See [Run modes](#run-modes).

---

## 1. Docker Quickstart (recommended)

### Prerequisites

- **Docker** with **Compose v2** (`docker compose`, not the old `docker-compose`).
  - Windows: Docker Desktop. Linux: Docker Engine + the Compose plugin.
- Free ports **5432 / 8000 / 5173** (change them in `.env` if they are busy).
- No host Python or Node. The smoke test runs inside the backend container.

### One command

```powershell
# Windows (PowerShell)
git clone <your-fork-url> sentinelflow
cd sentinelflow
./scripts/quickstart.ps1
```
```bash
# Linux / macOS
git clone <your-fork-url> sentinelflow
cd sentinelflow
./scripts/quickstart.sh
```

The script runs these steps in order and stops with an error message if one of them fails:

1. checks Docker + Compose v2 and that the daemon is reachable,
2. checks the ports SentinelFlow binds,
3. creates `.env` from `.env.example` and fills in random local values for `POSTGRES_PASSWORD` and `EXECUTION_TOKEN`,
4. validates the compose file (`docker compose config`),
5. brings up the stack in order: **postgres (healthy) → migrate (one-shot) → backend → frontend**,
6. waits for the backend to become healthy (`/ready` answers 200),
7. runs the demo **smoke test inside the backend container** over real HTTP, and
8. prints the access URLs.

The first run spends most of its time downloading and building images (PostgreSQL, Python slim, Node build, nginx). On a warm machine the application itself is up in seconds.

If the backend image build stalls downloading PyPI packages, you can build against a mirror you trust. The default stays the official PyPI: either set `PIP_INDEX_URL=https://<trusted-mirror>/simple/` in `.env` and rebuild (`./scripts/quickstart.sh --rebuild`), or build once with `docker compose build --build-arg PIP_INDEX_URL=https://<trusted-mirror>/simple/` and then `docker compose up -d`.

### Access URLs

| What | URL |
|---|---|
| Frontend (start here) | `http://localhost:5173` |
| Backend API | `http://localhost:8000/api/v1` |
| Interactive API docs (Swagger) | `http://localhost:8000/docs` |
| Readiness probe | `http://localhost:8000/ready` |

Useful commands:

```bash
docker compose ps                   # service health
docker compose logs -f backend      # live backend logs
./scripts/quickstart.ps1 -Down      # stop + remove (Windows)   [keeps the sentinelflow_pg-data volume]
./scripts/quickstart.sh  --down     # stop + remove (Linux)
```

---

## 2. First-run experience (what to do in the UI)

The quickstart's smoke test already injected a sample alert over HTTP, so the Dashboard has data in it. To walk the whole chain by hand:

1. **Generate a full alert storm (optional).** The Scenario Simulator is a CLI script that POSTs to the backend; it needs Python 3.10+ on the host:
   ```bash
   python simulator/runner/run.py --repeat 30 --base-url http://localhost:8000
   ```
   This replays 5 attack scenarios × 30 = **150 alerts**, which aggregate into **5 events**, get risk scores, and auto-create **3 incidents**. Without host Python, POST alerts interactively from `http://localhost:8000/docs`.
2. **Dashboard** (`http://localhost:5173`) — the counters and the risk distribution update on an auto-refresh of roughly 15 s.
3. **Events** — open a high-risk event to see the risk factor table and the alert evidence list.
4. **Event detail → AI (mock)** — click **Analyze with AI**, **Generate Risk Summary**, **Generate Response Recommendation**. With `mock` these return instantly and deterministically. The AI never emits a risk score; the event's own score stays authoritative.
5. **Approval Queue** — **Approve** (or Reject) a recommendation. Approving records a human decision; it dispatches nothing.
6. **Incidents → open a case → AI Investigation panel** — when the recommendation you approved belongs to that case's event, the panel shows an **Execute** control. With `EXECUTION_ADAPTER=mock` the dispatch is a zero-outbound DryRun (`status=succeeded`, `detail={"dry_run":true}`), so the whole chain runs with no external side effect.
7. **Execution Audit** — the append-only trail of that execution.
8. **Execution Observability** — read-only metrics and observed adapter health, derived from the audit log rather than a live probe.

Full walkthrough with expected output: **[docs/demo.md](demo.md)**.

---

## 3. Native Quickstart (developers)

### Prerequisites

- **Python ≥ 3.10** (3.12 tested) — backend.
- **Node ≥ 20.19** (22 LTS recommended; Vite 8) + npm — frontend.
- **PostgreSQL 16** for the full chain, **or** a local SQLite file for the chain up to approval (execution needs PostgreSQL — see [Troubleshooting](TROUBLESHOOTING.md#3-sqlite-execution-returns-500-database-is-locked)).

### One command

```powershell
# Windows (PowerShell)
./scripts/setup-dev.ps1                       # PostgreSQL from .env (Demo/production-like)
./scripts/setup-dev.ps1 -Database sqlite      # zero-dependency local core-chain DB
```
```bash
# Linux / macOS
./scripts/setup-dev.sh
DATABASE=sqlite ./scripts/setup-dev.sh
```

`setup-dev` checks the prerequisites, creates `backend/.venv` and installs requirements, installs frontend deps (`npm ci`), creates `.env` with a random local `EXECUTION_TOKEN`, runs `alembic upgrade head`, and prints how to start the servers. Options: `-SkipFrontend` / `SKIP_FRONTEND=1`, `-WithDevDeps` / `WITH_DEV_DEPS=1`.

### Start the dev servers

```bash
# Backend (terminal 1)
cd backend
#  Windows: .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
#  Linux:   ./.venv/bin/python -m uvicorn app.main:app --reload --port 8000

# Frontend (terminal 2)
cd frontend
npm run dev            # http://localhost:5173 (Vite proxies /api to :8000)
```

Then generate data with the simulator (step 1 above) and open `http://localhost:5173`.

---

## 4. Verify your install

```powershell
# Windows
./scripts/doctor.ps1     # environment + config diagnostics (PASS / WARN / FAIL)
./scripts/smoke.ps1      # end-to-end core chain over real HTTP
```
```bash
# Linux / macOS
./scripts/doctor.sh
./scripts/smoke.sh
```

- **doctor** checks Python, Node, Docker, Compose, PostgreSQL, ports, `.env`, `DATABASE_URL`, the frontend API URL, migration head vs current, backend `/health` + `/ready`, DB connectivity, the AI provider and the enabled adapters. A WARN does not fail the run; Docker and Ollama are mode-dependent.
- **smoke** drives the chain over HTTP and does not import app services. On success it prints `SentinelFlow demo smoke test: PASS` (PostgreSQL) or `SentinelFlow core smoke test (SQLite): PASS` (SQLite, where execution fails closed), and exits `0`; any failure exits non-zero.

---

## Run modes

Three sets of settings, so you do not need the full Wazuh / Shuffle / TheHive / Ollama stack to run the platform.

| Mode | AI | Execution | External systems |
|---|---|---|---|
| Demo (default) | `AI_PROVIDER=mock` | `EXECUTION_ADAPTER=mock` | disabled, credentials empty |
| Local AI | `AI_PROVIDER=ollama` + `AI_MODEL`, `AI_BASE_URL` | `EXECUTION_ADAPTER=mock` | disabled, credentials empty |
| Lab integrations | any | `shuffle` / `wazuh` / `thehive` | the systems you run yourself |

### Demo Mode (default)

- Stack: Frontend + Backend + PostgreSQL. That is all.
- AI: `AI_PROVIDER=mock` (deterministic, instant, offline).
- Execution: `EXECUTION_ADAPTER=mock` (zero-outbound DryRun).
- External systems: all disabled/empty.
- What you get: the complete core flow — alert → aggregate → risk → incident → AI (mock) → approval → mock execution → audit/dashboard — with no Wazuh, Shuffle, TheHive or Ollama. This is what the Docker Quickstart gives you.

### Local AI Mode (optional Ollama)

Demo Mode plus a local model. Ollama is optional and is not needed for the install to succeed.

```bash
docker compose --profile ollama up -d      # start the optional Ollama container
```
Then in `.env` set `AI_PROVIDER=ollama`, `AI_MODEL=qwen3:4b`, `AI_BASE_URL=http://ollama:11434` (the Docker service name) and restart the backend. If Ollama is unreachable, only the AI endpoints degrade (503); the platform still boots and the rest of the chain works. Doctor reports it as a WARN.

### Integration Lab Mode

This mode connects real Wazuh / Shuffle / TheHive instances that you operate in a lab you run yourself. It is configured through `.env`; there is no bundled compose profile, and the stack does not deploy or download those systems.

- Off by default: leave `EXECUTION_ADAPTER=mock` and the `THEHIVE_*` / `WAZUH_*` / `SHUFFLE_*` sections empty.
- To enable one, set `EXECUTION_ADAPTER` to `shuffle` / `wazuh` / `thehive` **and** fill in that adapter's whole section (base URL, credentials, workflow mapping). A half-configured adapter fails to boot instead of starting half-configured.
- Real adapters dispatch through durable dispatch behind the same human approval. There is no auto-retry, no auto-compensation and no way to skip the approval.
- These adapters are experimental lab integrations, not production-certified. This repository is not a production SOAR. See [SECURITY.md](../SECURITY.md).

---

## Stop, reset, data

- **Docker:** `./scripts/quickstart.ps1 -Down` (or `--down`) stops and removes the containers but **keeps** the `sentinelflow_pg-data` volume, so you can restart without losing data. `docker compose down -v` erases the data too.
- **Native SQLite:** stop the backend and delete the local `*.db` file, then run `alembic upgrade head` for a fresh database.
- **Native PostgreSQL:** drop/recreate the database, then `alembic upgrade head`.

---

## Next steps

- [Demo guide](demo.md) — the full end-to-end walkthrough with expected output.
- [Architecture](architecture.md) — data model, pipeline, risk rules, state machine.
- [API reference](api.md) — every REST endpoint.
- [Deployment](deployment.md) — production topology, migrations, hardening checklist.
- [Troubleshooting](TROUBLESHOOTING.md) — fixes for common problems, starting with the doctor.
- [SECURITY.md](../SECURITY.md) — the security model and disclosure policy.
