# SentinelFlow Quickstart

Two supported paths. **Docker Compose is the recommended Quickstart** — it needs
only Docker, provisions PostgreSQL for you, migrates, boots the backend and
frontend, and runs a smoke test. The **Native** path is for developers who want
hot-reload without containers.

| | Docker Quickstart (recommended) | Native (developers) |
|---|---|---|
| You install | **Docker** only | Python 3.10+, Node 20.19+, PostgreSQL 16 (or SQLite for a partial chain) |
| Command | `scripts/quickstart.ps1` / `.sh` | `scripts/setup-dev.ps1` / `.sh` |
| Database | PostgreSQL 16 (container, managed) | Your PostgreSQL, or a local SQLite file |
| Full demo chain (incl. execution) | **Yes** | Yes on PostgreSQL; SQLite stops at approval (see [Troubleshooting §3](TROUBLESHOOTING.md)) |

> **Default = Demo Mode.** `AI_PROVIDER=mock`, `EXECUTION_ADAPTER=mock`, every
> external system (Wazuh / Shuffle / TheHive / Ollama) disabled. No real SOAR is
> contacted and nothing is auto-installed. See [Run modes](#run-modes).

---

## 1. Docker Quickstart (recommended)

### Prerequisites

- **Docker** with **Compose v2** (`docker compose`, not the old `docker-compose`).
  - Windows: Docker Desktop. Linux: Docker Engine + the Compose plugin.
- Free ports **5432 / 8000 / 5173** (change them in `.env` if busy).
- **No host Python or Node required** — the smoke test runs *inside* the backend
  container.

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

The script does everything, in order, and stops with a clear message if a step
fails:

1. checks Docker + Compose v2 and that the daemon is reachable,
2. checks the ports SentinelFlow binds,
3. creates `.env` from `.env.example` and fills **random local secrets**
   (`POSTGRES_PASSWORD`, `EXECUTION_TOKEN`) — never a fixed/committed secret,
4. validates the compose file (`docker compose config`),
5. brings up the stack in the enforced order
   **postgres (healthy) → migrate (one-shot) → backend → frontend**,
6. waits for the backend to become healthy (`/ready` answers 200),
7. runs the demo **smoke test inside the backend container** over real HTTP, and
8. prints the access URLs.

> **First run is dominated by image download + build** (PostgreSQL, Python slim,
> Node build, nginx). That one-time cost is counted separately from the app's own
> startup; on a warm machine the app itself is up in seconds.

### Access URLs

| What | URL |
|---|---|
| **Frontend (start here)** | `http://localhost:5173` |
| Backend API | `http://localhost:8000/api/v1` |
| Interactive API docs (Swagger) | `http://localhost:8000/docs` |
| Readiness probe | `http://localhost:8000/ready` |

Useful commands:

```bash
docker compose ps                   # service health
docker compose logs -f backend      # live backend logs
./scripts/quickstart.ps1 -Down      # stop + remove (Windows)   [keeps the pg-data volume]
./scripts/quickstart.sh  --down     # stop + remove (Linux)
```

---

## 2. First-run experience (what to do in the UI)

The quickstart's smoke test already injected a sample alert over HTTP, so **the
Dashboard is live, not blank**. Now walk the chain by hand:

1. **Generate a full alert storm (optional).** The Scenario Simulator is a
   one-command CLI (needs Python 3.10+ on the host; it just POSTs to the backend):
   ```bash
   python simulator/runner/run.py --repeat 30 --base-url http://localhost:8000
   ```
   This replays 5 attack scenarios × 30 = **150 alerts → 5 aggregated events**,
   risk scores, and **3 auto-created incidents**. No host Python? POST alerts
   interactively from `http://localhost:8000/docs`.
2. **Dashboard** (`http://localhost:5173`) — watch the counters and risk
   distribution update (auto-refresh ~15 s).
3. **Events** — open a high-risk event → the explainable **risk factor** table +
   the alert evidence list.
4. **Event detail → AI (mock)** — click **Analyze with AI**, **Generate Risk
   Summary**, **Generate Response Recommendation**. With `mock` these are instant
   and deterministic; note the AI never emits a risk score (the event's score
   stays authoritative).
5. **Approval Queue** — **Approve** (or Reject) a recommendation. Approving
   records a human decision; it executes nothing.
6. **Execute Console** — dispatch the approved action. With `EXECUTION_ADAPTER=mock`
   this is a zero-outbound DryRun (`status=succeeded`, `detail={"dry_run":true}`)
   — the chain is proven with no external side effect.
7. **Execution Audit** — the append-only trail of the execution.
8. **Observability** — read-only metrics + observed adapter health derived from
   the audit log (no live probe).

Full walkthrough with expected output: **[docs/demo.md](demo.md)**.

---

## 3. Native Quickstart (developers)

### Prerequisites (versions derived from the real project config)

- **Python ≥ 3.10** (3.12 verified) — backend.
- **Node ≥ 20.19** (22 LTS recommended; Vite 8) + npm — frontend.
- **PostgreSQL 16** for the full chain, **or** a local SQLite file for the
  core chain up to approval (execution needs PostgreSQL — see
  [Troubleshooting §3](TROUBLESHOOTING.md)).

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

`setup-dev` checks the prerequisites, creates `backend/.venv` and installs
requirements, installs frontend deps (`npm ci`), creates `.env` with a **random**
local `EXECUTION_TOKEN`, runs `alembic upgrade head`, and prints how to start the
servers. Options: `-SkipFrontend` / `SKIP_FRONTEND=1`, `-WithDevDeps` /
`WITH_DEV_DEPS=1`.

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

Then generate data with the simulator (see §2 step 1) and open
`http://localhost:5173`.

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

- **doctor** checks Python, Node, Docker, Compose, PostgreSQL, ports, `.env`,
  `DATABASE_URL`, the frontend API URL, migration head vs current, backend
  `/health` + `/ready`, DB connectivity, the AI provider and enabled adapters.
  WARN never fails the run (Docker/Ollama are mode-dependent).
- **smoke** drives the real chain over HTTP (it never imports app services).
  On success it prints `SentinelFlow demo smoke test: PASS` (PostgreSQL) or
  `SentinelFlow core smoke test (SQLite): PASS` (SQLite, execution fails closed),
  and exits `0`; any failure exits non-zero.

---

## Run modes

SentinelFlow has three tiers so a newcomer is never blocked by the full
Wazuh / Shuffle / TheHive / Ollama stack.

### Demo Mode (default)

- **Stack:** Frontend + Backend + PostgreSQL. That's it.
- **AI:** `AI_PROVIDER=mock` (deterministic, instant, offline).
- **Execution:** `EXECUTION_ADAPTER=mock` (zero-outbound DryRun).
- **External systems:** all disabled/empty.
- **Goal:** see the complete core flow — alert → aggregate → risk → incident →
  AI (mock) → approval → mock execution → audit/dashboard — with **no** Wazuh,
  Shuffle, TheHive or Ollama. This is what the Docker Quickstart gives you.

### AI Local Mode (optional Ollama)

Demo Mode **plus** a local model. Ollama is **optional** — never an install
blocker.

```bash
docker compose --profile ollama up -d      # start the optional Ollama container
```
Then in `.env`: `AI_PROVIDER=ollama`, `AI_MODEL=qwen3:4b`,
`AI_BASE_URL=http://ollama:11434` (Docker service name) and restart the backend.
If Ollama is unreachable, **only the AI endpoints degrade** (503); the platform
still boots and the rest of the chain works. Doctor reports it as WARN.

### Integration Lab Mode (LAB / EXPERIMENTAL / NOT PRODUCTION-CERTIFIED)

For connecting **real** Wazuh / Shuffle / TheHive instances **that you operate in
a lab you run yourself**. It is **CONFIG-gated through `.env`, never a bundled
profile** — this stack deliberately never auto-deploys or auto-downloads those
systems.

- Off by default: leave `EXECUTION_ADAPTER=mock` and the `THEHIVE_*` / `WAZUH_*` /
  `SHUFFLE_*` sections empty.
- To enable: set `EXECUTION_ADAPTER` to `shuffle` / `wazuh` / `thehive` **and**
  fully configure the matching section (base URL + credentials + workflow mapping).
  A half-configured adapter **refuses to boot** (fail-closed) rather than
  half-run.
- Real adapters dispatch through **durable dispatch** behind the same human
  approval — no auto-retry, no auto-compensation, no approval bypass.
- These adapters are **LAB / EXPERIMENTAL / NOT PRODUCTION-CERTIFIED**. Cloning
  this repo does **not** give you a production SOAR. See [SECURITY.md](../SECURITY.md).

---

## Stop, reset, data

- **Docker:** `./scripts/quickstart.ps1 -Down` (or `--down`) stops and removes
  the containers but **keeps** the `sentinelflow-pg-data` volume — restart
  without losing data. `docker compose down -v` erases the data too.
- **Native SQLite:** stop the backend and delete the local `*.db` file, then
  `alembic upgrade head` for a fresh database.
- **Native PostgreSQL:** drop/recreate the database, then `alembic upgrade head`.

---

## Next steps

- [Demo guide](demo.md) — the full end-to-end walkthrough with expected output.
- [Architecture](architecture.md) — data model, pipeline, risk rules, state machine.
- [API reference](api.md) — every REST endpoint.
- [Deployment](deployment.md) — production topology, migrations, hardening checklist.
- [Troubleshooting](TROUBLESHOOTING.md) — doctor-first fixes for common problems.
- [SECURITY.md](../SECURITY.md) — the security model and disclosure policy.
