# SentinelFlow

SentinelFlow is an open-source platform for security-alert orchestration and
incident response. It ingests alerts over an HTTP/JSON API, normalizes and
deduplicates them into scored events, opens incidents from the high-risk ones,
and puts every response action behind a human approval and a separate execution
path with an append-only audit trail.

It runs offline out of the box. Demo Mode uses a mock AI provider and a
zero-outbound mock executor, so the whole pipeline — alert → event → incident →
AI → approval → execution → audit — works with no Wazuh, Shuffle, TheHive or
Ollama installed.

SentinelFlow is not a production SOAR. It is a demo and reference implementation
you can read, run and extend: it ships without edge authentication, the real
integrations are lab-only, and the external-outcome channels refuse rather than
guess ([Known limitations](#known-limitations)).

## Why

Alert queues are not short of alerts; they are short of decisions. An analyst
needs to know which alert matters, why it scored the way it did, and what
happens if they act on it — and that record has to survive an incident review.

The design follows from that:

- Detection is deterministic. Deduplication (SHA-256 fingerprint within a time
  window) and risk scoring are rule-based, and each event stores the factor
  breakdown behind its 0–100 score.
- AI advises. Models write explanations, risk summaries and response
  recommendations from a fixed action vocabulary. They never emit a risk score,
  and no AI output reaches an external system on its own.
- Approving is not executing. A decision is recorded as its own fact; execution
  is a separate authenticated path with its own guard, policy gate and durable
  dispatch record.
- Attempts are not results. Dispatching a request to an external system and
  reading back a confirmed result from it are two different facts, stored
  separately.

## Quickstart

### Docker (recommended)

You need Docker only — no host Python or Node.

```powershell
# Windows (PowerShell)
git clone https://github.com/buoluotou/sentinelflow.git
cd sentinelflow
./scripts/quickstart.ps1
```
```bash
# Linux / macOS
git clone https://github.com/buoluotou/sentinelflow.git
cd sentinelflow
./scripts/quickstart.sh
```

The script checks Docker, writes `.env` with random local secrets, starts
PostgreSQL → migrate → backend → frontend in that order, waits for health, runs
an end-to-end smoke test and prints the URLs:

| What | URL |
|---|---|
| Frontend (start here) | http://localhost:5173 |
| Backend API | http://localhost:8000/api/v1 |
| Interactive API docs | http://localhost:8000/docs |

The first run is dominated by base-image downloads and the two image builds, so
it tracks your network: seconds once the images are cached, minutes on a fresh
machine or a slow link. Later starts are fast.

If PyPI downloads stall on a restricted network, point the build at a mirror you
trust (the default stays the official PyPI): set
`PIP_INDEX_URL=https://<trusted-mirror>/simple/` in `.env` and rebuild with
`./scripts/quickstart.sh --rebuild`, or build directly with
`docker compose build --build-arg PIP_INDEX_URL=https://<trusted-mirror>/simple/`.
See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

### Native (no containers)

Native setup checks prerequisites, creates the backend venv, installs
dependencies, initializes `.env` and runs the migrations:

```powershell
./scripts/setup-dev.ps1                     # Windows
./scripts/setup-dev.ps1 -Database sqlite    # local core-chain DB, no PostgreSQL
```
```bash
./scripts/setup-dev.sh                      # Linux / macOS
DATABASE=sqlite ./scripts/setup-dev.sh
```

Then start the two dev servers:

```bash
# terminal 1 — backend
cd backend && uvicorn app.main:app --reload --port 8000

# terminal 2 — frontend
cd frontend && npm run dev
```

Requirements: Python ≥ 3.10 (3.12 verified), Node ≥ 20.19 (22 LTS recommended),
PostgreSQL 16 — or SQLite for the core chain up to approval. Full instructions:
[docs/QUICKSTART.md](docs/QUICKSTART.md#3-native-quickstart-developers).

### Configuration

All settings come from one `.env` at the repo root (pydantic-settings). Copy the
template instead of writing it by hand — `scripts/quickstart` and
`scripts/setup-dev` do it for you and fill a random local secret:

```bash
cp .env.example .env      # Windows: Copy-Item .env.example .env
```

`.env.example` is grouped into eight documented sections: **CORE · DATABASE · AI
· EXECUTION · THEHIVE · WAZUH · SHUFFLE · OBSERVABILITY**. Secrets have no
working default (`*_API_KEY`, `*_TOKEN`, `*_PASSWORD`, `DATABASE_URL` are
placeholders), `.env` is git-ignored, and the backend prints a startup summary of
which providers and adapters are enabled — with a boolean for "token set", never
the values. The frontend reads one variable, `VITE_API_BASE_URL`, and defaults to
the same-origin setup. Key variables and the hardening checklist:
[docs/deployment.md](docs/deployment.md).

### Verify and test

```bash
# environment and config diagnostics (PASS / WARN / FAIL; -SkipHttp if the backend is down)
./scripts/doctor.ps1     # Windows
./scripts/doctor.sh      # Linux / macOS

# end-to-end over real HTTP, never importing app services
./scripts/smoke.ps1      # Windows → "SentinelFlow demo smoke test: PASS"
./scripts/smoke.sh       # Linux / macOS

# backend: 2996 tests; the external-integration suite is deselected by default
cd backend && python -m pytest -q

# frontend
cd frontend && npm run typecheck && npm run test && npm run build
```

On PostgreSQL the smoke drives the complete chain, including durable-dispatch
execution. On SQLite it proves the chain through approval and asserts that the
execution step fails closed (`... core smoke test (SQLite): PASS`). Failures exit
non-zero.

## Demo and walkthrough

Generate an alert storm (one command; it needs Python 3.10+ on the host, or you
can POST alerts from the `/docs` UI instead):

```bash
python simulator/runner/run.py --repeat 30 --base-url http://localhost:8000
```

That replays five attack scenarios thirty times each: 150 alerts collapse into 5
aggregated events, which get risk scores, and 3 of them auto-create incidents.
Open http://localhost:5173 and follow the
**[demo guide](docs/demo.md)** — a 15-minute walkthrough with expected output at
every step: the dashboard counters, the events list and its risk factors, the
incident lifecycle, the three AI panels on an event, the approval queue, the
execution audit, the observability page, and the read-only incident AI
investigation view.

The console has six pages — Dashboard, Events, Incidents, Approval Queue,
Execution Audit, Observability. Execution is dispatched from the **AI
Investigation** panel on an incident; there is no separate Execute Console page.

## Architecture

```
        Simulator / SIEM adapters
                 │
   Alert ────────▼
   Normalization            adapter-based unified event model
                 │
   Deduplication ─▼          fingerprint + time-window aggregation
   Risk Engine              explainable, rule-based scoring (0–100)
                 │
   Incident ─────▼           auto-creation policy + lifecycle state machine
                 │
   AI Analysis ──▼           explanation / risk summary / recommendation (advisory)
                 │
   Approval ─────▼           human approve / reject — records a decision only
                 │
   Execution ────▼           Guard → policy → durable dispatch → adapter
                 │
   External Outcome ◀──────── inbound webhook  (separate trust domain)
                 │            manual reconcile (separate trust domain)
   Dashboard ────▼           read-only aggregation for the console
```

Alerts are preserved as evidence; normalization maps adapter payloads onto one
event model; deduplication aggregates by fingerprint inside
`DEDUP_WINDOW_SECONDS` (300 by default); the risk engine caps the score at 100
and stores its factors. Incidents are created once per event at risk ≥ 70 and
move through `open → in_progress → resolved → closed` (with `false_positive` as
an exit state). Approval decisions, execution audit rows and external outcomes
are separate append-only tables; an outcome is one of `unknown`, `pending`,
`confirmed_success`, `confirmed_failure` or `reconciliation_failed`.

**Stack:** FastAPI + SQLAlchemy + Alembic (backend); React 19 + TypeScript +
Vite (frontend); PostgreSQL 16, with SQLite supported for core-chain development.
The console reaches the API same-origin — Vite proxies `/api` in dev, nginx does
it in the Docker image — so there is no CORS configuration to tune. Outbound
adapter calls use the standard library (`urllib`, with redirects disabled).

```
sentinelflow/
├── backend/          # FastAPI: services/, models/, api/, Alembic migrations
├── frontend/         # React 19 + TypeScript + Vite console
├── simulator/        # Attack scenarios + a stdlib runner CLI
├── integrations/     # External adapter interfaces (Shuffle / Wazuh / TheHive)
├── scripts/          # quickstart · setup-dev · doctor · smoke (.ps1 + .sh)
├── infrastructure/   # Deployment assets
└── docs/             # Documentation
```

### Run modes

**Demo Mode (default).** Frontend + backend + PostgreSQL.
`AI_PROVIDER=mock`, `EXECUTION_ADAPTER=mock`, every external system disabled —
this is what the Docker quickstart gives you.

**AI Local Mode.** Demo Mode plus a local model:
`docker compose --profile ollama up -d`, then set `AI_PROVIDER=ollama`,
`AI_MODEL` and `AI_BASE_URL`. Ollama is optional and never blocks install; if it
is unreachable, only the AI endpoints degrade. The platform still runs. To use an
OpenAI-compatible endpoint instead, set `AI_PROVIDER=openai_compatible` (or its
`cloud` alias) with `AI_BASE_URL` and `AI_API_KEY`.

**Integration Lab Mode.** Real Wazuh / Shuffle / TheHive instances in a lab you
operate yourself. It is config-gated, never auto-deployed: set
`EXECUTION_ADAPTER` and fully configure the matching `.env` section — a
half-configured adapter refuses to boot. These connections are lab-only and not
production-certified. Per-mode instructions:
[docs/QUICKSTART.md](docs/QUICKSTART.md#run-modes).

## Security boundaries

- AI output is advisory. It is stored and displayed; it never writes a risk
  score and never triggers an action.
- A decision is recorded separately from execution. Approving or rejecting
  writes one decision per recommendation and executes nothing.
- Execution is its own guarded path. It needs a bearer token with the `executor`
  or `admin` role, passes the Guard and the optional execution policy (UTC window
  plus per-action minimum risk), and commits a durable dispatch record before any
  external call. There is no auto-retry and no approval bypass.
- The audit trail is append-only. Execution logs and external outcomes are
  written once and never rewritten.
- Identity comes from the bearer token. The execution operator is the
  authenticated principal; a client-supplied `operator` field is ignored. In
  production mode the recorded approval reviewer is the token's principal too.
- A missing configuration fails closed. An empty operator registry
  (`OPERATORS_JSON` and `EXECUTION_TOKEN` both empty) returns 401 on every write
  path; a half-configured adapter refuses to boot. `DEPLOYMENT_MODE=production`
  additionally requires PostgreSQL, an operator registry with at least one
  approval-capable and one execution-capable role, a real execution adapter, no
  compensation workflows, and loopback binding.

## Known limitations

**The platform ships without edge authentication.** There is no login, session
or SSO layer; published ports bind to loopback (`BIND_HOST=127.0.0.1`) as the
exposure control. Exposing it beyond a trusted network requires your own
SSO/reverse proxy. See [SECURITY.md](SECURITY.md) and the
[hardening checklist](docs/deployment.md#security-hardening-checklist).

**The console is a demo-mode tool for decisions.** With
`DEPLOYMENT_MODE=production`, `POST .../approve` and `POST .../reject` require a
bearer token, and the shipped UI sends no `Authorization` header for them: it has
no session layer and stores no credentials, so those calls return 401. The
execute dialog does accept a token typed in by hand, so execution works only if
an operator pastes one per action. Until an edge or session layer exists, treat
the browser console as a demo-mode interface.

**Real Wazuh / Shuffle / TheHive connections are lab-only.** They are
config-gated, require credentials you provide for a lab you run, and are not
production-certified.

**External outcomes refuse by design.** Inbound webhook callbacks and manual
reconcile are implemented, tested and persist outcomes, but the external-state
vocabulary is empty for every adapter and the production read-adapter registry is
empty. Every reported state is therefore refused with a static `404` or `422`
instead of being mapped, so no outcome is fabricated. Configuring a real adapter
does not give you `confirmed_success` today; that needs the evidenced vocabulary
and a registered read adapter.

**There is no coverage gate.** CI runs the backend suite (2996 tests collected by
default), the frontend typecheck, tests and production build, and a compose smoke
on PostgreSQL — but nothing measures or enforces coverage, so the number can
regress unnoticed. For reference, `pytest --cov=app` over the default backend
suite reports 98% statement coverage (124 of 5093 statements in
`backend/app` uncovered). `pytest-cov` is in `backend/requirements/dev.txt`; no
threshold is set.

## Roadmap

| Status | Capability |
|---|---|
| **Available** | Detection → incident pipeline; advisory AI (mock / Ollama / OpenAI-compatible); human approval; controlled execution with the mock executor; governance (operator RBAC, execution policy, metrics, observed adapter health); durable dispatch |
| **Implemented — fail-closed by design** | External-outcome channels (inbound webhook + manual reconcile, in separate trust domains). The external-state vocabulary and the production read-adapter registry are empty, so outcomes are refused with a static `404` / `422`. Configuring an adapter does not change this yet |
| **Implemented — certification blocked** | Real Shuffle / Wazuh / TheHive adapters: config-gated, lab-only, not production-certified |
| **Next** | Certify an evidenced external-state vocabulary and the read registry behind it; edge authentication / session layer for the console; production certification for the real adapters; further read-path work at audit-log scale (the execution audit list is chain-level paginated in SQL) |

## Documentation

- **[Quickstart](docs/QUICKSTART.md)** — Docker and native install, first-run walkthrough, run modes
- **[Demo guide](docs/demo.md)** — end-to-end walkthrough with expected output
- **[Architecture](docs/architecture.md)** · **[API reference](docs/api.md)** · **[Deployment](docs/deployment.md)**
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** · **[SECURITY.md](SECURITY.md)**
- Interactive API docs: run the backend and open `http://localhost:8000/docs`
- Internal design history lives under `docs/design/` — engineering records, not
  required reading to use SentinelFlow.

## License

MIT License. See [LICENSE](LICENSE).
