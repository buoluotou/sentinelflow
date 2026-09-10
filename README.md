# SentinelFlow

**An open-source security-alert orchestration and incident-response platform for SOC teams.**

SentinelFlow turns raw security alerts into deduplicated, risk-scored events and
manageable incidents, adds **advisory** AI analysis, and puts every response
action behind a **human approval** and a controlled, fully-audited execution
chain. The core safety rule end-to-end: **AI advises, humans decide, execution is
separate — Approve ≠ Execute.**

Out of the box it runs in **Demo Mode**: a mock AI provider and a zero-outbound
mock executor let you walk the *entire* pipeline — alert → incident → AI →
approval → execution → audit — with **no** Wazuh, Shuffle, TheHive or Ollama
installed.

---

## 5-Minute Quickstart (Docker — recommended)

You need **Docker only** (no host Python or Node). From a fresh clone:

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

The script checks Docker, creates `.env` with **random local secrets**, starts
**PostgreSQL → migrate → backend → frontend**, waits for health, runs an
end-to-end smoke test, and prints the URLs:

| What | URL |
|---|---|
| **Frontend (start here)** | **http://localhost:5173** |
| Backend API | http://localhost:8000/api/v1 |
| Interactive API docs | http://localhost:8000/docs |

**Generate a realistic alert storm** (one command; needs Python 3.10+ on the
host, or POST alerts from the `/docs` UI if you have none):

```bash
python simulator/runner/run.py --repeat 30 --base-url http://localhost:8000
```

150 alerts → 5 aggregated events → risk scores → 3 auto-created incidents. Open
the console and watch the Dashboard light up, then follow the
**[Demo guide](docs/demo.md)** through AI analysis, approval and execution.

> Prefer to run without containers? See the **[Native Quickstart](docs/QUICKSTART.md#3-native-quickstart-developers)**.
> Full install details, first-run walkthrough and reset: **[docs/QUICKSTART.md](docs/QUICKSTART.md)**.

---

## Features

**Detection → Incident**
- **Alert ingestion** over an HTTP/JSON API; every alert is preserved as evidence.
- **Normalization** into a unified event model (adapter-based).
- **Deduplication & aggregation** — SHA-256 fingerprint + time-window; 150
  duplicate alerts collapse into 1 event with 150 evidence records.
- **Explainable risk engine** — severity / frequency / public-source factors,
  score 0–100, four levels; the factor breakdown is stored per event.
- **Incident management** — automatic, idempotent case creation at risk ≥ 70 and
  a strict lifecycle state machine (`open → in_progress → resolved → closed`).

**AI-assisted analysis (advisory only)**
- A unified provider contract: **mock** (default, offline, deterministic),
  **Ollama** (local) and OpenAI-compatible cloud endpoints — switchable in `.env`
  with no code change.
- **Alert explanation**, **risk summary** and **response recommendation** (drawn
  from a frozen action vocabulary). The AI **never emits a risk score** — the
  event's own score stays authoritative.
- **Incident AI investigation** — a read-only panel aggregating an event's full
  AI history and approval audit. Zero buttons, zero mutating traffic.

**Human approval + controlled execution**
- **Approval Queue** — one-shot approve/reject decisions; "pending" is derived,
  never persisted. Approving records a decision; it executes nothing.
- **Response execution** — a Guard + policy gate, then a **durable dispatch**
  (the attempt is committed *before* any external call, so it survives a crash),
  then the adapter. An **append-only** execution audit trail.
- **External adapters** for **Shuffle**, **Wazuh** and **TheHive** behind one
  contract — implemented, but **off by default** (`EXECUTION_ADAPTER=mock`). Real
  connections require explicit configuration + credentials and are
  **LAB / EXPERIMENTAL / NOT PRODUCTION-CERTIFIED**.
- **External outcome** handling — inbound webhooks and manual reconciliation,
  kept in **separate trust domains**; outcomes are append-only and five-state
  (`unknown / pending / confirmed_success / confirmed_failure / reconciliation_failed`).
  **No auto-retry, no auto-compensation, no approval bypass.**

**Governance & observability**
- **Operator identity & RBAC** — the Bearer token is the sole server-side
  identity (any client-supplied `operator` field is ignored); only `executor` /
  `admin` may dispatch. Empty configuration stays fail-closed (401).
- **Execution policy** — an optional read-only gate (UTC window + per-action
  minimum risk) between Guard and Executor.
- **Execution metrics** and **observed adapter health** — read-only, derived from
  the audit log. *Observed ≠ probed*: no live health probe, no outbound request.

**Web console** — a dark SOC theme: Dashboard, Events, Incidents, Approval Queue,
Execute Console, Execution Audit and Observability.

---

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
   AI Analysis ──▼           explanation / risk summary / recommendation (ADVISORY)
   Recommendation
                 │
   Approval ─────▼           human approve / reject (Approve ≠ Execute)
                 │
   Execution ────▼           Guard → Policy → durable dispatch → adapter
   DispatchAttempt           pre-dispatch record committed BEFORE any external call
                 │
   External Outcome ◀──────── inbound webhook  (separate trust domain)
                 │            manual reconcile (separate trust domain)
   Dashboard ────▼           read-only aggregation for the console
```

**Built with:** FastAPI + SQLAlchemy + Alembic (backend), React 19 + TypeScript +
Vite (frontend), PostgreSQL 16 (database; SQLite supported for core-chain
development). Runtime HTTP uses the standard library. The console reaches the API
same-origin (Vite proxy in dev, nginx reverse proxy in Docker) — **no CORS
setup**.

Deeper detail: **[Architecture](docs/architecture.md)** · **[API reference](docs/api.md)** · **[Deployment](docs/deployment.md)**.

---

## Run modes

SentinelFlow has three tiers so you are never blocked by the full integrations
stack. Configuration lives in `.env` (see **[Configuration](#configuration)**).

### 1. Demo Mode (default)
Frontend + Backend + **PostgreSQL** only. `AI_PROVIDER=mock`,
`EXECUTION_ADAPTER=mock`, all external systems disabled. This is what the Docker
Quickstart gives you — the complete core flow with no external dependencies.

### 2. AI Local Mode (optional Ollama)
Demo Mode **plus** a local model. Ollama is **optional** and never an install
blocker: `docker compose --profile ollama up -d`, then set `AI_PROVIDER=ollama`,
`AI_MODEL`, `AI_BASE_URL`. If Ollama is unreachable, **only the AI endpoints
degrade** — the platform still runs.

### 3. Integration Lab Mode (LAB / EXPERIMENTAL / NOT PRODUCTION-CERTIFIED)
Connect **real** Wazuh / Shuffle / TheHive instances **in a lab you operate
yourself**. It is **config-gated, never auto-deployed**: set `EXECUTION_ADAPTER`
and fully configure the matching section (a half-configured adapter refuses to
boot). Cloning this repo does **not** give you a production SOAR.

Full instructions for each mode: **[docs/QUICKSTART.md](docs/QUICKSTART.md#run-modes)**.

---

## Configuration

All configuration is read from a single `.env` at the repo root
(pydantic-settings). **Copy the template — never hand-write it:**

```bash
cp .env.example .env      # Windows: Copy-Item .env.example .env
```

`scripts/quickstart` and `scripts/setup-dev` do this for you and fill a **random
local secret**, so a first-time Demo install needs no hand-editing.

`.env.example` is documented and grouped into eight sections:
**CORE · DATABASE · AI · EXECUTION · THEHIVE · WAZUH · SHUFFLE · OBSERVABILITY**.

Guarantees:
- **Secrets have no real default** (`*_API_KEY` / `*_TOKEN` / `*_PASSWORD` /
  `DATABASE_URL`); placeholders must be replaced. `.env` is git-ignored.
- **Optional integrations default to disabled/empty** and **fail closed** — an
  unconfigured adapter is refused at startup, never half-run.
- **Booleans are explicit** `true` / `false`.
- On startup the backend prints a **safe configuration summary** (which
  providers/adapters are enabled, the DB *driver*, whether a token is set) —
  **secrets are never logged** at any level.
- The frontend has a **single** authoritative API base (`VITE_API_BASE_URL`);
  leave it empty for the default same-origin setup.

Key variables and the hardening checklist: **[docs/deployment.md](docs/deployment.md)**.

---

## Development

Native (no Docker) setup — checks prerequisites, creates the venv, installs deps,
initializes `.env`, migrates:

```powershell
./scripts/setup-dev.ps1                     # Windows
./scripts/setup-dev.ps1 -Database sqlite    # zero-dependency local core-chain DB
```
```bash
./scripts/setup-dev.sh                      # Linux / macOS
DATABASE=sqlite ./scripts/setup-dev.sh
```

Then run the backend (`uvicorn app.main:app --reload --port 8000`) and the
frontend (`npm run dev`). Diagnose anything with **`scripts/doctor.ps1` /
`doctor.sh`** (PASS / WARN / FAIL across tools, ports, `.env`, migrations,
health, AI provider and adapters).

**Requirements:** Python ≥ 3.10 (3.12 verified), Node ≥ 20.19 (22 LTS
recommended), PostgreSQL 16 (or SQLite for the core chain up to approval).

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

---

## Testing

```bash
# Backend (2869 tests; the external-integration suite is deselected by default)
cd backend && python -m pytest -q

# Frontend
cd frontend && npm run typecheck && npm run test && npm run build
```

End-to-end over **real HTTP** (never imports app services):

```bash
./scripts/smoke.ps1     # Windows     →  "SentinelFlow demo smoke test: PASS"
./scripts/smoke.sh      # Linux/macOS
```

On PostgreSQL the smoke drives the complete chain including durable-dispatch
execution; on SQLite it proves the chain through approval and asserts the
execution step **fails closed** (`... core smoke test (SQLite): PASS`). Failures
exit non-zero.

---

## Security Model

SentinelFlow is designed around a small set of non-negotiable invariants:

- **Approve ≠ Execute.** AI output is advisory; a human decision is recorded
  separately; execution is its own controlled, audited chain.
- **Append-only audit.** Execution logs and external outcomes are never rewritten.
- **Dispatch fact ≠ external-outcome fact.** Recording an attempt is not the same
  as a confirmed external result; outcomes are five-state and reconciled only
  through separate, authenticated channels.
- **Durable dispatch.** Real external adapters commit the attempt *before* the
  outbound call, so a crash never loses track of an action.
- **Fail closed.** Empty/missing configuration (tokens, adapters, TheHive reader
  authorization) is refused, never silently allowed or half-run.
- **Identity from the token only.** Client-supplied identity fields are ignored;
  impersonation is impossible.
- **No auto-retry, no auto-compensation, no approval bypass.**

> The platform ships **without edge authentication** and is intended for
> evaluation inside trusted networks — put it behind your SSO/reverse proxy
> before any exposed deployment. Real adapters are LAB/EXPERIMENTAL. See
> **[SECURITY.md](SECURITY.md)** and the
> **[hardening checklist](docs/deployment.md#security-hardening-checklist)**.

---

## Troubleshooting

Run the doctor first — it identifies almost every install/startup problem in
seconds:

```bash
./scripts/doctor.ps1     # Windows        (add -SkipHttp if the backend is down)
./scripts/doctor.sh      # Linux / macOS
```

Then see **[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)** (logs, Docker
Quickstart issues, the SQLite execution boundary, 401/403, AI 503/502,
CORS/frontend, migrations).

---

## Roadmap

| Status | Capability |
|---|---|
| **Available** | Detection → incident pipeline; advisory AI (mock / Ollama / cloud); human approval; controlled execution with a mock executor; governance (operator RBAC, execution policy, metrics, observed health); durable dispatch, external-outcome reconciliation and recovery |
| **Available (LAB / EXPERIMENTAL)** | Real Shuffle / Wazuh / TheHive adapters — config-gated, not production-certified |
| **Next** | Broaden certified external integrations; edge authentication/authorization for exposed deployments; performance and pagination at audit-log scale |

---

## Documentation

- **[Quickstart](docs/QUICKSTART.md)** — Docker + native install, first-run walkthrough, run modes
- **[Demo guide](docs/demo.md)** — end-to-end walkthrough with expected output
- **[Architecture](docs/architecture.md)** · **[API reference](docs/api.md)** · **[Deployment](docs/deployment.md)**
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** · **[SECURITY.md](SECURITY.md)**
- Interactive API docs: run the backend and visit `http://localhost:8000/docs`
- Internal design history is kept under `docs/design/` (engineering records — not
  required reading to use SentinelFlow).

## License

MIT License. See [LICENSE](LICENSE).
