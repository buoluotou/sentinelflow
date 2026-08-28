# SentinelFlow

**An open-source security alert orchestration and incident response platform for SOC teams.**

SentinelFlow turns raw security alerts into deduplicated, risk-scored events and manageable incidents — with a web console built for fast triage. Phase 1 delivers a complete detection-to-incident pipeline; Phase 2 (v1.1.0) layers AI-assisted analysis — alert explanation, risk summary and response recommendations — behind a human approval queue, with a read-only AI investigation view on every incident. AI output is advisory only: **Approve ≠ Execute** (see [Roadmap](#roadmap)).

```
Simulator / SIEM adapters
        ↓
   Normalization          (adapter-based unified event model)
        ↓
   Deduplication          (fingerprint + time-window aggregation)
        ↓
   Risk Engine            (explainable, rule-based scoring)
        ↓
   Incident Management    (auto-creation policy + lifecycle state machine)
        ↓
   AI Analysis            (explanation / risk summary / recommendations — advisory only)
        ↓
   Human Approval Queue   (decisions recorded; execution stays out of scope)
        ↓
   React Web Console      (Dashboard / Events / Incident Queue / Approval Queue)
```

## Features (v1.1.0)

### Phase 1 — detection to incident

- **Alert Ingestion** — HTTP/JSON API; every alert preserved as evidence
- **Normalization** — adapter pattern with a unified event model (Simulator adapter implemented, Wazuh adapter reserved)
- **Deduplication & Aggregation** — SHA-256 fingerprint + 5-minute window; 150 duplicate alerts collapse into 1 event with 150 evidence records
- **Explainable Risk Engine** — severity / frequency / public-source factors, score 0–100, four risk levels; factor breakdown stored per event
- **Incident Management** — automatic incident creation at risk ≥ 70 (idempotent), strict lifecycle state machine (`open → in_progress → resolved → closed`)
- **Dashboard API** — one aggregated endpoint for the console home page
- **React Web Console** — dark SOC theme; Dashboard, Events (filter/pagination/risk factors/evidence), Incident Queue (status transitions)
- **Scenario Simulator** — 5 attack scenarios, one-command replay for demos and tests

### Phase 2 — AI-assisted analysis behind human approval

- **AI Provider Architecture** — unified `AIProvider` contract: Mock (default, offline-safe), Ollama and OpenAI-compatible cloud endpoints; frozen structured-output protocols, typed error contract (404 / 503 / 502), switchable via `.env` without touching business code
- **AI Alert Explanation** — explicit-trigger attack-type analysis with why-risky factors and confidence; append-only history on the Event Detail page
- **AI Risk Summary** — key findings, frozen risk-driver vocabulary and analyst priority; the AI never emits a risk score (`EventRisk.score` stays the single official score)
- **AI Response Recommendation** — up to 5 suggestions drawn from a frozen six-action vocabulary; an empty list is a first-class answer ("no action warranted")
- **Approval Queue** — one-shot human approve/reject decisions over recommendations; "pending" is derived and never persisted; approving records a decision, it never executes anything
- **Incident AI Investigation** — read-only panel on the Incident Detail page aggregating the event's full AI history + approval audit via one GET; zero buttons, zero mutating traffic

## Quick Start

### Prerequisites

- Python 3.12+
- Node.js 20+
- Docker (for PostgreSQL), or SQLite for a zero-dependency trial

### 1. Backend

```bash
cd backend
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# Linux/macOS:        source .venv/bin/activate
pip install -r requirements/base.txt

# Option A — PostgreSQL (production-like)
cp ../.env.example ../.env          # then edit credentials
docker compose up -d postgres       # from the repo root
python -m alembic upgrade head

# Option B — SQLite (no Docker needed, great for a first look)
# Windows PowerShell: $env:DATABASE_URL="sqlite:///sentinelflow.db"
# Linux/macOS:        export DATABASE_URL="sqlite:///sentinelflow.db"
python -m alembic upgrade head

python -m uvicorn app.main:app --port 8000
```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173 (proxies /api to :8000)
```

### 3. Demo: generate a realistic alert storm

```bash
python simulator/runner/run.py --repeat 30
```

This replays 5 attack scenarios × 30 repeats (150 alerts), producing 5 aggregated events, risk scores, and 3 auto-created incidents. Open the console and watch the Dashboard light up — then follow [docs/demo.md](docs/demo.md) through the AI analysis chain, the Approval Queue and the Incident AI view.

## Documentation

- [Architecture](docs/architecture.md) — data model, pipeline, risk rules, state machine
- [API Reference](docs/api.md) — all REST endpoints
- [Demo Guide](docs/demo.md) — end-to-end walkthrough with expected output
- [Deployment](docs/deployment.md) — Docker, migrations, hardening checklist
- Interactive docs: run the backend and visit `http://localhost:8000/docs` (OpenAPI/Swagger)

## Testing

```bash
cd backend
python -m pytest -q        # 538+ tests (default suite; real-model E2E under tests/e2e/ is excluded)
```

## Roadmap

| Version | Milestone |
|---|---|
| v1.0.0-phase1 | Core SOC platform: ingestion → normalization → deduplication → risk → incidents → console |
| **v1.1.0** | AI security analysis: alert explanation, risk summary, recommended actions behind a human approval queue, plus the incident AI investigation view (Ollama / cloud providers via a unified interface) — this release |
| v2.0 | Automated response / SOAR integration (execution layered behind the approval queue) |

Upstream projects such as **Wazuh**, **Shuffle**, and **TheHive** are planned integration targets via clean adapter interfaces — their source code is never vendored into this repository.

## Project Structure

```
sentinelflow/
├── backend/          # FastAPI backend (services/, models/, api/, Alembic migrations)
├── frontend/         # React 19 + TypeScript + Vite console
├── simulator/        # Attack scenarios + stdlib runner CLI
├── integrations/     # Reserved: external platform adapters
├── infrastructure/   # Reserved: deployment assets
├── docs/             # Documentation
└── tests/            # Reserved: integration & E2E tests
```

## Security

The platform ships **without authentication** and is intended for evaluation in trusted networks. See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy, and the [deployment hardening checklist](docs/deployment.md#security-hardening-checklist) before any exposed deployment.

## License

MIT License. See [LICENSE](LICENSE).
