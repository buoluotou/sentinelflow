# SentinelFlow

**An open-source security alert orchestration and incident response platform for SOC teams.**

SentinelFlow turns raw security alerts into deduplicated, risk-scored events and manageable incidents — with a web console built for fast triage. Phase 1 delivers a complete, demonstrable detection-to-incident pipeline; AI-assisted analysis is the next milestone (see [Roadmap](#roadmap)).

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
   React Web Console      (Dashboard / Events / Incident Queue)
```

## Features (Phase 1 — v1.0.0-phase1)

- **Alert Ingestion** — HTTP/JSON API; every alert preserved as evidence
- **Normalization** — adapter pattern with a unified event model (Simulator adapter implemented, Wazuh adapter reserved)
- **Deduplication & Aggregation** — SHA-256 fingerprint + 5-minute window; 150 duplicate alerts collapse into 1 event with 150 evidence records
- **Explainable Risk Engine** — severity / frequency / public-source factors, score 0–100, four risk levels; factor breakdown stored per event
- **Incident Management** — automatic incident creation at risk ≥ 70 (idempotent), strict lifecycle state machine (`open → in_progress → resolved → closed`)
- **Dashboard API** — one aggregated endpoint for the console home page
- **React Web Console** — dark SOC theme; Dashboard, Events (filter/pagination/risk factors/evidence), Incident Queue (status transitions)
- **Scenario Simulator** — 5 attack scenarios, one-command replay for demos and tests

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

This replays 5 attack scenarios × 30 repeats (150 alerts), producing 5 aggregated events, risk scores, and 3 auto-created incidents. Open the console and watch the Dashboard light up. See [docs/demo.md](docs/demo.md).

## Documentation

- [Architecture](docs/architecture.md) — data model, pipeline, risk rules, state machine
- [API Reference](docs/api.md) — all REST endpoints
- [Demo Guide](docs/demo.md) — end-to-end walkthrough with expected output
- [Deployment](docs/deployment.md) — Docker, migrations, hardening checklist
- Interactive docs: run the backend and visit `http://localhost:8000/docs` (OpenAPI/Swagger)

## Testing

```bash
cd backend
python -m pytest -q        # 202 tests
```

## Roadmap

| Version | Milestone |
|---|---|
| **v1.0.0-phase1** | Core SOC platform: ingestion → normalization → deduplication → risk → incidents → console (this release) |
| v1.1.x | AI security analysis: alert explanation, risk summary, recommended actions behind a human approval queue (Ollama / cloud providers via a unified interface) |
| v2.0 | Automated response / SOAR integration |

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

Phase 1 ships **without authentication** and is intended for evaluation in trusted networks. See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy, and the [deployment hardening checklist](docs/deployment.md#security-hardening-checklist) before any exposed deployment.

## License

MIT License. See [LICENSE](LICENSE).
