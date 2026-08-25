# SentinelFlow Architecture (Phase 1)

## Overview

SentinelFlow is a monorepo with three runtime components:

| Component | Tech | Role |
|---|---|---|
| `backend/` | FastAPI + SQLAlchemy 2.0 + Alembic | Ingestion pipeline, risk engine, incident lifecycle, REST API |
| `frontend/` | React 19 + TypeScript + Vite + react-router-dom | SOC web console (dark theme) |
| `simulator/` | Python stdlib CLI | Replays 5 attack scenarios against the API |

Databases: **PostgreSQL 16** in production (via `docker-compose.yml`), **SQLite** for tests and zero-dependency trials (JSON columns use `JSON().with_variant(JSONB(), "postgresql")` for dual compatibility).

## Data Pipeline

```
Raw alert (POST /alerts or POST /normalize)
  → Normalization        adapter per source → NormalizedAlert (unified model)
  → Deduplication        SHA-256 fingerprint + 5-minute window
      ├─ merge into existing AlertGroup (alert_count++, last_seen)
      └─ or create a new AlertGroup
  → RiskService.recalculate   same DB transaction as the alert insert
  → IncidentPolicy            score ≥ 70 → auto-create Incident (idempotent)
  → commit
```

Key semantics:

- **fingerprint ≠ group.** A fingerprint identifies a *kind* of event (stable across time; excludes timestamps and raw payloads). An `AlertGroup` is one fingerprint sliced by a 5-minute aggregation window — the same fingerprint can produce multiple groups over time. Fingerprints are indexed but **not unique** for this reason.
- **Evidence is never discarded.** Every ingested alert is persisted (`alerts`) together with its raw payload (`alert_events`), and linked to its group.
- **Risk is computed on the write path only.** Reads (`GET /events`, dashboard) are pure queries against stored snapshots.
- **Two ingestion entry points, one pipeline.** `/alerts` accepts the unified `AlertCreate` format directly; `/normalize` accepts raw source payloads and runs the adapter first. Both converge into normalization → deduplication → DB.

## Data Model

```
alert_groups (an "event")
  ├── 1 ← N  alerts            evidence alerts
  ├── 1 ← N  alert_events      raw payloads (JSONB)
  ├── 1 ← 1  event_risk        current risk snapshot (unique FK)
  └── 1 ← 0..1 incidents       at most one CURRENT incident (unique FK)

incidents carry a frozen risk_score snapshot copied at creation time.
```

All primary keys are UUIDs. Migrations are hand-written Alembic scripts (`backend/migrations/versions/`, currently 0001–0004) with full upgrade/downgrade support.

## Risk Engine (rules v1.0, frozen)

Pure, explainable, rule-based scoring — no external services.

| Factor | Points |
|---|---|
| Severity base | low 10 · medium 30 · high 50 · critical 70 |
| Frequency (alerts in group) | 1–5: +0 · 6–20: +10 · 21–50: +20 · 51–100: +30 · 101+: +40 |
| Public source IP | +20 (once per event; explicit exclusion list — Python `ipaddress` flags are unreliable for multicast/TEST-NET/CGNAT) |

Score capped at 100. Levels: **0–30 low · 31–70 medium · 71–90 high · 91–100 critical.**
The factor breakdown `[{name, score, reason}]` is stored as JSON per event and surfaced in the API and console.

## Incident Lifecycle (frozen state machine)

```
open ──→ in_progress ──→ resolved ──→ closed
 │            │             │
 ├──→ false_positive ───────┴──────→ closed
 └──→ closed
```

- `open → resolved` is **illegal** (must pass through `in_progress`).
- `closed` is terminal. Invalid transitions return `409` with a stable message.
- **Auto-creation policy:** an incident is created automatically the first time an event's risk score reaches **≥ 70** (score-based, not severity-based — the Risk Engine is the single weight source). Evaluation happens only on the write path; existing events are never backfilled. One current incident per event (unique constraint + guard = idempotent under alert storms).
- `Incident.risk_score` is a **snapshot** taken at the first threshold crossing; later recalculations do not change it.

## Backend Layering (invariant)

```
api/v1/        HTTP only: request validation, exception → status-code mapping
schemas/       Pydantic v2 request/response models
services/      All business logic (normalization, dedup, risk, incidents, dashboard)
models/        SQLAlchemy ORM
```

Services `add`/`flush` but never `commit` — the transaction boundary lives in the API layer or the pipeline engine. New data sources implement `BaseAdapter` and register with the `NormalizationEngine`; the engine itself stays untouched.

## Frontend Architecture

```
React pages → api/ client (fetch wrapper) → FastAPI
```

- `types/` are field-for-field mirrors of the backend schemas — the console never derives business numbers itself.
- The home page binds the single `GET /api/v1/dashboard/summary` endpoint (real-time aggregation computed server-side).
- Incident action buttons mirror the frozen transition matrix **for display only**; validity is always decided by the backend state machine.
- Vite dev proxy forwards `/api` and `/health` to `localhost:8000`.

## Integration Points (reserved, not coupled)

Upstream platforms are adapter targets only — their source is never vendored:

| Platform | Planned role | Phase 1 state |
|---|---|---|
| Wazuh | Alert source adapter (`normalization/adapters/wazuh.py` returns 501 until implemented) | Interface reserved |
| Ollama / cloud LLMs | AI analysis providers behind a unified `AIProvider` interface | Phase 2 (v1.1.x) |
| Shuffle | Automated response execution behind the approval queue | Phase 3 (v2.0) |
| TheHive | Case management interop | Under evaluation |
