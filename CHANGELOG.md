# Changelog

All notable changes to SentinelFlow are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **AI Provider Architecture (Phase 2 Step 9)** — unified `AIProvider` contract with Mock (default, offline-safe), Ollama (`/api/chat`) and OpenAI-compatible providers ("cloud" is a deployment alias); frozen structured-output protocol `{summary, attack_type, why_risky[], confidence}`; typed error taxonomy (config / unavailable / parse); settings-based registry (`AI_PROVIDER`, `AI_MODEL`, `AI_BASE_URL`, `AI_API_KEY`). AI output is advisory only — no execution.
- **AI alert-explanation data layer (Step 10.1–10.3, unreleased work-in-progress)** — `ai_analyses` history table (migration 0005; indexed, non-unique `alert_group_id`), evidence-bounded AIRequest builder (max 20 alerts) and `AIAnalysisService` (flush-only, typed errors).
- **AI alert-explanation API (Step 10.4–10.6, unreleased work-in-progress)** — explicit-trigger endpoints `POST/GET /api/v1/events/{id}/ai-analysis` (201 with full analysis / latest read); error contract 404 (unknown event or no analysis), 503 (provider misconfigured/unreachable), 502 (protocol violation, never persisted). Real Ollama integration verified against local `qwen3:4b` (native JSON mode, configurable `AI_TIMEOUT_SECONDS`); tests stay on the mock provider.
- **Event Detail AI panel (Step 10.7, unreleased work-in-progress)** — "AI Alert Explanation" panel on the event detail page: latest analysis on load (attack type, summary, why-risky list, confidence, provider/model), explicit "Analyze with AI" trigger with disabled analyzing state and slow-model hint, backend error detail surfaced verbatim; re-analysis appends history, never edits. Browser E2E verified against real `qwen3:4b` and the mock provider.

## [1.0.0-phase1] - 2026-08-25

Phase 1: the complete detection-to-incident SOC platform.

### Added

- **Alert Ingestion** — `POST /api/v1/alerts` + listing/detail; every alert and raw payload preserved as evidence
- **Normalization** — adapter-based unified event model (`POST /api/v1/normalize`); Simulator adapter implemented, Wazuh adapter reserved (501)
- **Deduplication & Aggregation** — SHA-256 fingerprint + 5-minute window (`DEDUP_WINDOW_SECONDS`); fingerprint ≠ group semantics; window expiry opens new events
- **Explainable Risk Engine** — severity / frequency / public-source factors, 0–100 score, four levels; factor breakdown stored per event; recalculated transactionally on the write path only; surfaced in `GET /api/v1/events` (`?level=` filter)
- **Incident Management** — data model, service-layer lifecycle state machine (`open → in_progress → resolved/false_positive → closed`), REST API with 404/409 error contract, automatic creation at risk ≥ 70 (idempotent, snapshot-at-first-threshold-crossing)
- **Dashboard API** — `GET /api/v1/dashboard/summary` real-time aggregation (active incidents, severity breakdown, today's alerts/events, risk distribution)
- **React Web Console** — dark SOC theme; Dashboard (auto-refresh), Events (filter/pagination/detail with risk factors and evidence), Incident Queue (status filter, lifecycle transitions)
- **Scenario Simulator** — 5 attack scenarios + stdlib runner CLI (`--repeat`, `--timestamps now|file`)
- **Docs** — architecture, API reference, demo guide, deployment + security hardening checklist
- **Release engineering** — 202-test backend suite, Alembic migrations 0001–0004, `.env.example` with placeholders only

### Known Limitations (Phase 1)

- No authentication — deploy behind a trusted reverse proxy (see `docs/deployment.md`)
- SQLite is supported for evaluation/CI; PostgreSQL 16 is the production target
