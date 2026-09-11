# SentinelFlow Architecture (v1.4.0-rc2)

## Overview

SentinelFlow is a monorepo with three runtime components:

| Component | Tech | Role |
|---|---|---|
| `backend/` | FastAPI + SQLAlchemy 2.0 + Alembic | Ingestion pipeline, risk engine, incident lifecycle, AI analysis services, approval queue, response execution, external adapters, execution governance and observability, REST API |
| `frontend/` | React 19 + TypeScript + Vite + react-router-dom | SOC web console (dark theme) |
| `simulator/` | Python stdlib CLI | Replays 5 attack scenarios against the API |

Databases: PostgreSQL 16 in production (via `docker-compose.yml`), SQLite for tests and zero-dependency trials. JSON columns are declared as `JSON().with_variant(JSONB(), "postgresql")`, so the same models run on both engines.

## Ingestion and Normalization

Two endpoints write alerts, and both end in the same pipeline:

- `POST /alerts` takes the unified `AlertCreate` payload.
- `POST /normalize` takes a raw source payload (`{source, raw_data}`) and runs the source adapter first.

A source adapter turns its own payload shape into a `NormalizedAlert`, the unified model the rest of the pipeline consumes. Adding a source means implementing `BaseAdapter` and registering it with the `NormalizationEngine`; the engine itself does not change. An unknown source is a `400`, and a source whose adapter is not implemented is a `501` (Wazuh normalization is in that state).

## Deduplication and Aggregation

```
Raw alert (POST /alerts or POST /normalize)
  → Normalization          source adapter → NormalizedAlert
  → Deduplication          SHA-256 fingerprint + aggregation window
      ├─ merge into the existing AlertGroup (alert_count++, last_seen)
      └─ or create a new AlertGroup
  → RiskService.recalculate   same DB transaction as the alert insert
  → Incident policy           score ≥ 70 → create Incident (idempotent)
  → commit
```

The aggregation window is `DEDUP_WINDOW_SECONDS`, default 300 seconds.

A fingerprint identifies a kind of event. It is derived from alert content and stays stable over time — timestamps and raw payloads are excluded — so one fingerprint can produce several groups over time. An `AlertGroup` is one fingerprint sliced by one aggregation window, and fingerprints are indexed but not unique, which is what makes that slicing possible.

Every ingested alert is persisted in `alerts` with its raw payload in `alert_events`, linked to its group.

## Risk Engine

Rule-based scoring, rules version 1.0, no external services. The output is a score plus a factor breakdown `[{name, score, reason}]` stored as JSON per event and surfaced in the API and the console.

| Factor | Points |
|---|---|
| Severity base | low 10 · medium 30 · high 50 · critical 70 |
| Frequency (alerts in group) | 1–5: +0 · 6–20: +10 · 21–50: +20 · 51–100: +30 · 101+: +40 |
| Public source IP | +20, once per event |

The score is capped at 100. Levels: 0–30 low · 31–70 medium · 71–90 high · 91–100 critical.

The public-source check uses a hardcoded exclusion list (private, loopback, link-local, multicast, reserved, unspecified, plus CGNAT and the TEST-NET documentation ranges) rather than `ipaddress.is_global` alone, because the stdlib flags are not reliable across Python versions — on 3.12.x multicast is classified as global and `100.64.0.0/10` as neither private nor reserved.

Scoring runs on the write path only, in the same transaction as the alert insert. Reads (`GET /events`, the dashboard) query the stored snapshot.

## Incidents

```
open ──→ in_progress ──→ resolved ──→ closed
 │            │             │
 ├──→ false_positive ───────┴──────→ closed
 └──→ closed
```

- `open → resolved` is rejected; the transition must pass through `in_progress`.
- `closed` is terminal. An invalid transition returns `409` with a stable message.
- An incident is created automatically the first time an event's risk score reaches 70 or more (`AUTO_CREATE_THRESHOLD = 70`). The decision is score-based, not severity-based, so the risk engine stays the single source of weights.
- Auto-creation is evaluated on the write path only; existing events are never backfilled. One current incident per event (unique constraint plus a guard), so an alert storm cannot create duplicates.
- `Incident.risk_score` is a snapshot taken at the first threshold crossing. Later recalculations do not change it, and no AI result writes it back.

## AI Analysis (advisory only)

```
User trigger (console button / API POST)
  → RequestBuilder         AlertGroup + EventRisk + evidence (≤20) → AIRequest
  → AIProvider.generate()  dispatches by task: alert_explanation / risk_summary /
                           response_recommendation
  → Protocol parse         Pydantic schema, extra=forbid; a violation is a 502 and is
                           never persisted
  → append-only history row → flush (the API layer owns the commit)
```

- Provider registry (`services/ai/registry.py`): one `AIProvider` contract with three implementations — Mock (default, deterministic, offline), Ollama (`/api/chat`, native JSON mode) and OpenAI-compatible ("cloud" is a deployment alias for the same code path). Selection is configuration only (`AI_PROVIDER`, `AI_MODEL`, `AI_BASE_URL`, `AI_API_KEY`, `AI_TIMEOUT_SECONDS`); changing the model does not touch business code.
- Protocols (`services/ai/models.py`): every task output sets `extra=forbid`, so an unknown field such as a smuggled `risk_score` is a `502` rather than being coerced. Recommendations are restricted to six actions, and an empty list is a valid answer.
- Errors: configuration or unreachable provider → `503`, protocol violation → `502`. A failed call never persists a row.
- History: AI rows are the event's append-only history. Re-triggering appends, reads return the latest row (`created_at DESC, id DESC`), and deleting an incident does not delete AI history.

AI output is advisory. It never carries a risk score: `EventRisk.score` is the only official score.

## Approval

`ai_response_approvals` stores exactly `approved` or `rejected` (CHECK constraint plus `UNIQUE(recommendation_id)`). "Pending" is derived — a recommendation with no decision row — and is never stored.

Decisions are insert-only and one-shot, with `reviewed_at` stamped by the server. A client sends `reviewer` and an optional comment; other fields are rejected. Approving records a human decision and nothing else: it does not block an IP, create an incident, touch `EventRisk`, or call an orchestrator. Execution is a separate chain that the client requests.

Write access depends on the deployment mode. In demo mode (the default) the approval endpoints are tokenless and the body `reviewer` is display-only. In production mode a Bearer token is required, an authenticated operator without the approval permission gets `403`, and the recorded reviewer is always the token's principal rather than the body field.

## Response Execution

```
Approved recommendation
  → Execute Intent            (client: execution_id + note)
  → Auth / RBAC gate          (Bearer token → operator; executor / admin only)
  → execution_log: requested  (append-only row, same transaction)
  → Guard                     (rejection codes over EXECUTABLE_ACTIONS)
  → Execution policy          (read-only: UTC time window + risk thresholds)
  → durable dispatch record   (dispatch_attempt, committed on its own transaction)
  → ResponseExecutor          (one active adapter: exactly one)
      ├─ MockExecutor         (default; offline DryRun, no outbound request)
      ├─ ShuffleExecutor      (workflow orchestration)
      ├─ WazuhExecutor        (endpoint / security response)
      └─ TheHiveExecutor      (case creation; escalate_to_incident only)
  → execution_log: dispatched → succeeded / failed
  → append-only audit         (no secrets persisted; redacted via ***)
```

Actions: `block_source_ip`, `isolate_host`, `disable_account`, `hunt_related_activity`, `escalate_to_incident`, `monitor_only`. Statuses: `requested`, `guard_rejected`, `dispatched`, `succeeded`, `failed`, plus `compensation_requested`, `compensation_succeeded` and `compensation_failed` for the reverse chain.

**Operator identity.** Write endpoints require a Bearer token resolved to an operator registered in `OPERATORS_JSON` (name, token, role: `viewer` / `reviewer` / `executor` / `admin`); the legacy `EXECUTION_TOKEN` fallback maps to the synthetic operator `legacy-execution` with role `executor`. A missing, empty or wrong credential is a `401` before any row is written, and an empty registry keeps that path closed. Dispatch requires `executor` or `admin`; any other role gets `403`. The token's operator name is the only identity recorded, so a client-supplied `operator` field is accepted and ignored.

**Guard.** Five rejection codes — `approval_not_approved`, `recommendation_missing`, `action_not_in_snapshot`, `action_not_executable`, `executor_unsupported` — all checked before any outbound call. A guard refusal is recorded as `guard_rejected`.

**Execution policy.** With `EXECUTION_POLICY_ENABLED=true`, every dispatch also passes a read-only gate between the guard and the executor: a UTC server-clock window `[start, end)` and a per-action minimum risk threshold read from `EventRisk.score`. A policy refusal appends `guard_rejected` with `detail.source="policy"`, which distinguishes it from a structural guard refusal. A malformed policy configuration is a `503` with rollback, never a silent allow.

**Durable dispatch.** Before the adapter is called, the dispatch binding (execution, approval, adapter, action, target, server-clock start) is committed to `dispatch_attempt` on its own transaction. That record survives a caller rollback, a terminal-write failure or a process crash, which is what the caller's business transaction cannot do. It is unique per `execution_id` and per `approval_id`, so a duplicate or concurrent dispatch is refused before any request leaves the process. A committed attempt with no terminal row is a candidate for manual reconciliation, never for an automatic retry.

**Single active adapter.** `EXECUTION_ADAPTER` names exactly one adapter; an empty or multi-valued setting is rejected at startup. The selected adapter's `supports()` decides which actions it can execute, and an unsupported action is `executor_unsupported`.

**Credentials.** Each adapter has its own `AdapterCredentials` (Bearer API key, or user/password for Wazuh). Secrets travel only `.env → Settings → AdapterCredentials → Authorization header`; a shape check rejects query strings and userinfo in a base URL, and `SecretRedactionFilter` keeps credentials out of Python logs.

**Outcomes.** Adapter results are classified per adapter (timeouts, HTTP faults, unavailable) and recorded in `detail`. An ambiguous answer — success without an identity — raises `ExecutorOutcomeViolation`. There is no automatic retry anywhere.

**Compensation.** The reverse path is symmetric where the adapter supports it (Wazuh: isolate→release, block→unblock). `disable_account` has no machine reversal, so its compensation is rejected outright; `escalate_to_incident` is non-compensable because case lifecycle stays with the human investigator. The reverse path commits its own durable record to `compensation_attempt` before the external call, on the same reasoning as forward dispatch. Real-adapter compensation is experimental.

**Idempotency.** `external_execution_id` tracks the adapter-side identity for deduplication and reconciliation.

**Safety boundary.** No automatic approval, no automatic retry, no adapter fan-out, no hidden execution. Adapter implementations exist, but the default configuration stays offline (`EXECUTION_ADAPTER=mock`); a real connection requires `.env` configuration and credentials.

## Outcome Channels

Dispatch outcome and external effect are two separate fact layers. `execution_log.succeeded` / `failed` record what happened to the dispatch request; `execution_outcome` records what the external system later did. Neither layer rewrites the other: `succeeded` plus `confirmed_failure` is legal (the command landed, the effect did not).

`execution_outcome` is append-only with no unique index — late or reordered facts are appended, and the current outcome is the fact with the latest `observed_at`. The outcome vocabulary is `unknown`, `pending`, `confirmed_success`, `confirmed_failure`, `reconciliation_failed`, stored under a CHECK constraint. Outcome facts never trigger execution, retry or compensation.

Two channels write these facts, and they are the only two; background polling and schedulers do not exist.

- **Webhook (push).** `POST /webhooks/{adapter}` lets an external system report an outcome. The adapter identity comes from the route, and each adapter authenticates with its own callback token (`SHUFFLE_CALLBACK_TOKEN`, `WAZUH_CALLBACK_TOKEN`, `THEHIVE_CALLBACK_TOKEN`). Callback credentials are a third trust domain, separate from both the operator registry and the outbound API keys. The offline mock adapter has no callback channel.
- **Manual reconcile (pull).** `POST /executions/{execution_id}/reconcile` asks the platform to read the external system's current state for one past execution and append what it finds. The adapter and external reference are read from the dispatch fact; the operator identity comes from the Bearer token. The production read-adapter registry is empty, so every adapter is currently refused with `404 adapter read unsupported`.

## Read Models

These views are read-only and derived from stored facts. None of them writes, and none of them recomputes a business number on the client.

- **Execution metrics** — `GET /executions/metrics`, no credential. `total_chains`, `executed_chains`, `succeeded`, `failed`, `guard_rejected`, `in_flight`, `success_rate = succeeded / (succeeded + failed)`, `executor_failure_rate`, `guard_rejection_rate = guard_rejected / total_chains` (guard rejections never enter the outcome denominators), `rejections_by_source`, `failure_classifications`, `latency` and `by_adapter`. An empty denominator is `null`, which the UI renders as N/A rather than 0%.
- **Observed adapter health** — `GET /executions/health`, no credential and no outbound request. Per-adapter `observed_status` from `unknown` / `healthy` / `degraded` / `failing`, derived from the recent-20 terminal chain window. Thresholds: `healthy ≥ 0.9`, `degraded ≥ 0.5`. Guard refusals and in-flight chains stay out of the window, so governance pressure is not attributed to an adapter. These are observed values; there is no live probe.
- **Incident AI context** — `GET /incidents/{id}/ai-context` composes an incident's event AI history into one DTO through `viewonly` ORM traversals: no schema change and no writes. The incident snapshot exposes its creation-time `risk_score`; the AI histories keep their protocol shapes, each recommendation carrying its `approval | null`. An unknown incident is a `404` before anything is assembled, so no data from another case can be returned.
- **Dashboard** — `GET /dashboard/summary` aggregates open incidents, severity breakdown, today's alerts and events, and the risk distribution in one query path, with no cache and no extra tables.

The metrics and health services contain no `add`, `commit`, `flush` or `delete`; repeated GETs against an unchanged log return identical bodies.

## Data Model

```
alert_groups (an "event")
  ├── 1 ← N  alerts            evidence alerts
  ├── 1 ← N  alert_events      raw payloads (JSONB)
  ├── 1 ← 1  event_risk        current risk snapshot (unique FK)
  ├── 1 ← 0..1 incidents       at most one current incident (unique FK)
  ├── 1 ← N  ai_analyses                  append-only AI explanation history (indexed, non-unique)
  ├── 1 ← N  ai_risk_summaries            append-only AI risk-summary history (indexed, non-unique)
  └── 1 ← N  ai_response_recommendations  append-only recommendation history
                 └── 1 ← 0..1 ai_response_approvals  one-shot human decision (UNIQUE)

execution_log (append-only; FK approval_id → ai_response_approvals ON DELETE NO ACTION)
  11 columns: execution_id · alert_group_id · approval_id · adapter_name ·
  action · target · operator · status (8 legal values) · detail (JSONB) ·
  external_execution_id · created_at.
  3 partial unique indexes enforce chain integrity.

execution_outcome    append-only external-effect facts, no unique index (time series by observed_at)
dispatch_attempt     one durable execute attempt per execution_id and per approval_id
compensation_attempt one durable compensation attempt per compensation chain
```

Incidents carry a risk score snapshot copied at creation time and reach their event's AI history through read-only (`viewonly`) traversals. No AI table has a foreign key to `incidents`.

All primary keys are UUIDs. Migrations are hand-written Alembic scripts in `backend/migrations/versions/`, currently 0001–0014, with upgrade and downgrade for each.

## Backend Layering

```
api/v1/        HTTP only: request validation, exception → status-code mapping
schemas/       Pydantic v2 request/response models
services/      All business logic (normalization, dedup, risk, incidents, dashboard,
               ai providers, ai analysis services, approvals, incident ai context,
               response execution, external adapters, credential boundary)
models/        SQLAlchemy ORM
```

Services may `add` and `flush` but never `commit`; the transaction boundary belongs to the API layer or the pipeline engine. Two exceptions commit on their own connection, both for durability: `dispatch_attempt` and `compensation_attempt`.

## Frontend Console

```
React pages → api/ client (fetch wrapper) → FastAPI
```

- `types/` mirrors the backend schemas field for field; the console does not derive business numbers itself.
- The home page renders `GET /api/v1/dashboard/summary`; the aggregation is computed server-side.
- Incident action buttons mirror the transition matrix for display only. Validity is decided by the backend state machine.
- AI panels (explanation, risk summary, recommendation) fire only on a user action: page load emits GETs only, never a POST, and no AI panel shows a risk score.
- The Approval Queue records one-shot decisions (a `201` removes the row locally, a `409` re-syncs from the server). The Incident Detail AI panel is read-only and has no buttons.
- The Execute Console drives the execution chain (select action → confirm → observe result). The Execution Audit page renders the append-only `execution_log` with its redacted detail.
- The Observability page (`/observability`) is read-only: no buttons, no write traffic, no auto-refresh, and it mirrors `GET /executions/metrics` plus `GET /executions/health` field for field.
- The Vite dev proxy forwards `/api` and `/health` to `localhost:8000`.

## Integration Points

Upstream platforms are adapter targets; their source is never vendored.

| Platform | Role | State |
|---|---|---|
| Wazuh | Alert source adapter (normalization) and endpoint response adapter (active-response) | Normalization: interface reserved, returns `501`. Response adapter implemented |
| Ollama / cloud LLMs | AI analysis providers behind the `AIProvider` interface | Implemented |
| Shuffle | Workflow orchestration adapter | Implemented |
| TheHive | Case management / investigation adapter | Implemented |
