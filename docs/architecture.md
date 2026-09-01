# SentinelFlow Architecture (v1.3.0)

## Overview

SentinelFlow is a monorepo with three runtime components:

| Component | Tech | Role |
|---|---|---|
| `backend/` | FastAPI + SQLAlchemy 2.0 + Alembic | Ingestion pipeline, risk engine, incident lifecycle, AI analysis services, approval queue, response execution, external adapters, execution governance & observability, REST API |
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
  ├── 1 ← 0..1 incidents       at most one CURRENT incident (unique FK)
  ├── 1 ← N  ai_analyses                append-only AI explanation history (indexed, non-unique)
  ├── 1 ← N  ai_risk_summaries          append-only AI risk-summary history (indexed, non-unique)
  └── 1 ← N  ai_response_recommendations  append-only recommendation history
                 └── 1 ← 0..1 ai_response_approvals  one-shot human decision (UNIQUE)

execution_log (append-only; FK approval_id → ai_response_approvals ON DELETE NO ACTION)
  11 frozen columns: execution_id · alert_group_id · approval_id · adapter_name ·
  action · target · operator · status (8 legal values) · detail (JSONB) ·
  external_execution_id · created_at.
  3 partial unique indexes enforce chain integrity.

incidents carry a frozen risk_score snapshot copied at creation time and reach
their event's AI history through read-only (viewonly) traversals — no incident
FK on any AI table.
```

All primary keys are UUIDs. Migrations are hand-written Alembic scripts (`backend/migrations/versions/`, currently 0001–0009) with full upgrade/downgrade support.

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
- `Incident.risk_score` is a **snapshot** taken at the first threshold crossing; later recalculations do not change it — and no AI result ever writes it back.

## AI Analysis Layer (Phase 2, advisory only)

```
Explicit trigger (console button / API POST)
  → RequestBuilder         AlertGroup + EventRisk + evidence (≤20) → frozen AIRequest
  → AIProvider.generate()  dispatches by task: alert_explanation / risk_summary /
                           response_recommendation
  → Protocol parse         frozen Pydantic schema, extra=forbid; violation → 502, never persisted
  → append-only history row → flush (API owns commit)
```

- **Provider registry** (`services/ai/registry.py`): one `AIProvider` contract, three implementations — Mock (default, deterministic, offline-safe), Ollama (`/api/chat`, native JSON mode), OpenAI-compatible ("cloud" is a deployment alias, not a separate code path). Selection is pure configuration (`AI_PROVIDER` / `AI_MODEL` / `AI_BASE_URL` / `AI_API_KEY` / `AI_TIMEOUT_SECONDS`); business code never changes when the model changes.
- **Frozen protocols** (`services/ai/models.py`): every task output is `extra=forbid` — a smuggled `risk_score` or unknown field is a `502`, never coerced. Recommendations are limited to a frozen six-action vocabulary; an empty list is a first-class answer.
- **Error taxonomy**: Config / Unavailable / Parse → HTTP `503` / `503` / `502`; failures never persist a row.
- **History semantics**: AI rows are the AlertGroup's append-only history. Re-triggering appends; reads return the latest (`created_at DESC, id DESC`). Deleting an incident never deletes AI history.

## Approval Queue (Approve ≠ Execute)

- `ai_response_approvals` stores exactly `{approved, rejected}` (CHECK constraint + `UNIQUE(recommendation_id)`); **"pending" is derived** (recommendation without a decision row) and never persisted.
- Decisions are INSERT-only, one-shot, with `reviewed_at` server-stamped; clients send only `reviewer` (+ optional comment), extra fields rejected.
- Approving records a human decision. It never blocks an IP, creates an incident, touches `EventRisk`, or calls any orchestrator — execution is Phase 3 (v1.2.0).

## Response Execution Layer (Phase 3, v1.2.0)

```
Approved Recommendation
  → Explicit Execute Intent   (client: execution_id + note)
  → Auth / RBAC gate           (Bearer token → Operator; executor/admin only)
  → execution_log: requested  (append-only row created in same transaction)
  → Guard                     (5 rejection codes over EXECUTABLE_ACTIONS)
  → Execution Policy          (read-only: time window + risk thresholds; v1.3.0)
  → ResponseExecutor          (Single-Active-Adapter: exactly ONE adapter)
      ├─ MockExecutor          (default; zero-outbound DryRun)
      ├─ ShuffleExecutor       (workflow orchestration)
      ├─ WazuhExecutor         (endpoint / security response)
      └─ TheHiveExecutor       (case creation; escalate_to_incident only)
  → execution_log: dispatched → succeeded / failed
  → Append-only audit         (secrets never persisted; redacted via ***)
```

Key semantics:

- **Eight-word vocabulary** — `block_source_ip`, `isolate_host`, `disable_account`, `hunt_related_activity`, `escalate_to_incident`, `monitor_only` (execution vocabulary); plus `requested` / `guard_rejected` / `dispatched` / `succeeded` / `failed` (status vocabulary). Compensation adds `compensation_requested` / `compensation_succeeded` / `compensation_failed`.
- **Guard** — five rejection codes (`action_not_executable`, `approval_not_found`, `approval_already_executed`, `executor_unsupported`, `adapter_misconfigured`); all checked before any outbound call.
- **Single-Active-Adapter** — `EXECUTION_ADAPTER` names exactly ONE adapter; multi-value selection is rejected at startup. The selected adapter's `supports()` decides which actions it can execute; unsupported actions are `executor_unsupported`.
- **Credential boundary** — each adapter has its own `AdapterCredentials` (Bearer API-key or Basic user/password shape); secrets travel only `.env → Settings → AdapterCredentials → Authorization header`; URL shape gate rejects query strings / userinfo in BASE_URL; `SecretRedactionFilter` prevents credential leakage in Python logging.
- **Outcome handling** — frozen per-adapter outcome matrix (timeouts / HTTP faults / unavailable classified in `detail`); ambiguous answers (success without identity) raise `ExecutorOutcomeViolation`; zero automatic retry anywhere.
- **Compensation** — symmetric where the adapter supports it (Wazuh: isolate→release, block→unblock); `disable_account` refuses compensation outright; `escalate_to_incident` is non-compensable (case lifecycle is human-led).
- **Idempotency propagation** — `external_execution_id` tracks the adapter-side identity for dedup / reconciliation.
- **Safety boundary** — No automatic approval. No automatic retry. No internal adapter fan-out. No hidden execution. Adapter implementations exist, but the default configuration stays offline (`EXECUTION_ADAPTER=mock`); real connections require explicit `.env` configuration plus credentials.

## Execution Governance & Observability (Phase 3.3, v1.3.0)

The governance triangle over the v1.2.0 execution layer — Who can execute + When execution is allowed + How execution performs. No new tables, no new migrations, no new execution states: everything is derived read-only from the frozen `execution_log` facts.

- **Operator identity & RBAC** — static registry from `OPERATORS_JSON` (name + token + role: `viewer` / `reviewer` / `executor` / `admin`); one token resolves to exactly one Operator, and that authenticated name is the SOLE recorded identity — a client-supplied `operator` field is accepted but always ignored (impersonation impossible). Dispatch is gated to `executor` / `admin` (`403` otherwise); empty configuration stays fail-closed (`401`).
- **Execution Policy** — a pure, read-only decision model evaluated between Guard and Executor (`EXECUTION_POLICY_*` settings, disabled by default): a UTC server-clock time window `[start, end)` + per-action minimum risk thresholds consuming the authoritative `EventRisk.score` (the client has no channel to supply risk / severity / timestamp / policy fields — `extra="forbid"`). Policy refusals append `guard_rejected` with `detail.source="policy"` (distinct from structural Guard refusals); a malformed policy configuration is a static `503` with rollback — never a silent allow.
- **Execution Metrics** — `GET /executions/metrics` (no credential): derived-only SELECT over `execution_log` — total / succeeded / failed / guard-rejected / in-flight chains, `success_rate = succeeded / (succeeded + failed)` with `guard_rejected` NEVER in the adapter denominator, `guard_rejection_rate` as the separate governance metric, rejection provenance (`guard` vs `policy`), failure classifications, latency. Empty denominators are `null` → the UI renders N/A, never 0%.
- **Observed adapter health** — `GET /executions/health` (no credential): per-adapter status from the frozen vocabulary `unknown` / `healthy` / `degraded` / `failing` over the recent-20 TERMINAL chain window (guard refusals and in-flight chains never enter the window, so governance pressure is never misattributed to an adapter). Thresholds: `healthy ≥ 0.9`, `degraded ≥ 0.5`. **Observed ≠ probed** — status is derived from recorded facts; there is no live health probe and no outbound request.
- **Read-only invariant** — the metrics/health services contain no `add` / `commit` / `flush` / `delete`; repeated GETs against an unchanged log are byte-identical.

## Incident AI Context (read-only aggregation)

`GET /incidents/{id}/ai-context` composes the incident's event AI history into one DTO through `viewonly` ORM traversals — zero schema change, zero writes (no add/flush/commit in the service). The incident snapshot exposes only the creation-time `risk_score`; AI histories embed their Step 10–13 protocol schemas unchanged, each recommendation carrying its `approval | null`. Unknown incident → unified `404` before anything is assembled (no cross-case leak). The console panel renders this single GET with zero buttons and zero mutating traffic: **Observe / Review / Audit, never Decide / Execute.**

## Backend Layering (invariant)

```
api/v1/        HTTP only: request validation, exception → status-code mapping
schemas/       Pydantic v2 request/response models
services/      All business logic (normalization, dedup, risk, incidents, dashboard,
               ai providers, ai analysis services, approvals, incident ai context,
               response execution, external adapters, credential boundary)
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
- AI panels (explanation / risk summary / recommendation) are explicit-trigger: page load emits only GETs, never an automatic POST; every render is protocol-shaped and never shows a risk score.
- The Approval Queue page records one-shot decisions (201 removes locally, 409 re-syncs from the server); the Incident Detail "AI Investigation" panel is read-only with zero buttons.
- The Execute Console drives the execution chain (select action → confirm → observe result); the Execution Audit page shows the append-only `execution_log` with secret-redacted detail.
- The Observability page (`/observability`, v1.3.0) is strictly read-only: zero buttons, zero write traffic, field-for-field mirror of `GET /executions/metrics` + `GET /executions/health` (the UI never recomputes), no auto-refresh.
- Vite dev proxy forwards `/api` and `/health` to `localhost:8000`.

## Integration Points

Upstream platforms are adapter targets — their source is never vendored:

| Platform | Role | State |
|---|---|---|
| Wazuh | Alert source adapter (normalization) + endpoint response adapter (active-response) | Normalization: interface reserved (501). Response adapter: **shipped in v1.2.0** (Phase 3.2) |
| Ollama / cloud LLMs | AI analysis providers behind the unified `AIProvider` interface | Shipped in v1.1.0 (Phase 2) |
| Shuffle | Workflow orchestration adapter | **Shipped in v1.2.0** (Phase 3.2) |
| TheHive | Case management / investigation adapter | **Shipped in v1.2.0** (Phase 3.2) |
