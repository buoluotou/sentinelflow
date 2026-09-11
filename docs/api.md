# SentinelFlow API Reference (v1.4.0-rc2)

Base URL: `http://localhost:8000/api/v1` · Interactive docs: `http://localhost:8000/docs`

All write endpoints are JSON; timestamps are ISO-8601 UTC; ids are UUID strings.

## Health (outside /api/v1)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Service + database connectivity check |

## Alerts

| Method | Path | Description |
|---|---|---|
| POST | `/alerts` | Ingest one alert (unified `AlertCreate` format). Runs the full pipeline: normalization → deduplication → risk → incident policy. `201` with `AlertRead` |
| GET | `/alerts?skip=&limit=` | List alerts, most recently seen first (limit ≤ 100) |
| GET | `/alerts/{id}` | One alert incl. raw contributing events. `404` if missing |

## Normalization

| Method | Path | Description |
|---|---|---|
| POST | `/normalize` | Normalize a raw source payload (`{source, raw_data}`) and ingest the result. Response adds `alert_id` / `group_id` / `group_alert_count` / `created_group`. Errors: `400` unknown source or malformed payload, `501` adapter not implemented (e.g. Wazuh) |

## Events (aggregated alert groups)

| Method | Path | Description |
|---|---|---|
| GET | `/events?page=&size=&level=` | Paged list, most recently seen first. Each item carries the current risk snapshot (`risk_score`, `risk_level`; null for legacy events). `level` ∈ low/medium/high/critical (invalid → `422`; filtering excludes events without a risk record) |
| GET | `/events/{id}` | Event summary + fingerprint + evidence alerts + risk factor breakdown (`risk` is null when no assessment exists). `404` if missing |

## AI Analysis (advisory only)

All three AI endpoint pairs fire only when the user triggers them (the console never auto-POSTs), are append-only (every trigger stores a new history row; reads return the latest), and share one error contract: `404` unknown event / no record yet · `503` provider misconfigured or unreachable · `502` model output violated the protocol (never persisted). AI output never contains a risk score; `EventRisk.score` stays the single official score.

| Method | Path | Description |
|---|---|---|
| POST | `/events/{id}/ai-analysis` | Generate an AI alert explanation. `201` with `{provider, model, summary, attack_type, why_risky[], confidence}` |
| GET | `/events/{id}/ai-analysis` | Latest explanation. `404` when none exists yet |
| POST | `/events/{id}/ai-risk-summary` | Generate an AI risk summary. `201` with `{summary, key_findings[1..5], risk_drivers[fixed vocabulary], analyst_priority, confidence}` |
| GET | `/events/{id}/ai-risk-summary` | Latest risk summary. `404` when none exists yet |
| POST | `/events/{id}/response-recommendation` | Generate AI response recommendations. `201` with `{overall_rationale, recommendations[0..5] × {action, target, rationale}, confidence}`; actions limited to the six-word vocabulary (`block_source_ip`, `isolate_host`, `disable_account`, `hunt_related_activity`, `escalate_to_incident`, `monitor_only`); an empty list is a valid answer ("no action warranted") |
| GET | `/events/{id}/response-recommendation` | Latest recommendation. `404` when none exists yet |

Provider selection is deployment configuration (`AI_PROVIDER` = `mock` / `ollama` / `cloud` in `.env`), never a request parameter.

## Approval Queue

Human decisions over AI response recommendations. "Pending" is a derived state (recommendations without a decision row) and is never persisted; the database stores exactly `approved` / `rejected`. Decisions record only — they never block an IP, touch `EventRisk`, or call any orchestrator. Execution is a separate chain (see below).

| Method | Path | Description |
|---|---|---|
| GET | `/approvals` | The pending queue: recommendations without a decision, oldest first, each embedding its recommendation payload |
| GET | `/approvals/{approval_id}` | One recorded decision (`status`, `reviewer`, `review_comment`, server-stamped `reviewed_at`) |
| POST | `/response-recommendations/{recommendation_id}/approve` | Record an approval decision. Body: `{reviewer, review_comment?}` (extra fields rejected). `201` with the decision row |
| POST | `/response-recommendations/{recommendation_id}/reject` | Record a rejection decision. Same body/contract as approve |

Errors: `404` unknown recommendation · `409` already reviewed (one-shot decision; `UNIQUE(recommendation_id)` enforced).

**Auth boundary.** In demo mode (the default) both write paths stay tokenless and the body `reviewer` is display-only. In production mode a Bearer token is required: a missing or unknown token is `401`, an authenticated operator without the approval permission (`viewer` / `executor`) is `403`, and the recorded reviewer is always the token's principal, never the body field.

## Response Execution

Controlled execution layered on top of approved recommendations. All write endpoints require `Authorization: Bearer <token>`; the token is resolved server-side to an operator identity (`.env` `OPERATORS_JSON`, with the legacy `EXECUTION_TOKEN` fallback mapping to the synthetic operator `legacy-execution` with role `executor`). Missing / empty / wrong credential → `401` before the Service runs (zero `execution_log` rows). Read endpoints need no token.

**The Execute Intent carries identity keys only**: `{execution_id, approval_id, operator?, comment?}` — `execution_id` and `approval_id` are required UUIDs, `operator` (≤ 128 chars) is optional and always ignored (the Bearer token is the sole identity), `comment` (≤ 512 chars) is audit metadata that can never influence action, target or any decision. `action`, `target`, `direction`, `decision`, `detail` and `created_at` are server-side facts assembled from the approved recommendation snapshot; every request model is `extra="forbid"`, so a smuggled field is a `422` at the schema boundary, before the Service runs. `execution_id` is a caller-supplied UUID serving as idempotency key and as execution identity: a replay is `409`, and it can never decide approval / action / target / direction.

**Operator identity.** Operators are registered in `.env` via `OPERATORS_JSON` (name, token, role: `viewer` / `reviewer` / `executor` / `admin`). The Bearer token resolves to the only server-side identity; a client-supplied `operator` body field is accepted but always ignored. Only `executor` / `admin` may dispatch executions; other roles receive `403`.

**Execution Policy.** With `EXECUTION_POLICY_ENABLED=true`, every dispatch additionally passes a read-only policy gate between Guard and Executor — a UTC time window (`EXECUTION_POLICY_WINDOW_START` / `EXECUTION_POLICY_WINDOW_END`, strict HH:MM, `[start, end)`) and per-action minimum risk thresholds (`EXECUTION_POLICY_MIN_RISK_*`) consuming the server-side `EventRisk.score`. Policy refusals are recorded as `guard_rejected` with `detail.source="policy"` (distinct from structural Guard refusals); the client can supply no risk / severity / timestamp / policy field (`extra=forbid`). A malformed policy configuration returns `503` and rolls back rather than allowing the dispatch.

| Method | Path | Description |
|---|---|---|
| POST | `/executions` | Dispatch one Execute Intent. Body: `{execution_id, approval_id, operator?, comment?}` (`operator` ignored). The chain is `requested` → Guard (approval is `approved`, the recommendation snapshot carries the action, the action is machine-executable, the adapter supports it) → Policy gate (time window + risk threshold) → `dispatched` → adapter → `succeeded` / `failed`. `201` with the `ExecutionRead` body — `201` means the execution fact was recorded, not that the external action succeeded; the outcome is `derived_state` (`succeeded` / `failed` / `guard_rejected`). A Guard refusal is recorded as `guard_rejected` with `detail.source="guard"`; a Policy refusal uses the same state with `detail.source="policy"` (there is no `policy_rejected` word). Adapter secrets are never returned; detail is redacted via `***`. Errors: `404` unknown approval (no row) · `409` the approval already has a forward execution (even after `failed` — the recovery path is compensation, never re-execution) or the `execution_id` is already bound (no row) · `422` schema violation · `503` adapter or policy misconfigured (transaction rolled back, no half-written chain) |
| GET | `/executions?page=&size=&status=&direction=&approval_id=` | Paged append-only audit list, most recent activity first, one entry per execution chain (a compensation is its own `execution_id`, so it is listed separately). `page` ≥ 1 (default `1`), `size` 1–100 (default `20`); `status` filters on the derived state ∈ `requested` / `guard_rejected` / `dispatched` / `succeeded` / `failed` / `compensation_requested` / `compensation_succeeded` / `compensation_failed`; `direction` ∈ `execute` / `compensate`; `approval_id` is a UUID. An invalid value → `422`. Body: `{total, page, size, items[]}`; each item carries `execution_id`, `approval_id`, `direction`, `action`, `target`, `operator`, `derived_state`, `chain[]`, `created_at`, `last_decision_at` |
| GET | `/executions/{execution_id}` | One chain's complete audit history, `created_at` ASC. Body: `{execution_id, approval_id, direction, action, target, derived_state, chain[], history[]}`; every `history` entry is the raw append-only row: `id`, `execution_id`, `approval_id`, `decision`, `direction`, `action`, `target`, `operator`, `detail` (redacted), `compensates_execution_id` (`null` on execute rows), `created_at`. `404` `Execution not found` for an unknown id and for a malformed UUID alike |
| POST | `/executions/compensate` | Request compensation for a settled forward execution — a new `execution_id` undoing it. Body: `{execution_id, compensates_execution_id, operator?, comment?}` (`operator` ignored). `approval_id`, `action` and `target` are inherited server-side from the original chain and are not accepted here (a client-supplied `approval_id` is `422`). `201` with the same `ExecutionRead` body, `direction="compensate"` and `derived_state` = `compensation_succeeded` / `compensation_failed`. Compensation is adapter-dependent: Wazuh reverses `isolate_host` / `block_source_ip` only (never `disable_account`), TheHive reverses nothing (it never auto-closes a case), the offline mock simulates the inverse of every executable action except `escalate_to_incident`. A capability miss does not produce `guard_rejected` — the compensate vocabulary has no such word: the chain ends as `compensation_failed` with `detail.classification="capability_missing"`. Errors: `404` unknown `compensates_execution_id` · `409` original not in a terminal state (`succeeded` / `failed` only), original already compensated (at most one compensation per original), the original is itself a compensation chain, or the new `execution_id` is already bound · `422` schema violation · `503` adapter misconfigured, or a recognized external adapter reached the reverse dispatch without its durable compensation store |
| POST | `/executions/{execution_id}/reconcile` | **Manual Reconcile** — the pull-side counterpart of the webhook push path: ask the platform to go read the external system's current state for one past execution and append what it finds as an outcome fact. Body is the empty object `{}` (`extra="forbid"`, so `execution_id` / `adapter` / `external_reference` / `external_state` / `observed_at` / `source` / `operator` are all `422`): the id comes from the path, the operator identity from the Bearer token (`executor` / `admin` only), the adapter + external reference are extracted read-only from the `execution_log` dispatch fact, and `source` is always `manual_reconcile`. `200` with `{accepted, execution_id, adapter, outcome_status, observed_at, source, derived_outcome_status, observed_at_kind}` (`observed_at_kind` ∈ `external` / `server-observation`). Errors, all with a static detail: `404` malformed or unknown `execution_id` · `404` `adapter read unsupported` · `422` `reconcile validation failed` (no reconcilable external reference, or an external state outside the mapped vocabulary — no facts appended) · `500` `reconcile outcome persistence failed` (rolled back, never `accepted=true`). The production read-adapter registry is empty, so every adapter is currently refused with `404 adapter read unsupported`; no read is fabricated that the platform cannot perform |
| GET | `/executions/metrics` | **Read-only execution metrics** — no credential, zero writes, derived purely from `execution_log` over `direction="execute"` chains. Body: `total_chains`, `executed_chains`, `succeeded`, `failed`, `guard_rejected`, `in_flight`, `success_rate = succeeded / (succeeded + failed)`, `executor_failure_rate`, `guard_rejection_rate = guard_rejected / total_chains` (`guard_rejected` never enters the outcome denominators), `rejections_by_source` (rejection provenance: `guard` vs `policy`), `failure_classifications`, `latency` (`count` / `average_seconds` / `min_seconds` / `max_seconds` — `dispatched` → terminal adapter time) and `by_adapter`. Empty denominators are `null` (rendered as N/A, never 0%) |
| GET | `/executions/health` | **Read-only observed adapter health** — no credential, no outbound requests, no live probing: body `{generated_at, window_size, adapters{}}`, where each adapter carries `observed_status` from the vocabulary `unknown` / `healthy` / `degraded` / `failing`, derived from the recent-20 terminal chain window (guard refusals and in-flight chains never enter the window). Thresholds: `healthy ≥ 0.9`, `degraded ≥ 0.5`; `unknown` = no terminal observation yet. The field is named `observed_status`, not `healthy`, so it cannot be read as a live probe result |

**Execution status vocabulary**: `requested` → `dispatched` → `succeeded` / `failed`; compensation: `compensation_requested` → `compensation_succeeded` / `compensation_failed`; guard rejection: `guard_rejected` (terminal). Every decision belongs to exactly one direction, and the storage CHECK constraint admits only the legal `decision × direction` combinations — so `guard_rejected` exists in the `execute` direction only, and no `compensation_*` word can appear on an execute chain. All rows are append-only; no UPDATE / DELETE. State is never stored: it is derived as the `decision` of the chain's latest row (`created_at DESC, id DESC`).

**Adapter configuration** (`.env`): `EXECUTION_ADAPTER` selects exactly one active adapter (`mock` by default — offline DryRun, zero external requests, no credentials of its own). Real adapters fail closed at startup when their settings are missing: `shuffle` (`SHUFFLE_BASE_URL` + `SHUFFLE_API_KEY`), `wazuh` (`WAZUH_BASE_URL` + `WAZUH_API_USER` + `WAZUH_API_PASSWORD`), `thehive` (`THEHIVE_BASE_URL` + `THEHIVE_API_KEY`). Configuring a reverse Shuffle workflow (`SHUFFLE_WORKFLOW_REVERSE_*`) additionally requires `EXECUTION_COMPENSATION_EXPERIMENTAL=true`, or the application will not start — real-adapter compensation is lab-only, and the offline mock is exempt.

## Adapter Callbacks (inbound outcomes)

The push-side counterpart of `/executions/{id}/reconcile`: an external system reports the outcome of a past execution. The adapter identity comes from the server-side route, never from the body, and each recognized adapter authenticates with its own callback credential (`.env` `SHUFFLE_CALLBACK_TOKEN` / `WAZUH_CALLBACK_TOKEN` / `THEHIVE_CALLBACK_TOKEN`). This is a third trust domain, separate from both the human operator registry and the outbound `*_API_KEY` credentials: a human token never authenticates a callback, and a callback token never authenticates a human write path. `mock` has no callback channel, and any adapter without one resolves to `404 unsupported callback adapter` — never `401`.

| Method | Path | Description |
|---|---|---|
| POST | `/webhooks/{adapter}` | Report one execution outcome. Body: `{execution_id, external_reference, external_state, observed_at}` — observation data only; `adapter`, `source` (always `webhook`), `operator` and any unknown field are `422` (`extra="forbid"`), so a client can never become the trust root or pick its ingress channel. `200` with `{"accepted": true}`, returned only once the outcome fact is committed (never `201` / `204`). Every authentication failure — missing / malformed / wrong / unconfigured credential — collapses to one uniform `401` `callback authentication failed`; a well-formed `execution_id` mapping to no chain is `404` `execution correlation failed`; contract / mapping refusals are `422` `callback validation failed` (a refused external state is never a fabricated fact); a rolled-back append is `500` `outcome persistence failed`, never `accepted=true`. Every detail is static: no credential, adapter, id or external state is ever echoed |

## Incidents

| Method | Path | Description |
|---|---|---|
| POST | `/incidents` | Manually open a case for an event (`{alert_group_id}`); title/severity/description/risk snapshot auto-filled. `201`. Errors: `404` event not found · `409` case already exists or event has no risk assessment |
| GET | `/incidents?page=&size=&status=` | Paged queue, newest first. `status` ∈ open/in_progress/resolved/false_positive/closed (invalid → `422`) |
| GET | `/incidents/{id}` | One case with full lifecycle fields. `404` if missing |
| PATCH | `/incidents/{id}/status` | Request a lifecycle move (`{status}`). The backend state machine validates it; invalid moves → `409` `Invalid incident status transition: {from} -> {to}`. Side effects: `resolved_at` + `disposition=resolved` on resolve; `closed_at` on close |
| GET | `/incidents/{id}/ai-context` | **Read-only** AI investigation context: incident snapshot (`id/status/severity/risk_score_snapshot`) + the event's complete AI histories (`analyses[]`, `risk_summaries[]`, `response_recommendations[{recommendation, approval\|null}]`, each `created_at ASC`). Never generates or refreshes AI data, never touches risk or approvals; page loads emit only this GET. `404` `Incident not found` (unknown id and malformed UUID alike, no context body, and no data from another case); an incident without AI history answers `200` with empty histories; `approval=null` is the derived pending state |

## Dashboard

| Method | Path | Description |
|---|---|---|
| GET | `/dashboard/summary` | Real-time aggregated snapshot (no caching, no extra tables): `open_incidents` (status open + in_progress), severity breakdown of active cases (`critical_incidents` / `high_incidents` / `medium_incidents`), `today_alerts` / `today_events` (since 00:00 UTC), `risk_distribution` (EventRisk level counts over all events) |

## Error Contract

- Validation failures → `422` (FastAPI standard)
- Business conflicts (duplicate case, illegal transition, missing risk, already-reviewed recommendation) → `409` with a stable human-readable `detail`
- Missing resources → `404` with `detail`
- AI provider errors → `503` (misconfigured/unreachable) · protocol violations → `502` (never persisted)
- Execution adapter errors → `503` (adapter misconfigured, or a recognized external adapter with no durable dispatch/compensation store) · guard and policy rejections → `201` with `derived_state="guard_rejected"` (not an HTTP error — the execution fact is recorded, and `detail.source` says `guard` or `policy`)
- Missing, empty or wrong execution credential → `401` on all write execution endpoints, before any row is written; authenticated operators without dispatch permission → `403` (RBAC)
- Manual Reconcile refusals are `404` / `422` / `500` with static details (`execution correlation failed` / `adapter read unsupported` / `reconcile validation failed` / `reconcile outcome persistence failed`); inbound adapter callbacks use their own credential domain — `401` `callback authentication failed`, `404` for an unknown channel, `422` `callback validation failed`, `500` `outcome persistence failed`
- Errors are surfaced verbatim by the web console (no silent failures)
