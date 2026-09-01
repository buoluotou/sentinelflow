# SentinelFlow API Reference (v1.2.0)

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

## AI Analysis (Phase 2, advisory only)

All three AI endpoint pairs are **explicit-trigger** (the console never auto-POSTs), append-only (every trigger stores a new history row, reads return the latest), and share one error contract: `404` unknown event / no record yet · `503` provider misconfigured or unreachable · `502` model output violated the frozen protocol (never persisted). AI output never contains a risk score — `EventRisk.score` stays the single official score.

| Method | Path | Description |
|---|---|---|
| POST | `/events/{id}/ai-analysis` | Generate an AI alert explanation. `201` with `{provider, model, summary, attack_type, why_risky[], confidence}` |
| GET | `/events/{id}/ai-analysis` | Latest explanation. `404` when none exists yet |
| POST | `/events/{id}/ai-risk-summary` | Generate an AI risk summary. `201` with `{summary, key_findings[1..5], risk_drivers[frozen vocabulary], analyst_priority, confidence}` |
| GET | `/events/{id}/ai-risk-summary` | Latest risk summary. `404` when none exists yet |
| POST | `/events/{id}/response-recommendation` | Generate AI response recommendations. `201` with `{overall_rationale, recommendations[0..5] × {action, target, rationale}, confidence}`; actions limited to the frozen six-word vocabulary (`block_source_ip`, `isolate_host`, `disable_account`, `hunt_related_activity`, `escalate_to_incident`, `monitor_only`); an empty list is a valid answer ("no action warranted") |
| GET | `/events/{id}/response-recommendation` | Latest recommendation. `404` when none exists yet |

Provider selection is deployment configuration (`AI_PROVIDER` = `mock` / `ollama` / `cloud` in `.env`), never a request parameter.

## Approval Queue (Phase 2, Approve ≠ Execute)

Human decisions over AI response recommendations. "Pending" is a derived state (recommendations without a decision row) and is never persisted; the database stores exactly `approved` / `rejected`. Decisions record only — they never block an IP, touch `EventRisk`, or call any orchestrator. Execution is a separate Phase 3 chain (see below).

| Method | Path | Description |
|---|---|---|
| GET | `/approvals` | The pending queue: recommendations without a decision, oldest first, each embedding its recommendation payload |
| GET | `/approvals/{approval_id}` | One recorded decision (`status`, `reviewer`, `review_comment`, server-stamped `reviewed_at`) |
| POST | `/response-recommendations/{recommendation_id}/approve` | Record an APPROVE decision. Body: `{reviewer, review_comment?}` (extra fields rejected). `201` with the decision row |
| POST | `/response-recommendations/{recommendation_id}/reject` | Record a REJECT decision. Same body/contract as approve |

Errors: `404` unknown recommendation · `409` already reviewed (one-shot decision; `UNIQUE(recommendation_id)` enforced).

## Response Execution (Phase 3, v1.2.0)

Controlled execution layered on top of approved recommendations. All write endpoints require `Authorization: Bearer <EXECUTION_TOKEN>` (the shared secret from `.env`; empty token → every write returns `401`). Read endpoints need no token.

| Method | Path | Description |
|---|---|---|
| POST | `/executions` | Dispatch an approved recommendation for execution. Body: `{alert_group_id, recommendation_id, action, target?, operator, note?}`. The Guard validates: action is executable, approval exists and has not been executed, adapter supports the action. `201` with the `execution_log` row (`status` = `dispatched` / `succeeded` / `failed` / `guard_rejected`). Adapter secrets are never returned; detail is redacted via `***` |
| GET | `/executions?skip=&limit=` | Append-only execution audit trail, newest first. Each row includes `execution_id`, `adapter_name`, `action`, `target`, `operator`, `status`, `detail` (redacted), `external_execution_id`, `created_at`. Secrets never appear |
| GET | `/executions/{execution_id}` | One execution row with full detail (redacted). `404` if missing |
| POST | `/executions/compensate` | Request compensation for a previous execution. Body: `{execution_id, operator, note?}`. Requires Bearer token. `201` with the compensation `execution_log` row (`status` = `compensation_requested` / `compensation_succeeded` / `compensation_failed` / `guard_rejected`). Compensation is adapter-dependent: supported for Wazuh isolate/block (symmetric reversal); refused for `disable_account` and `escalate_to_incident` |

**Execution status vocabulary**: `requested` → `dispatched` → `succeeded` / `failed`; compensation: `compensation_requested` → `compensation_succeeded` / `compensation_failed`; guard rejection: `guard_rejected` (terminal). All rows are append-only; no UPDATE / DELETE.

**Adapter configuration** (`.env`): `EXECUTION_ADAPTER` selects the single active adapter (`mock` by default — offline DryRun, zero external requests). Real adapters (`shuffle` / `wazuh` / `thehive`) require explicit credentials and fail-closed startup validation.

## Incidents

| Method | Path | Description |
|---|---|---|
| POST | `/incidents` | Manually open a case for an event (`{alert_group_id}`); title/severity/description/risk snapshot auto-filled. `201`. Errors: `404` event not found · `409` case already exists or event has no risk assessment |
| GET | `/incidents?page=&size=&status=` | Paged queue, newest first. `status` ∈ open/in_progress/resolved/false_positive/closed (invalid → `422`) |
| GET | `/incidents/{id}` | One case with full lifecycle fields. `404` if missing |
| PATCH | `/incidents/{id}/status` | Request a lifecycle move (`{status}`). The backend state machine validates it; invalid moves → `409` `Invalid incident status transition: {from} -> {to}`. Side effects: `resolved_at` + `disposition=resolved` on resolve; `closed_at` on close |
| GET | `/incidents/{id}/ai-context` | **Read-only** AI investigation context: incident snapshot (`id/status/severity/risk_score_snapshot`) + the event's complete AI histories (`analyses[]`, `risk_summaries[]`, `response_recommendations[{recommendation, approval\|null}]`, each `created_at ASC`). Never generates/refreshes AI data, never touches risk or approvals; page loads emit only this GET. `404` `Incident not found` (unknown id AND malformed UUID, no context body, no cross-case leak); an incident without AI history answers `200` with empty histories; `approval=null` is the derived pending state |

## Dashboard

| Method | Path | Description |
|---|---|---|
| GET | `/dashboard/summary` | Real-time aggregated snapshot (no caching, no extra tables): `open_incidents` (status open + in_progress), severity breakdown of active cases (`critical_incidents` / `high_incidents` / `medium_incidents`), `today_alerts` / `today_events` (since 00:00 UTC), `risk_distribution` (EventRisk level counts over all events) |

## Error Contract

- Validation failures → `422` (FastAPI standard)
- Business conflicts (duplicate case, illegal transition, missing risk, already-reviewed recommendation) → `409` with a stable human-readable `detail`
- Missing resources → `404` with `detail`
- AI provider errors → `503` (misconfigured/unreachable) · protocol violations → `502` (never persisted)
- Execution adapter errors → `503` (adapter misconfigured) · guard rejections → `201` with `status=guard_rejected` (not an HTTP error — the execution fact is recorded)
- Missing `EXECUTION_TOKEN` or wrong token → `401` on all write execution endpoints
- Errors are surfaced verbatim by the web console (no silent failures)
