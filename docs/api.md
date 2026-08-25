# SentinelFlow API Reference (Phase 1)

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

## Incidents

| Method | Path | Description |
|---|---|---|
| POST | `/incidents` | Manually open a case for an event (`{alert_group_id}`); title/severity/description/risk snapshot auto-filled. `201`. Errors: `404` event not found · `409` case already exists or event has no risk assessment |
| GET | `/incidents?page=&size=&status=` | Paged queue, newest first. `status` ∈ open/in_progress/resolved/false_positive/closed (invalid → `422`) |
| GET | `/incidents/{id}` | One case with full lifecycle fields. `404` if missing |
| PATCH | `/incidents/{id}/status` | Request a lifecycle move (`{status}`). The backend state machine validates it; invalid moves → `409` `Invalid incident status transition: {from} -> {to}`. Side effects: `resolved_at` + `disposition=resolved` on resolve; `closed_at` on close |

## Dashboard

| Method | Path | Description |
|---|---|---|
| GET | `/dashboard/summary` | Real-time aggregated snapshot (no caching, no extra tables): `open_incidents` (status open + in_progress), severity breakdown of active cases (`critical_incidents` / `high_incidents` / `medium_incidents`), `today_alerts` / `today_events` (since 00:00 UTC), `risk_distribution` (EventRisk level counts over all events) |

## Error Contract

- Validation failures → `422` (FastAPI standard)
- Business conflicts (duplicate case, illegal transition, missing risk) → `409` with a stable human-readable `detail`
- Missing resources → `404` with `detail`
- Errors are surfaced verbatim by the web console (no silent failures)
