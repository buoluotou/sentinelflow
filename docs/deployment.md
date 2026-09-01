# SentinelFlow Deployment Guide

## Topology

```
Browser ──▶ React console (static build or Vite) ──▶ FastAPI (:8000) ──▶ PostgreSQL 16
```

Phase 1 runs three processes: PostgreSQL (Docker), the backend (uvicorn), and the console (static files served by any web server; in development, the Vite dev server proxies `/api`).

## 1. Database

```bash
# from the repo root
cp .env.example .env        # REQUIRED: change POSTGRES_PASSWORD and the DATABASE_URL credentials
docker compose up -d postgres
```

The compose file uses env-var substitution only — no secrets are baked into the repository. Data persists in the `sentinelflow-pg-data` volume. Healthcheck: `pg_isready`.

**SQLite alternative** (evaluation / CI): set `DATABASE_URL="sqlite:///sentinelflow.db"` and skip Docker entirely. JSON columns are dual-compatible by design.

## 2. Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate    # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements/base.txt
python -m alembic upgrade head                        # migrations 0001–0009
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Configuration is read from `.env` at the repo root (pydantic-settings). Key variables:

| Category | Variables | Notes |
|---|---|---|
| Database | `DATABASE_URL` | PostgreSQL (production) or SQLite (evaluation) |
| Backend | `BACKEND_HOST`, `BACKEND_PORT`, `DEBUG` | Set `DEBUG=false` in production |
| AI Provider | `AI_PROVIDER`, `AI_MODEL`, `AI_BASE_URL`, `AI_API_KEY`, `AI_TIMEOUT_SECONDS` | `mock` (default, offline) / `ollama` / `cloud` |
| Execution | `EXECUTION_ADAPTER`, `EXECUTION_TOKEN` | `mock` (default, DryRun) / `shuffle` / `wazuh` / `thehive`; token required on write endpoints |
| Operators / RBAC (v1.3.0) | `OPERATORS_JSON` | Static operator registry (name + token + role: `viewer` / `reviewer` / `executor` / `admin`). Bearer token is the sole recorded identity; empty registry + empty `EXECUTION_TOKEN` → every write stays closed (`401`). Tokens never enter logs / responses / audit / DB |
| Execution Policy (v1.3.0) | `EXECUTION_POLICY_ENABLED`, `EXECUTION_POLICY_WINDOW_START`, `EXECUTION_POLICY_WINDOW_END`, `EXECUTION_POLICY_MIN_RISK_*` | Disabled by default (exact v1.2.0 behavior). Read-only gate between Guard and Executor: UTC time window `[start, end)` + per-action minimum risk thresholds against the server-side `EventRisk.score`; refusals land as `guard_rejected` with `detail.source="policy"`; malformed configuration → static `503` + rollback |
| Adapter credentials | `SHUFFLE_BASE_URL`, `SHUFFLE_API_KEY`, `WAZUH_BASE_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`, `THEHIVE_BASE_URL`, `THEHIVE_API_KEY` | Empty = fail-closed; only the selected adapter's pair is validated |
| Adapter mapping | `SHUFFLE_WORKFLOW_*` (6 forward + 2 reverse), `SHUFFLE_TIMEOUT_SECONDS`, `WAZUH_TIMEOUT_SECONDS`, `THEHIVE_TIMEOUT_SECONDS` | Shuffle action → workflow id mapping; HTTP timeouts |
| Deduplication | `DEDUP_WINDOW_SECONDS` | Fingerprint aggregation window |

Production suggestions: run uvicorn behind a reverse proxy (nginx/Caddy) with `--workers 1` (the pipeline relies on per-request DB transactions; multi-worker is safe but adds no benefit for SQLite), enable TLS at the proxy, and set `DEBUG=false`.

## 3. Frontend

```bash
cd frontend
npm install
npm run build            # output: frontend/dist (tsc type-check included)
```

Serve `frontend/dist` with any static file server and proxy `/api` + `/health` to the backend, e.g. nginx:

```nginx
location /api/    { proxy_pass http://backend:8000; }
location /health  { proxy_pass http://backend:8000; }
location /        { try_files $uri /index.html; }   # SPA routing fallback
```

In development, `npm run dev` handles the proxy automatically (Vite).

## 4. Verification

```bash
curl http://localhost:8000/health                       # {"status":"ok","database":"connected"}
python simulator/runner/run.py --repeat 5               # 25 alerts → 5 events
curl http://localhost:8000/api/v1/dashboard/summary     # metrics reflect the run
```

## 5. Backup

- PostgreSQL: `docker exec sf-postgres pg_dump -U <user> <db> > backup.sql`
- SQLite: copy the `.db` file while the backend is stopped.

## Security Hardening Checklist

Phase 1 is intentionally minimal — review every item before exposing the platform beyond a trusted network:

- [ ] **No authentication yet.** Put the console behind your SSO/reverse-proxy auth. Do not expose port 8000 directly.
- [ ] Replace the `change_me` placeholder in `.env` (both `POSTGRES_PASSWORD` and `DATABASE_URL`).
- [ ] `.env` is git-ignored and never committed (only `.env.example` with placeholders is tracked) — keep it that way; rotate any credential that ever leaked.
- [ ] Set `DEBUG=false` outside development.
- [ ] Serve the console over TLS; the backend itself listens plain HTTP by design (TLS terminates at the proxy).
- [ ] Restrict CORS/proxy access to the API from the console origin only.
- [ ] The ingestion endpoints accept arbitrary JSON payloads by design (they are the SIEM intake) — rate-limit them at the proxy.
- [ ] Keep PostgreSQL unexposed (no public port mapping; the compose file binds to the host for local use only).
- [ ] Set `EXECUTION_TOKEN` to a strong random value before enabling any real execution adapter; an empty token rejects every write with `401` (fail-closed). Prefer `OPERATORS_JSON` (v1.3.0) to bind distinct operators and roles — only `executor` / `admin` can dispatch (`403` otherwise); keep operator tokens out of logs, tickets and screenshots.
- [ ] Keep `EXECUTION_ADAPTER=mock` unless you have explicitly configured adapter credentials and workflow mappings. Real adapters require explicit `.env` configuration — the platform never falls back to a real adapter silently.
- [ ] If you enable `EXECUTION_POLICY_ENABLED=true`, verify the window and per-action risk thresholds match your change-management hours; a malformed policy configuration refuses with `503` and rolls back — never a silent allow.

## Upgrading

1. `git pull`
2. `pip install -r requirements/base.txt` (backend) / `npm install && npm run build` (frontend)
3. `python -m alembic upgrade head`
4. Restart the backend

Migrations are additive and reversible (full downgrade support) through Phase 3 (0001–0009).
