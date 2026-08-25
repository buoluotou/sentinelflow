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
python -m alembic upgrade head                        # migrations 0001–0004
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Configuration is read from `.env` at the repo root (pydantic-settings). Recognised variables: `DATABASE_URL`, `BACKEND_HOST`, `BACKEND_PORT`, `DEBUG`, `DEDUP_WINDOW_SECONDS`.

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

- [ ] **No authentication yet.** Put the console behind your SSO/reverse-proxy auth, or wait for the Phase 2 auth milestone. Do not expose port 8000 directly.
- [ ] Replace the `change_me` placeholder in `.env` (both `POSTGRES_PASSWORD` and `DATABASE_URL`).
- [ ] `.env` is git-ignored and never committed (only `.env.example` with placeholders is tracked) — keep it that way; rotate any credential that ever leaked.
- [ ] Set `DEBUG=false` outside development.
- [ ] Serve the console over TLS; the backend itself listens plain HTTP by design (TLS terminates at the proxy).
- [ ] Restrict CORS/proxy access to the API from the console origin only.
- [ ] The ingestion endpoints accept arbitrary JSON payloads by design (they are the SIEM intake) — rate-limit them at the proxy.
- [ ] Keep PostgreSQL unexposed (no public port mapping; the compose file binds to the host for local use only).

## Upgrading

1. `git pull`
2. `pip install -r requirements/base.txt` (backend) / `npm install && npm run build` (frontend)
3. `python -m alembic upgrade head`
4. Restart the backend

Migrations are additive and reversible (full downgrade support) throughout Phase 1.
