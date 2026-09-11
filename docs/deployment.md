# SentinelFlow Deployment Guide

## Topology

```
Browser ──▶ React console (static build or Vite) ──▶ FastAPI (127.0.0.1:8000) ──▶ PostgreSQL 16
```

The stack runs three processes: PostgreSQL (Docker), the backend (uvicorn), and the console (static files served by any web server; in development, the Vite dev server proxies `/api`).

Every port defaults to loopback: `docker-compose.yml` publishes on `${BIND_HOST:-127.0.0.1}`, `.env.example` ships `BIND_HOST=127.0.0.1`, and the native backend is started on `127.0.0.1` below. The platform has no edge authentication of its own, so this loopback default is what keeps an instance off the local network.

## 1. Database

```bash
# from the repo root
cp .env.example .env        # required: set POSTGRES_PASSWORD and the DATABASE_URL credentials
docker compose up -d postgres
```

The compose file uses env-var substitution only — no secrets are baked into the repository. Data persists in the `sentinelflow_pg-data` volume (the `pg-data` volume of the `sentinelflow` compose project). Healthcheck: `pg_isready`.

SQLite alternative (core-chain development / CI): set `DATABASE_URL="sqlite:///sentinelflow.db"` and skip Docker entirely. JSON columns work on either backend. Caveat: the durable-dispatch execution step needs PostgreSQL/MVCC — on SQLite it fails closed (`database is locked`), so nothing is dispatched and no execution outcome is recorded. SQLite covers the chain up to human approval; use PostgreSQL for the full demo and for production.

## 2. Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate    # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements/base.lock
python -m alembic upgrade head                        # migrations 0001–0014
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

`--host 127.0.0.1` is the correct default: the API ships without edge authentication, so a host-run backend must stay local. Binding anything else requires the edge setup described in [Production / edge](#production--edge) and [Binding to every interface](#binding-to-every-interface).

Configuration is read from `.env` at the repo root (pydantic-settings). Key variables:

| Category | Variables | Notes |
|---|---|---|
| Database | `DATABASE_URL` | PostgreSQL (production) or SQLite (evaluation) |
| Backend | `BACKEND_HOST`, `BACKEND_PORT`, `DEBUG` | Set `DEBUG=false` in production |
| AI Provider | `AI_PROVIDER`, `AI_MODEL`, `AI_BASE_URL`, `AI_API_KEY`, `AI_TIMEOUT_SECONDS` | `mock` (default, offline) / `ollama` / `cloud` |
| Execution | `EXECUTION_ADAPTER`, `EXECUTION_TOKEN` | `mock` (default, DryRun) / `shuffle` / `wazuh` / `thehive`; token required on write endpoints |
| Operators / RBAC | `OPERATORS_JSON` | Static operator registry (name + token + role: `viewer` / `reviewer` / `executor` / `admin`). The Bearer token is the sole recorded identity; empty registry plus empty `EXECUTION_TOKEN` means every write stays closed (`401`). Tokens never enter logs / responses / audit / DB |
| Execution Policy | `EXECUTION_POLICY_ENABLED`, `EXECUTION_POLICY_WINDOW_START`, `EXECUTION_POLICY_WINDOW_END`, `EXECUTION_POLICY_MIN_RISK_*` | Disabled by default. Read-only gate between Guard and Executor: UTC time window `[start, end)` + per-action minimum risk thresholds against the server-side `EventRisk.score`; refusals land as `guard_rejected` with `detail.source="policy"`; malformed configuration → static `503` + rollback |
| Adapter credentials | `SHUFFLE_BASE_URL`, `SHUFFLE_API_KEY`, `WAZUH_BASE_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`, `THEHIVE_BASE_URL`, `THEHIVE_API_KEY` | Empty = fail-closed; only the selected adapter's pair is validated |
| Adapter mapping | `SHUFFLE_WORKFLOW_*` (4 forward + 2 reverse), `SHUFFLE_TIMEOUT_SECONDS`, `WAZUH_TIMEOUT_SECONDS`, `THEHIVE_TIMEOUT_SECONDS` | Shuffle action → workflow id mapping (one workflow per executable action); HTTP timeouts |
| Deduplication | `DEDUP_WINDOW_SECONDS` | Fingerprint aggregation window |

### Production / edge

TLS and authentication terminate at a reverse proxy, which is the only component listening on a public address:

```
Internet ──► reverse proxy (TLS + SSO/auth) ──► 127.0.0.1:8000
```

nginx or Caddy terminates TLS, enforces SSO or operator authentication, rate-limits the write paths, and forwards to the loopback port (in the Docker stack, to the `frontend` service, which proxies `/api`, `/health` and `/ready` to `backend:8000`). Run uvicorn with `--workers 1`: the pipeline relies on per-request DB transactions, so extra workers are safe but add nothing. Set `DEBUG=false`. Working proxy configs, security headers and rate limits: [operations/PRODUCTION-EDGE.md](operations/PRODUCTION-EDGE.md).

### Binding to every interface

Containers and hosts that must accept traffic from another machine bind the port on all interfaces:

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

In the Docker stack the backend container binds `0.0.0.0` inside the container, and the host port stays on `${BIND_HOST:-127.0.0.1}` unless you set `BIND_HOST=0.0.0.0` in `.env`.

A non-loopback bind is acceptable only behind a reverse proxy, a firewall or a trusted network. Never expose port 8000 directly to the internet: edge authentication and TLS must terminate upstream.

## 3. Frontend

```bash
cd frontend
npm install
npm run build            # output: frontend/dist (tsc type-check included)
```

Serve `frontend/dist` with any static file server and proxy `/api`, `/health` and `/ready` to the backend, e.g. nginx:

```nginx
location /api/    { proxy_pass http://backend:8000; }
location /health  { proxy_pass http://backend:8000; }
location /ready   { proxy_pass http://backend:8000; }
location /        { try_files $uri /index.html; }   # SPA routing fallback
```

In development, `npm run dev` handles the proxy automatically (Vite).

## 4. Verification

```bash
curl http://localhost:8000/health                       # {"status":"ok","service":"sentinelflow-backend","database":"connected","database_driver":"..."}
curl http://localhost:8000/ready                        # 200 only when the DB answers SELECT 1, else 503
python simulator/runner/run.py --repeat 5               # 25 alerts → 5 events
curl http://localhost:8000/api/v1/dashboard/summary     # metrics reflect the run
```

## 5. Backup

- PostgreSQL: `docker compose exec -T postgres pg_dump -U <user> <db> > backup.sql`
- SQLite: copy the `.db` file while the backend is stopped.

## Security Hardening Checklist

The platform ships with token-based RBAC but no edge authentication, no TLS and no rate limiting. Review every item before exposing it beyond a trusted network:

- [ ] There is no edge authentication. Put the console behind your SSO or reverse-proxy auth, and keep port 8000 on loopback; do not expose it directly.
- [ ] Replace the `change_me` placeholder in `.env` (both `POSTGRES_PASSWORD` and `DATABASE_URL`).
- [ ] `.env` is git-ignored and never committed (only `.env.example` with placeholders is tracked) — keep it that way; rotate any credential that ever leaked.
- [ ] Set `DEBUG=false` outside development.
- [ ] Serve the console over TLS. The backend answers plain HTTP; TLS terminates at the proxy.
- [ ] Restrict CORS/proxy access to the API from the console origin only.
- [ ] The ingestion endpoints accept arbitrary JSON payloads — they are the SIEM intake — so rate-limit them at the proxy.
- [ ] Keep PostgreSQL unexposed: no public port mapping. The compose file publishes it on loopback for local use only.
- [ ] Set `EXECUTION_TOKEN` to a strong random value before enabling any real execution adapter; an empty token rejects every write with `401` (fail-closed). Prefer `OPERATORS_JSON` to bind distinct operators and roles — only `executor` / `admin` can dispatch (`403` otherwise); keep operator tokens out of logs, tickets and screenshots.
- [ ] Keep `EXECUTION_ADAPTER=mock` unless you have configured adapter credentials and workflow mappings. A real adapter needs a complete `.env` section of its own; the platform never falls back to one on its own.
- [ ] Container hardening (shipped by default): the compose stack runs `postgres` / `migrate` / `backend` / `frontend` with `read_only: true`, scoped `tmpfs` mounts and `no-new-privileges:true`; the backend image runs as a non-root user (uid 10001). Keep these settings when you copy the compose into a production overlay. `DEPLOYMENT_MODE=production` also refuses to boot on unsafe settings — see [Production mode](#production-mode).
- [ ] If you enable `EXECUTION_POLICY_ENABLED=true`, check that the window and per-action risk thresholds match your change-management hours; a malformed policy configuration is refused with `503` and rolled back rather than allowed through.

### Production mode

With `DEPLOYMENT_MODE=production`, `backend/app/core/runtime_mode.py` validates the settings during API startup and refuses to boot (`ProductionModeError`) when any of them is unsafe. The error collects every problem and names the offending setting names, never their values:

- `BIND_HOST` is not loopback (`127.0.0.1`, `localhost` or `::1`).
- `OPERATORS_JSON` is empty, unparseable, or missing an approval-capable (`reviewer` / `admin`) or an execution-capable (`executor` / `admin`) operator. The legacy `EXECUTION_TOKEN`-only path does not satisfy the gate.
- `DATABASE_URL` is not PostgreSQL.
- `EXECUTION_ADAPTER` is empty or `mock`.
- `EXECUTION_COMPENSATION_EXPERIMENTAL=true`, or any `SHUFFLE_WORKFLOW_REVERSE_*` id is set.

The gate runs before adapter validation, so a misconfigured production instance fails at startup rather than at the first write. `DEPLOYMENT_MODE=demo` (the default) skips it.

## Upgrading

1. `git pull`
2. `pip install -r requirements/base.lock` (backend) / `npm install && npm run build` (frontend)
3. `python -m alembic upgrade head`
4. Restart the backend

Migrations are additive and reversible, and every one of `0001–0014` implements `downgrade()`.

## Resource guidance

The full Docker stack (PostgreSQL, the one-shot migrate job, the backend and the
frontend) stays below ~1.5 GiB RSS under demo traffic. Minimums for an
evaluation host:

- CPU: 2 cores (a cold image build benefits from 4+)
- RAM: 4 GiB (PostgreSQL ≈512 MiB, backend ≈300 MiB, frontend ≈32 MiB,
  plus build headroom)
- Disk: ≈5 GiB (images + BuildKit cache + the `pg-data` volume)

For production sizing, set resource limits in your own overlay; the shipped
compose keeps the demo unrestricted so a small machine can run it too:

```yaml
services:
  backend:
    deploy:
      resources:
        limits: { cpus: "2.0", memory: 1g }
  postgres:
    deploy:
      resources:
        limits: { cpus: "2.0", memory: 2g }
```
