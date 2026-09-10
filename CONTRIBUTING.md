# Contributing to SentinelFlow

Thanks for your interest in contributing to SentinelFlow!

## Branching Strategy

- `main` — always releasable; protected, no direct pushes.
- `feat/<short-description>` — new features, e.g. `feat/normalization-service`.
- `fix/<short-description>` — bug fixes.
- `docs/<short-description>` — documentation only changes.

Open a pull request against `main` with a clear description of the change and how it was verified.

## Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <summary>

type:  feat | fix | docs | refactor | test | chore | ci
scope: backend | frontend | simulator | infra | docs (optional)
```

Examples:

```
feat(backend): add alert ingestion API
test(backend): cover 404 path for alert detail
docs: add quick start for docker compose
```

## Local Development Setup

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker Desktop

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements/dev.lock

# database
docker compose up -d postgres
alembic upgrade head

# run tests
pytest

# start the dev server
uvicorn app.main:app --reload
```

### Dependency locking

`requirements/base.txt` (runtime) and `requirements/dev.txt` (dev/test) are the
abstract inputs: they declare direct dependencies with `>=` floors. Their
`*.lock` siblings pin the exact transitive-resolved versions, and every install
path — the Docker image, `scripts/setup-dev.*`, and the manual commands above —
installs from the lock, so a build today and a build in six months are identical
(this mirrors the frontend's `package-lock.json`).

After editing a `.txt`, regenerate the lock with [uv](https://docs.astral.sh/uv/)
and re-run the full test suite before committing:

```bash
uv pip compile backend/requirements/base.txt --universal --python-version 3.12 -o backend/requirements/base.lock
uv pip compile backend/requirements/dev.txt  --universal --python-version 3.12 -o backend/requirements/dev.lock
```

By default `uv` keeps the versions already in the `.lock` and only resolves what
your `.txt` change requires; pass `--upgrade` (or `--upgrade-package <name>`) to
intentionally bump. `--universal` emits cross-platform markers (`uvloop` on
Linux, `colorama`/`tzdata` on Windows) so one lock serves the Linux Docker image
and native Windows/macOS dev alike. Never hand-edit a `.lock`, and never bump it
without a green `pytest` run.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

### Simulator

Scenario fixtures live in `simulator/scenarios/<scenario>/events.json`. The
runner that posts them to the backend is implemented in Phase 1 Step 5.

## Code Style

- Backend: keep the API / Schema / Service / Model layer separation. HTTP
  handling stays in `app/api`, business logic in `app/services`, persistence
  in `app/models`.
- Schema changes must come with an Alembic migration — never rely on implicit
  table creation.
- Frontend: TypeScript strict mode; keep pages under `src/pages/`.
- Never commit `.env`, credentials or API keys (see [SECURITY.md](SECURITY.md)).
