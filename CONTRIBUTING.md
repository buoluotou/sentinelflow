# Contributing to SentinelFlow

## Branching

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

Keep one logical change per commit, and put the reasoning in the commit body or the PR description rather than in code comments.

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

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

The Vite dev server proxies `/api` and `/health` to `localhost:8000`, so a running backend is enough for the console to be usable.

### Simulator

Scenario fixtures live in `simulator/scenarios/<scenario>/events.json`, and the runner that posts them to the backend is `simulator/runner/run.py`. It uses the standard library only:

```powershell
python simulator/runner/run.py
python simulator/runner/run.py --repeat 30 --scenario ssh_failed_login
```

Its options are documented in `simulator/runner/README.md`.

### Dependency locking

`requirements/base.txt` (runtime) and `requirements/dev.txt` (dev/test) are the abstract inputs: they declare direct dependencies with `>=` floors. Their `*.lock` siblings pin the exact transitive-resolved versions, and every install path installs from the lock — the Docker image, `scripts/setup-dev.*`, and the manual commands above — so a build today and a build in six months resolve identically. The frontend does the same with `package-lock.json`.

After editing a `.txt`, regenerate the lock with [uv](https://docs.astral.sh/uv/) and re-run the full test suite before committing:

```bash
uv pip compile backend/requirements/base.txt --universal --python-version 3.12 -o backend/requirements/base.lock
uv pip compile backend/requirements/dev.txt  --universal --python-version 3.12 -o backend/requirements/dev.lock
```

By default `uv` keeps the versions already in the `.lock` and only resolves what your `.txt` change requires; pass `--upgrade` (or `--upgrade-package <name>`) to bump on purpose. `--universal` emits cross-platform markers (`uvloop` on Linux, `colorama`/`tzdata` on Windows), so one lock serves the Linux Docker image and native Windows/macOS development alike. Never hand-edit a `.lock`, and never bump it without a green `pytest` run.

## Running the Tests

### Backend

Run `pytest` from `backend/`. The default suite is offline and deterministic: it uses in-memory SQLite, forces `AI_PROVIDER=mock`, and deselects the `external` marker, so nothing reaches a real model or a real integration target.

- `pytest -m external` opts in to the tests that talk to real external systems (Shuffle, Wazuh, TheHive). They need a lab environment and are not part of a normal run.
- The PostgreSQL durability suites read `SENTINELFLOW_PG_TEST_URL`; without it they are skipped, so point that variable at a real PostgreSQL when you are touching dispatch, compensation or audit ordering.
- `backend/tests/e2e/` is not collected by the default run.

### Frontend

Run these from `frontend/`:

```powershell
npm run typecheck
npm run test
npm run build
```

`npm run test` runs the vitest suite once.

### Continuous Integration

`.github/workflows/ci.yml` runs on pushes and pull requests to `main`: the backend suite from `requirements/dev.lock`, the frontend typecheck/test/build, a fresh PostgreSQL migration to a single head, a compose configuration check, both image builds, a dependency advisory report and a secret scan. Keep a pull request green before asking for review.

## Code Style

- Backend: keep the API / Schema / Service / Model layer separation. HTTP handling stays in `app/api`, business logic in `app/services`, persistence in `app/models`.
- Services may `add` and `flush` but never `commit`; the transaction boundary belongs to the API layer.
- Schema changes must come with an Alembic migration — never rely on implicit table creation.
- Frontend: TypeScript strict mode; keep pages under `src/pages/`.
- Never commit `.env`, credentials or API keys (see [SECURITY.md](SECURITY.md)).

### Comment Style

- A comment states the technical reason for the code: the constraint, the failure mode, or the invariant that would otherwise be violated.
- Do not narrate development history — no account of what changed, when, or in what order.
- Do not reference internal round, milestone or gate identifiers. Those belong in the design and audit records, not in code.
- Do not praise the design or the implementation. Describe the behavior.
- Prefer one precise sentence over three vague ones. If a comment needs a paragraph, the code probably needs a clearer shape.

```python
# Avoid: restates the code, or explains the authoring process.
# This is a robust guard that was added for the execution work.

# Prefer: names the reason the branch has to exist.
# A 409 here means the approval already dispatched; the recovery path is
# compensation, never a second execute.
```

## Secrets

All secrets are read from environment variables at runtime. Never commit `.env`, credentials, API keys or tokens, and never paste a token into a test fixture, a log line or an issue. See [SECURITY.md](SECURITY.md) for the trust domains and the reporting process.
