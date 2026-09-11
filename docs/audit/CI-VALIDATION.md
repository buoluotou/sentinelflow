# CI — Configuration & Local Validation (RC2 §14)

**Status: CI CONFIGURED / LOCALLY VALIDATED.** No push happened this round, so
there is deliberately **no** "GitHub CI PASS" claim. This document maps every
CI job to the local evidence that exercised the same steps.

## The pipeline

`.github/workflows/ci.yml` — jobs (see the file for the full definitions):

| Job | What it runs | Local validation (this round) |
|---|---|---|
| `Backend` | `pip install -r requirements/dev.lock` + `pytest -q -ra` (external deselected by conftest) | **2935 passed, 27 deselected, rc=0** (`rc2-evidence/04-backend-tests.txt`) |
| `Frontend` | `npm ci` + `typecheck` + `vitest run` + `vite build` | typecheck rc=0; **97/97 tests**; build 279.99 kB (82.07 kB gzip) (`05-frontend-tests.txt`) |
| `Quality` | `git diff --check` + `bash -n scripts/*.sh` + `docker compose config` (throwaway .env) | `GIT_DIFF_CHECK=OK`; `bash -n` all rc=0; `COMPOSE_CONFIG_RC=0` |
| `Migration` | fresh `postgres:16` service → `alembic upgrade head` → current == heads + schema spot-check | §13 upgrade evidence: 0009→0014 real PG, counts+digests MATCH (`13-upgrade-validation.txt`) |
| `Docker` | `docker compose build backend frontend` | cached build + `--no-cache` backend rebuild 54.3 s with the documented mirror arg (`06-docker-validation.txt`) |
| `PostgreSQL external durable suite` | `pytest -m external` (dispatch + compensation + audit-ordering PG) on a real PG service | **20 passed** (`07-postgres-external.txt`) |
| `Security` | `pip-audit` on base.lock; `npm audit` (fail on critical only); high-signal secret scan + tracked-`.env` check | `pip-audit`: no known vulnerabilities; `npm audit`: 0/0/0/0/0; secret scan PASS (`09-dependency-audit.txt`, `18-secret-scan.txt`) |

## Explicit non-goals (by design)

- The external labs (TheHive / Shuffle / Wazuh real targets) are **not** run in
  CI — they remain opt-in on a lab host (`pytest -m external` with dedicated
  env vars), exactly as the conftest deselects them by default.
- No production system, no real credentials; the only secret in the workflow
  is a throwaway local PostgreSQL service password.
- Actions are pinned to major-version tags (`actions/checkout@v4`, …). SHA
  pinning is a follow-up hardening once the repository has a release cadence —
  recorded as an open item, not silently skipped.

## How to flip this to a real "CI PASS"

Push the branch, open the PR, and let GitHub run the pipeline; the branch
protection plan (`docs/operations/GITHUB-BRANCH-PROTECTION.md`) lists these
job names as the required checks.
