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
| `PostgreSQL external durable suite` | `pytest -m external` (dispatch 9 + compensation 9 + audit-ordering 2 + risk/incident 2) on a real PG service, then the anti-false-green gate (`scripts/ci/check_pg_external_result.py`: collected=22, passed=22, skipped=0) | **22 passed / 0 skipped**, gate OK (`rc2r-evidence/05-postgres-22.txt`); negative control (a skipped run) FAILS the gate |
| `Security` | `pip-audit` on base.lock (REAL gate, no `|| true`); `npm audit` HIGH+CRITICAL FAIL / MEDIUM+LOW report; `scripts/ci/secret-scan.sh` (real FAIL, precise allowlist, tracked-`.env` fail) | `pip-audit` rc=0 (0 advisories); npm 0/0/0/0/0 gate OK; secret gate GREEN, and RED on a synthetic `ghp_` fixture + staged `.env`, GREEN after cleanup (`rc2r-evidence/11-security-gate-validation.txt`) |

## Explicit non-goals (by design)

- The external labs (TheHive / Shuffle / Wazuh real targets) are **not** run in
  CI — they remain opt-in on a lab host (`pytest -m external` with dedicated
  env vars), exactly as the conftest deselects them by default.
- No production system, no real credentials; the only secret in the workflow
  is a throwaway local PostgreSQL service password.
- Actions are pinned to major-version tags (`actions/checkout@v4`, …). SHA
  pinning is a follow-up hardening once the repository has a release cadence —
  recorded as an open item, not silently skipped.

## RC2-R §6 — local equivalence for every job (latest pass)

| Job | Local equivalent (rc2-r evidence) | Result |
|---|---|---|
| Backend | full `pytest` on a clean LF copy at HEAD | 0 failures (see the RC2-R report §tests) |
| Frontend | `npm ci` + `typecheck` + `vitest run` + `vite build` | 0 failures |
| Quality | `git diff --check`, `bash -n scripts/*.sh scripts/ci/*.sh`, `py_compile` of the CI helper, `docker compose config` | all rc=0 |
| Migration | fresh PostgreSQL 16 → `alembic upgrade head` → `current == heads` | `0014 (head)` == `0014 (head)` |
| Docker | `docker compose build backend frontend` + demo boot/smoke | images build; 18/18 smoke |
| Postgres external | the 22-test suite + anti-false-green gate | **22 passed / 0 skipped**, gate OK + negative control FAIL |
| Security | pip-audit real gate; npm audit HIGH/CRITICAL gate; secret gate RED/GREEN | all as documented above |

**Status remains `CI CONFIGURED` / `CI LOCALLY VALIDATED`** — no push this
round, so `CI REAL GITHUB RUN = UNVERIFIED` (as the acceptance matrix states).

## How to flip this to a real "CI PASS"

Push the branch, open the PR, and let GitHub run the pipeline; the branch
protection plan (`docs/operations/GITHUB-BRANCH-PROTECTION.md`) lists these
job names as the required checks.
