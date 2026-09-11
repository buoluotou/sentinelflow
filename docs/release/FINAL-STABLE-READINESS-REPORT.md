# Final Stable Readiness Report

Candidate: **v1.4.0-rc2**. Scope: the final optimization round before tagging, as
frozen in advance. This report records what was changed, what was measured, and
what is explicitly not claimed.

## 1. Repository state

| Item | Value |
|---|---|
| Branch | `rc2/finalization-fixes` |
| Base | `9542f36` (= `v1.4.0-rc1`) |
| Pull request | #1 |
| Commits on the branch | 19 |
| `v1.4.0-rc1` tag | untouched (`f6b3f60` → `9542f36`) |

No reset, rebase, amend or force push was used, and the branch protection rules
already on `main` were not weakened.

## 2. Test counts

| Suite | Result |
|---|---|
| Backend, default suite | **2997 passed, 27 deselected, 0 failed, 0 skipped** (95.9 s in CI) |
| Backend, PostgreSQL external durable suite | 22 collected, 22 passed, 0 skipped |
| Frontend | typecheck clean, **97/97** tests, production build 279.99 kB (gzip 82.07 kB) |
| Browser end-to-end (Playwright, PostgreSQL) | see §4 |

New regression tests added this round: 9 for the non-ASCII credential, 2 for the
execution-list query, 1 for the approval-queue query count, 3 for the release
identity, 16 for the redaction filter and its substitution set.

Every one of the security regressions was shown to fail against the pre-fix
code: 8 of the 9 credential tests fail without the byte encoding, the list-query
structural test fails without the SQL pagination, and the queue-count test fails
with `4 -> 31`.

## 3. Coverage

Measured on CI with `pytest --cov=app`:

| Scope | Statements | Uncovered | Coverage | Floor |
|---|---|---|---|---|
| total | 5093 | 126 | **97.5%** | 95% |
| `app/services/executions/` | 1748 | — | 96.7% | 93% |
| `app/services/outcomes/` | 430 | — | 95.3% | 92% |
| `app/services/manual_reconcile/` | 61 | — | 100% | 95% |
| `app/services/read_adapters/` | 407 | — | 98.0% | 95% |
| `app/api/v1/` | 562 | — | 99.1% | 95% |
| `app/core/` | 149 | — | 95.3% | 92% |
| `app/services/ai/` | 452 | — | 95.4% | 92% |

The floors sit below the measured baseline with headroom, so ordinary churn
passes and a real regression fails. They are meant to be raised when the baseline
moves, never lowered to make a build green.

## 4. Browser end-to-end

The previous suite could not run: it booted the backend against SQLite, where the
durable-dispatch contract fails closed, while the journeys asserted success — so
six of its eleven journeys were impossible — and a module-level busy-port check
could turn a broken runner into a green skip.

Rebuilt on PostgreSQL: the harness requires a PostgreSQL `DATABASE_URL`, refuses
SQLite, resets the schema, migrates to head, and starts uvicorn and the Vite dev
server on ports it asserts are free. Children run in their own process group so
teardown signals the whole tree on both platforms. 40 journeys across four
modules cover the execution path through the console (alert → event → case →
recommendation → approval → execute → succeeded → audit), the approval queue, the
incident AI context and observability. The CI job gates on the pytest counts:
collected > 0, every module present, passed == collected, skipped == 0.

## 5. Read-path scale sanity

`scripts/perf_read_paths.py` seeds 10 000 alerts, 1 000 events, 1 000 incidents
and 9 999 audit rows (3 333 chains) and times each read endpoint, counting the
statements issued per request. Environment: Windows 11, Python 3.12.2, SQLite.

| Endpoint | Statements | Median | Response |
|---|---|---|---|
| `GET /api/v1/events` | 3 | 11 ms | total 1000, 20 items |
| `GET /api/v1/incidents` | 2 | 6 ms | total 1000, 20 items |
| `GET /api/v1/approvals` | 2 | 56 ms | 500 rows |
| `GET /api/v1/executions` | 3 | 566 ms | total 3333, 20 items |
| `GET /api/v1/dashboard/summary` | 7 | 19 ms | — |
| `GET /api/v1/executions/metrics` | 1 | 408 ms | — |
| `GET /api/v1/executions/health` | 1 | 410 ms | — |

Findings, recorded rather than fixed:

- No endpoint issues a per-row query, and no endpoint hydrates an unbounded
  result set. Statement counts are constant in the row count.
- `GET /api/v1/approvals` returns every pending recommendation and has no
  pagination. At 500 pending rows it is 56 ms; the response size grows with the
  queue. Adding pagination would change a public response shape, so it is left
  as a decision for the maintainer.
- The execution list and the two audit read models scan the audit table: the
  list needs the per-chain window functions, and the metrics and health models
  aggregate the whole log by design. At 10 000 rows that is 0.4–0.6 s on SQLite.
  An index on `(execution_id, created_at, id)` is the obvious next step if the
  audit table grows past that; no index was added, because this round measures
  rather than tunes.

## 6. Security

| Item | State |
|---|---|
| Non-ASCII credential | returns a uniform 401 on all three write paths (was 500) |
| Log redaction | filter installed on the application logger, the root logger and their handlers; substitution set covers operator tokens, callback tokens, the AI provider key and the database password |
| Secret scan | CI fails on a tracked `.env` or an unallowlisted credential pattern |
| Dependency advisories | `pip-audit` runs as a gate against `base.lock`; `npm audit` fails on HIGH and CRITICAL |
| npm registry | every lock entry resolves from `registry.npmjs.org` with an integrity hash; the SBOM was regenerated from the same tree |
| Container images | not digest-pinned; the observed digests are recorded in `docs/operations/DEPENDENCY-INTEGRITY.md` |
| Per-artifact pip hashes | **not enforced** — the locks pin exact versions only |

## 7. Documentation

The user-facing documents were rewritten in plain product-documentation style:
`README`, `README.zh-CN`, `CHANGELOG`, `SECURITY`, `CONTRIBUTING`, `docs/*` and
the operations runbooks. Internal round and milestone identifiers, process
narration and self-assessment are gone from them; the dated engineering records
remain under `docs/design/` and `docs/audit/` and now say that their numbers are
historical.

Corrections verified against the code during that pass: the API reference
documented an execution request contract that no longer existed; the demo and
quickstart pointed at an "Execute Console" page that does not exist; the
deployment guide led with an any-interface bind on a platform without edge
authentication; the architecture document listed guard rejection codes that
`guard.py` does not define and a migration range that stopped at 0009; the
roadmap described the outcome channels as plainly available although they refuse
by design; and the source comments carried the same process vocabulary, which was
stripped in a separate mechanical pass.

## 8. CI

Nine jobs, all green on the merge candidate. The two added this round:

- `compose-demo-e2e` — boots the documented compose demo on PostgreSQL, waits
  for the ordered boot, checks the reverse proxy, and runs `scripts/smoke.py`
  inside the backend container; it fails unless the full
  `SentinelFlow demo smoke test: PASS` banner is produced.
- `browser-e2e` — the Playwright suite against PostgreSQL with the count gate.

The migration job also now proves the upgrade direction: a database created at
revision 0009, holding rows, upgrades to head with the rows intact and a single
head.

## 9. Branch protection

`main` requires: strict status checks, a pull request, linear history, no force
push, no deletion, and conversation resolution. The required checks are the seven
original jobs plus the two added this round.

## 10. Release

`v1.4.0-rc1` is untouched. `v1.4.0-rc2` is tagged on the merged `main` HEAD and
published as a GitHub pre-release (prerelease = true).

## 11. Capability matrix

| Capability | State |
|---|---|
| Core (ingestion → normalization → dedup → risk → incident) | works, tested, demo-proven |
| Demo mode | works end to end with no external system |
| Docker compose demo | boots in order, smoke passes on PostgreSQL |
| PostgreSQL | supported and exercised in CI, including concurrency and recovery |
| SQLite | development only; the execution step fails closed by design |
| Auth | bearer token on write paths; missing or wrong credential is a uniform 401 |
| RBAC | viewer / reviewer / executor / admin, enforced server-side |
| Forward durability | durable dispatch commits before the outbound call; no automatic retry |
| Compensation durability | reservation plus target binding; reverse path never exercised against a real system |
| Audit pagination | execution list is chain-level paginated in SQL; the approvals queue is not paginated |
| Logging redaction | installed and tested |
| CI | nine jobs, all required on `main` |
| Compose E2E | green on PostgreSQL |
| Browser E2E | PostgreSQL-backed, gated on counts |
| Coverage | measured and gated per module |
| Documentation | rewritten; internal records separated |
| TheHive | read/write adapters implemented; verified outcome **BLOCKED** |
| Shuffle | adapter implemented; real lab **RESOURCE BLOCKED** |
| Wazuh | adapter implemented; real lab **RESOURCE BLOCKED** |
| Production candidate | partial — the edge and session layers do not exist |
| Production certified | **NO** |

## 12. Not claimed

This release is a stable **public demo and reference implementation**. It is not
a certified production SOAR, no external outcome is confirmed for any real
adapter, and the console cannot authenticate its own write actions outside demo
mode.
