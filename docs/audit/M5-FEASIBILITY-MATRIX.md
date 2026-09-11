# SentinelFlow M5 — Feasibility / Validation Matrix

> Purpose (§15/§17/§18): record what was **actually verified**, on **which environment**, with **what evidence** — and mark everything this machine cannot run as **UNVERIFIED**. No "theoretically supported" is reported as PASS. Demo Mode is prioritized to a real PASS wherever this host allows.
>
> Rule: **PASS** = executed here with captured output. **UNVERIFIED** = required tooling/OS absent on this host. **N/A** = intentionally not applicable.

---

## 0. Verification host (the only environment available for M5 validation)

| Item | Value |
|---|---|
| OS | Windows 11 24H2 |
| Shell | PowerShell (`pwsh`) |
| Python | 3.12.2 (`backend/.venv`) |
| Node / npm | v24.16.0 / 11.13.0 |
| git | `D:\AI\Git` (+ Git bash `D:\AI\Git\bin\bash.exe` for `.sh` syntax checks) |
| **docker** | **NOT FOUND** (no daemon, no `docker compose`) |
| **psql / PostgreSQL** | **NOT FOUND** (no client, no service, port 5432 not listening) |
| **ollama** | **NOT PRESENT** |
| WSL | bash stub present but **no distro installed** (unusable) |

Consequence: **every Docker, Linux, PostgreSQL and Ollama path is UNVERIFIED here.** The only fully runnable path is **Windows Native + SQLite**.

---

## 1. Four-environment matrix (§15)

| Environment | Verdict | Evidence / reason |
|---|---|---|
| **Windows 11 Native** | **PASS (core chain on SQLite)** | Python 3.12.2 + Node 24. Fresh-DB migrate, backend boot, HTTP smoke, full pytest, frontend typecheck/build/test all PASS (see §2). The execution→outcome leg fails **CLOSED** on SQLite (see §4) — it needs PostgreSQL/MVCC. |
| **Windows Docker** | **UNVERIFIED** | Docker not installed on this host. `docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile`, `frontend/nginx.conf`, `scripts/quickstart.ps1` are written and structure-reviewed, but **not executed** here. |
| **Linux Native** | **UNVERIFIED (syntax only)** | No Linux host. `scripts/setup-dev.sh`, `doctor.sh`, `smoke.sh`, `quickstart.sh` pass `bash -n` (Git bash, rc=0) but were **not run** on Linux. |
| **Linux Docker** | **UNVERIFIED** | No Linux + no Docker on this host. |

---

## 2. Test & regression results (§18) — executed on Windows Native

| # | Check | Command | Result | Evidence |
|---|---|---|---|---|
| 1 | Backend full pytest | `python -m pytest tests -q` | **PASS** | `2869 passed, 14 deselected` in `72.74s` (external suite deselected by default) |
| 2 | Frontend typecheck | `npm run typecheck` (`tsc --noEmit`) | **PASS** | rc=0, no type errors |
| 3 | Frontend production build | `npm run build` (`tsc && vite build`) | **PASS** | vite 8.2.2, 50 modules; `index.js` **279.99 kB (82.07 kB gzip)**, `index.css` 5.04 kB, `index.html` 0.40 kB; built in 1.16s — bundle normal, no anomaly |
| 4 | Frontend unit tests | `npm run test` (`vitest run`) | **PASS** | 9 test files, **97 tests passed**, rc=0 |
| 5 | Frontend lint (eslint) | — | **N/A** | No eslint configured; `typecheck` covers type safety. Recorded as TECH-DEBT in `M5-CODE-AUDIT.md` §8 (introducing eslint now would add noise, deferred) |
| 6 | Migration upgrade head | `alembic upgrade head` | **PASS** | SQLite `0001 → 0012`, rc=0 |
| 7 | Migration downgrade/upgrade throwaway | `alembic downgrade base` → `upgrade head` | **PASS** | SQLite `0012 → base → 0012`, all rc=0 — chain is **fully reversible** |
| 8 | Secret scan | `git grep` (private keys / AKIA / xox / ghp_ / sk- / hardcoded literals) | **PASS** | No real secrets. Only hits are `AKIAIOSFODNN7EXAMPLE` (AWS **documentation example** key) + `SUPER_SECRET_*` fixtures in `backend/tests/` that **assert non-leakage** (redaction tests). Non-test source/scripts/compose: **clean (rc=1)** |
| 9 | `.env` hygiene | `git ls-files`, `.gitignore` | **PASS** | `.env` **not tracked**; `.gitignore` = `.env`, `.env.*`, `!.env.example` (only the placeholder template is committed) |
| 10 | `git diff --check` | `git diff --check` (+ `--cached`) | **PASS** | rc=0 — no whitespace errors, no conflict markers |
| 11 | Native smoke (fresh DB, Demo mode) | `python scripts/smoke.py` over HTTP | **PASS** | 15 steps, **exit 0**, `SentinelFlow core smoke test (SQLite): PASS`. Core chain over **real HTTP** (not direct service calls): health → ready → dashboard → simulator alert → event → risk → incident → AI mock → approval. Execution step **fails CLOSED** on SQLite (§4) |
| 12 | Native timing (clone → complete core chain) | timed migrate + boot + smoke | **PASS** | `migrate 2.00s + startup 2.41s + smoke_chain 6.44s = ` **10.85s** (excludes one-time `pip install` / `npm ci`; excludes Docker image pull — see §3) |
| 13 | `doctor.ps1` | `./scripts/doctor.ps1 -SkipHttp` | **PASS** | **13 PASS / 6 WARN / 0 FAIL**, exit 0. The 6 WARN are exactly the absent tools (docker, compose, psql, PostgreSQL:5432, backend:8000 not running, ollama) — correct diagnostics, not failures |
| 14 | `.sh` syntax | `bash -n scripts/*.sh` | **PASS** | `quickstart.sh`, `setup-dev.sh`, `doctor.sh`, `smoke.sh` all rc=0 (Git bash) |

---

## 3. UNVERIFIED on this host (tooling absent) — §18 items requiring Docker / PostgreSQL / Linux

| Check | Verdict | Why it cannot run here |
|---|---|---|
| Docker build (backend + frontend images) | **UNVERIFIED** | No Docker daemon |
| `docker compose config` validation | **UNVERIFIED** | No `docker compose` |
| Docker Quickstart end-to-end (`quickstart.ps1` / `.sh`) | **UNVERIFIED** | No Docker; scripts written + syntax/structure-reviewed only |
| In-container smoke over **PostgreSQL** (full demo chain incl. execution→outcome) | **UNVERIFIED** | No Docker + no PostgreSQL |
| Migration on **PostgreSQL** | **UNVERIFIED** | No PostgreSQL (SQLite migration verified instead, §2 #6/#7) |
| Windows Docker Quickstart | **UNVERIFIED** | No Docker |
| Linux Docker Quickstart | **UNVERIFIED** | No Linux + no Docker |
| Linux Native setup (`setup-dev.sh`) | **UNVERIFIED** | No Linux (bash -n clean only) |
| AI Local Mode (Ollama) | **UNVERIFIED** | No Ollama installed; `AI_PROVIDER=ollama` degrade-path is code-reviewed, not run |

**Docker first-run image download/build time** (the §10 "counted separately" segment) is **UNVERIFIED** — it cannot be measured without Docker. The measured **native** clone→core-chain time is **≈11s** (§2 #12).

---

## 4. The single Demo-Mode segment that is UNVERIFIED here: execution → external outcome

- The Demo core chain (alert → normalization → dedup → risk → incident → AI mock → approval) is **PASS natively on SQLite** (§2 #11).
- The **execution** step (`POST /api/v1/executions`) goes through `DurableDispatchAttemptStore.record()`, which commits the pre-dispatch attempt on an **independent MVCC connection** (frozen M4-F contract). Under SQLite's single writer lock this **fails CLOSED** (`database is locked`, HTTP 500, no dispatch, no external call, no fabricated outcome). See `M5-CODE-AUDIT.md` **H-3**.
- Therefore the **execution → outcome → manual-reconcile** leg is a **PostgreSQL-only** path and is **UNVERIFIED on this host** (no PostgreSQL). It is exercised by the backend test suite (in-memory StaticPool engine) and by `smoke.py`'s PostgreSQL branch, but not run live here.
- `smoke.py` is **driver-aware**: on SQLite it asserts the fail-closed invariants (`metrics.total_chains == 0`, `succeeded == 0`) and prints `core smoke test (SQLite): PASS`; on PostgreSQL it runs the full chain and prints `demo smoke test: PASS`. It never claims the full-demo PASS on SQLite.

**Fail-closed invariants confirmed under the SQLite DB-lock failure (§2):** Dispatch Fact ≠ External Outcome Fact (not conflated) · no fabricated Outcome · no auto retry/polling/compensation · human approval not bypassed. The security contract **does not degrade** at this platform boundary.

---

## 5. Independent tracks (kept separate per §15/§19 — never bundled into a Demo PASS)

| Track | Status | Note |
|---|---|---|
| Real PostgreSQL concurrency / external dispatch | **INDEPENDENT — not run here** | Requires a PostgreSQL instance + the durable-dispatch crash/concurrency harness; out of scope for this host |
| Real TheHive Lab (gate ⑤ trusted-reader proof) | **UNKNOWN / fail-closed — INDEPENDENT** | Not deployed; production reader registry stays unauthorized; no forged instance/tenant proof (§2, §19) |
| Real Wazuh / Shuffle Lab | **INDEPENDENT — not deployed** | Integration Lab is CONFIG-gated, `LAB / EXPERIMENTAL / NOT PRODUCTION-CERTIFIED`; never auto-deployed (§4, §19) |

---

## 6. Bottom line

- **CORE APPLICATION on Windows Native (SQLite):** **PASS** — boots, migrates (reversibly), serves the full core chain over HTTP, 2869 backend tests + 97 frontend tests green, frontend builds clean, no secrets, no whitespace errors.
- **DEMO MODE on PostgreSQL (the supported Demo DB):** **UNVERIFIED on this host** (no Docker/PostgreSQL). Every runnable segment short of the PG-only execution leg is PASS natively; the PG-only leg is covered by tests + the smoke PostgreSQL branch but not executed live here.
- **DOCKER QUICKSTART / WINDOWS DOCKER / LINUX NATIVE / LINUX DOCKER / AI LOCAL / POSTGRESQL VALIDATION / THEHIVE LAB / WAZUH-SHUFFLE:** **UNVERIFIED** (tooling absent) or **INDEPENDENT** (external lab).

See `docs/design/M5-RELEASE-READINESS-FINAL-REPORT.md` for the per-capability readiness verdicts (§21 — no single PASS merges all capabilities).
