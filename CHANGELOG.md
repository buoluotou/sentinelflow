# Changelog

All notable changes to SentinelFlow are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.4.0-rc2] - 2026-09-11

### Fixed

- **Non-ASCII Bearer credential on the execution write paths** — a credential
  containing non-ASCII characters raised an unhandled error and answered 500.
  `OperatorRegistry.lookup` (`backend/app/services/executions/operators.py`)
  now encodes the presented token and the known token as bytes before
  comparing them, so every malformed credential gets the same 401.
- **`GET /api/v1/executions` loaded the whole audit table** — the endpoint read
  every audit row into memory and paginated in Python. It now filters, orders
  and pages at the execution-chain level in SQL and hydrates only the rows of
  the requested page (`backend/app/api/v1/response_execution.py`).
- **`GET /api/v1/approvals` issued one extra query per queued row** — the alert
  group behind each queued recommendation is now loaded with the page instead
  of one query at a time.
- **`frontend/package-lock.json` resolved all 185 dependency URLs through a
  third-party npm mirror** — every entry now points at
  `registry.npmjs.org`. Versions and integrity hashes are unchanged.
- **Shell scripts were tracked without the executable bit** — all five
  (`scripts/quickstart.sh`, `scripts/setup-dev.sh`, `scripts/smoke.sh`,
  `scripts/doctor.sh`, `scripts/ci/secret-scan.sh`) are now committed as
  executable, so the documented `./scripts/quickstart.sh` works on Linux and
  macOS.

### Changed

- **Secret redaction is now installed on production logging** — the redaction
  filter is attached to the application logger, the root logger and their
  handlers, so records logged through other loggers (uvicorn's included) are
  filtered too. The redaction set now covers the operator tokens, the adapter
  callback tokens, the AI provider key and the password inside `DATABASE_URL`.
- **OpenAPI version** — the API document takes its version from
  `app.__version__` instead of a separate literal, which had reported 1.3.0
  while the release tag was already `v1.4.0-rc1`.

### Added

- **Docker Compose demo stack in CI** — a job starts the documented
  `docker compose` demo stack on PostgreSQL and runs the end-to-end smoke test
  inside the backend container. The job fails unless the full PostgreSQL banner
  is produced, so a stack that silently fell back to SQLite cannot pass.
- **Browser end-to-end suite** — Playwright running against a
  PostgreSQL-backed harness, with a gate that fails on a collection shortfall,
  on a failure and on a skip.
- **Statement coverage measurement and gate** — `pytest-cov` measures statement
  coverage, and `scripts/ci/check_coverage.py` fails when the package total or
  the execution, approval, policy, auth, durability and outcome modules fall
  below their floors.
- **`scripts/perf_read_paths.py`** — a read-path scale check that seeds a fixed
  dataset and asserts bounded statement counts, so a query that grows with the
  table fails instead of passing on a demo-sized database.

### Documentation

- **User-facing documentation rewritten** — the docs no longer use internal
  development vocabulary. The API reference was corrected: it documented an
  execution request contract that no longer existed. The deployment guide now
  defaults to loopback with an explicit production edge topology, and new
  operations notes cover append-only database grants
  (`docs/operations/POSTGRES-APPEND-ONLY.md`) and dependency integrity
  (`docs/operations/DEPENDENCY-INTEGRITY.md`).

## [Unreleased]

### Added
- **Durable compensation target binding**: the reverse-operation reservation
  now also binds the reverse operation identity and the exact endpoint, and the
  send consumes the committed binding instead of resolving it again from
  mutable settings. The new `CompensationBindingContributor` protocol
  (`compensation_binding_facts` + `compensate_with_binding`) is implemented by
  Shuffle (`workflow:<id>` + `/api/v1/workflows/<id>/execute`) and Wazuh
  (`command:<release-host|unblock-source-ip>` +
  `/api/v1/agents/<id>/active-response`). The binding schema is now
  `sentinelflow.compensation_binding.v2` (`reverse_operation_ref`); v1 records
  are never parsed as v2 and never back-filled. Any config or mapping drift
  between the durable commit and the wire call fails closed with no outbound
  call. A new shared no-redirect transport (`executions/transport.py`) makes
  the default Shuffle and Wazuh transports reject every 3xx response, so an
  `Authorization` header is never forwarded to another host; the TheHive
  adapter is unchanged. 31 new tests
  (`test_compensation_target_binding.py`) cover the full matrix, including
  redirect checks against a real local server.

### Security
- **Security gates in CI now fail the build**: `pip-audit` runs as a gate
  instead of being swallowed with `|| true`, using an explicit CVE allowlist;
  `npm audit` fails on HIGH and CRITICAL findings (MEDIUM and LOW are
  reported); the new `scripts/ci/secret-scan.sh` fails on any unallowlisted
  high-confidence credential hit (private key / ghp_ / github_pat_ / AKIA /
  xox / sk- / long Bearer) and on a tracked `.env`. The allowlist holds only
  the exact AWS documentation example value, with no directory-wide
  exclusions. A synthetic fixture and a staged `.env` make the scanner exit 1;
  removing them returns exit 0.

### Fixed
- **The PostgreSQL CI job could pass without running the durable suite**: the
  `postgres-external` job now sets `SENTINELFLOW_PG_TEST_URL`, the variable the
  suites actually read (`DATABASE_URL` alone silently skipped everything), and
  runs all four files (dispatch 9 + compensation 9 + audit-ordering 2 +
  risk/incident 2 = 22). `scripts/ci/check_pg_external_result.py` gates the
  result on collected=22, passed=22, skipped=0; an unexpected skip fails the
  job. The risk/incident PostgreSQL tests now run for real: 2/2 passed on
  PostgreSQL 16.

- **Durable compensation for reverse dispatch**: the reverse (compensation)
  dispatch now has the same durable protection as forward dispatch. The new
  append-only `compensation_attempt` table (migration 0013) commits the
  immutable reverse binding in its own transaction before the external
  compensation request, with a unique reservation on `original_execution_id`
  (one durable compensation per original execution), a unique `execution_id`
  replay guard, and `compensation_attempt_id` as the terminal row's correlation
  handle (`detail["compensation_attempt_id"]`). A persistence failure means no
  external call; a timeout, a lost response, a crash, a caller rollback or a
  failed terminal write keeps the attempt and never retries it automatically —
  recovery is a manual, read-only reconciliation through
  `find_unreconciled_compensations` / `classify_compensation_recovery`.
  Recognized adapters without a durable compensation store fail closed (503),
  mirroring the existing requirement for forward dispatch, with the offline
  mock still exempt. `EXECUTION_COMPENSATION_EXPERIMENTAL` is retained while
  the reverse path awaits real-lab validation.

### Fixed
- **Risk → incident transaction atomicity**: `RiskService.recalculate` used to
  commit internally, splitting the ingestion pipeline — a failure while
  auto-opening the SOC case left the risk updated and the case missing, and a
  caller rollback could not take the risk update back. The deduplication engine
  is now the single transaction boundary for the pipeline: alert evidence, the
  EventRisk snapshot and the automatic Incident commit or roll back together.
  The one-case-per-event invariant holds under a concurrent race through
  `uq_incidents_alert_group_id` and a nested SAVEPOINT in
  `auto_create_from_risk` — the loser's unique violation is a benign no-op that
  keeps its transaction valid, so no duplicate case appears and no transaction
  is poisoned. The scoring rules are unchanged: a score of 70 or more
  auto-creates a case, and the case snapshot copies the risk score.
- **Audit ordering without process-global clock state**: the audit timestamp no
  longer comes from a process-global high-water mark (`_LAST_AUDIT_STAMP` was
  neither thread-safe nor correct across worker processes, and the
  `(created_at DESC, id DESC)` tie-break degraded to a random uuid4 lottery on
  ties). `created_at` is now stamped by the database at INSERT — PostgreSQL
  uses `clock_timestamp()` (migration 0014), the statement's real time rather
  than the transaction-start `now()`, while SQLite keeps `CURRENT_TIMESTAMP` —
  and `execution_log.id` is minted by an insert-ordered UUIDv7 generator
  (`app.core.ids.uuid7`), so the `(created_at, id)` tie-break reproduces the
  true insertion order through same-millisecond bursts and clamped backward
  clock steps. One chain is written by exactly one process, so per-chain
  ordering needs no cross-process coordination, and no caller ever passes or
  fabricates a timestamp. The execution-list read order uses the same
  insert-ordered UUIDv7 as its final tie-break (`last_decision_at`, then the
  chain's last audit-row id), which is deterministic on SQLite's
  second-precision timestamps too, where a uuid4 `execution_id` tie-break was a
  coin flip.

### Added
- **`DEPLOYMENT_MODE` (demo | production) with an approval auth boundary and a
  fail-closed production startup check**. Production mode will not start on an
  unsafe setting, and reports one sanitized error naming settings keys only:
  missing `OPERATORS_JSON` auth, SQLite, the mock execution adapter,
  compensation or reverse workflows, or a non-loopback `BIND_HOST`. Approval
  write paths have an explicit boundary — demo mode keeps the tokenless,
  display-only behaviour, while production mode answers 401 to a tokenless
  approval, requires the separate approval permission (viewer and executor get
  403) and records the Bearer token's principal while ignoring any identity in
  the request body. The permissions are named explicitly by
  `OperatorRole.can_approve`, `can_reconcile` and `can_admin`.

### Security
- **Docker hardening enabled by default**: `postgres` / `migrate` / `backend` /
  `frontend` run with `read_only: true`, scoped `tmpfs` mounts and
  `no-new-privileges:true`; the backend image was already non-root (uid 10001).
  No privileged mode, no host docker socket, no host mounts. All four
  containers report `ReadonlyRootfs=true` and the 18-step smoke test passes
  18/18. Recommended minimums and optional production limits are documented in
  docs/deployment.md.

### Added
- **Engineering documentation set**: the external integration safety matrix
  (per capability, not one overall verdict), the TheHive supported-version
  (5.x) feasibility study, the dependency security audit, the CI local
  validation mapping, the production-edge (TLS / reverse-proxy) design, the
  GitHub branch-protection plan, the backup/restore procedure (with the
  read-only + tmpfs finding), and the CycloneDX SBOMs (`artifacts/sbom/`).

### Changed
- **Compose project isolation** — removed the fixed `container_name:` values and
  the global volume names from `docker-compose.yml`; `docker compose -p <project>`
  (or `COMPOSE_PROJECT_NAME`) now yields independent containers / networks /
  volumes with no extra overrides. Default single-instance behaviour is
  unchanged (project `sentinelflow`, data volume `sentinelflow_pg-data`; the
  one-time copy from a volume using the older `sentinelflow-pg-data` name is
  documented in docs/TROUBLESHOOTING.md).
- **Quickstart health wait** resolves the backend through
  `docker compose ps -q backend` instead of the fixed name `sf-backend`
  (bash + PowerShell), so any project name works.
- **Backend image build**: opt-in `PIP_INDEX_URL` build arg (default stays the
  official `https://pypi.org/simple`) for China / restricted networks — set it
  in `.env` and rebuild, or `docker compose build --build-arg PIP_INDEX_URL=...`.
- **Docs**: mirror guidance in README / QUICKSTART / TROUBLESHOOTING; fixed
  container-name references; dependency wording clarified — `base.lock` is
  exact version pins (no pip `--hash` verification), recorded by lockfile
  artifact SHA-256 separately.

## [1.3.0] - 2026-09-01

Governance and observability around the v1.2.0 execution layer: who may execute
(operator identity and RBAC), when execution is allowed (execution policy) and
how execution performs (execution metrics and observed adapter health), all
surfaced in the execution observability UI. Governance and observability, not
automation: no automatic approval, no automatic retry, no adapter fan-out and
no hidden execution — every verdict is derived read-only from recorded
execution facts. The v1.2.0 safety model is unchanged: no new tables, no new
migrations, no new execution states and no new adapters, and the release's last
stages were verification only, with no production-code changes.

### Added

- **Operator identity & RBAC** — static operator registry (`OPERATORS_JSON`: name + token + role, one token → exactly one operator) with four roles `viewer / reviewer / executor / admin`; the write-path gate `authenticate_operator` resolves the Bearer token to the single server-side identity — any client-supplied `operator` field is accepted for backwards compatibility but ignored, so impersonation is impossible, and only `executor` / `admin` may dispatch executions (403 for the other roles); an empty configuration stays fail-closed (401). The legacy `EXECUTION_TOKEN` maps to the synthetic `legacy-execution` operator unchanged.
- **Execution policy** — a pure, read-only decision model evaluated between Guard and Executor (`EXECUTION_POLICY_*` settings, disabled by default): a UTC server-clock time window `[start, end)` and per-action minimum risk thresholds read from the server-side `EventRisk.score` (a missing risk fact fails closed). Policy refusals land as `guard_rejected` with `detail.source = "policy"` (distinct from structural Guard refusals); the request schema (`extra="forbid"`) accepts no risk / severity / timestamp / policy field, so forged client values have no channel in; a malformed policy configuration is a static 503 with rollback, never a silent allow.
- **Execution metrics read model + API** — `GET /api/v1/executions/metrics` (no credential, read-only): total / succeeded / failed / guard_rejected / in-flight chains, `success_rate = succeeded / (succeeded + failed)` with `guard_rejected` never counted in the adapter denominator, `guard_rejection_rate` as the separate governance metric, rejection provenance (`guard` vs `policy`), failure classifications and latency — all derived from `execution_log` with zero writes; an empty denominator is `null`, which the UI renders as N/A rather than 0%.
- **Adapter observed health read model + API** — `GET /api/v1/executions/health` (no credential, read-only, no active probing): per-adapter observed status from the four-word vocabulary `unknown / healthy / degraded / failing` over the most recent 20 terminal chains; guard refusals and in-flight chains never enter that window, so governance pressure cannot be misattributed to an adapter; thresholds `healthy ≥ 0.9`, `degraded ≥ 0.5`; `unknown` means no terminal observation, never an invented verdict.
- **Execution observability UI** — read-only `/observability` console page: six metrics cards + per-adapter health cards with the `Observed: {status}` badge; the page has no buttons and sends no write traffic, mirrors the two GET responses field for field (the UI never recomputes them) and does not auto-refresh.
- **Cross-layer and browser regression tests** — 7 cross-layer journeys plus 7 real-Chromium browser journeys covering all eight E2E specs: N/A rates on an empty log, the four observed statuses, the governance-flood invariant (1 success + 20 policy refusals → `Observed: healthy`), three real adapter-failure classifications visible end to end, zero writes on read-only pages, zero token participation in observability, and browser output matching the API field for field.

### Validation

- Backend: 1353 passed, 0 failed, 0 skipped (3 external adapter tests deselected by default)
- Frontend: 97 passed + `tsc --noEmit` 0 errors + production build success
- Browser E2E: 18/18 (11 execution journeys + 7 observability journeys)
- Migrations: 0001 → 0009 round trip including `downgrade base`; this release adds no new migrations
- `v1.1.0` (tag on `0f6e3fc`) and `v1.2.0` (tag on `2be74f8`) unchanged

## [1.2.0] - 2026-08-31

External response adapters: controlled response execution extends from the
offline Mock executor to three real external systems behind one unified
`ResponseExecutor` contract, while the v1.1.x safety model is unchanged end to
end:

AI → Recommendation → Human Approval → Explicit Execution → Guard / Policy → External Adapter → Shuffle / Wazuh / TheHive → Execution Audit

No automatic approval. No automatic retry. No internal adapter fan-out:
`EXECUTION_ADAPTER` names exactly one adapter. No hidden execution. External
systems cannot modify SentinelFlow risk or incident facts, and adapter secrets
are never persisted in execution audit records.

**Deployment boundary:** all four adapter implementations (mock / shuffle /
wazuh / thehive) exist, but the default configuration and the default test
suite stay offline — mock remains the credential-free default, every adapter
test runs against offline stub transports, and real Shuffle / Wazuh / TheHive
connections require explicit `.env` configuration plus the opt-in `external`
test mode (`pytest -m external`). This release adds support for external
execution, not a default live connection.

### Added

- **Controlled response execution (commit `657cb87`, first released here)** — append-only `execution_log` (migration 0009: 11 columns, 8 legal decision×direction combinations, three partial unique indexes, FK `approval_id` ON DELETE NO ACTION); a derived-state machine with the 8-word vocabulary; Guard with five rejection codes over `EXECUTABLE_ACTIONS`; a deterministic zero-outbound `MockExecutor`; a synchronous Execute / Compensation service; the API `POST /api/v1/executions` + `.../compensate` + read endpoints (201 records an execution fact, not a success; Bearer `EXECUTION_TOKEN` on write paths only); and the React Execute Console and Execution Audit UI. Backend 875 passed + 11 real-browser E2E journeys at release.
- **External adapter architecture** — shuffle / wazuh / thehive move from reserved placeholder slots to recognized adapters with fail-closed startup validation (`validate_adapter_config` in the lifespan gate); selecting more than one adapter is rejected; configuration errors name setting keys only — credential values never surface (repr masking included).
- **Adapter credential boundary** — one independent secret boundary for every external credential: the only legal life of a secret is `.env → Settings → AdapterCredentials → Authorization header`. URL shape checks reject query strings, fragments and userinfo, so a credential can never ride inside a URL; credentials are repr-masked (Bearer api-key + Basic user/password shapes); `service._append` is the single audit `***` redaction gate; adapter misconfiguration is a static 503; and a `SecretRedactionFilter` masks Python logging.
- **Shuffle workflow adapter** — workflow orchestration: each executable action triggers exactly one pre-configured workflow (flat `SHUFFLE_WORKFLOW_*` mapping, failing closed on any empty id); optional reverse workflows gate compensation capability; `succeeded` means the trigger was confirmed, with no automatic retry; `external_execution_id` tracks the external execution id so idempotency can propagate. The test suite gains an `external` marker: real-instance tests are deselected unless the run opts in with `-m external`, so the default suite stays zero-outbound.
- **Wazuh endpoint response adapter** — endpoint / security response: the vocabulary `isolate_host` / `disable_account` / `block_source_ip` via Wazuh `POST /agents/{id}/active-response`, authenticated with the `WAZUH_API_USER` / `WAZUH_API_PASSWORD` pair (Basic) through the credential boundary above. Compensation is symmetric where the endpoint allows it (isolate → release, block → unblock); `disable_account` cannot be compensated at all — account state is a human decision.
- **TheHive case adapter** — case creation, not a response engine: `escalate_to_incident` posts a six-field body to `POST /api/case` with `sentinelflow_execution_id` for idempotency / audit / external tracking, and human investigators take over from there (never auto-investigation, never auto-close). Success requires HTTP 200/201 and a `case_id` — case identity, not a success flag; a 409 duplicate resolves to `succeeded + idempotent_duplicate` unless the response claims another execution's id or contradicts the event, which fails closed; there is no compensation, because the case lifecycle belongs to the investigation.
- **Capability policy** — `EXECUTABLE_ACTIONS` grows 3 → 4 (`escalate_to_incident`, the only capability added in this release) while `NON_COMPENSATABLE_ACTIONS` keeps it non-compensable: escalating to a case has no machine reversal. `hunt_related_activity` / `monitor_only` stay advisory, not machine-executable.
- **Fail-closed outcome handling and protocol-violation validation** — a per-adapter outcome matrix (timeouts / HTTP faults / unavailable providers classified in `detail`); an ambiguous adapter answer (success without an identity) raises `ExecutorOutcomeViolation`, and only the platform's outcome parser judges `protocol_violation`; nothing retries automatically.

### Validation

- Backend: 1132 passed, 0 failed, 0 skipped (875 → 911 → 950 → 991 → 1048 → 1132 as the adapters landed)
- External adapter tests are opt-in (`pytest -m external`): 3 deselected by default
- The default test suite makes no real external request
- `v1.1.0` (tag on `0f6e3fc`) and `v1.0.0-phase1` unchanged; this release consists of five commits `59e78d1` → `2be74f8`, each rebuilt and tested on its own

## [1.1.0] - 2026-08-27

AI-assisted analysis behind a human approval queue: the AI advises, humans
decide, and execution stays out of scope — approving a recommendation never
executes it.

### Added

- **AI provider architecture** — a unified `AIProvider` contract with Mock (default, offline), Ollama (`/api/chat`) and OpenAI-compatible providers ("cloud" is a deployment alias); the structured-output protocol `{summary, attack_type, why_risky[], confidence}`; a typed error taxonomy (config / unavailable / parse); a settings-based registry (`AI_PROVIDER`, `AI_MODEL`, `AI_BASE_URL`, `AI_API_KEY`). AI output is advisory only — it never triggers execution.
- **AI alert-explanation data layer** — the `ai_analyses` history table (migration 0005; indexed, non-unique `alert_group_id`), an evidence-bounded AIRequest builder (max 20 alerts) and `AIAnalysisService` (flush-only, typed errors).
- **AI alert-explanation API** — the explicit-trigger endpoints `POST/GET /api/v1/events/{id}/ai-analysis` (201 with the full analysis / latest read); error contract 404 (unknown event or no analysis), 503 (provider misconfigured or unreachable), 502 (protocol violation, never persisted). Verified against a local `qwen3:4b` Ollama model (native JSON mode, configurable `AI_TIMEOUT_SECONDS`); the tests stay on the mock provider.
- **Event detail AI panel** — an "AI Alert Explanation" panel on the event detail page: the latest analysis on load (attack type, summary, why-risky list, confidence, provider/model), an explicit "Analyze with AI" trigger with a disabled analyzing state and a slow-model hint, and backend error detail surfaced verbatim; re-analysis appends history instead of editing it. Verified in a browser against both a real `qwen3:4b` model and the mock provider.
- **AI risk-summary protocol and task-unified providers** — a new `risk_summary` task alongside `alert_explanation`; the `RiskSummary` protocol `{summary, key_findings[1..5], risk_drivers[vocabulary], analyst_priority(low/medium/high/critical), confidence 0..1}` with a 10-term `RISK_DRIVERS` vocabulary and strict rejection of unknown fields (the AI never emits a new risk score — `EventRisk.score` stays the single official score); `AIProvider.generate(request)` dispatches by task, with `explain()` kept as a compatibility alias; the `ai_risk_summaries` history table (migration 0006, indexed non-unique `alert_group_id`) plus an optional `prior_explanation` carry-over from the latest alert explanation.
- **AI risk-summary request builder** — `build_risk_summary_request()` translates AlertGroup + EventRisk + evidence (plus the optional latest alert explanation) into a `task=risk_summary` AIRequest; the task is fixed inside the builder, so callers cannot steer it, a missing alert explanation never blocks generation, and both tasks share one evidence projection (`MAX_EVIDENCE=20`, earliest first, `None` fields dropped); `prior_explanation` is a structured `{summary, attack_type, why_risky, confidence}` projection with no internal ids or provider metadata.
- **AI risk-summary service** — `AIRiskSummaryService.generate_risk_summary()` orchestrates Event + EventRisk + evidence (plus the optional latest alert explanation) through the task-unified provider and appends a validated `ai_risk_summaries` row; it is flush-only (the API owns the transaction boundary), history is append-only with no overwrite, an `isinstance(RiskSummary)` guard turns a wrong-protocol provider answer into a 502 that is never persisted, and the same error contract applies (404 / 503 / 502, failures never persist). Advisory only — it never touches `EventRisk` or `Incident` and never produces execution actions.
- **AI risk-summary API** — the explicit-trigger endpoints `POST/GET /api/v1/events/{id}/ai-risk-summary` (201 with the full summary / latest read ordered `created_at DESC, id DESC`); error contract identical to the alert-explanation endpoints — 404 (unknown event or no summary), 503 (provider misconfigured or unreachable), 502 (protocol violation or a wrong-protocol provider answer, never persisted); `AIRiskSummaryRead` mirrors the row field for field and never exposes a risk score. Tests inject failing providers through the `get_ai_risk_summary_service` dependency; no real model runs in CI.
- **AI risk-summary protocol regression and real-model E2E** — 34 new offline regression tests pin the protocol: `risk_score` injection rejected via `extra=forbid`, unknown risk drivers rejected with no coercion, `confidence` bounded to [0, 1], `key_findings` bounded to 1..5, `analyst_priority` limited to the defined enum, and config / unavailable / parse failures never persisting a row. The real-model E2E lives under `backend/tests/e2e/` behind an `ollama` marker (`collect_ignore_glob` keeps the default suite mock-only and offline); it was verified against a live local `qwen3:4b` on the full POST → DB → GET chain and on dead-URL fault injection (503, zero persisted rows), asserting protocol shape only and never natural-language content.
- **Event detail AI risk-summary panel** — an "AI Risk Summary" panel on the event detail page mirroring the alert-explanation panel: the latest summary on load (GET only — never an automatic POST), a 404 rendered as a normal "No risk summary generated yet." empty state, an explicit "Generate Risk Summary" trigger with a disabled generating state and a slow-model hint, the 201 response rendered directly without a follow-up GET, and backend 503/502 details surfaced verbatim. It shows analyst priority, confidence, summary, key findings and risk drivers only — never a risk score, because `EventRisk.score` stays the single official score. First frontend test stack: vitest + jsdom + Testing Library, 8 unit tests covering all states plus a guard that a smuggled `risk_score` is never rendered.
- **Browser E2E for the AI risk-summary panel** — verified in a browser against the live console with two chains: the mock chain covers the full user path (empty state → explicit generate → panel render → refresh loading the latest via GET only, never an automatic POST → a second generate appending a second history row with the first untouched), and the real `qwen3:4b` chain covers the slow-model path (disabled generating state, ~33s inference under the 180s timeout, a protocol-shaped render with the driver vocabulary, provider/model surfaced as ollama/qwen3:4b). Both chains leave `EventRisk` and `Incident` untouched and never surface a risk score in the UI.
- **Risk-summary release verification** — backend 347 passed (0 failed / 0 skipped), frontend 8 passed + zero TypeScript errors + production build; the mock and real `qwen3:4b` browser chains re-run green (risk_score never rendered, EventRisk/Incident unchanged, history append-only); the real-model suite under `tests/e2e/` re-run explicitly under the `ollama` marker (2 passed; the default suite stays mock-only and offline); migration 0006 verified through `alembic upgrade head` with no `create_all` in the production path; `git diff --check` clean. Released as the single commit `feat(ai): add risk summary`.
- **AI response-recommendation protocol and data model** — the `response_recommendation` task with a six-action vocabulary `RESPONSE_ACTIONS` (`block_source_ip`, `isolate_host`, `disable_account`, `hunt_related_activity`, `escalate_to_incident`, `monitor_only`; anything else is a 502 protocol violation that never persists); the output protocol `{overall_rationale, recommendations[0..5] × {action, target, rationale}, confidence 0..1}` with `extra=forbid` at both layers, where an empty recommendations list is a first-class answer ("no action warranted", distinct from "no record yet"); the system prompt forbids execution and risk-score recomputation; an optional `prior_summary` carries a five-key projection of the latest risk summary; the `ai_response_recommendations` history table (migration 0007, indexed non-unique `alert_group_id`); deterministic Mock bands (≥70 block+escalate / 40–69 hunt / <40 empty).
- **AI response-recommendation service and API** — `AIResponseRecommendationService` (flush-only, with a vocabulary re-check so typed-object providers cannot bypass the word list; failures never persist) behind the explicit-trigger endpoints `POST/GET /api/v1/events/{id}/response-recommendation` (201 with the full recommendation / latest read ordered `created_at DESC, id DESC`); the API owns commit + refresh; error contract identical to the other AI endpoints (404 / 503 / 502); `AIResponseRecommendationRead` mirrors the row field for field and never exposes a risk score.
- **Response-recommendation cross-layer regression** — all six actions round-tripped through the real API path, the three Mock score bands verified end to end (empty recommendations treated as success), protocol violations driven through the raw-output Ollama path (unknown action / extra field / risk_score smuggle / confidence out of bounds → 502 with zero new rows), and the POST → GET → POST → GET loop proving append-only history with the first record never updated.
- **Event detail response-recommendation panel** — a "Response Recommendation" panel completing the analysis chain (explanation → risk summary → response recommendation): the latest recommendation on load, a 404 empty state strictly distinguished from 200 + `recommendations=[]` ("No response action warranted."), an explicit single "Generate Response Recommendation" button, display-layer labels for the six actions (no new protocol enum), and no execution affordance of any kind — Approve/Execute stays out of the UI until the approval workflow lands.
- **Browser E2E for the response-recommendation panel** — two chains verified: the mock chain covered empty state → generate → refresh (GET only) → second generate (two rows, the first untouched, EventRisk/Incident unchanged, all six action labels rendered), and the real `qwen3:4b` chain produced a protocol-shaped recommendation (3 actions, all within the vocabulary, confidence in [0,1]) under the 180s timeout — structure asserted, natural-language content never pinned.
- **Response-recommendation release verification** — backend 427 passed, frontend 19 passed + zero TypeScript errors + production build; migration 0007 verified via `alembic upgrade head` with no `create_all` in the production path; `git diff --check` clean; all 25 changed files belong to this feature and no sensitive artifact is present. Released as the single commit `feat(ai): add response recommendation`.
- **Approval queue over AI response recommendations** — human decisions layered on AI advice, with approval kept separate from execution at every layer: the `ai_response_approvals` table (migration 0008, `UNIQUE(recommendation_id)`, `CHECK status IN ('approved','rejected')` — "pending" is a derived queue state and is never persisted); INSERT-only one-shot decisions with `reviewed_at` stamped by the server (clients can send only `reviewer` + optional `review_comment`, `extra="forbid"`); `GET /api/v1/approvals` serving the pending queue projected by the backend (`created_at ASC, id ASC`) and `POST .../approve|reject` returning 201, with a repeat decision answered 409; a React Approval Queue page (read-only recommendations, shared reviewer, double-click guard, local removal on 201 vs server re-sync on 409); real-browser Playwright E2E (10 journeys: lifecycle, persistence, refresh, empty queue, concurrent 409, delayed-POST busy state, network whitelist). No AI result or decision ever touches `EventRisk`, `Incident` or any orchestrator — execution stayed out of this release. Backend 505 passed / frontend 35 passed; released as the single commit `feat(ai): add approval queue`.
- **Incident AI association protocol and data model** — the incident-centric case view: `Incident` gains read-only (`viewonly`) traversals to its event's `ai_analyses`, `ai_risk_summaries` and `ai_response_recommendations` (the approval is reachable via `recommendation.approval`), joining on the same `alert_group_id` — no schema change, no new migration, no incident foreign key on any AI table. The boundaries hold: `Incident.risk_score` stays the creation-time snapshot of `EventRisk.score` and no AI result writes it back; the AI rows remain the AlertGroup's append-only history, so deleting an incident never deletes AI history; an approved decision is displayed and audited only, never consumed automatically (no Shuffle/Wazuh/TheHive execution).
- **Incident AI context service** — `get_incident_ai_context(db, incident_id)` is a pure read aggregation composing those traversals into the `IncidentAIContext` DTO (`IncidentSnapshot{id, status, severity, risk_score_snapshot}` + the complete histories `analyses[] / risk_summaries[] / response_recommendations[{recommendation, approval|null}]`, each embedding its existing protocol schema unchanged, ordered `created_at ASC`). An unknown incident raises the project's unified `IncidentNotFound` before anything is assembled, so nothing leaks across cases; an incident without AI history returns a valid empty context; `approval=None` stays the derived pending state and is never persisted. The service writes nothing — no add/flush/commit — the incident snapshot, status and severity and all AI/approval row counts are unchanged by a read, and an approved recommendation surfaces as audit information only: no execution, no incident transition and no risk recompute.
- **Incident AI context API** — `GET /api/v1/incidents/{incident_id}/ai-context` exposes the incident's complete AI history as a strictly read-only HTTP endpoint. The router is a passthrough into the service — it never queries AI tables itself, never generates or refreshes AI data, never recomputes risk and never touches approvals or the incident state. A 404 reuses the unified `"Incident not found"` detail (unknown id and malformed UUID alike) with no context body and no cross-case leak; an incident without AI history answers 200 with empty histories; `approval=null` keeps the derived pending semantics and adds no persisted approval status. Verified by 7 dedicated API tests (unknown/malformed 404, empty 200, full history + approved/rejected/pending semantics, incident A↔B isolation, HTTP read-only boundary) — backend suite 531 passed.
- **Incident AI integration cross-layer regression** — covers the three features above together, keeping the full chain (`AlertGroup -> EventRisk -> Incident -> AI Context` with explanation, risk summary, recommendation and approval) intact once combined. The new `test_incident_ai_cross_layer_regression.py` drives every AI row through the production endpoints (mock provider: `POST /events/{id}/ai-analysis | ai-risk-summary | response-recommendation`, `POST .../approve|reject`) and observes the result at ORM, service and API layers: the full-lifecycle body matches the database rows id for id; histories stay complete (`created_at ASC`, never latest-overwrites) with approved/rejected/pending coexisting and pending never persisted; `Incident.risk_score` and `EventRisk.score` survive AI activity plus repeated context reads; isolation holds at all three layers; an approved chain read end to end fabricates no execution, no new recommendation and no status move; empty and analysis-only pipelines are legal context states. No production code changed and no bug was found — 7 new tests, backend suite 538 passed.
- **React incident AI view** — the Incident Detail page gains a read-only "AI Investigation" panel consuming only `GET /incidents/{id}/ai-context` (one new API-client method `getIncidentAIContext`, GET-only; no generate/approve/reject/execute client added). One protocol end to end: the new `IncidentAIContext` / `IncidentSnapshot` / `RecommendationWithApproval` TypeScript types compose the existing types unchanged (plus `AIResponseApproval` mirroring the backend read schema) — no second frontend protocol. Complete histories render newest-first with nothing dropped (`AI Explanation History (n)` / `Risk Summary History (n)` / `Response Recommendation History (n)`); approvals audit as Approved/Rejected chips with reviewer + reviewed-at + comment, while `approval=null` renders as the derived "Pending Review" label, never sent back to the backend; empty and partial pipelines are legal states ("No AI analysis available yet.", never "Failed to load"); only `risk_score_snapshot` is shown. Approve/Reject stay owned by the Approval Queue: the panel renders no buttons. No backend change was needed. Frontend 43 passed (8 new: full / multi-history / approval-states / empty / partial / safety-boundary / snapshot + a 404 banner), tsc clean, Vite build OK.
- **Browser E2E for the incident AI view** — real Chromium + real uvicorn + real vite over a throwaway SQLite database, in `backend/tests/e2e/test_incident_ai_context_browser.py` (9 journeys). Every AI row is produced through the production endpoints (mock provider: `POST /events/{id}/ai-analysis | ai-risk-summary | response-recommendation`, `POST .../approve|reject`) and only the event skeleton is seeded. Verified in a genuine browser: the full AI context (incident info + risk snapshot + explanation / risk summary / recommendation / approval all visible); the three approval states, with `approval=null` rendering only "Pending Review" while the database stores exactly `{approved, rejected}` (no pending row); 3×3×3 histories all visible (never latest-only); empty ("No AI analysis available yet.", no error banner) and partial (explanation-only) pipelines healthy; an unknown incident giving the unified 404 "Incident not found" with zero cross-case leakage; the risk snapshot staying at 80 after further AI history lands. The safety boundary extends to the browser: the AI Investigation panel renders no buttons and none of Execute / Block Now / Isolate Now / Disable Now / Run Response / Retry Execution / Approve / Reject; a page load emits only `GET .../ai-context` (dev-mode StrictMode may repeat the read-only GET once) and zero POSTs of any kind — observe, review and audit, never decide or execute. No production code changed; two test-infrastructure fixes came with it (pipe-drain threads so the ~4 KB Windows pipe buffer can no longer deadlock uvicorn mid-run, and widened post-navigation expect timeouts against vite cold compiles). Backend 538 passed; frontend 43 passed / tsc clean / build OK; E2E 9/9 green twice in a row.
- **Incident AI release verification** — backend 538 passed (0 failed / 0 skipped), frontend 43 passed + zero TypeScript errors + production build, and the browser E2E re-run green (9/9, a third consecutive run); the migration round trip verified on a throwaway SQLite (`alembic upgrade head` 0001→0008, `current` = 0008, `downgrade base` full rollback, re-upgrade clean — this feature adds no new migration); a full change audit: `git diff --check` clean, all 8 tracked production edits additive, the 10 new files all Incident-AI test, schema, service or component artifacts, no stray .env, database, tmp, log or screenshot file, and no execution code anywhere (Shuffle / Wazuh / TheHive appear only in comments stating they are not called). The security boundaries were re-checked: `EventRisk.score` and `Incident.risk_score` are never written by this feature (the snapshot is projected read-only), the context service is write-free (no add/flush/commit), approvals stay `{approved, rejected}` with pending derived only, and the browser layer emits zero mutating traffic.

## [1.0.0-phase1] - 2026-08-25

The first release: the complete detection-to-incident SOC platform.

### Added

- **Alert Ingestion** — `POST /api/v1/alerts` + listing/detail; every alert and raw payload preserved as evidence
- **Normalization** — adapter-based unified event model (`POST /api/v1/normalize`); Simulator adapter implemented, Wazuh adapter reserved (501)
- **Deduplication & Aggregation** — SHA-256 fingerprint + 5-minute window (`DEDUP_WINDOW_SECONDS`); fingerprint ≠ group semantics; window expiry opens new events
- **Explainable Risk Engine** — severity / frequency / public-source factors, 0–100 score, four levels; factor breakdown stored per event; recalculated transactionally on the write path only; surfaced in `GET /api/v1/events` (`?level=` filter)
- **Incident Management** — data model, service-layer lifecycle state machine (`open → in_progress → resolved/false_positive → closed`), REST API with 404/409 error contract, automatic creation at risk ≥ 70 (idempotent, snapshot-at-first-threshold-crossing)
- **Dashboard API** — `GET /api/v1/dashboard/summary` real-time aggregation (active incidents, severity breakdown, today's alerts/events, risk distribution)
- **React Web Console** — dark SOC theme; Dashboard (auto-refresh), Events (filter/pagination/detail with risk factors and evidence), Incident Queue (status filter, lifecycle transitions)
- **Scenario Simulator** — 5 attack scenarios + stdlib runner CLI (`--repeat`, `--timestamps now|file`)
- **Docs** — architecture, API reference, demo guide, deployment + security hardening checklist
- **Release engineering** — 202-test backend suite, Alembic migrations 0001–0004, `.env.example` with placeholders only

### Known Limitations

- No authentication — deploy behind a trusted reverse proxy (see `docs/deployment.md`)
- SQLite is supported for evaluation/CI; PostgreSQL 16 is the production target
