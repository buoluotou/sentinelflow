# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in SentinelFlow, please do not open a public issue.

Report it privately to the maintainers with:

- a description of the issue,
- reproduction steps or a proof of concept,
- the affected component (backend / frontend / simulator / infrastructure).

We aim to acknowledge reports within 48 hours and to publish fixes for confirmed issues as soon as practical.

## Scope

Only assets in this repository are in scope. Upstream projects (Wazuh, Shuffle, TheHive, Ollama) have their own security policies.

## Deployment Modes

`DEPLOYMENT_MODE` selects the security posture, and the two modes differ in what they enforce.

**demo** (default) is the local evaluation setup. Loopback binding is the exposure control, the approval endpoints are tokenless, and the offline mock execution adapter is allowed.

**production** is checked at startup by `validate_production_mode`. The gate collects every unsafe setting and aborts startup, naming the offending keys and never their values. It requires:

- `OPERATORS_JSON` authentication, with at least one operator that can approve and one that can execute (the `EXECUTION_TOKEN`-only path is not an identity source in production),
- PostgreSQL (SQLite is demo and native development only),
- a real execution adapter (`EXECUTION_ADAPTER` must not be `mock` or empty),
- `EXECUTION_COMPENSATION_EXPERIMENTAL=false` and no `SHUFFLE_WORKFLOW_REVERSE_*` workflow,
- `BIND_HOST` on loopback.

## Threat Assumptions

The API is not a TLS terminator and does not run SSO. TLS and user authentication belong to a reverse proxy in front of it; the API port is not meant to be exposed directly. In production the loopback bind requirement enforces that. See [docs/operations/PRODUCTION-EDGE.md](docs/operations/PRODUCTION-EDGE.md).

Within the application there are three separate trust domains, and a credential from one never authenticates another:

| Domain | Credential | Covers |
|---|---|---|
| Human operators | `OPERATORS_JSON` Bearer token (name, role: `viewer` / `reviewer` / `executor` / `admin`), with the legacy `EXECUTION_TOKEN` fallback mapping to the synthetic operator `legacy-execution` | Execution dispatch, compensation, manual reconcile, and approvals in production mode |
| Inbound adapter callbacks | `SHUFFLE_CALLBACK_TOKEN` / `WAZUH_CALLBACK_TOKEN` / `THEHIVE_CALLBACK_TOKEN`, bound per route | `POST /webhooks/{adapter}` only |
| Outbound adapter calls | `SHUFFLE_API_KEY`, `WAZUH_API_USER` + `WAZUH_API_PASSWORD`, `THEHIVE_API_KEY`, `THEHIVE_READ_API_KEY` | Requests the platform makes to external systems |

What is authenticated:

- Every execution write path (`POST /executions`, `POST /executions/compensate`, `POST /executions/{execution_id}/reconcile`) requires a Bearer token. The token resolves server-side to one operator identity, which is the only identity recorded; a `operator` field in the request body is accepted and ignored. Dispatch requires the `executor` or `admin` role, and any other role gets `403`.
- Approval writes require a token in production mode and are tokenless in demo mode.
- Adapter callbacks authenticate against the callback token of the adapter named in the route.

What is not authenticated:

- All read endpoints, including `/executions/metrics`, `/executions/health`, `/executions`, `/approvals`, `/events`, `/incidents` and `/dashboard/summary`.
- Ingestion (`POST /alerts`, `POST /normalize`).

Both stay behind the deployment's network boundary; neither is a substitute for one.

## Fail-Closed Behavior

- An empty or wrong execution credential is a `401` before any row is written.
- An empty `EXECUTION_ADAPTER`, an unknown adapter name or a multi-valued one is rejected at startup.
- A real adapter with missing settings fails at startup rather than running half-configured. The mock adapter needs no credentials.
- A malformed execution policy configuration returns `503` and rolls back the dispatch.
- An unconfigured callback token closes that adapter's inbound channel with a uniform `401`; it does not block startup and it does not affect outbound dispatch.
- An external state the reconciliation contract does not recognize is refused, and no outcome fact is written for it.

## Execution Guarantees

- Execution happens only for an approved recommendation, through an Execute Intent the client sends, and only through the guard → policy → adapter chain.
- There is no automatic approval, no automatic retry and no adapter fan-out.
- Adapter output that is ambiguous — a success without an identity — raises `ExecutorOutcomeViolation` instead of being recorded as a success.
- Secrets travel only `.env → Settings → AdapterCredentials → Authorization header`. A base URL with a query string or userinfo is rejected, `SecretRedactionFilter` keeps credentials out of Python logs, `Settings.__repr__` masks values for names ending in `API_KEY`, `TOKEN` or `PASSWORD`, and audit `detail` is redacted with `***`.
- AI output is advisory. It is never written back to `EventRisk.score` or to an incident's risk snapshot, and it never triggers execution.

## Append-Only Records

These tables accept inserts only; nothing in the application updates or deletes rows:

- `execution_log` — one row per execution decision, with a foreign key to `ai_response_approvals` set to `ON DELETE NO ACTION`. Execution state is derived from the latest row rather than stored.
- `ai_response_approvals` — one-shot human decisions, one per recommendation.
- `ai_analyses`, `ai_risk_summaries`, `ai_response_recommendations` — AI history; re-triggering appends.
- `execution_outcome` — external-effect facts, kept separate from dispatch outcome so neither layer rewrites the other.
- `dispatch_attempt` and `compensation_attempt` — durable bindings committed on their own transaction before the external request, so a rollback, a terminal-write failure or a process crash does not erase the record of what was sent where.

## Experimental and Not Production-Certified

- Real-adapter compensation. Configuring a reverse Shuffle workflow requires `EXECUTION_COMPENSATION_EXPERIMENTAL=true` or the application will not start, and production mode rejects both. The offline mock compensates without that flag.
- The reconciliation read path. The production read-adapter registry is empty, so `POST /executions/{execution_id}/reconcile` currently answers `404 adapter read unsupported` for every adapter. The durable dispatch and compensation records are what recovery uses instead: a committed attempt with no terminal row is a manual reconciliation candidate, never an automatic retry.
- The mock adapter produces simulated outcomes and is intended for demo and test runs, not for reporting real response actions.

## Repository Hygiene

- Never commit `.env` files — it is git-ignored. Use `.env.example` as the template.
- Never commit credentials, API keys or tokens. All secrets are read from environment variables at runtime.
- Docker Compose reads the PostgreSQL password from the environment; change the default `change_me` value before running locally.
