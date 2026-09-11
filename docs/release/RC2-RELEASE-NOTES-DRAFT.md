# v1.4.0 Release Notes — DRAFT (RC2 §24)

> **Status: DRAFT ONLY.** No tag, no GitHub Release, no push. The version number
> is a *recommendation* (§25, pending final review). This file exists so the
> release can be cut mechanically once the final review approves it.

## Recommended version: `v1.4.0`

Rationale: RC2 adds real features and behavior changes on top of v1.3.0
(production deployment mode, an approval auth boundary, durable compensation,
CI) — a MINOR bump under this project's semver practice, not a patch. An
`v1.4.0-rc1` pre-release is acceptable if the reviewer prefers a staged call
for the first real-lab claims; the artifacts are identical.

## Highlights

### Production debt closed (the headline)

- **Durable compensation (C-1).** Reverse dispatch now gets the same durable
  protection as forward dispatch: an append-only `compensation_attempt`
  reservation commits on its own transaction before any external reverse call,
  with a UNIQUE reservation per original execution. Persistence failure ⇒ zero
  external call; lost response / crash / rollback ⇒ the attempt survives and
  is NEVER auto-retried (manual, read-only reconciliation only).
  `EXECUTION_COMPENSATION_EXPERIMENTAL` remains, by design, pending real-lab
  validation of the reverse path.
- **Risk → Incident atomicity (H-1).** The deduplication engine is the one
  pipeline transaction boundary: alert evidence + risk snapshot + automatic
  incident commit or roll back together. The one-case-per-event invariant
  survives a true concurrent race (unique index + nested SAVEPOINT).
- **Audit ordering (H-2).** `created_at` is stamped by the database at INSERT
  (PostgreSQL `clock_timestamp()` via migration 0014); `execution_log.id` is an
  insert-ordered UUIDv7. The frozen `(created_at, id)` order is now
  deterministic under threads, sessions and rapid bursts — and the execution
  list read order ties break on the same insert-ordered id.

### Production posture

- **`DEPLOYMENT_MODE=demo|production`** with a fail-closed production startup
  gate (no SQLite, no tokenless approval, no mock adapter, no unsafe
  compensation, loopback bind required).
- **Approval auth boundary / RBAC** — production approvals come from an
  authenticated Bearer principal; approval / execution / reconcile / admin
  permissions are separate; body identity fields are ignored.
- **Docker hardening by default** — read-only rootfs, scoped tmpfs,
  `no-new-privileges`, non-root backend, no host socket.

### Release engineering & docs

- `.github/workflows/ci.yml` — exact-lock backend suite, frontend
  typecheck/test/build, compose config, fresh-PostgreSQL migration gate,
  images build, dedicated PostgreSQL durable suite job, dependency advisory +
  secret scan. **CI CONFIGURED / LOCALLY VALIDATED**; a real GitHub run is
  pending the first push.
- New operations docs: `docs/operations/BACKUP-RESTORE.md` (verified procedure,
  including the read-only/tmpfs finding), `PRODUCTION-EDGE.md`,
  `GITHUB-BRANCH-PROTECTION.md`.
- `docs/integration/EXTERNAL-INTEGRATION-MATRIX.md` — per-capability external
  integration status (never one PASS for everything).

## External integration lab — what is now PROVEN (and what is not)

- **TheHive 4.1.24-1 (isolated lab): WRITE PASS, READ PASS**, on the exact
  image digest `sha256:c8b6c7ea...c6811` — a real case was created through the
  durable dispatch chain, and re-read independently (resource id, execution
  tag, severity, `createdAt` all match).
- **VERIFIED EXTERNAL OUTCOME = BLOCKED BY GATE 5.** TheHive 4.1.24-1 carries
  no authoritative instance/tenant fact; the platform refuses to fabricate one
  (`observed_instance = observed_tenant = None`, zero outcome facts). This is
  the correct fail-closed result, not a defect.
- **Shuffle / Wazuh real labs: NOT VALIDATED / RESOURCE BLOCKED** — see the
  capability matrix for the measured resource reasons. No mock or stub was
  used to fill the gap.
- **Production readiness: NOT CERTIFIED.** Lab evidence never upgrades to a
  production certification; TheHive 4 is EOL and the reverse path is
  unvalidated against a real system.

## Upgrade notes

- Migration head: `0014` (`0013` compensation_attempt, `0014` audit ordering).
  An old `0009` v1.3.0-era database was upgraded to `0014` with counts and
  content digests verified intact.
- **Backup/restore:** the hardened postgres container has a read-only rootfs +
  tmpfs `/tmp` — the legacy "dump inside the container then `docker cp`" flow
  no longer works. Use the streamed form in `docs/operations/BACKUP-RESTORE.md`.
- Application rollback ≠ database downgrade: restore the last known-good dump
  and redeploy the matching application version.

## Not in this release

- No tag / GitHub Release / push (deliberately; pending review).
- No production certification, no real Wazuh/Shuffle lab, no fixes to frozen
  M4 semantics (Outcome vocabulary, dispatch binding) — those remain frozen.
