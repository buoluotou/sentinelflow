# Backup & Restore — SentinelFlow PostgreSQL (RC2 §12)

**Status: VERIFIED on a real PostgreSQL 16 round trip** (2026-09-10 Kali /
2026-09-11 UTC validation run, stack at Alembic head `0014`). This document
records the exact, executed procedure — not a plan.

Evidence: `/tmp/rc2-evidence/12-backup-restore.txt` (full command log, count
tables, content digests, failure case) and the artifact
`sentinelflow-backup.dump` (streamed to the host at validation time;
SHA-256 `23b26231aece3b3622dd8a70db4737683639575a58bf5bd1f3bbd903f76cbfeb`,
44 KiB).

> **RC2 §18 interaction — read this first.** The production hardening makes
> `postgres` run with a **read-only root filesystem + tmpfs `/tmp`**. The
> legacy pattern "`pg_dump -f /tmp/x.dump` inside the container, then
> `docker cp`" **fails** now: tmpfs mounts are not part of the container root
> filesystem layer, so `docker cp` cannot see the file (`Could not find the
> file ... in container`). The validation reproduced this deliberately.
> **Use the streamed form below** — it never touches the container filesystem.

## 1. What is backed up

The PostgreSQL database `sentinelflow` (the compose `pg-data` volume is just
where it lives — **never back up the volume files as a substitute for a
logical dump**; a file copy of a running cluster is not a consistent backup).

The logical dump captures every fact table: `alerts`, `alert_events`,
`alert_groups`, `event_risk`, `incidents`, `ai_analyses`, `ai_risk_summaries`,
`ai_response_recommendations`, `ai_response_approvals`, `execution_log`,
`execution_outcome`, `dispatch_attempt`, `compensation_attempt`
(RC2: migration 0013), `alembic_version`.

The dump never contains operator tokens / execution tokens / passwords —
those are **never stored in the database by design** (they live only in `.env`
/ the operator registry), so a leaked dump yields SOC data, never credentials.
Treat it as sensitive anyway (it is the full alert/incident history).

## 2. Canonical procedure (verified as-is)

```bash
# 1) BACKUP — stream the custom-format dump straight to the host.
#    Works with the read_only + tmpfs hardening; needs no container path.
docker compose exec -T postgres pg_dump \
    -U "${POSTGRES_USER:-sentinelflow}" \
    -d "${POSTGRES_DB:-sentinelflow}" -Fc \
    > backup-$(date +%Y%m%d-%H%M%S).dump

# 2) RESTORE — into a DEDICATED FRESH database (never over the demo database):
docker compose exec -T postgres psql -U sentinelflow -d postgres \
    -c "CREATE DATABASE sentinelflow_restore OWNER sentinelflow"
docker exec -i <project>-postgres-1 pg_restore \
    -U sentinelflow -d sentinelflow_restore < backup-YYYYmmdd-HHMMSS.dump

# 3) VERIFY (counts + content digests — see §3), then drop the throwaway db:
docker compose exec -T postgres psql -U sentinelflow -d postgres \
    -c "DROP DATABASE sentinelflow_restore"
```

Notes:

- `pg_restore` **must not be given the argument `-`**: it treats `-` as a
  literal filename (unlike `pg_dump`). Omit the filename to read stdin, or
  pass a real file path.
- The restore target must be **brand new / empty**. `pg_restore` does not
  merge; see §4.
- `<project>` is the compose project name (`sentinelflow` by default; any
  `docker compose -p <name>` produces `<name>-postgres-1`).

## 3. Verification performed (evidence)

Two independent rounds, both streamed **from the host artifact**:

| Round | Path | Result |
|---|---|---|
| 1 | host artifact → fresh `sentinelflow_restore` | `pg_dump rc=0`, `pg_restore rc=0` |
| 2 | same artifact → fresh `sentinelflow_restore_host` (repeatability) | `pg_restore rc=0` |

**Per-table comparison (counts + row-order-independent `md5(string_agg(x::text ORDER BY x::text))` content digests): 13/13 MATCH, 0 MISMATCH** —
the full-source snapshot diff against the restored database is empty.
Validation dataset (post-smoke, head 0014): `alerts=7`, `alert_events=7`,
`alert_groups=1`, `event_risk=1`, `incidents=1`, `ai_analyses=7`,
`ai_response_recommendations=7`, `ai_response_approvals=7`, `execution_log=18`,
`execution_outcome=1` (documented synthetic fixture for outcome coverage —
the demo reconcile path is intentionally 404/fail-closed),
`dispatch_attempt=6`, `compensation_attempt=0`, `alembic_version=1` (`0014`).

**Relational probes on the restored database** (all non-zero where data is
expected): `chains_with_approval=6`, `all_chains=6`, `succeeded_terminals=6`,
`dispatch_attempts_joined=18`, `outcomes_joined=3`, `open_incidents=1`,
`incidents_with_group=1`, `alembic_version=0014`.

**Independence check**: after restore, source and restored databases answered
`count(*) FROM alerts` independently (`7` / `7`) — the demo database was never
the restore target.

## 4. Failure cases (verified behavior)

| Case | Result |
|---|---|
| Restore into a **non-empty, conflicting** database | **Fails loudly** — `pg_restore` reports every conflicting statement (`relation "alerts" already exists`, `column ... does not exist`, `multiple primary keys ...`). It never silently merges partial data. Restore into a **fresh** database, or use `--clean --if-exists` deliberately. |
| Restore into a missing target database | connection error — create the DB first (see §2 step 2). |
| Wrong credentials / user without rights on the target DB | PostgreSQL refuses (auth or ownership error) — the `-U` user must own the target database. |
| `docker cp` of an in-container dump under RC2 §18 hardening | `Could not find the file ... in container` — tmpfs is invisible to `docker cp`; use the streamed form. |
| `pg_restore ... -` (stdin spelled as `-`) | `could not open input file "-"` — omit the filename instead. |

## 5. Production recommendation (documented — NOT auto-configured)

- **Scheduled backups**: `pg_dump -Fc` on a cron/systemd timer; the wrapper
  must fail loudly (non-zero exit) and keep a timestamped artifact.
- **Retention**: e.g. 7 daily + 4 weekly + 6 monthly; prune by age, never
  "latest only".
- **Encryption**: `age` / `gpg` the dump at rest (it is plain SOC data).
- **Off-host copy**: sync encrypted dumps to a second machine / object store
  you operate. This repository never auto-connects to any cloud storage.
- **Restore drills**: run §2's restore-into-a-dedicated-db on a schedule; the
  §3 count/digest comparison is the acceptance check (script it, assert zero
  MISMATCH).
- **Point-in-time**: for RPO below the dump interval, configure PostgreSQL
  WAL archiving + base backups — an operational decision outside this repo.
- **Volume snapshots**: only as a *supplement* (whole-host DR), never as the
  primary backup — they may capture a torn state of a live cluster.

## 6. Upgrade / rollback note (RC2 §13)

Application rollback **≠** database destructive downgrade. The supported
recovery path is: restore the last known-good dump (this document) and
redeploy the matching application version. Alembic `downgrade` is a
development affordance, **not** a production rollback strategy — the upgrade
validation (old `0009` schema + data → head `0014`, data + digests intact)
lives in `docs/design/` and the review bundle's `07-postgres-validation.txt`.
