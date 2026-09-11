# Backup and Restore — SentinelFlow PostgreSQL

**Status: this procedure was run end to end against PostgreSQL 16.** Two runs,
2026-09-10 on Kali and 2026-09-11 UTC, with the stack at Alembic head `0014`.
The commands below are the commands that were run.

Evidence: the full command log from that run (commands, per-table counts, content
digests, and the failure case) and the artifact
`sentinelflow-backup.dump` (streamed to the host at validation time;
SHA-256 `507f3759343b3c24ec63ccfb18c1638f40fa2b373c0f6716a3c8d95117288582`,
48 KiB — regenerated 2026-09-11 after the host reboot; the streamed procedure
was reproduced end-to-end and both snapshot diffs matched again).

> **Read this first: the production hardening breaks the old `docker cp`
> pattern.** Production runs `postgres` with a read-only root filesystem and a
> tmpfs `/tmp`. The legacy pattern — `pg_dump -f /tmp/x.dump` inside the
> container, then `docker cp` — fails now: tmpfs mounts are not part of the
> container root filesystem layer, so `docker cp` cannot see the file
> (`Could not find the file ... in container`). The validation reproduced this
> failure. Use the streamed form below: it never touches the container
> filesystem.

## 1. What is backed up

The PostgreSQL database `sentinelflow`. The compose `pg-data` volume is only
where it lives: never back up the volume files instead of a logical dump,
because a file copy of a running cluster is not a consistent backup.

The logical dump captures every fact table: `alerts`, `alert_events`,
`alert_groups`, `event_risk`, `incidents`, `ai_analyses`, `ai_risk_summaries`,
`ai_response_recommendations`, `ai_response_approvals`, `execution_log`,
`execution_outcome`, `dispatch_attempt`, `compensation_attempt` (migration
0013), `alembic_version`.

The dump never contains operator tokens, execution tokens or passwords: those
are never stored in the database (they live only in `.env` / the operator
registry), so a leaked dump yields SOC data, never credentials. Treat the dump
as sensitive anyway — it is the full alert and incident history.

## 2. Backup and restore procedure

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

- `pg_restore` must not be given the argument `-`: it treats `-` as a literal
  filename (unlike `pg_dump`). Omit the filename to read stdin, or pass a real
  file path.
- The restore target must be brand new and empty: `pg_restore` does not merge
  (section 4).
- `<project>` is the compose project name (`sentinelflow` by default; any
  `docker compose -p <name>` produces `<name>-postgres-1`).

## 3. Verification performed

Two independent runs, both streamed from the host artifact:

| Run | Path | Result |
|---|---|---|
| 1 | host artifact → fresh `sentinelflow_restore` | `pg_dump rc=0`, `pg_restore rc=0` |
| 2 | same artifact → fresh `sentinelflow_restore_host` (repeatability) | `pg_restore rc=0` |

The per-table comparison — row counts plus the row-order-independent
`md5(string_agg(x::text ORDER BY x::text))` content digest of every table —
matched on 13 of 13 tables, with 0 mismatches. The full-source snapshot diff
against the restored database is empty.

Validation dataset (post-smoke, head 0014): `alerts=8`, `alert_events=8`,
`alert_groups=2`, `event_risk=2`, `incidents=2`, `ai_analyses=8`,
`ai_response_recommendations=12`, `ai_response_approvals=12`,
`execution_log=33`, `execution_outcome=1` (a synthetic fixture covering the
outcome path; the demo reconcile path answers 404 and fails closed),
`dispatch_attempt=11`, `compensation_attempt=0`, `alembic_version=1` (`0014`).

Relational probes on the restored database, all non-zero where data is
expected: `chains_with_approval=11`, `all_chains=11`, `succeeded_terminals=10`,
`dispatch_attempts_joined=33`, `outcomes_joined=3`, `open_incidents=2`,
`incidents_with_group=2`, `alembic_version=0014`.

Independence check: after the restore, the source and the restored database
answered `count(*) FROM alerts` independently (`8` / `8`). The demo database was
never the restore target.

## 4. Failure cases

| Case | Result |
|---|---|
| Restore into a non-empty, conflicting database | Fails loudly: `pg_restore` reports every conflicting statement (`relation "alerts" already exists`, `column ... does not exist`, `multiple primary keys ...`) and never silently merges partial data. Restore into a fresh database, or use `--clean --if-exists`. |
| Restore into a missing target database | Connection error. Create the database first (section 2, step 2). |
| Wrong credentials, or a user without rights on the target database | PostgreSQL refuses with an auth or ownership error. The `-U` user must own the target database. |
| `docker cp` of an in-container dump when `postgres` runs with a read-only root filesystem and tmpfs `/tmp` | `Could not find the file ... in container`: tmpfs is invisible to `docker cp`. Use the streamed form. |
| `pg_restore ... -` (stdin spelled as `-`) | `could not open input file "-"`. Omit the filename instead. |

## 5. Production recommendations

Nothing in this section is configured by the repository.

- Scheduled backups: run `pg_dump -Fc` from a cron or systemd timer. The
  wrapper must fail loudly, with a non-zero exit, and keep a timestamped
  artifact.
- Retention: for example 7 daily, 4 weekly and 6 monthly copies, pruned by age.
  Never keep "latest only".
- Encryption: encrypt the dump at rest with `age` or `gpg`; it is plain SOC
  data.
- Off-host copy: sync encrypted dumps to a second machine or object store you
  operate. This repository never auto-connects to any cloud storage.
- Restore drills: run the restore into a dedicated database (section 2) on a
  schedule, and use the count and digest comparison (section 3) as the
  acceptance check: script it and assert zero mismatches.
- Point-in-time recovery: for an RPO below the dump interval, configure
  PostgreSQL WAL archiving and base backups. That is an operational decision
  outside this repository.
- Volume snapshots: only as a supplement for whole-host disaster recovery,
  never as the primary backup; a snapshot may capture a torn state of a live
  cluster.

## 6. Upgrade and rollback

Application rollback is not the same as a destructive database downgrade. The
supported recovery path is to restore the last known-good dump (this document)
and redeploy the matching application version. Alembic `downgrade` is a
development affordance, not a production rollback strategy.

The upgrade validation — old `0009` schema and data upgraded to head `0014`,
with data and digests intact — lives in `docs/design/`.
