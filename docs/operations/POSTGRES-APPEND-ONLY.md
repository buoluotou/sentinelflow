# PostgreSQL Append-Only Audit Tables

The execution audit trail is insert-only in application code. The database does not
enforce that yet. This document records the first fact, gives a production grant
layout that adds the second, and says why the stack runs without it.

## 1. What the application already guarantees

Four tables hold execution facts:

| Table | Model | Migration |
|---|---|---|
| `execution_log` | `backend/app/models/execution_log.py` (`ExecutionLog`) | `0009_add_execution_log.py` |
| `execution_outcome` | `backend/app/models/execution_outcome.py` (`ExecutionOutcome`) | `0010_add_execution_outcome.py` |
| `dispatch_attempt` | `backend/app/models/dispatch_attempt.py` (`DispatchAttempt`) | `0011_add_dispatch_attempt.py`, index widened in `0012` |
| `compensation_attempt` | `backend/app/models/compensation_attempt.py` (`CompensationAttempt`) | `0013_add_compensation_attempt.py` |

Rows are inserted and never modified; searching `backend/app` for a write path against them returns no code:

```
grep -rnE "\b(update|delete)\s*\(" backend/app
# 3 hits, all prose inside comments and docstrings
grep -rnE "\b(UPDATE\s+\w+\s+SET|DELETE\s+FROM|TRUNCATE)\b" backend/app
# no matches
```

Execution state is derived from the rows rather than stored beside them: reads take
the latest row per `execution_id` ordered by `(created_at ASC, id ASC)`
(`backend/app/services/executions/state.py`). None of the four tables has an
`updated_at` column, so a row has no field an update could legitimately touch.

That holds in application code only. The code never issues an `UPDATE` or
`DELETE`; nothing stops another session from doing so. A `psql` shell or a
maintenance script connecting as the owning user can rewrite any row.

## 2. A runtime role without UPDATE or DELETE

Create two roles: one that owns the schema and runs Alembic, one the application
connects as. The first block runs once as a superuser. The second runs as
`sentinelflow_owner` after every `alembic upgrade head`. The third runs once.

```sql
CREATE ROLE sentinelflow_owner LOGIN PASSWORD '<ddl-password>';
CREATE ROLE sentinelflow_app   LOGIN PASSWORD '<app-password>';
ALTER DATABASE sentinelflow OWNER TO sentinelflow_owner;
GRANT CONNECT ON DATABASE sentinelflow TO sentinelflow_app;
GRANT USAGE   ON SCHEMA   public     TO sentinelflow_app;
```

```sql
-- Business tables: the application reads and writes them normally.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinelflow_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinelflow_app;
-- Audit facts: append only. The REVOKE must come after any broad grant; it is
-- what removes the UPDATE and DELETE that ALL TABLES just handed over.
GRANT  SELECT, INSERT
    ON execution_log, execution_outcome, dispatch_attempt, compensation_attempt
    TO sentinelflow_app;
REVOKE UPDATE, DELETE ON execution_log, execution_outcome, dispatch_attempt,
       compensation_attempt FROM sentinelflow_app;
```

```sql
ALTER DEFAULT PRIVILEGES FOR ROLE sentinelflow_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinelflow_app;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinelflow_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO sentinelflow_app;
```

Default privileges hand out `UPDATE` and `DELETE` on every future table, so a
migration adding a fifth fact table would widen the grant. Keep the audit `GRANT` /
`REVOKE` pair next to your DDL and re-run it after each migration; both are
idempotent.

Three details the example depends on. `sentinelflow_owner` keeps ownership of the
schema, the tables and `alembic_version`, and keeps `CREATE` / `ALTER` / `DROP`; the
application role is not an owner, since an owner can grant rights back to itself.
`migrate` and `backend` need different credentials, so point `migrate` at
`sentinelflow_owner` and `backend` at `sentinelflow_app`. The audit tables use UUID
primary keys generated in Python and own no sequence; the sequence grant covers
future tables, and foreign-key checks run with the privileges of the table owner, so
`execution_log.approval_id` needs no grant on `ai_response_approvals`.

No trigger, rule or view is involved. The grant is the whole mechanism.

## 3. Why the default install does not do this

The compose stack runs one database user. `POSTGRES_USER` creates the database,
owns the schema, runs `alembic upgrade head` in `migrate` and serves requests in
`backend`. Splitting the roles means a second secret, two `DATABASE_URL` values and
a grant step between the migration and the first request, which breaks the
one-command quickstart and the CI jobs that connect as a single user (`migration`,
`postgres-external`, `compose-demo-e2e` in `.github/workflows/ci.yml`). So
`docker compose up` on a laptop leaves the application with `UPDATE` and `DELETE` on
all four tables. Treat section 2 as a production step and add it to the checklist in
[PRODUCTION-EDGE.md](PRODUCTION-EDGE.md).

## 4. Verifying the grant

As the application role, with `WHERE false` so a missing denial damages nothing:

```
$ docker compose exec postgres psql -U sentinelflow_app -d sentinelflow
sentinelflow=> UPDATE execution_log SET decision = 'failed' WHERE false;
ERROR:  permission denied for table execution_log
sentinelflow=> DELETE FROM execution_outcome WHERE false;
ERROR:  permission denied for table execution_outcome
```

Insert must keep working: run one execution and watch the row count rise.
