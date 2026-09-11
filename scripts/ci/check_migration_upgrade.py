"""Upgrade a database that already holds rows from an older revision.

The migration job covers a fresh install. This covers the other direction: a
database created at revision 0009, written to, then upgraded to head. It fails
if any row disappears, if a stored value changes, or if the schema does not end
on a single head.

Usage:
    check_migration_upgrade.py [--database-url URL] [--from-revision 0009]
"""
from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend"

GROUP = uuid.uuid4().hex
RECOMMENDATION = uuid.uuid4().hex
APPROVAL = uuid.uuid4().hex
EXECUTION = uuid.uuid4().hex
TARGET = "203.0.113.10"
STAMP = "2026-01-02T03:04:05+00:00"


def _alembic_config():
    from alembic.config import Config

    config = Config(str(BACKEND / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND / "migrations"))
    return config


def _upgrade(revision: str) -> None:
    from alembic import command

    command.upgrade(_alembic_config(), revision)


def _write_rows(engine) -> None:
    """Insert the dependency chain an execution_log row needs."""
    from sqlalchemy import text

    statements = [
        (
            "INSERT INTO alert_groups (id, fingerprint, title, category, severity,"
            " status, alert_count, first_seen, last_seen) VALUES (:id, :fp, :title,"
            " :cat, :sev, 'open', 1, :stamp, :stamp)",
            {"id": GROUP, "fp": uuid.uuid4().hex, "title": "upgrade check",
             "cat": "authentication", "sev": "high", "stamp": STAMP},
        ),
        (
            "INSERT INTO ai_response_recommendations (id, alert_group_id, provider,"
            " model, overall_rationale, recommendations, confidence) VALUES (:id,"
            " :group, 'mock', 'mock-deterministic', 'upgrade check', :recs, 0.7)",
            {"id": RECOMMENDATION, "group": GROUP,
             "recs": '[{"action": "block_source_ip", "target": "%s", "rationale": "r"}]' % TARGET},
        ),
        (
            "INSERT INTO ai_response_approvals (id, recommendation_id, status,"
            " reviewer, reviewed_at) VALUES (:id, :rec, 'approved', 'analyst-1', :stamp)",
            {"id": APPROVAL, "rec": RECOMMENDATION, "stamp": STAMP},
        ),
        (
            "INSERT INTO execution_log (id, execution_id, approval_id, decision,"
            " direction, action, target, operator, detail) VALUES (:id, :exec,"
            " :approval, 'dispatched', 'execute', 'block_source_ip', :target,"
            " 'analyst-1', :detail)",
            {"id": uuid.uuid4().hex, "exec": EXECUTION, "approval": APPROVAL,
             "target": TARGET, "detail": '{"classification": "ok"}'},
        ),
    ]
    with engine.begin() as conn:
        for statement, params in statements:
            conn.execute(text(statement), params)


def _check_rows(engine) -> None:
    from sqlalchemy import text

    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT id, execution_id, approval_id, decision, direction, action,"
                " target, operator FROM execution_log WHERE execution_id = :exec"
            ),
            {"exec": EXECUTION},
        ).mappings().one()
        approval = conn.execute(
            text("SELECT status, reviewer FROM ai_response_approvals WHERE id = :id"),
            {"id": APPROVAL},
        ).mappings().one()
        group = conn.execute(
            text("SELECT title FROM alert_groups WHERE id = :id"), {"id": GROUP}
        ).mappings().one()
        revision = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()

    expected = {
        "execution_id": EXECUTION,
        "approval_id": APPROVAL,
        "decision": "dispatched",
        "direction": "execute",
        "action": "block_source_ip",
        "target": TARGET,
        "operator": "analyst-1",
    }
    uuid_columns = {"execution_id", "approval_id"}
    for column, value in expected.items():
        stored = str(row[column])
        if column in uuid_columns:
            # PostgreSQL returns a hyphenated UUID, SQLite the stored 32 characters.
            stored = stored.replace("-", "")
        if stored != value:
            raise SystemExit(f"execution_log.{column} changed: {row[column]} != {value}")
    if approval["status"] != "approved" or approval["reviewer"] != "analyst-1":
        raise SystemExit(f"approval row changed: {dict(approval)}")
    if group["title"] != "upgrade check":
        raise SystemExit(f"alert group row changed: {dict(group)}")
    print(f"  rows survived: execution_log + ai_response_approvals + alert_groups")
    print(f"  alembic_version after upgrade: {revision}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--from-revision", default="0009")
    args = parser.parse_args(argv)

    url = args.database_url or os.environ.get("DATABASE_URL")
    if not url:
        print("FAIL: no database URL (pass --database-url or set DATABASE_URL)")
        return 1
    os.environ["DATABASE_URL"] = url
    sys.path.insert(0, str(BACKEND))

    from app.core.database import engine

    driver = url.split("://", 1)[0]
    print(f"historical upgrade check ({driver})")
    print(f"  step 1: upgrade to {args.from_revision}")
    _upgrade(args.from_revision)
    print("  step 2: write rows at that revision")
    _write_rows(engine)
    print("  step 3: upgrade to head")
    _upgrade("head")
    print("  step 4: verify the stored rows")
    _check_rows(engine)

    from alembic.runtime.migration import MigrationContext

    with engine.connect() as conn:
        heads = MigrationContext.configure(conn).get_current_heads()
    if len(heads) != 1:
        print(f"FAIL: expected a single head, found {heads}")
        return 1
    print(f"\nPASS: {args.from_revision} -> {heads[0]}, data intact, single head")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
