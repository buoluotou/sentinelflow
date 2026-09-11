"""Seed a fixed dataset and time the read paths against it.

The point is not throughput figures. It is to catch the failure modes a
demo-sized database hides: an unbounded query behind a paged endpoint,
full-table ORM hydration, or a follow-up query per row.

Times are single-run wall clock on the machine that ran it, so compare runs on
the same machine, not across machines. Statement counts are the stable part:
they must not grow with the row count.

Usage:
python scripts/perf_read_paths.py
DATABASE_URL=sqlite:///./perf.db python scripts/perf_read_paths.py
DATABASE_URL=postgresql+psycopg://user:pw@host:5432/db python scripts/perf_read_paths.py
"""
from __future__ import annotations

import argparse
import os
import platform
import statistics
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND = REPO_ROOT / "backend"

# Bounds are generous: they are meant to fail on a query that
# scales with the table, not to police milliseconds on a shared CI runner.
MAX_STATEMENTS_PER_REQUEST = 15
MAX_SECONDS_PER_REQUEST = 2.0


def _bootstrap_database_url(url: str | None) -> str:
    """Resolve the target database and export it before the app is imported."""
    resolved = url or os.environ.get("DATABASE_URL")
    if not resolved:
        handle, path = tempfile.mkstemp(prefix="sentinelflow-perf-", suffix=".db")
        os.close(handle)
        os.unlink(path)
        resolved = f"sqlite:///{Path(path).as_posix()}"
    os.environ["DATABASE_URL"] = resolved
    sys.path.insert(0, str(BACKEND))
    return resolved


def _upgrade_schema() -> None:
    from alembic import command
    from alembic.config import Config

    config = Config(str(BACKEND / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND / "migrations"))
    command.upgrade(config, "head")


def _seed(counts: dict[str, int]) -> dict[str, int]:
    """Insert a connected dataset with bulk statements."""
    from sqlalchemy import insert

    from app.core.database import engine
    from app.models import (
        AIResponseApproval,
        AIResponseRecommendation,
        Alert,
        AlertEvent,
        AlertGroup,
        EventRisk,
        ExecutionLog,
        Incident,
    )

    base = datetime.now(timezone.utc) - timedelta(days=2)
    groups, alerts, events, risks, incidents, recs, approvals = [], [], [], [], [], [], []

    for i in range(counts["events"]):
        gid = uuid.uuid4()
        stamp = base + timedelta(seconds=i)
        groups.append({
            "id": gid, "fingerprint": uuid.uuid4().hex, "title": f"Event {i}",
            "category": "authentication", "severity": "high", "status": "open",
            "alert_count": max(1, counts["alerts"] // counts["events"]),
            "first_seen": stamp, "last_seen": stamp,
        })
        risks.append({
            "id": uuid.uuid4(), "alert_group_id": gid,
            "score": 50 + (i % 50), "level": "high" if i % 2 else "medium",
            "factors": {"severity": 50},
        })
        incidents.append({
            "id": uuid.uuid4(), "alert_group_id": gid, "title": f"Incident {i}",
            "description": "seeded", "severity": "high", "risk_score": 70,
            "status": "open",
        })

    per_group = max(1, counts["alerts"] // counts["events"])
    for i in range(counts["alerts"]):
        group = groups[i // per_group] if i // per_group < len(groups) else groups[-1]
        aid = uuid.uuid4()
        stamp = base + timedelta(microseconds=i)
        alerts.append({
            "id": aid, "source": "perf", "event_type": "auth_failure",
            "severity": "high", "status": "open", "title": f"Alert {i}",
            "first_seen_at": stamp, "last_seen_at": stamp, "event_count": 1,
            "alert_group_id": group["id"],
        })
        events.append({
            "id": uuid.uuid4(), "alert_id": aid, "source": "perf",
            "event_type": "auth_failure", "event_timestamp": stamp,
            "raw_data": {"i": i},
        })

    # One recommendation per execution chain, each with its own approval: the
    # audit table allows a single forward execution per approval, so chains
    # cannot share one. A further set of recommendations is left undecided, so
    # the approval queue has pending rows to render.
    chain_length = 3
    chains = max(1, counts["executions"] // chain_length)
    decisions = ("requested", "dispatched", "succeeded")
    log_rows = []
    chain_approvals = []
    for c in range(chains):
        group = groups[c % len(groups)]
        rid = uuid.uuid4()
        stamp = base + timedelta(seconds=c)
        recs.append({
            "id": rid, "alert_group_id": group["id"], "provider": "mock",
            "model": "mock-deterministic", "overall_rationale": "seeded",
            "recommendations": [{"action": "block_source_ip",
                                 "target": "203.0.113.10", "rationale": "seeded"}],
            "confidence": 0.7,
        })
        approval_id = uuid.uuid4()
        chain_approvals.append(approval_id)
        approvals.append({
            "id": approval_id, "recommendation_id": rid, "status": "approved",
            "reviewer": "analyst-1", "reviewed_at": stamp,
        })
    for p in range(counts["pending"]):
        recs.append({
            "id": uuid.uuid4(), "alert_group_id": groups[p % len(groups)]["id"],
            "provider": "mock", "model": "mock-deterministic",
            "overall_rationale": "seeded",
            "recommendations": [{"action": "block_source_ip",
                                 "target": "203.0.113.10", "rationale": "seeded"}],
            "confidence": 0.7,
        })
    for c in range(chains):
        execution_id = uuid.uuid4()
        for step, decision in enumerate(decisions):
            log_rows.append({
                "id": uuid.uuid4(), "execution_id": execution_id,
                "approval_id": chain_approvals[c], "decision": decision,
                "direction": "execute", "action": "block_source_ip",
                "target": "203.0.113.10", "operator": "legacy-execution",
                "detail": {"step": step},
                "created_at": base + timedelta(seconds=c, microseconds=step),
            })

    tables = (
        (AlertGroup, groups), (EventRisk, risks), (Incident, incidents),
        (AIResponseRecommendation, recs), (AIResponseApproval, approvals),
        (Alert, alerts), (AlertEvent, events), (ExecutionLog, log_rows),
    )
    inserted: dict[str, int] = {}
    with engine.begin() as conn:
        for model, rows in tables:
            if not rows:
                continue
            conn.execute(insert(model.__table__), rows)
            inserted[model.__tablename__] = len(rows)
    return inserted


def _measure(client, engine, probes, repeats: int):
    from sqlalchemy import event

    counter = {"n": 0}

    def _count(conn, cursor, statement, parameters, context, executemany):
        counter["n"] += 1

    event.listen(engine, "before_cursor_execute", _count)
    results = []
    try:
        for name, url, expect_total in probes:
            timings, status, statements, body = [], None, 0, None
            for _ in range(repeats):
                counter["n"] = 0
                started = time.perf_counter()
                response = client.get(url)
                timings.append((time.perf_counter() - started) * 1000)
                status = response.status_code
                statements = counter["n"]
                body = response.json()
            results.append({
                "name": name, "url": url, "status": status,
                "ms": statistics.median(timings), "statements": statements,
                "body": body, "expect_total": expect_total,
            })
    finally:
        event.remove(engine, "before_cursor_execute", _count)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--alerts", type=int, default=10_000)
    parser.add_argument("--events", type=int, default=1_000)
    parser.add_argument("--incidents", type=int, default=1_000)
    parser.add_argument("--executions", type=int, default=10_000)
    parser.add_argument("--pending", type=int, default=500,
                        help="recommendations left undecided, so the queue has rows")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--keep", action="store_true",
                        help="keep a generated SQLite database instead of deleting it")
    args = parser.parse_args(argv)

    url = _bootstrap_database_url(args.database_url)
    from fastapi.testclient import TestClient

    from app.core.database import engine, settings
    from app.main import app
    from sqlalchemy import text

    print(f"database      : {settings.DATABASE_URL.split('@')[-1]}")
    print(f"driver        : {settings.DATABASE_URL.split('://', 1)[0]}")
    print(f"python        : {platform.python_version()} on {platform.system()} "
          f"{platform.release()}")
    started = time.perf_counter()
    _upgrade_schema()
    counts = {
        "alerts": args.alerts, "events": args.events,
        "incidents": args.incidents, "executions": args.executions,
        "pending": args.pending,
    }
    inserted = _seed(counts)
    print(f"seeded        : " + ", ".join(f"{k}={v}" for k, v in inserted.items())
          + f"  ({time.perf_counter() - started:.1f}s)")
    with engine.connect() as conn:
        if settings.DATABASE_URL.startswith("postgresql"):
            print(f"server        : {conn.execute(text('SHOW server_version')).scalar()}")

    chains = max(1, args.executions // 3)
    probes = [
        ("GET /events", "/api/v1/events?page=1&size=20", args.events),
        ("GET /incidents", "/api/v1/incidents?page=1&size=20", args.incidents),
        ("GET /approvals", "/api/v1/approvals", None),
        ("GET /executions", "/api/v1/executions?page=1&size=20", chains),
        ("GET /dashboard/summary", "/api/v1/dashboard/summary", None),
        ("GET /executions/metrics", "/api/v1/executions/metrics", None),
        ("GET /executions/health", "/api/v1/executions/health", None),
    ]

    with TestClient(app) as client:
        results = _measure(client, engine, probes, args.repeats)

    print()
    print(f"{'endpoint':<24}{'status':>7}{'statements':>12}{'median ms':>12}   paging")
    print("-" * 74)
    failures = []
    for row in results:
        body = row["body"]
        paging = ""
        if isinstance(body, dict) and "total" in body:
            paging = f"total={body['total']} size={len(body.get('items', []))}"
            if row["expect_total"] is not None and body["total"] != row["expect_total"]:
                failures.append(
                    f"{row['name']}: total={body['total']} expected {row['expect_total']}")
            if len(body.get("items", [])) > 20:
                failures.append(f"{row['name']}: page returned more rows than requested")
        elif isinstance(body, list):
            paging = f"rows={len(body)}"
        print(f"{row['name']:<24}{row['status']:>7}{row['statements']:>12}"
              f"{row['ms']:>12.1f}   {paging}")
        if row["status"] != 200:
            failures.append(f"{row['name']}: HTTP {row['status']}")
        if row["statements"] > MAX_STATEMENTS_PER_REQUEST:
            failures.append(
                f"{row['name']}: {row['statements']} statements "
                f"(bound {MAX_STATEMENTS_PER_REQUEST})")
        if row["ms"] > MAX_SECONDS_PER_REQUEST * 1000:
            failures.append(f"{row['name']}: {row['ms']:.0f} ms "
                            f"(bound {MAX_SECONDS_PER_REQUEST * 1000:.0f} ms)")

    print()
    if failures:
        print("FAIL")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(f"PASS  every read path answered 200 with a bounded statement count "
          f"(<= {MAX_STATEMENTS_PER_REQUEST}) and no per-row query growth")
    if args.keep:
        print(f"kept database: {url}")
    else:
        database_file = url.removeprefix("sqlite:///")
        if url.startswith("sqlite:///") and Path(database_file).exists():
            engine.dispose()
            try:
                Path(database_file).unlink()
            except OSError:
                print(f"note: could not remove {database_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
