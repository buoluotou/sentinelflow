"""PostgreSQL-specific Risk <-> Incident atomicity + race proofs (RC2 / H-1).

SQLite serialises writers and the StaticPool harness cannot run two real
transactions, so the TRUE concurrent threshold-crossing race and real MVCC
rollback semantics are certified HERE or stay explicitly UNVERIFIED:

  req A  TWO concurrent crossing alerts for the SAME event: both keep their
         alert + risk update, EXACTLY ONE case is created (the one-case-per-
         event unique constraint + the benign savepoint), and NO request
         fails with an unhandled error.
  req B  incident insert failure on a REAL PostgreSQL transaction: the whole
         unit (group + alert + risk + case) rolls back together — never a
         partial "risk updated / case missing" state.

STATUS — **PostgreSQL UNVERIFIED** until this module runs against a real
PostgreSQL. It is ``@pytest.mark.external`` AND guarded by the dedicated-DB
env var, so a normal ``pytest`` run NEVER touches a database.

SAFETY: ``SENTINELFLOW_PG_TEST_URL`` MUST point at a DEDICATED throwaway
PostgreSQL. ``create_all`` is idempotent; ``_cleanup`` removes ONLY the rows
this test created (scoped by fingerprint).
"""
import os
import threading
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session

from app.core.database import Base
from app.models import Alert, AlertGroup, EventRisk, Incident
from app.schemas.alert import AlertCreate, Severity
from app.services.deduplication.engine import DeduplicationEngine
from app.services.deduplication.fingerprint import FingerprintGenerator
from app.services.normalization.models import (
    ActorInfo,
    AssetInfo,
    Category,
    NormalizedAlert,
)

PG_URL_ENV = "SENTINELFLOW_PG_TEST_URL"
BASE_TIME = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)


def _pg_engine():
    url = os.environ.get(PG_URL_ENV, "")
    if not url:
        pytest.skip(
            "LAB BLOCKED: no dedicated PostgreSQL configured "
            f"({PG_URL_ENV} unset) — the true H-1 concurrent threshold-crossing "
            "race and the MVCC rollback semantics stay explicitly UNVERIFIED."
        )
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    return engine


def _normalized() -> NormalizedAlert:
    return NormalizedAlert(
        source="simulator",
        event_type="ssh_failed_login",
        category=Category.AUTHENTICATION,
        title="SSH failed login",
        asset=AssetInfo(hostname="server01", ip="192.168.1.10"),
        actor=ActorInfo(ip="10.10.10.5", user="root"),
        raw_event={"timestamp": BASE_TIME.isoformat().replace("+00:00", "Z")},
    )


def _alert_create() -> AlertCreate:
    return AlertCreate(
        source="simulator",
        event_type="ssh_failed_login",
        severity=Severity.CRITICAL,
        timestamp=BASE_TIME,
        title="SSH failed login",
    )


def _seed_below_then_crossing_group(engine) -> str:
    """Seed + COMMIT a group that is BELOW the threshold by one alert (severity
    high 50 + frequency band (21..) +20 = 70 at the next alert), with its risk
    snapshot — so the concurrent alerts race ONLY on the incident, never on
    group/risk creation."""
    fingerprint = FingerprintGenerator.generate(_normalized())
    now = datetime.now(timezone.utc)
    with Session(engine) as session:
        group = AlertGroup(
            fingerprint=fingerprint,
            title="SSH failed login",
            category="authentication",
            severity="high",
            alert_count=50,
            first_seen=now,
            last_seen=now,
        )
        session.add(group)
        session.flush()
        session.add(
            EventRisk(alert_group=group, score=60, level="medium", factors=[])
        )
        session.commit()
    return fingerprint


def _cleanup(engine, fingerprint: str) -> None:
    """Targeted, FK-safe removal of ONLY this test's rows (scoped by fingerprint)."""
    with Session(engine) as session:
        groups = session.scalars(
            select(AlertGroup).where(AlertGroup.fingerprint == fingerprint)
        ).all()
        for group in groups:
            session.execute(delete(Alert).where(Alert.alert_group_id == group.id))
            session.execute(delete(AlertGroup).where(AlertGroup.id == group.id))
        session.commit()


@pytest.mark.external
def test_concurrent_crossing_alerts_create_exactly_one_case():
    """req A — TRUE parallel crossing alerts for one event under PostgreSQL
    MVCC: both alerts land, the risk updates, and EXACTLY ONE case exists —
    zero unhandled errors (the loser side of any incident race is a benign,
    transaction-preserving no-op)."""
    engine = _pg_engine()
    fingerprint = _seed_below_then_crossing_group(engine)
    errors: list[str] = []
    lock = threading.Lock()

    def _race():
        session = Session(engine)
        try:
            DeduplicationEngine().process(session, _normalized(), _alert_create())
        except Exception as exc:  # noqa: BLE001 — recorded and asserted below
            with lock:
                errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            session.close()

    threads = [threading.Thread(target=_race) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    try:
        assert errors == []
        with Session(engine) as reader:
            group = reader.scalars(
                select(AlertGroup).where(AlertGroup.fingerprint == fingerprint)
            ).one()
            alerts = reader.scalars(
                select(Alert).where(Alert.alert_group_id == group.id)
            ).all()
            incidents = reader.scalars(
                select(Incident).where(Incident.alert_group_id == group.id)
            ).all()
            risk = reader.scalars(
                select(EventRisk).where(EventRisk.alert_group_id == group.id)
            ).one()
            assert len(alerts) == 2       # both concurrent alerts landed
            assert len(incidents) == 1    # exactly one case — never duplicated
            assert risk.score >= 70
            assert incidents[0].risk_score >= 70  # snapshot >= threshold
    finally:
        _cleanup(engine, fingerprint)
        engine.dispose()


@pytest.mark.external
def test_incident_failure_rolls_back_the_whole_unit_on_postgres(monkeypatch):
    """req B — on a REAL PostgreSQL transaction, an incident-insert failure
    rolls back the alert, the group and the risk update TOGETHER: no partial
    "risk updated / case missing" state can survive."""
    engine = _pg_engine()
    normalized = _normalized()
    fingerprint = FingerprintGenerator.generate(normalized)

    def _boom(db, group_id):  # noqa: ANN001
        raise RuntimeError("incident insert failed")

    monkeypatch.setattr("app.services.incidents.service.create_incident", _boom)
    session = Session(engine)
    try:
        with pytest.raises(RuntimeError):
            DeduplicationEngine().process(session, normalized, _alert_create())
        session.rollback()  # what the API layer's session close does on error
        with Session(engine) as reader:
            assert (
                reader.query(AlertGroup)
                .filter(AlertGroup.fingerprint == fingerprint)
                .count()
                == 0
            )
            assert (
                reader.query(Alert)
                .join(AlertGroup, Alert.alert_group_id == AlertGroup.id)
                .filter(AlertGroup.fingerprint == fingerprint)
                .count()
                == 0
            )
            assert (
                reader.query(EventRisk)
                .join(AlertGroup, EventRisk.alert_group_id == AlertGroup.id)
                .filter(AlertGroup.fingerprint == fingerprint)
                .count()
                == 0
            )
            assert (
                reader.query(Incident)
                .join(AlertGroup, Incident.alert_group_id == AlertGroup.id)
                .filter(AlertGroup.fingerprint == fingerprint)
                .count()
                == 0
            )
    finally:
        session.close()
        _cleanup(engine, fingerprint)
        engine.dispose()
