"""Phase 1 Step 4.3: DeduplicationEngine tests."""

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import Alert, AlertGroup
from app.services.deduplication.engine import DeduplicationEngine
from app.services.normalization.models import (
    ActorInfo,
    AssetInfo,
    Category,
    NormalizedAlert,
)
from app.services.normalization.normalizer import NormalizationEngine

BASE_TIME = datetime(2026, 8, 24, 10, 0, 0, tzinfo=timezone.utc)


def _make_normalized(actor_ip: str = "10.10.10.5", when: datetime = BASE_TIME):
    """Normalized SSH-failed-login alert; `when` controls the event time."""
    return NormalizedAlert(
        source="simulator",
        event_type="ssh_failed_login",
        category=Category.AUTHENTICATION,
        title="SSH failed login",
        asset=AssetInfo(hostname="server01", ip="192.168.1.10"),
        actor=ActorInfo(ip=actor_ip, user="root"),
        raw_event={"timestamp": when.isoformat().replace("+00:00", "Z")},
    )


def _process(db: Session, engine: DeduplicationEngine, normalized):
    alert_create = NormalizationEngine.to_alert_create(normalized)
    return engine.process(db, normalized, alert_create)


def test_case1_first_alert_creates_one_group(db_session):
    engine = DeduplicationEngine()

    result = _process(db_session, engine, _make_normalized())

    assert result.created_group is True
    assert db_session.query(AlertGroup).count() == 1
    assert db_session.query(Alert).count() == 1
    assert result.group.alert_count == 1


def test_case2_100_duplicates_one_group_100_evidence_rows(db_session):
    engine = DeduplicationEngine()

    for i in range(100):
        # spread inside the 5 min window; timestamp does NOT affect fingerprint
        _process(
            db_session, engine, _make_normalized(when=BASE_TIME + timedelta(seconds=i))
        )

    assert db_session.query(Alert).count() == 100
    groups = db_session.query(AlertGroup).all()
    assert len(groups) == 1
    assert groups[0].alert_count == 100
    assert len(groups[0].alerts) == 100
    # every evidence alert keeps its raw event
    assert all(len(alert.events) == 1 for alert in groups[0].alerts)


def test_case3_different_actors_different_groups(db_session):
    engine = DeduplicationEngine()

    r1 = _process(db_session, engine, _make_normalized(actor_ip="10.10.10.5"))
    r2 = _process(db_session, engine, _make_normalized(actor_ip="10.10.10.6"))

    assert r1.created_group is True
    assert r2.created_group is True
    assert r1.group.id != r2.group.id
    assert db_session.query(AlertGroup).count() == 2
    assert db_session.query(Alert).count() == 2


def test_case4_window_expiry_opens_new_group(db_session):
    engine = DeduplicationEngine()  # default window: 300s

    r1 = _process(db_session, engine, _make_normalized(when=BASE_TIME))
    # 6 minutes later: outside the window -> new group, same fingerprint
    r2 = _process(
        db_session, engine, _make_normalized(when=BASE_TIME + timedelta(minutes=6))
    )
    # 1 minute after the second one: back inside the window of group 2
    r3 = _process(
        db_session, engine, _make_normalized(when=BASE_TIME + timedelta(minutes=7))
    )

    assert r1.created_group is True
    assert r2.created_group is True
    assert r3.created_group is False
    assert r2.group.id != r1.group.id
    assert r3.group.id == r2.group.id
    # fingerprint identifies the event kind, not the group
    assert r1.group.fingerprint == r2.group.fingerprint

    groups = db_session.query(AlertGroup).order_by(AlertGroup.first_seen).all()
    assert len(groups) == 2
    assert [g.alert_count for g in groups] == [1, 2]


def test_window_boundary_is_inclusive(db_session):
    engine = DeduplicationEngine()

    _process(db_session, engine, _make_normalized(when=BASE_TIME))
    # exactly 300s later: rule is inclusive (elapsed <= window)
    result = _process(
        db_session, engine, _make_normalized(when=BASE_TIME + timedelta(seconds=300))
    )

    assert result.created_group is False
    assert db_session.query(AlertGroup).count() == 1
    assert result.group.alert_count == 2
