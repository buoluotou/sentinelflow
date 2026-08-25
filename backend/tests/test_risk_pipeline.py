"""Phase 1 Step 5.3: Risk pipeline integration tests.

Every deduplication pass must leave the event with an up-to-date, single
EventRisk snapshot (create on first scoring, update in place afterwards).
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import EventRisk
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


def _as_utc(dt: datetime) -> datetime:
    """SQLite hands back naive datetimes; treat them as UTC for comparison."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _factor_scores(risk: EventRisk) -> dict[str, int]:
    return {f["name"]: f["score"] for f in risk.factors}


def test_first_alert_auto_creates_event_risk(db_session):
    engine = DeduplicationEngine()

    result = _process(db_session, engine, _make_normalized())

    assert db_session.query(EventRisk).count() == 1
    risk = result.group.risk
    assert risk is not None
    assert risk.alert_group_id == result.group.id
    # medium base 30, count 1 (+0), private source (+0)
    assert risk.score == 30
    assert risk.level == "low"
    assert _factor_scores(risk) == {
        "severity": 30,
        "frequency": 0,
        "public_source": 0,
    }
    assert risk.created_at is not None
    assert risk.updated_at is not None


def test_repeated_alerts_update_risk_in_place(db_session):
    engine = DeduplicationEngine()

    for i in range(100):
        _process(
            db_session,
            engine,
            _make_normalized(when=BASE_TIME + timedelta(seconds=i)),
        )

    # never a second row — the snapshot is updated, not duplicated
    risks = db_session.query(EventRisk).all()
    assert len(risks) == 1
    risk = risks[0]
    assert risk.alert_group.alert_count == 100
    # 30 severity + 30 frequency (100 alerts) + 0 private source
    assert risk.score == 60
    assert risk.level == "medium"


def test_frequency_threshold_crossing_changes_score(db_session):
    engine = DeduplicationEngine()

    for i in range(5):
        _process(
            db_session,
            engine,
            _make_normalized(when=BASE_TIME + timedelta(seconds=i)),
        )
    risk = db_session.query(EventRisk).one()
    risk_id = risk.id
    assert risk.score == 30  # count 5: no frequency bonus yet

    # 6th alert crosses the 6-20 band (+10)
    _process(db_session, engine, _make_normalized(when=BASE_TIME + timedelta(seconds=5)))
    risk = db_session.query(EventRisk).one()
    assert risk.id == risk_id  # same row, updated in place
    assert risk.score == 40


def test_updated_at_refreshed_on_recalculate(db_session):
    engine = DeduplicationEngine()

    _process(db_session, engine, _make_normalized())
    first_updated = _as_utc(db_session.query(EventRisk).one().updated_at)

    _process(db_session, engine, _make_normalized(when=BASE_TIME + timedelta(seconds=1)))
    second_updated = _as_utc(db_session.query(EventRisk).one().updated_at)

    assert second_updated >= first_updated
    assert db_session.query(EventRisk).count() == 1


def test_no_valid_public_ip_means_no_public_bonus(db_session):
    """Only private sources in the group -> public factor stays 0.

    (Invalid/unparsable IPs are covered at engine level in test_risk_engine;
    here the pipeline simply must not invent a bonus.)
    """
    engine = DeduplicationEngine()

    _process(db_session, engine, _make_normalized(actor_ip="192.168.1.50"))
    _process(
        db_session,
        engine,
        _make_normalized(actor_ip="192.168.1.50", when=BASE_TIME + timedelta(seconds=1)),
    )

    risk = db_session.query(EventRisk).one()
    assert _factor_scores(risk)["public_source"] == 0
    assert risk.score == 30


def test_public_source_bonus_persists_and_applies_once_via_pipeline(db_session):
    """A public actor earns +20 exactly once, stable across recalculations.

    Changing the actor IP opens a NEW group (actor is part of the
    fingerprint), so the multi-public-IP "applied once" semantics are
    covered at engine level (test_risk_engine::test_case3b).
    """
    engine = DeduplicationEngine()

    for i in range(5):
        _process(
            db_session,
            engine,
            _make_normalized(actor_ip="8.8.8.8", when=BASE_TIME + timedelta(seconds=i)),
        )

    risk = db_session.query(EventRisk).one()
    # count 5: severity 30 + frequency 0 + public 20 (once)
    assert _factor_scores(risk)["public_source"] == 20
    assert risk.score == 50
