"""Phase 1 Step 5.1: EventRisk data model tests."""

from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.models import AlertGroup, EventRisk

FINGERPRINT_A = "a" * 64
FINGERPRINT_B = "b" * 64


def _make_group(fingerprint: str = FINGERPRINT_A) -> AlertGroup:
    now = datetime.now(timezone.utc)
    return AlertGroup(
        fingerprint=fingerprint,
        title="SSH failed login",
        category="authentication",
        severity="medium",
        first_seen=now,
        last_seen=now,
    )


def test_event_risk_creation_defaults(db_session):
    group = _make_group()
    risk = EventRisk(alert_group=group)
    db_session.add_all([group, risk])
    db_session.commit()
    db_session.refresh(risk)

    assert risk.id is not None
    assert risk.alert_group_id == group.id
    assert risk.score == 0
    assert risk.level == "low"
    assert risk.factors is None
    assert risk.created_at is not None
    assert risk.updated_at is not None


def test_event_risk_factors_roundtrip(db_session):
    """factors keeps the explainable, itemized score breakdown (JSONB)."""
    group = _make_group()
    factors = {
        "base": 40,
        "external_source": 20,
        "high_frequency": 30,
        "critical_asset": 10,
    }
    risk = EventRisk(alert_group=group, score=100, level="critical", factors=factors)
    db_session.add_all([group, risk])
    db_session.commit()
    db_session.refresh(risk)

    assert risk.factors == factors
    assert sum(v for v in risk.factors.values()) == risk.score


def test_group_links_to_risk_one_to_one(db_session):
    group = _make_group()
    risk = EventRisk(alert_group=group, score=70, level="medium")
    db_session.add_all([group, risk])
    db_session.commit()
    db_session.refresh(group)

    assert group.risk is not None
    assert group.risk.score == 70

    # Deleting the group cascades to its risk assessment.
    db_session.delete(group)
    db_session.commit()
    assert db_session.query(EventRisk).count() == 0


def test_group_without_risk_still_works(db_session):
    group = _make_group()
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)

    assert group.risk is None


def test_one_current_risk_per_event(db_session):
    """Rescoring must UPDATE the existing row, never insert a second one —
    alert_group_id is unique so "current risk" stays a cheap O(1) join."""
    group = _make_group()
    db_session.add_all([group, EventRisk(alert_group=group, score=40, level="medium")])
    db_session.commit()

    with pytest.raises(IntegrityError):
        db_session.add(EventRisk(alert_group=group, score=85, level="high"))
        db_session.flush()
    db_session.rollback()

    assert db_session.query(EventRisk).count() == 1


def test_distinct_events_each_get_their_own_risk(db_session):
    group_a = _make_group(FINGERPRINT_A)
    group_b = _make_group(FINGERPRINT_B)
    db_session.add_all(
        [
            group_a,
            group_b,
            EventRisk(alert_group=group_a, score=100, level="critical"),
            EventRisk(alert_group=group_b, score=25, level="low"),
        ]
    )
    db_session.commit()

    assert db_session.query(EventRisk).count() == 2
