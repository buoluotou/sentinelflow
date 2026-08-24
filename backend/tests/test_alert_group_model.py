"""Phase 1 Step 4.1: AlertGroup data model tests."""

from datetime import datetime, timezone

from app.models import Alert, AlertGroup

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


def test_alert_group_creation(db_session):
    group = _make_group()
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)

    assert group.id is not None
    assert group.fingerprint == FINGERPRINT_A
    assert group.alert_count == 1
    assert group.status == "open"
    assert group.created_at is not None
    assert group.updated_at is not None


def test_alert_links_to_group(db_session):
    group = _make_group()
    # Assign the object (not group.id): the id only exists after flush, the
    # ORM fills the foreign key automatically.
    alert = Alert(source="simulator", event_type="ssh_failed_login", alert_group=group)
    db_session.add_all([group, alert])
    db_session.commit()
    db_session.refresh(alert)
    db_session.refresh(group)

    assert alert.alert_group_id == group.id
    assert alert.alert_group.fingerprint == FINGERPRINT_A
    assert [a.id for a in group.alerts] == [alert.id]


def test_alert_without_group_still_works(db_session):
    alert = Alert(source="simulator", event_type="ssh_failed_login")
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    assert alert.alert_group_id is None
    assert alert.alert_group is None


def test_duplicate_fingerprint_allowed(db_session):
    """After the aggregation window expires, the same fingerprint must be able
    to open a brand new group — so fingerprint is indexed but NOT unique."""
    db_session.add_all([_make_group(), _make_group()])
    db_session.commit()

    assert db_session.query(AlertGroup).count() == 2
    assert db_session.query(AlertGroup).filter_by(fingerprint=FINGERPRINT_A).count() == 2
    assert db_session.query(AlertGroup).filter_by(fingerprint=FINGERPRINT_B).count() == 0
