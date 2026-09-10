"""RC2 / H-1 — Risk <-> Incident transaction atomicity (production debt fix).

The pre-RC2 pipeline durably SPLIT at risk recalculation:
``RiskService.recalculate`` committed internally, so a failure while
auto-opening the SOC case left exactly the debt's failure mode —
"risk updated / case missing" — and a caller rollback could never take the
risk update back. RC2 makes the deduplication engine the ONE pipeline
transaction boundary: alert evidence + EventRisk snapshot + automatic Incident
commit or roll back TOGETHER, while the frozen one-case-per-event invariant
(``uq_incidents_alert_group_id``) stays enforced — including under a race
(the loser's nested SAVEPOINT is a benign no-op that keeps its transaction
valid).

Frozen business rules preserved: score >= 70 auto-creates a case; the incident
snapshot COPIES the risk score; repeated alerts never duplicate the case.

PostgreSQL-specific transaction/race proofs live in
``test_risk_incident_atomicity_postgres.py`` (``-m external``, dedicated DB).
"""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.services.risk.service import service as risk_service
from app.models import Alert, AlertGroup, EventRisk, Incident
from app.schemas.alert import AlertCreate, Severity
from app.services.deduplication.engine import DeduplicationEngine
from app.services.deduplication.fingerprint import FingerprintGenerator
from app.services.incidents.service import auto_create_from_risk
from app.services.normalization.models import (
    ActorInfo,
    AssetInfo,
    Category,
    NormalizedAlert,
)
from app.services.normalization.normalizer import NormalizationEngine

BASE_TIME = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)


def _normalized(when: datetime = BASE_TIME) -> NormalizedAlert:
    return NormalizedAlert(
        source="simulator",
        event_type="ssh_failed_login",
        category=Category.AUTHENTICATION,
        title="SSH failed login",
        asset=AssetInfo(hostname="server01", ip="192.168.1.10"),
        actor=ActorInfo(ip="10.10.10.5", user="root"),
        raw_event={"timestamp": when.isoformat().replace("+00:00", "Z")},
    )


def _crossing_alert_create(when: datetime = BASE_TIME) -> AlertCreate:
    """One alert whose severity (critical = 70) crosses the auto-case threshold."""
    return AlertCreate(
        source="simulator",
        event_type="ssh_failed_login",
        severity=Severity.CRITICAL,
        timestamp=when,
        title="SSH failed login",
    )


def _process(db, engine: DeduplicationEngine, when: datetime = BASE_TIME):
    return engine.process(
        db, _normalized(when), _crossing_alert_create(when)
    )


def _assert_nothing_persisted(db) -> None:
    assert db.query(AlertGroup).count() == 0
    assert db.query(Alert).count() == 0
    assert db.query(EventRisk).count() == 0
    assert db.query(Incident).count() == 0


# --------------------------------------------------------------------------
# Normal commit path (frozen rules preserved)
# --------------------------------------------------------------------------
def test_normal_pipeline_commits_alert_risk_and_case_together(db_session):
    engine = DeduplicationEngine()

    result = _process(db_session, engine)

    risk = result.group.risk
    incident = result.group.incident
    assert risk is not None and risk.score >= 70
    assert incident is not None
    # frozen rule: the case COPIES the risk score at creation (snapshot).
    assert incident.risk_score == risk.score
    assert incident.status == "open"
    assert db_session.query(Incident).count() == 1
    assert db_session.query(EventRisk).count() == 1
    assert db_session.query(Alert).count() == 1


def test_repeated_crossing_alerts_never_duplicate_the_case(db_session):
    engine = DeduplicationEngine()

    for i in range(3):
        _process(db_session, engine, when=BASE_TIME + timedelta(seconds=i))

    assert db_session.query(Incident).count() == 1
    assert db_session.query(EventRisk).count() == 1
    assert db_session.query(Alert).count() == 3


# --------------------------------------------------------------------------
# H-1 regression: failures roll the WHOLE unit back (no partial commit)
# --------------------------------------------------------------------------
def test_incident_insert_failure_rolls_back_the_risk_update(db_session, monkeypatch):
    """THE H-1 regression: pre-RC2 the risk update was already COMMITTED when
    the case insert failed — "risk updated, incident missing". Now the API
    layer's rollback (session close on the error) erases the entire unit."""

    def _boom(db, group_id):  # noqa: ANN001
        raise RuntimeError("incident insert failed")

    monkeypatch.setattr("app.services.incidents.service.create_incident", _boom)
    engine = DeduplicationEngine()

    with pytest.raises(RuntimeError):
        _process(db_session, engine)

    db_session.rollback()  # what the API layer does on the propagated error
    _assert_nothing_persisted(db_session)


def test_risk_failure_rolls_back_the_alert_and_group_too(db_session, monkeypatch):
    class _BrokenRiskEngine:
        def calculate(self, group, alerts):  # noqa: ANN001
            raise RuntimeError("risk engine failed")

    monkeypatch.setattr(
        risk_service, "_engine", _BrokenRiskEngine()
    )
    engine = DeduplicationEngine()

    with pytest.raises(RuntimeError):
        _process(db_session, engine)

    db_session.rollback()
    _assert_nothing_persisted(db_session)


def test_recalculate_never_commits_on_its_own(db_session):
    """Direct proof of the fix: pre-RC2 ``recalculate`` committed internally;
    now a caller rollback erases the risk snapshot entirely."""

    normalized = _normalized()
    group = AlertGroup(
        fingerprint=FingerprintGenerator.generate(normalized),
        title="SSH failed login",
        category="authentication",
        severity="critical",
        alert_count=1,
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
    )
    db_session.add(group)
    db_session.flush()

    risk = risk_service.recalculate(db_session, group)
    assert risk is not None and risk.score >= 70

    db_session.rollback()
    assert db_session.query(EventRisk).count() == 0
    assert db_session.query(AlertGroup).count() == 0


def test_all_pipeline_writes_roll_back_as_one_unit(db_session):
    """The caller owns the boundary: with the pipeline steps pending in ONE
    transaction, a rollback discards group + alert + risk + case together."""

    normalized = _normalized()
    group = AlertGroup(
        fingerprint=FingerprintGenerator.generate(normalized),
        title="SSH failed login",
        category="authentication",
        severity="critical",
        alert_count=1,
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
    )
    db_session.add(group)
    db_session.flush()
    db_session.add(
        Alert(
            source="simulator",
            event_type="ssh_failed_login",
            severity="critical",
            status="open",
            title="SSH failed login",
            source_ip="10.0.0.9",
            first_seen_at=BASE_TIME,
            last_seen_at=BASE_TIME,
            event_count=1,
            alert_group=group,
        )
    )
    db_session.flush()

    risk = risk_service.recalculate(db_session, group)
    assert risk.score >= 70
    incident = auto_create_from_risk(db_session, group)
    assert incident is not None

    db_session.rollback()
    _assert_nothing_persisted(db_session)


# --------------------------------------------------------------------------
# Duplicate race: the constraint + savepoint keep the transaction valid
# --------------------------------------------------------------------------
def test_duplicate_case_race_is_a_benign_noop(db_session, monkeypatch):
    """A concurrent worker wins the case (simulated by a unique violation on
    the one-case-per-event constraint). The loser's savepoint rolls back to a
    no-op and its alert + risk still commit — no 500, no partial state."""

    def _duplicate(db, group_id):  # noqa: ANN001
        raise IntegrityError(
            "INSERT INTO incidents ...",
            {},
            Exception("UNIQUE constraint failed: incidents.alert_group_id"),
        )

    monkeypatch.setattr("app.services.incidents.service.create_incident", _duplicate)
    engine = DeduplicationEngine()

    result = _process(db_session, engine)  # must NOT raise

    assert result.group.risk is not None and result.group.risk.score >= 70
    assert result.group.incident is None  # the (simulated) winner owns the case
    assert db_session.query(Incident).count() == 0
    # the transaction stayed valid: the alert + risk committed normally.
    assert db_session.query(EventRisk).count() == 1
    assert db_session.query(Alert).count() == 1


def test_non_unique_incident_integrity_error_still_propagates(db_session, monkeypatch):
    """Only the one-case-per-event conflict is benign; any other integrity
    failure rolls the WHOLE unit back."""

    def _other(db, group_id):  # noqa: ANN001
        raise IntegrityError(
            "INSERT INTO incidents ...", {}, Exception("some other constraint")
        )

    monkeypatch.setattr("app.services.incidents.service.create_incident", _other)
    engine = DeduplicationEngine()

    with pytest.raises(IntegrityError):
        _process(db_session, engine)

    db_session.rollback()
    _assert_nothing_persisted(db_session)
