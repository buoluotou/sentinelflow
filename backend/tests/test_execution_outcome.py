"""Phase 3.4.1: execution_outcome data-model freeze tests.

Locks the frozen shape of ExecutionOutcome before Migration/Reconciliation/
Webhook land (design doc docs/design/phase3.4-execution-outcome-lifecycle.md,
adjudications O1-O5):

- vocabulary: exactly five outcome words (O1) + exactly two ingress sources;
  dispatch-layer words (succeeded/failed/...) are NOT legal outcome words —
  the two vocabularies never cross-contaminate (D3.4-04)
- independent fact layer: plain execution_id column (no FK), no unique
  index — multiple facts per execution form an append-only time series
  (D3.4-06), derivation orders by observed_at (O2)
- O5 / D3.4-09: outcome facts coexist with ANY dispatch state and never
  rewrite execution_log history (dispatch=failed + manual
  confirmed_success is recordable; the dispatch rows stay untouched)
- append-only audit fact: no updated_at, created_at is server-stamped
- recorder identity + observed_at + detail are mandatory fact fields

Model shape + static migration-0010 shape freeze ONLY — no service, no
API, no webhook, no frontend (3.4.1 gate; 3.4.2-3.4.6 stay closed until
this is accepted).
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.models import (
    CONFIRMED_OUTCOME_STATUSES,
    EXECUTION_DECISIONS,
    OUTCOME_SOURCES,
    OUTCOME_STATUSES,
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    ExecutionLog,
    ExecutionOutcome,
)


def _fact(db_session, **overrides) -> ExecutionOutcome:
    """One outcome fact; overrides drive every attack."""
    defaults = dict(
        execution_id=uuid.uuid4(),
        outcome_status="pending",
        source="webhook",
        operator="adapter:mock",
        observed_at=datetime.now(timezone.utc),
        detail={"raw": "workflow_running"},
    )
    defaults.update(overrides)
    row = ExecutionOutcome(**defaults)
    db_session.add(row)
    return row


def _seed_approved(db_session) -> AIResponseApproval:
    """One committed event + recommendation + approved decision."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint=uuid.uuid4().hex,
        title="SSH Brute Force on edge-gateway",
        category="authentication",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db_session.add(group)
    db_session.flush()
    record = AIResponseRecommendation(
        alert_group=group,
        provider="mock",
        model="mock-deterministic",
        overall_rationale="[mock] guidance",
        recommendations=[
            {"action": "block_source_ip", "target": "203.0.113.7", "rationale": "abuse"}
        ],
        confidence=0.7,
    )
    db_session.add(record)
    db_session.flush()
    approval = AIResponseApproval(
        recommendation_id=record.id,
        status="approved",
        reviewer="analyst-1",
        reviewed_at=now,
    )
    db_session.add(approval)
    db_session.commit()
    return approval


class TestOutcomeVocabulary:
    def test_outcome_statuses_frozen_five_words(self):
        assert OUTCOME_STATUSES == frozenset(
            {
                "unknown",
                "pending",
                "confirmed_success",
                "confirmed_failure",
                "reconciliation_failed",
            }
        )

    def test_outcome_sources_frozen_two_words(self):
        assert OUTCOME_SOURCES == frozenset({"webhook", "manual_reconcile"})

    def test_confirmed_subset_is_exactly_the_two_verdicts(self):
        assert CONFIRMED_OUTCOME_STATUSES == frozenset(
            {"confirmed_success", "confirmed_failure"}
        )
        assert CONFIRMED_OUTCOME_STATUSES < OUTCOME_STATUSES

    def test_outcome_vocabulary_disjoint_from_dispatch_vocabulary(self):
        # D3.4-04: the two fact layers never share a word — `succeeded`
        # and `failed` belong to dispatch ONLY.
        assert not (OUTCOME_STATUSES & EXECUTION_DECISIONS)

    def test_outcome_sources_disjoint_from_dispatch_directions(self):
        # A source word is an ingress channel, never a dispatch direction.
        assert not (OUTCOME_SOURCES & {"execute", "compensate"})


class TestTableShape:
    def test_table_name(self):
        assert ExecutionOutcome.__tablename__ == "execution_outcome"

    def test_exact_column_set(self):
        assert set(ExecutionOutcome.__table__.columns.keys()) == {
            "id",
            "execution_id",
            "outcome_status",
            "source",
            "operator",
            "observed_at",
            "detail",
            "created_at",
        }

    def test_no_updated_at_append_only(self):
        # D3.4-06: append-only facts never update.
        assert "updated_at" not in ExecutionOutcome.__table__.columns

    def test_id_is_uuid_primary_key(self):
        column = ExecutionOutcome.__table__.columns["id"]
        assert column.primary_key is True

    def test_execution_id_plain_column_not_fk(self):
        # Independent fact layer: read-only link to the chain key, never
        # an FK into execution_log (precedent: compensates_execution_id).
        column = ExecutionOutcome.__table__.columns["execution_id"]
        assert not column.foreign_keys
        assert column.nullable is False
        assert column.index is True

    def test_no_unique_index_anywhere(self):
        # The time series IS the audit trail — uniqueness would forbid
        # late/reordered facts (O2: append everything, derive latest).
        assert not any(index.unique for index in ExecutionOutcome.__table__.indexes)

    def test_derivation_composite_index_exists(self):
        index = next(
            index
            for index in ExecutionOutcome.__table__.indexes
            if index.name == "ix_execution_outcome_execution_id_observed_at"
        )
        assert [column.name for column in index.columns] == [
            "execution_id",
            "observed_at",
        ]

    def test_created_at_server_default(self):
        column = ExecutionOutcome.__table__.columns["created_at"]
        assert column.server_default is not None
        assert "CURRENT_TIMESTAMP" in str(column.server_default.arg)

    def test_mandatory_fact_fields(self):
        for name in ("outcome_status", "source", "operator", "observed_at", "detail"):
            assert ExecutionOutcome.__table__.columns[name].nullable is False, name


class TestCheckConstraints:
    @pytest.mark.parametrize("status", sorted(OUTCOME_STATUSES))
    def test_each_frozen_status_accepted(self, db_session, status):
        _fact(db_session, outcome_status=status)
        db_session.commit()

    @pytest.mark.parametrize(
        "status", ["reconciled", "success", "failure", "ok", "", "CONFIRMED_SUCCESS"]
    )
    def test_unknown_status_rejected(self, db_session, status):
        _fact(db_session, outcome_status=status)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()

    @pytest.mark.parametrize("status", sorted(EXECUTION_DECISIONS))
    def test_dispatch_words_rejected_as_outcome_status(self, db_session, status):
        # D3.4-04 at storage level: `succeeded` / `failed` / `requested`
        # and every other dispatch decision can never enter the outcome
        # layer — the CHECK is the last line against vocabulary leakage.
        _fact(db_session, outcome_status=status)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()

    @pytest.mark.parametrize("source", sorted(OUTCOME_SOURCES))
    def test_each_frozen_source_accepted(self, db_session, source):
        _fact(db_session, source=source)
        db_session.commit()

    @pytest.mark.parametrize(
        "source", ["api", "auto", "scheduler", "polling", "", "WEBHOOK"]
    )
    def test_unknown_source_rejected(self, db_session, source):
        # No third ingress channel exists (D3.4-03: no background polling).
        _fact(db_session, source=source)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_missing_operator_rejected(self, db_session):
        _fact(db_session, operator=None)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_missing_observed_at_rejected(self, db_session):
        _fact(db_session, observed_at=None)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()


class TestAppendOnlyTimeSeries:
    def test_multiple_facts_per_execution_allowed(self, db_session):
        execution_id = uuid.uuid4()
        base = datetime.now(timezone.utc)
        for offset, status in enumerate(
            ["pending", "pending", "confirmed_success"], start=1
        ):
            _fact(
                db_session,
                execution_id=execution_id,
                outcome_status=status,
                observed_at=base + timedelta(minutes=offset),
            )
        db_session.commit()
        rows = (
            db_session.query(ExecutionOutcome)
            .filter_by(execution_id=execution_id)
            .all()
        )
        assert len(rows) == 3

    def test_derivation_orders_by_observed_at_not_insert_order(self, db_session):
        # O2: late facts are appended; the latest OBSERVATION wins even
        # when it arrives out of order (insert order deliberately mixed).
        execution_id = uuid.uuid4()
        base = datetime.now(timezone.utc)
        for minutes, status in [(30, "confirmed_success"), (5, "pending"), (60, "confirmed_failure")]:
            _fact(
                db_session,
                execution_id=execution_id,
                outcome_status=status,
                observed_at=base + timedelta(minutes=minutes),
            )
        db_session.commit()
        latest = (
            db_session.query(ExecutionOutcome)
            .filter_by(execution_id=execution_id)
            .order_by(ExecutionOutcome.observed_at.desc())
            .first()
        )
        assert latest.outcome_status == "confirmed_failure"

    def test_equal_observed_at_facts_both_persist(self, db_session):
        # The model never rejects a fact; tie-breaking is a derivation
        # concern (3.4.2), not a storage constraint.
        execution_id = uuid.uuid4()
        moment = datetime.now(timezone.utc)
        _fact(db_session, execution_id=execution_id, observed_at=moment)
        _fact(
            db_session,
            execution_id=execution_id,
            outcome_status="confirmed_success",
            observed_at=moment,
        )
        db_session.commit()
        assert (
            db_session.query(ExecutionOutcome)
            .filter_by(execution_id=execution_id)
            .count()
            == 2
        )

    def test_detail_json_roundtrip(self, db_session):
        detail = {"raw_status": "workflow_complete", "mapping": "done->confirmed_success"}
        row = _fact(db_session, detail=detail)
        db_session.commit()
        fetched = db_session.get(ExecutionOutcome, row.id)
        assert fetched.detail == detail

    def test_detail_defaults_to_empty_dict(self, db_session):
        row = ExecutionOutcome(
            execution_id=uuid.uuid4(),
            outcome_status="unknown",
            source="manual_reconcile",
            operator="ops-1",
            observed_at=datetime.now(timezone.utc),
        )
        db_session.add(row)
        db_session.commit()
        assert row.detail == {}


class TestLayerIndependence:
    """O5 / D3.4-09: Outcome records facts, Dispatch history stays intact."""

    def test_outcome_fact_needs_no_dispatch_row(self, db_session):
        # The Outcome layer is independent: a fact about an execution the
        # dispatch log has never seen is storable (the reconciliation
        # contract decides admission, not the storage layer).
        row = _fact(db_session, outcome_status="confirmed_success")
        db_session.commit()
        assert db_session.get(ExecutionOutcome, row.id) is not None

    def test_dispatch_failed_plus_manual_confirmed_success_coexist(self, db_session):
        # The O5 inconsistency scenario: dispatch says failed, the outside
        # world later says the effect happened. The fact is recordable...
        approval = _seed_approved(db_session)
        execution_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        for decision in ("requested", "failed"):
            db_session.add(
                ExecutionLog(
                    execution_id=execution_id,
                    approval_id=approval.id,
                    decision=decision,
                    direction="execute",
                    action="block_source_ip",
                    target="203.0.113.7",
                    operator="ops-1",
                    detail={},
                    created_at=now,
                )
            )
        db_session.commit()
        _fact(
            db_session,
            execution_id=execution_id,
            outcome_status="confirmed_success",
            source="manual_reconcile",
            operator="ops-1",
            observed_at=now + timedelta(minutes=10),
            detail={"evidence": "firewall rule present despite lost response"},
        )
        db_session.commit()
        # ...and the dispatch history is NOT rewritten by the outcome fact.
        dispatch_rows = (
            db_session.query(ExecutionLog)
            .filter_by(execution_id=execution_id)
            .order_by(ExecutionLog.created_at)
            .all()
        )
        assert [row.decision for row in dispatch_rows] == ["requested", "failed"]

    def test_dispatch_succeeded_plus_confirmed_failure_coexist(self, db_session):
        # The canonical legal combination (§4 O5 table): command delivered,
        # effect not achieved — both facts stand side by side.
        approval = _seed_approved(db_session)
        execution_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        db_session.add(
            ExecutionLog(
                execution_id=execution_id,
                approval_id=approval.id,
                decision="succeeded",
                direction="execute",
                action="isolate_host",
                target="host-42",
                operator="ops-1",
                detail={},
                created_at=now,
            )
        )
        db_session.commit()
        _fact(
            db_session,
            execution_id=execution_id,
            outcome_status="confirmed_failure",
            source="webhook",
            operator="adapter:wazuh",
            observed_at=now + timedelta(minutes=5),
        )
        db_session.commit()
        dispatch = (
            db_session.query(ExecutionLog).filter_by(execution_id=execution_id).one()
        )
        outcome = (
            db_session.query(ExecutionOutcome)
            .filter_by(execution_id=execution_id)
            .one()
        )
        assert dispatch.decision == "succeeded"
        assert outcome.outcome_status == "confirmed_failure"


class TestOutcomeMigration:
    """Static link + shape freeze of migration 0010 (runtime round-trip
    base→0009→0010 and 0010→0009→0010 is verified at the 3.4.1 gate via
    alembic on a temp SQLite DB, following the 3.1.2 precedent)."""

    @staticmethod
    def _migration_source() -> str:
        # migrations/ is an Alembic script dir, not an importable package
        # (no __init__.py): read/exec the file directly, as alembic does.
        from pathlib import Path

        path = (
            Path(__file__).resolve().parents[1]
            / "migrations"
            / "versions"
            / "0010_add_execution_outcome.py"
        )
        return path.read_text(encoding="utf-8")

    def test_migration_0010_links_0009(self):
        namespace: dict = {}
        exec(self._migration_source(), namespace)
        assert namespace["revision"] == "0010"
        assert namespace["down_revision"] == "0009"
        assert callable(namespace["upgrade"])
        assert callable(namespace["downgrade"])

    def test_migration_creates_only_execution_outcome(self):
        source = self._migration_source()
        assert 'op.create_table(\n        "execution_outcome"' in source
        # D3.4-05: execution_log is never rebuilt, altered, or renamed.
        assert "execution_log" not in source.replace(
            "execution_log.compensates_execution_id", ""
        ).replace("execution_log's", "").replace("execution_log —", "")

    def test_migration_mirrors_both_check_constraints(self):
        source = self._migration_source()
        assert "ck_execution_outcome_status" in source
        assert "ck_execution_outcome_source" in source
        for word in sorted(OUTCOME_STATUSES):
            assert f"'{word}'" in source
        for word in sorted(OUTCOME_SOURCES):
            assert f"'{word}'" in source

    def test_migration_has_no_foreign_keys(self):
        # Independent fact layer: no FK into execution_log or approvals —
        # the link is a plain chain key and neither table ever deletes.
        assert "ForeignKeyConstraint" not in self._migration_source()

    def test_migration_indexes_are_plain_not_unique(self):
        source = self._migration_source()
        assert "ix_execution_outcome_execution_id_observed_at" in source
        # O2/D3.4-06: the time series must stay appendable — no UNIQUE.
        assert "unique=True" not in source
        assert "CREATE UNIQUE INDEX" not in source

    def test_migration_downgrade_drops_everything_it_created(self):
        source = self._migration_source()
        downgrade = source.split("def downgrade")[1]
        assert 'op.drop_table("execution_outcome")' in downgrade
        assert downgrade.count("op.drop_index") == 2
