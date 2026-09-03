"""Phase 3.4.2: pure outcome derivation tests.

The whole later outcome stack (reconcile contract, webhook ingest, API,
metrics UI) derives the current outcome state through these functions, so
this suite is deliberately hard: the five-word vocabulary freeze, the
dispatch/outcome vocabulary isolation (O5 / D3.4-04), deterministic
``observed_at DESC, id DESC`` selection, out-of-order delivery, callback
replay, the empty-fact ``unknown`` sentinel, and a structural + DB-backed
proof that derivation is PURE — no execution_log write, no fact mutation,
no session side effect, no invented verdict.

Most tests are DB-free on purpose: derive_outcome_state /
latest_observation must be PURE (no INSERT/UPDATE/DELETE/flush/commit) and
lightweight stubs prove it — the exact discipline of
tests/test_execution_state.py. A final class exercises the same functions
against a real in-memory session to prove no side effects on persisted
execution_outcome / execution_log rows and to nail O5 end to end.
"""
import ast
import inspect
import itertools
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import (
    CONFIRMED_OUTCOME_STATUSES,
    EXECUTION_DECISIONS,
    OUTCOME_STATUSES,
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    ExecutionLog,
    ExecutionOutcome,
)
from app.services.executions.state import derive_execution_state
from app.services.outcomes.derivation import (
    UNKNOWN_OUTCOME,
    ForeignOutcomeVocabulary,
    OutcomeDerivationError,
    derive_outcome_state,
    latest_observation,
)

T0 = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

# The eight dispatch-layer decision words that must NEVER be an outcome
# state (requirement 13 / D3.4-04): requested, guard_rejected, dispatched,
# succeeded, failed, compensation_requested/succeeded/failed.
DISPATCH_WORDS = sorted(EXECUTION_DECISIONS)


@dataclass
class StubObservation:
    """Minimal structural stand-in for ExecutionOutcome (Protocol
    conformance is the contract — derivation never needs the DB)."""

    id: uuid.UUID
    observed_at: datetime
    outcome_status: str


def obs(status, *, observed_at=None, obs_id=None):
    return StubObservation(
        id=obs_id or uuid.uuid4(),
        observed_at=observed_at or T0,
        outcome_status=status,
    )


def series(*statuses, start=T0):
    """Observations of one execution, strictly increasing observed_at."""
    return [
        obs(status, observed_at=start + timedelta(seconds=i))
        for i, status in enumerate(statuses)
    ]


# ---------------------------------------------------------------------------
# Vocabulary freeze + dispatch/outcome isolation (requirement 13, section 三)
# ---------------------------------------------------------------------------


class TestOutcomeVocabularyFreeze:
    def test_five_words_exactly(self):
        assert OUTCOME_STATUSES == frozenset(
            {
                "unknown",
                "pending",
                "confirmed_success",
                "confirmed_failure",
                "reconciliation_failed",
            }
        )
        assert UNKNOWN_OUTCOME in OUTCOME_STATUSES

    def test_confirmed_subset_is_the_two_verdicts(self):
        assert CONFIRMED_OUTCOME_STATUSES == frozenset(
            {"confirmed_success", "confirmed_failure"}
        )
        assert CONFIRMED_OUTCOME_STATUSES < OUTCOME_STATUSES

    @pytest.mark.parametrize("word", DISPATCH_WORDS)
    def test_no_dispatch_word_is_an_outcome_state(self, word):
        # requirement 13: none of the eight dispatch decisions may ever be
        # read as an outcome state.
        assert word not in OUTCOME_STATUSES

    def test_vocabularies_are_disjoint(self):
        assert OUTCOME_STATUSES.isdisjoint(EXECUTION_DECISIONS)

    def test_derivation_module_does_not_import_the_dispatch_log(self):
        # O5 structural proof: the outcome derivation layer imports the
        # outcome fact vocabulary ONLY — never execution_log — so it cannot
        # read or write the dispatch log no matter how it is called. The
        # docstring may *mention* execution_log to explain the boundary;
        # what matters is that it is never imported.
        import app.services.outcomes.derivation as mod

        tree = ast.parse(inspect.getsource(mod))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        assert "app.models.execution_outcome" in imported
        assert not any("execution_log" in name for name in imported)


# ---------------------------------------------------------------------------
# Empty + single-observation derivation (requirements 1-5, Cases 1-5)
# ---------------------------------------------------------------------------


class TestDeriveEmptyAndSingle:
    def test_empty_observations_derive_unknown(self):
        # Case 1 / requirement 1: no facts -> unknown (NOT None).
        assert latest_observation([]) is None
        assert derive_outcome_state([]) == "unknown"

    @pytest.mark.parametrize(
        "status",
        [
            "unknown",
            "pending",
            "confirmed_success",
            "confirmed_failure",
            "reconciliation_failed",
        ],
    )
    def test_single_observation_derives_its_own_status(self, status):
        # Cases 2-5 / requirements 2-5 (plus a stored 'unknown' fact).
        single = [obs(status)]
        assert latest_observation(single) is single[0]
        assert derive_outcome_state(single) == status


# ---------------------------------------------------------------------------
# Latest observed_at wins (requirements 6-8, Cases 6-7)
# ---------------------------------------------------------------------------


class TestDeriveLatestObservedAtWins:
    def test_later_success_overrides_earlier_failure(self):
        # Case 6 / requirement 6: history confirmed_failure, then a newer
        # confirmed_success -> confirmed_success.
        rows = series("confirmed_failure", "confirmed_success")
        assert derive_outcome_state(rows) == "confirmed_success"

    def test_out_of_order_delivery_resolves_by_observed_at(self):
        # requirement 7: facts delivered out of order still resolve to the
        # latest observed_at, never to the last-arrived row.
        a = obs("pending", observed_at=T0 + timedelta(seconds=1))
        b = obs("confirmed_success", observed_at=T0 + timedelta(seconds=3))
        c = obs("confirmed_failure", observed_at=T0 + timedelta(seconds=2))
        assert latest_observation([a, b, c]) is b
        assert derive_outcome_state([a, b, c]) == "confirmed_success"
        assert derive_outcome_state([c, a, b]) == "confirmed_success"
        assert derive_outcome_state([b, c, a]) == "confirmed_success"

    def test_replayed_older_fact_does_not_override_newer(self):
        # Case 7 / requirement 8: a replayed confirmed_failure with an
        # EARLIER observed_at cannot override a newer confirmed_success.
        newer = obs("confirmed_success", observed_at=T0 + timedelta(seconds=5))
        replayed_old = obs("confirmed_failure", observed_at=T0)
        assert derive_outcome_state([newer, replayed_old]) == "confirmed_success"
        assert derive_outcome_state([replayed_old, newer]) == "confirmed_success"

    def test_latest_by_observed_at_wins_regardless_of_id(self):
        # the newest observed_at wins even when its id is the smallest —
        # observed_at is the primary key of recency, id only breaks ties.
        small_id = uuid.UUID(int=1)
        big_id = uuid.UUID(int=2**127)
        late = obs(
            "confirmed_failure",
            observed_at=T0 + timedelta(seconds=2),
            obs_id=small_id,
        )
        early = obs("pending", observed_at=T0, obs_id=big_id)
        assert derive_outcome_state([early, late]) == "confirmed_failure"
        assert derive_outcome_state([late, early]) == "confirmed_failure"

    def test_input_order_does_not_matter(self):
        rows = series("pending", "confirmed_failure", "confirmed_success")
        assert derive_outcome_state(list(reversed(rows))) == "confirmed_success"
        assert derive_outcome_state([rows[2], rows[0], rows[1]]) == "confirmed_success"


# ---------------------------------------------------------------------------
# Same observed_at -> id DESC (requirement 9, Case 8)
# ---------------------------------------------------------------------------


class TestDeriveSameTimestampDeterminism:
    def test_same_observed_at_resolved_by_id_desc(self):
        low = uuid.UUID(int=10)
        high = uuid.UUID(int=20)
        first = obs("confirmed_failure", observed_at=T0, obs_id=low)
        second = obs("confirmed_success", observed_at=T0, obs_id=high)
        assert latest_observation([first, second]) is second
        assert derive_outcome_state([first, second]) == "confirmed_success"
        assert derive_outcome_state([second, first]) == "confirmed_success"

    def test_same_observed_at_all_permutations_deterministic(self):
        ids = [uuid.UUID(int=n) for n in (5, 9, 3)]
        statuses = ["pending", "confirmed_success", "confirmed_failure"]
        rows = [
            obs(status, observed_at=T0, obs_id=oid)
            for status, oid in zip(statuses, ids)
        ]
        # id 9 is the largest -> its status (confirmed_success) wins in
        # EVERY input order; determinism never rests on list position.
        for perm in itertools.permutations(rows):
            assert derive_outcome_state(list(perm)) == "confirmed_success"


# ---------------------------------------------------------------------------
# Purity + isolation (requirement 12 structural, per-execution isolation)
# ---------------------------------------------------------------------------


class TestDerivePurityAndIsolation:
    def test_two_executions_derive_independently(self):
        chain_a = series("pending", "confirmed_success")
        chain_b = series("pending", "confirmed_failure")
        assert derive_outcome_state(chain_a) == "confirmed_success"
        assert derive_outcome_state(chain_b) == "confirmed_failure"

    def test_derive_never_looks_beyond_given_observations(self):
        # a caller bug (mixing executions) must not silently leak state:
        # derivation only ever answers for the observations it was handed.
        chain = series("pending", "confirmed_failure", "confirmed_success")
        assert derive_outcome_state(chain[:1]) == "pending"
        assert derive_outcome_state(chain[:2]) == "confirmed_failure"
        assert derive_outcome_state(chain) == "confirmed_success"

    def test_derive_is_pure_no_writes(self):
        # requirement 12 (structural): stub observations carry no session;
        # repeated calls are identical and leave the input untouched.
        rows = series("pending", "confirmed_failure")
        snapshot = [(r.id, r.observed_at, r.outcome_status) for r in rows]
        first = derive_outcome_state(rows)
        second = derive_outcome_state(rows)
        assert first == second == "confirmed_failure"
        assert [(r.id, r.observed_at, r.outcome_status) for r in rows] == snapshot

    def test_derive_works_on_orm_rows_too(self):
        # the Protocol is satisfied by real ExecutionOutcome instances as
        # well (attribute access only — still no DB round-trip).
        eid = uuid.uuid4()
        orm_rows = [
            ExecutionOutcome(
                execution_id=eid,
                outcome_status=status,
                source="webhook",
                operator="adapter:wazuh",
                observed_at=T0 + timedelta(seconds=i),
                detail={},
            )
            for i, status in enumerate(("pending", "confirmed_success"))
        ]
        assert derive_outcome_state(orm_rows) == "confirmed_success"


# ---------------------------------------------------------------------------
# Foreign vocabulary refused at runtime (requirement 13, enforced)
# ---------------------------------------------------------------------------


class TestForeignVocabularyRefused:
    @pytest.mark.parametrize("word", DISPATCH_WORDS)
    def test_dispatch_word_cannot_be_derived_as_outcome(self, word):
        # requirement 13 (runtime): a dispatch word smuggled into the
        # winning observation is refused, never returned as a state.
        with pytest.raises(ForeignOutcomeVocabulary) as exc_info:
            derive_outcome_state([obs(word)])
        assert exc_info.value.status == word
        assert isinstance(exc_info.value, OutcomeDerivationError)

    def test_arbitrary_foreign_word_refused(self):
        with pytest.raises(ForeignOutcomeVocabulary):
            derive_outcome_state([obs("healthy")])  # an observed-HEALTH word

    def test_valid_vocabulary_never_raises(self):
        for status in sorted(OUTCOME_STATUSES):
            assert derive_outcome_state([obs(status)]) == status


# ---------------------------------------------------------------------------
# No DB side effect + O5, against a REAL session (requirements 10-12, O5)
# ---------------------------------------------------------------------------


def _seed_approval(db_session) -> AIResponseApproval:
    """One committed event + recommendation + approved decision (the
    FK-safe chain used across the execution test-suite)."""
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


class TestDeriveNoDbSideEffect:
    """Derivation over PERSISTED rows: it must not mutate execution_outcome,
    must not touch execution_log, and must leave the session clean."""

    def _seed(self, db_session, execution_id, *, decisions, outcomes):
        """Seed one dispatch chain (``decisions``) plus outcome facts
        (``outcomes`` = tuple of (status, source)); observed_at increases
        with position so the LAST outcome is the newest."""
        approval = _seed_approval(db_session)
        now = datetime.now(timezone.utc)
        db_session.add_all(
            [
                ExecutionLog(
                    execution_id=execution_id,
                    approval_id=approval.id,
                    decision=decision,
                    direction="execute",
                    action="isolate_host",
                    target="host-42",
                    operator="ops-1",
                    detail={},
                    created_at=now + timedelta(seconds=i),
                )
                for i, decision in enumerate(decisions)
            ]
        )
        db_session.add_all(
            [
                ExecutionOutcome(
                    execution_id=execution_id,
                    outcome_status=status,
                    source=source,
                    operator="adapter:wazuh" if source == "webhook" else "ops-1",
                    observed_at=now + timedelta(minutes=5, seconds=i),
                    detail={"raw": status},
                )
                for i, (status, source) in enumerate(outcomes)
            ]
        )
        db_session.commit()

    def _log_rows(self, db_session, execution_id):
        return list(
            db_session.scalars(
                select(ExecutionLog).where(ExecutionLog.execution_id == execution_id)
            )
        )

    def _outcome_rows(self, db_session, execution_id):
        return list(
            db_session.scalars(
                select(ExecutionOutcome).where(
                    ExecutionOutcome.execution_id == execution_id
                )
            )
        )

    @staticmethod
    def _log_snapshot(rows):
        return sorted(
            (r.id, r.decision, r.direction, r.created_at) for r in rows
        )

    @staticmethod
    def _outcome_snapshot(rows):
        return sorted(
            (r.id, r.outcome_status, r.source, r.observed_at) for r in rows
        )

    def _assert_no_side_effect(self, db_session, log_before, outcome_before, eid):
        # requirement 12: nothing staged to write, anywhere in the session.
        assert not list(db_session.new)
        assert not list(db_session.dirty)
        assert not list(db_session.deleted)
        # requirement 10: execution_log unchanged (count + content).
        log_after = self._log_rows(db_session, eid)
        assert self._log_snapshot(log_after) == log_before
        # requirement 11: outcome facts unchanged (count + content).
        outcome_after = self._outcome_rows(db_session, eid)
        assert self._outcome_snapshot(outcome_after) == outcome_before

    def test_o5_dispatch_succeeded_outcome_confirmed_failure(self, db_session):
        # section 六 canonical case: dispatch=succeeded is LEGAL beside
        # outcome=confirmed_failure. Derivation reports confirmed_failure
        # while the dispatch chain STILL derives succeeded — neither layer
        # rewrites the other.
        eid = uuid.uuid4()
        self._seed(
            db_session,
            eid,
            decisions=("requested", "dispatched", "succeeded"),
            outcomes=(("pending", "webhook"), ("confirmed_failure", "webhook")),
        )
        log_before = self._log_snapshot(self._log_rows(db_session, eid))
        outcome_before = self._outcome_snapshot(self._outcome_rows(db_session, eid))
        assert len(log_before) == 3
        assert len(outcome_before) == 2

        derived = derive_outcome_state(self._outcome_rows(db_session, eid))
        assert derived == "confirmed_failure"
        assert derive_execution_state(self._log_rows(db_session, eid)) == "succeeded"

        self._assert_no_side_effect(db_session, log_before, outcome_before, eid)

    def test_failed_dispatch_never_invents_confirmed_success(self, db_session):
        # section 六 reverse: a FAILED dispatch with NO outcome fact derives
        # 'unknown' — derivation never fabricates a confirmed_success. Only
        # a real stored fact can produce that word.
        eid = uuid.uuid4()
        self._seed(
            db_session,
            eid,
            decisions=("requested", "dispatched", "failed"),
            outcomes=(),
        )
        log_before = self._log_snapshot(self._log_rows(db_session, eid))
        outcome_before = self._outcome_snapshot(self._outcome_rows(db_session, eid))
        assert outcome_before == []

        assert derive_outcome_state(self._outcome_rows(db_session, eid)) == "unknown"
        assert derive_execution_state(self._log_rows(db_session, eid)) == "failed"

        self._assert_no_side_effect(db_session, log_before, outcome_before, eid)

    def test_manual_reconcile_success_over_failed_dispatch(self, db_session):
        # section 六: dispatch=failed never AUTO-creates confirmed_success,
        # but a real recorded manual_reconcile fact MAY carry it. Derivation
        # reports the fact; the dispatch chain still derives failed.
        eid = uuid.uuid4()
        self._seed(
            db_session,
            eid,
            decisions=("requested", "dispatched", "failed"),
            outcomes=(
                ("confirmed_failure", "webhook"),
                ("confirmed_success", "manual_reconcile"),
            ),
        )
        log_before = self._log_snapshot(self._log_rows(db_session, eid))
        outcome_before = self._outcome_snapshot(self._outcome_rows(db_session, eid))

        derived = derive_outcome_state(self._outcome_rows(db_session, eid))
        assert derived == "confirmed_success"
        assert derive_execution_state(self._log_rows(db_session, eid)) == "failed"

        self._assert_no_side_effect(db_session, log_before, outcome_before, eid)
