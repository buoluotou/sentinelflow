"""Phase 3.4.4-C: Webhook Gate 3 — Correlation tests.

Correlation is the first gate to touch the database, and the whole 3.4.4
discipline rests on it staying a PURE, READ-ONLY existence check:

    validated execution_id -> ExecutionLog chain existence -> PASS / reject

This suite nails the four properties that make Gate 3 safe:

1. EXISTENCE, NOT VERDICT (spec §5 / §7 + the closing rule). A PASS proves
   only that the chain EXISTS. Even a chain whose latest dispatch is
   ``succeeded`` yields NO outcome word — ``CorrelatedExecution`` structurally
   cannot carry one. A FAIL is a pure rejection (``UnmappableExecutionId``),
   never a degradation to ``unknown`` / ``reconciliation_failed`` /
   ``confirmed_failure`` and never an Outcome Fact.
2. READ-ONLY (spec §10 / §11 / §19). SELECT only: no INSERT / UPDATE / DELETE
   / COMMIT, nothing staged in the session, ``execution_log`` byte-identical
   before and after, outcome count unchanged on BOTH the PASS and FAIL path.
3. THE RIGHT KEY (spec §3 / §17). Correlation keys on ``ExecutionLog
   .execution_id`` (the chain key) — never the row PK ``id``, never operator,
   never external_reference.
4. A BOUNDED MODULE (spec §13 / §15). The AST import surface is an exact
   allowlist: SQLAlchemy select + the ExecutionLog model + a Session + the
   3.4.3 reconciliation domain (for the frozen ``ContractValidationFailure``
   family). No executor, no adapter client, no external transport, no retry,
   no compensation, no FastAPI.

The AST assertions are deliberately docstring-immune (they parse imports, not
prose): the module docstring legitimately NAMES the things Gate 3 must not do
(executor / adapter / retry / mapping), so a naive substring check would be
both brittle and wrong. Format-vs-existence (spec §8) is proven by keeping
``UnmappableExecutionId`` (existence) a distinct sibling of 3.4.3-A's
``MissingExecutionId`` (format) inside ONE frozen exception family.
"""
import ast
import inspect
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import (
    OUTCOME_STATUSES,
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    ExecutionLog,
    ExecutionOutcome,
)
from app.services.outcomes import correlation as correlation_module
from app.services.outcomes.correlation import (
    CorrelatedExecution,
    UnmappableExecutionId,
    correlate_execution,
)
from app.services.outcomes.reconciliation import (
    ContractValidationFailure,
    MissingExecutionId,
)

NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)

#: The exact import surface Gate 3 is allowed (spec §13 / §15).
ALLOWED_MODULES = {
    "uuid",
    "dataclasses",
    "sqlalchemy",
    "sqlalchemy.orm",
    "app.models.execution_log",
    "app.services.outcomes.reconciliation",
}
ALLOWED_NAMES = {
    "dataclass",
    "select",
    "Session",
    "ExecutionLog",
    "ContractValidationFailure",
}

#: Module fragments Gate 3 must NEVER import (spec §2 / §13 / §15). Precise
#: enough not to false-positive on the allowed ``app.models.execution_log``
#: (a MODEL) or ``app.services.outcomes.reconciliation`` (the 3.4.3 domain).
FORBIDDEN_MODULE_FRAGMENTS = (
    "app.services.executions",  # the executor / dispatch service layer
    "executor",
    "adapter",
    "app.integrations",
    "requests",
    "httpx",
    "retry",
    "compensation",
    "fastapi",  # §15: the domain layer is transport-agnostic
    "app.api",  # the router / HTTP layer
)


# ---------------------------------------------------------------------------
# seeding + snapshot helpers (mirror tests/test_outcome_derivation.py)
# ---------------------------------------------------------------------------
def _seed_approval(db_session) -> AIResponseApproval:
    """One committed event + recommendation + approved decision (the FK-safe
    chain used across the execution test-suite)."""
    group = AlertGroup(
        fingerprint=uuid.uuid4().hex,
        title="SSH Brute Force on edge-gateway",
        category="authentication",
        severity="high",
        first_seen=NOW,
        last_seen=NOW,
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
        reviewed_at=NOW,
    )
    db_session.add(approval)
    db_session.commit()
    return approval


def _seed_chain(db_session, execution_id, *, decisions, operator="ops-1"):
    """Seed one dispatch chain of ``ExecutionLog`` rows keyed on execution_id,
    each under its OWN approval (one approval -> at most one forward execute
    ``requested`` row, ``ux_execution_log_approval_id_execute``). ``created_at``
    increases with position so rows are distinguishable."""
    approval = _seed_approval(db_session)
    db_session.add_all(
        [
            ExecutionLog(
                execution_id=execution_id,
                approval_id=approval.id,
                decision=decision,
                direction="execute",
                action="isolate_host",
                target="host-42",
                operator=operator,
                detail={},
                created_at=NOW + timedelta(seconds=i),
            )
            for i, decision in enumerate(decisions)
        ]
    )
    db_session.commit()
    return approval


def _all_log_rows(db_session):
    return list(db_session.scalars(select(ExecutionLog)))


def _log_snapshot(db_session):
    """Full-table content snapshot of execution_log (spec §11)."""
    return sorted(
        (
            r.id,
            r.execution_id,
            r.approval_id,
            r.decision,
            r.direction,
            r.action,
            r.target,
            r.operator,
            r.created_at,
        )
        for r in _all_log_rows(db_session)
    )


def _outcome_count(db_session):
    return len(list(db_session.scalars(select(ExecutionOutcome))))


def _assert_session_clean(db_session):
    """Nothing staged to write anywhere in the session (spec §10 / §12.8)."""
    assert not list(db_session.new)
    assert not list(db_session.dirty)
    assert not list(db_session.deleted)


def _imported_correlation():
    """AST import surface of correlation.py — docstring-immune (spec §13)."""
    tree = ast.parse(inspect.getsource(correlation_module))
    modules, names, funcs, classes = set(), set(), set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                modules.add(node.module)
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.FunctionDef):
            funcs.add(node.name)
        elif isinstance(node, ast.ClassDef):
            classes.add(node.name)
    return modules, names, funcs, classes


# ---------------------------------------------------------------------------
# §12.1 / §12.4 / §12.5 + the closing rule — Correlation PASS
# ---------------------------------------------------------------------------
class TestCorrelationPass:
    def test_01_existing_chain_correlates(self, db_session):
        # §12.1: a valid execution_id WITH an existing chain -> PASS.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("requested", "dispatched", "succeeded"))
        result = correlate_execution(db_session, eid)
        assert isinstance(result, CorrelatedExecution)
        assert result.execution_id == eid
        assert result.row_count == 3

    def test_04_multiple_rows_correlate(self, db_session):
        # §12.4: multiple ExecutionLog rows for the SAME execution_id.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            decisions=("requested", "guard_rejected", "dispatched", "failed"),
        )
        result = correlate_execution(db_session, eid)
        assert result.row_count == 4

    @pytest.mark.parametrize(
        "decision",
        ["requested", "guard_rejected", "dispatched", "succeeded", "failed"],
    )
    def test_05_existence_succeeds_with_any_single_row(self, db_session, decision):
        # §12.5: existence succeeds with ANY row — even a lone 'requested' or
        # a 'failed' dispatch is still an existing chain.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=(decision,))
        result = correlate_execution(db_session, eid)
        assert result.execution_id == eid
        assert result.row_count == 1

    def test_correlated_identity_is_the_trusted_execution_id(self, db_session):
        # §5: the result is the trusted, correlated execution identity that
        # downstream (D/E) consumes — never the raw untrusted callback input.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("requested",))
        result = correlate_execution(db_session, eid)
        assert result.execution_id == eid
        assert isinstance(result.execution_id, uuid.UUID)

    def test_result_is_frozen(self, db_session):
        # The correlated identity is immutable evidence.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("requested",))
        result = correlate_execution(db_session, eid)
        with pytest.raises(Exception):
            result.row_count = 999  # type: ignore[misc]
        assert result.row_count == 1

    def test_succeeded_chain_yields_no_outcome_word(self, db_session):
        # THE CLOSING RULE: even when the chain holds execution_log.succeeded,
        # correlation emits NO outcome word. CorrelatedExecution structurally
        # cannot carry a status, and no confirmed_success fact is written.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("requested", "dispatched", "succeeded"))
        result = correlate_execution(db_session, eid)
        assert set(result.__slots__) == {"execution_id", "row_count"}
        assert not hasattr(result, "outcome_status")
        # no outcome word is derivable from the result, and none was stored
        assert _outcome_count(db_session) == 0
        for word in OUTCOME_STATUSES:
            assert not hasattr(result, word)

    def test_failed_chain_yields_no_confirmed_failure(self, db_session):
        # Symmetric guard: a 'failed' dispatch is NOT laundered into
        # confirmed_failure at Gate 3 (that is Gate 4 + persistence).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("requested", "dispatched", "failed"))
        result = correlate_execution(db_session, eid)
        assert isinstance(result, CorrelatedExecution)
        assert _outcome_count(db_session) == 0

    def test_signature_is_session_and_execution_id(self):
        # §14: correlate_execution(session, execution_id).
        params = list(inspect.signature(correlate_execution).parameters)
        assert params == ["session", "execution_id"]


# ---------------------------------------------------------------------------
# §12.2 / §12.11 / §12.12 / §12.13 + §6 / §7 — Correlation FAIL
# ---------------------------------------------------------------------------
class TestCorrelationFailure:
    def test_02_nonexistent_chain_raises_unmappable(self, db_session):
        # §12.2: a valid UUID with NO ExecutionLog row -> UnmappableExecutionId,
        # even though OTHER chains exist in the table.
        _seed_chain(db_session, uuid.uuid4(), decisions=("requested",))
        with pytest.raises(UnmappableExecutionId):
            correlate_execution(db_session, uuid.uuid4())

    def test_unmappable_is_a_contract_validation_failure(self):
        # §6: ONE frozen exception family — not a second exception system.
        assert issubclass(UnmappableExecutionId, ContractValidationFailure)

    def test_11_unknown_execution_id_creates_no_fact(self, db_session):
        # §12.11: unknown execution_id -> no Outcome Fact.
        before = _outcome_count(db_session)
        with pytest.raises(UnmappableExecutionId):
            correlate_execution(db_session, uuid.uuid4())
        assert _outcome_count(db_session) == before == 0

    def test_12_unknown_is_not_the_word_unknown(self, db_session):
        # §12.12 / §7: rejection is NOT the outcome word 'unknown'. No fact is
        # stored at all, so nothing carries 'unknown'.
        with pytest.raises(UnmappableExecutionId):
            correlate_execution(db_session, uuid.uuid4())
        rows = list(db_session.scalars(select(ExecutionOutcome)))
        assert rows == []
        assert all(r.outcome_status != "unknown" for r in rows)

    def test_13_unknown_is_not_reconciliation_failed(self, db_session):
        # §12.13 / §7: rejection NEVER degrades to reconciliation_failed.
        with pytest.raises(UnmappableExecutionId):
            correlate_execution(db_session, uuid.uuid4())
        rows = list(db_session.scalars(select(ExecutionOutcome)))
        assert rows == []
        assert all(r.outcome_status != "reconciliation_failed" for r in rows)

    def test_failure_is_a_rejection_not_a_returned_status(self, db_session):
        # §7: a FAIL RAISES; it never RETURNS an outcome word.
        with pytest.raises(ContractValidationFailure):
            correlate_execution(db_session, uuid.uuid4())

    def test_no_status_degradation_on_failure(self, db_session):
        # §7: the rejection is not any of the five outcome words.
        with pytest.raises(UnmappableExecutionId) as excinfo:
            correlate_execution(db_session, uuid.uuid4())
        assert type(excinfo.value).__name__ not in OUTCOME_STATUSES
        assert _outcome_count(db_session) == 0


# ---------------------------------------------------------------------------
# §8 / §12.3 — the UUID format/existence boundary belongs to B, not C
# ---------------------------------------------------------------------------
class TestUuidBoundary:
    def test_03_c_does_not_revalidate_uuid_format(self):
        # §12.3 / §8: format validity is B / 3.4.3-A's job. correlation.py
        # never parses a UUID string, never imports the schema, never calls the
        # contract format validator.
        modules, names, _, _ = _imported_correlation()
        source = inspect.getsource(correlation_module)
        assert "validate_observation" not in source
        assert "WebhookCallbackRequest" not in source
        assert "MissingExecutionId" not in names
        assert not any("schemas" in m for m in modules)

    def test_format_and_existence_are_distinct_exceptions(self):
        # §8: MissingExecutionId (format, 3.4.3-A) and UnmappableExecutionId
        # (existence, 3.4.4-C) are distinct siblings in ONE family.
        assert issubclass(UnmappableExecutionId, ContractValidationFailure)
        assert issubclass(MissingExecutionId, ContractValidationFailure)
        assert not issubclass(UnmappableExecutionId, MissingExecutionId)
        assert not issubclass(MissingExecutionId, UnmappableExecutionId)

    def test_execution_id_annotation_is_uuid(self):
        # C RECEIVES an already-validated UUID (it does not re-check format).
        hints = inspect.signature(correlate_execution).parameters["execution_id"]
        assert hints.annotation is uuid.UUID


# ---------------------------------------------------------------------------
# §10 / §11 / §19 + §12.6 / §12.8 / §12.14 — read-only discipline
# ---------------------------------------------------------------------------
class TestReadOnly:
    def test_06_no_execution_log_mutation_on_pass(self, db_session):
        # §12.6 / §11: execution_log is byte-identical before/after a PASS.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("requested", "dispatched", "succeeded"))
        before = _log_snapshot(db_session)
        correlate_execution(db_session, eid)
        assert _log_snapshot(db_session) == before

    def test_no_execution_log_mutation_on_fail(self, db_session):
        # §11: a FAILED correlation of a missing id leaves OTHER chains intact.
        other = uuid.uuid4()
        _seed_chain(db_session, other, decisions=("requested", "dispatched"))
        before = _log_snapshot(db_session)
        with pytest.raises(UnmappableExecutionId):
            correlate_execution(db_session, uuid.uuid4())
        assert _log_snapshot(db_session) == before

    def test_08_no_insert_update_delete_on_pass(self, db_session):
        # §12.8: nothing staged to write after a PASS.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("requested",))
        correlate_execution(db_session, eid)
        _assert_session_clean(db_session)

    def test_08_no_insert_update_delete_on_fail(self, db_session):
        # §12.8: nothing staged to write after a FAIL either.
        _seed_approval(db_session)
        with pytest.raises(UnmappableExecutionId):
            correlate_execution(db_session, uuid.uuid4())
        _assert_session_clean(db_session)

    def test_19_pass_outcome_count_unchanged(self, db_session):
        # §19: Correlation PASS -> outcome count before == after.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("requested", "dispatched"))
        before = _outcome_count(db_session)
        correlate_execution(db_session, eid)
        assert _outcome_count(db_session) == before == 0

    def test_19_fail_outcome_count_unchanged(self, db_session):
        # §19: Correlation FAIL -> outcome count before == after.
        before = _outcome_count(db_session)
        with pytest.raises(UnmappableExecutionId):
            correlate_execution(db_session, uuid.uuid4())
        assert _outcome_count(db_session) == before == 0

    def test_14_no_execution_creation(self, db_session):
        # §12.14: correlation never CREATES an ExecutionLog row.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("requested",))
        count_before = len(_all_log_rows(db_session))
        correlate_execution(db_session, eid)
        with pytest.raises(UnmappableExecutionId):
            correlate_execution(db_session, uuid.uuid4())
        assert len(_all_log_rows(db_session)) == count_before

    def test_correlation_never_commits_on_pass(self, db_session, monkeypatch):
        # §10: read-only means NO COMMIT. Patch commit to explode; a PASS must
        # still return without triggering it.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("requested", "dispatched"))

        def _boom():
            raise AssertionError("correlate_execution must not COMMIT (spec §10)")

        monkeypatch.setattr(db_session, "commit", _boom)
        result = correlate_execution(db_session, eid)
        assert result.row_count == 2

    def test_correlation_never_commits_on_fail(self, db_session, monkeypatch):
        # §10: the FAIL path raises UnmappableExecutionId, never a commit.
        _seed_approval(db_session)

        def _boom():
            raise AssertionError("correlate_execution must not COMMIT (spec §10)")

        monkeypatch.setattr(db_session, "commit", _boom)
        with pytest.raises(UnmappableExecutionId):
            correlate_execution(db_session, uuid.uuid4())


# ---------------------------------------------------------------------------
# §12.9 / §12.10 / §12.15 / §12.16 + §2 — no execution side-capabilities
# ---------------------------------------------------------------------------
class TestNoSideCapabilities:
    def test_09_no_executor_invocation(self):
        # §12.9: no executor in the import surface (docstring-immune).
        modules, names, funcs, _ = _imported_correlation()
        assert not any("app.services.executions" in m for m in modules)
        assert not any("executor" in m.lower() for m in modules)
        assert "Executor" not in names
        assert funcs == {"correlate_execution"}

    def test_10_no_adapter_invocation(self):
        # §12.10: no adapter client / external transport in the import surface.
        modules, names, _, _ = _imported_correlation()
        assert not any("adapter" in m.lower() for m in modules)
        assert not any("app.integrations" in m for m in modules)
        assert "requests" not in modules
        assert "httpx" not in modules

    def test_15_no_retry(self):
        # §12.15: correlation never retries.
        modules, names, funcs, _ = _imported_correlation()
        assert not any("retry" in m.lower() for m in modules)
        assert not any("retry" in n.lower() for n in names)
        assert not any("retry" in f.lower() for f in funcs)

    def test_16_no_compensation(self):
        # §12.16: correlation never compensates.
        modules, names, funcs, _ = _imported_correlation()
        assert not any("compensation" in m.lower() for m in modules)
        assert not any("compensation" in n.lower() for n in names)
        assert not any("compensation" in f.lower() for f in funcs)

    def test_no_outcome_persistence(self):
        # §2 / §7: the module never imports or constructs an Outcome Fact.
        modules, names, _, _ = _imported_correlation()
        assert "ExecutionOutcome" not in names
        assert not any("execution_outcome" in m for m in modules)
        source = inspect.getsource(correlation_module)
        assert "ExecutionOutcome(" not in source

    def test_no_mapping(self):
        # §2 / §14: correlation never maps external_state onto an outcome word.
        _, names, _, _ = _imported_correlation()
        assert "normalize_external_state" not in names
        source = inspect.getsource(correlation_module)
        assert "normalize_external_state" not in source


# ---------------------------------------------------------------------------
# §13 / §15 — AST import boundary
# ---------------------------------------------------------------------------
class TestImportBoundary:
    def test_modules_are_an_exact_allowlist(self):
        modules, _, _, _ = _imported_correlation()
        assert modules == ALLOWED_MODULES

    def test_imported_names_are_an_exact_allowlist(self):
        _, names, _, _ = _imported_correlation()
        assert names == ALLOWED_NAMES

    def test_funcs_and_classes(self):
        _, _, funcs, classes = _imported_correlation()
        assert funcs == {"correlate_execution"}
        assert classes == {"UnmappableExecutionId", "CorrelatedExecution"}

    def test_15_no_fastapi_import(self):
        # §15: the domain layer never imports FastAPI / raises HTTPException.
        modules, names, _, _ = _imported_correlation()
        assert "fastapi" not in modules
        assert not any(m.startswith("fastapi") for m in modules)
        assert "HTTPException" not in names

    def test_no_forbidden_modules(self):
        modules, _, _, _ = _imported_correlation()
        for module in modules:
            for fragment in FORBIDDEN_MODULE_FRAGMENTS:
                assert fragment not in module, f"{module} must not import {fragment}"


# ---------------------------------------------------------------------------
# §3 / §17 — correlation keys on execution_id, never id / operator
# ---------------------------------------------------------------------------
class TestCorrelationKey:
    def test_correlates_on_execution_id_not_the_row_pk(self, db_session):
        # §17: the chain key is ExecutionLog.execution_id, NOT the row PK id.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("requested", "dispatched"))
        row_pk = _all_log_rows(db_session)[0].id
        assert row_pk != eid
        # keying on execution_id PASSES ...
        assert correlate_execution(db_session, eid).row_count == 2
        # ... while the row PK (a valid UUID, but not an execution_id) does NOT.
        with pytest.raises(UnmappableExecutionId):
            correlate_execution(db_session, row_pk)

    def test_not_keyed_on_operator(self, db_session):
        # §17: the client operator is NEVER a correlation key. Two chains share
        # an operator (each under its own approval); correlating one finds only
        # its own rows, never the other operator-identical chain.
        eid1, eid2 = uuid.uuid4(), uuid.uuid4()
        _seed_chain(
            db_session, eid1, decisions=("requested", "dispatched"),
            operator="ops-shared",
        )
        _seed_chain(
            db_session, eid2, decisions=("requested",),
            operator="ops-shared",
        )
        assert correlate_execution(db_session, eid1).row_count == 2
        assert correlate_execution(db_session, eid2).row_count == 1

    def test_query_targets_the_execution_id_column(self):
        # §4: the existence query keys on ExecutionLog.execution_id.
        source = inspect.getsource(correlation_module)
        assert "ExecutionLog.execution_id == execution_id" in source
