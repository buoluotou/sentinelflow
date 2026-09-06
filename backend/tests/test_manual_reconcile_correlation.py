"""3.4.5-A2-B Manual Reconcile — correlation + external-reference extraction.

A2-B makes Manual Reconcile *history-driven*: an ``execution_id`` is CORRELATED
(reusing 3.4.4-C, never a second existence query) and the adapter identity +
adapter-specific external reference are lifted READ-ONLY from the historical
``execution_log`` chain. It performs NO external read, NO mapping, NO persistence
and NO execution — it stops at ``NotImplementedError`` (the router's honest 501).

The suite nails the properties that make B safe (spec §1-§19):

1. THE RIGHT FACTS FROM THE RIGHT ROWS (spec §5-§7 — the crux). One execution_id
   maps to MULTIPLE rows, so selection is by the platform's FROZEN ordering, not
   list/insert position: the adapter is ``detail["executor"]`` of the FIRST
   chronological row (the ``requested`` row — the ``metrics.py::_adapter_of``
   precedent), and the reference is the adapter-specific key of the TERMINAL row
   (the latest by ``created_at, id`` — ``derive_execution_state``'s ordering, the
   only row ``_terminal_outcome_detail`` writes the executor's response onto).
   ``test_26_*`` decouples INSERT order / row id from ``created_at`` to prove it.
2. NO FABRICATED HANDLE (spec §8-§11). A missing shuffle/wazuh/thehive reference,
   a ``failed`` dispatch with no handle, a never-dispatched (``guard_rejected``)
   chain, or a Shuffle ``workflow_id`` / Wazuh ``command`` look-alike is
   ``MissingExternalReference`` -> rejected, never a substituted reference.
   ``mock`` alone yields ``external_reference=None`` (recognized, no read; A2-C
   decides UnsupportedAdapterRead).
3. HISTORY WINS, THE CLIENT LOSES (spec §6 / §14-§16 / §19). The adapter and the
   reference come ONLY from ``execution_log``: ``extract_context`` structurally
   takes neither an adapter, nor an operator, nor a reference; a smuggled
   ``{"adapter": ..., "external_reference": ...}`` body is a 422 at the empty
   schema and never perturbs the historical facts.
4. READ-ONLY (spec §16-§17). SELECT only: no INSERT/UPDATE/DELETE/COMMIT, nothing
   staged, ``execution_log`` byte-identical (INCLUDING ``detail``) before/after on
   the PASS, the FAIL and the ``NotImplementedError`` path; zero Outcome Facts.
5. A BOUNDED MODULE (spec §2 / §13). The AST import surface is an EXACT allowlist
   (docstring-immune — this module NAMES the forbidden things in prose): the
   ExecutionLog model + SQLAlchemy select + ``correlate_execution`` (3.4.4-C) +
   ``MissingExternalReference`` (3.4.3-B) + ``ADAPTER_NAMES`` (the registry
   VOCABULARY, reused not copied). No executor, no read adapter, no transport, no
   mapping, no persistence, no retry, no compensation, no FastAPI.

The AST assertions parse imports, never prose, so the docstring's legitimate
NAMING of ReadAdapterRegistry / adapter.read / HTTP / mapping / retry /
compensation cannot false-positive; the runtime side-effect proofs (0 outcome
rows, 0 new log rows, no commit) back them independently.
"""
import ast
import inspect
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import (
    OUTCOME_STATUSES,
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    ExecutionLog,
    ExecutionOutcome,
)
from app.services.executions.registry import ADAPTER_NAMES
from app.services.outcomes import manual_reconcile as reconcile_module
from app.services.outcomes.correlation import (
    UnmappableExecutionId,
    correlate_execution,
)
from app.services.outcomes.manual_reconcile import (
    CorrelatedExecutionContext,
    extract_context,
    reconcile_execution,
)
from app.services.outcomes.reconciliation import (
    ContractValidationFailure,
    MissingExternalReference,
)

NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)

RECONCILE = "/api/v1/executions/{eid}/reconcile"

#: The exact import surface B is allowed (spec §2 / §13). ``__future__`` is the
#: ``from __future__ import annotations`` line; ``app.services.executions.registry``
#: is sanctioned for the ``ADAPTER_NAMES`` VOCABULARY ONLY (reused, never a copied
#: registry, never the executor service); ``app.services.outcomes.correlation`` is
#: the mandated 3.4.4-C reuse.
ALLOWED_MODULES = {
    "__future__",
    "uuid",
    "dataclasses",
    "typing",
    "sqlalchemy",
    "sqlalchemy.orm",
    "app.models.execution_log",
    "app.services.executions.registry",
    "app.services.outcomes.correlation",
    "app.services.outcomes.reconciliation",
}
ALLOWED_NAMES = {
    "annotations",
    "dataclass",
    "NoReturn",
    "select",
    "Session",
    "ExecutionLog",
    "ADAPTER_NAMES",
    "correlate_execution",
    "MissingExternalReference",
}
ALLOWED_FUNCS = {
    "_select_chain",
    "_detail_of",
    "_extract_adapter",
    "_extract_reference",
    "extract_context",
    "reconcile_execution",
}
ALLOWED_CLASSES = {"CorrelatedExecutionContext"}

#: Fragments B must NEVER import (spec §2). Unlike correlation.py we CANNOT forbid
#: ``app.services.executions`` wholesale — ``registry`` lives there and is the
#: sanctioned vocabulary source — so the executions import is pinned to EXACTLY
#: ``registry`` in a dedicated test, and the dispatch/read/persistence/transport
#: submodules are forbidden here.
FORBIDDEN_MODULE_FRAGMENTS = (
    "httpx",
    "requests",
    "urllib",
    "app.integrations",
    "app.services.manual_reconcile",  # the 3.4.5-A1 sealed read-contract package
    "app.models.execution_outcome",  # Outcome persistence (A2-E)
    "fastapi",
    "app.api",
    "retry",
    "compensat",
)
#: Imported NAMES B must never bind (docstring-immune; the module docstring NAMES
#: several of these in its FORBIDDEN list, so only the AST is trustworthy).
FORBIDDEN_NAMES = (
    "execute_response",
    "compensate_response",
    "ResponseExecutor",
    "create_executor",
    "ReadAdapterRegistry",
    "AdapterReadRequest",
    "FakeReadAdapter",
    "read_adapter",
    "normalize_external_state",
    "validate_observation",
    "ExecutionOutcome",
    "persist_callback_outcome",
    "UnmappableExecutionId",  # B never raises it directly — 3.4.4-C does (spec §3)
    "HTTPException",
    "Operator",
)


# ---------------------------------------------------------------------------
# seeding + snapshot helpers (mirror tests/test_correlation.py, extended so each
# row carries its OWN detail — B reads detail["executor"] + the reference key)
# ---------------------------------------------------------------------------
def _seed_approval(db_session) -> AIResponseApproval:
    """One committed event + recommendation + approved decision (the FK-safe chain
    used across the execution suite). Each execute chain needs its OWN approval
    (``ux_execution_log_approval_id_execute``: <=1 execute 'requested' per
    approval)."""
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


def _seed_chain(db_session, execution_id, *, rows, operator="ops-1"):
    """Seed one execute chain. ``rows`` = ``[(decision, detail), ...]`` in
    CHRONOLOGICAL order; ``created_at`` strictly increases with position so the
    terminal row is unambiguous. INSERT order == chronological order here."""
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
                detail=detail,
                created_at=NOW + timedelta(seconds=i),
            )
            for i, (decision, detail) in enumerate(rows)
        ]
    )
    db_session.commit()
    return approval


def _seed_chain_at(db_session, execution_id, *, rows, operator="ops-1"):
    """Seed one execute chain from ``[(decision, detail, created_at), ...]``,
    inserted in the GIVEN order with EXPLICIT ``created_at``. INSERT order (hence
    row ``id``) is deliberately DECOUPLED from chronological order so a test can
    prove selection follows ``created_at`` — never the natural/insert order or the
    row PK (spec §7 / §18 item 26). The DB does NOT enforce "requested first"
    (that is a Service invariant), so this seeding is valid."""
    approval = _seed_approval(db_session)
    for decision, detail, created_at in rows:
        db_session.add(
            ExecutionLog(
                execution_id=execution_id,
                approval_id=approval.id,
                decision=decision,
                direction="execute",
                action="isolate_host",
                target="host-42",
                operator=operator,
                detail=detail,
                created_at=created_at,
            )
        )
    db_session.commit()
    return approval


def _all_log_rows(db_session):
    return list(db_session.scalars(select(ExecutionLog)))


def _log_snapshot(db_session):
    """Full-table content snapshot of execution_log INCLUDING ``detail`` (spec §17:
    B must not mutate detail / status / reference). ``detail`` is JSON-canonicalized
    so dict key order is irrelevant; the tuple is keyed by the unique row ``id`` so
    dicts are never order-compared."""
    return sorted(
        (
            (
                r.id,
                r.execution_id,
                r.approval_id,
                r.decision,
                r.direction,
                r.action,
                r.target,
                r.operator,
                json.dumps(r.detail, sort_keys=True),
                r.created_at,
            )
            for r in _all_log_rows(db_session)
        ),
        key=lambda t: t[0],
    )


def _outcome_count(db_session):
    return len(list(db_session.scalars(select(ExecutionOutcome))))


def _assert_session_clean(db_session):
    """Nothing staged to write anywhere in the session (spec §16)."""
    assert not list(db_session.new)
    assert not list(db_session.dirty)
    assert not list(db_session.deleted)


def _imported_reconcile():
    """AST import surface of manual_reconcile.py — docstring-immune (spec §2)."""
    tree = ast.parse(inspect.getsource(reconcile_module))
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


def _url(eid: str) -> str:
    return RECONCILE.format(eid=eid)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def operators(monkeypatch):
    """Four operators, one per role, via OPERATORS_JSON (the 3.3.1 harness)."""
    monkeypatch.setattr(
        settings,
        "OPERATORS_JSON",
        json.dumps(
            [
                {"token": "tok-exec", "name": "exec-op", "role": "executor"},
                {"token": "tok-admin", "name": "admin-op", "role": "admin"},
                {"token": "tok-viewer", "name": "view-op", "role": "viewer"},
                {"token": "tok-reviewer", "name": "rev-op", "role": "reviewer"},
            ]
        ),
    )


#: A canonical, reference-bearing shuffle chain (requested -> dispatched ->
#: succeeded with the §6.2 external handle on the TERMINAL row).
def _shuffle_rows(reference="sf-exec-abc123"):
    return [
        ("requested", {"executor": "shuffle"}),
        ("dispatched", {"executor": "shuffle"}),
        ("succeeded", {"external_execution_id": reference, "workflow_id": "wf-tpl-1"}),
    ]


# ---------------------------------------------------------------------------
# §18 items 1/2/5/6/7/8/13 — extract_context yields the right read-only context
# ---------------------------------------------------------------------------
class TestExtractContext:
    def test_01_existing_chain_yields_context(self, db_session):
        # §18.1: an existing chain -> a pure CorrelatedExecutionContext.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        ctx = extract_context(db_session, eid)
        assert isinstance(ctx, CorrelatedExecutionContext)
        assert ctx.execution_id == eid

    def test_02_missing_chain_raises_unmappable(self, db_session):
        # §18.2 / §4: no chain -> UnmappableExecutionId (from 3.4.4-C), never a
        # fabricated context, never 'unknown' / 'reconciliation_failed'.
        _seed_chain(db_session, uuid.uuid4(), rows=_shuffle_rows())
        with pytest.raises(UnmappableExecutionId):
            extract_context(db_session, uuid.uuid4())
        assert _outcome_count(db_session) == 0

    def test_05_executor_extracted_from_requested_row(self, db_session):
        # §18.5 / §6: the adapter is detail["executor"] of the FIRST chronological
        # row (the requested row), read-only from history.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        assert extract_context(db_session, eid).adapter == "shuffle"

    def test_06_shuffle_reference_extracted(self, db_session):
        # §18.6 / §5: Shuffle -> detail["external_execution_id"] on the TERMINAL row.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows("sf-exec-xyz"))
        ctx = extract_context(db_session, eid)
        assert ctx.adapter == "shuffle"
        assert ctx.external_reference == "sf-exec-xyz"

    def test_07_wazuh_reference_extracted(self, db_session):
        # §18.7 / §5: Wazuh -> detail["command_id"] on the TERMINAL row.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "wazuh"}),
                ("dispatched", {"executor": "wazuh"}),
                ("succeeded", {"command_id": "cmd-77", "command": "restart-agent"}),
            ],
        )
        ctx = extract_context(db_session, eid)
        assert ctx.adapter == "wazuh"
        assert ctx.external_reference == "cmd-77"

    def test_08_thehive_reference_extracted(self, db_session):
        # §18.8 / §5: TheHive -> detail["case_id"] on the TERMINAL row.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "thehive"}),
                ("dispatched", {"executor": "thehive"}),
                ("succeeded", {"case_id": "case-4242"}),
            ],
        )
        ctx = extract_context(db_session, eid)
        assert ctx.adapter == "thehive"
        assert ctx.external_reference == "case-4242"

    def test_13_mock_recognized_reference_none(self, db_session):
        # §18.13 / §14: executor=mock -> adapter="mock", external_reference=None,
        # NOT MissingExternalReference (mock has no external object; A2-C decides
        # UnsupportedAdapterRead). dry_run.execution_id is the PLATFORM id, never a
        # reference, and is not read.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "mock"}),
                ("dispatched", {"executor": "mock"}),
                ("succeeded", {"dry_run": {"executor": "mock", "execution_id": str(eid)}}),
            ],
        )
        ctx = extract_context(db_session, eid)
        assert ctx.adapter == "mock"
        assert ctx.external_reference is None


# ---------------------------------------------------------------------------
# §18 items 9/10/11/12 + §8-§11 — never fabricate a handle
# ---------------------------------------------------------------------------
class TestMissingReference:
    def test_09_missing_shuffle_reference_rejected(self, db_session):
        # §18.9 / §11: Shuffle terminal row WITHOUT external_execution_id.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "shuffle"}),
                ("dispatched", {"executor": "shuffle"}),
                ("succeeded", {"status": "ok"}),
            ],
        )
        with pytest.raises(MissingExternalReference):
            extract_context(db_session, eid)

    def test_10_missing_wazuh_reference_rejected(self, db_session):
        # §18.10 / §10: Wazuh terminal row WITHOUT command_id.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "wazuh"}),
                ("dispatched", {"executor": "wazuh"}),
                ("succeeded", {"status": "ok"}),
            ],
        )
        with pytest.raises(MissingExternalReference):
            extract_context(db_session, eid)

    def test_11_missing_thehive_reference_rejected(self, db_session):
        # §18.11 / §9: TheHive case_id is MANDATORY terminal evidence; absent ->
        # MissingExternalReference.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "thehive"}),
                ("dispatched", {"executor": "thehive"}),
                ("succeeded", {"status": "ok"}),
            ],
        )
        with pytest.raises(MissingExternalReference):
            extract_context(db_session, eid)

    def test_12_failed_dispatch_without_reference_rejected(self, db_session):
        # §18.12 / §8: a 'failed' TERMINAL row with no handle. The execution_id
        # EXISTS and the adapter is KNOWN, but B never constructs a reference.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "shuffle"}),
                ("dispatched", {"executor": "shuffle"}),
                ("failed", {"executor": "shuffle", "error": "connection timeout"}),
            ],
        )
        with pytest.raises(MissingExternalReference):
            extract_context(db_session, eid)

    def test_shuffle_workflow_id_is_not_substituted(self, db_session):
        # §11 TRAP: a Shuffle terminal row carrying ONLY workflow_id (the workflow
        # TEMPLATE id) must NOT be laundered into external_execution_id.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "shuffle"}),
                ("dispatched", {"executor": "shuffle"}),
                ("succeeded", {"workflow_id": "wf-template-999"}),
            ],
        )
        with pytest.raises(MissingExternalReference):
            extract_context(db_session, eid)

    def test_wazuh_command_is_not_command_id(self, db_session):
        # §10 TRAP: a Wazuh terminal row carrying 'command' (the command NAME) but
        # no 'command_id' must NOT be substituted.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "wazuh"}),
                ("dispatched", {"executor": "wazuh"}),
                ("succeeded", {"command": "restart-wazuh-agent"}),
            ],
        )
        with pytest.raises(MissingExternalReference):
            extract_context(db_session, eid)

    def test_guard_rejected_chain_has_no_reference(self, db_session):
        # §8: a chain that never dispatched (requested -> guard_rejected) has NO
        # terminal executor response, hence NO reference -> MissingExternalReference.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "shuffle"}),
                ("guard_rejected", {"reason": "cooldown"}),
            ],
        )
        with pytest.raises(MissingExternalReference):
            extract_context(db_session, eid)

    def test_missing_reference_is_a_contract_validation_failure(self):
        # §22: reuse the ONE frozen family — not a second exception system.
        assert issubclass(MissingExternalReference, ContractValidationFailure)


# ---------------------------------------------------------------------------
# §18 items 14/15/16/17 + §6 / §13 — adapter identity is history-driven
# ---------------------------------------------------------------------------
class TestAdapterIdentity:
    def test_17_unknown_adapter_rejected(self, db_session):
        # §18.17 / §13: an executor OUTSIDE the reused ADAPTER_NAMES vocabulary has
        # no reference-key mapping -> fail-closed MissingExternalReference, never a
        # guessed adapter.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "datadog"}),
                ("dispatched", {"executor": "datadog"}),
                ("succeeded", {"external_execution_id": "dd-1"}),
            ],
        )
        with pytest.raises(MissingExternalReference):
            extract_context(db_session, eid)

    def test_absent_executor_rejected(self, db_session):
        # §13: a requested row with no executor at all is not reconcilable.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[("requested", {}), ("dispatched", {}), ("succeeded", {"case_id": "c"})],
        )
        with pytest.raises(MissingExternalReference):
            extract_context(db_session, eid)

    def test_non_string_executor_rejected(self, db_session):
        # §13: a non-str executor (corrupt detail) is never coerced into an adapter.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[("requested", {"executor": 123}), ("succeeded", {"case_id": "c"})],
        )
        with pytest.raises(MissingExternalReference):
            extract_context(db_session, eid)

    def test_14_extract_context_takes_no_adapter_from_client(self):
        # §18.14 / §6: STRUCTURAL — extract_context(session, execution_id) has NO
        # adapter parameter, so a client can never supply one.
        params = list(inspect.signature(extract_context).parameters)
        assert params == ["session", "execution_id"]

    def test_15_extract_context_takes_no_operator(self):
        # §18.15 / §6: STRUCTURAL — the operator/recorder never reaches extraction,
        # so it can never influence the adapter or the reference.
        params = list(inspect.signature(extract_context).parameters)
        assert "operator" not in params

    def test_16_extract_context_takes_no_external_reference(self):
        # §18.16 / §7: STRUCTURAL — no reference parameter; the reference is only
        # ever read from execution_log.
        params = list(inspect.signature(extract_context).parameters)
        assert "external_reference" not in params
        assert "reference" not in params

    def test_operator_value_does_not_change_adapter(self, db_session):
        # §18.15: reconcile_execution carries an operator, but the adapter is the
        # historical one regardless of the operator string passed.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        # extraction (what reconcile_execution runs before stopping) is operator-
        # blind: two different operators, one historical adapter.
        assert extract_context(db_session, eid).adapter == "shuffle"
        with pytest.raises(NotImplementedError):
            reconcile_execution(db_session, eid, "attacker-op")
        assert extract_context(db_session, eid).adapter == "shuffle"

    def test_adapter_read_from_first_row_not_terminal(self, db_session):
        # §7: the adapter is the FIRST chronological row's executor even when the
        # TERMINAL row carries a DECOY executor (a wrong impl reading the terminal
        # row would resolve to wazuh and then fail on shuffle's key).
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "shuffle"}),
                ("dispatched", {"executor": "shuffle"}),
                ("succeeded", {"executor": "wazuh", "external_execution_id": "sf-real"}),
            ],
        )
        ctx = extract_context(db_session, eid)
        assert ctx.adapter == "shuffle"
        assert ctx.external_reference == "sf-real"

    def test_adapter_vocabulary_is_reused_not_copied(self):
        # §13: B reuses the registry's ADAPTER_NAMES object — it does NOT copy or
        # re-declare a second adapter registry.
        assert reconcile_module.ADAPTER_NAMES is ADAPTER_NAMES
        assert set(ADAPTER_NAMES) == {"mock", "shuffle", "wazuh", "thehive"}


# ---------------------------------------------------------------------------
# §18 items 25/26 + §7 — deterministic multi-row selection
# ---------------------------------------------------------------------------
class TestDeterministicSelection:
    def test_26_shuffled_insert_selects_by_created_at(self, db_session):
        # §18.26 / §7: INSERT order (hence row id) is DECOUPLED from chronological
        # order. Insert succeeded FIRST (lowest id, latest created_at) and requested
        # LAST (highest id, earliest created_at). Only a created_at ASC sort yields
        # adapter from requested and reference from succeeded; an id/insert-order
        # impl would read the adapter from the succeeded row (no executor -> fail)
        # and the reference from the requested row (no handle -> fail).
        eid = uuid.uuid4()
        _seed_chain_at(
            db_session,
            eid,
            rows=[
                ("succeeded", {"external_execution_id": "sf-real"}, NOW + timedelta(seconds=2)),
                ("dispatched", {"executor": "shuffle"}, NOW + timedelta(seconds=1)),
                ("requested", {"executor": "shuffle"}, NOW),
            ],
        )
        ctx = extract_context(db_session, eid)
        assert ctx.adapter == "shuffle"
        assert ctx.external_reference == "sf-real"

    def test_reference_from_terminal_not_earliest_row(self, db_session):
        # §7: the reference is the TERMINAL (latest created_at) row's handle even
        # when an EARLIER row carries a decoy reference-shaped key.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "shuffle", "external_execution_id": "DECOY-EARLY"}),
                ("dispatched", {"executor": "shuffle"}),
                ("succeeded", {"external_execution_id": "sf-terminal-real"}),
            ],
        )
        assert extract_context(db_session, eid).external_reference == "sf-terminal-real"

    def test_25_repeated_call_is_deterministic(self, db_session):
        # §18.25: repeated extraction over an unchanged chain is identical, and
        # leaves the chain byte-identical (no mutation between calls).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows("sf-stable"))
        before = _log_snapshot(db_session)
        first = extract_context(db_session, eid)
        second = extract_context(db_session, eid)
        assert (first.adapter, first.external_reference) == (
            second.adapter,
            second.external_reference,
        )
        assert first.execution_id == second.execution_id == eid
        assert _log_snapshot(db_session) == before


# ---------------------------------------------------------------------------
# §18 item 4 + §16 / §17 — read-only discipline
# ---------------------------------------------------------------------------
class TestReadOnly:
    def test_04_execution_log_rows_unchanged(self, db_session):
        # §18.4 / §17: execution_log (INCLUDING detail) is byte-identical after a
        # successful extraction.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        before = _log_snapshot(db_session)
        extract_context(db_session, eid)
        assert _log_snapshot(db_session) == before

    def test_rows_unchanged_after_reconcile_not_implemented(self, db_session):
        # §17 / §20: even the full pipeline entrypoint (which stops at 501) leaves
        # the chain untouched and writes zero Outcome Facts.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        before = _log_snapshot(db_session)
        with pytest.raises(NotImplementedError):
            reconcile_execution(db_session, eid, "exec-op")
        assert _log_snapshot(db_session) == before
        assert _outcome_count(db_session) == 0

    def test_rows_unchanged_on_missing_reference_path(self, db_session):
        # §17: a rejected extraction (MissingExternalReference) mutates nothing.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[("requested", {"executor": "shuffle"}), ("failed", {"error": "x"})],
        )
        before = _log_snapshot(db_session)
        with pytest.raises(MissingExternalReference):
            extract_context(db_session, eid)
        assert _log_snapshot(db_session) == before

    def test_rows_unchanged_on_unmappable_path(self, db_session):
        # §17: a missing chain leaves OTHER chains intact.
        other = uuid.uuid4()
        _seed_chain(db_session, other, rows=_shuffle_rows())
        before = _log_snapshot(db_session)
        with pytest.raises(UnmappableExecutionId):
            extract_context(db_session, uuid.uuid4())
        assert _log_snapshot(db_session) == before

    def test_no_insert_update_delete(self, db_session):
        # §16: nothing staged to write after extraction.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        extract_context(db_session, eid)
        _assert_session_clean(db_session)

    def test_extract_never_commits(self, db_session, monkeypatch):
        # §16: read-only means NO COMMIT. Patch commit to explode; extraction must
        # still return without triggering it.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())

        def _boom():
            raise AssertionError("extract_context must not COMMIT (spec §16)")

        monkeypatch.setattr(db_session, "commit", _boom)
        assert extract_context(db_session, eid).adapter == "shuffle"

    def test_no_new_execution_log_row(self, db_session):
        # §16 / §18.22: extraction never CREATES an execution_log row.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        count_before = len(_all_log_rows(db_session))
        extract_context(db_session, eid)
        assert len(_all_log_rows(db_session)) == count_before


# ---------------------------------------------------------------------------
# §18 item 3 — correlation REUSES 3.4.4-C (no second existence query)
# ---------------------------------------------------------------------------
class TestCorrelationReuse:
    def test_03_correlation_reused_via_spy(self, db_session, monkeypatch):
        # §18.3 / §3: extract_context delegates the existence gate to
        # correlate_execution — called EXACTLY once with (session, execution_id).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        calls = []
        real = correlate_execution

        def _spy(session, execution_id):
            calls.append((session, execution_id))
            return real(session, execution_id)

        monkeypatch.setattr(reconcile_module, "correlate_execution", _spy)
        ctx = extract_context(db_session, eid)
        assert len(calls) == 1
        assert calls[0][0] is db_session
        assert calls[0][1] == eid
        assert ctx.adapter == "shuffle"

    def test_unmappable_is_never_bound_by_b(self):
        # §3 / §22: B does NOT import/raise UnmappableExecutionId itself — it can
        # only surface from 3.4.4-C. (Docstring-immune AST.)
        _, names, _, _ = _imported_reconcile()
        assert "UnmappableExecutionId" not in names

    def test_existence_gate_call_is_present_in_source(self):
        # §3: the mandated reuse call is literally present.
        source = inspect.getsource(reconcile_module)
        assert "correlate_execution(session, execution_id)" in source


# ---------------------------------------------------------------------------
# §2 / §13 — AST import boundary (exact allowlist == nothing forbidden)
# ---------------------------------------------------------------------------
class TestImportBoundary:
    def test_modules_are_an_exact_allowlist(self):
        modules, _, _, _ = _imported_reconcile()
        assert modules == ALLOWED_MODULES

    def test_names_are_an_exact_allowlist(self):
        _, names, _, _ = _imported_reconcile()
        assert names == ALLOWED_NAMES

    def test_funcs_are_an_exact_allowlist(self):
        _, _, funcs, _ = _imported_reconcile()
        assert funcs == ALLOWED_FUNCS

    def test_classes_are_an_exact_allowlist(self):
        _, _, _, classes = _imported_reconcile()
        assert classes == ALLOWED_CLASSES

    def test_executions_import_is_registry_only(self):
        # §13: the ONLY app.services.executions.* import is the registry (for the
        # ADAPTER_NAMES vocabulary) — never the dispatch service / base / an adapter.
        modules, _, _, _ = _imported_reconcile()
        executions = {m for m in modules if m.startswith("app.services.executions")}
        assert executions == {"app.services.executions.registry"}

    def test_no_forbidden_module_fragments(self):
        modules, _, _, _ = _imported_reconcile()
        for module in modules:
            for fragment in FORBIDDEN_MODULE_FRAGMENTS:
                assert fragment not in module, f"{module} must not import {fragment}"

    def test_no_forbidden_names(self):
        _, names, _, _ = _imported_reconcile()
        for name in names:
            assert name not in FORBIDDEN_NAMES

    def test_no_fastapi_import(self):
        # §15 / §2: the domain layer is transport-agnostic (HTTP lives in the router).
        modules, names, _, _ = _imported_reconcile()
        assert not any(m.startswith("fastapi") for m in modules)
        assert "HTTPException" not in names


# ---------------------------------------------------------------------------
# §18 items 18-24 — no external side-capabilities (AST + runtime proofs)
# ---------------------------------------------------------------------------
class TestNoSideCapabilities:
    def test_18_no_http_transport(self):
        # §18.18 / §2 / §15: no HTTP client in the import surface.
        modules, _, _, _ = _imported_reconcile()
        assert not any(f in m for m in modules for f in ("httpx", "requests", "urllib"))
        assert not any("app.integrations" in m for m in modules)

    def test_19_no_read_adapter_invocation(self):
        # §18.19 / §2: no read-adapter registry/request/client, and no .read( call.
        modules, names, _, _ = _imported_reconcile()
        assert not any("app.services.manual_reconcile" in m for m in modules)
        for forbidden in ("ReadAdapterRegistry", "AdapterReadRequest", "FakeReadAdapter", "read_adapter"):
            assert forbidden not in names
        assert ".read(" not in inspect.getsource(reconcile_module)

    def test_20_no_mapping(self):
        # §18.20 / §2: B never maps an external_state onto an outcome word.
        _, names, _, _ = _imported_reconcile()
        assert "normalize_external_state" not in names
        assert "validate_observation" not in names
        source = inspect.getsource(reconcile_module)
        assert "normalize_external_state" not in source

    def test_21_no_outcome_persistence(self, db_session):
        # §18.21 / §2: no Outcome Fact is imported, constructed, or written.
        _, names, _, _ = _imported_reconcile()
        assert "ExecutionOutcome" not in names
        assert "ExecutionOutcome(" not in inspect.getsource(reconcile_module)
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        extract_context(db_session, eid)
        with pytest.raises(NotImplementedError):
            reconcile_execution(db_session, eid, "exec-op")
        assert _outcome_count(db_session) == 0

    def test_22_no_execution_dispatch(self, db_session):
        # §18.22 / §2: no executor/dispatch import; no new execution_log row.
        _, names, _, _ = _imported_reconcile()
        for forbidden in ("execute_response", "compensate_response", "ResponseExecutor", "create_executor"):
            assert forbidden not in names
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        before = len(_all_log_rows(db_session))
        extract_context(db_session, eid)
        assert len(_all_log_rows(db_session)) == before

    def test_23_no_retry(self):
        # §18.23 / §2: B never retries.
        modules, names, funcs, _ = _imported_reconcile()
        assert not any("retry" in m.lower() for m in modules)
        assert not any("retry" in n.lower() for n in names)
        assert not any("retry" in f.lower() for f in funcs)

    def test_24_no_compensation(self):
        # §18.24 / §2: B never compensates.
        modules, names, funcs, _ = _imported_reconcile()
        assert not any("compensat" in m.lower() for m in modules)
        assert not any("compensat" in n.lower() for n in names)
        assert not any("compensat" in f.lower() for f in funcs)

    def test_no_reconciliation_failed_produced(self, db_session):
        # §23: there is NO read attempt in B, so NO outcome word — least of all
        # reconciliation_failed — is ever produced (behavioural, docstring-immune).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        with pytest.raises(NotImplementedError):
            reconcile_execution(db_session, eid, "exec-op")
        rows = list(db_session.scalars(select(ExecutionOutcome)))
        assert rows == []
        assert all(r.outcome_status not in OUTCOME_STATUSES for r in rows)


# ---------------------------------------------------------------------------
# §12 — CorrelatedExecutionContext is a pure read-only structure
# ---------------------------------------------------------------------------
class TestContextPurity:
    def test_context_fields_are_exact(self):
        # §12: exactly execution_id / adapter / external_reference — nothing more.
        assert set(CorrelatedExecutionContext.__slots__) == {
            "execution_id",
            "adapter",
            "external_reference",
        }

    def test_context_is_frozen(self, db_session):
        # §12: the extracted context is immutable evidence.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        ctx = extract_context(db_session, eid)
        with pytest.raises(Exception):
            ctx.adapter = "wazuh"  # type: ignore[misc]
        assert ctx.adapter == "shuffle"

    def test_context_carries_no_outcome_status(self, db_session):
        # §12: no derived state / outcome word rides along.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        ctx = extract_context(db_session, eid)
        assert not hasattr(ctx, "outcome_status")
        assert not hasattr(ctx, "derived_outcome_status")
        for word in OUTCOME_STATUSES:
            assert not hasattr(ctx, word)

    def test_context_carries_no_credential(self, db_session):
        # §12: no API credential / operator token / callback token.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        ctx = extract_context(db_session, eid)
        for attr in ("api_key", "authorization", "token", "callback_token", "operator", "credential"):
            assert not hasattr(ctx, attr)


# ---------------------------------------------------------------------------
# §19 / §20 / §21 — API mapping + the client-override security invariant
# ---------------------------------------------------------------------------
class TestApiCorrelationMapping:
    def test_valid_reference_chain_is_501(self, client, db_session, operators):
        # §20: a correlated, reference-bearing chain reaches the pipeline and stops
        # at an HONEST 501 (no read adapter yet) — NEVER a 200 accepted.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        r = client.post(_url(str(eid)), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 501
        assert r.status_code != 200
        assert r.json()["detail"] == "manual reconcile not yet implemented"
        assert r.json().get("accepted") is not True

    def test_mock_chain_is_501_not_422(self, client, db_session, operators):
        # §14: mock (adapter recognized, reference None) is NOT a MissingExternal
        # Reference — it reaches the same honest 501; A2-C decides capability.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[("requested", {"executor": "mock"}), ("succeeded", {"dry_run": {}})],
        )
        r = client.post(_url(str(eid)), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 501

    def test_missing_reference_chain_is_422(self, client, db_session, operators):
        # §21: a chain with no reconcilable handle -> 422 (MissingExternalReference),
        # static detail, no fact.
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "shuffle"}),
                ("dispatched", {"executor": "shuffle"}),
                ("failed", {"error": "timeout"}),
            ],
        )
        r = client.post(_url(str(eid)), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 422
        assert r.json()["detail"] == "reconcile validation failed"
        assert _outcome_count(db_session) == 0

    def test_nonexistent_and_non_uuid_404_are_uniform(self, client, operators):
        # §4 / §21: a well-formed UUID with no chain AND a malformed id both -> the
        # SAME uniform static 404 (a caller cannot distinguish format from absence).
        absent = client.post(_url(str(uuid.uuid4())), json={}, headers=_auth("tok-exec"))
        malformed = client.post(_url("not-a-uuid"), json={}, headers=_auth("tok-exec"))
        assert absent.status_code == 404
        assert malformed.status_code == 404
        assert absent.json()["detail"] == malformed.json()["detail"] == "execution correlation failed"

    def test_501_and_422_write_nothing(self, client, db_session, operators):
        # §16 / §25: neither the honest 501 nor the 422 writes an Outcome Fact or a
        # new execution_log row.
        ok = uuid.uuid4()
        _seed_chain(db_session, ok, rows=_shuffle_rows())
        bad = uuid.uuid4()
        _seed_chain(db_session, bad, rows=[("requested", {"executor": "wazuh"}), ("failed", {})])
        log_before = _log_snapshot(db_session)
        client.post(_url(str(ok)), json={}, headers=_auth("tok-exec"))
        client.post(_url(str(bad)), json={}, headers=_auth("tok-exec"))
        assert _outcome_count(db_session) == 0
        assert _log_snapshot(db_session) == log_before

    def test_19_client_cannot_smuggle_adapter_or_reference(self, client, db_session, operators):
        # §19 — THE security invariant: a body claiming {"adapter": "wazuh",
        # "external_reference": "attacker-controlled"} is a 422 at the EMPTY schema
        # (extra="forbid") and never perturbs history; the platform still extracts
        # the HISTORICAL shuffle adapter + handle.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows("sf-historical-real"))
        before = _log_snapshot(db_session)
        r = client.post(
            _url(str(eid)),
            json={"adapter": "wazuh", "external_reference": "attacker-controlled"},
            headers=_auth("tok-exec"),
        )
        assert r.status_code == 422  # rejected at the boundary, before the pipeline
        assert _log_snapshot(db_session) == before  # history untouched
        ctx = extract_context(db_session, eid)
        assert ctx.adapter == "shuffle"  # never the client's "wazuh"
        assert ctx.external_reference == "sf-historical-real"  # never "attacker-controlled"

    def test_19_historical_adapter_wins_over_client(self, db_session):
        # §19 (service layer): with a shuffle chain in history, extraction yields
        # shuffle + the historical handle no matter what a caller might have wanted;
        # there is no parameter through which a client value could enter.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows("sf-truth"))
        ctx = extract_context(db_session, eid)
        assert (ctx.adapter, ctx.external_reference) == ("shuffle", "sf-truth")
