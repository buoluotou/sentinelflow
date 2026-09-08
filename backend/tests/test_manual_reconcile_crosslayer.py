"""3.4.5-A2-F Manual Reconcile — CROSS-LAYER FINAL GATE (platform-side seal).

A2-F adds NO new business code. It is the FINAL cross-layer / security / invariant
gate that proves the WHOLE 3.4.5-A platform seam works END TO END over the REAL
production stack::

    Operator Auth (real authenticate_operator dependency)
        -> Correlation (real correlate_execution)
        -> Reference Extraction (real extract_context)
        -> ReadAdapterRegistry (real A1 registry)
        -> Read Attempt (test-injected FakeReadAdapter)
        -> SUCCESS -> ExternalObservation -> validate_observation -> map_external_state
                   -> ExecutionOutcome INSERT -> derive_outcome_state
        -> FAILURE -> reconciliation_failed -> ExecutionOutcome INSERT

THE DISTINCTION FROM A2-E (spec §二十七 / §二十八). A2-E pinned the two edges by
calling the SERVICE function ``reconcile_execution(db, eid, operator, registry)``
directly, so its HTTP-level tests could only reach the REJECTIONS the EMPTY
production registry allows (401 / 403 / 404 / 422) — a SUCCESS or a read-FAILURE
200 could never be driven over HTTP without a reader. A2-F CLOSES that gap: it
drives BOTH 200 exits (Wazuh success -> confirmed_success AND a fake-reader
timeout -> reconciliation_failed) through the REAL HTTP -> FastAPI -> router ->
service -> validation -> mapping -> persistence -> DB pipeline, and reads the
committed fact back with a FRESH SELECT. It never inserts an Outcome ORM row
directly to fake an end-to-end result (spec §二十八).

THE ONE TEST-INJECTION SEAM (and why it is legitimate). The router calls
``reconcile_execution(db, execution_uuid, authenticated.name)`` with NO registry
argument, so the service resolves ``default_read_adapter_registry()`` AT CALL TIME
(``manual_reconcile.py`` L366) — a module-global name bound by ``from ... import``
at L130-135. Re-binding THAT name (``reconcile_module.default_read_adapter_registry``)
to a factory returning ``ReadAdapterRegistry([fake])`` is therefore the ONLY way to
drive a reader through the real stack. It is:

  * TEST-ONLY + auto-restored by ``monkeypatch`` — production code is UNCHANGED
    (spec §二十五), no architecture refactor (spec §三十一);
  * NOT a global mutation of the production default — the real
    ``default_read_adapter_registry()`` stays EMPTY (``TestProductionRegistryEmpty``
    re-proves it after every injection is torn down, spec §十九);
  * the designed seam — the FakeReadAdapter is test-injected (spec §二十八), while
    EVERY other layer (auth, correlation, extraction, registry, validation, mapping,
    persistence, derivation, DB) is the REAL production pipeline.

TWO FAILURE BOUNDARIES, SIDE BY SIDE (spec §三). Case A: NO reader (the empty
production registry) -> ``UnsupportedAdapterRead`` -> 404 -> ZERO facts. Case B: a
reader EXISTS and ``read()`` fails in transit -> ``reconciliation_failed`` -> 200 ->
+1 fact. ``TestFailureBoundaryAandB`` proves they are DISTINCT semantics, never
conflated (a capability gap is NOT a read failure).

HONEST CONCURRENCY CAVEAT (spec §二十三). The TestClient and ``db_session`` share ONE
SQLite StaticPool Session/connection and are NOT thread-safe, so
``TestConcurrencySimulation`` does NOT spawn real threads and does NOT claim to
validate production PostgreSQL concurrency. It is an APPLICATION-LEVEL concurrency
SIMULATION: two interleaved reconcile arrivals (both orders) asserting the
invariants that MUST hold — both facts retained, historical rows immutable, derived
state deterministic (order-independent), no session corruption, no retry.

TEST-ONLY GATE. This file changes NO production module; it re-proves the frozen
invariants (append-only, ExecutionLog read-only, Outcome historical immutability,
O5 dispatch independence, credential/identity isolation, no retry, no execution, no
webhook coupling, rollback -> zero partial fact, HTTP semantics) over the REAL
cross-layer stack, so the whole 3.4.5-A platform side can be sealed.
"""
import ast
import dataclasses
import inspect
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.models import (
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    ExecutionLog,
    ExecutionOutcome,
)
from app.schemas.reconcile import MANUAL_RECONCILE_SOURCE, ManualReconcileResponse
from app.services.manual_reconcile import (
    AdapterReadRequest,
    AdapterReadResult,
    ReadAdapter,
    ReadAdapterRegistry,
    ReadTransportError,
    UnsupportedAdapterRead,
    default_read_adapter_registry,
)
from app.services.outcomes import manual_persist as persist_module
from app.services.outcomes import manual_reconcile as reconcile_module
from app.services.outcomes.derivation import derive_outcome_state

#: Fixed clock for seeding the DISPATCH chain (execution_log.created_at). OUTCOME
#: facts use the real ``datetime.now`` (the service stamps ``observed_at`` with the
#: server clock at reconcile time) unless a test supplies an explicit external time.
NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)

#: The reconcile path template (execution_id is a PATH param).
RECONCILE = "/api/v1/executions/{eid}/reconcile"

#: Operator identities + tokens for the multi-role RBAC matrix (spec §五). The
#: reconcile HUMAN recorder is ``exec-op`` (executor); ``view-op`` (viewer) is the
#: authenticated-but-not-authorized 403 case; ``admin-op`` (admin) also may execute.
#: NONE is the dispatch chain's operator (``ops-1``) and NONE is the webhook machine
#: domain (``adapter:...``).
OPERATOR = "exec-op"
VIEWER = "view-op"
ADMIN = "admin-op"
EXEC_TOKEN = "tok-exec"
VIEWER_TOKEN = "tok-viewer"
ADMIN_TOKEN = "tok-admin"

#: G1-C / B0 §15.4 — the TEST-ONLY fake adapter is the platform success-pipeline
#: vehicle for the Manual Reconcile CROSS-LAYER stack too. The real Wazuh vocabulary
#: is now EMPTY / fail-closed, so NO production adapter can carry a success fact over
#: HTTP; the ``fake_read_adapter`` conftest fixture injects this identity's vocabulary
#: AND its ``_EXTERNAL_REFERENCE_KEYS`` handle, so a migrated success test is a PURE
#: identity swap (chain executor + reader name), NEVER a reopening of the real Wazuh
#: vocabulary. The rejection / read-failure / 404 / 401 / 403 proofs below stay on the
#: real production adapters (wazuh / shuffle) — those paths never reach the emptied
#: vocabulary (a transport failure or a capability gate is decided before mapping).
FAKE = "fakesuccess"

#: A message LOADED with things that must NEVER reach a fact, a response, a log or an
#: exception string (spec §十 / §二十二). If any path did ``str(exc)`` / echoed
#: ``raw_evidence``, these substrings would surface — the hygiene tests assert they
#: do not, over the REAL HTTP body.
SECRECY_MESSAGE = (
    "read failed: token=SUPER_SECRET_TOKEN api_key=AKIAIOSFODNN7EXAMPLE "
    "Authorization: Bearer eyJhbGciOiJKV1Qi password=hunter2"
)
SECRET_SUBSTRINGS = (
    "SUPER_SECRET_TOKEN",
    "AKIAIOSFODNN7EXAMPLE",
    "Authorization",
    "Bearer",
    "hunter2",
    "api_key",
    "password",
)

#: The SUCCESS mapping-evidence detail shape and the FAILURE detail shape (A2-D).
#: Disjoint: a success fact NEVER carries ``failure_category`` and a failure fact
#: NEVER carries the mapping evidence — proving the failure edge bypasses
#: ``map_external_state`` even over the full HTTP stack.
SUCCESS_DETAIL_KEYS = {
    "adapter",
    "external_reference",
    "observed_state",
    "normalized_state",
    "outcome_status",
    "mapping_reason",
}
FAILURE_DETAIL_KEYS = {"adapter", "external_reference", "failure_category", "reason"}


def _url(eid: str) -> str:
    return RECONCILE.format(eid=eid)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _post(client, eid, *, token=EXEC_TOKEN, body=None):
    """One reconcile POST over the REAL TestClient -> FastAPI stack. The body is the
    EMPTY object by default (spec §二十二); a smuggling test passes an explicit body."""
    return client.post(
        _url(str(eid)), json=body if body is not None else {}, headers=_auth(token)
    )


# ---------------------------------------------------------------------------
# test-only FakeReadAdapter (spec §二十八) — NEVER a production reader and NEVER
# globally registered: it enters ONLY the test registry that ``_inject_registry``
# builds. It has ONLY ``name`` + ``read`` (no execute / compensate / dispatch /
# trigger verb) and performs NO I/O: ``read`` raises the primed transport error (the
# failure edge) or returns a canned ``AdapterReadResult`` (the success edge). It
# records its call count + requests so tests prove ``read()`` ran EXACTLY once
# (spec §十一) or NEVER (the rejection gates short-circuit before the pipeline).
# ---------------------------------------------------------------------------
def _result(external_state, *, observed_at=None, raw_evidence=None):
    return AdapterReadResult(
        external_state=external_state,
        observed_at=observed_at,
        raw_evidence=raw_evidence if raw_evidence is not None else {},
    )


class FakeReadAdapter(ReadAdapter):
    def __init__(self, name="wazuh", *, result=None, error=None):
        self._name = name
        self._result = result if result is not None else _result("success")
        self._error = error
        self.requests: list[AdapterReadRequest] = []
        self.call_count = 0

    @property
    def name(self) -> str:
        return self._name

    def read(self, request: AdapterReadRequest) -> AdapterReadResult:
        self.call_count += 1
        self.requests.append(request)
        if self._error is not None:
            raise self._error
        return self._result

    @property
    def last_request(self) -> AdapterReadRequest:
        return self.requests[-1]


def _inject_registry(monkeypatch, *fakes):
    """THE cross-layer test seam (spec §二十七 / §二十八). Re-bind the service module's
    ``default_read_adapter_registry`` name — the module-global that
    ``reconcile_execution`` resolves AT CALL TIME when the router passes no registry —
    to a factory returning a test registry holding ``fakes``. This is the ONLY way to
    drive a reader through the REAL HTTP -> router -> service -> validate -> map ->
    persist -> DB stack. TEST-ONLY (auto-restored), NOT a global mutation of the
    production default (which stays EMPTY), NO production code touched."""
    registry = ReadAdapterRegistry(list(fakes))
    monkeypatch.setattr(
        reconcile_module, "default_read_adapter_registry", lambda: registry
    )
    return registry


# ---------------------------------------------------------------------------
# seeding + snapshot helpers (mirror the sealed A2-C/A2-D/A2-E files; the chain must
# be a valid execute chain so correlate_execution accepts it — ONE fresh approval per
# execute chain, the frozen partial-unique-index discipline).
# ---------------------------------------------------------------------------
def _seed_approval(db_session) -> AIResponseApproval:
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
    """One execute chain from ``[(decision, detail), ...]`` in CHRONOLOGICAL order.
    The dispatch ``operator`` (``ops-1``) is DELIBERATELY distinct from the reconcile
    ``OPERATOR`` (``exec-op``) so the identity-isolation tests prove the fact's
    operator is the reconcile human, never inherited from the dispatch log."""
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


def _shuffle_rows(reference="sf-exec-abc123"):
    return [
        ("requested", {"executor": "shuffle"}),
        ("dispatched", {"executor": "shuffle"}),
        ("succeeded", {"external_execution_id": reference, "workflow_id": "wf-tpl-1"}),
    ]


def _wazuh_rows(reference="wazuh-cmd-abc123", *, terminal_decision="succeeded"):
    """A WAZUH execute chain whose terminal row carries the ``command_id`` handle.
    ``terminal_decision`` is parametrizable for the O5 dispatch-independence proof
    (spec §八): the dispatch word does NOT decide the outcome — the READ + 3.4.3-B
    mapping does."""
    return [
        ("requested", {"executor": "wazuh"}),
        ("dispatched", {"executor": "wazuh"}),
        (terminal_decision, {"command_id": reference}),
    ]


def _wazuh_rows_no_reference():
    """A WAZUH chain with NO ``command_id`` on its terminal row: the adapter identity
    is present but the external handle is absent, so ``extract_context`` raises
    ``MissingExternalReference`` BEFORE the registry is consulted -> 422 (spec §五)."""
    return [
        ("requested", {"executor": "wazuh"}),
        ("dispatched", {"executor": "wazuh"}),
        ("failed", {"note": "dispatch failed before a command_id was returned"}),
    ]


def _fake_rows(reference="fake-cmd-abc123", *, terminal_decision="succeeded"):
    """G1-C / B0 §15.4 — a TEST-ONLY fake-adapter execute chain mirroring
    ``_wazuh_rows`` but keyed on the fake identity: the requested/dispatched rows
    carry ``executor=fakesuccess`` (so ``_extract_adapter`` -> ``registry.get`` ->
    ``map_external_state`` all see the fake over the REAL HTTP stack) and the terminal
    row carries the ``command_id`` handle the ``fake_read_adapter`` fixture registers
    in ``_EXTERNAL_REFERENCE_KEYS``. This is the platform success-pipeline vehicle now
    that the real Wazuh vocabulary is empty/refused. ``terminal_decision`` stays
    parametrizable for the O5 dispatch-independence proof."""
    return [
        ("requested", {"executor": FAKE}),
        ("dispatched", {"executor": FAKE}),
        (terminal_decision, {"command_id": reference}),
    ]


def _seed_historical_outcome(
    db_session,
    execution_id,
    *,
    status="confirmed_success",
    source="webhook",
    operator="adapter:wazuh",
    hours_ago=1,
    observed_at=None,
):
    """A PRIOR Outcome Fact for the same execution (spec §六 / §七 / §十五). Seeded as a
    ``webhook`` fact by default to prove the manual_reconcile append COEXISTS with a
    different source and never overwrites it. ``observed_at`` defaults to a REAL past
    server time; a derivation test may pin it explicitly."""
    fact = ExecutionOutcome(
        execution_id=execution_id,
        outcome_status=status,
        source=source,
        operator=operator,
        observed_at=observed_at
        if observed_at is not None
        else datetime.now(timezone.utc) - timedelta(hours=hours_ago),
        detail={"external_state": "completed", "note": "historical"},
    )
    db_session.add(fact)
    db_session.commit()
    return fact


def _fact_snapshot(fact):
    return (
        fact.id,
        fact.outcome_status,
        fact.source,
        fact.operator,
        fact.observed_at,
        json.dumps(fact.detail, sort_keys=True),
    )


def _facts(db_session, execution_id):
    return list(
        db_session.scalars(
            select(ExecutionOutcome).where(ExecutionOutcome.execution_id == execution_id)
        )
    )


def _only_fact(db_session, execution_id):
    rows = _facts(db_session, execution_id)
    assert len(rows) == 1, f"expected exactly one fact, got {len(rows)}"
    return rows[0]


def _outcome_count(db_session):
    return len(list(db_session.scalars(select(ExecutionOutcome))))


def _all_log_rows(db_session):
    return list(db_session.scalars(select(ExecutionLog)))


def _log_snapshot(db_session):
    """FULL execution_log content snapshot — EVERY column spec §十四 names (id,
    execution_id, approval_id, decision, direction, action, target,
    compensates_execution_id, operator, detail, created_at). JSON-canonicalized, keyed
    by id. The whole F flow must leave this byte-identical (spec §十四 / §八)."""
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
                r.compensates_execution_id,
                r.operator,
                json.dumps(r.detail, sort_keys=True),
                r.created_at,
            )
            for r in _all_log_rows(db_session)
        ),
        key=lambda t: t[0],
    )


def _import_surface(module):
    """AST import surface of ONE module (docstring-immune — mirrors the sealed A2-D /
    A2-E probe). Returns (imported-modules, imported-names)."""
    tree = ast.parse(inspect.getsource(module))
    modules, names = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                modules.add(node.module)
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
    return modules, names


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def operators(monkeypatch):
    """Multi-role operator registry via OPERATORS_JSON (the 3.3.1 harness) for the
    cross-layer RBAC matrix. The conftest autouse fixture resets the module-level
    registry around every test, so the monkeypatched config always takes effect and
    ``authenticate_operator`` resolves executor / viewer / admin on the real stack."""
    monkeypatch.setattr(
        settings,
        "OPERATORS_JSON",
        json.dumps(
            [
                {"token": EXEC_TOKEN, "name": OPERATOR, "role": "executor"},
                {"token": VIEWER_TOKEN, "name": VIEWER, "role": "viewer"},
                {"token": ADMIN_TOKEN, "name": ADMIN, "role": "admin"},
            ]
        ),
    )


# ===========================================================================
# spec §二十七 / §二十八 — THE CROSS-LAYER HTTP -> DB SUCCESS PATH
# ===========================================================================
class TestHttpToDbSuccess:
    """The flagship A2-F proof (spec §二十七): a read SUCCESS driven through the REAL
    HTTP -> FastAPI -> Operator Auth -> Correlation -> Reference Extraction ->
    Registry -> FakeReadAdapter -> validate_observation -> map_external_state ->
    ExecutionOutcome INSERT -> DB pipeline, read back with a FRESH SELECT. This is
    what A2-E could NOT do at the HTTP layer (its registry was empty).

    G1-C / B0 §15.4: the SUCCESS vehicle is the TEST-ONLY fake adapter — the real
    Wazuh vocabulary is now EMPTY/refused (see TestRejectedMatrix's reversal), so the
    platform success pipeline is proven on the fake identity, NEVER by reopening Wazuh.
    """

    pytestmark = pytest.mark.usefixtures("fake_read_adapter")

    def test_http_fake_success_to_confirmed_success_in_db(
        self, client, operators, db_session, monkeypatch
    ):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        log_before = _log_snapshot(db_session)
        assert _outcome_count(db_session) == 0
        fake = FakeReadAdapter(FAKE, result=_result("success"))
        _inject_registry(monkeypatch, fake)

        r = _post(client, eid)

        # HTTP envelope (spec §二十一): 200 + accepted=true.
        assert r.status_code == 200
        body = r.json()
        assert body["accepted"] is True
        assert body["outcome_status"] == "confirmed_success"
        assert body["source"] == MANUAL_RECONCILE_SOURCE
        assert body["adapter"] == FAKE
        assert body["execution_id"] == str(eid)
        assert fake.call_count == 1  # ONE read over the full stack (spec §十一)
        # The fact is REALLY in the DB — a fresh SELECT round-trip, NOT the response
        # echo (spec §二十八: never a direct ORM insert faking end-to-end).
        fact = _only_fact(db_session, eid)
        assert fact.outcome_status == "confirmed_success"
        assert fact.source == MANUAL_RECONCILE_SOURCE
        assert fact.operator == OPERATOR  # the authenticated HUMAN, server-fixed
        assert set(fact.detail) == SUCCESS_DETAIL_KEYS
        assert fact.detail["observed_state"] == "success"
        # The dispatch log is byte-identical (spec §十四).
        assert _log_snapshot(db_session) == log_before

    def test_http_fake_running_to_pending_in_db(
        self, client, operators, db_session, monkeypatch
    ):
        # spec §四: an in-progress external effect -> pending over the real stack.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("running")))

        r = _post(client, eid)

        assert r.status_code == 200
        assert r.json()["outcome_status"] == "pending"
        assert _only_fact(db_session, eid).outcome_status == "pending"

    def test_http_fake_unknown_to_unknown_in_db(
        self, client, operators, db_session, monkeypatch
    ):
        # spec §四: a RECOGNIZED-but-ambiguous state -> unknown (the legitimate unknown,
        # NOT the forbidden "unrecognized -> unknown" downgrade). G1-C: the real Wazuh
        # vocabulary is empty, so this legitimate-unknown proof rides the fake adapter.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("unknown")))

        r = _post(client, eid)

        assert r.status_code == 200
        assert r.json()["outcome_status"] == "unknown"
        assert _only_fact(db_session, eid).outcome_status == "unknown"

    def test_http_response_body_matches_persisted_fact(
        self, client, operators, db_session, monkeypatch
    ):
        # spec §二十二: the response envelope and the DB fact AGREE on every shared
        # field — the response is a faithful view of the persisted fact, never a
        # separately fabricated verdict.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))

        body = _post(client, eid).json()
        fact = _only_fact(db_session, eid)

        assert body["outcome_status"] == fact.outcome_status == "confirmed_success"
        assert body["source"] == fact.source == MANUAL_RECONCILE_SOURCE
        assert body["adapter"] == fact.detail["adapter"] == FAKE
        assert body["execution_id"] == str(fact.execution_id)
        # derived_outcome_status is COMPUTED on read (never stored) — with one fact it
        # equals that fact's own status.
        assert body["derived_outcome_status"] == "confirmed_success"
        assert "derived_outcome_status" not in fact.detail  # never persisted

    def test_http_success_derivation_reflects_history(
        self, client, operators, db_session, monkeypatch
    ):
        # spec §七: with a historical confirmed_success (2h ago) and a fresh pending
        # read (now), the response's derived_outcome_status is the LATEST observation.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        _seed_historical_outcome(
            db_session, eid, status="confirmed_success", hours_ago=2
        )
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("running")))

        body = _post(client, eid).json()

        assert body["outcome_status"] == "pending"  # THIS observation
        assert body["derived_outcome_status"] == "pending"  # latest (now) wins
        assert len(_facts(db_session, eid)) == 2  # both retained (append-only)


# ===========================================================================
# spec §二十七 — THE CROSS-LAYER HTTP -> DB READ-FAILURE PATH
# ===========================================================================
class TestHttpToDbReadFailure:
    """A FakeReadAdapter whose ``read()`` fails in transit, driven through the REAL
    HTTP -> ... -> DB stack -> ONE ``reconciliation_failed`` fact -> 200 (spec §十七).
    A read failure is NEVER a 500 (reconciliation_failed is itself a legal Outcome
    Fact) and NEVER ``confirmed_failure`` (a mapped external verdict)."""

    @pytest.mark.parametrize(
        "error,expected_category",
        [
            (TimeoutError("simulated timeout"), "timeout"),
            (ConnectionError("simulated connection refused"), "connection_failure"),
            (ReadTransportError("upstream 503", category="transport_error"),
             "transport_error"),
        ],
        ids=["timeout", "connection", "transport"],
    )
    def test_http_read_failure_to_reconciliation_failed_in_db(
        self, client, operators, db_session, monkeypatch, error, expected_category
    ):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        log_before = _log_snapshot(db_session)
        fake = FakeReadAdapter("wazuh", error=error)
        _inject_registry(monkeypatch, fake)

        r = _post(client, eid)

        assert r.status_code == 200  # NOT a 500 (spec §二十一)
        body = r.json()
        assert body["accepted"] is True
        assert body["outcome_status"] == "reconciliation_failed"
        assert body["observed_at_kind"] == "server-observation"
        assert fake.call_count == 1  # ONE read attempt, NO retry (spec §十一)
        fact = _only_fact(db_session, eid)
        assert fact.outcome_status == "reconciliation_failed"
        assert fact.source == MANUAL_RECONCILE_SOURCE
        assert fact.operator == OPERATOR
        assert fact.detail["failure_category"] == expected_category
        assert set(fact.detail) == FAILURE_DETAIL_KEYS
        assert _log_snapshot(db_session) == log_before  # dispatch log untouched

    def test_http_read_failure_never_confirmed_failure(
        self, client, operators, db_session, monkeypatch
    ):
        # A2-D crux over the full stack: could-not-READ is NEVER a MAPPED verdict.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        _inject_registry(
            monkeypatch, FakeReadAdapter("wazuh", error=ConnectionError("refused"))
        )

        body = _post(client, eid).json()

        assert body["outcome_status"] == "reconciliation_failed"
        assert body["outcome_status"] != "confirmed_failure"
        assert "failure_category" in _only_fact(db_session, eid).detail

    def test_http_read_failure_observed_at_is_server_not_external(
        self, client, operators, db_session, monkeypatch
    ):
        # spec §十七 item 5: a read failure has NO trustworthy external timestamp, so
        # the fact time is the SERVER OBSERVATION time, declared as such.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        _inject_registry(
            monkeypatch, FakeReadAdapter("wazuh", error=TimeoutError("t"))
        )

        body = _post(client, eid).json()

        assert body["observed_at_kind"] == "server-observation"
        # the ISO timestamp is parseable and tz-aware (server clock, UTC).
        stamped = datetime.fromisoformat(body["observed_at"])
        assert stamped.tzinfo is not None or body["observed_at"].endswith("Z")


# ===========================================================================
# spec §三 — Case A (no reader) vs Case B (reader + transport failure), SIDE BY SIDE
# ===========================================================================
class TestFailureBoundaryAandB:
    """The two failure boundaries MUST stay distinct (spec §三): Case A has NO read
    attempt (a capability rejection, zero fact); Case B HAS a read attempt that failed
    in transit (reconciliation_failed, one fact). Conflating them would let "no reader
    exists" masquerade as "reader tried and failed"."""

    def test_case_a_no_reader_404_zero_fact(self, client, operators, db_session):
        # Case A: the EMPTY production registry (NO injection) -> UnsupportedAdapterRead
        # -> 404 -> ZERO facts. NOT reconciliation_failed (no read was attempted).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())

        r = _post(client, eid)

        assert r.status_code == 404
        assert r.json()["detail"] == "adapter read unsupported"
        assert _outcome_count(db_session) == 0

    def test_case_b_reader_transport_failure_200_one_fact(
        self, client, operators, db_session, monkeypatch
    ):
        # Case B: a reader EXISTS and read() fails in transit -> reconciliation_failed
        # -> 200 -> +1 fact.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        _inject_registry(
            monkeypatch, FakeReadAdapter("wazuh", error=TimeoutError("t"))
        )

        r = _post(client, eid)

        assert r.status_code == 200
        assert r.json()["outcome_status"] == "reconciliation_failed"
        assert _outcome_count(db_session) == 1

    def test_case_a_and_b_are_distinct_semantics(
        self, client, operators, db_session, monkeypatch
    ):
        # The SAME adapter (wazuh), the SAME chain, but Case A (no reader) and Case B
        # (reader fails) produce DIFFERENT status codes AND different fact counts.
        eid_a = uuid.uuid4()
        _seed_chain(db_session, eid_a, rows=_wazuh_rows())
        r_a = _post(client, eid_a)  # no injection -> empty registry

        eid_b = uuid.uuid4()
        _seed_chain(db_session, eid_b, rows=_wazuh_rows())
        _inject_registry(monkeypatch, FakeReadAdapter("wazuh", error=TimeoutError("t")))
        r_b = _post(client, eid_b)

        assert r_a.status_code == 404 and r_b.status_code == 200
        assert _outcome_count(db_session) == 1  # ONLY Case B wrote a fact
        assert len(_facts(db_session, eid_a)) == 0
        assert len(_facts(db_session, eid_b)) == 1
        assert _only_fact(db_session, eid_b).outcome_status == "reconciliation_failed"


# ===========================================================================
# spec §五 — the COMPLETE rejected matrix over the REAL HTTP stack
# ===========================================================================
class TestRejectedMatrix:
    """Every rejection closes with ZERO Outcome Facts EXCEPT "reader exists + read
    failed" (reconciliation_failed, +1). Each row is a DISTINCT HTTP status and a
    DISTINCT trust boundary that short-circuits BEFORE persistence (spec §五)."""

    def test_auth_failure_401_0fact(self, client, operators, db_session, monkeypatch):
        # An INVALID token -> 401 at the RBAC dependency, BEFORE the body / path / read.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        fake = FakeReadAdapter("wazuh", result=_result("success"))
        _inject_registry(monkeypatch, fake)
        r = _post(client, eid, token="not-a-real-token")
        assert r.status_code == 401
        assert fake.call_count == 0  # auth short-circuits before the read
        assert _outcome_count(db_session) == 0

    def test_viewer_403_0fact(self, client, operators, db_session, monkeypatch):
        # A VIEWER (authenticated, role lacks can_execute) -> 403, BEFORE the pipeline.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        fake = FakeReadAdapter("wazuh", result=_result("success"))
        _inject_registry(monkeypatch, fake)
        r = _post(client, eid, token=VIEWER_TOKEN)
        assert r.status_code == 403
        assert "may not dispatch executions" in r.json()["detail"]
        assert fake.call_count == 0  # RBAC short-circuits before the read
        assert _outcome_count(db_session) == 0

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_admin_may_reconcile_200(self, client, operators, db_session, monkeypatch):
        # can_execute covers admin too -> a successful reconcile (RBAC completeness).
        # G1-C / B0 §15.4: the SUCCESS rides the TEST-ONLY fake adapter (real Wazuh is
        # empty/refused); METHOD-scoped so the sibling 401/403/404/422 refusal proofs
        # stay in PURE production state.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))
        r = _post(client, eid, token=ADMIN_TOKEN)
        assert r.status_code == 200
        assert r.json()["accepted"] is True
        assert _only_fact(db_session, eid).operator == ADMIN  # the admin identity

    def test_correlation_failure_404_0fact(self, client, operators, db_session):
        # An execution_id that maps to NO chain -> UnmappableExecutionId -> uniform 404.
        missing = uuid.uuid4()
        r = _post(client, missing)
        assert r.status_code == 404
        assert r.json()["detail"] == "execution correlation failed"
        assert _outcome_count(db_session) == 0

    def test_missing_reference_422_0fact(self, client, operators, db_session):
        # A wazuh chain with NO command_id -> the reference gate (BEFORE the registry)
        # -> MissingExternalReference -> 422, zero fact.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows_no_reference())
        r = _post(client, eid)
        assert r.status_code == 422
        assert r.json()["detail"] == "reconcile validation failed"
        assert _outcome_count(db_session) == 0

    def test_unsupported_reader_404_0fact(self, client, operators, db_session):
        # A correlated, reference-bearing chain whose adapter has NO reader (empty
        # production registry) -> 404, zero fact (NOT reconciliation_failed).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        r = _post(client, eid)
        assert r.status_code == 404
        assert r.json()["detail"] == "adapter read unsupported"
        assert _outcome_count(db_session) == 0

    def test_unrecognized_state_422_0fact(self, client, operators, db_session, monkeypatch):
        # NEW cross-layer capability: a shuffle read of an UNEVIDENCED state, driven over
        # HTTP via the injected registry -> UnrecognizedExternalState -> 422 -> ZERO facts,
        # NEVER downgraded to unknown. A2-E proved this at the SERVICE level only; F proves
        # it through the full HTTP -> read -> map -> 422 stack.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", result=_result("succeeded"))
        _inject_registry(monkeypatch, fake)
        r = _post(client, eid)
        assert r.status_code == 422
        assert r.json()["detail"] == "reconcile validation failed"
        assert fake.call_count == 1  # the read DID succeed
        assert _outcome_count(db_session) == 0  # mapping refused it

    @pytest.mark.parametrize(
        "state", ["success", "completed", "confirmed", "done", "ok", "running", "unknown"]
    )
    def test_wazuh_former_evidenced_words_now_refused_422_0fact(
        self, client, operators, db_session, monkeypatch, state
    ):
        # G1-C / B0 §15.4 REVERSAL (cross-layer HTTP mirror of the A2-E mapping-file
        # reversal): the real Wazuh vocabulary is now EMPTY, so EVERY former evidenced
        # word — read successfully over the REAL HTTP -> auth -> correlation ->
        # extraction -> registry -> read stack — is refused at the 3.4.3-B mapping with
        # UnrecognizedExternalState -> 422, ZERO Outcome Facts. The read DID succeed
        # (call_count == 1): the refusal is at MAPPING, not transport, so it is NEVER
        # reconciliation_failed and NEVER downgraded to unknown. NO fake fixture — this
        # is the PURE production Wazuh refusal; it is exactly what the old
        # success/running/unknown 200 anchors are reversed into.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        fake = FakeReadAdapter("wazuh", result=_result(state))
        _inject_registry(monkeypatch, fake)
        r = _post(client, eid)
        assert r.status_code == 422
        assert r.json()["detail"] == "reconcile validation failed"
        assert fake.call_count == 1  # the read succeeded; the MAPPING refused
        assert _outcome_count(db_session) == 0

    def test_read_transport_failure_is_the_only_appending_row(
        self, client, operators, db_session, monkeypatch
    ):
        # The matrix's ONE appending row: reader exists + read fails -> reconciliation_failed / +1.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        _inject_registry(monkeypatch, FakeReadAdapter("wazuh", error=TimeoutError("t")))
        r = _post(client, eid)
        assert r.status_code == 200
        assert r.json()["outcome_status"] == "reconciliation_failed"
        assert _outcome_count(db_session) == 1

    def test_malformed_execution_id_404_0fact(self, client, operators, db_session):
        # A malformed path id is indistinguishable from an absent chain -> uniform 404.
        r = client.post(_url("not-a-uuid"), json={}, headers=_auth(EXEC_TOKEN))
        assert r.status_code == 404
        assert r.json()["detail"] == "execution correlation failed"
        assert _outcome_count(db_session) == 0


# ===========================================================================
# spec §六 / §七 — APPEND-ONLY + REPLAY + OUT-OF-ORDER over the REAL HTTP stack
# ===========================================================================
class TestAppendOnlyReplay:
    """spec §六: repeated reconciles INSERT a new row each time (never UPDATE / UPSERT /
    MERGE / DELETE); every historical row stays byte-identical. Driven over HTTP by
    re-injecting a fresh reader per arrival (each POST is a full HTTP -> DB cycle).

    G1-C / B0 §15.4: the arrivals ride the TEST-ONLY fake adapter (the real Wazuh
    vocabulary is empty/refused) so each append is a genuine SUCCESS/pending
    observation, not a refusal — the append-only invariant needs real appended rows."""

    pytestmark = pytest.mark.usefixtures("fake_read_adapter")

    def test_three_arrivals_three_rows_history_immutable(
        self, client, operators, db_session, monkeypatch
    ):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        t1 = datetime.now(timezone.utc) - timedelta(hours=3)
        t2 = datetime.now(timezone.utc) - timedelta(hours=2)
        t3 = datetime.now(timezone.utc) - timedelta(hours=1)

        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("running", observed_at=t1)))
        r1 = _post(client, eid)  # pending @ t1
        snap1 = {_fact_snapshot(f) for f in _facts(db_session, eid)}
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success", observed_at=t2)))
        r2 = _post(client, eid)  # confirmed_success @ t2
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("running", observed_at=t3)))
        r3 = _post(client, eid)  # pending @ t3

        assert (r1.status_code, r2.status_code, r3.status_code) == (200, 200, 200)
        rows = _facts(db_session, eid)
        assert len(rows) == 3  # THREE rows, never deduped / updated
        assert len({f.id for f in rows}) == 3  # three DISTINCT ids
        assert [f.outcome_status for f in sorted(rows, key=lambda o: o.observed_at)] == [
            "pending", "confirmed_success", "pending",
        ]
        # arrival 1's row is byte-identical after arrivals 2 + 3 (append-only).
        assert snap1 <= {_fact_snapshot(f) for f in rows}

    def test_replayed_old_observation_does_not_override_newer(
        self, client, operators, db_session, monkeypatch
    ):
        # spec §七: T1 pending, T2 confirmed_success, then a T1 REPLAY carrying an OLDER
        # observed_at -> the derived state stays confirmed_success (derivation is by
        # observed_at, NOT by arrival order).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        t1 = datetime.now(timezone.utc) - timedelta(hours=3)
        t2 = datetime.now(timezone.utc) - timedelta(hours=1)

        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("running", observed_at=t1)))
        _post(client, eid)  # T1 pending
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success", observed_at=t2)))
        _post(client, eid)  # T2 confirmed_success
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("running", observed_at=t1)))
        r3 = _post(client, eid)  # T1 replay (old timestamp)

        rows = _facts(db_session, eid)
        assert len(rows) == 3
        assert derive_outcome_state(rows) == "confirmed_success"
        assert r3.json()["derived_outcome_status"] == "confirmed_success"

    def test_out_of_order_arrival_derives_by_observed_at(
        self, client, operators, db_session, monkeypatch
    ):
        # spec §七: a newer-timestamped fact arriving FIRST is NOT overridden by an
        # older-timestamped fact arriving SECOND — derivation is observed_at DESC.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        newer = datetime.now(timezone.utc) - timedelta(hours=1)
        older = datetime.now(timezone.utc) - timedelta(hours=5)

        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success", observed_at=newer)))
        _post(client, eid)  # confirmed_success @ newer, arrives FIRST
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("running", observed_at=older)))
        r2 = _post(client, eid)  # pending @ older, arrives SECOND

        rows = _facts(db_session, eid)
        assert len(rows) == 2
        assert derive_outcome_state(rows) == "confirmed_success"  # newer wins despite order
        assert r2.json()["derived_outcome_status"] == "confirmed_success"


# ===========================================================================
# spec §七 — DERIVATION (computed on read, never stored) over HTTP + DB
# ===========================================================================
class TestDerivationCrossLayer:
    """The derived current state is ``derive_outcome_state()`` over ``observed_at DESC,
    id DESC`` — proven over the real HTTP response AND recomputed from the DB facts."""

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_latest_observed_at_wins(self, client, operators, db_session, monkeypatch):
        # G1-C / B0 §15.4: the fresh pending read rides the TEST-ONLY fake adapter (real
        # Wazuh is empty/refused); METHOD-scoped so the sibling wazuh read-failure /
        # ORM-tiebreak derivation proofs stay in PURE production state.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        _seed_historical_outcome(db_session, eid, status="confirmed_success", hours_ago=2)
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("running")))
        body = _post(client, eid).json()
        assert body["derived_outcome_status"] == "pending"  # fresh (now) beats 2h-ago
        assert derive_outcome_state(_facts(db_session, eid)) == "pending"

    def test_same_timestamp_id_desc_tiebreak(self, db_session):
        # equal observed_at -> the HIGHER id wins. UUIDs are not monotonic, so the
        # invariant is "derive == max by (observed_at, id)", whatever that id is.
        eid = uuid.uuid4()
        same = datetime.now(timezone.utc)
        f1 = ExecutionOutcome(
            execution_id=eid, outcome_status="confirmed_success", source="webhook",
            operator="adapter:wazuh", observed_at=same, detail={},
        )
        f2 = ExecutionOutcome(
            execution_id=eid, outcome_status="pending", source=MANUAL_RECONCILE_SOURCE,
            operator=OPERATOR, observed_at=same, detail={},
        )
        db_session.add_all([f1, f2])
        db_session.commit()
        rows = _facts(db_session, eid)
        winner = max(rows, key=lambda o: (o.observed_at, o.id))
        assert derive_outcome_state(rows) == winner.outcome_status

    def test_reconciliation_failed_can_be_derived(
        self, client, operators, db_session, monkeypatch
    ):
        # a read-failure fact is a first-class observation — it CAN be the derived state.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        _seed_historical_outcome(db_session, eid, status="confirmed_success", hours_ago=2)
        _inject_registry(monkeypatch, FakeReadAdapter("wazuh", error=TimeoutError("t")))
        body = _post(client, eid).json()
        assert body["derived_outcome_status"] == "reconciliation_failed"

    def test_historical_facts_preserved_after_derivation(
        self, client, operators, db_session, monkeypatch
    ):
        # spec §十五: deriving a new current state NEVER deletes / overwrites history.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        historical = _seed_historical_outcome(
            db_session, eid, status="confirmed_success", hours_ago=2
        )
        before = _fact_snapshot(historical)
        _inject_registry(monkeypatch, FakeReadAdapter("wazuh", error=TimeoutError("t")))
        _post(client, eid)
        rows = _facts(db_session, eid)
        assert {f.outcome_status for f in rows} == {
            "confirmed_success", "reconciliation_failed",
        }
        still = next(f for f in rows if f.id == historical.id)
        assert _fact_snapshot(still) == before  # byte-identical


# ===========================================================================
# spec §八 — O5 DISPATCH INDEPENDENCE over the REAL HTTP -> DB stack
# ===========================================================================
class TestO5CrossLayer:
    """The outcome is NEVER auto-decided by the dispatch decision; the READ + 3.4.3-B
    mapping decides it, and ``execution_log`` is byte-identical before/after."""

    def test_dispatch_succeeded_plus_read_failure(
        self, client, operators, db_session, monkeypatch
    ):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows(terminal_decision="succeeded"))
        log_before = _log_snapshot(db_session)
        _inject_registry(monkeypatch, FakeReadAdapter("wazuh", error=TimeoutError("t")))
        body = _post(client, eid).json()
        assert body["outcome_status"] == "reconciliation_failed"
        assert _only_fact(db_session, eid).outcome_status == "reconciliation_failed"
        assert _log_snapshot(db_session) == log_before  # dispatch log UNCHANGED

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_dispatch_failed_plus_read_success(
        self, client, operators, db_session, monkeypatch
    ):
        # G1-C / B0 §15.4: the SUCCESS read rides the TEST-ONLY fake adapter (real Wazuh
        # is empty/refused); METHOD-scoped so the sibling wazuh read-failure + dispatch-
        # word-refusal proofs stay in PURE production state.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows(terminal_decision="failed"))
        log_before = _log_snapshot(db_session)
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))
        body = _post(client, eid).json()
        assert body["outcome_status"] == "confirmed_success"  # LEGAL combo (spec §八)
        assert _only_fact(db_session, eid).outcome_status == "confirmed_success"
        assert _log_snapshot(db_session) == log_before
        assert any(r.decision == "failed" for r in _all_log_rows(db_session))

    def test_dispatch_word_is_not_an_external_state(
        self, client, operators, db_session, monkeypatch
    ):
        # The dispatch word "succeeded" is NOT an evidenced external state: a Wazuh read
        # returning "succeeded" (not "success") is REFUSED, never laundered (DISPATCH != OUTCOME).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        _inject_registry(monkeypatch, FakeReadAdapter("wazuh", result=_result("succeeded")))
        r = _post(client, eid)
        assert r.status_code == 422
        assert _outcome_count(db_session) == 0


# ===========================================================================
# spec §九 — IDENTITY ISOLATION (client cannot smuggle adapter/reference/operator/source)
# ===========================================================================
class TestIdentityIsolation:
    """The client can NEVER supply adapter / external_reference / operator / source — all
    come from server-side history / identity. A smuggling body is refused at the schema
    boundary (``extra="forbid"``) BEFORE the pipeline runs (spec §九)."""

    SMUGGLE = {
        "adapter": "attacker",
        "external_reference": "attacker-ref",
        "operator": "admin",
        "source": "webhook",
    }

    def test_smuggled_identity_body_rejected_422(
        self, client, operators, db_session, monkeypatch
    ):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        fake = FakeReadAdapter("wazuh", result=_result("success"))
        _inject_registry(monkeypatch, fake)
        r = _post(client, eid, body=self.SMUGGLE)
        assert r.status_code == 422  # extra="forbid" at the boundary
        assert fake.call_count == 0  # the pipeline NEVER ran
        assert _outcome_count(db_session) == 0  # no smuggled value persisted

    def test_smuggle_does_not_touch_history(
        self, client, operators, db_session, monkeypatch
    ):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        log_before = _log_snapshot(db_session)
        _inject_registry(monkeypatch, FakeReadAdapter("wazuh", result=_result("success")))
        _post(client, eid, body=self.SMUGGLE)
        assert _log_snapshot(db_session) == log_before  # historical adapter/ref/operator intact
        assert _outcome_count(db_session) == 0  # no fact carries the attacker's values

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_operator_and_source_come_from_server_not_body(
        self, client, operators, db_session, monkeypatch
    ):
        # With the legal EMPTY body, operator is the authenticated human and source is
        # manual_reconcile — both server-fixed; adapter/reference come from history.
        # G1-C / B0 §15.4: the SUCCESS rides the TEST-ONLY fake adapter, so the
        # from-history adapter/reference are the fake identity's (still server-side,
        # still NEVER client-supplied); METHOD-scoped so the smuggling-refusal proofs
        # stay in PURE production state.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows(), operator="ops-1")
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))
        _post(client, eid, body={})
        fact = _only_fact(db_session, eid)
        assert fact.operator == OPERATOR == "exec-op"  # from the token, not the body
        assert fact.operator != "ops-1"  # not the dispatch operator
        assert fact.source == MANUAL_RECONCILE_SOURCE  # server-fixed
        assert fact.detail["adapter"] == FAKE  # from history, not the body
        assert fact.detail["external_reference"] == "fake-cmd-abc123"  # from history

    def test_single_smuggled_field_also_rejected(self, client, operators, db_session):
        # Even ONE extra field is a 422 (extra="forbid" is all-or-nothing).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        r = _post(client, eid, body={"operator": "admin"})
        assert r.status_code == 422
        assert _outcome_count(db_session) == 0


# ===========================================================================
# spec §十 — CREDENTIAL ISOLATION (operator token != adapter credential; no secret leaks)
# ===========================================================================
class TestCredentialIsolation:
    """The operator token does authentication/authorization ONLY; the adapter credential
    belongs ONLY to the read adapter. No API key / password / token enters the Outcome
    detail, the DB, the response body, the log, or an exception string (spec §十)."""

    def test_read_request_carries_no_operator_or_credential(
        self, client, operators, db_session, monkeypatch
    ):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        fake = FakeReadAdapter("wazuh", result=_result("success"))
        _inject_registry(monkeypatch, fake)
        _post(client, eid)
        # The AdapterReadRequest has ONLY read-only context — NO operator / credential.
        assert {f.name for f in dataclasses.fields(AdapterReadRequest)} == {
            "execution_id", "adapter", "external_reference",
        }
        req = fake.last_request
        assert req.adapter == "wazuh"
        assert req.external_reference == "wazuh-cmd-abc123"
        assert EXEC_TOKEN not in str(req)  # the operator token never travels to the read
        assert OPERATOR not in (req.adapter, req.external_reference)

    def test_secret_laden_read_failure_never_reaches_db_or_body(
        self, client, operators, db_session, monkeypatch
    ):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        _inject_registry(
            monkeypatch,
            FakeReadAdapter("wazuh", error=ReadTransportError(SECRECY_MESSAGE, category="timeout")),
        )
        r = _post(client, eid)
        assert r.status_code == 200
        fact_blob = json.dumps(_only_fact(db_session, eid).detail)
        for secret in SECRET_SUBSTRINGS:
            assert secret not in fact_blob  # never in the DB
            assert secret not in r.text  # never in the HTTP body

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_secret_laden_raw_evidence_never_reaches_db_or_body(
        self, client, operators, db_session, monkeypatch
    ):
        # G1-C / B0 §15.4: the SUCCESS read (whose raw_evidence must be redacted) rides
        # the TEST-ONLY fake adapter — a redaction proof needs a PERSISTED success fact,
        # which the empty/refused real Wazuh vocabulary can no longer produce.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        _inject_registry(
            monkeypatch,
            FakeReadAdapter(
                FAKE,
                result=_result(
                    "success",
                    raw_evidence={
                        "Authorization": "Bearer SUPER_SECRET_TOKEN",
                        "api_key": "AKIAIOSFODNN7EXAMPLE",
                        "password": "hunter2",
                    },
                ),
            ),
        )
        r = _post(client, eid)
        assert r.status_code == 200
        detail = _only_fact(db_session, eid).detail
        assert set(detail) == SUCCESS_DETAIL_KEYS  # raw_evidence is NOT a key
        fact_blob = json.dumps(detail)
        for secret in SECRET_SUBSTRINGS:
            assert secret not in fact_blob
            assert secret not in r.text

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_operator_token_never_persisted_anywhere(
        self, client, operators, db_session, monkeypatch
    ):
        # G1-C / B0 §15.4: rides the TEST-ONLY fake adapter — this proof reads back a
        # PERSISTED success fact (``_only_fact``), which the empty/refused real Wazuh
        # vocabulary can no longer produce.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))
        r = _post(client, eid)
        assert EXEC_TOKEN not in r.text
        assert EXEC_TOKEN not in json.dumps(_only_fact(db_session, eid).detail)
        assert EXEC_TOKEN not in json.dumps(_log_snapshot(db_session), default=str)


# ===========================================================================
# spec §十一 / §十二 — NO RETRY + NO EXECUTION (AST + runtime-spy double proof)
# ===========================================================================
class TestNoRetryNoExecution:
    """ONE read attempt per reconcile (no retry / backoff / sleep / loop) and NO
    execution / dispatch / compensation / fan-out. Proven by AST (the import surface
    binds no executor / retry) AND a runtime spy (call_count == 1, execution_log
    unchanged, no new dispatch rows) — the double proof spec §十二 recommends."""

    def test_one_read_attempt_over_http(self, client, operators, db_session, monkeypatch):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        fake = FakeReadAdapter("wazuh", result=_result("success"))
        _inject_registry(monkeypatch, fake)
        _post(client, eid)
        assert fake.call_count == 1  # exactly ONE read
        assert len(fake.requests) == 1

    def test_one_read_attempt_on_failure_over_http(
        self, client, operators, db_session, monkeypatch
    ):
        # A transport failure is NOT retried either (spec §十一).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        fake = FakeReadAdapter("wazuh", error=TimeoutError("t"))
        _inject_registry(monkeypatch, fake)
        _post(client, eid)
        assert fake.call_count == 1  # ONE attempt, no retry after failure

    def test_ast_no_executor_retry_compensation(self):
        # AST half: NEITHER the orchestrator NOR the persister binds an executor, a
        # retry / backoff / sleep library, or a compensation.
        for module in (reconcile_module, persist_module):
            modules, names = _import_surface(module)
            for token in ("retry", "tenacity", "backoff", "sleep"):
                assert not any(token in m for m in modules)
                assert not any(token in n for n in names)
            assert not any("compensat" in m for m in modules)
            assert not any("compensat" in n for n in names)
            for forbidden in (
                "ResponseExecutor", "create_executor", "execute_response",
                "compensate_response",
            ):
                assert forbidden not in names
        # the orchestrator binds NOTHING under app.services.executions (sealed A2-B rule).
        recon_modules, _ = _import_surface(reconcile_module)
        assert not any(m.startswith("app.services.executions") for m in recon_modules)

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_runtime_spy_no_dispatch_rows(
        self, client, operators, db_session, monkeypatch
    ):
        # Runtime half: the full HTTP flow adds NO execution_log row and invokes NO
        # executor — the Outcome layer records facts, it never re-enters Dispatch.
        # G1-C / B0 §15.4: rides the TEST-ONLY fake adapter so the flow is a genuine
        # SUCCESS appending exactly ONE Outcome fact (``_outcome_count == 1``) — the
        # empty/refused real Wazuh vocabulary would append zero and mask the spy proof.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        log_before = _log_snapshot(db_session)
        rows_before = len(_all_log_rows(db_session))
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))
        _post(client, eid)
        assert len(_all_log_rows(db_session)) == rows_before  # no new dispatch row
        assert _log_snapshot(db_session) == log_before
        assert _outcome_count(db_session) == 1  # only the Outcome fact was appended


# ===========================================================================
# spec §十三 — NO WEBHOOK COUPLING (two separate ingress trust domains)
# ===========================================================================
class TestNoWebhookCoupling:
    """Manual Reconcile and the webhook are TWO ingress trust domains. The reconcile
    pipeline never uses a callback token, never calls the webhook ingress handler; it
    MAY reuse ONLY the shared persistence vocabulary (``app.services.outcomes.webhook``'s
    ExecutionOutcomeFact + OutcomePersistenceError), which is NOT the ingress."""

    def test_no_webhook_ingress_import(self):
        modules, names = _import_surface(reconcile_module)
        # NOT the webhook INGRESS router / handler / callback-token verifier.
        assert not any(m.endswith("api.v1.webhooks") for m in modules)
        for forbidden in (
            "authenticate_webhook", "verify_callback", "callback_token",
            "WebhookCallbackRequest", "require_callback_token",
        ):
            assert forbidden not in names
        # the shared PERSISTENCE vocabulary IS allowed (it is not the ingress).
        assert "app.services.outcomes.webhook" in modules

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_reconcile_source_is_never_webhook(
        self, client, operators, db_session, monkeypatch
    ):
        # G1-C / B0 §15.4: rides the TEST-ONLY fake adapter — this proof reads back a
        # PERSISTED success fact to check its source/operator, which the empty/refused
        # real Wazuh vocabulary can no longer produce.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))
        _post(client, eid)
        fact = _only_fact(db_session, eid)
        assert fact.source == MANUAL_RECONCILE_SOURCE  # never "webhook"
        assert fact.source != "webhook"
        assert fact.operator == OPERATOR  # a human name
        assert not fact.operator.startswith("adapter:")  # never the machine domain

    def test_callback_token_not_accepted_as_operator(
        self, client, operators, db_session
    ):
        # A webhook-style callback token is NOT an operator credential -> 401 (the two
        # ingress trust domains do not share secrets).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        r = _post(client, eid, token="whsec_callback_token_not_an_operator")
        assert r.status_code == 401
        assert _outcome_count(db_session) == 0


# ===========================================================================
# spec §十四 — ExecutionLog READ-ONLY (full-column snapshot byte-identical)
# ===========================================================================
class TestExecutionLogReadonly:
    """The FULL F flow leaves execution_log byte-identical — EVERY column §十四 names.
    SELECT only, never UPDATE / DELETE."""

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_log_unchanged_over_success_http(
        self, client, operators, db_session, monkeypatch
    ):
        # G1-C / B0 §15.4: this is the SUCCESS-flow log-immutability proof, so it rides
        # the TEST-ONLY fake adapter — the real Wazuh vocabulary is empty/refused and
        # would turn this into a 422 rejection (the log is unchanged either way, so a
        # wazuh vehicle would be a FALSE GREEN that no longer exercises a success).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        before = _log_snapshot(db_session)
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))
        _post(client, eid)
        assert _log_snapshot(db_session) == before

    def test_log_unchanged_over_failure_http(
        self, client, operators, db_session, monkeypatch
    ):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        before = _log_snapshot(db_session)
        _inject_registry(monkeypatch, FakeReadAdapter("shuffle", error=TimeoutError("t")))
        _post(client, eid)
        assert _log_snapshot(db_session) == before

    def test_log_unchanged_over_rejection_http(self, client, operators, db_session):
        # Even a rejection (unsupported reader) leaves the log untouched.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        before = _log_snapshot(db_session)
        _post(client, eid)  # empty production registry -> 404
        assert _log_snapshot(db_session) == before


# ===========================================================================
# spec §十五 — OUTCOME HISTORICAL IMMUTABILITY (only new INSERT)
# ===========================================================================
class TestOutcomeHistoricalImmutability:
    """Existing Outcome Facts are byte-identical after the full flow; only a new INSERT
    is allowed (spec §十五)."""

    # G1-C / B0 §15.4: the new INSERT rides the TEST-ONLY fake adapter (real Wazuh is
    # empty/refused) — the immutability proof needs a genuine appended success fact.
    pytestmark = pytest.mark.usefixtures("fake_read_adapter")

    def test_two_historical_facts_unchanged_after_reconcile(
        self, client, operators, db_session, monkeypatch
    ):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        h1 = _seed_historical_outcome(
            db_session, eid, status="confirmed_success", source="webhook", hours_ago=3
        )
        h2 = _seed_historical_outcome(
            db_session, eid, status="pending", source=MANUAL_RECONCILE_SOURCE,
            operator="exec-op", hours_ago=2,
        )
        before = {_fact_snapshot(h1), _fact_snapshot(h2)}
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))
        _post(client, eid)
        rows = _facts(db_session, eid)
        assert len(rows) == 3  # 2 historical + 1 new
        assert before <= {_fact_snapshot(f) for f in rows}  # both historical byte-identical
        new = [f for f in rows if f.id not in {h1.id, h2.id}]
        assert len(new) == 1
        assert new[0].outcome_status == "confirmed_success"


# ===========================================================================
# spec §十六 — TRANSACTION (rollback -> 500 over the REAL HTTP stack, zero partial fact)
# ===========================================================================
class TestTransactionCrossLayer:
    """Success add -> flush -> commit; a persistence failure on EITHER edge rolls back ->
    OutcomePersistenceError -> the router's 500, never accepted=true, never a partial
    fact. A2-E proved the service-level rollback; F proves the router maps it to 500 END
    TO END over HTTP."""

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_success_commit_failure_500_zero_fact(
        self, client, operators, db_session, monkeypatch
    ):
        # G1-C / B0 §15.4: the SUCCESS edge (whose persistence is made to fail -> 500)
        # rides the TEST-ONLY fake adapter; METHOD-scoped so the sibling Shuffle
        # failure-edge 500 proof stays in PURE production state.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        log_before = _log_snapshot(db_session)
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))

        def _commit_boom():
            raise SQLAlchemyError("simulated commit failure")

        monkeypatch.setattr(db_session, "commit", _commit_boom)
        r = _post(client, eid)
        assert r.status_code == 500
        assert r.json()["detail"] == "reconcile outcome persistence failed"
        assert r.json().get("accepted") is not True
        assert _outcome_count(db_session) == 0  # the flushed INSERT was rolled back
        assert _log_snapshot(db_session) == log_before  # the committed chain survives

    def test_failure_commit_failure_500_zero_fact(
        self, client, operators, db_session, monkeypatch
    ):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        log_before = _log_snapshot(db_session)
        _inject_registry(monkeypatch, FakeReadAdapter("shuffle", error=TimeoutError("t")))

        def _commit_boom():
            raise SQLAlchemyError("simulated commit failure")

        monkeypatch.setattr(db_session, "commit", _commit_boom)
        r = _post(client, eid)
        assert r.status_code == 500
        assert r.json()["detail"] == "reconcile outcome persistence failed"
        assert _outcome_count(db_session) == 0
        assert _log_snapshot(db_session) == log_before

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_no_partial_fact_lingers_after_rollback_http(
        self, client, operators, db_session, monkeypatch
    ):
        # G1-C / B0 §15.4: the good (200) reconcile rides the TEST-ONLY fake adapter, so
        # the commit is restored EXPLICITLY (NOT ``monkeypatch.undo()`` — the
        # ``monkeypatch`` fixture is SHARED with ``fake_read_adapter``, so ``undo()``
        # would also revert the fixture's vocabulary + reference-key patches and the
        # second, good reconcile would be refused instead of appending its one fact).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))
        real_commit = db_session.commit

        def _commit_boom():
            raise SQLAlchemyError("simulated commit failure")

        monkeypatch.setattr(db_session, "commit", _commit_boom)
        r = _post(client, eid)
        assert r.status_code == 500
        assert _outcome_count(db_session) == 0
        monkeypatch.setattr(db_session, "commit", real_commit)  # restore ONLY the commit
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))
        r2 = _post(client, eid)
        assert r2.status_code == 200
        assert _outcome_count(db_session) == 1  # no partial fact lingered


# ===========================================================================
# spec §十八 / §十九 / §二十 — the PRODUCTION registry stays EMPTY (F re-proves it)
# ===========================================================================
class TestProductionRegistryEmpty:
    """The PRODUCTION default registry is EMPTY, the fake NEVER leaks to production, and
    NO real Shuffle/Wazuh/TheHive read adapter is wired (those are 3.4.5-B/C/D)."""

    def test_default_registry_rejects_every_adapter(self):
        registry = default_read_adapter_registry()
        for adapter in ("mock", "shuffle", "wazuh", "thehive", "unknown"):
            with pytest.raises(UnsupportedAdapterRead):
                registry.get(adapter)

    def test_production_http_path_404_without_injection(
        self, client, operators, db_session
    ):
        # NO injection -> the real empty registry -> every adapter 404s, zero fact.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        r = _post(client, eid)
        assert r.status_code == 404
        assert r.json()["detail"] == "adapter read unsupported"
        assert _outcome_count(db_session) == 0

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_injection_does_not_mutate_production_default(
        self, client, operators, db_session, monkeypatch
    ):
        # After injecting a fake for one request, the REAL production factory (this
        # module's own import, never patched) is STILL empty — the monkeypatch rebinds
        # only the service module's name, never the source function. G1-C / B0 §15.4:
        # the injected 200 rides the TEST-ONLY fake adapter (real Wazuh is empty/refused),
        # and the production factory is then re-proved to reject the REAL wazuh identity.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))
        r = _post(client, eid)
        assert r.status_code == 200  # succeeds via the injected registry
        real = default_read_adapter_registry()  # the UNPATCHED source factory
        with pytest.raises(UnsupportedAdapterRead):
            real.get("wazuh")

    def test_no_real_read_adapter_wired(self):
        # §二十: F adds NO ShuffleReadAdapter / WazuhReadAdapter / TheHiveReadAdapter.
        import app.services.manual_reconcile as mr_pkg

        for forbidden in (
            "ShuffleReadAdapter", "WazuhReadAdapter", "TheHiveReadAdapter",
            "MockReadAdapter",
        ):
            assert not hasattr(mr_pkg, forbidden)


# ===========================================================================
# spec §二十三 — CONCURRENCY (APPLICATION-LEVEL SIMULATION, honestly labeled)
# ===========================================================================
class TestConcurrencySimulation:
    """APPLICATION-LEVEL concurrency SIMULATION (spec §二十三 HONESTY caveat). The
    TestClient and ``db_session`` share ONE SQLite StaticPool Session/connection and are
    NOT thread-safe, so this does NOT spawn real threads and does NOT claim to validate
    production PostgreSQL concurrency. It simulates two interleaved reconcile arrivals
    (both orders) and asserts the invariants that MUST hold: both facts retained,
    historical rows immutable, derived state deterministic (order-independent), no
    session corruption, no retry."""

    # G1-C / B0 §15.4: the successful arrivals ride the TEST-ONLY fake adapter (the real
    # Wazuh vocabulary is empty/refused); the interleaved Shuffle read-FAILURE stays a
    # pure production reconciliation_failed.
    pytestmark = pytest.mark.usefixtures("fake_read_adapter")

    def test_two_arrivals_both_retained_deterministic(
        self, client, operators, db_session, monkeypatch
    ):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        t_pending = datetime.now(timezone.utc) - timedelta(hours=2)
        t_success = datetime.now(timezone.utc) - timedelta(hours=1)
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("running", observed_at=t_pending)))
        r1 = _post(client, eid)
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success", observed_at=t_success)))
        r2 = _post(client, eid)
        assert (r1.status_code, r2.status_code) == (200, 200)
        rows = _facts(db_session, eid)
        assert len(rows) == 2  # both retained, no lost update
        assert {f.outcome_status for f in rows} == {"pending", "confirmed_success"}
        assert derive_outcome_state(rows) == "confirmed_success"  # newer observed_at wins
        assert r2.json()["derived_outcome_status"] == "confirmed_success"

    def test_arrival_order_independence(
        self, client, operators, db_session, monkeypatch
    ):
        # The SAME two observations in the OPPOSITE arrival order derive IDENTICALLY.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        t_pending = datetime.now(timezone.utc) - timedelta(hours=2)
        t_success = datetime.now(timezone.utc) - timedelta(hours=1)
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success", observed_at=t_success)))
        _post(client, eid)  # confirmed_success (newer) FIRST
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("running", observed_at=t_pending)))
        r2 = _post(client, eid)  # pending (older) SECOND
        rows = _facts(db_session, eid)
        assert len(rows) == 2
        assert derive_outcome_state(rows) == "confirmed_success"  # SAME as the other order
        assert r2.json()["derived_outcome_status"] == "confirmed_success"

    def test_no_session_corruption_across_executions(
        self, client, operators, db_session, monkeypatch
    ):
        # Two DIFFERENT executions reconciled interleaved never corrupt each other's
        # session state or cross-write facts.
        eid_a, eid_b = uuid.uuid4(), uuid.uuid4()
        _seed_chain(db_session, eid_a, rows=_fake_rows())
        _seed_chain(db_session, eid_b, rows=_shuffle_rows())
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))
        ra = _post(client, eid_a)
        _inject_registry(monkeypatch, FakeReadAdapter("shuffle", error=TimeoutError("t")))
        rb = _post(client, eid_b)
        assert (ra.status_code, rb.status_code) == (200, 200)
        assert _only_fact(db_session, eid_a).outcome_status == "confirmed_success"
        assert _only_fact(db_session, eid_b).outcome_status == "reconciliation_failed"
        assert _outcome_count(db_session) == 2  # one per execution, no cross-write


# ===========================================================================
# spec §二十一 / §二十二 — HTTP SEMANTICS (full status matrix, no accepted=true on error)
# ===========================================================================
class TestHttpSemantics:
    """The FULL status-code matrix (200 success / 200 read-failure / 404 unsupported /
    422 contract / 401 auth / 403 RBAC / 404 correlation / 500 persistence), NO error
    response ever carries accepted=true, the body leaks no secret, and ONE response
    schema is reused (no second envelope)."""

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_success_200_accepted_true(self, client, operators, db_session, monkeypatch):
        # G1-C / B0 §15.4: the 200 SUCCESS rides the TEST-ONLY fake adapter (real Wazuh
        # is empty/refused); METHOD-scoped so the read-failure / rejection-matrix /
        # secret-leak proofs stay in PURE production state.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))
        r = _post(client, eid)
        assert r.status_code == 200 and r.json()["accepted"] is True

    def test_read_failure_200_accepted_true(self, client, operators, db_session, monkeypatch):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        _inject_registry(monkeypatch, FakeReadAdapter("wazuh", error=TimeoutError("t")))
        r = _post(client, eid)
        assert r.status_code == 200 and r.json()["accepted"] is True

    def test_no_error_response_carries_accepted_true(
        self, client, operators, db_session, monkeypatch
    ):
        # EVERY rejection path: the body NEVER claims accepted=true (spec §二十一).
        responses = []
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        responses.append(_post(client, eid, token="bad-token"))  # 401
        responses.append(_post(client, eid, token=VIEWER_TOKEN))  # 403
        responses.append(_post(client, uuid.uuid4()))  # 404 correlation
        eid_ref = uuid.uuid4()
        _seed_chain(db_session, eid_ref, rows=_wazuh_rows_no_reference())
        responses.append(_post(client, eid_ref))  # 422 missing reference
        eid_unsup = uuid.uuid4()
        _seed_chain(db_session, eid_unsup, rows=_shuffle_rows())
        responses.append(_post(client, eid_unsup))  # 404 unsupported
        responses.append(_post(client, eid, body={"operator": "admin"}))  # 422 smuggle
        eid_state = uuid.uuid4()
        _seed_chain(db_session, eid_state, rows=_shuffle_rows())
        _inject_registry(monkeypatch, FakeReadAdapter("shuffle", result=_result("succeeded")))
        responses.append(_post(client, eid_state))  # 422 unrecognized state
        for r in responses:
            assert r.status_code in (401, 403, 404, 422)
            assert r.json().get("accepted") is not True
        assert _outcome_count(db_session) == 0  # NONE of them wrote a fact

    def test_error_body_leaks_no_secret(self, client, operators, db_session):
        # Rejection bodies are STATIC — no token, no adapter reference, no execution_id.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        for token in ("bad-token", VIEWER_TOKEN):
            r = _post(client, eid, token=token)
            for secret in SECRET_SUBSTRINGS:
                assert secret not in r.text
            assert "wazuh-cmd-abc123" not in r.text  # no external-reference echo
            assert str(eid) not in r.text  # no execution_id echo in a static detail

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_persistence_500_not_accepted(self, client, operators, db_session, monkeypatch):
        # The 500 (persistence failure) body is a static detail, never accepted=true.
        # G1-C / B0 §15.4: the SUCCESS edge (made to fail persistence -> 500) rides the
        # TEST-ONLY fake adapter (real Wazuh is empty/refused -> would be 422, not 500).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        _inject_registry(monkeypatch, FakeReadAdapter(FAKE, result=_result("success")))

        def _commit_boom():
            raise SQLAlchemyError("boom")

        monkeypatch.setattr(db_session, "commit", _commit_boom)
        r = _post(client, eid)
        assert r.status_code == 500
        assert r.json().get("accepted") is not True
        assert r.json()["detail"] == "reconcile outcome persistence failed"

    def test_one_response_schema_reused(self):
        # §二十二: the field SET is EXACTLY the frozen A2-A envelope — no second schema.
        assert set(ManualReconcileResponse.model_fields) == {
            "accepted", "execution_id", "adapter", "outcome_status", "observed_at",
            "source", "derived_outcome_status", "observed_at_kind",
        }
