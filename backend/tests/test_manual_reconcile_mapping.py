"""3.4.5-A2-E Manual Reconcile — MAPPING + OUTCOME PERSISTENCE acceptance.

A2-E closes the A2 platform seam by unifying the two edges A2-C/A2-D left open::

    Manual Reconcile -> Correlation (A2-B) -> Reference Extraction (A2-B)
        -> ReadAdapterRegistry / reader.read() (A1 + A2-C)
            |-- SUCCESS -> ExternalObservation
            |              -> validate_observation()   (3.4.3-A, NEVER skipped)
            |              -> map_external_state()     (3.4.3-B, the ONLY word source)
            |              -> redact_detail()          (the final secret gate)
            |              -> ExecutionOutcomeFact INSERT (append-only) -> 200
            |
            '-- FAILURE -> reconciliation_failed (A2-D, byte-identical, NO mapper)
                           -> ExecutionOutcomeFact INSERT (append-only) -> 200

THE TWO EDGES THIS FILE PINS (spec §一 / §二十二):

  * SUCCESS (spec §三 / §四 / §七): a reader EXISTS (a test-injected
    ``FakeReadAdapter``, NEVER the empty production registry, §十九) and ``read()``
    returns an ``AdapterReadResult``. Its ``external_state`` is validated by
    3.4.3-A and mapped by 3.4.3-B — Wazuh ``success``/``completed``/``confirmed``/
    ``done``/``ok`` -> ``confirmed_success``, ``running`` -> ``pending``, ``unknown``
    -> ``unknown`` — and EXACTLY ONE mapped fact is appended (``source`` =
    ``manual_reconcile``, ``operator`` = the authenticated HUMAN, ``detail`` = the
    redacted mapping evidence). The mapper is the ONLY word source: this file proves
    the service's outcome equals ``map_external_state(validate_observation(obs))``
    computed independently, so NO vocabulary is copied and NO ``external_state ->
    outcome_status`` shortcut exists. An UNEVIDENCED state (EVERY shuffle / thehive
    / mock word today, §四) is REFUSED with ``UnrecognizedExternalState`` -> 422 ->
    ZERO facts, NEVER downgraded to ``unknown`` and NEVER ``reconciliation_failed``.

  * FAILURE (spec §五 / §八, sealed A2-D): a reader EXISTS and ``read()`` raises a
    transport error -> ONE ``reconciliation_failed`` fact whose ``detail`` is the
    FAILURE shape (``failure_category`` / ``reason``), NOT the mapping shape — a read
    failure has NO ``external_state`` and therefore NEVER enters ``map_external_state``.

APPEND-ONLY + DERIVATION (spec §九 / §十 / §十一): both edges INSERT exactly one
row, never UPDATE / UPSERT / MERGE / DELETE. Historical facts are immutable (a prior
``confirmed_success`` survives a later ``reconciliation_failed``), ``execution_log``
is never touched, and NO derived state is stored — the current state is computed on
read by ``derive_outcome_state()`` over ``observed_at DESC, id DESC``.

O5 DISPATCH INDEPENDENCE (spec §十二): the outcome is NEVER auto-decided by the
dispatch decision. ``dispatch=succeeded`` + a read failure -> ``reconciliation_failed``
(log unchanged); ``dispatch=failed`` + a Wazuh read success -> ``confirmed_success``.

ISOLATION (spec §十六 / §十七 / §二十五, AST- + runtime-proven on BOTH the
orchestrator ``manual_reconcile.py`` AND the persister ``manual_persist.py``): NO
executor, NO retry / sleep / backoff (ONE ``read()`` per POST), NO compensation, NO
write adapter, NO background worker. Rollback (spec §十六): a persistence failure on
EITHER edge rolls back -> ``OutcomePersistenceError`` -> ZERO partial facts, never
``accepted=true``. Secret hygiene (spec §十五 / §二十三 / §二十四): NEITHER the fact
``detail`` NOR the response leaks an API key / password / Authorization / token / raw
external payload, and A2-E adds NO field to the frozen A2-A ``ManualReconcileResponse``.
"""
import ast
import inspect
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.models import (
    OUTCOME_STATUSES,
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
from app.services.outcomes.manual_persist import (
    ReconciledOutcome,
    persist_reconcile_outcome,
)
from app.services.outcomes.manual_reconcile import reconcile_execution
from app.services.outcomes.mapping import map_external_state
from app.services.outcomes.reconciliation import (
    ContractValidationFailure,
    ExternalObservation,
    InvalidObservedAt,
    MissingExternalReference,
    MissingExternalState,
    UnrecognizedExternalState,
    validate_observation,
)
from app.services.outcomes.webhook import OutcomePersistenceError

#: Fixed clock for seeding the DISPATCH chain (execution_log.created_at). OUTCOME
#: facts use the real ``datetime.now`` because the service stamps ``observed_at``
#: with the server clock at reconcile time (spec §七 / §八).
NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)

#: The reconcile path template (execution_id is a PATH param).
RECONCILE = "/api/v1/executions/{eid}/reconcile"

#: The authenticated HUMAN operator identity for service-level calls (spec §七). A
#: HUMAN recorder name — NEVER the webhook's ``adapter:{identity}`` machine domain,
#: NEVER the dispatch chain's ``operator`` (``ops-1``), NEVER a client-supplied string.
OPERATOR = "exec-op"

#: G1-C / B0 §15.4 — the TEST-ONLY fake adapter is the platform success-pipeline
#: vehicle for the Manual Reconcile path too. The real Wazuh vocabulary is now
#: EMPTY / fail-closed, so NO production adapter can carry a success fact; the
#: ``fake_read_adapter`` conftest fixture injects this identity's vocabulary AND its
#: ``_EXTERNAL_REFERENCE_KEYS`` handle so a migrated success test is a pure identity
#: swap (executor + reader name), NEVER a reopening of the real Wazuh vocabulary.
FAKE = "fakesuccess"

#: A message LOADED with things that must NEVER reach a fact or a response (spec §八
#: / §十五 / §二十三). If any path did ``str(exc)`` / echoed ``raw_evidence`` into
#: ``detail``, these substrings would surface — the hygiene tests assert they do not.
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

#: The SUCCESS mapping-evidence detail shape (spec §十五) and the FAILURE detail
#: shape (A2-D). Disjoint: a success fact NEVER carries ``failure_category`` and a
#: failure fact NEVER carries the mapping evidence — proving the failure edge bypasses
#: ``map_external_state`` (spec §五).
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


# ---------------------------------------------------------------------------
# test-only FakeReadAdapter (spec §十九 / §二十二) — NEVER a production reader, and
# NEVER globally registered: it enters ONLY an EXPLICIT ``ReadAdapterRegistry([fake])``
# constructor injection. It has ONLY ``name`` + ``read`` (no execute / compensate /
# dispatch / trigger verb) and performs NO I/O: ``read`` raises the primed transport
# error (the A2-D failure edge) or returns a canned ``AdapterReadResult`` (the A2-E
# success edge). It records its call count so tests prove ``read()`` ran EXACTLY once
# (spec §十七) or NEVER (the rejection gates).
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


# ---------------------------------------------------------------------------
# seeding + snapshot helpers (mirror test_manual_reconcile_read_failure.py; the chain
# must be a valid execute chain so correlate_execution accepts it)
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
    ``OPERATOR`` (``exec-op``) so item 16 proves the fact's operator is the reconcile
    human, never inherited from the dispatch log."""
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
    """A WAZUH execute chain whose terminal row carries the ``command_id`` handle
    (``_EXTERNAL_REFERENCE_KEYS["wazuh"]``). ``terminal_decision`` is parametrizable
    for the O5 dispatch-independence proof (spec §十二): the dispatch word does NOT
    decide the outcome — the READ + 3.4.3-B mapping does."""
    return [
        ("requested", {"executor": "wazuh"}),
        ("dispatched", {"executor": "wazuh"}),
        (terminal_decision, {"command_id": reference}),
    ]


def _wazuh_rows_no_reference():
    """A WAZUH chain with NO ``command_id`` on its terminal row: the adapter identity
    is present but the external handle is absent, so ``extract_context`` raises
    ``MissingExternalReference`` BEFORE the registry is consulted (spec §十四 item 9 ->
    422, provable over HTTP with the EMPTY production registry)."""
    return [
        ("requested", {"executor": "wazuh"}),
        ("dispatched", {"executor": "wazuh"}),
        ("failed", {"note": "dispatch failed before a command_id was returned"}),
    ]


def _fake_rows(reference="fake-cmd-abc123", *, terminal_decision="succeeded"):
    """G1-C / B0 §15.4 — a TEST-ONLY fake-adapter execute chain mirroring
    ``_wazuh_rows`` but keyed on the fake identity: the requested/dispatched rows
    carry ``executor=fakesuccess`` (so ``_extract_adapter`` -> ``registry.get`` ->
    ``map_external_state`` all see the fake) and the terminal row carries the
    ``command_id`` handle the ``fake_read_adapter`` fixture registers in
    ``_EXTERNAL_REFERENCE_KEYS``. This is the platform success-pipeline vehicle now
    that the real Wazuh vocabulary is empty/refused."""
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
):
    """A PRIOR Outcome Fact for the same execution (spec §十 / §十一). Its
    ``observed_at`` is a REAL past server time so a reconcile the service stamps with
    ``datetime.now`` is strictly LATER (latest-wins derivation). Seeded as a ``webhook``
    fact to prove the manual_reconcile append COEXISTS with a different source and
    never overwrites it."""
    fact = ExecutionOutcome(
        execution_id=execution_id,
        outcome_status=status,
        source=source,
        operator=operator,
        observed_at=datetime.now(timezone.utc) - timedelta(hours=hours_ago),
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
    """Full-table content snapshot of execution_log INCLUDING ``detail`` (spec §十五 /
    §十二: neither edge may mutate the dispatch log). JSON-canonicalized, keyed by id."""
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


def _import_surface(module):
    """AST import surface of ONE module (docstring-immune — mirrors the sealed A2-D
    ``_service_import_surface``). Returns (imported-modules, imported-names)."""
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


def _reconcile_import_surface():
    """The orchestrator's surface (``manual_reconcile.py``) — the module the SEALED
    A2-B / A2-C boundary tests audit; A2-E keeps it mapping-free / persistence-free."""
    return _import_surface(reconcile_module)


def _persist_import_surface():
    """The persister's surface (``manual_persist.py``) — where A2-E legitimately owns
    the mapper / validator / ORM / redaction, audited here for the FIRST time."""
    return _import_surface(persist_module)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def operators(monkeypatch):
    """Executor operator via OPERATORS_JSON (the 3.3.1 harness) for the API-level
    rejection tests. The conftest autouse fixture resets the module-level registry
    around every test, so the monkeypatched config always takes effect."""
    monkeypatch.setattr(
        settings,
        "OPERATORS_JSON",
        json.dumps([{"token": "tok-exec", "name": OPERATOR, "role": "executor"}]),
    )


# ===========================================================================
# spec §十八 items 1-3 + §三 / §四 — the SUCCESS mapping edge
# ===========================================================================
class TestSuccessMapping:
    """A reader EXISTS (test-injected) and ``read()`` SUCCEEDS: the raw
    ``external_state`` is validated (3.4.3-A) then mapped (3.4.3-B) onto the outcome
    vocabulary, and EXACTLY ONE mapped fact is appended.

    G1-C / B0 §15.4: the real Wazuh vocabulary is now EMPTY / fail-closed, so NO
    production adapter maps a success word. The platform success-pipeline proof is
    carried by the TEST-ONLY fake adapter (``fake_read_adapter`` fixture + ``_fake_rows``
    + ``FakeReadAdapter(FAKE, ...)``) — a pure identity swap that NEVER reopens the real
    Wazuh vocabulary. Every shuffle / thehive / mock / blank state is still refused
    (§四, ``TestRejectedZeroFact``); the blank-state validation proof below stays on the
    real (refused) Wazuh path, and the Wazuh former-evidenced-word reversal lives in
    ``TestRejectedZeroFact``."""

    pytestmark = pytest.mark.usefixtures("fake_read_adapter")

    @pytest.mark.parametrize(
        "state", ["success", "completed", "confirmed", "done", "ok"]
    )
    def test_01_wazuh_terminal_success_maps_to_confirmed_success(self, db_session, state):
        # spec §十八 item 1 + §四 (G1-C: fake adapter): EVERY evidenced success word ->
        # confirmed_success.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        fake = FakeReadAdapter(FAKE, result=_result(state))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.accepted is True
        assert response.outcome_status == "confirmed_success"
        assert fake.call_count == 1  # ONE read (spec §十七)
        fact = _only_fact(db_session, eid)
        assert fact.outcome_status == "confirmed_success"
        assert fact.detail["observed_state"] == state  # RAW word preserved
        assert fact.detail["normalized_state"] == state  # fake is already lower-case
        assert set(fact.detail) == SUCCESS_DETAIL_KEYS

    def test_02_wazuh_running_maps_to_pending(self, db_session):
        # spec §十八 item 2 (G1-C: fake adapter): an in-progress external effect ->
        # pending (NEVER guessed to confirmed_success, NEVER unknown).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        fake = FakeReadAdapter(FAKE, result=_result("running"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.outcome_status == "pending"
        assert _only_fact(db_session, eid).outcome_status == "pending"

    def test_03_wazuh_unknown_maps_to_unknown(self, db_session):
        # spec §十八 item 3 (G1-C: fake adapter): a RECOGNIZED-but-ambiguous state ->
        # unknown. This is the legitimate ``unknown``, NOT the forbidden "unrecognized
        # -> unknown" downgrade (that is refused, item 8).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        fake = FakeReadAdapter(FAKE, result=_result("unknown"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.outcome_status == "unknown"
        assert _only_fact(db_session, eid).outcome_status == "unknown"

    def test_wazuh_case_insensitive_success(self, db_session):
        # §四 (G1-C: fake adapter): the fake vocabulary lower-cases agent_status (its
        # case_insensitive normalization), so "SUCCESS" maps too — observed_state stays
        # RAW, normalized_state is folded.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        fake = FakeReadAdapter(FAKE, result=_result("SUCCESS"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.outcome_status == "confirmed_success"
        fact = _only_fact(db_session, eid)
        assert fact.detail["observed_state"] == "SUCCESS"
        assert fact.detail["normalized_state"] == "success"

    def test_wazuh_mapping_form_agent_status(self, db_session):
        # §四 (G1-C: fake adapter): a structured external_state yields its word under the
        # fake's evidenced state_key (``agent_status``) — the Mapping branch of
        # _extract_state_word.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        fake = FakeReadAdapter(FAKE, result=_result({"agent_status": "success"}))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.outcome_status == "confirmed_success"
        assert _only_fact(db_session, eid).detail["normalized_state"] == "success"

    def test_validation_runs_before_mapping_blank_state(self, db_session):
        # spec §三: validate_observation() is NEVER skipped. A BLANK external_state is
        # refused at 3.4.3-A (MissingExternalState) BEFORE the mapper ever runs -> ZERO
        # facts. Proves there is no direct external_state -> outcome_status shortcut.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        fake = FakeReadAdapter("wazuh", result=_result(""))
        with pytest.raises(MissingExternalState):
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert fake.call_count == 1  # the read DID succeed
        assert _outcome_count(db_session) == 0  # but validation refused it pre-mapping

    def test_same_word_is_adapter_specific_no_copied_vocabulary(self, db_session):
        # §四 "不要复制词表" (G1-C: fake adapter): the SAME word "success" maps to
        # confirmed_success for the FAKE adapter (evidenced) but is REFUSED for SHUFFLE
        # (empty vocabulary). Proves the outcome comes from map_external_state's
        # per-adapter table, NOT a global word list copied into the reconcile path.
        wid = uuid.uuid4()
        _seed_chain(db_session, wid, rows=_fake_rows())
        wfake = FakeReadAdapter(FAKE, result=_result("success"))
        wresp = reconcile_execution(db_session, wid, OPERATOR, ReadAdapterRegistry([wfake]))
        assert wresp.outcome_status == "confirmed_success"

        sid = uuid.uuid4()
        _seed_chain(db_session, sid, rows=_shuffle_rows())
        sfake = FakeReadAdapter("shuffle", result=_result("success"))
        with pytest.raises(UnrecognizedExternalState):
            reconcile_execution(db_session, sid, OPERATOR, ReadAdapterRegistry([sfake]))
        assert len(_facts(db_session, sid)) == 0

    def test_success_outcome_equals_independent_mapper(self, db_session):
        # §四: the service's word is EXACTLY map_external_state(validate_observation(obs))
        # recomputed here independently — one vocabulary source, no divergence.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        fake = FakeReadAdapter(FAKE, result=_result("success"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        obs = ExternalObservation(
            execution_id=eid,
            adapter=FAKE,
            external_reference="fake-cmd-abc123",
            external_state="success",
            observed_at=datetime.now(timezone.utc),
            source=MANUAL_RECONCILE_SOURCE,
        )
        expected = map_external_state(validate_observation(obs))
        assert response.outcome_status == expected.outcome_status == "confirmed_success"

    def test_success_never_writes_reconciliation_failed(self, db_session):
        # spec §五 / §四: a SUCCESS read maps to a StateMapping, which STRUCTURALLY
        # cannot be reconciliation_failed (StateMapping.__post_init__ refuses it). The
        # read-failure verdict is impossible on the success edge.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        fake = FakeReadAdapter(FAKE, result=_result("success"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.outcome_status != "reconciliation_failed"
        fact = _only_fact(db_session, eid)
        assert fact.outcome_status != "reconciliation_failed"
        assert "failure_category" not in fact.detail

    def test_observed_at_external_when_supplied(self, db_session):
        # spec §七: a reliable EXTERNAL timestamp is used as the fact time and declared
        # observed_at_kind="external".
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        when = datetime.now(timezone.utc) - timedelta(minutes=5)
        fake = FakeReadAdapter(FAKE, result=_result("success", observed_at=when))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.observed_at_kind == "external"
        assert response.observed_at.tzinfo is not None  # AWARE

    def test_observed_at_server_when_absent(self, db_session):
        # spec §七 / §八: an ABSENT external timestamp (A1 contract's None) is supplied
        # by the platform as the SERVER OBSERVATION time, declared "server-observation".
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        fake = FakeReadAdapter(FAKE, result=_result("success"))  # observed_at=None
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.observed_at_kind == "server-observation"
        assert response.observed_at.tzinfo is not None


# ===========================================================================
# spec §十八 items 4-6 + §五 — the READ FAILURE edge (sealed A2-D, re-pinned here)
# ===========================================================================
class TestReadFailureVerdict:
    """A reader EXISTS and ``read()`` FAILS in transit -> ``reconciliation_failed``.
    This edge is byte-identical to sealed A2-D; it is re-pinned here to prove the two
    edges COEXIST and that the failure ``detail`` is the FAILURE shape, never the
    mapping shape (a read failure has NO external_state, so it NEVER enters the mapper,
    spec §五)."""

    @pytest.mark.parametrize(
        "error,expected_category",
        [
            (TimeoutError("simulated timeout"), "timeout"),
            (ConnectionError("simulated connection refused"), "connection_failure"),
            (OSError("simulated transport error"), "transport_error"),
        ],
        ids=["timeout", "connection", "transport"],
    )
    def test_04_06_every_transport_shape_is_reconciliation_failed(
        self, db_session, error, expected_category
    ):
        # spec §十八 items 4-6: timeout / connection / transport ALL close to the SAME
        # reconciliation_failed verdict with a SAFE STATIC failure_category (spec §八).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=error)
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.accepted is True
        assert response.outcome_status == "reconciliation_failed"
        assert response.observed_at_kind == "server-observation"
        assert fake.call_count == 1
        fact = _only_fact(db_session, eid)
        assert fact.outcome_status == "reconciliation_failed"
        assert fact.detail["failure_category"] == expected_category
        assert fact.detail["reason"] == "read_transport_failure"

    def test_failure_detail_is_failure_shape_not_mapping_shape(self, db_session):
        # spec §五: the failure fact carries the FAILURE detail shape and NONE of the
        # mapping evidence — structural proof it bypassed map_external_state.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=TimeoutError("t"))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        detail = _only_fact(db_session, eid).detail
        assert set(detail) == FAILURE_DETAIL_KEYS
        for mapping_key in ("observed_state", "normalized_state", "mapping_reason"):
            assert mapping_key not in detail

    def test_failure_never_confirmed_failure(self, db_session):
        # A2-D crux: reconciliation_failed (could not READ) is NEVER confirmed_failure
        # (a MAPPED external verdict). No mapping runs on the failure edge.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=ConnectionError("refused"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.outcome_status == "reconciliation_failed"
        assert response.outcome_status != "confirmed_failure"


# ===========================================================================
# spec §十八 items 7-10 + §十四 — REJECTED paths write ZERO facts
# ===========================================================================
class TestRejectedZeroFact:
    """Every rejection closes with ZERO Outcome Facts (spec §十四). Only "reader
    EXISTS + read FAILED" appends (``reconciliation_failed``); a capability gap, an
    unevidenced state, a missing reference and a correlation failure all refuse."""

    def test_07_unsupported_reader_http_404_zero_fact(self, client, operators, db_session):
        # spec §十八 item 7 + §十四: a correlated, reference-bearing chain whose adapter
        # has NO reader (the EMPTY production registry) -> 404, ZERO facts. NOT
        # reconciliation_failed (no read was attempted).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        r = client.post(_url(str(eid)), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 404
        assert r.json()["detail"] == "adapter read unsupported"
        assert _outcome_count(db_session) == 0

    def test_08_unrecognized_state_service_zero_fact_is_422(self, db_session):
        # spec §十八 item 8 + §四 / §十四: a shuffle read of an UNEVIDENCED state is
        # REFUSED with UnrecognizedExternalState, ZERO facts, NEVER downgraded to
        # unknown. It is a ContractValidationFailure, so the router maps it to 422.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", result=_result("succeeded"))
        with pytest.raises(UnrecognizedExternalState):
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert fake.call_count == 1  # the read DID succeed
        assert _outcome_count(db_session) == 0
        assert issubclass(UnrecognizedExternalState, ContractValidationFailure)

    @pytest.mark.parametrize(
        "state", ["success", "completed", "confirmed", "done", "ok", "running", "unknown"]
    )
    def test_wazuh_former_evidenced_words_are_now_refused_zero_fact(self, db_session, state):
        # G1-C / B0 §15.4 REVERSAL (the manual-path mirror of the webhook/mapping
        # reversals): the real Wazuh vocabulary is now EMPTY, so EVERY former
        # code-evidenced word — a SUCCESSFUL read of "success"/"running"/"unknown"/...
        # — is REFUSED at the 3.4.3-B mapping with UnrecognizedExternalState and writes
        # ZERO facts. The read DID succeed (call_count==1); the refusal is at MAPPING,
        # not transport, so it is NEVER reconciliation_failed. Runs in the PRODUCTION
        # state (no fake fixture on this class) — the real Wazuh vocabulary is empty.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        fake = FakeReadAdapter("wazuh", result=_result(state))
        with pytest.raises(UnrecognizedExternalState):
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert fake.call_count == 1  # the read DID succeed
        assert _outcome_count(db_session) == 0

    def test_09_missing_reference_http_422_zero_fact(self, client, operators, db_session):
        # spec §十八 item 9 + §十四: a wazuh chain with NO command_id -> the reference
        # gate (which runs BEFORE the registry) raises MissingExternalReference -> 422,
        # ZERO facts — provable over HTTP with the EMPTY production registry.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows_no_reference())
        r = client.post(_url(str(eid)), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 422
        assert r.json()["detail"] == "reconcile validation failed"
        assert _outcome_count(db_session) == 0

    def test_10_correlation_failure_http_404_zero_fact(self, client, operators, db_session):
        # spec §十八 item 10 + §十四: an execution_id that maps to NO chain ->
        # UnmappableExecutionId -> the uniform 404, ZERO facts.
        missing = uuid.uuid4()
        r = client.post(_url(str(missing)), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 404
        assert r.json()["detail"] == "execution correlation failed"
        assert _outcome_count(db_session) == 0

    def test_authentication_failure_http_401_zero_fact(self, client, operators, db_session):
        # spec §十四: an INVALID token -> 401 at the RBAC dependency, BEFORE the body or
        # the path id is considered -> ZERO facts.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        r = client.post(_url(str(eid)), json={}, headers=_auth("not-a-real-token"))
        assert r.status_code == 401
        assert _outcome_count(db_session) == 0


# ===========================================================================
# spec §十八 items 11-15 + §九 / §十 — APPEND-ONLY persistence
# ===========================================================================
class TestPersistence:
    """Both edges INSERT exactly one row and never mutate history (spec §九 / §十).

    G1-C / B0 §15.4: the SUCCESS edge runs on the TEST-ONLY fake adapter (the real
    Wazuh vocabulary is empty/refused); the FAILURE edge (shuffle read error ->
    reconciliation_failed) is unchanged — it never enters the mapper."""

    pytestmark = pytest.mark.usefixtures("fake_read_adapter")

    def test_11_success_appends_exactly_one(self, db_session):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        assert _outcome_count(db_session) == 0
        fake = FakeReadAdapter(FAKE, result=_result("success"))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert _outcome_count(db_session) == 1

    def test_12_failure_appends_exactly_one(self, db_session):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        assert _outcome_count(db_session) == 0
        fake = FakeReadAdapter("shuffle", error=TimeoutError("t"))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert _outcome_count(db_session) == 1

    def test_13_repeated_success_appends_one_each(self, db_session):
        # spec §九: a repeat reconcile is a NEW observation, never an UPDATE / dedup.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        for expected in (1, 2, 3):
            fake = FakeReadAdapter(FAKE, result=_result("success"))
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
            assert len(_facts(db_session, eid)) == expected
        ids = [f.id for f in _facts(db_session, eid)]
        assert len(set(ids)) == 3  # three DISTINCT rows

    def test_14_historical_fact_unchanged(self, db_session):
        # spec §十: a prior confirmed_success survives a later reconcile UNCHANGED; the
        # new fact is APPENDED beside it (both retained), never overwritten.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        historical = _seed_historical_outcome(db_session, eid, status="confirmed_success")
        before = _fact_snapshot(historical)
        fake = FakeReadAdapter("shuffle", error=TimeoutError("t"))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        rows = _facts(db_session, eid)
        assert len(rows) == 2
        still = next(f for f in rows if f.id == historical.id)
        assert _fact_snapshot(still) == before  # byte-identical
        assert {f.outcome_status for f in rows} == {
            "confirmed_success",
            "reconciliation_failed",
        }

    def test_15_execution_log_unchanged_on_both_edges(self, db_session):
        # spec §十二 / §十五: NEITHER edge mutates the dispatch log (O5 — the Outcome
        # layer records facts, it never rewrites Dispatch history).
        for rows, kind in ((_fake_rows(), "success"), (_shuffle_rows(), "failure")):
            eid = uuid.uuid4()
            _seed_chain(db_session, eid, rows=rows)
            before = _log_snapshot(db_session)
            if kind == "success":
                fake = FakeReadAdapter(FAKE, result=_result("success"))
            else:
                fake = FakeReadAdapter("shuffle", error=TimeoutError("t"))
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
            assert _log_snapshot(db_session) == before


# ===========================================================================
# spec §十八 items 16-20 + §七 / §八 / §十五 / §二十三 — SECURITY
# ===========================================================================
class TestSecurity:
    """The fact's provenance is server-fixed and its evidence is secret-free.

    G1-C / B0 §15.4: the SUCCESS-edge security proofs (operator/source/response/detail)
    run on the TEST-ONLY fake adapter; the FAILURE-edge credential proof (test_18,
    shuffle read error) is unchanged — it never enters the mapper."""

    pytestmark = pytest.mark.usefixtures("fake_read_adapter")

    def test_16_operator_is_the_authenticated_human(self, db_session):
        # spec §七 / item 16: the fact operator is the reconcile HUMAN (OPERATOR), set
        # server-side — NEVER the dispatch chain's operator ("ops-1") and NEVER the
        # webhook machine domain ("adapter:...").
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows(), operator="ops-1")
        fake = FakeReadAdapter(FAKE, result=_result("success"))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        fact = _only_fact(db_session, eid)
        assert fact.operator == OPERATOR == "exec-op"
        assert fact.operator != "ops-1"
        assert not fact.operator.startswith("adapter:")

    def test_17_source_is_manual_reconcile_on_both_edges(self, db_session):
        # spec §七 / §八 / item 17: BOTH edges stamp source=manual_reconcile (never
        # "webhook"), fixed server-side.
        for rows, adapter, kw in (
            (_fake_rows(), FAKE, {"result": _result("success")}),
            (_shuffle_rows(), "shuffle", {"error": TimeoutError("t")}),
        ):
            eid = uuid.uuid4()
            _seed_chain(db_session, eid, rows=rows)
            fake = FakeReadAdapter(adapter, **kw)
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
            fact = _only_fact(db_session, eid)
            assert fact.source == MANUAL_RECONCILE_SOURCE == "manual_reconcile"

    def test_18_failure_detail_records_no_credential(self, db_session):
        # spec §八 / item 18: a secret-laden transport exception NEVER reaches the fact
        # — the failure detail records ONLY the safe static classification, never
        # str(exc), never an API key / password / Authorization / token.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter(
            "shuffle", error=ReadTransportError(SECRECY_MESSAGE, category="timeout")
        )
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        blob = json.dumps(_only_fact(db_session, eid).detail)
        for secret in SECRET_SUBSTRINGS:
            assert secret not in blob

    def test_19_response_leaks_no_authorization_or_token(self, db_session):
        # spec §二十三 / item 19: even when the read carries secrets, the RESPONSE
        # envelope echoes none of them.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        fake = FakeReadAdapter(
            FAKE,
            result=_result(
                "success",
                raw_evidence={
                    "Authorization": "Bearer SUPER_SECRET_TOKEN",
                    "api_key": "AKIAIOSFODNN7EXAMPLE",
                },
            ),
        )
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        blob = response.model_dump_json()
        for secret in SECRET_SUBSTRINGS:
            assert secret not in blob

    def test_20_success_detail_excludes_raw_evidence_and_secrets(self, db_session):
        # spec §十五 / §二十三 / item 20: the raw AdapterReadResult.raw_evidence payload
        # is NOT persisted — only the mapped evidence is — so a secret in raw_evidence
        # never reaches the fact, and redact_detail() is the final gate.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        fake = FakeReadAdapter(
            FAKE,
            result=_result(
                "success",
                raw_evidence={
                    "api_key": "SUPER_SECRET_TOKEN",
                    "Authorization": "Bearer hunter2",
                    "password": "hunter2",
                },
            ),
        )
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        detail = _only_fact(db_session, eid).detail
        assert set(detail) == SUCCESS_DETAIL_KEYS  # raw_evidence is NOT a key
        blob = json.dumps(detail)
        for secret in SECRET_SUBSTRINGS:
            assert secret not in blob


# ===========================================================================
# spec §十八 items 21-24 + §十一 — DERIVATION (computed on read, never stored)
# ===========================================================================
class TestDerivation:
    """The current state is ``derive_outcome_state()`` over ``observed_at DESC, id
    DESC`` — never a stored column (spec §十一)."""

    def test_21_latest_observed_at_wins_over_historical(self, db_session):
        # item 21: the just-appended reconciliation_failed (now) is LATER than a
        # historical confirmed_success (2h ago), so it is the derived current state.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        _seed_historical_outcome(db_session, eid, status="confirmed_success", hours_ago=2)
        fake = FakeReadAdapter("shuffle", error=TimeoutError("t"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.derived_outcome_status == "reconciliation_failed"
        assert derive_outcome_state(_facts(db_session, eid)) == "reconciliation_failed"

    def test_22_same_timestamp_id_desc_breaks_tie(self, db_session):
        # item 22: equal observed_at -> the HIGHER id wins (the id DESC tiebreak).
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
        assert winner.id == max(f1.id, f2.id)
        assert derive_outcome_state(rows) == winner.outcome_status

    def test_23_reconciliation_failed_can_be_current_derived_state(self, db_session):
        # item 23: a read-failure fact is a first-class observation — it CAN be the
        # derived current state (never suppressed, never laundered).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=TimeoutError("t"))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert derive_outcome_state(_facts(db_session, eid)) == "reconciliation_failed"

    def test_24_historical_confirmed_success_preserved_after_later_failure(self, db_session):
        # item 24 + spec §十: BOTH facts are retained — the historical confirmed_success
        # is NOT deleted / overwritten even though the CURRENT derived state is now
        # reconciliation_failed. T1 confirmed_success + T2 reconciliation_failed coexist.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        historical = _seed_historical_outcome(
            db_session, eid, status="confirmed_success", hours_ago=2
        )
        fake = FakeReadAdapter("shuffle", error=TimeoutError("t"))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        rows = _facts(db_session, eid)
        assert {f.outcome_status for f in rows} == {
            "confirmed_success",
            "reconciliation_failed",
        }
        assert any(
            f.id == historical.id and f.outcome_status == "confirmed_success" for f in rows
        )


# ===========================================================================
# spec §十八 items 25-29 + §十六 / §十七 / §二十五 — ISOLATION (BOTH modules)
# ===========================================================================
class TestIsolation:
    """AST import-surface + runtime proof that NEITHER the orchestrator
    (``manual_reconcile.py``) NOR the persister (``manual_persist.py``) reaches an
    executor, a retry, a compensation, a write adapter or a background worker."""

    def test_25_no_executor_reachable(self):
        recon_modules, recon_names = _reconcile_import_surface()
        persist_modules, persist_names = _persist_import_surface()
        # the orchestrator binds NOTHING under app.services.executions (sealed A2-B rule).
        assert not any(m.startswith("app.services.executions") for m in recon_modules)
        # the persister's ONLY executions binding is the redaction helper (redact_detail)
        # — NEVER an executor / write-adapter module.
        exec_bindings = {
            m for m in persist_modules if m.startswith("app.services.executions")
        }
        assert exec_bindings == {"app.services.executions.secrets"}
        for names in (recon_names, persist_names):
            for forbidden in (
                "ResponseExecutor", "create_executor", "execute_response",
                "compensate_response",
            ):
                assert forbidden not in names

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_26_no_retry_sleep_backoff(self, db_session):
        # item 26 + spec §十七: no retry / sleep / backoff library is imported, and ONE
        # read() runs per reconcile (the success path re-extracts context read-only but
        # NEVER re-invokes read()). G1-C: the runtime read runs on the TEST-ONLY fake
        # adapter (the real Wazuh vocabulary is empty/refused).
        for modules, names in (_reconcile_import_surface(), _persist_import_surface()):
            for token in ("retry", "tenacity", "backoff", "sleep"):
                assert not any(token in m for m in modules)
                assert not any(token in n for n in names)
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        fake = FakeReadAdapter(FAKE, result=_result("success"))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert fake.call_count == 1
        assert len(fake.requests) == 1

    def test_27_no_compensation(self):
        for modules, names in (_reconcile_import_surface(), _persist_import_surface()):
            assert not any("compensat" in m for m in modules)
            assert not any("compensat" in n for n in names)

    def test_28_read_adapter_has_no_write_verb(self):
        # item 28 + spec §二十五: the read contract's SOLE verb is read() — no write verb
        # exists on it, and no write-adapter module is imported by either surface.
        fake = FakeReadAdapter("wazuh")
        assert hasattr(fake, "read")
        for verb in (
            "execute", "compensate", "dispatch", "trigger", "create_case",
            "send_command", "write",
        ):
            assert not hasattr(fake, verb)
        for modules, _ in (_reconcile_import_surface(), _persist_import_surface()):
            assert not any(m.endswith("executions.response") for m in modules)
            assert not any("write_adapter" in m for m in modules)

    def test_29_no_background_worker(self):
        for modules, names in (_reconcile_import_surface(), _persist_import_surface()):
            for token in (
                "celery", "dramatiq", "threading", "multiprocessing", "concurrent",
                "asyncio", "BackgroundTasks", "scheduler",
            ):
                assert not any(token in m for m in modules)
                assert not any(token in n for n in names)


# ===========================================================================
# spec §十八 items 30-32 + §十六 — ROLLBACK (zero partial fact)
# ===========================================================================
class TestRollback:
    """A persistence failure on EITHER edge rolls back -> OutcomePersistenceError ->
    ZERO partial facts, never ``accepted=true`` (spec §十六)."""

    # G1-C / B0 §15.4: the SUCCESS-edge rollback proofs ride the TEST-ONLY fake adapter
    # (the real Wazuh vocabulary is empty/refused); the fixture is ADDITIVE, so test_31's
    # Shuffle failure-edge rollback below stays a pure production proof.
    pytestmark = pytest.mark.usefixtures("fake_read_adapter")

    def test_30_success_persistence_rollback_zero_fact(self, db_session, monkeypatch):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        log_before = _log_snapshot(db_session)

        def _commit_boom():
            raise SQLAlchemyError("simulated commit failure")

        monkeypatch.setattr(db_session, "commit", _commit_boom)
        fake = FakeReadAdapter(FAKE, result=_result("success"))
        with pytest.raises(OutcomePersistenceError):
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert _outcome_count(db_session) == 0  # the flushed INSERT was rolled back
        assert _log_snapshot(db_session) == log_before  # the committed log survives

    def test_31_failure_persistence_rollback_zero_fact(self, db_session, monkeypatch):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        log_before = _log_snapshot(db_session)

        def _commit_boom():
            raise SQLAlchemyError("simulated commit failure")

        monkeypatch.setattr(db_session, "commit", _commit_boom)
        fake = FakeReadAdapter("shuffle", error=TimeoutError("t"))
        with pytest.raises(OutcomePersistenceError):
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert _outcome_count(db_session) == 0
        assert _log_snapshot(db_session) == log_before

    def test_32_no_partial_fact_lingers_after_rollback(self, db_session, monkeypatch):
        # item 32: a rolled-back attempt leaves NO partial row — a later good reconcile
        # produces EXACTLY one fact. G1-C / B0 §15.4: the good reconcile rides the
        # TEST-ONLY fake adapter, so the commit is restored EXPLICITLY (NOT
        # ``monkeypatch.undo()``, which — the ``monkeypatch`` fixture being SHARED with
        # ``fake_read_adapter`` — would also revert the fixture's vocabulary +
        # reference-key patches and break the second, good reconcile).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        real_commit = db_session.commit

        def _commit_boom():
            raise SQLAlchemyError("simulated commit failure")

        monkeypatch.setattr(db_session, "commit", _commit_boom)
        fake = FakeReadAdapter(FAKE, result=_result("success"))
        with pytest.raises(OutcomePersistenceError):
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert _outcome_count(db_session) == 0
        monkeypatch.setattr(db_session, "commit", real_commit)  # restore ONLY the commit
        fake2 = FakeReadAdapter(FAKE, result=_result("success"))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake2]))
        assert _outcome_count(db_session) == 1


# ===========================================================================
# spec §十二 — O5 DISPATCH INDEPENDENCE
# ===========================================================================
class TestO5DispatchIndependence:
    """The outcome is NEVER auto-decided by the dispatch decision. The Dispatch layer
    (``execution_log.succeeded`` / ``failed``) and the Outcome layer legally disagree;
    the READ + 3.4.3-B mapping — not the dispatch word — decides the Outcome Fact."""

    def test_o5_dispatch_succeeded_plus_read_failure(self, db_session):
        # dispatch says "succeeded", but the read FAILS -> reconciliation_failed, and the
        # dispatch log is UNCHANGED (the Outcome layer never rewrites Dispatch history).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows(terminal_decision="succeeded"))
        log_before = _log_snapshot(db_session)
        fake = FakeReadAdapter("wazuh", error=TimeoutError("t"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.outcome_status == "reconciliation_failed"
        assert _only_fact(db_session, eid).outcome_status == "reconciliation_failed"
        assert _log_snapshot(db_session) == log_before

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_o5_dispatch_failed_plus_read_success(self, db_session):
        # dispatch says "failed", but the read SUCCEEDS and maps -> confirmed_success
        # is LEGAL (spec §十二). The outcome comes from the mapping, NOT the dispatch word.
        # G1-C / B0 §15.4: the SUCCESS read rides the TEST-ONLY fake adapter (the real
        # Wazuh vocabulary is empty/refused); METHOD-scoped so the two sibling wazuh
        # refusal / read-failure proofs stay in PURE production state.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows(terminal_decision="failed"))
        log_before = _log_snapshot(db_session)
        fake = FakeReadAdapter(FAKE, result=_result("success"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.outcome_status == "confirmed_success"
        assert _only_fact(db_session, eid).outcome_status == "confirmed_success"
        # the dispatch log STILL says "failed" — untouched (O5: facts, not rewrites).
        assert _log_snapshot(db_session) == log_before
        assert any(r.decision == "failed" for r in _all_log_rows(db_session))

    def test_o5_dispatch_word_never_maps_to_outcome(self, db_session):
        # the dispatch words "succeeded"/"failed" are NOT external states: a Wazuh read
        # returning the DISPATCH word "succeeded" (not the evidenced "success") is
        # REFUSED, never laundered into confirmed_success (§四 / RC-06 DISPATCH != OUTCOME).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        fake = FakeReadAdapter("wazuh", result=_result("succeeded"))
        with pytest.raises(UnrecognizedExternalState):
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert _outcome_count(db_session) == 0


# ===========================================================================
# manual_persist UNIT tests — persist_reconcile_outcome in isolation
# ===========================================================================
class TestManualPersistUnit:
    """Direct unit tests of ``persist_reconcile_outcome`` (the A2-E success persister).
    It does NOT re-run correlation (``execution_id`` is a plain non-FK column), so a
    bare UUID suffices; these pin validate -> map -> redact -> append in isolation."""

    # G1-C / B0 §15.4: ``persist_reconcile_outcome`` takes ``adapter`` + ``external_reference``
    # DIRECTLY (no registry, no ``_extract_reference``), so the UNIT-layer ``fake_adapter_vocab``
    # fixture is the minimal sufficient injection: the SUCCESS words ride the TEST-ONLY fake
    # adapter while the refusal unit tests below stay pure-production wazuh / shuffle / mock.
    pytestmark = pytest.mark.usefixtures("fake_adapter_vocab")

    def test_unit_success_appends_mapped_fact(self, db_session):
        eid = uuid.uuid4()
        out = persist_reconcile_outcome(
            db_session, execution_id=eid, adapter=FAKE,
            external_reference="fake-cmd-abc123", external_state="success",
            observed_at=None, operator=OPERATOR,
        )
        assert isinstance(out, ReconciledOutcome)
        assert out.outcome_status == "confirmed_success"
        assert out.observed_at_kind == "server-observation"  # observed_at=None
        assert out.observed_at.tzinfo is not None  # AWARE
        fact = _only_fact(db_session, eid)
        assert fact.outcome_status == "confirmed_success"
        assert fact.source == MANUAL_RECONCILE_SOURCE
        assert fact.operator == OPERATOR
        assert set(fact.detail) == SUCCESS_DETAIL_KEYS

    def test_unit_external_observed_at_kind(self, db_session):
        eid = uuid.uuid4()
        when = datetime.now(timezone.utc) - timedelta(minutes=5)
        out = persist_reconcile_outcome(
            db_session, execution_id=eid, adapter=FAKE, external_reference="ref",
            external_state="ok", observed_at=when, operator=OPERATOR,
        )
        assert out.observed_at_kind == "external"
        assert out.outcome_status == "confirmed_success"  # "ok" is evidenced

    def test_unit_validates_before_mapping_blank_state(self, db_session):
        eid = uuid.uuid4()
        with pytest.raises(MissingExternalState):
            persist_reconcile_outcome(
                db_session, execution_id=eid, adapter="wazuh", external_reference="ref",
                external_state="", observed_at=None, operator=OPERATOR,
            )
        assert _outcome_count(db_session) == 0

    def test_unit_unrecognized_shuffle_state(self, db_session):
        eid = uuid.uuid4()
        with pytest.raises(UnrecognizedExternalState):
            persist_reconcile_outcome(
                db_session, execution_id=eid, adapter="shuffle",
                external_reference="sf-exec-abc123", external_state="succeeded",
                observed_at=None, operator=OPERATOR,
            )
        assert _outcome_count(db_session) == 0

    def test_unit_missing_reference_none(self, db_session):
        eid = uuid.uuid4()
        with pytest.raises(MissingExternalReference):
            persist_reconcile_outcome(
                db_session, execution_id=eid, adapter="mock", external_reference=None,
                external_state="success", observed_at=None, operator=OPERATOR,
            )
        assert _outcome_count(db_session) == 0

    def test_unit_invalid_observed_at_naive(self, db_session):
        eid = uuid.uuid4()
        with pytest.raises(InvalidObservedAt):
            persist_reconcile_outcome(
                db_session, execution_id=eid, adapter="wazuh", external_reference="ref",
                external_state="success", observed_at=datetime(2026, 9, 6, 12, 0, 0),
                operator=OPERATOR,
            )
        assert _outcome_count(db_session) == 0

    def test_unit_rollback_on_persistence_failure(self, db_session, monkeypatch):
        eid = uuid.uuid4()

        def _commit_boom():
            raise SQLAlchemyError("commit failed")

        monkeypatch.setattr(db_session, "commit", _commit_boom)
        with pytest.raises(OutcomePersistenceError):
            persist_reconcile_outcome(
                db_session, execution_id=eid, adapter=FAKE, external_reference="ref",
                external_state="success", observed_at=None, operator=OPERATOR,
            )
        assert _outcome_count(db_session) == 0

    def test_unit_never_stores_derived_state(self, db_session):
        # spec §十一: no derived_state is ever written (computed on read only).
        eid = uuid.uuid4()
        persist_reconcile_outcome(
            db_session, execution_id=eid, adapter=FAKE, external_reference="ref",
            external_state="success", observed_at=None, operator=OPERATOR,
        )
        fact = _only_fact(db_session, eid)
        assert "derived_state" not in fact.detail
        assert "derived_outcome_status" not in fact.detail
        assert not hasattr(fact, "derived_state")


# ===========================================================================
# spec §十三 / §二十三 / §二十四 — the HTTP RESPONSE envelope
# ===========================================================================
class TestHttpEnvelope:
    """BOTH real exits return the SAME frozen ``ManualReconcileResponse`` with
    ``accepted=True``; A2-E adds NO field and creates NO second schema."""

    @pytest.mark.usefixtures("fake_read_adapter")
    def test_success_service_returns_200_envelope(self, db_session):
        # G1-C / B0 §15.4: the 200 SUCCESS envelope rides the TEST-ONLY fake adapter
        # (the real Wazuh vocabulary is empty/refused); METHOD-scoped so the sibling
        # Shuffle failure-envelope + structural-schema proofs stay pure-production.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_fake_rows())
        fake = FakeReadAdapter(FAKE, result=_result("success"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert isinstance(response, ManualReconcileResponse)
        assert response.accepted is True
        assert response.outcome_status == "confirmed_success"
        assert response.source == MANUAL_RECONCILE_SOURCE
        assert response.adapter == FAKE
        assert response.execution_id == eid

    def test_failure_service_returns_same_envelope(self, db_session):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=TimeoutError("t"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert isinstance(response, ManualReconcileResponse)
        assert response.accepted is True
        assert response.outcome_status == "reconciliation_failed"

    def test_one_envelope_no_second_response_schema(self):
        # §二十四: the field SET is EXACTLY the A2-A frozen one — A2-E added NO field
        # (outcome_status already existed), so no second response schema was created.
        assert set(ManualReconcileResponse.model_fields) == {
            "accepted", "execution_id", "adapter", "outcome_status", "observed_at",
            "source", "derived_outcome_status", "observed_at_kind",
        }

    def test_router_declares_200_envelope(self):
        # §十三: the route STRUCTURALLY declares status_code=200 + the frozen
        # response_model, so BOTH real exits are 200 — a read failure is NEVER a 500
        # (reconciliation_failed is itself a legal Outcome Fact).
        from app.api.v1.reconcile import router

        route = next(
            r for r in router.routes if getattr(r, "path", "").endswith("/reconcile")
        )
        assert route.status_code == 200
        assert route.response_model is ManualReconcileResponse


# ===========================================================================
# spec §十九 / §二十 — the PRODUCTION registry stays EMPTY
# ===========================================================================
class TestProductionRegistryEmpty:
    """The fake is NEVER globally registered; production has NO real read adapter yet
    (those are 3.4.5-B/C/D), so the success edge is reachable ONLY via test injection."""

    def test_default_registry_rejects_every_adapter(self):
        registry = default_read_adapter_registry()
        for adapter in ("mock", "shuffle", "wazuh", "thehive", "unknown"):
            with pytest.raises(UnsupportedAdapterRead):
                registry.get(adapter)

    def test_success_unreachable_via_production_registry(self, db_session):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows())
        with pytest.raises(UnsupportedAdapterRead):
            reconcile_execution(db_session, eid, OPERATOR, default_read_adapter_registry())
        assert _outcome_count(db_session) == 0

    def test_no_real_read_adapter_wired(self):
        # §二十: A2-E adds NO ShuffleReadAdapter / WazuhReadAdapter / TheHiveReadAdapter.
        # The empty production registry IS the behavioral proof; additionally no such
        # class is exported from the read-contract package.
        import app.services.manual_reconcile as mr_pkg

        for forbidden in (
            "ShuffleReadAdapter", "WazuhReadAdapter", "TheHiveReadAdapter",
            "MockReadAdapter",
        ):
            assert not hasattr(mr_pkg, forbidden)
