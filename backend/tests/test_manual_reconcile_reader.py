"""Manual Reconcile — ReadAdapterRegistry integration with a fake read adapter.

Wires the ``CorrelatedExecutionContext`` built by correlation + read-only
external-reference extraction into the ``ReadAdapterRegistry`` and proves the full
platform chain end to end with a test-only ``FakeReadAdapter``::

    execution_id -> correlate -> ExecutionLog chain
                 -> adapter (detail["executor"]) + external_reference
                 -> ReadAdapterRegistry.get(adapter)
                 -> reader.read(AdapterReadRequest) -> AdapterReadResult

The ``FakeReadAdapter`` enters only a test injection point — an explicit
``ReadAdapterRegistry([fake])`` instance passed by constructor injection. It is
never registered into ``default_read_adapter_registry()``, which stays empty, so
production (shuffle / wazuh / thehive / mock / unknown) still rejects at
``registry.get`` with ``UnsupportedAdapterRead`` -> rejected -> zero Outcome Fact.
No test here mutates a global registry, so there is no global state a test can
modify and forget to restore.

Two different rejections, kept different:

  * No reader at all (``registry.get`` lookup fails) -> ``UnsupportedAdapterRead``.
    There was no read attempt, so it is a rejection with no fact, and never
    ``reconciliation_failed``. This is every adapter in the empty production registry.
  * A reader exists and ``read()`` is actually attempted but fails at transport level
    (timeout / connection / transport) -> the raw failure signal surfaces only. It is
    not converted to ``reconciliation_failed`` and writes no fact; that conversion
    belongs to the read-failure path.

What this layer does not do: no real Shuffle/Wazuh/TheHive read, no HTTP (urllib /
requests / httpx), no ``normalize_external_state`` / mapping, no Outcome persistence /
INSERT / UPDATE / DELETE / COMMIT, no executor / dispatch, no retry, no compensation.
``reconcile_execution`` used to stop at ``NotImplementedError`` after a successful
fake read, with the pipeline reaching ``AdapterReadResult`` and no further, and never
a 200 ``accepted``. The real mapping edge replaced that stub, so a shuffle fake read
is now refused with ``UnrecognizedExternalState`` — shuffle has no evidenced
vocabulary — and the guarantee is unweakened: zero Outcome Facts and never a 200
``accepted``. The three ``reconcile_execution`` tests below now assert
``UnrecognizedExternalState`` (previously ``NotImplementedError``); every other
assertion (``call_count == 1`` / ``_outcome_count == 0`` / the request-attribute
checks) is unchanged.

The client-override boundary, structural fake isolation (no global registry
mutation), the absence of external I/O, the absence of DB writes and the
read-failure signal are all covered here at the service / registry layer. The HTTP
mapping of the unsupported path (``UnsupportedAdapterRead`` -> 404) and the
missing-reference path (-> 422) is proven in ``test_manual_reconcile_correlation.py``:
the router uses the empty default registry, so a fake reader cannot be injected over
HTTP without mutating that global.
"""
import ast
import inspect
import json
import uuid
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path

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
from app.services.manual_reconcile import (
    AdapterReadRequest,
    AdapterReadResult,
    ReadAdapter,
    ReadAdapterRegistry,
    UnsupportedAdapterRead,
    default_read_adapter_registry,
)
from app.services.outcomes import manual_reconcile as reconcile_module
from app.services.outcomes.manual_reconcile import (
    extract_context,
    read_external_state,
    reconcile_execution,
)
from app.services.outcomes.reconciliation import (
    MissingExternalReference,
    UnrecognizedExternalState,
)

NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)

# The three real adapters plus mock and an unknown name — all of them are
# unsupported in the empty production registry.
ALL_ADAPTERS = ("shuffle", "wazuh", "thehive", "mock", "datadog")


#
# test-only FakeReadAdapter — never a production reader
#
def _result(external_state, *, observed_at=None, raw_evidence=None):
    """A canned ``AdapterReadResult`` carrying a raw external state: an external-system
    word / Mapping, never an outcome word like ``confirmed_success`` / ``pending`` /
    ``unknown`` — the mapping edge produces those from this one."""
    return AdapterReadResult(
        external_state=external_state,
        observed_at=observed_at,
        raw_evidence=raw_evidence if raw_evidence is not None else {},
    )


class FakeReadAdapter(ReadAdapter):
    """A test-only ``ReadAdapter``. Implements only ``name`` + ``read``
    — it structurally has no ``execute`` / ``compensate`` / ``dispatch`` /
    ``trigger`` verb. It performs no I/O: ``read`` returns a canned
    ``AdapterReadResult`` (success evidence) or raises a primed transport
    error (read failure) — proving the platform chain without any external
    system.

    It records every ``AdapterReadRequest`` it receives and its call count so tests
    can prove the right execution_id / adapter / external_reference are passed
    and that ``read()`` is invoked exactly once.

    It is never registered into ``default_read_adapter_registry()``:
    tests inject it via an explicit ``ReadAdapterRegistry([fake])`` instance only.
    """

    def __init__(self, name="shuffle", *, result=None, error=None):
        self._name = name
        self._result = result if result is not None else _result("in_progress")
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


#
# seeding + snapshot helpers (mirror test_manual_reconcile_correlation.py; the
# chain must be a valid execute chain so correlate_execution accepts it)
#
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
    """One execute chain from ``[(decision, detail), ...]`` in chronological order."""
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


def _wazuh_rows(reference="cmd-77"):
    return [
        ("requested", {"executor": "wazuh"}),
        ("dispatched", {"executor": "wazuh"}),
        ("succeeded", {"command_id": reference, "command": "restart-agent"}),
    ]


def _thehive_rows(reference="case-4242"):
    return [
        ("requested", {"executor": "thehive"}),
        ("dispatched", {"executor": "thehive"}),
        ("succeeded", {"case_id": reference}),
    ]


def _mock_rows():
    return [("requested", {"executor": "mock"}), ("succeeded", {"dry_run": {}})]


def _all_log_rows(db_session):
    return list(db_session.scalars(select(ExecutionLog)))


def _outcome_count(db_session):
    return len(list(db_session.scalars(select(ExecutionOutcome))))


def _log_snapshot(db_session):
    """Full-table content snapshot of execution_log including ``detail``, which the
    read path must not mutate. JSON-canonicalized, keyed by the unique row id."""
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


def _service_import_surface():
    """AST import surface of the service module (docstring-immune)."""
    tree = ast.parse(inspect.getsource(reconcile_module))
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


#
# the production registry stays empty
#
class TestProductionRegistryEmpty:
    def test_08_default_registry_is_empty(self):
        # The production default registry has zero readers.
        assert default_read_adapter_registry().registered_adapters() == ()

    def test_07_no_default_fake_reader(self):
        # No FakeReadAdapter (nor any reader) is in the production default.
        registry = default_read_adapter_registry()
        for adapter in ALL_ADAPTERS + ("fake",):
            assert not registry.is_supported(adapter)

    @pytest.mark.parametrize("adapter", ALL_ADAPTERS)
    def test_default_registry_rejects_every_adapter(self, adapter):
        # Every adapter — real, mock, unknown — rejects at the empty registry.
        with pytest.raises(UnsupportedAdapterRead) as excinfo:
            default_read_adapter_registry().get(adapter)
        assert excinfo.value.adapter == adapter

    def test_default_registry_unmutated_by_fake_injection(self, db_session):
        # Injecting a fake into an explicit registry instance never touches the
        # production default, so there is no global state to restore.
        before = default_read_adapter_registry().registered_adapters()
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        read_external_state(db_session, eid, ReadAdapterRegistry([FakeReadAdapter("shuffle")]))
        after = default_read_adapter_registry().registered_adapters()
        assert before == after == ()


#
# registry lookup is unsupported for every adapter
#
class TestRegistryLookupUnsupported:
    def test_09_shuffle_lookup_unsupported(self):
        with pytest.raises(UnsupportedAdapterRead):
            default_read_adapter_registry().get("shuffle")

    def test_10_wazuh_lookup_unsupported(self):
        with pytest.raises(UnsupportedAdapterRead):
            default_read_adapter_registry().get("wazuh")

    def test_11_thehive_lookup_unsupported(self):
        with pytest.raises(UnsupportedAdapterRead):
            default_read_adapter_registry().get("thehive")

    def test_12_mock_lookup_unsupported(self):
        # mock is never reconcilable — no reader for it is registered in production.
        with pytest.raises(UnsupportedAdapterRead):
            default_read_adapter_registry().get("mock")

    def test_13_unknown_adapter_lookup_unsupported(self):
        with pytest.raises(UnsupportedAdapterRead):
            default_read_adapter_registry().get("datadog")

    def test_unsupported_message_does_not_echo_reference(self):
        # The message names the adapter (not a secret) but never an external_reference.
        with pytest.raises(UnsupportedAdapterRead) as excinfo:
            default_read_adapter_registry().get("shuffle")
        assert "sf-exec" not in str(excinfo.value)
        assert excinfo.value.adapter == "shuffle"


#
# unsupported adapter via read_external_state (service level)
#
class TestUnsupportedViaPipeline:
    @pytest.mark.parametrize(
        "rows",
        [_shuffle_rows(), _wazuh_rows(), _thehive_rows(), _mock_rows()],
        ids=["shuffle", "wazuh", "thehive", "mock"],
    )
    def test_read_external_state_rejects_at_empty_registry(self, db_session, rows):
        # A correlated, reference-bearing chain (or mock) still rejects at the empty
        # production registry — no read attempt, no fact.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=rows)
        with pytest.raises(UnsupportedAdapterRead):
            read_external_state(db_session, eid, default_read_adapter_registry())
        assert _outcome_count(db_session) == 0

    def test_16_unsupported_produces_zero_fact(self, db_session):
        # UnsupportedAdapterRead -> rejected -> zero Outcome Fact, and the
        # execution_log is byte-identical (no write on the rejection path).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        before = _log_snapshot(db_session)
        with pytest.raises(UnsupportedAdapterRead):
            read_external_state(db_session, eid, default_read_adapter_registry())
        assert _outcome_count(db_session) == 0
        assert _log_snapshot(db_session) == before

    def test_unsupported_is_not_reconciliation_failed(self, db_session):
        # A registry lookup failure is not a read attempt, so it is never
        # reconciliation_failed — no outcome word of any kind is produced.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        with pytest.raises(UnsupportedAdapterRead):
            read_external_state(db_session, eid, default_read_adapter_registry())
        rows = list(db_session.scalars(select(ExecutionOutcome)))
        assert rows == []
        assert all(r.outcome_status not in OUTCOME_STATUSES for r in rows)


#
# missing reference happens before the registry is consulted
#
class TestMissingReferenceBeforeRegistry:
    def test_14_missing_reference_rejects_before_registry_read(self, db_session):
        # Even when a reader exists for the adapter, a chain with no reconcilable
        # reference rejects with MissingExternalReference first — the registry's
        # read() is never reached (the fake records zero calls).
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "shuffle"}),
                ("dispatched", {"executor": "shuffle"}),
                ("failed", {"error": "connection timeout"}),  # no external_execution_id
            ],
        )
        fake = FakeReadAdapter("shuffle")
        with pytest.raises(MissingExternalReference):
            read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert fake.call_count == 0  # extraction gate ran before registry.get/read
        assert _outcome_count(db_session) == 0

    def test_missing_reference_not_downgraded_to_unsupported(self, db_session):
        # A no-reference shuffle chain is MissingExternalReference (422 family), not
        # UnsupportedAdapterRead — the two rejections stay distinct even when the
        # adapter would be unsupported anyway.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=[("requested", {"executor": "shuffle"}), ("failed", {})])
        with pytest.raises(MissingExternalReference):
            read_external_state(db_session, eid, default_read_adapter_registry())


#
# the FakeReadAdapter platform chain
#
class TestFakeReaderIntegration:
    def test_01_existing_execution_with_fake_reader(self, db_session):
        # An existing execution plus an injected fake reader yields an AdapterReadResult.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", result=_result("succeeded"))
        result = read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert isinstance(result, AdapterReadResult)

    def test_02_correct_adapter_passed(self, db_session):
        # The reader receives the historical adapter (from ExecutionLog).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle")
        read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert fake.last_request.adapter == "shuffle"

    def test_03_correct_external_reference_passed(self, db_session):
        # The reader receives the historical external_reference.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows("sf-historical-real"))
        fake = FakeReadAdapter("shuffle")
        read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert fake.last_request.external_reference == "sf-historical-real"

    def test_04_correct_execution_id_passed(self, db_session):
        # The reader receives the same execution_id (a UUID).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle")
        read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert fake.last_request.execution_id == eid
        assert isinstance(fake.last_request.execution_id, uuid.UUID)

    def test_05_reader_read_called_exactly_once(self, db_session):
        # read() is invoked exactly once per reconcile read.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle")
        read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert fake.call_count == 1
        assert len(fake.requests) == 1

    def test_06_fake_result_returned_intact(self, db_session):
        # The reader's AdapterReadResult is returned intact — the exact object,
        # unmodified, unmapped (no outcome word added).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        canned = _result(
            "succeeded", observed_at=NOW, raw_evidence={"external_status": "succeeded"}
        )
        fake = FakeReadAdapter("shuffle", result=canned)
        result = read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert result is canned
        assert result.external_state == "succeeded"
        assert result.observed_at == NOW
        assert result.raw_evidence == {"external_status": "succeeded"}
        assert not hasattr(result, "outcome_status")

    def test_27_reader_invoked_exactly_once_through_reconcile(self, db_session):
        # Through the full reconcile_execution entrypoint the reader is still invoked
        # exactly once. The entrypoint no longer stops at the NotImplementedError stub:
        # a shuffle read reaches the external-state mapping, which refuses it (shuffle
        # has no evidenced vocabulary) with UnrecognizedExternalState -> zero facts.
        # The call_count invariant is unchanged.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle")
        with pytest.raises(UnrecognizedExternalState):
            reconcile_execution(db_session, eid, "exec-op", registry=ReadAdapterRegistry([fake]))
        assert fake.call_count == 1

    def test_wazuh_reader_receives_command_id(self, db_session):
        # For wazuh the adapter-specific key command_id is the reference passed.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_wazuh_rows("cmd-999"))
        fake = FakeReadAdapter("wazuh")
        read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert fake.last_request.adapter == "wazuh"
        assert fake.last_request.external_reference == "cmd-999"

    def test_thehive_reader_receives_case_id(self, db_session):
        # For thehive the adapter-specific key case_id is the reference passed.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_thehive_rows("case-777"))
        fake = FakeReadAdapter("thehive")
        read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert fake.last_request.adapter == "thehive"
        assert fake.last_request.external_reference == "case-777"


#
# raw external states, never outcome words
#
class TestReadResultBoundary:
    @pytest.mark.parametrize(
        "raw_state",
        ["succeeded", "in_progress", "vendor-specific-unrecognized-state"],
        ids=["confirmed-success-evidence", "pending-evidence", "unknown-evidence"],
    )
    def test_success_evidence_is_raw_not_an_outcome_word(self, db_session, raw_state):
        # The fake returns raw external evidence for the success / pending / unknown
        # cases; the AdapterReadResult never carries an outcome word (the mapping edge
        # produces those) and has no outcome_status field.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", result=_result(raw_state))
        result = read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert result.external_state == raw_state
        assert result.external_state not in OUTCOME_STATUSES
        assert not hasattr(result, "outcome_status")

    def test_result_can_carry_structured_external_state(self, db_session):
        # external_state may be a small structured Mapping, still raw (unmapped).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        canned = _result({"status": "completed", "steps": 3})
        fake = FakeReadAdapter("shuffle", result=canned)
        result = read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert result.external_state == {"status": "completed", "steps": 3}

    def test_adapter_read_result_has_no_outcome_status_field(self):
        # The read result shape carries external_state / observed_at / raw_evidence
        # and nothing interpreted.
        assert set(AdapterReadResult.__dataclass_fields__) == {
            "external_state",
            "observed_at",
            "raw_evidence",
        }


#
# a read failure is a signal only; the read-failure path maps it
#
class TestReadFailureSignal:
    @pytest.mark.parametrize("exc_cls", [TimeoutError, ConnectionError, OSError])
    def test_17_read_failure_propagates_and_creates_no_outcome(self, db_session, exc_cls):
        # A fake reader that fails at transport level (timeout / connection /
        # transport): the raw failure surfaces, no Outcome Fact is created, and it is
        # not converted to reconciliation_failed (the read-failure path does that).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=exc_cls("simulated read failure"))
        before = _log_snapshot(db_session)
        with pytest.raises(exc_cls):
            read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert fake.call_count == 1  # the read was attempted (unlike unsupported)
        assert _outcome_count(db_session) == 0
        assert _log_snapshot(db_session) == before

    def test_read_failure_is_not_reconciliation_failed(self, db_session):
        # A real read() failing is not reconciliation_failed here — no outcome word of
        # any kind is written; the failure stays an ephemeral signal.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=TimeoutError("timed out"))
        with pytest.raises(TimeoutError):
            read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        rows = list(db_session.scalars(select(ExecutionOutcome)))
        assert rows == []
        assert all(r.outcome_status != "reconciliation_failed" for r in rows)

    def test_read_failure_is_distinct_from_unsupported(self, db_session):
        # A read failure (reader exists, read attempted) is a different signal from
        # UnsupportedAdapterRead (no reader, no attempt). Prove they diverge.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=ConnectionError("refused"))
        with pytest.raises(ConnectionError):
            read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        # the same chain, but with the empty registry, is UnsupportedAdapterRead —
        # a lookup rejection, not a transport failure.
        with pytest.raises(UnsupportedAdapterRead):
            read_external_state(db_session, eid, default_read_adapter_registry())


#
# no side capabilities
#
class TestNoSideCapabilities:
    def test_18_no_mapping(self):
        # The read path never maps an external_state onto an outcome word.
        modules, names = _service_import_surface()
        assert "normalize_external_state" not in names
        assert "map_external_state" not in names
        source = inspect.getsource(reconcile_module)
        assert "normalize_external_state" not in source

    def test_19_no_persistence(self, db_session):
        # No Outcome Fact is imported, constructed, or written — even with a fake
        # reader that returns successfully.
        _, names = _service_import_surface()
        assert "ExecutionOutcome" not in names
        assert "ExecutionOutcome(" not in inspect.getsource(reconcile_module)
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        read_external_state(db_session, eid, ReadAdapterRegistry([FakeReadAdapter("shuffle")]))
        assert _outcome_count(db_session) == 0

    def test_20_no_executor(self):
        # No write-side executor / dispatch is imported.
        modules, names = _service_import_surface()
        assert not any(m.startswith("app.services.executions") for m in modules)
        for forbidden in ("execute_response", "ResponseExecutor", "create_executor"):
            assert forbidden not in names

    def test_21_no_retry(self):
        # The read path never retries a read. AST-only: the service docstring names
        # "retry" in prose, so a source-substring check would false-positive; only the
        # import surface is trustworthy (docstring-immune).
        modules, names = _service_import_surface()
        assert not any("retry" in m.lower() for m in modules)
        assert not any("retry" in n.lower() for n in names)

    def test_22_no_compensation(self):
        # The read path never compensates.
        modules, names = _service_import_surface()
        assert not any("compensat" in m.lower() for m in modules)
        assert not any("compensat" in n.lower() for n in names)

    def test_23_no_http_transport_in_service(self):
        # The service module imports no HTTP client.
        modules, _ = _service_import_surface()
        assert not any(f in m for m in modules for f in ("httpx", "requests", "urllib"))
        assert not any("app.integrations" in m for m in modules)

    def test_23_no_http_transport_in_this_test_module(self):
        # This test harness (which owns the FakeReadAdapter) is offline too — it
        # imports no HTTP client and the fake does no network I/O.
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots.add(node.module)
        assert not any(f in r for r in roots for f in ("httpx", "requests", "urllib", "socket"))

    def test_fake_reader_is_not_a_production_reader(self):
        # The FakeReadAdapter is a ReadAdapter (structurally valid) but is not in the
        # production default registry — proven structurally.
        assert issubclass(FakeReadAdapter, ReadAdapter)
        assert default_read_adapter_registry().registered_adapters() == ()


#
# no DB write even with a fake reader (runtime)
#
class TestNoDatabaseWrite:
    def test_read_with_fake_reader_writes_nothing(self, db_session):
        # A successful fake read leaves execution_log byte-identical, stages nothing,
        # and writes zero Outcome Facts.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        before = _log_snapshot(db_session)
        read_external_state(
            db_session, eid, ReadAdapterRegistry([FakeReadAdapter("shuffle", result=_result("succeeded"))])
        )
        assert _log_snapshot(db_session) == before
        assert _outcome_count(db_session) == 0
        assert not list(db_session.new)
        assert not list(db_session.dirty)
        assert not list(db_session.deleted)

    def test_read_never_commits(self, db_session, monkeypatch):
        # Read-only means no commit — patch commit to explode; the fake-reader read
        # must still return without triggering it.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())

        def _boom():
            raise AssertionError("read_external_state must not COMMIT (spec §24)")

        monkeypatch.setattr(db_session, "commit", _boom)
        result = read_external_state(db_session, eid, ReadAdapterRegistry([FakeReadAdapter("shuffle")]))
        assert isinstance(result, AdapterReadResult)

    def test_read_creates_no_execution_log_row(self, db_session):
        # Reading never creates an execution_log row.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        count_before = len(_all_log_rows(db_session))
        read_external_state(db_session, eid, ReadAdapterRegistry([FakeReadAdapter("shuffle")]))
        assert len(_all_log_rows(db_session)) == count_before


#
# request and result are immutable
#
class TestImmutability:
    def test_24_request_is_immutable(self, db_session):
        # The AdapterReadRequest handed to the reader is frozen.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle")
        read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        request = fake.last_request
        with pytest.raises(FrozenInstanceError):
            request.adapter = "wazuh"  # type: ignore[misc]
        assert request.adapter == "shuffle"

    def test_25_result_is_immutable(self):
        # The AdapterReadResult is — no post-hoc outcome_status.
        result = _result("in_progress")
        with pytest.raises(FrozenInstanceError):
            result.external_state = "succeeded"  # type: ignore[misc]
        assert result.external_state == "in_progress"

    def test_request_fields_are_exact(self):
        # The read request carries execution_id / adapter / external_reference and no
        # operator / credential / outcome field.
        assert set(AdapterReadRequest.__dataclass_fields__) == {
            "execution_id",
            "adapter",
            "external_reference",
        }


#
# deterministic lookup + constructor injection
#
class TestDeterministicLookup:
    def test_26_repeated_lookup_is_deterministic(self):
        # A name always resolves to the same reader object; order is stable.
        fake = FakeReadAdapter("shuffle")
        registry = ReadAdapterRegistry([fake])
        assert registry.get("shuffle") is registry.get("shuffle") is fake
        assert registry.registered_adapters() == ("shuffle",)
        assert registry.registered_adapters() == ("shuffle",)

    def test_injected_registry_resolves_only_its_reader(self):
        # An explicit registry supports exactly the injected adapters.
        registry = ReadAdapterRegistry([FakeReadAdapter("shuffle")])
        assert registry.is_supported("shuffle")
        assert not registry.is_supported("wazuh")
        assert not registry.is_supported("mock")

    def test_duplicate_registration_is_a_construction_error(self):
        # Registry invariant: two readers with one name -> ValueError, never a silent
        # overwrite.
        with pytest.raises(ValueError):
            ReadAdapterRegistry([FakeReadAdapter("shuffle"), FakeReadAdapter("shuffle")])

    def test_repeated_read_is_deterministic(self, db_session):
        # Repeated reads over an unchanged chain yield equal results and leave the
        # chain byte-identical.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows("sf-stable"))
        before = _log_snapshot(db_session)
        fake = FakeReadAdapter("shuffle", result=_result("succeeded"))
        registry = ReadAdapterRegistry([fake])
        first = read_external_state(db_session, eid, registry)
        second = read_external_state(db_session, eid, registry)
        assert first.external_state == second.external_state == "succeeded"
        assert fake.call_count == 2  # one read per call, deterministic
        assert _log_snapshot(db_session) == before


#
# the client can never override adapter / reference / credential
#
class TestNoClientOverride:
    def test_read_external_state_takes_no_operator_or_client_value(self):
        # Structural: read_external_state(session, execution_id, registry) has no
        # adapter / operator / external_reference parameter, so a client value can
        # never enter the read; adapter + reference come only from ExecutionLog.
        params = list(inspect.signature(read_external_state).parameters)
        assert params == ["session", "execution_id", "registry"]
        for forbidden in ("operator", "adapter", "external_reference", "reference", "token", "credential"):
            assert forbidden not in params

    def test_operator_never_reaches_the_read(self, db_session):
        # reconcile_execution carries an operator, but it never reaches the read — the
        # request the fake receives has no operator / credential attribute, and the
        # adapter + reference are the historical ones regardless of the operator. The
        # shuffle read is now refused with UnrecognizedExternalState instead of the
        # NotImplementedError stub; every assertion below is unchanged.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows("sf-truth"))
        fake = FakeReadAdapter("shuffle")
        with pytest.raises(UnrecognizedExternalState):
            reconcile_execution(db_session, eid, "attacker-op", registry=ReadAdapterRegistry([fake]))
        request = fake.last_request
        assert request.adapter == "shuffle"
        assert request.external_reference == "sf-truth"
        for forbidden in ("operator", "token", "api_key", "credential", "callback_token"):
            assert not hasattr(request, forbidden)

    def test_adapter_and_reference_come_from_history(self, db_session):
        # With a shuffle chain in history, the fake reader receives the shuffle adapter
        # + the historical handle — there is no channel for a client override.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows("sf-historical"))
        fake = FakeReadAdapter("shuffle")
        read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert (fake.last_request.adapter, fake.last_request.external_reference) == (
            "shuffle",
            "sf-historical",
        )
        assert fake.last_request.execution_id == eid


#
# reconcile_execution never fabricates a 200 for an unevidenced read
#
class TestReconcileStopsAtResult:
    def test_reconcile_with_fake_reader_reads_then_not_implemented(self, db_session):
        # Even with a reader that returns successfully, reconcile_execution never
        # fabricates a 200 for a shuffle read. The NotImplementedError stub is gone:
        # the read reaches the external-state mapping, which refuses the shuffle state
        # ("succeeded" is unevidenced for shuffle) with UnrecognizedExternalState. The
        # guarantee is unchanged: the read happened exactly once and zero facts were
        # persisted (call_count / _outcome_count unchanged).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", result=_result("succeeded"))
        with pytest.raises(UnrecognizedExternalState):
            reconcile_execution(db_session, eid, "exec-op", registry=ReadAdapterRegistry([fake]))
        assert fake.call_count == 1
        assert _outcome_count(db_session) == 0

    def test_reconcile_default_registry_is_unsupported(self, db_session):
        # With no explicit registry (the empty production default), a reference-bearing
        # chain rejects with UnsupportedAdapterRead — never a read.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        with pytest.raises(UnsupportedAdapterRead):
            reconcile_execution(db_session, eid, "exec-op")
        assert _outcome_count(db_session) == 0

    def test_read_external_state_returns_internal_result(self, db_session):
        # read_external_state yields the internal AdapterReadResult, the terminal
        # artifact of this layer's platform chain — nothing further is produced here.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        canned = _result("succeeded", raw_evidence={"external_status": "succeeded"})
        fake = FakeReadAdapter("shuffle", result=canned)
        result = read_external_state(db_session, eid, ReadAdapterRegistry([fake]))
        assert result is canned

    def test_reconcile_registry_defaults_to_none(self):
        # reconcile_execution's registry parameter defaults to None (resolved to the
        # empty production default) — a test must pass an explicit instance.
        signature = inspect.signature(reconcile_execution)
        assert signature.parameters["registry"].default is None

    def test_read_external_state_requires_explicit_registry(self):
        # read_external_state has no default registry — the caller must inject one, so
        # production can never accidentally resolve a reader.
        signature = inspect.signature(read_external_state)
        assert signature.parameters["registry"].default is inspect.Parameter.empty
