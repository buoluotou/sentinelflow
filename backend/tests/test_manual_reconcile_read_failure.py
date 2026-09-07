"""3.4.5-A2-D Manual Reconcile — READ FAILURE -> ``reconciliation_failed`` acceptance.

This is the step that FIRST turns a definition into behaviour. A2-C proved the
platform chain down to ``reader.read()`` and deliberately LEFT a transport failure
as a raw, ephemeral signal (``TestReadFailureSignal`` — NO fact, NO conversion).
A2-D converts ONE thing and only ONE thing:

    a reader EXISTED, ``read()`` was ACTUALLY invoked, and it FAILED in transit
    (timeout / connection / transport / unavailable)  ->  ``reconciliation_failed``
    -> append EXACTLY ONE Outcome Fact -> HTTP 200 (design §4.3).

THE INVARIANT THAT MUST NEVER SLIP (spec §6 / §9 / §27 — the crux of A2-D): two
rejections that look adjacent stay STRICTLY disjoint, and this file proves them
SIDE BY SIDE on the SAME chain (``TestCaseAAndCaseBSideBySide``):

  * Case A — NO reader (``registry.get`` finds nothing): ``UnsupportedAdapterRead``
    -> 404 -> ZERO Outcome Facts, and NEVER ``reconciliation_failed``. There was no
    read ATTEMPT, so there is nothing to have "failed". This is EVERY adapter in the
    EMPTY production registry (shuffle / wazuh / thehive / mock / unknown).
  * Case B — a reader EXISTS (a test-injected ``FakeReadAdapter``) and ``read()``
    raises a transport error -> ``reconciliation_failed`` -> EXACTLY ONE fact.

``reconciliation_failed`` (the RECONCILE ACTION could not read the outside world —
fact source is the reconciliation process) is NEVER ``confirmed_failure`` (the
outside world was read and said the effect was NOT achieved — a MAPPED external
state, 3.4.3-B, A2-E). A2-D writes the former and can never write the latter: it
performs NO mapping (spec §16 / §21), so at the A2-D SEAL a SUCCESSFUL read stopped at
``NotImplementedError`` -> 501 with ZERO facts. (A2-E FLAG: A2-E replaced that stub — a
SUCCESSFUL SHUFFLE read is now REFUSED at 3.4.3-B mapping with ``UnrecognizedExternalState``
-> 422 and STILL ZERO facts, since shuffle has no evidenced vocabulary, §四. The A2-D
read-FAILURE path proven below is byte-identical and untouched.)

WHAT D DELIBERATELY DOES NOT DO (AST- + runtime-proven below): NO real
Shuffle/Wazuh/TheHive read, NO HTTP, NO mapping / ``normalize_external_state``, NO
SUCCESS-fact persistence, NO executor / dispatch / compensation, NO retry / sleep /
backoff (ONE read attempt, spec §15), NO global-registry mutation (the fake enters
ONLY an EXPLICIT ``ReadAdapterRegistry([fake])`` constructor injection, spec §22).
The read-FAILURE path is the ONE writer, and it reuses ``webhook.py``'s persistence
vocabulary (the ``ExecutionOutcomeFact`` alias + ``OutcomePersistenceError``) for a
single APPEND-ONLY INSERT — never a second ORM writer (spec §22 / §23).

Secret hygiene (spec §10 / §25): the fact ``detail`` records ONLY a SAFE STATIC
classification (``adapter`` / ``external_reference`` / ``failure_category`` /
``reason``) — NEVER ``str(exc)``, a callback token, an operator token, an adapter
API key, an ``Authorization`` header, or a password. The raw transport exception's
message is never read into any artifact, so a secret-bearing failure string cannot
leak into the fact or the response.

Covered here (spec §26 items 1-29 + §27 Case A/B): the four transport shapes
(timeout / connection / transport / unavailable), read-called-exactly-once, the
``reconciliation_failed`` verdict + its persisted fact, ``source`` /
human ``operator`` / server ``observed_at``, historical-outcome + execution_log
immutability, the two disjoint rejections, contract / mapping failures -> zero
fact, no retry / compensation / execute, secret non-leakage, append-only derivation
(latest read failure wins over a prior ``confirmed_success``), repeat reconcile ->
separate facts, rollback on persistence failure, and the two gate-ordering proofs
(no read when the reference is missing / the registry is unsupported).
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
from app.services.outcomes import manual_reconcile as reconcile_module
from app.services.outcomes.manual_reconcile import (
    read_external_state,
    reconcile_execution,
)
from app.services.outcomes.reconciliation import (
    MissingExternalReference,
    UnrecognizedExternalState,
)
from app.services.outcomes.webhook import OutcomePersistenceError

#: Fixed clock for seeding the DISPATCH chain (execution_log.created_at). The
#: OUTCOME facts deliberately use the real ``datetime.now`` because the service
#: stamps ``observed_at`` with the server clock at reconcile time (spec §9).
NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)

#: The reconcile path template (execution_id is a PATH param).
RECONCILE = "/api/v1/executions/{eid}/reconcile"

#: The authenticated operator identity used for service-level calls. It is a HUMAN
#: recorder name (spec §11) — NEVER the webhook's ``adapter:{identity}`` machine
#: domain, and NEVER a client-supplied string.
OPERATOR = "exec-op"

#: A failure message LOADED with things that must NEVER reach a fact or a response
#: (spec §10 / §25). If the service ever did ``str(exc)`` into ``detail``, these
#: substrings would surface — the hygiene tests assert they do not.
SECRETY_MESSAGE = (
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


def _url(eid: str) -> str:
    return RECONCILE.format(eid=eid)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# test-only FakeReadAdapter (spec §4 / §22) — NEVER a production reader. It has
# ONLY ``name`` + ``read`` (no execute / compensate / dispatch / trigger verb) and
# performs NO I/O: ``read`` raises the primed transport error (A2-D read failure)
# or returns a canned result. It records its call count so tests can prove read()
# was invoked EXACTLY once (spec §26 item 5) or NEVER (items 28 / 29).
# ---------------------------------------------------------------------------
def _result(external_state, *, observed_at=None, raw_evidence=None):
    return AdapterReadResult(
        external_state=external_state,
        observed_at=observed_at,
        raw_evidence=raw_evidence if raw_evidence is not None else {},
    )


class FakeReadAdapter(ReadAdapter):
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


# ---------------------------------------------------------------------------
# seeding + snapshot helpers (mirror test_manual_reconcile_reader.py; the chain
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
    """One execute chain from ``[(decision, detail), ...]`` in CHRONOLOGICAL order."""
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


def _seed_historical_outcome(
    db_session,
    execution_id,
    *,
    status="confirmed_success",
    source="webhook",
    operator="adapter:shuffle",
    hours_ago=1,
):
    """A PRIOR Outcome Fact for the same execution (spec §13 / §24 / §25). Its
    ``observed_at`` is a REAL past server time so the reconcile read failure the
    service stamps with ``datetime.now`` is strictly LATER (latest-wins derivation).
    Seeded as a ``webhook`` fact to prove the manual_reconcile append COEXISTS with
    a different source, never overwrites it."""
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
            select(ExecutionOutcome).where(
                ExecutionOutcome.execution_id == execution_id
            )
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
    """Full-table content snapshot of execution_log INCLUDING ``detail`` (spec §26
    item 12: D must not mutate the dispatch log). JSON-canonicalized, keyed by id."""
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
    """AST import surface of the A2-D service module (docstring-immune)."""
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def operators(monkeypatch):
    """Executor operator via OPERATORS_JSON (the 3.3.1 harness) for the API-level
    Case A test. The conftest autouse fixture resets the module-level registry
    around every test, so the monkeypatched config always takes effect."""
    monkeypatch.setattr(
        settings,
        "OPERATORS_JSON",
        json.dumps([{"token": "tok-exec", "name": OPERATOR, "role": "executor"}]),
    )


# ===========================================================================
# spec §27 — Case A and Case B MUST appear side by side (the crux of A2-D)
# ===========================================================================
class TestCaseAAndCaseBSideBySide:
    """The SAME correlated, reference-bearing shuffle chain, run against TWO
    registries. Case A (EMPTY) and Case B (a fake that times out) MUST diverge —
    a zero-fact rejection vs a one-fact ``reconciliation_failed`` verdict. They are
    NEVER the same outcome, and Case A is NEVER ``reconciliation_failed``."""

    def test_case_a_then_case_b_on_the_same_chain_diverge(self, db_session):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())

        # --- Case A: registry EMPTY -> UnsupportedAdapterRead -> ZERO facts -----
        with pytest.raises(UnsupportedAdapterRead):
            reconcile_execution(db_session, eid, OPERATOR, default_read_adapter_registry())
        assert _outcome_count(db_session) == 0

        # --- Case B: fake registered, read() times out -> reconciliation_failed -
        fake = FakeReadAdapter("shuffle", error=TimeoutError("simulated timeout"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert isinstance(response, ManualReconcileResponse)
        assert response.outcome_status == "reconciliation_failed"
        assert fake.call_count == 1
        assert _outcome_count(db_session) == 1

    def test_case_a_api_empty_registry_404_zero_facts(self, client, operators, db_session):
        # Case A over HTTP: the route uses the EMPTY production registry, so a
        # correlated, reference-bearing shuffle chain rejects 404 with a STATIC
        # detail and writes ZERO facts (spec §27 Case A / §26 items 13-14).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        r = client.post(_url(str(eid)), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 404
        assert r.json()["detail"] == "adapter read unsupported"
        assert _outcome_count(db_session) == 0

    def test_case_a_unsupported_is_not_reconciliation_failed(self, db_session):
        # spec §26 item 14: a registry LOOKUP failure is NOT a read attempt, so it
        # produces NO outcome word of any kind — never reconciliation_failed.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        with pytest.raises(UnsupportedAdapterRead):
            reconcile_execution(db_session, eid, OPERATOR, default_read_adapter_registry())
        rows = _facts(db_session, eid)
        assert rows == []
        assert all(r.outcome_status not in OUTCOME_STATUSES for r in rows)


# ===========================================================================
# spec §26 items 1-10 — Case B: the reconciliation_failed verdict + its fact
# ===========================================================================
class TestReadTransportFailureVerdict:
    @pytest.mark.parametrize(
        "error,expected_category",
        [
            (TimeoutError("simulated timeout"), "timeout"),
            (ConnectionError("simulated connection refused"), "connection_failure"),
            (OSError("simulated transport error"), "transport_error"),
            (
                ReadTransportError("simulated adapter unavailable", category="adapter_unavailable"),
                "adapter_unavailable",
            ),
        ],
        ids=["timeout", "connection", "transport", "unavailable"],
    )
    def test_01_04_every_transport_shape_is_reconciliation_failed(
        self, db_session, error, expected_category
    ):
        # spec §26 items 1-4: timeout / connection error / transport error /
        # unavailable ALL close to the SAME reconciliation_failed verdict, each with
        # its SAFE STATIC failure_category recorded (spec §10). The domain
        # ReadTransportError and the builtin transport errors are caught as a UNION.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=error)
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.outcome_status == "reconciliation_failed"
        assert fake.call_count == 1
        fact = _only_fact(db_session, eid)
        assert fact.outcome_status == "reconciliation_failed"
        assert fact.detail["failure_category"] == expected_category
        assert fact.detail["reason"] == "read_transport_failure"

    def test_05_read_called_exactly_once(self, db_session):
        # spec §26 item 5 / §15: ONE read attempt — the failure path re-extracts the
        # context (read-only, no read) but NEVER re-invokes read().
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=TimeoutError("simulated timeout"))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert fake.call_count == 1
        assert len(fake.requests) == 1

    def test_06_read_failure_is_reconciliation_failed_not_confirmed_failure(self, db_session):
        # spec §26 item 6 + the opening admonition: reconciliation_failed (the
        # reconcile ACTION could not read) is NEVER confirmed_failure (a MAPPED
        # external verdict). D writes no mapping, so confirmed_failure is impossible.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=ConnectionError("refused"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.outcome_status == "reconciliation_failed"
        assert response.outcome_status != "confirmed_failure"
        assert _only_fact(db_session, eid).outcome_status == "reconciliation_failed"

    def test_07_reconciliation_failed_fact_persisted(self, db_session):
        # spec §26 item 7: exactly ONE reconciliation_failed row is committed.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=TimeoutError("simulated timeout"))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        fact = _only_fact(db_session, eid)
        assert fact.execution_id == eid
        assert fact.outcome_status == "reconciliation_failed"

    def test_08_source_is_manual_reconcile(self, db_session):
        # spec §26 item 8 / §12: the ingress channel is FIXED server-side.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=TimeoutError("simulated timeout"))
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert response.source == MANUAL_RECONCILE_SOURCE == "manual_reconcile"
        assert _only_fact(db_session, eid).source == "manual_reconcile"

    def test_09_operator_is_human_not_adapter_machine(self, db_session):
        # spec §26 item 9 / §11: the recorder is the AUTHENTICATED HUMAN operator,
        # NEVER the webhook's ``adapter:{identity}`` machine trust domain.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=TimeoutError("simulated timeout"))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        fact = _only_fact(db_session, eid)
        assert fact.operator == OPERATOR == "exec-op"
        assert not fact.operator.startswith("adapter:")

    def test_10_observed_at_is_server_observation_time(self, db_session):
        # spec §26 item 10 / §9: a read failure carries NO trustworthy external
        # timestamp, so the fact time is the SERVER OBSERVATION time (aware, ~now),
        # and the envelope DECLARES it via observed_at_kind (never dressed as an
        # external event time).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=TimeoutError("simulated timeout"))
        before = datetime.now(timezone.utc)
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        after = datetime.now(timezone.utc)
        assert response.observed_at_kind == "server-observation"
        assert response.observed_at.tzinfo is not None
        assert before <= response.observed_at <= after


# ===========================================================================
# spec §7 — the conversion lives ONLY in reconcile_execution (A2-C split intact)
# ===========================================================================
class TestConversionLivesOnlyInTheEntrypoint:
    def test_read_external_state_still_propagates_raw_while_entrypoint_converts(
        self, db_session
    ):
        # spec §7: ``read_external_state`` stays a PURE PROPAGATOR (the A2-C
        # ``TestReadFailureSignal`` locks it) — it raises the builtin UNCHANGED and
        # writes NOTHING. The reconciliation_failed conversion lives ONLY in
        # ``reconcile_execution``. Same chain, same failure, two different layers.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())

        with pytest.raises(TimeoutError):
            read_external_state(
                db_session,
                eid,
                ReadAdapterRegistry([FakeReadAdapter("shuffle", error=TimeoutError("t"))]),
            )
        assert _outcome_count(db_session) == 0  # the propagator wrote nothing

        response = reconcile_execution(
            db_session,
            eid,
            OPERATOR,
            ReadAdapterRegistry([FakeReadAdapter("shuffle", error=TimeoutError("t"))]),
        )
        assert response.outcome_status == "reconciliation_failed"
        assert _outcome_count(db_session) == 1  # the entrypoint appended exactly one


# ===========================================================================
# spec §26 items 11-12 / 24-26 / §13 — append-only, immutability, derivation
# ===========================================================================
class TestAppendOnlyAndDerivation:
    def test_11_historical_outcome_unchanged(self, db_session):
        # spec §26 item 11 / §13: appending the read-failure fact NEVER touches a
        # prior fact — the historical row is byte-identical afterwards.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        hist = _seed_historical_outcome(db_session, eid)
        hist_snapshot = _fact_snapshot(hist)
        before_count = len(_facts(db_session, eid))

        reconcile_execution(
            db_session,
            eid,
            OPERATOR,
            ReadAdapterRegistry([FakeReadAdapter("shuffle", error=TimeoutError("t"))]),
        )

        hist_after = db_session.get(ExecutionOutcome, hist.id)
        assert _fact_snapshot(hist_after) == hist_snapshot
        assert len(_facts(db_session, eid)) == before_count + 1  # APPEND, not replace

    def test_12_execution_log_unchanged(self, db_session):
        # spec §26 item 12: the dispatch log is SELECT-only — the read-failure path
        # never UPDATEs / DELETEs / INSERTs an execution_log row.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        before = _log_snapshot(db_session)
        reconcile_execution(
            db_session,
            eid,
            OPERATOR,
            ReadAdapterRegistry([FakeReadAdapter("shuffle", error=TimeoutError("t"))]),
        )
        assert _log_snapshot(db_session) == before

    def test_13_two_facts_coexist_derived_is_latest(self, db_session):
        # spec §13: T1 confirmed_success + T2 (reconcile) timeout -> TWO facts, the
        # history STILL exists, and the DERIVED state is reconciliation_failed
        # (observed_at DESC / id DESC). The stored series is never rewritten.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        _seed_historical_outcome(db_session, eid, status="confirmed_success")

        response = reconcile_execution(
            db_session,
            eid,
            OPERATOR,
            ReadAdapterRegistry([FakeReadAdapter("shuffle", error=TimeoutError("t"))]),
        )

        statuses = sorted(f.outcome_status for f in _facts(db_session, eid))
        assert statuses == ["confirmed_success", "reconciliation_failed"]
        assert response.derived_outcome_status == "reconciliation_failed"

    def test_24_derivation_latest_read_failure_wins(self, db_session):
        # spec §26 item 24: the derived state over the series is the LATEST
        # observation — the fresh reconciliation_failed, not the older
        # confirmed_success. This is derivation, not an echo of this observation.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        _seed_historical_outcome(db_session, eid, status="confirmed_success", hours_ago=2)
        response = reconcile_execution(
            db_session,
            eid,
            OPERATOR,
            ReadAdapterRegistry([FakeReadAdapter("shuffle", error=TimeoutError("t"))]),
        )
        assert response.derived_outcome_status == "reconciliation_failed"
        assert response.outcome_status == "reconciliation_failed"

    def test_25_previous_confirmed_success_immutable(self, db_session):
        # spec §26 item 25: the prior confirmed_success fact survives UNCHANGED —
        # the new verdict is APPENDED, the history is never reinterpreted (O5).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        hist = _seed_historical_outcome(db_session, eid, status="confirmed_success")
        hist_snapshot = _fact_snapshot(hist)
        reconcile_execution(
            db_session,
            eid,
            OPERATOR,
            ReadAdapterRegistry([FakeReadAdapter("shuffle", error=TimeoutError("t"))]),
        )
        hist_after = db_session.get(ExecutionOutcome, hist.id)
        assert _fact_snapshot(hist_after) == hist_snapshot
        assert hist_after.outcome_status == "confirmed_success"

    def test_26_repeat_reconcile_creates_separate_facts(self, db_session):
        # spec §26 item 26 / §13: two failing reconciles APPEND two distinct facts
        # (INSERT-only — never UPDATE / UPSERT / MERGE), forming a time series.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        r1 = reconcile_execution(
            db_session,
            eid,
            OPERATOR,
            ReadAdapterRegistry([FakeReadAdapter("shuffle", error=TimeoutError("t1"))]),
        )
        r2 = reconcile_execution(
            db_session,
            eid,
            OPERATOR,
            ReadAdapterRegistry([FakeReadAdapter("shuffle", error=TimeoutError("t2"))]),
        )
        facts = _facts(db_session, eid)
        assert len(facts) == 2
        assert len({f.id for f in facts}) == 2  # distinct rows, not an upsert
        assert all(f.outcome_status == "reconciliation_failed" for f in facts)
        assert r1.outcome_status == r2.outcome_status == "reconciliation_failed"


# ===========================================================================
# spec §26 items 20-23 / §10 / §25 — secret hygiene
# ===========================================================================
class TestReadFailureSecretHygiene:
    def test_20_no_api_credential_in_detail(self, db_session):
        # spec §26 item 20: an adapter API key in the failure message NEVER reaches
        # the fact detail — only the static classification is recorded.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter(
            "shuffle", error=ReadTransportError(SECRETY_MESSAGE, category="timeout")
        )
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        detail_json = json.dumps(_only_fact(db_session, eid).detail)
        assert "AKIAIOSFODNN7EXAMPLE" not in detail_json
        assert "api_key" not in detail_json.lower()

    def test_21_no_authorization_in_detail(self, db_session):
        # spec §26 item 21: an Authorization header / Bearer token in the failure
        # message NEVER reaches the fact detail.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter(
            "shuffle", error=ReadTransportError(SECRETY_MESSAGE, category="timeout")
        )
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        detail_json = json.dumps(_only_fact(db_session, eid).detail).lower()
        assert "authorization" not in detail_json
        assert "bearer" not in detail_json
        assert "super_secret_token" not in detail_json

    def test_22_raw_exception_message_never_recorded(self, db_session):
        # spec §26 item 22 / §25: the service records ONLY the static category, never
        # ``str(exc)``. A builtin TimeoutError carrying secrets proves the raw message
        # is not copied into the fact, and only the safe class survives.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=TimeoutError(SECRETY_MESSAGE))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        fact = _only_fact(db_session, eid)
        detail_json = json.dumps(fact.detail)
        for secret in SECRET_SUBSTRINGS:
            assert secret not in detail_json
        assert fact.detail["failure_category"] == "timeout"
        assert set(fact.detail) == {
            "adapter",
            "external_reference",
            "failure_category",
            "reason",
        }

    def test_23_no_token_in_response(self, db_session):
        # spec §26 item 23: the ManualReconcileResponse envelope leaks no secret from
        # the failure — it carries only the safe verdict + provenance fields.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter(
            "shuffle", error=ReadTransportError(SECRETY_MESSAGE, category="timeout")
        )
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        response_json = response.model_dump_json()
        for secret in SECRET_SUBSTRINGS:
            assert secret not in response_json
        assert response.accepted is True
        assert response.outcome_status == "reconciliation_failed"


# ===========================================================================
# spec §26 items 17-19 / §2 / §15 — no retry, no compensation, no execution
# ===========================================================================
class TestReadFailureNoSideCapabilities:
    def test_17_no_retry_no_sleep(self, db_session):
        # spec §26 item 17 / §15: ONE read attempt, no retry / sleep / backoff /
        # loop. Runtime (call_count == 1) + the import surface carries no ``time`` /
        # ``asyncio`` to sleep with.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=TimeoutError("t"))
        reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert fake.call_count == 1
        modules, _ = _service_import_surface()
        assert "time" not in modules
        assert "asyncio" not in modules

    def test_18_no_compensation(self, db_session):
        # spec §26 item 18: a read failure NEVER triggers compensation — no new
        # execution_log row (a compensation would be a fresh chain), and no
        # write-side executor import.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        before = _log_snapshot(db_session)
        reconcile_execution(
            db_session,
            eid,
            OPERATOR,
            ReadAdapterRegistry([FakeReadAdapter("shuffle", error=TimeoutError("t"))]),
        )
        assert _log_snapshot(db_session) == before
        modules, _ = _service_import_surface()
        assert not any(m.startswith("app.services.executions") for m in modules)

    def test_19_no_execute_no_dispatch(self):
        # spec §26 item 19 / §2: the service imports NO write-side executor /
        # dispatch / compensation stack — a fact row can never trigger execution.
        modules, names = _service_import_surface()
        assert not any(m.startswith("app.services.executions") for m in modules)
        assert "create_executor" not in names
        assert "ResponseExecutor" not in names
        assert "compensate_response" not in names


# ===========================================================================
# spec §26 items 15-16 / 28 — gate ordering: failures BEFORE the read write 0
# ===========================================================================
class TestReadFailureGateOrdering:
    def test_15_contract_failure_zero_fact(self, db_session):
        # spec §26 item 15: a chain with NO reconcilable external reference rejects
        # with MissingExternalReference BEFORE any read — ZERO facts (a contract
        # failure is never laundered into reconciliation_failed).
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
        fake = FakeReadAdapter("shuffle", error=TimeoutError("would fail"))
        with pytest.raises(MissingExternalReference):
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert _outcome_count(db_session) == 0

    def test_16_successful_read_maps_nothing_zero_fact(self, db_session):
        # spec §26 item 16 / §16: a SUCCESSFUL SHUFFLE read maps to NOTHING and writes
        # ZERO facts. A2-E FLAG: at the A2-D seal this stopped at the NotImplementedError
        # stub; A2-E replaced it with the real 3.4.3-B mapping edge, which REFUSES the
        # shuffle state ("succeeded" is unevidenced for shuffle, §四) with
        # UnrecognizedExternalState -> STILL zero facts. The invariant is UNWEAKENED and
        # the two assertions below are VERBATIM UNCHANGED.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", result=_result("succeeded"))
        with pytest.raises(UnrecognizedExternalState):
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert fake.call_count == 1  # the read DID succeed
        assert _outcome_count(db_session) == 0  # but nothing was mapped / persisted

    def test_28_no_adapter_read_if_external_reference_missing(self, db_session):
        # spec §26 item 28 / §10: the extraction gate runs BEFORE registry.get /
        # read() — a missing reference means read() is NEVER invoked (call_count 0).
        eid = uuid.uuid4()
        _seed_chain(
            db_session,
            eid,
            rows=[("requested", {"executor": "shuffle"}), ("failed", {})],
        )
        fake = FakeReadAdapter("shuffle", error=TimeoutError("would fail"))
        with pytest.raises(MissingExternalReference):
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))
        assert fake.call_count == 0
        assert _outcome_count(db_session) == 0

    def test_29_no_adapter_read_if_registry_unsupported(self, db_session):
        # spec §26 item 29 / §6: with the EMPTY registry no reader exists, so read()
        # is NEVER invoked — an unregistered fake stays at call_count 0 and the path
        # is UnsupportedAdapterRead (zero facts), NOT reconciliation_failed.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle")  # deliberately NOT registered
        with pytest.raises(UnsupportedAdapterRead):
            reconcile_execution(db_session, eid, OPERATOR, default_read_adapter_registry())
        assert fake.call_count == 0
        assert _outcome_count(db_session) == 0


# ===========================================================================
# spec §26 item 27 / §23 — rollback when the fact append itself fails
# ===========================================================================
class TestReadFailurePersistenceRollback:
    def test_27_rollback_if_persistence_fails(self, db_session, monkeypatch):
        # spec §26 item 27 / §23: if the reconciliation_failed append FAILS at the
        # DB layer, the transaction is ROLLED BACK (no partial fact survives) and an
        # OutcomePersistenceError surfaces — the router maps it to a 5xx, NEVER
        # accepted=true, NEVER an infra error laundered into reconciliation_failed.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_shuffle_rows())
        fake = FakeReadAdapter("shuffle", error=TimeoutError("simulated timeout"))

        def _commit_boom():
            raise SQLAlchemyError("simulated commit failure")

        # Fail ONLY the fact commit (the seed chain already committed above).
        monkeypatch.setattr(db_session, "commit", _commit_boom)
        with pytest.raises(OutcomePersistenceError):
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([fake]))

        # rollback undid the flushed INSERT — no partial fact survives.
        assert _outcome_count(db_session) == 0
        # the dispatch log the seed committed is untouched by the rollback.
        assert len(_all_log_rows(db_session)) == 3
