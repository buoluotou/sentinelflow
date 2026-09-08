"""TheHive WRITE -> READ closure (Phase 3.4.5-M2 §6, LAB-BLOCKED substitute).

§6 asks for the full platform chain: controlled TheHive case creation -> saved REAL
resource reference -> explicit Manual Reconcile -> real ``GET case`` -> independent
Outcome -> audit query. The real ``GET`` against a live TheHive is LAB BLOCKED (no
container runtime / virtualization / memory on this host), so this file proves the
closure with the REAL ``TheHiveExecutor`` (write) and the REAL ``TheHiveReadAdapter``
(read) joined by INJECTED stub transports and the REAL reconcile pipeline over an
in-memory DB — NO network, and NO mock ever passed off as a real TheHive.

WHAT THIS PROVES THAT NO SINGLE-ADAPTER TEST CAN (the §6 crux):

  * the correlation tag the WRITE side POSTs into ``InputCase.tags``
    (``sentinelflow_execution_tag(execution_id)``) is the EXACT string the READ side
    re-verifies on ``GET /api/case/{_id}`` — a single source of truth imported from
    ``executions.thehive`` by BOTH adapters, so it can never drift;
  * the STRING ``case_id`` (``OutputCase._id``) the executor returns is the EXACT
    reference the reconcile extraction (``_EXTERNAL_REFERENCE_KEYS["thehive"]``)
    hands the reader — never the numeric ``caseId``;
  * a DIFFERENT execution can NEVER claim the same case (its tag does not match) ->
    ``case_unverified`` -> REFUSED -> zero fact (no cross-execution / historical
    mis-attribution);
  * the closure lands ONE independent ``confirmed_success`` Outcome Fact via the
    real append-only pipeline, retrievable by an audit query.

FAITHFULNESS NOTE: the dispatch chain is seeded with the REAL executor's returned
``detail`` (exactly what the execution service writes onto the terminal
``execution_log`` row), mirroring the sanctioned isolation pattern in
``test_manual_reconcile_read_failure.py`` rather than re-driving the whole HTTP
execution service. The write and read are both REAL adapters; only the transport is
stubbed and only the chain persistence is reproduced.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import (
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    ExecutionLog,
    ExecutionOutcome,
)
from app.schemas.reconcile import MANUAL_RECONCILE_SOURCE
from app.services.executions import ExecutionDispatch, TheHiveExecutor
from app.services.executions.secrets import AdapterCredentials
from app.services.executions.thehive import (
    SENTINELFLOW_TAG,
    sentinelflow_approval_tag,
    sentinelflow_execution_tag,
)
from app.services.manual_reconcile import AdapterReadRequest, ReadAdapterRegistry
from app.services.outcomes.manual_reconcile import reconcile_execution
from app.services.outcomes.reconciliation import UnrecognizedExternalState
from app.services.read_adapters.thehive import (
    CASE_CREATED,
    CASE_UNVERIFIED,
    TheHiveReadAdapter,
)

LAB_BASE_URL = "https://thehive.lab.local"
LAB_API_KEY = "LAB_THEHIVE_KEY_DO_NOT_USE"
ESCALATE = "escalate_to_incident"
TARGET = "INC-2026-0142"
REFERENCE = "~42"  # the STRING OutputCase._id (EntityIdOrName id-prefix form)
CASE_NUMBER = 42  # the Int human case NUMBER — audit-only, NEVER the reference
OPERATOR = "recon-op"
NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# stub transport (the isolation seam — NO socket is ever opened)
# ---------------------------------------------------------------------------
class _Resp:
    def __init__(self, status, body_bytes):
        self.status = status
        self._body = body_bytes

    def read(self):
        return self._body


class StubTransport:
    """Records every outbound ``urllib`` Request and plays back a fixed payload.
    Used for BOTH the write POST and the read GET so the two real adapters talk to
    a deterministic, offline double."""

    def __init__(self, *, status=200, payload=None):
        self._status = status
        self._payload = payload if payload is not None else {}
        self.calls = []

    def __call__(self, request, timeout=None):
        self.calls.append(request)
        return _Resp(self._status, json.dumps(self._payload).encode("utf-8"))

    @property
    def last(self):
        return self.calls[-1]

    @property
    def call_count(self):
        return len(self.calls)


def _creds():
    return AdapterCredentials(adapter="thehive", base_url=LAB_BASE_URL, api_key=LAB_API_KEY)


def _recent_created_ms(minutes_ago=3):
    return int(
        (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).timestamp() * 1000
    )


def _created_case(execution_id, approval_id, *, created_ms=None):
    """The OutputCase a real TheHive 4.1.24-1 (``b6649bb``) returns on create AND
    re-serves on ``GET /api/case/{_id}``: ``_id`` == ``id`` (String), ``caseId``
    (Int number), ``createdAt`` (epoch millis), and ``tags`` — the ``Set[String]``
    ``CaseSrv.create`` persists from ``InputCase.tags`` and echoes back."""
    return {
        "_id": REFERENCE,
        "id": REFERENCE,
        "caseId": CASE_NUMBER,
        "createdAt": created_ms if created_ms is not None else _recent_created_ms(),
        "tags": [
            SENTINELFLOW_TAG,
            sentinelflow_execution_tag(execution_id),
            sentinelflow_approval_tag(approval_id),
        ],
        "title": f"SentinelFlow escalation: {TARGET}",
        "status": "Open",
        "severity": 3,
    }


def _dispatch(execution_id, approval_id):
    return ExecutionDispatch(
        execution_id=execution_id,
        action=ESCALATE,
        target=TARGET,
        approval_id=approval_id,
    )


def _create_case(execution_id, approval_id):
    """Run the REAL executor against a stub: returns ``(outcome, posted_tags,
    created_case)`` — the write half of the closure."""
    created = _created_case(execution_id, approval_id)
    write = StubTransport(status=201, payload=created)
    executor = TheHiveExecutor(_creds(), timeout=1.0, transport=write)
    outcome = executor.execute(_dispatch(execution_id, approval_id))
    posted_tags = json.loads(write.last.data.decode("utf-8"))["tags"]
    return outcome, posted_tags, created


# ---------------------------------------------------------------------------
# DB seeding (mirrors test_manual_reconcile_read_failure.py's isolation pattern)
# ---------------------------------------------------------------------------
def _seed_chain(db_session, execution_id, *, rows):
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
        recommendations=[{"action": ESCALATE, "target": TARGET, "rationale": "escalate"}],
        confidence=0.7,
    )
    db_session.add(record)
    db_session.flush()
    approval = AIResponseApproval(
        recommendation_id=record.id, status="approved", reviewer="analyst-1", reviewed_at=NOW
    )
    db_session.add(approval)
    db_session.flush()
    db_session.add_all(
        [
            ExecutionLog(
                execution_id=execution_id,
                approval_id=approval.id,
                decision=decision,
                direction="execute",
                action=ESCALATE,
                target=TARGET,
                operator="ops-1",
                detail=detail,
                created_at=NOW + timedelta(seconds=i),
            )
            for i, (decision, detail) in enumerate(rows)
        ]
    )
    db_session.commit()
    return approval


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


# ===========================================================================
# 1. WRITE -> READ correlation handshake (no DB): one source of truth
# ===========================================================================
class TestWriteReadCorrelationHandshake:
    def test_executor_returns_the_string_reference_and_posts_the_tag(self):
        eid = uuid.uuid4()
        aid = uuid.uuid4()
        outcome, posted_tags, created = _create_case(eid, aid)
        assert outcome.status == "succeeded"
        # the reconcile key carries the STRING _id, NEVER the numeric caseId.
        assert outcome.detail["case_id"] == REFERENCE
        assert outcome.detail["case_number"] == CASE_NUMBER
        assert "case_id" not in created  # TheHive emits _id/id, SentinelFlow derives case_id
        # the correlation tag the writer POSTed is the canonical single-source string.
        assert sentinelflow_execution_tag(eid) in posted_tags
        assert posted_tags == created["tags"]  # create persists + echoes InputCase.tags

    def test_reader_verifies_the_case_bearing_the_executors_own_tag(self):
        eid = uuid.uuid4()
        aid = uuid.uuid4()
        outcome, posted_tags, created = _create_case(eid, aid)
        read = StubTransport(status=200, payload=created)  # GET echoes the persisted case
        reader = TheHiveReadAdapter(_creds(), timeout=1.0, transport=read)
        result = reader.read(
            AdapterReadRequest(
                execution_id=eid, adapter="thehive", external_reference=outcome.detail["case_id"]
            )
        )
        assert result.external_state == CASE_CREATED
        assert result.observed_at is not None  # createdAt supplied the authoritative time
        assert read.call_count == 1  # ONE read — no retry / poll / compensation

    def test_a_different_execution_cannot_claim_the_same_case(self):
        eid = uuid.uuid4()
        aid = uuid.uuid4()
        other = uuid.uuid4()
        outcome, _posted_tags, created = _create_case(eid, aid)
        read = StubTransport(status=200, payload=created)  # the case still bears eid's tag
        reader = TheHiveReadAdapter(_creds(), timeout=1.0, transport=read)
        result = reader.read(
            AdapterReadRequest(
                execution_id=other,  # a DIFFERENT execution reads the SAME case
                adapter="thehive",
                external_reference=outcome.detail["case_id"],
            )
        )
        # identity holds but correlation FAILS -> never confirmed for the wrong run.
        assert result.external_state == CASE_UNVERIFIED


# ===========================================================================
# 2. FULL platform chain over the REAL reconcile pipeline (in-memory DB)
# ===========================================================================
class TestPlatformChainClosure:
    def test_write_then_explicit_reconcile_yields_one_confirmed_success(self, db_session):
        eid = uuid.uuid4()
        aid = uuid.uuid4()
        # (a) controlled creation via the REAL executor.
        outcome, _posted_tags, created = _create_case(eid, aid)
        case_id = outcome.detail["case_id"]
        # (b) persist the dispatch chain with the executor's REAL detail — exactly
        #     what the execution service writes onto the terminal execution_log row.
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "thehive"}),
                ("dispatched", {"executor": "thehive"}),
                ("succeeded", dict(outcome.detail)),
            ],
        )
        # (c) explicit Manual Reconcile with the REAL reader injected; the GET echoes
        #     the persisted case (same _id, same tags).
        read = StubTransport(status=200, payload=created)
        reader = TheHiveReadAdapter(_creds(), timeout=1.0, transport=read)
        response = reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([reader]))
        # (d) independent Outcome + audit query.
        assert response.accepted is True
        assert response.outcome_status == "confirmed_success"
        assert response.source == MANUAL_RECONCILE_SOURCE
        assert response.observed_at_kind == "external"
        fact = _only_fact(db_session, eid)
        assert fact.outcome_status == "confirmed_success"
        assert fact.operator == OPERATOR
        # the reader re-fetched BY THE STRING REFERENCE the executor produced — never
        # by the numeric case number.
        assert read.last.full_url.endswith(f"/api/case/{case_id}")
        assert f"/api/case/{CASE_NUMBER}" not in read.last.full_url
        assert read.call_count == 1

    def test_cross_execution_reconcile_is_refused_zero_facts(self, db_session):
        # A chain for execution OTHER pointing at the SAME case the executor created
        # for EID: the reader verifies identity but NOT correlation -> REFUSED, zero
        # fact. Proves no historical / cross-execution mis-attribution (§5 / §6).
        eid = uuid.uuid4()
        aid = uuid.uuid4()
        other = uuid.uuid4()
        outcome, _posted_tags, created = _create_case(eid, aid)
        _seed_chain(
            db_session,
            other,
            rows=[
                ("requested", {"executor": "thehive"}),
                ("dispatched", {"executor": "thehive"}),
                ("succeeded", dict(outcome.detail)),  # same case_id as eid's creation
            ],
        )
        read = StubTransport(status=200, payload=created)  # tags bind eid, NOT other
        reader = TheHiveReadAdapter(_creds(), timeout=1.0, transport=read)
        with pytest.raises(UnrecognizedExternalState):
            reconcile_execution(db_session, other, OPERATOR, ReadAdapterRegistry([reader]))
        assert _outcome_count(db_session) == 0

    def test_repeat_reconcile_after_creation_is_append_only(self, db_session):
        eid = uuid.uuid4()
        aid = uuid.uuid4()
        outcome, _posted_tags, created = _create_case(eid, aid)
        _seed_chain(
            db_session,
            eid,
            rows=[
                ("requested", {"executor": "thehive"}),
                ("dispatched", {"executor": "thehive"}),
                ("succeeded", dict(outcome.detail)),
            ],
        )
        registry = ReadAdapterRegistry(
            [TheHiveReadAdapter(_creds(), timeout=1.0, transport=StubTransport(status=200, payload=created))]
        )
        first = reconcile_execution(db_session, eid, OPERATOR, registry)
        second = reconcile_execution(db_session, eid, OPERATOR, registry)
        assert first.outcome_status == second.outcome_status == "confirmed_success"
        rows = _facts(db_session, eid)
        assert len(rows) == 2  # append-only: two facts, never an overwrite
        assert len({r.id for r in rows}) == 2
