"""TheHive WRITE -> READ closure at THREE honestly-labelled test levels
(Phase 3.4.5-M2 §6; M2-R §2/§5 re-scope — NONE is a real external E2E).

§6 asked for a full platform chain. The real ``GET`` against a live TheHive is LAB
BLOCKED (no container runtime / virtualization / memory on this host), so this file
proves the closure at three DISTINCT levels, each labelled with exactly what it does
and does NOT establish (reviewer P1-3 / M2-R §5: 区分单元、service 集成、HTTP 集成
和真实外部 E2E — never pass a seeded chain off as a complete HTTP run):

  1. COMPONENT handshake (``TestWriteReadCorrelationHandshake``, no DB): the REAL
     ``TheHiveExecutor`` (write) and the REAL ``TheHiveReadAdapter`` (read) over
     INJECTED stub transports — the correlation-tag + STRING-reference handshake.
  2. SERVICE integration (``TestSeededChainIsolation``, in-memory DB): the dispatch
     chain is SEEDED with the executor's REAL ``detail`` and ``reconcile_execution``
     is called DIRECTLY with a test-injected reader. Under M2-R §2 FAIL-CLOSED the
     thehive vocabulary is EMPTY, so the mapping REFUSES the reader's verified
     ``case_created`` -> ZERO Outcome Fact. NOT an HTTP run, NOT named as one.
  3. HTTP integration (``TestHttpRouteChain``, M2-R §5): the REAL FastAPI routes are
     driven end to end — ``POST /api/v1/executions`` (the REAL ``TheHiveExecutor``
     via the ``get_response_executor`` seam + a stub transport, so the REAL execution
     SERVICE writes the chain) then ``POST /api/v1/executions/{id}/reconcile``. The
     reconcile route correlates the persisted reference but resolves NO reader (the
     SEALED EMPTY production registry — the route exposes NO injection seam) ->
     ``UnsupportedAdapterRead`` 404 -> ZERO Outcome Fact: the production read path is
     UNWIRED by design (M2-R §4), so NO confirmed_success is reachable over HTTP.

The REAL external E2E (a live ``GET /api/case/{_id}``) is ``TestRealLabRead`` in
``test_read_adapter_thehive.py`` — ``@pytest.mark.external``, DESELECTED, LAB BLOCKED.
No mock is ever passed off as a real TheHive; only the transport is stubbed.

WHAT THIS PROVES THAT NO SINGLE-ADAPTER TEST CAN:

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
  * M2-R §2 fail-closed: even THIS execution's own verified creation is REFUSED at
    the empty mapping -> ZERO fact (no path launders ``case_created`` into success);
  * M2-R §5 HTTP-route: driven through the REAL approval -> execution -> reconcile
    routes, the write side persists the case reference + correlation tag via the REAL
    service, and the reconcile route honestly 404s at the UNWIRED production registry
    -> ZERO fact (no seeded-chain substitute, no fabricated HTTP success).

FAITHFULNESS NOTE: levels 1-2 stub ONLY the transport and (level 2) reproduce the
chain persistence with the REAL executor's returned ``detail``, mirroring the
sanctioned isolation pattern in ``test_manual_reconcile_read_failure.py``. Level 3
drives the REAL execution SERVICE over HTTP (NO seeded ``execution_log``); only the
external transport is stubbed and the reader registry stays at its sealed production
default (empty).
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.api.v1.reconcile import RECONCILE_UNSUPPORTED_ADAPTER_DETAIL
from app.api.v1.response_execution import get_response_executor
from app.core.config import settings
from app.models import (
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    ExecutionLog,
    ExecutionOutcome,
)
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

#: The REAL FastAPI route paths driven by level 3 (``TestHttpRouteChain``).
EXECUTE = "/api/v1/executions"
RECONCILE = "/api/v1/executions/{eid}/reconcile"
#: Legacy EXECUTION_TOKEN fallback -> a synthetic EXECUTOR operator (can_execute).
EXEC_TOKEN = "exec-secret-thehive-http-chain"


# ---------------------------------------------------------------------------
# HTTP-route fixtures (M2-R §5 level 3 — the REAL FastAPI routes)
# ---------------------------------------------------------------------------
@pytest.fixture()
def app():
    """The FastAPI app — the ``get_response_executor`` override seam. The conftest
    ``client`` fixture clears ALL dependency_overrides on teardown."""
    from app.main import app as fastapi_app

    return fastapi_app


@pytest.fixture()
def exec_auth(monkeypatch):
    """Authenticate BOTH the write and the reconcile route with the legacy
    EXECUTION_TOKEN fallback (a synthetic EXECUTOR operator, ``can_execute`` True).
    The conftest autouse fixture resets the operator registry around every test."""
    monkeypatch.setattr(settings, "EXECUTION_TOKEN", EXEC_TOKEN)
    return {"Authorization": f"Bearer {EXEC_TOKEN}"}


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


def _seed_approval(db_session):
    """Seed ONLY the approval world (AlertGroup -> recommendation -> approval) with
    an ``escalate_to_incident`` snapshot — NO ``execution_log`` rows. Level 3 drives
    the REAL execution SERVICE over HTTP, which WRITES the chain; seeding the rows
    here would make it a seeded chain, not an HTTP one (reviewer P1-3). The default
    ExecutionPolicy is DISABLED (``EXECUTION_POLICY_ENABLED=False``), so no EventRisk
    row is needed for the dispatch to be allowed."""
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
    db_session.commit()
    return approval


def _drive_http_execution(client, app, db_session, exec_auth):
    """Level-3 setup: seed the approval world, inject the REAL ``TheHiveExecutor``
    (stub transport) via the ``get_response_executor`` seam, and POST ``/executions``
    over HTTP so the REAL service writes the chain. Returns
    ``(execution_id, write_stub, exec_response)``."""
    approval = _seed_approval(db_session)
    execution_id = uuid.uuid4()
    created = _created_case(execution_id, approval.id)
    write = StubTransport(status=201, payload=created)
    app.dependency_overrides[get_response_executor] = lambda: TheHiveExecutor(
        _creds(), timeout=1.0, transport=write
    )
    resp = client.post(
        EXECUTE,
        json={
            "execution_id": str(execution_id),
            "approval_id": str(approval.id),
            "operator": "ops-1",
        },
        headers=exec_auth,
    )
    return execution_id, write, resp


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
# 2. SEEDED-chain isolation over the REAL reconcile pipeline (in-memory DB) —
#    M2-R §5: NOT a complete HTTP E2E; under §2 fail-closed the verified
#    creation is REFUSED at the empty mapping (zero fact).
# ===========================================================================
class TestSeededChainIsolation:
    def test_write_then_seeded_reconcile_is_refused_fail_closed_zero_facts(self, db_session):
        # M2-R §2/§5: the REAL executor creates the case, the chain is SEEDED with the
        # executor's REAL detail, and the REAL reader VERIFIES it (identity +
        # correlation + a valid createdAt) and re-fetches BY THE STRING reference —
        # but the fail-closed EMPTY mapping REFUSES case_created -> ZERO Outcome Fact.
        # A SEEDED-chain isolation proof, NOT a complete HTTP E2E and NOT a
        # confirmed_success closure (deferred to the source-isolation Amendment).
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
        #     the persisted case (same _id, same tags) so the reader VERIFIES creation.
        read = StubTransport(status=200, payload=created)
        reader = TheHiveReadAdapter(_creds(), timeout=1.0, transport=read)
        with pytest.raises(UnrecognizedExternalState):
            reconcile_execution(db_session, eid, OPERATOR, ReadAdapterRegistry([reader]))
        # (d) the reader still re-fetched BY THE STRING REFERENCE the executor produced
        #     (never the numeric case number), exactly once — but fail-closed = ZERO fact.
        assert read.last.full_url.endswith(f"/api/case/{case_id}")
        assert f"/api/case/{CASE_NUMBER}" not in read.last.full_url
        assert read.call_count == 1
        assert _outcome_count(db_session) == 0

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

    def test_repeat_seeded_reconcile_stays_fail_closed_zero_facts(self, db_session):
        # M2-R §2: reconciling a verified creation TWICE still REFUSES both times
        # (fail-closed) -> ZERO facts, never a laundered success and never an
        # overwrite. (Append-only TWO-fact behaviour lives on the read-FAILURE
        # reconciliation_failed path, unchanged by the vocabulary fix.)
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
        for _ in range(2):
            with pytest.raises(UnrecognizedExternalState):
                reconcile_execution(db_session, eid, OPERATOR, registry)
        assert _outcome_count(db_session) == 0


# ===========================================================================
# 3. HTTP-ROUTE platform chain (M2-R §5 level 3, reviewer P1-3): the REAL
#    FastAPI approval -> execution -> reconcile routes, NOT a seeded chain + a
#    direct reconcile_execution call. The write side runs the REAL TheHiveExecutor
#    (get_response_executor seam + a stub transport) so the REAL execution SERVICE
#    persists the chain; the reconcile route resolves NO reader (the SEALED EMPTY
#    production registry — the route exposes NO injection seam) ->
#    UnsupportedAdapterRead 404 -> ZERO fact. HTTP INTEGRATION, NOT a real external
#    E2E (transport stubbed) and NOT a confirmed_success closure (the production
#    read path is UNWIRED by design, M2-R §4).
# ===========================================================================
class TestHttpRouteChain:
    def test_http_execution_then_reconcile_is_unwired_zero_facts(
        self, client, db_session, app, exec_auth
    ):
        execution_id, write, exec_resp = _drive_http_execution(
            client, app, db_session, exec_auth
        )

        # (a) the HTTP execution succeeded through the REAL service + REAL executor:
        #     201 = an execution FACT exists; derived_state carries the verdict.
        assert exec_resp.status_code == 201
        body = exec_resp.json()
        assert body["derived_state"] == "succeeded"
        assert body["chain"] == ["requested", "dispatched", "succeeded"]
        assert body["action"] == ESCALATE
        assert body["target"] == TARGET
        # the REAL executor POSTed to /api/case EXACTLY once (no retry / poll), with
        # the correlation tag riding in the declared InputCase.tags Set[String].
        assert write.call_count == 1
        assert write.last.full_url.endswith("/api/case")
        posted_tags = json.loads(write.last.data.decode("utf-8"))["tags"]
        assert sentinelflow_execution_tag(execution_id) in posted_tags
        # the REAL service persisted the chain: the requested row carries the adapter
        # identity (detail["executor"]) and the TERMINAL row the STRING case_id
        # reference (the reconcile extraction key) — WRITTEN over HTTP, never seeded.
        rows = list(
            db_session.scalars(
                select(ExecutionLog)
                .where(ExecutionLog.execution_id == execution_id)
                .order_by(ExecutionLog.created_at.asc(), ExecutionLog.id.asc())
            )
        )
        assert [r.decision for r in rows] == ["requested", "dispatched", "succeeded"]
        assert rows[0].detail["executor"] == "thehive"
        assert rows[-1].detail["case_id"] == REFERENCE

        # (b) the HTTP reconcile correlates that reference but the PRODUCTION registry
        #     is EMPTY and the route exposes NO reader seam -> UnsupportedAdapterRead
        #     -> 404 (static detail) -> ZERO Outcome Fact. The unwired production read
        #     path can NEVER fabricate a confirmed_success over HTTP (M2-R §4); the
        #     fail-closed mapping (level 2) and the webhook forgery refusal
        #     (test_webhook_persistence.py) close the other two entries.
        recon_resp = client.post(
            RECONCILE.format(eid=execution_id), json={}, headers=exec_auth
        )
        assert recon_resp.status_code == 404
        assert recon_resp.json() == {"detail": RECONCILE_UNSUPPORTED_ADAPTER_DETAIL}
        assert _outcome_count(db_session) == 0  # no fabricated success over HTTP

    def test_http_reconcile_404_is_static_and_read_only(
        self, client, db_session, app, exec_auth
    ):
        # The unwired 404 is STATIC + non-disclosing (the reconcile route's
        # non-discrimination discipline, now proven for a REAL thehive chain driven
        # over HTTP): it echoes no execution_id, no adapter, no reference, no
        # credential — and a reconcile is READ-only, appending ZERO execution_outcome
        # and ZERO new execution_log row (it NEVER dispatches / executes).
        execution_id, _write, _exec_resp = _drive_http_execution(
            client, app, db_session, exec_auth
        )
        log_rows_before = len(list(db_session.scalars(select(ExecutionLog))))
        recon_resp = client.post(
            RECONCILE.format(eid=execution_id), json={}, headers=exec_auth
        )
        assert recon_resp.status_code == 404
        detail = recon_resp.json()["detail"]
        assert detail == RECONCILE_UNSUPPORTED_ADAPTER_DETAIL
        assert str(execution_id) not in detail
        assert "thehive" not in detail
        assert REFERENCE not in detail
        assert EXEC_TOKEN not in detail
        assert _outcome_count(db_session) == 0
        assert len(list(db_session.scalars(select(ExecutionLog)))) == log_rows_before
