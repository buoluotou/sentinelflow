"""M3 trusted creation-proof tests — Component + read_creation + Service (Phase 3.4.5-M3 §6).

WHAT THIS PROVES. The source-isolated trusted creation-proof channel (Amendment §5.3 +
§6.2) at THREE levels, with NO network and NO real TheHive (LAB BLOCKED on this host):

  1. COMPONENT — the SINGLE pure six-gate verifier ``verify_creation_effect`` against
     hand-built ``ReadCorrelationContext`` / ``VerifiedReadResult`` shapes: the positive
     verdict (ALL six gates pass -> ``VerifiedCreationEffect``) and the FULL negative
     matrix (each gate's every fail-closed reason). This is where the strict-correlation
     logic is proven exhaustively, including the reviewer's probes: the ten-year-old
     re-tagged case (gate 4 ``created_before_dispatch`` + the decisive
     ``dispatch_created_at_mismatch``), a future-dated ``createdAt`` (``created_out_of_window``),
     cross-instance / cross-tenant (gate 5), a wrong reference (gate 1
     ``resource_id_mismatch``), and an unapproved / non-escalate action (gate 6).
  2. read_creation — ``TheHiveReadAdapter.read_creation`` against an INJECTED
     ``StubTransport``: a faithful typed observation of a 200 body, the all-``None``
     observation for a non-object body (a gate-1 refusal, NOT a transport failure), and
     the 401/403/404/timeout/connection/5xx discrimination (each a ``ReadTransportError``
     with a SAFE STATIC category). ``observed_instance`` / ``observed_tenant`` are ALWAYS
     ``None`` (4.1.24-1 ``OutputCase`` carries neither -> gate 5 fails closed).
  3. SERVICE — ``reconcile_verified_execution`` over a REAL seeded dispatch chain:
     the derivation produces the immutable fact matrix (gate 5 bindings UNKNOWN), a
     faithful read of a real dispatched execution STILL fails closed at gate 5
     (``VerifiedCreationRefused``, ZERO fact — Amendment §12), a transport failure is
     ``reconciliation_failed`` (NEVER ``confirmed_failure``), the EMPTY production
     registry fails closed (``UnsupportedAdapterRead``), a reader without ``read_creation``
     is not a trusted reader, and the whitelisted ``_persist_verified_creation_outcome``
     appends exactly ONE ``confirmed_success`` fact with NO raw response / NO secret /
     NO tenant value.

HONESTY (Amendment §12 / constraint #2). The positive ``confirmed_success`` arm is
composition-proven (Component positive + Service persist) but is UNREACHABLE for REAL
history: ``derive_read_correlation_context`` sets ``instance_binding`` / ``tenant_binding``
to ``None`` for every real execution, so gate 5 refuses. NO test here fabricates an
instance / tenant binding to force a real-history success — that is the correct fail-closed
state, not a gap. The Component positive uses an EXPLICITLY hand-built context (a future
§12 forward-binding shape), never a real derived one.

Design invariants honored: ``read`` is the SOLE public verb (``read_creation`` is an
internal additional READ verb, never a write verb); ONE read attempt (no retry / poll /
compensation); a refused proof is ZERO fact (never ``confirmed_failure``, never
``reconciliation_failed``); a failed READ is ``reconciliation_failed`` (never
``confirmed_failure``); credentials never surface in a message, a fact, or an observation.
"""
import io
import json
import os
import urllib.error
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
from app.services.executions.binding import BINDING_DETAIL_KEY, build_dispatch_binding
from app.services.executions.secrets import AdapterCredentials
from app.services.executions.thehive import THEHIVE_ACTIONS, sentinelflow_execution_tag
from app.services.manual_reconcile import (
    AdapterReadRequest,
    AdapterReadResult,
    ReadAdapter,
    ReadAdapterRegistry,
    ReadTransportError,
    UnsupportedAdapterRead,
)
from app.services.outcomes.verified_proof import (
    UnsealedCreationEffect,
    VerifiedCreationRefused,
    _persist_verified_creation_outcome,
    derive_read_correlation_context,
    reconcile_verified_execution,
)
from app.services.read_adapters.thehive import (
    TheHiveReadAdapter,
    _created_at_to_datetime,
)
from app.services.read_adapters.verified import (
    APPROVED_APPROVAL_STATUS,
    APPROVED_CREATION_ACTION,
    GATE_APPROVED_ACTION,
    GATE_CORRELATION,
    GATE_CREATION_TIME,
    GATE_IDENTITY,
    GATE_INSTANCE_TENANT,
    GATE_TIME_ORDER,
    MAX_CREATION_WINDOW,
    MAX_DISPATCH_CLOCK_SKEW,
    PROOF_SCOPE_VERIFIED_CREATION,
    REASON_APPROVAL_NOT_APPROVED,
    REASON_APPROVAL_SNAPSHOT_INCONSISTENT,
    REASON_CREATED_BEFORE_DISPATCH,
    REASON_CREATED_OUT_OF_WINDOW,
    REASON_DISPATCH_CREATED_AT_MISMATCH,
    REASON_DISPATCH_CREATED_AT_UNKNOWN,
    REASON_DISPATCH_STARTED_AT_UNKNOWN,
    REASON_TERMINAL_RECORDED_AT_UNKNOWN,
    REASON_INSTANCE_BINDING_UNKNOWN,
    REASON_INSTANCE_MISMATCH,
    REASON_MISSING_CREATED_AT,
    REASON_MISSING_EXECUTION_CORRELATION_TAG,
    REASON_NO_STRING_RESOURCE_ID,
    REASON_REFERENCE_NOT_FROM_TERMINAL_SUCCESS,
    REASON_REFERENCE_UNKNOWN,
    REASON_RESOURCE_ID_MISMATCH,
    REASON_TENANT_BINDING_UNKNOWN,
    REASON_TENANT_MISMATCH,
    REASON_UNAPPROVED_ACTION,
    CreationRefusal,
    ReadCorrelationContext,
    TrustedCreationReader,
    VerifiedCreationEffect,
    VerifiedReadResult,
    created_at_millis,
    created_at_to_datetime,
    verify_creation_effect,
)

# ---------------------------------------------------------------------------
# constants (fixed clock + obviously-fake Lab identity — NEVER a real secret)
# ---------------------------------------------------------------------------
NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
DISPATCH_MS = int(NOW.timestamp() * 1000)
REFERENCE = "~42"
OPERATOR = "recon-op"
INSTANCE = "thehive.lab.local"
TENANT = "organisation-1"
EID = uuid.UUID("11111111-1111-4111-8111-111111111111")
APPROVAL_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")
TARGET = "case"
LAB_BASE_URL = "https://thehive.lab.local"
LAB_API_KEY = "LAB_THEHIVE_KEY_DO_NOT_USE"
SECRET_BODY = b'{"message":"SUPER_SECRET_BODY","x":"AKIAIOSFODNN7EXAMPLE"}'


# ---------------------------------------------------------------------------
# Component builders — a fully-passing context + observation, overridden per gate
# ---------------------------------------------------------------------------
def _context(**overrides) -> ReadCorrelationContext:
    """A context whose immutable facts SATISFY all six gates (the §12 forward-binding
    shape: instance / tenant bindings PRESENT). Component-only — a REAL derived context
    NEVER has bindings (gate 5 fails closed), proven in the Service section."""
    base = dict(
        execution_id=EID,
        adapter="thehive",
        external_reference=REFERENCE,
        approved_action=APPROVED_CREATION_ACTION,
        approval_status_at_dispatch=APPROVED_APPROVAL_STATUS,
        bound_approval_id=str(APPROVAL_ID),
        bound_action=APPROVED_CREATION_ACTION,
        bound_target=TARGET,
        chain_approval_id=str(APPROVAL_ID),
        chain_target=TARGET,
        dispatch_started_at=NOW,
        terminal_recorded_at=NOW,
        dispatch_created_at=NOW,
        dispatch_created_at_millis=DISPATCH_MS,
        instance_binding=INSTANCE,
        tenant_binding=TENANT,
        reference_from_terminal_success=True,
    )
    base.update(overrides)
    return ReadCorrelationContext(**base)


def _observed(**overrides) -> VerifiedReadResult:
    """An observation that MATCHES ``_context()`` on every gate."""
    base = dict(
        resource_id=REFERENCE,
        correlation_tag_present=True,
        external_created_at=NOW,
        external_created_at_millis=DISPATCH_MS,
        case_number=42,
        observed_instance=INSTANCE,
        observed_tenant=TENANT,
    )
    base.update(overrides)
    return VerifiedReadResult(**base)


# ---------------------------------------------------------------------------
# read_creation / Service stub transport (the isolation seam — NO network, ever)
# ---------------------------------------------------------------------------
class _StubResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")

    def read(self):
        return self._body


class StubTransport:
    """Mimics ``urllib.request.urlopen``: records every ``(request, timeout)``, returns a
    canned response OR raises a canned exception. Mirrors test_read_adapter_thehive.py."""

    def __init__(self, *, status=200, body=None, exc=None):
        self._status = status
        self._body = body if body is not None else {}
        self._exc = exc
        self.calls: list[tuple] = []

    def __call__(self, request, timeout=None):
        self.calls.append((request, timeout))
        if self._exc is not None:
            raise self._exc
        return _StubResponse(self._status, self._body)

    @property
    def call_count(self):
        return len(self.calls)


def _creds(base_url=LAB_BASE_URL, api_key=LAB_API_KEY):
    return AdapterCredentials(adapter="thehive", base_url=base_url, api_key=api_key)


def _reader(transport, *, timeout=30.0):
    return TheHiveReadAdapter(_creds(), timeout=timeout, transport=transport)


def _request(execution_id=EID, reference=REFERENCE, adapter="thehive"):
    return AdapterReadRequest(
        execution_id=execution_id, adapter=adapter, external_reference=reference
    )


def _case_body(execution_id=EID, *, reference=REFERENCE, created_ms=DISPATCH_MS,
               case_number=42, extra_tags=None, include_id=True, include_created=True):
    """A realistic OutputCase v0 body (TheHive 4.1.24-1): ``_id`` == ``id``, ``createdAt``
    (epoch millis), ``tags`` (carrying THIS execution's correlation tag), ``caseId`` (the
    audit-only human NUMBER, never the reference)."""
    tags = [sentinelflow_execution_tag(execution_id), "sentinelflow"]
    if extra_tags:
        tags.extend(extra_tags)
    body = {"_id": reference, "caseId": case_number, "tags": tags,
            "title": "escalated by SentinelFlow", "status": "Open", "severity": 3}
    if include_created:
        body["createdAt"] = created_ms
    if include_id:
        body["id"] = reference
    return body


def _http_error(code, body=SECRET_BODY):
    return urllib.error.HTTPError(
        f"{LAB_BASE_URL}/api/case/{REFERENCE}", code, "err", {}, io.BytesIO(body)
    )


# ---------------------------------------------------------------------------
# Service seeding (mirrors test_read_adapter_thehive.py + adds raw_response.createdAt)
# ---------------------------------------------------------------------------
def _seed_approval(db_session, *, status="approved"):
    group = AlertGroup(
        fingerprint=uuid.uuid4().hex, title="SSH Brute Force on edge-gateway",
        category="authentication", severity="high", first_seen=NOW, last_seen=NOW,
    )
    db_session.add(group)
    db_session.flush()
    record = AIResponseRecommendation(
        alert_group=group, provider="mock", model="mock-deterministic",
        overall_rationale="[mock] guidance",
        recommendations=[{"action": "escalate_to_incident", "target": "case",
                          "rationale": "escalate"}],
        confidence=0.7,
    )
    db_session.add(record)
    db_session.flush()
    approval = AIResponseApproval(
        recommendation_id=record.id, status=status, reviewer="analyst-1", reviewed_at=NOW
    )
    db_session.add(approval)
    db_session.commit()
    return approval


def _binding_detail(execution_id, approval_id, *, action="escalate_to_incident",
                    target="case", approval_status="approved", started_at=None,
                    target_instance=None, target_tenant=None):
    """A faithful post-M4-A TheHive pre-dispatch binding detail — the shape the REAL write
    path persists into the ``dispatched`` row (``build_dispatch_binding(...).to_detail()``).
    ``target_instance`` / ``target_tenant`` default ``None``: TheHive 4.1.24-1 has no
    authoritative dispatch-time identity source, so gate 5 stays fail-closed (Amendment §12)."""
    binding = build_dispatch_binding(
        execution_id=execution_id,
        approval_id=approval_id,
        adapter="thehive",
        action=action,
        target=target,
        approval_status=approval_status,
        dispatch_started_at=started_at or (NOW + timedelta(seconds=1)),
        contributor_facts={
            "endpoint": LAB_BASE_URL,
            "version_evidence_ref": None,
            "version_assertion_kind": "config-declaration",
            "target_instance": target_instance,
            "target_tenant": target_tenant,
        },
    )
    return binding.to_detail()


def _seed_chain(db_session, execution_id, *, rows, action="escalate_to_incident",
                operator="ops-1", approval_status="approved", with_binding=True,
                binding_approval_status=None):
    """One execute chain from ``[(decision, detail), ...]`` in CHRONOLOGICAL order. The
    ``dispatched`` row carries the immutable pre-dispatch binding (M4-A) unless
    ``with_binding=False`` — the OLD-HISTORY shape (no binding) M4-D must reject fail-closed.
    ``binding_approval_status`` overrides the binding's dispatch-time approval snapshot
    (default: the chain's ``approval_status``) to seed an approval-inconsistency probe."""
    approval = _seed_approval(db_session, status=approval_status)
    snapshot_status = (
        binding_approval_status if binding_approval_status is not None else approval_status
    )
    logs = []
    for i, (decision, detail) in enumerate(rows):
        row_detail = dict(detail)
        if with_binding and decision == "dispatched":
            row_detail[BINDING_DETAIL_KEY] = _binding_detail(
                execution_id, approval.id, action=action, target="case",
                approval_status=snapshot_status, started_at=NOW + timedelta(seconds=i),
            )
        logs.append(
            ExecutionLog(
                execution_id=execution_id, approval_id=approval.id, decision=decision,
                direction="execute", action=action, target="case", operator=operator,
                detail=row_detail, created_at=NOW + timedelta(seconds=i),
            )
        )
    db_session.add_all(logs)
    db_session.commit()
    return approval


def _verified_rows(reference=REFERENCE, case_number=42, created_ms=DISPATCH_MS):
    """A thehive dispatch chain AS THE REAL WRITE PATH PERSISTS IT: the terminal
    ``succeeded`` row's ``detail`` carries ``case_id`` (the reference) AND ``raw_response``
    with the immutable ``createdAt`` (``service._terminal_outcome_detail``) — the gate-4
    exact-match source. This is the faithful historical shape, source-verified §11.3."""
    raw_response = {
        "_id": reference, "id": reference, "createdAt": created_ms,
        "caseId": case_number, "tags": [sentinelflow_execution_tag(EID)],
        "status": "Open", "severity": 3,
    }
    return [
        ("requested", {"executor": "thehive"}),
        ("dispatched", {"executor": "thehive"}),
        ("succeeded", {"provider": "thehive", "case_id": reference,
                       "case_number": case_number, "raw_response": raw_response}),
    ]


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
# 1. created_at converters — the proof-layer canonical helpers + drift pin
# ===========================================================================
class TestCreatedAtConverters:
    def test_valid_epoch_millis_to_aware_utc(self):
        dt = created_at_to_datetime(DISPATCH_MS)
        assert dt == NOW
        assert dt.tzinfo is not None

    def test_bool_is_never_a_timestamp(self):
        # isinstance(True, int) is True in Python -> must be excluded explicitly.
        assert created_at_to_datetime(True) is None
        assert created_at_to_datetime(False) is None
        assert created_at_millis(True) is None

    def test_non_number_and_none_are_refused(self):
        for bad in (None, "1700000000000", [], {}, object()):
            assert created_at_to_datetime(bad) is None
        assert created_at_millis(None) is None
        assert created_at_millis("1700000000000") is None

    def test_out_of_range_is_refused_not_raised(self):
        assert created_at_to_datetime(10**30) is None

    def test_millis_rejects_float_and_bool(self):
        assert created_at_millis(1700000000000.5) is None
        assert created_at_millis(DISPATCH_MS) == DISPATCH_MS

    def test_proof_converter_agrees_with_frozen_read_path(self):
        # The proof-layer created_at_to_datetime and the frozen read-path
        # _created_at_to_datetime MUST agree on the whole matrix, so the two read
        # paths can never drift on the creation-time semantics.
        for value in (DISPATCH_MS, 0, True, False, None, "x", 10**30, -1):
            assert created_at_to_datetime(value) == _created_at_to_datetime(value)


# ===========================================================================
# 2. COMPONENT — the single six-gate verifier: positive + full negative matrix
# ===========================================================================
class TestVerifierPositive:
    def test_all_six_gates_pass_yields_verified_creation_effect(self):
        verdict = verify_creation_effect(_context(), _observed())
        assert isinstance(verdict, VerifiedCreationEffect)
        assert verdict.execution_id == EID
        assert verdict.adapter == "thehive"
        assert verdict.external_reference == REFERENCE
        assert verdict.external_created_at == NOW
        assert verdict.case_number == 42
        assert verdict.instance_verified is True
        assert verdict.tenant_verified is True

    def test_verifier_is_pure_no_mutation_of_inputs(self):
        ctx, obs = _context(), _observed()
        verify_creation_effect(ctx, obs)
        # frozen + slots dataclasses: a mutation would raise; re-read the fields.
        assert ctx.instance_binding == INSTANCE
        assert obs.resource_id == REFERENCE

    def test_case_number_is_optional_audit_only(self):
        verdict = verify_creation_effect(_context(), _observed(case_number=None))
        assert isinstance(verdict, VerifiedCreationEffect)
        assert verdict.case_number is None


class TestVerifierGate1Identity:
    @pytest.mark.parametrize("bad", [None, "", 42, True, ["~42"]])
    def test_no_string_resource_id(self, bad):
        verdict = verify_creation_effect(_context(), _observed(resource_id=bad))
        assert isinstance(verdict, CreationRefusal)
        assert (verdict.gate, verdict.reason) == (GATE_IDENTITY, REASON_NO_STRING_RESOURCE_ID)

    @pytest.mark.parametrize("bad", [None, ""])
    def test_reference_unknown(self, bad):
        verdict = verify_creation_effect(_context(external_reference=bad), _observed())
        assert (verdict.gate, verdict.reason) == (GATE_IDENTITY, REASON_REFERENCE_UNKNOWN)

    def test_resource_id_mismatch_cross_instance(self):
        # A DIFFERENT case answered (cross-instance / historical same-number).
        verdict = verify_creation_effect(_context(), _observed(resource_id="~999"))
        assert (verdict.gate, verdict.reason) == (GATE_IDENTITY, REASON_RESOURCE_ID_MISMATCH)


class TestVerifierGate2Correlation:
    def test_missing_execution_correlation_tag(self):
        verdict = verify_creation_effect(_context(), _observed(correlation_tag_present=False))
        assert (verdict.gate, verdict.reason) == (
            GATE_CORRELATION, REASON_MISSING_EXECUTION_CORRELATION_TAG
        )


class TestVerifierGate3CreationTime:
    def test_missing_created_at(self):
        verdict = verify_creation_effect(_context(), _observed(external_created_at=None))
        assert (verdict.gate, verdict.reason) == (GATE_CREATION_TIME, REASON_MISSING_CREATED_AT)

    def test_naive_created_at_is_refused(self):
        naive = NOW.replace(tzinfo=None)
        verdict = verify_creation_effect(_context(), _observed(external_created_at=naive))
        assert (verdict.gate, verdict.reason) == (GATE_CREATION_TIME, REASON_MISSING_CREATED_AT)


class TestVerifierGate4TimeOrder:
    def test_dispatch_started_at_unknown(self):
        # M4-D: no binding -> no REAL dispatch start -> gate 4 fails closed (old history).
        verdict = verify_creation_effect(_context(dispatch_started_at=None), _observed())
        assert (verdict.gate, verdict.reason) == (
            GATE_TIME_ORDER, REASON_DISPATCH_STARTED_AT_UNKNOWN
        )

    def test_terminal_recorded_at_unknown(self):
        verdict = verify_creation_effect(_context(terminal_recorded_at=None), _observed())
        assert (verdict.gate, verdict.reason) == (
            GATE_TIME_ORDER, REASON_TERMINAL_RECORDED_AT_UNKNOWN
        )

    def test_ten_year_old_retagged_case_is_before_dispatch(self):
        # THE reviewer's probe: a case created ten years ago, re-tagged with THIS
        # execution's tag. Gate 4a rejects it on the skew bound ALONE.
        ancient = NOW - timedelta(days=3650)
        verdict = verify_creation_effect(
            _context(), _observed(external_created_at=ancient,
                                  external_created_at_millis=int(ancient.timestamp() * 1000))
        )
        assert (verdict.gate, verdict.reason) == (GATE_TIME_ORDER, REASON_CREATED_BEFORE_DISPATCH)

    def test_future_dated_created_at_is_out_of_window(self):
        future = NOW + MAX_CREATION_WINDOW + timedelta(seconds=1)
        verdict = verify_creation_effect(
            _context(), _observed(external_created_at=future,
                                  external_created_at_millis=int(future.timestamp() * 1000))
        )
        assert (verdict.gate, verdict.reason) == (GATE_TIME_ORDER, REASON_CREATED_OUT_OF_WINDOW)

    def test_dispatch_created_at_unknown_fails_closed(self):
        # The immutable exact-match source is absent -> NEVER re-derived from the live read.
        verdict = verify_creation_effect(_context(dispatch_created_at_millis=None), _observed())
        assert (verdict.gate, verdict.reason) == (
            GATE_TIME_ORDER, REASON_DISPATCH_CREATED_AT_UNKNOWN
        )

    def test_exact_match_mismatch_is_decisive(self):
        # In-window but a DIFFERENT createdAt than the immutable dispatch-time value: the
        # authoritative exact match kills it (this is what makes the ten-year probe moot
        # even without the skew bound).
        other = DISPATCH_MS + 1000
        verdict = verify_creation_effect(
            _context(),
            _observed(external_created_at=created_at_to_datetime(other),
                      external_created_at_millis=other),
        )
        assert (verdict.gate, verdict.reason) == (
            GATE_TIME_ORDER, REASON_DISPATCH_CREATED_AT_MISMATCH
        )

    def test_skew_bound_tolerates_sub_second_precedence(self):
        # A legitimate createdAt precedes dispatch_started_at by well under the skew bound.
        created = NOW - timedelta(seconds=1)
        verdict = verify_creation_effect(
            _context(dispatch_created_at_millis=int(created.timestamp() * 1000)),
            _observed(external_created_at=created,
                      external_created_at_millis=int(created.timestamp() * 1000)),
        )
        assert isinstance(verdict, VerifiedCreationEffect)


class TestVerifierGate5InstanceTenant:
    def test_instance_binding_unknown_fails_closed_for_real_history(self):
        # THE Amendment §12 fail-closed: a REAL derived context has NO instance binding.
        verdict = verify_creation_effect(_context(instance_binding=None), _observed())
        assert (verdict.gate, verdict.reason) == (
            GATE_INSTANCE_TENANT, REASON_INSTANCE_BINDING_UNKNOWN
        )

    def test_instance_mismatch(self):
        verdict = verify_creation_effect(_context(), _observed(observed_instance="other.host"))
        assert (verdict.gate, verdict.reason) == (GATE_INSTANCE_TENANT, REASON_INSTANCE_MISMATCH)

    def test_observed_instance_none_is_a_mismatch(self):
        # The real 4.1.24-1 reader observes None -> a second fail-closed even when a
        # binding existed.
        verdict = verify_creation_effect(_context(), _observed(observed_instance=None))
        assert (verdict.gate, verdict.reason) == (GATE_INSTANCE_TENANT, REASON_INSTANCE_MISMATCH)

    def test_tenant_binding_unknown_fails_closed(self):
        verdict = verify_creation_effect(_context(tenant_binding=None), _observed())
        assert (verdict.gate, verdict.reason) == (
            GATE_INSTANCE_TENANT, REASON_TENANT_BINDING_UNKNOWN
        )

    def test_tenant_mismatch(self):
        verdict = verify_creation_effect(_context(), _observed(observed_tenant="organisation-2"))
        assert (verdict.gate, verdict.reason) == (GATE_INSTANCE_TENANT, REASON_TENANT_MISMATCH)


class TestVerifierGate6ApprovedAction:
    def test_unapproved_action(self):
        verdict = verify_creation_effect(_context(approved_action="close_case"), _observed())
        assert (verdict.gate, verdict.reason) == (GATE_APPROVED_ACTION, REASON_UNAPPROVED_ACTION)

    def test_approval_not_approved(self):
        # M4-D: the DISPATCH-TIME snapshot (not the live status) is "rejected".
        verdict = verify_creation_effect(
            _context(approval_status_at_dispatch="rejected"), _observed()
        )
        assert (verdict.gate, verdict.reason) == (
            GATE_APPROVED_ACTION, REASON_APPROVAL_NOT_APPROVED
        )

    def test_bound_action_snapshot_inconsistent(self):
        # M4-D: the binding's action snapshot != the chain's approved action.
        verdict = verify_creation_effect(_context(bound_action="close_case"), _observed())
        assert (verdict.gate, verdict.reason) == (
            GATE_APPROVED_ACTION, REASON_APPROVAL_SNAPSHOT_INCONSISTENT
        )

    def test_bound_target_snapshot_inconsistent(self):
        verdict = verify_creation_effect(_context(bound_target="other"), _observed())
        assert (verdict.gate, verdict.reason) == (
            GATE_APPROVED_ACTION, REASON_APPROVAL_SNAPSHOT_INCONSISTENT
        )

    def test_bound_approval_id_snapshot_inconsistent(self):
        verdict = verify_creation_effect(
            _context(bound_approval_id=str(uuid.uuid4())), _observed()
        )
        assert (verdict.gate, verdict.reason) == (
            GATE_APPROVED_ACTION, REASON_APPROVAL_SNAPSHOT_INCONSISTENT
        )

    def test_reference_not_from_terminal_success(self):
        verdict = verify_creation_effect(
            _context(reference_from_terminal_success=False), _observed()
        )
        assert (verdict.gate, verdict.reason) == (
            GATE_APPROVED_ACTION, REASON_REFERENCE_NOT_FROM_TERMINAL_SUCCESS
        )

    def test_approved_action_is_pinned_to_the_frozen_write_vocabulary(self):
        # Drift pin: the read/proof layer's APPROVED_CREATION_ACTION must be a member of
        # the WRITE side's frozen THEHIVE_ACTIONS, so the two can never silently diverge.
        assert APPROVED_CREATION_ACTION in THEHIVE_ACTIONS


class TestVerifierGate6AbsentEvidenceFailsClosed:
    """M4-F §4: gate 6 must FAIL CLOSED on ABSENT immutable evidence — a missing
    dispatch-time approval snapshot / execution snapshot is NEVER treated as
    ``approved`` and NEVER back-filled from the live approval status or the current
    config ("若现有不可变历史缺少必要证据，保持拒绝…不得用当前审批状态倒填").
    These isolate gate 6's own None-handling (the sibling wrong-VALUE refusals are
    ``TestVerifierGate6ApprovedAction``; the derivation that PRODUCES None for old
    history is ``TestDeriveReadCorrelationContext``)."""

    def test_absent_approval_snapshot_is_refused_never_treated_as_approved(self):
        # approval_status_at_dispatch=None (no binding captured it) -> refuse; None is
        # NEVER implicitly "approved" and NEVER re-read from the live approval.status.
        verdict = verify_creation_effect(
            _context(approval_status_at_dispatch=None), _observed()
        )
        assert (verdict.gate, verdict.reason) == (
            GATE_APPROVED_ACTION, REASON_APPROVAL_NOT_APPROVED
        )

    def test_absent_bound_approval_id_is_refused(self):
        verdict = verify_creation_effect(_context(bound_approval_id=None), _observed())
        assert (verdict.gate, verdict.reason) == (
            GATE_APPROVED_ACTION, REASON_APPROVAL_SNAPSHOT_INCONSISTENT
        )

    def test_absent_bound_action_is_refused(self):
        verdict = verify_creation_effect(_context(bound_action=None), _observed())
        assert (verdict.gate, verdict.reason) == (
            GATE_APPROVED_ACTION, REASON_APPROVAL_SNAPSHOT_INCONSISTENT
        )

    def test_absent_bound_target_is_refused(self):
        verdict = verify_creation_effect(_context(bound_target=None), _observed())
        assert (verdict.gate, verdict.reason) == (
            GATE_APPROVED_ACTION, REASON_APPROVAL_SNAPSHOT_INCONSISTENT
        )


# ===========================================================================
# 3. read_creation — the internal trusted read verb (StubTransport, NO network)
# ===========================================================================
class TestReadCreationVerb:
    def test_faithful_observation_of_a_verified_case(self):
        body = _case_body(created_ms=DISPATCH_MS)
        reader = _reader(StubTransport(body=body))
        observed = reader.read_creation(_request())
        assert isinstance(observed, VerifiedReadResult)
        assert observed.resource_id == REFERENCE
        assert observed.correlation_tag_present is True
        assert observed.external_created_at == NOW
        assert observed.external_created_at_millis == DISPATCH_MS
        assert observed.case_number == 42

    def test_instance_and_tenant_are_always_none(self):
        # 4.1.24-1 OutputCase carries NEITHER -> gate 5 fails closed for every real read.
        reader = _reader(StubTransport(body=_case_body()))
        observed = reader.read_creation(_request())
        assert observed.observed_instance is None
        assert observed.observed_tenant is None

    def test_mismatched_resource_id_is_observed_not_adjudicated(self):
        # The reader reports WHAT IT SAW (even a mismatch); the VERIFIER adjudicates.
        reader = _reader(StubTransport(body=_case_body(reference="~999")))
        observed = reader.read_creation(_request())
        assert observed.resource_id == "~999"

    def test_absent_correlation_tag_is_observed_false(self):
        body = _case_body(extra_tags=["unrelated"])
        body["tags"] = ["unrelated"]  # strip THIS execution's tag
        reader = _reader(StubTransport(body=body))
        assert reader.read_creation(_request()).correlation_tag_present is False

    def test_missing_created_at_yields_none_observation(self):
        reader = _reader(StubTransport(body=_case_body(include_created=False)))
        observed = reader.read_creation(_request())
        assert observed.external_created_at is None
        assert observed.external_created_at_millis is None

    def test_non_object_body_is_a_refusal_not_a_transport_failure(self):
        # A 200 with a non-JSON body -> all-None observation (gate 1 refuses), NOT a raise.
        reader = _reader(StubTransport(body=b"not-json"))
        observed = reader.read_creation(_request())
        assert observed.resource_id is None
        assert observed.correlation_tag_present is False

    def test_read_creation_is_a_trusted_creation_reader(self):
        assert isinstance(_reader(StubTransport()), TrustedCreationReader)

    @pytest.mark.parametrize("code,category", [
        (401, "authentication_failure"), (403, "authorization_failure"),
        (404, "not_found"), (500, "transport_error"), (503, "adapter_unavailable"),
    ])
    def test_http_errors_raise_read_transport_error_with_safe_category(self, code, category):
        reader = _reader(StubTransport(exc=_http_error(code)))
        with pytest.raises(ReadTransportError) as excinfo:
            reader.read_creation(_request())
        assert excinfo.value.category == category
        # the secret-laden error body NEVER surfaces in the message.
        assert "SUPER_SECRET_BODY" not in str(excinfo.value)
        assert LAB_API_KEY not in str(excinfo.value)

    def test_timeout_raises_read_transport_error(self):
        reader = _reader(StubTransport(exc=TimeoutError("boom")))
        with pytest.raises(ReadTransportError) as excinfo:
            reader.read_creation(_request())
        assert excinfo.value.category == "timeout"

    def test_connection_failure_raises_read_transport_error(self):
        reader = _reader(StubTransport(exc=urllib.error.URLError("dns")))
        with pytest.raises(ReadTransportError) as excinfo:
            reader.read_creation(_request())
        assert excinfo.value.category == "connection_failure"

    def test_missing_reference_raises_without_a_get(self):
        transport = StubTransport(body=_case_body())
        reader = _reader(transport)
        with pytest.raises(ReadTransportError):
            reader.read_creation(_request(reference=""))
        assert transport.call_count == 0  # NO GET with a non-str/empty reference

    def test_one_read_attempt_no_retry(self):
        transport = StubTransport(body=_case_body())
        _reader(transport).read_creation(_request())
        assert transport.call_count == 1


# ===========================================================================
# 4. SERVICE — reconcile_verified_execution over a REAL seeded chain
# ===========================================================================
class TestDeriveReadCorrelationContext:
    def test_derives_the_immutable_fact_matrix(self, db_session):
        # §2 fact-matrix proof (M4-D): the derivation anchors gates 1/2/3/4/6 on immutable
        # history + the pre-dispatch binding, and leaves gate 5 bindings UNKNOWN.
        approval = _seed_chain(db_session, EID, rows=_verified_rows())
        ctx = derive_read_correlation_context(db_session, EID)
        assert ctx.adapter == "thehive"
        assert ctx.external_reference == REFERENCE
        assert ctx.approved_action == APPROVED_CREATION_ACTION
        assert ctx.reference_from_terminal_success is True
        # M4-D gate 4: DISTINCT times — the REAL dispatch START (the dispatched row, i=1)
        # vs the TERMINAL RECORD (the succeeded row, i=2). NEVER conflated.
        assert ctx.dispatch_started_at == NOW + timedelta(seconds=1)
        assert ctx.terminal_recorded_at == NOW + timedelta(seconds=2)
        assert ctx.dispatch_created_at_millis == DISPATCH_MS
        # M4-D gate 6: the DISPATCH-TIME approval snapshot + execution snapshot, and the
        # chain counterparts they are cross-checked against.
        assert ctx.approval_status_at_dispatch == APPROVED_APPROVAL_STATUS
        assert ctx.bound_action == APPROVED_CREATION_ACTION
        assert ctx.bound_target == "case"
        assert ctx.bound_approval_id == str(approval.id)
        assert ctx.chain_approval_id == str(approval.id)
        assert ctx.chain_target == "case"
        # Amendment §12: the instance / tenant binding DOES NOT EXIST -> UNKNOWN.
        assert ctx.instance_binding is None
        assert ctx.tenant_binding is None

    def test_derived_context_never_backfills_from_config(self, db_session):
        # The binding carries a config-declared endpoint (base URL) + version, but the
        # derivation MUST NOT invent an instance / tenant binding from them (constraint #2).
        _seed_chain(db_session, EID, rows=_verified_rows())
        ctx = derive_read_correlation_context(db_session, EID)
        assert ctx.instance_binding is None
        assert ctx.tenant_binding is None

    def test_old_history_without_binding_fails_closed(self, db_session):
        # M4-D: a pre-M4-A chain (NO binding) has NO real dispatch start and NO dispatch-time
        # approval snapshot -> gate 4 fails closed; the derivation NEVER back-fills. The
        # terminal-record time still exists (it is the terminal row's OWN stamp).
        _seed_chain(db_session, EID, rows=_verified_rows(), with_binding=False)
        ctx = derive_read_correlation_context(db_session, EID)
        assert ctx.dispatch_started_at is None
        assert ctx.approval_status_at_dispatch is None
        assert ctx.bound_action is None
        assert ctx.bound_approval_id is None
        assert ctx.instance_binding is None
        assert ctx.terminal_recorded_at == NOW + timedelta(seconds=2)


class TestReconcileVerifiedExecution:
    def test_real_history_fails_closed_at_gate5_zero_facts(self, db_session):
        # THE Amendment §12 proof: a FAITHFUL read of a REAL dispatched execution (same
        # reference, correlation tag, and the SAME immutable createdAt) STILL cannot reach
        # confirmed_success — gate 5 refuses because the instance/tenant binding is UNKNOWN.
        _seed_chain(db_session, EID, rows=_verified_rows())
        transport = StubTransport(body=_case_body(created_ms=DISPATCH_MS))
        reader = _reader(transport)
        with pytest.raises(VerifiedCreationRefused) as excinfo:
            reconcile_verified_execution(
                db_session, EID, OPERATOR, ReadAdapterRegistry([reader])
            )
        assert excinfo.value.gate == GATE_INSTANCE_TENANT
        assert excinfo.value.reason == REASON_INSTANCE_BINDING_UNKNOWN
        assert transport.call_count == 1  # ONE read — no retry / poll
        assert _outcome_count(db_session) == 0  # ZERO fact — fail-closed

    def test_old_history_without_binding_refused_at_gate4_zero_facts(self, db_session):
        # M4-D: a pre-M4-A chain (NO binding) cannot prove the REAL dispatch start -> gate 4
        # refuses (dispatch_started_at_unknown), ZERO fact. Old history is NEVER back-filled,
        # and the faithful read (matching reference / tag / createdAt) STILL cannot pass.
        _seed_chain(db_session, EID, rows=_verified_rows(), with_binding=False)
        reader = _reader(StubTransport(body=_case_body(created_ms=DISPATCH_MS)))
        with pytest.raises(VerifiedCreationRefused) as excinfo:
            reconcile_verified_execution(
                db_session, EID, OPERATOR, ReadAdapterRegistry([reader])
            )
        assert excinfo.value.gate == GATE_TIME_ORDER
        assert excinfo.value.reason == REASON_DISPATCH_STARTED_AT_UNKNOWN
        assert _outcome_count(db_session) == 0

    def test_refused_proof_is_never_confirmed_failure(self, db_session):
        _seed_chain(db_session, EID, rows=_verified_rows())
        reader = _reader(StubTransport(body=_case_body(created_ms=DISPATCH_MS)))
        with pytest.raises(VerifiedCreationRefused):
            reconcile_verified_execution(
                db_session, EID, OPERATOR, ReadAdapterRegistry([reader])
            )
        # a refused proof writes NOTHING — never confirmed_failure, never reconciliation_failed.
        assert _outcome_count(db_session) == 0

    def test_ten_year_old_retagged_case_refused_zero_facts(self, db_session):
        # The reviewer's probe at the SERVICE layer: the live case carries THIS execution's
        # tag but an ancient createdAt != the immutable dispatch-time value -> gate 4 refuses.
        ancient_ms = int((NOW - timedelta(days=3650)).timestamp() * 1000)
        _seed_chain(db_session, EID, rows=_verified_rows(created_ms=DISPATCH_MS))
        body = _case_body(created_ms=ancient_ms)
        reader = _reader(StubTransport(body=body))
        with pytest.raises(VerifiedCreationRefused) as excinfo:
            reconcile_verified_execution(
                db_session, EID, OPERATOR, ReadAdapterRegistry([reader])
            )
        assert excinfo.value.gate == GATE_TIME_ORDER
        assert _outcome_count(db_session) == 0

    def test_cross_reference_read_refused_zero_facts(self, db_session):
        # A DIFFERENT case answers the GET (cross-instance / historical) -> gate 1 refuses.
        _seed_chain(db_session, EID, rows=_verified_rows())
        reader = _reader(StubTransport(body=_case_body(reference="~999")))
        with pytest.raises(VerifiedCreationRefused) as excinfo:
            reconcile_verified_execution(
                db_session, EID, OPERATOR, ReadAdapterRegistry([reader])
            )
        assert excinfo.value.gate == GATE_IDENTITY
        assert _outcome_count(db_session) == 0

    def test_read_transport_failure_is_reconciliation_failed(self, db_session):
        # A failed READ (404) is reconciliation_failed, NEVER confirmed_failure.
        _seed_chain(db_session, EID, rows=_verified_rows())
        reader = _reader(StubTransport(exc=_http_error(404)))
        response = reconcile_verified_execution(
            db_session, EID, OPERATOR, ReadAdapterRegistry([reader])
        )
        assert response.outcome_status == "reconciliation_failed"
        assert response.observed_at_kind == "server-observation"
        fact = _only_fact(db_session, EID)
        assert fact.outcome_status == "reconciliation_failed"
        assert fact.outcome_status != "confirmed_failure"
        assert fact.detail["failure_category"] == "not_found"
        assert fact.detail["reason"] == "read_transport_failure"

    def test_empty_production_registry_fails_closed(self, db_session):
        # The trusted channel is NOT wired: the EMPTY default registry -> UnsupportedAdapterRead.
        _seed_chain(db_session, EID, rows=_verified_rows())
        with pytest.raises(UnsupportedAdapterRead):
            reconcile_verified_execution(db_session, EID, OPERATOR)  # no registry
        assert _outcome_count(db_session) == 0

    def test_reader_without_read_creation_is_not_trusted(self, db_session):
        # A plain read-only ReadAdapter (no read_creation verb) is NOT a trusted creation
        # reader -> UnsupportedAdapterRead (constraint #1: the type name is not the trust).
        class _PlainReader(ReadAdapter):
            @property
            def name(self) -> str:
                return "thehive"

            def read(self, request: AdapterReadRequest) -> AdapterReadResult:
                return AdapterReadResult(
                    external_state="Open", observed_at=None, raw_evidence={}
                )

        _seed_chain(db_session, EID, rows=_verified_rows())
        with pytest.raises(UnsupportedAdapterRead):
            reconcile_verified_execution(
                db_session, EID, OPERATOR, ReadAdapterRegistry([_PlainReader()])
            )
        assert _outcome_count(db_session) == 0

    def test_repeat_reconcile_appends_never_overwrites(self, db_session):
        # Two transport-failure reconciles APPEND two facts (append-only), never overwrite.
        _seed_chain(db_session, EID, rows=_verified_rows())
        for _ in range(2):
            reader = _reader(StubTransport(exc=_http_error(503)))
            reconcile_verified_execution(
                db_session, EID, OPERATOR, ReadAdapterRegistry([reader])
            )
        assert len(_facts(db_session, EID)) == 2


class TestPersistVerifiedCreationOutcome:
    def _effect(self, execution_id=EID, case_number=42):
        # M4-C: a REAL verifier-minted (SEALED) effect — the ONLY shape persist now accepts.
        # Built by running the six-gate verifier over a fully-passing context + observation,
        # NOT a plain hand-constructed VerifiedCreationEffect (which persist now REFUSES).
        verdict = verify_creation_effect(
            _context(execution_id=execution_id), _observed(case_number=case_number)
        )
        assert isinstance(verdict, VerifiedCreationEffect)
        return verdict

    def test_verifier_mints_a_sealed_effect(self):
        # The verifier's positive verdict IS sealed; persist accepts ONLY a sealed effect.
        effect = verify_creation_effect(_context(), _observed())
        assert isinstance(effect, VerifiedCreationEffect)
        assert effect.is_sealed()

    def test_appends_one_confirmed_success_with_whitelisted_detail(self, db_session):
        outcome = _persist_verified_creation_outcome(db_session, self._effect(), OPERATOR)
        assert outcome.outcome_status == "confirmed_success"
        assert outcome.observed_at == NOW
        assert outcome.observed_at_kind == "external"
        fact = _only_fact(db_session, EID)
        assert fact.outcome_status == "confirmed_success"
        assert fact.source == "manual_reconcile"
        assert fact.operator == OPERATOR
        d = fact.detail
        assert d["proof_scope"] == PROOF_SCOPE_VERIFIED_CREATION
        assert d["version_assertion_kind"] == "config-declaration"
        assert d["instance_verified"] is True
        assert d["tenant_verified"] is True
        assert d["external_reference"] == REFERENCE

    def test_whitelist_excludes_raw_response_secret_and_tenant_value(self, db_session):
        _persist_verified_creation_outcome(db_session, self._effect(), OPERATOR)
        d = _only_fact(db_session, EID).detail
        serialized = json.dumps(d)
        assert "raw_response" not in d
        assert "raw_evidence" not in d
        assert "createdAt" not in d
        # NEVER the raw instance / tenant VALUES (§3 — only the verification booleans).
        assert TENANT not in serialized
        assert INSTANCE not in serialized
        assert LAB_API_KEY not in serialized

    def test_case_number_is_optional_in_the_whitelist(self, db_session):
        _persist_verified_creation_outcome(
            db_session, self._effect(case_number=None), OPERATOR
        )
        assert "case_number" not in _only_fact(db_session, EID).detail

    def test_persist_is_append_only_no_side_effects(self, db_session):
        # ONE INSERT per call; two calls append two facts (never UPDATE / UPSERT).
        _persist_verified_creation_outcome(db_session, self._effect(), OPERATOR)
        _persist_verified_creation_outcome(db_session, self._effect(), OPERATOR)
        assert len(_facts(db_session, EID)) == 2

    def test_persist_refuses_a_plain_unsealed_effect_zero_fact(self, db_session):
        # M4-C BOUNDARY: a PLAIN hand-constructed VerifiedCreationEffect (NOT minted by the
        # verifier — its seal is not the private sentinel) is REFUSED with ZERO fact. persist
        # no longer trusts the TYPE NAME alone (Amendment §11.2 constraint #1). The seal is NOT
        # a magic credential — the real boundary is the AST-proven single construction site.
        plain = VerifiedCreationEffect(
            execution_id=EID, adapter="thehive", external_reference=REFERENCE,
            external_created_at=NOW, case_number=42,
            instance_verified=True, tenant_verified=True,
            seal=object(),  # NOT the verifier's private _VERIFIER_SEAL
        )
        assert not plain.is_sealed()
        with pytest.raises(UnsealedCreationEffect):
            _persist_verified_creation_outcome(db_session, plain, OPERATOR)
        assert _outcome_count(db_session) == 0


# ===========================================================================
# 5. REAL LAB trusted read — deselected by default; SKIPS (LAB BLOCKED), never fakes
# ===========================================================================
@pytest.mark.external
class TestRealLabTrustedRead:
    """The REAL ``read_creation`` ``GET /api/case/{_id}`` against a live TheHive 4.1.24-1 Lab.

    Behind ``@pytest.mark.external`` (conftest DESELECTS it unless ``-m external``) AND a
    live-Lab env guard, so a normal ``pytest`` run never touches a real system and this
    SKIPS rather than fabricating a result. LAB BLOCKED on this host (no container runtime /
    virtualization / memory — the M2 Lab feasibility finding). It documents the exact real
    trusted-read intent for the phase that has a running Lab, and is the ONLY place a real
    trusted-channel ``GET`` is issued.

    HONEST §12 STATE (constraint #2 — never fabricate a real success). Even against a REAL
    Lab, ``read_creation`` observes ``observed_instance`` / ``observed_tenant`` as ``None``
    (4.1.24-1 ``OutputCase`` carries neither), and ``derive_read_correlation_context`` leaves
    the bindings UNKNOWN for real history, so gate 5 FAILS CLOSED -> ``reconcile_verified_
    execution`` yields ``VerifiedCreationRefused``, NEVER a real ``confirmed_success``. This
    test therefore asserts the READER half only (a faithful typed observation whose instance
    / tenant bindings are None); the persisted ``confirmed_success`` closure stays LAB BLOCKED
    pending the §12 forward-binding Amendment. A None-binding read is NEVER accepted as success.
    """

    def test_real_read_creation_observes_typed_creation_with_none_bindings(self):
        base_url = os.environ.get("THEHIVE_LAB_BASE_URL", "")
        # The INDEPENDENT read-only key (Amendment §5 — never the create-capable write key).
        api_key = (
            os.environ.get("THEHIVE_LAB_READ_API_KEY", "")
            or os.environ.get("THEHIVE_LAB_API_KEY", "")
        )
        reference = os.environ.get("THEHIVE_LAB_CASE_REF", "")
        execution_id = os.environ.get("THEHIVE_LAB_EXECUTION_ID", "")
        if not (base_url and api_key and reference and execution_id):
            pytest.skip(
                "LAB BLOCKED: no real TheHive Lab configured (THEHIVE_LAB_* env unset) — "
                "the trusted read channel is SOURCE-certified only (b6649bb / 2c2a7a4); see "
                "the M2-R §6 Lab feasibility finding and Amendment §12"
            )
        creds = AdapterCredentials(adapter="thehive", base_url=base_url, api_key=api_key)
        reader = TheHiveReadAdapter(creds)  # REAL urllib opener, no stub
        observed = reader.read_creation(
            AdapterReadRequest(
                execution_id=uuid.UUID(execution_id), adapter="thehive",
                external_reference=reference,
            )
        )
        # The typed observation is faithful; the instance / tenant bindings are ALWAYS None
        # on 4.1.24-1 -> gate 5 fails closed (Amendment §12). A transport failure would have
        # raised ReadTransportError (never a fabricated verdict).
        assert isinstance(observed, VerifiedReadResult)
        assert observed.observed_instance is None
        assert observed.observed_tenant is None
