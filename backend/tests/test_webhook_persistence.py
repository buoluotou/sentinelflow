"""Phase 3.4.4-E — Outcome Fact Persistence tests (the append edge).

This suite locks the FIRST step allowed to write, and the ONLY thing it may
write: an append-only INSERT into ``execution_outcome`` once all four frozen
inbound gates have passed.

    External System -> HTTP Webhook
        -> Gate 1 Authentication    (3.4.4-A, sealed)
        -> Gate 2 Schema            (3.4.4-B, sealed)
        -> Gate 3 Correlation       (3.4.4-C, sealed)
        -> Gate 4 Semantic Mapping  (3.4.4-D, sealed)
        -> Outcome Fact Append      (THIS FILE, 3.4.4-E)
        -> commit -> HTTP 200 {"accepted": true}

Coverage map (spec §22 A-I, plus §23 ORM identity, §24 transaction, §25 HTTP):
  A. successful persistence  — the TEST-ONLY fake adapter (G1-C / B0 §15.4)
     confirmed_success / pending / unknown each append exactly ONE fact with the
     right execution_id, source=webhook, operator=adapter:fakesuccess, UTC
     observed_at, server-side created_at. The REAL Wazuh vocabulary is now EMPTY
     (fail-closed), so its former success words are REFUSED (422, zero fact).
  B. append-only             — a second callback ADDS a second fact; the first
     is byte-identical; a replay is a NEW row (no dedup / UPDATE / DELETE).
  C. failed gates            — auth / schema / correlation / mapping rejection
     each leave the outcome count UNCHANGED (zero fact), and Shuffle/TheHive
     stay fail-closed (§30) — never a fabricated fact.
  D. security                — the callback token / Authorization / identity are
     absent from detail, response and exception; operator is never client-set.
  E. rollback                — a simulated flush / commit failure rolls back,
     raises OutcomePersistenceError (never accepted=true, never
     reconciliation_failed), and leaves NO partial fact.
  F. execution_log immutable — the dispatch log is byte-identical before/after.
  G. derivation              — derive_outcome_state over the appended series
     picks the latest observed_at, ignores a late older replay, breaks an
     equal-timestamp tie by id DESC.
  H. execution isolation     — no executor / retry / compensation import, no new
     dispatch row, no execution created.
  I. adapter isolation       — no adapter read / outbound IO in persistence.

The AST assertions are docstring-immune (they parse imports / calls, not prose).
G1-C EMPTIED the real Wazuh vocabulary (fail-closed), so NO production adapter is
a success vehicle; the end-to-end success pipeline is proven on a TEST-ONLY fake
adapter (B0 §15.4), NEVER by reopening a real vocabulary. Shuffle/TheHive/Wazuh
success is NEVER forced by widening the D mapping.
"""
import ast
import inspect
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.api.v1 import webhooks as webhook_module
from app.api.v1.webhooks import (
    CALLBACK_AUTH_FAILURE_DETAIL,
    CALLBACK_CORRELATION_FAILURE_DETAIL,
    CALLBACK_PERSISTENCE_FAILURE_DETAIL,
    CALLBACK_UNSUPPORTED_ADAPTER_DETAIL,
    CALLBACK_VALIDATION_FAILURE_DETAIL,
)
from app.core.config import settings
from app.models import (
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    ExecutionLog,
)
from app.models.execution_outcome import (
    OUTCOME_SOURCES,
    OUTCOME_STATUSES,
    ExecutionOutcome,
)
from app.schemas.webhook import WebhookCallbackRequest, to_external_observation
from app.services.outcomes import webhook as webhook_service
from app.services.outcomes.derivation import derive_outcome_state
from app.services.outcomes.reconciliation import (
    ContractValidationFailure,
    ExternalObservation,
    UnrecognizedExternalState,
)
from app.services.outcomes.webhook import (
    OutcomePersistenceError,
    persist_callback_outcome,
)

NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)
WEBHOOK = "/api/v1/webhooks"

# Distinct per-adapter callback secrets (mirrors tests/test_webhook_authentication).
SHUFFLE_TOKEN = "shuffle-callback-secret"
WAZUH_TOKEN = "wazuh-callback-secret"
THEHIVE_TOKEN = "thehive-callback-secret"

#: G1-C / B0 §15.4 — the TEST-ONLY fake adapter is the platform success-pipeline
#: vehicle (the real Wazuh vocabulary is now EMPTY / fail-closed). Its webhook
#: channel reuses the declared WAZUH_CALLBACK_TOKEN (conftest.fake_adapter_channel),
#: so WAZUH_TOKEN still authenticates it; the operator identity becomes
#: ``adapter:fakesuccess``. Mirrors conftest.FAKE_ADAPTER.
FAKE = "fakesuccess"

#: The exact import surface the persistence service is allowed (§22.H / §22.I /
#: §23). Deliberately EXACT: any executor / adapter-client / outbound-transport
#: / FastAPI / router module would break this set. ``app.services.executions
#: .secrets`` is REQUIRED (the §21 redaction gate) and is NOT an executor import.
SERVICE_MODULES = {
    "sqlalchemy.exc",
    "sqlalchemy.orm",
    "app.models.execution_outcome",
    "app.services.executions.secrets",
    "app.services.outcomes.correlation",
    "app.services.outcomes.mapping",
    "app.services.outcomes.reconciliation",
}

#: Fragments that must NEVER appear in the service import surface. Precise
#: enough not to false-positive on ``app.services.executions.secrets`` (the
#: redaction gate) or ``app.models.execution_outcome`` (the ORM fact).
FORBIDDEN_SERVICE_FRAGMENTS = (
    "executor",
    "response_execution",
    "registry",
    "retry",
    "compensation",
    "dispatch",
    "httpx",
    "requests",
    "app.integrations",
    "urllib",
    "fastapi",
    "app.api",
)


# --------------------------------------------------------------------------
# fixtures + helpers (seed pattern mirrors tests/test_correlation.py)
# --------------------------------------------------------------------------
@pytest.fixture()
def all_tokens(monkeypatch):
    """Configure all three callback channels with distinct secrets."""
    monkeypatch.setattr(settings, "SHUFFLE_CALLBACK_TOKEN", SHUFFLE_TOKEN)
    monkeypatch.setattr(settings, "WAZUH_CALLBACK_TOKEN", WAZUH_TOKEN)
    monkeypatch.setattr(settings, "THEHIVE_CALLBACK_TOKEN", THEHIVE_TOKEN)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _raiser(exc: Exception):
    """A zero-arg callable that raises ``exc`` (for monkeypatching a Session
    method to simulate a DB failure)."""
    def _raise(*args, **kwargs):
        raise exc
    return _raise


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


def _seed_chain(db_session, execution_id, *, decisions=("succeeded",), operator="ops-1"):
    """Seed one dispatch chain of ``ExecutionLog`` rows keyed on execution_id.
    Correlation (Gate 3) only needs the chain to EXIST, so a single row is the
    norm here; ``decisions`` may carry a dispatch word to prove §6 (the outcome
    is NEVER derived from it)."""
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
    """Full-table content snapshot of execution_log (§2 / §18 / §22.F)."""
    return sorted(
        (
            r.id, r.execution_id, r.approval_id, r.decision, r.direction,
            r.action, r.target, r.operator, r.created_at,
        )
        for r in _all_log_rows(db_session)
    )


def _all_outcomes(db_session):
    return list(db_session.scalars(select(ExecutionOutcome)))


def _outcome_count(db_session):
    return len(_all_outcomes(db_session))


def _outcome_snapshot(db_session):
    """Row-by-row content snapshot of execution_outcome (§18 historical
    immutability). detail is JSON-canonicalized so the tuple is hashable."""
    return sorted(
        (
            o.id, o.execution_id, o.outcome_status, o.source, o.operator,
            o.observed_at, o.created_at,
            json.dumps(o.detail, sort_keys=True, default=str),
        )
        for o in _all_outcomes(db_session)
    )


def _assert_session_clean(db_session):
    """Nothing left staged to write anywhere in the session (§9 / §10)."""
    assert not list(db_session.new)
    assert not list(db_session.dirty)
    assert not list(db_session.deleted)


def _body(execution_id, *, external_state="success", external_reference="wazuh-ref-1",
          observed_at=NOW, **extra):
    """A Gate-2-valid callback body. ``extra`` smuggles forbidden fields to
    prove ``extra="forbid"`` rejects them (§22.D)."""
    payload = {
        "execution_id": str(execution_id),
        "external_reference": external_reference,
        "external_state": external_state,
        "observed_at": observed_at.isoformat(),
    }
    payload.update(extra)
    return payload


def _observation(execution_id, *, adapter=FAKE, external_state="success",
                 external_reference="wazuh-ref-1", observed_at=NOW, source="webhook"):
    """A frozen 3.4.3-A ExternalObservation for service-level tests. G1-C: the
    default adapter is the TEST-ONLY fake (the real Wazuh vocabulary is empty), so
    service-level success proofs run on the fake; refusal tests pass a real
    adapter explicitly."""
    return ExternalObservation(
        execution_id=execution_id,
        adapter=adapter,
        external_reference=external_reference,
        external_state=external_state,
        observed_at=observed_at,
        source=source,
    )


def _imported_service():
    """AST view of the persistence service's OWN imports + defined symbols +
    Name-calls — docstring-immune (mirrors the 3.4.3/3.4.4 import-surface
    tests)."""
    tree = ast.parse(inspect.getsource(webhook_service))
    modules, from_names, aliases, funcs, classes, calls = set(), set(), {}, set(), set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                modules.add(node.module)
            for alias in node.names:
                from_names.add(alias.name)
                if alias.asname:
                    aliases[alias.name] = alias.asname
        elif isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.FunctionDef):
            funcs.add(node.name)
        elif isinstance(node, ast.ClassDef):
            classes.add(node.name)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.add(node.func.id)
    return modules, from_names, aliases, funcs, classes, calls


# ==========================================================================
# A. Successful persistence (§22.A / §1 / §5 / §6 / §8)
# ==========================================================================
class TestSuccessfulPersistence:
    # G1-C / B0 §15.4: the platform success pipeline runs on the TEST-ONLY fake
    # adapter (the real Wazuh vocabulary is EMPTY / fail-closed). The two Wazuh
    # tests below are REVERSED to prove the security fix (422, zero fact).
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_wazuh_confirmed_success_is_now_refused_422(self, client, db_session, all_tokens):
        # G1-C SECURITY FIX (end-to-end over HTTP): the real Wazuh vocabulary is
        # EMPTY, so a former success word authenticates (Gate 1) + correlates
        # (Gate 3) but is REFUSED at Gate 4 -> 422, ZERO fact. Never a fabricated
        # confirmed_success.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        before = _outcome_count(db_session)
        resp = client.post(
            f"{WEBHOOK}/wazuh", json=_body(eid, external_state="success"),
            headers=_bearer(WAZUH_TOKEN),
        )
        assert resp.status_code == 422
        assert resp.json() == {"detail": CALLBACK_VALIDATION_FAILURE_DETAIL}
        assert _outcome_count(db_session) == before   # zero fact
        _assert_session_clean(db_session)

    @pytest.mark.parametrize(
        "state",
        ["completed", "confirmed", "done", "success", "ok", "running", "unknown"],
    )
    def test_wazuh_vocabulary_is_now_refused_422(self, client, db_session, all_tokens, state):
        # G1-C: EVERY former Wazuh vocabulary word (the success / pending / unknown
        # sides) is now REFUSED over HTTP -> 422, ZERO fact. No Wazuh word produces
        # an Outcome on the mapping business path.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(
            f"{WEBHOOK}/wazuh", json=_body(eid, external_state=state),
            headers=_bearer(WAZUH_TOKEN),
        )
        assert resp.status_code == 422, state
        assert resp.json() == {"detail": CALLBACK_VALIDATION_FAILURE_DETAIL}
        assert _outcome_count(db_session) == 0

    def test_source_and_operator_are_server_side(self, client, db_session, all_tokens):
        # §5: source is the frozen webhook channel; operator is adapter:{auth}.
        # G1-C: proven on the TEST-ONLY fake adapter (operator=adapter:fakesuccess).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        fact = _all_outcomes(db_session)[0]
        assert fact.source == "webhook"
        assert fact.source in OUTCOME_SOURCES
        assert fact.operator == f"adapter:{FAKE}"

    def test_observed_at_is_utc_normalized(self, client, db_session, all_tokens):
        # §5: a +02:00 fact time is stored as the SAME instant in UTC.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        plus_two = datetime(2026, 9, 3, 14, 0, 0, tzinfo=timezone(timedelta(hours=2)))
        resp = client.post(
            f"{WEBHOOK}/{FAKE}", json=_body(eid, observed_at=plus_two),
            headers=_bearer(WAZUH_TOKEN),
        )
        assert resp.status_code == 200
        # SQLite does not persist tzinfo, so compare the naive wall clock: 12:00
        # proves the +02:00 input was normalized to UTC (not stored as 14:00).
        stored = _all_outcomes(db_session)[0].observed_at
        assert stored.replace(tzinfo=None) == NOW.replace(tzinfo=None)

    def test_created_at_and_id_are_server_side(self, client, db_session, all_tokens):
        # §5: created_at / id are DB / server defaults, never client-supplied.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        fact = _all_outcomes(db_session)[0]
        assert fact.created_at is not None
        assert fact.id is not None

    def test_external_state_mapping_form(self, client, db_session, all_tokens):
        # §4/§8: a Mapping external_state carries the word under the fake adapter's
        # agent_status key; observed_state preserves the RAW extracted word.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(
            f"{WEBHOOK}/{FAKE}",
            json=_body(eid, external_state={"agent_status": "success"}),
            headers=_bearer(WAZUH_TOKEN),
        )
        assert resp.status_code == 200
        fact = _all_outcomes(db_session)[0]
        assert fact.outcome_status == "confirmed_success"
        assert fact.detail["observed_state"] == "success"

    def test_external_state_preserved_raw_no_second_normalization(self, client, db_session, all_tokens):
        # §8: persistence is NOT a second normalization layer — the RAW word
        # ("SUCCESS") is echoed as observed_state; D produced the lowered form.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(
            f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="SUCCESS"),
            headers=_bearer(WAZUH_TOKEN),
        )
        assert resp.status_code == 200
        fact = _all_outcomes(db_session)[0]
        assert fact.outcome_status == "confirmed_success"
        assert fact.detail["observed_state"] == "SUCCESS"     # RAW preserved
        assert fact.detail["normalized_state"] == "success"   # the matched form

    def test_outcome_status_not_derived_from_dispatch_decision(self, client, db_session, all_tokens):
        # §6: a dispatch decision of "failed" must NOT pull the outcome toward
        # failure — the word comes ONLY from the external_state via Gate 4.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("failed",))
        resp = client.post(
            f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="success"),
            headers=_bearer(WAZUH_TOKEN),
        )
        assert resp.status_code == 200
        assert _all_outcomes(db_session)[0].outcome_status == "confirmed_success"

    def test_service_returns_committed_orm_fact(self, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        fact = persist_callback_outcome(db_session, _observation(eid))
        assert isinstance(fact, ExecutionOutcome)
        assert type(fact).__module__ == "app.models.execution_outcome"
        assert _outcome_count(db_session) == 1
        _assert_session_clean(db_session)

    def test_service_accepts_a_schema_built_observation(self, db_session, all_tokens):
        # The real Schema -> Contract -> persist path (B's to_external_observation).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        req = WebhookCallbackRequest(
            execution_id=eid, external_reference="ref", external_state="success",
            observed_at=NOW,
        )
        fact = persist_callback_outcome(db_session, to_external_observation(req, adapter=FAKE))
        assert fact.outcome_status == "confirmed_success"
        assert fact.operator == f"adapter:{FAKE}"
        assert fact.source == "webhook"


# ==========================================================================
# B. Append-only (§22.B / §3 / §17 / §18)
# ==========================================================================
class TestAppendOnly:
    #: G1-C / B0 §15.4 — the platform append-only pipeline is proven on the
    #: TEST-ONLY fake adapter (the real Wazuh vocabulary is now empty/refused).
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_second_callback_adds_second_fact(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        r1 = client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="running", observed_at=NOW), headers=_bearer(WAZUH_TOKEN))
        r2 = client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="success", observed_at=NOW + timedelta(seconds=5)), headers=_bearer(WAZUH_TOKEN))
        assert r1.status_code == r2.status_code == 200
        facts = _all_outcomes(db_session)
        assert len(facts) == 2
        assert {f.outcome_status for f in facts} == {"pending", "confirmed_success"}

    def test_first_fact_byte_identical_after_second(self, client, db_session, all_tokens):
        # §18: appending NEVER mutates the rows already there.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="running", observed_at=NOW), headers=_bearer(WAZUH_TOKEN))
        before = set(_outcome_snapshot(db_session))
        assert len(before) == 1
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="success", observed_at=NOW + timedelta(seconds=5)), headers=_bearer(WAZUH_TOKEN))
        after = set(_outcome_snapshot(db_session))
        assert len(after) == 2
        assert before <= after   # the prior row survives byte-identical

    def test_replay_identical_callback_appends_new_fact(self, client, db_session, all_tokens):
        # §17: NO dedup — a replayed identical callback is a NEW fact (rows +2).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        body = _body(eid, external_state="success", observed_at=NOW)
        r1 = client.post(f"{WEBHOOK}/{FAKE}", json=body, headers=_bearer(WAZUH_TOKEN))
        r2 = client.post(f"{WEBHOOK}/{FAKE}", json=body, headers=_bearer(WAZUH_TOKEN))
        assert r1.status_code == r2.status_code == 200
        facts = _all_outcomes(db_session)
        assert len(facts) == 2
        assert len({f.id for f in facts}) == 2   # two distinct rows

    def test_service_session_writes_are_append_only(self):
        # §3: the ONLY mutating Session calls are add/flush/commit/rollback —
        # no delete / merge / bulk-upsert / execute anywhere in the source.
        src = inspect.getsource(webhook_service)
        for present in ("session.add(", "session.flush(", "session.commit(", "session.rollback("):
            assert present in src, present
        for forbidden in ("session.delete(", "session.merge(", "session.bulk_", "session.execute(", ".update(", ".delete("):
            assert forbidden not in src, forbidden


# ==========================================================================
# C. Zero fact on every failed gate (§22.C / §19 / §30 / §12 / §31)
# ==========================================================================
class TestZeroFactOnFailure:
    def test_auth_failure_writes_no_fact(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/wazuh", json=_body(eid), headers=_bearer("wrong-token"))
        assert resp.status_code == 401
        assert resp.json() == {"detail": CALLBACK_AUTH_FAILURE_DETAIL}
        assert _outcome_count(db_session) == 0

    def test_missing_header_writes_no_fact(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/wazuh", json=_body(eid))
        assert resp.status_code == 401
        assert _outcome_count(db_session) == 0

    def test_schema_failure_no_body_writes_no_fact(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/wazuh", headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 422
        assert _outcome_count(db_session) == 0

    def test_schema_failure_missing_field_writes_no_fact(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        body = _body(eid)
        del body["external_state"]
        resp = client.post(f"{WEBHOOK}/wazuh", json=body, headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 422
        assert _outcome_count(db_session) == 0

    def test_schema_failure_extra_field_writes_no_fact(self, client, db_session, all_tokens):
        # extra="forbid": a smuggled field is a 422 at the boundary.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/wazuh", json=_body(eid, outcome_status="confirmed_success"), headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 422
        assert _outcome_count(db_session) == 0

    def test_correlation_failure_writes_no_fact(self, client, db_session, all_tokens):
        # well-formed UUID but NO chain -> 404 (Gate 3).
        resp = client.post(f"{WEBHOOK}/wazuh", json=_body(uuid.uuid4()), headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 404
        assert resp.json() == {"detail": CALLBACK_CORRELATION_FAILURE_DETAIL}
        assert _outcome_count(db_session) == 0

    def test_mapping_failure_writes_no_fact(self, client, db_session, all_tokens):
        # an unrecognized Wazuh state -> 422 (Gate 4), never guessed to unknown.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/wazuh", json=_body(eid, external_state="banana"), headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 422
        assert resp.json() == {"detail": CALLBACK_VALIDATION_FAILURE_DETAIL}
        assert _outcome_count(db_session) == 0

    def test_shuffle_fail_closed_writes_no_fact(self, client, db_session, all_tokens):
        # §30: EVERY Shuffle state is refused — even a plausible "success".
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        for state in ("success", "completed", "resolved", "done", "ok"):
            resp = client.post(f"{WEBHOOK}/shuffle", json=_body(eid, external_state=state), headers=_bearer(SHUFFLE_TOKEN))
            assert resp.status_code == 422, state
            assert resp.json() == {"detail": CALLBACK_VALIDATION_FAILURE_DETAIL}
        assert _outcome_count(db_session) == 0

    def test_thehive_fail_closed_writes_no_fact(self, client, db_session, all_tokens):
        # §30 / M2-R §2: EVERY TheHive word a webhook could plausibly carry is
        # refused — the native-lifecycle words (resolved/closed/success/completed/ok,
        # case created != resolved) AND the M2 §5 synthesized ``case_created``, which
        # M2-R §2 REMOVED from the path-agnostic vocabulary (fail-closed). Zero facts.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        for state in ("resolved", "closed", "success", "completed", "ok", "case_created"):
            resp = client.post(f"{WEBHOOK}/thehive", json=_body(eid, external_state=state), headers=_bearer(THEHIVE_TOKEN))
            assert resp.status_code == 422, state
        assert _outcome_count(db_session) == 0

    def test_thehive_forged_case_created_callback_is_refused_zero_facts(
        self, client, db_session, all_tokens
    ):
        # M2-R §2 SECURITY REGRESSION (reviewer P1-1). BEFORE the fix, ``case_created``
        # sat in the path-agnostic thehive vocabulary, so THIS request — a VALID
        # THEHIVE_CALLBACK_TOKEN (Gate 1 pass), a Gate-2-valid schema, a SEEDED chain
        # so execution correlation passes (Gate 3), and the bare string
        # ``case_created`` — mapped straight to ``confirmed_success`` and appended an
        # Outcome Fact WITHOUT ever passing the trusted reader. That is the G1-A/G1-C
        # defect class: a verified-effect signal degraded into a string ANY inbound
        # entry can submit. AFTER M2-R §2 (empty vocabulary, fail-closed) the SAME
        # forged callback is REFUSED at Gate 4 -> 422 (static detail) -> ZERO fact.
        # No caller-controllable verified=true flag, no second table: the word simply
        # maps to NOTHING on the webhook path (and every other path).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)  # Gate 3 correlation PASSES -> refusal is Gate 4
        resp = client.post(
            f"{WEBHOOK}/thehive",
            json=_body(eid, external_state="case_created"),
            headers=_bearer(THEHIVE_TOKEN),  # a VALID, configured callback token
        )
        assert resp.status_code == 422
        assert resp.json() == {"detail": CALLBACK_VALIDATION_FAILURE_DETAIL}
        assert _outcome_count(db_session) == 0  # ZERO Outcome Fact — forgery refused
        _assert_session_clean(db_session)

    def test_unsupported_adapter_writes_no_fact(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/mock", json=_body(eid), headers=_bearer(SHUFFLE_TOKEN))
        assert resp.status_code == 404
        assert resp.json() == {"detail": CALLBACK_UNSUPPORTED_ADAPTER_DETAIL}
        assert _outcome_count(db_session) == 0

    def test_contract_failure_family_never_writes_a_fact(self, db_session, all_tokens):
        # service level: a Gate-4 rejection propagates untouched, add() unreached.
        # G1-C: uses a REAL adapter (wazuh, empty vocab) explicitly — this refusal
        # proof runs in the production state (no fake fixture on this class).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        with pytest.raises(UnrecognizedExternalState):
            persist_callback_outcome(db_session, _observation(eid, adapter="wazuh", external_state="banana"))
        assert _outcome_count(db_session) == 0
        _assert_session_clean(db_session)


# ==========================================================================
# D. Security (§22.D / §20 / §21 / §25)
# ==========================================================================
class TestSecurity:
    #: G1-C / B0 §15.4 — the success-path security proofs (token/identity never
    #: echoed, operator server-side) run on the TEST-ONLY fake adapter; the
    #: mapping-REJECTION proof below stays on the real (now-refused) Wazuh path.
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_callback_token_absent_from_detail(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        blob = json.dumps(_all_outcomes(db_session)[0].detail, default=str).lower()
        assert WAZUH_TOKEN not in blob
        assert "authorization" not in blob
        assert "bearer" not in blob

    def test_response_echoes_no_credential_identity_or_payload(self, client, db_session, all_tokens):
        # §25 + the identity-not-echoed property relocated from 3.4.4-A.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(
            f"{WEBHOOK}/{FAKE}",
            json=_body(eid, external_state="success", external_reference="secret-ref-xyz"),
            headers=_bearer(WAZUH_TOKEN),
        )
        assert resp.status_code == 200
        text = resp.text
        assert WAZUH_TOKEN not in text
        assert FAKE not in text                    # adapter identity not echoed
        assert "authorization" not in text.lower()
        assert "bearer" not in text.lower()
        assert "secret-ref-xyz" not in text        # no raw payload echoed
        assert "success" not in text               # no external_state echoed
        assert "confirmed_success" not in text     # no ORM / derived state echoed

    def test_token_absent_from_mapping_rejection(self, client, db_session, all_tokens):
        # G1-C: stays on the REAL Wazuh path — every Wazuh word is now refused, so
        # this proves a mapping rejection leaks no token (production state).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/wazuh", json=_body(eid, external_state="banana"), headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 422
        assert WAZUH_TOKEN not in resp.text
        assert resp.json() == {"detail": CALLBACK_VALIDATION_FAILURE_DETAIL}

    def test_operator_is_never_client_controlled(self, client, db_session, all_tokens):
        # §5/§20: a smuggled operator field is refused; the fact's operator is
        # ALWAYS the server-side adapter identity.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, operator="attacker"), headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 422
        assert _outcome_count(db_session) == 0
        resp2 = client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        assert resp2.status_code == 200
        assert _all_outcomes(db_session)[0].operator == f"adapter:{FAKE}"

    def test_persistence_error_message_leaks_no_secret(self, db_session, all_tokens, monkeypatch):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        monkeypatch.setattr(db_session, "flush", _raiser(SQLAlchemyError("boom")))
        with pytest.raises(OutcomePersistenceError) as exc:
            persist_callback_outcome(db_session, _observation(eid))
        msg = str(exc.value)
        assert WAZUH_TOKEN not in msg
        assert f"adapter:{FAKE}" not in msg

    def test_router_detail_constants_are_static_and_credential_free(self):
        # §12/§31: every HTTP detail is a STATIC string leaking nothing.
        for detail in (
            CALLBACK_AUTH_FAILURE_DETAIL, CALLBACK_CORRELATION_FAILURE_DETAIL,
            CALLBACK_VALIDATION_FAILURE_DETAIL, CALLBACK_PERSISTENCE_FAILURE_DETAIL,
            CALLBACK_UNSUPPORTED_ADAPTER_DETAIL,
        ):
            low = detail.lower()
            for forbidden in ("wazuh", "shuffle", "thehive", "token", "bearer", "authorization", "secret", "execution_id"):
                assert forbidden not in low, (detail, forbidden)


# ==========================================================================
# E. Rollback (§22.E / §10 / §24)
# ==========================================================================
class TestRollback:
    #: G1-C / B0 §15.4 — rollback-on-DB-failure is proven on the fake adapter (a
    #: real Wazuh word is refused at Gate 4 before any flush/commit is reached).
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_flush_failure_rolls_back_and_raises(self, db_session, all_tokens, monkeypatch):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        calls = {"rollback": 0}
        orig_rollback = db_session.rollback

        def spy_rollback():
            calls["rollback"] += 1
            return orig_rollback()

        monkeypatch.setattr(db_session, "flush", _raiser(SQLAlchemyError("simulated flush failure")))
        monkeypatch.setattr(db_session, "rollback", spy_rollback)
        with pytest.raises(OutcomePersistenceError):
            persist_callback_outcome(db_session, _observation(eid))
        assert calls["rollback"] == 1
        assert _outcome_count(db_session) == 0
        _assert_session_clean(db_session)

    def test_commit_failure_rolls_back_no_half_fact(self, db_session, all_tokens, monkeypatch):
        # §24: flush DID stage the INSERT, commit failed -> rollback -> no fact.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        calls = {"flush": 0, "rollback": 0}
        orig_flush, orig_rollback = db_session.flush, db_session.rollback

        def spy_flush(*a, **k):
            calls["flush"] += 1
            return orig_flush(*a, **k)

        def spy_rollback():
            calls["rollback"] += 1
            return orig_rollback()

        monkeypatch.setattr(db_session, "flush", spy_flush)
        monkeypatch.setattr(db_session, "commit", _raiser(SQLAlchemyError("simulated commit failure")))
        monkeypatch.setattr(db_session, "rollback", spy_rollback)
        with pytest.raises(OutcomePersistenceError):
            persist_callback_outcome(db_session, _observation(eid))
        assert calls["flush"] == 1
        assert calls["rollback"] == 1
        assert _outcome_count(db_session) == 0   # no half fact survives
        _assert_session_clean(db_session)

    def test_flush_failure_via_http_is_500(self, client, db_session, all_tokens, monkeypatch):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        monkeypatch.setattr(db_session, "flush", _raiser(SQLAlchemyError("simulated flush failure")))
        resp = client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 500
        assert resp.json() == {"detail": CALLBACK_PERSISTENCE_FAILURE_DETAIL}
        assert _outcome_count(db_session) == 0

    def test_commit_failure_via_http_is_500(self, client, db_session, all_tokens, monkeypatch):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        monkeypatch.setattr(db_session, "commit", _raiser(SQLAlchemyError("simulated commit failure")))
        resp = client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 500
        assert _outcome_count(db_session) == 0

    def test_persistence_error_is_not_a_contract_failure(self):
        # §10: a DB failure is NOT a 4xx contract rejection.
        assert not issubclass(OutcomePersistenceError, ContractValidationFailure)

    def test_persistence_failure_never_yields_reconciliation_failed(self, db_session, all_tokens, monkeypatch):
        # §10: a DB failure is NEVER laundered into the 3.4.5 read-failure word.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        monkeypatch.setattr(db_session, "flush", _raiser(SQLAlchemyError("simulated flush failure")))
        with pytest.raises(OutcomePersistenceError):
            persist_callback_outcome(db_session, _observation(eid))
        assert [o.outcome_status for o in _all_outcomes(db_session)] == []


# ==========================================================================
# F. execution_log immutability (§22.F / §2 / §18)
# ==========================================================================
class TestExecutionLogImmutable:
    #: G1-C / B0 §15.4 — success/rollback log-immutability proven on the fake adapter.
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_execution_log_identical_before_and_after_success(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        before = _log_snapshot(db_session)
        resp = client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 200
        assert _log_snapshot(db_session) == before
        assert _outcome_count(db_session) == 1

    def test_execution_log_identical_after_rollback(self, db_session, all_tokens, monkeypatch):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        before = _log_snapshot(db_session)
        monkeypatch.setattr(db_session, "flush", _raiser(SQLAlchemyError("x")))
        with pytest.raises(OutcomePersistenceError):
            persist_callback_outcome(db_session, _observation(eid))
        assert _log_snapshot(db_session) == before

    def test_no_new_dispatch_row_created(self, client, db_session, all_tokens):
        # §22.H: persistence never creates an execution / dispatch row.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        n_before = len(_all_log_rows(db_session))
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        assert len(_all_log_rows(db_session)) == n_before
        assert _outcome_count(db_session) == 1


# ==========================================================================
# G. Derivation over the appended series (§22.G / §16)
# ==========================================================================
class TestDerivation:
    #: G1-C / B0 §15.4 — derivation-over-series proven on the fake adapter.
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_derivation_picks_latest_observed_at(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="running", observed_at=NOW), headers=_bearer(WAZUH_TOKEN))
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="success", observed_at=NOW + timedelta(seconds=10)), headers=_bearer(WAZUH_TOKEN))
        facts = _all_outcomes(db_session)
        assert len(facts) == 2
        assert derive_outcome_state(facts) == "confirmed_success"

    def test_late_older_replay_does_not_change_derived_state(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="success", observed_at=NOW + timedelta(seconds=10)), headers=_bearer(WAZUH_TOKEN))
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="running", observed_at=NOW), headers=_bearer(WAZUH_TOKEN))
        facts = _all_outcomes(db_session)
        assert len(facts) == 2
        assert derive_outcome_state(facts) == "confirmed_success"   # latest observed_at wins

    def test_equal_timestamp_tie_breaks_by_id_desc(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="running", observed_at=NOW), headers=_bearer(WAZUH_TOKEN))
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="success", observed_at=NOW), headers=_bearer(WAZUH_TOKEN))
        facts = _all_outcomes(db_session)
        assert len(facts) == 2
        assert facts[0].observed_at == facts[1].observed_at   # a genuine tie
        winner = max(facts, key=lambda o: (o.observed_at, o.id))
        assert winner.id == max(f.id for f in facts)          # larger id, NOT insert order
        assert derive_outcome_state(facts) == winner.outcome_status

    def test_no_derived_state_is_stored(self, client, db_session, all_tokens):
        # §16: the DB stores observations only — no derived_outcome column/value.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="running", observed_at=NOW), headers=_bearer(WAZUH_TOKEN))
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="success", observed_at=NOW + timedelta(seconds=10)), headers=_bearer(WAZUH_TOKEN))
        facts = _all_outcomes(db_session)
        assert len(facts) == 2                            # BOTH rows kept, not collapsed
        assert {f.outcome_status for f in facts} == {"pending", "confirmed_success"}
        for f in facts:
            assert "derived" not in json.dumps(f.detail, default=str).lower()


# ==========================================================================
# H + I. Execution / adapter isolation (§22.H / §22.I / §29)
# ==========================================================================
class TestIsolation:
    def test_service_imports_no_executor_or_adapter_io(self):
        modules, from_names, *_ = _imported_service()
        joined = " ".join(modules) + " " + " ".join(from_names)
        for forbidden in FORBIDDEN_SERVICE_FRAGMENTS:
            assert forbidden not in joined, forbidden

    def test_service_makes_no_adapter_read_call(self):
        # §29: adapter read (get_status / query_status / outbound HTTP) is 3.4.5.
        # AST-based (docstring-immune): collect every called name and assert no
        # adapter-read / outbound-transport call exists in the persistence path.
        tree = ast.parse(inspect.getsource(webhook_service))
        called = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    called.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    called.add(node.func.attr)
        for forbidden in ("get_status", "query_status", "urlopen", "request"):
            assert forbidden not in called, forbidden


# ==========================================================================
# §23. ORM identity — the fact is the ORM model, never the Pydantic dispatch DTO
# ==========================================================================
class TestOrmIdentity:
    #: G1-C / B0 §15.4 — the ORM-identity fact is produced on the fake adapter.
    pytestmark = pytest.mark.usefixtures("fake_adapter_vocab")

    def test_service_aliases_the_orm_fact(self):
        modules, from_names, aliases, funcs, classes, calls = _imported_service()
        assert "app.models.execution_outcome" in modules
        assert aliases.get("ExecutionOutcome") == "ExecutionOutcomeFact"
        assert "app.services.executions.models" not in modules   # never the DTO module
        assert "ExecutionOutcomeFact" in calls                   # constructed

    def test_service_defines_only_the_sanctioned_symbols(self):
        modules, from_names, aliases, funcs, classes, calls = _imported_service()
        assert modules == SERVICE_MODULES
        assert funcs == {"persist_callback_outcome"}
        assert classes == {"OutcomePersistenceError"}

    def test_persisted_fact_is_the_orm_not_the_dto(self, db_session, all_tokens):
        from app.services.executions.models import ExecutionOutcome as DispatchDTO

        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        fact = persist_callback_outcome(db_session, _observation(eid))
        assert type(fact).__module__ == "app.models.execution_outcome"
        assert type(fact).__name__ == "ExecutionOutcome"
        assert hasattr(fact, "__table__")            # a SQLAlchemy ORM model
        assert not isinstance(fact, DispatchDTO)     # NOT the Pydantic dispatch DTO
        assert fact.outcome_status in OUTCOME_STATUSES


# ==========================================================================
# §24. Transaction order + gate-before-write
# ==========================================================================
class TestTransaction:
    #: G1-C / B0 §15.4 — transaction order + gate-before-write proven on the fake
    #: adapter (test_every_gate_runs_before_add uses a word OUTSIDE the fake vocab
    #: -> UnrecognizedExternalState, add() never reached).
    pytestmark = pytest.mark.usefixtures("fake_adapter_vocab")

    def test_order_is_add_flush_commit(self, db_session, all_tokens, monkeypatch):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        order = []
        orig_add, orig_flush, orig_commit = db_session.add, db_session.flush, db_session.commit

        def spy_add(obj):
            order.append("add")
            return orig_add(obj)

        def spy_flush(*a, **k):
            order.append("flush")
            return orig_flush(*a, **k)

        def spy_commit():
            order.append("commit")
            return orig_commit()

        monkeypatch.setattr(db_session, "add", spy_add)
        monkeypatch.setattr(db_session, "flush", spy_flush)
        monkeypatch.setattr(db_session, "commit", spy_commit)
        persist_callback_outcome(db_session, _observation(eid))
        assert order == ["add", "flush", "commit"]
        assert _outcome_count(db_session) == 1

    def test_every_gate_runs_before_add(self, db_session, all_tokens, monkeypatch):
        # §9: a gate rejection means add() is NEVER reached — nothing staged.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        added = []
        orig_add = db_session.add

        def spy_add(obj):
            added.append(obj)
            return orig_add(obj)

        monkeypatch.setattr(db_session, "add", spy_add)
        with pytest.raises(UnrecognizedExternalState):
            persist_callback_outcome(db_session, _observation(eid, external_state="banana"))
        assert added == []
        assert _outcome_count(db_session) == 0


# ==========================================================================
# §25. HTTP response contract
# ==========================================================================
class TestHttpResponse:
    #: G1-C / B0 §15.4 — the 200 success-response contract is proven on the fake
    #: adapter (a real Wazuh success word is now REFUSED -> 422, see TestZeroFactOnFailure).
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_success_is_exactly_200_accepted_true(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 200            # never 201 / 204
        assert resp.json() == {"accepted": True}
        assert set(resp.json()) == {"accepted"}   # EXACTLY one key

    def test_success_body_carries_nothing_else(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(
            f"{WEBHOOK}/{FAKE}",
            json=_body(eid, external_state="success", external_reference="ref-abc"),
            headers=_bearer(WAZUH_TOKEN),
        )
        for leaked in ("ref-abc", "success", "confirmed_success", WAZUH_TOKEN, "execution_id", "observed_state", FAKE):
            assert leaked not in resp.text, leaked

    def test_endpoint_is_registered_at_the_frozen_path(self):
        # §11: POST /api/v1/webhooks/{adapter}, the path is frozen.
        paths = {(r.path, tuple(sorted(r.methods))) for r in webhook_module.router.routes}
        assert ("/webhooks/{adapter}", ("POST",)) in paths
