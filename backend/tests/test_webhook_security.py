"""F — Security / Replay / Rollback / Execution-Isolation Final Gate.

E (3.4.4-E) wired the append edge and proved persistence WORKS. F is NOT a
re-implementation and NOT a duplicate of E: it is the INDEPENDENT final seal
over the WHOLE webhook inbound surface. Where E asked "does a fact get written
correctly?", F asks the adversarial / structural questions:

    Authentication -> Schema -> Correlation -> Mapping -> Persistence
        -> SECURITY FINAL GATE (this file)

F's job (spec 3.4.4-F sections 3-26):
  - Credential secrecy across EVERY sink: DB, detail, execution_log, response,
    exception, application log (caplog), repr (section 4).
  - Cross-adapter token isolation: one adapter's token never authenticates
    another's route (section 5).
  - Identity smuggling: adapter / operator / source / outcome_status in the body
    are refused; identity is server-side only (sections 6/7/8).
  - Execution isolation by AST over BOTH the router AND the service — no
    executor, no ExecutionLog creation, no execute/compensate/retry, no adapter
    IO, no background machinery (sections 9/23/24).
  - Replay / out-of-order / same-timestamp determinism (sections 10/11/12).
  - Historical immutability, rollback, concurrency-by-interleaving (13/14/15).
  - The zero-fact matrix, HTTP semantics, error/detail leakage (16/17/18/19).
  - Outcome-vocabulary boundary, O5 cross-layer, observed_at boundary (20/21/22).
  - Test independence (no dev-machine token, no external system) (section 25).
  - ONE end-to-end cross-layer security matrix over 20 scenarios (section 26).

Discipline (section 29): F NEVER weakens a security assertion to go green, NEVER
widens the Shuffle/TheHive vocabulary, NEVER lets source=manual_reconcile spoof a
webhook, NEVER lets a dispatch word become an outcome word. Wazuh remains the only
adapter with a code-evidenced vocabulary, so it is the only end-to-end success
vehicle; confirmed_failure is NOT webhook-producible today and is exercised at the
model/derivation layer (the future 3.4.5 manual_reconcile path), never by widening
the D mapping.
"""
import ast
import inspect
import json
import logging
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
    MAX_FUTURE_SKEW,
    ContractValidationFailure,
    ExternalObservation,
    InvalidObservedAt,
    UnrecognizedExternalState,
    validate_observation,
)
from app.services.outcomes.webhook import (
    OutcomePersistenceError,
    persist_callback_outcome,
)

NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)
WEBHOOK = "/api/v1/webhooks"

# G1-C / B0 — the TEST-ONLY fake adapter is the platform success-pipeline
# vehicle (the real Wazuh vocabulary is now EMPTY / fail-closed, so NO production
# adapter can carry a success fact). Its webhook channel reuses the declared
# WAZUH_CALLBACK_TOKEN (conftest.fake_adapter_channel), so WAZUH_TOKEN still
# authenticates it and the operator identity becomes ``adapter:fakesuccess``.
FAKE = "fakesuccess"

# Distinct, fixture-only callback secrets (section 25: NEVER a dev-machine token).
SHUFFLE_TOKEN = "shuffle-callback-secret-F"
WAZUH_TOKEN = "wazuh-callback-secret-F"
THEHIVE_TOKEN = "thehive-callback-secret-F"

# Distinctive secret-looking values used to prove NON-leakage (sections 4/18/19).
SECRET_STATE = "SUP3R-SECRET-EXTERNAL-STATE-do-not-echo"
SECRET_REF = "secret-external-ref-do-not-echo"

# The five-word OUTCOME vocabulary (section 20) and the eight DISPATCH
# words that must NEVER appear as an outcome_status.
OUTCOME_FIVE = {
    "unknown", "pending", "confirmed_success",
    "confirmed_failure", "reconciliation_failed",
}
DISPATCH_WORDS = (
    "requested", "guard_rejected", "dispatched", "succeeded", "failed",
    "compensation_requested", "compensation_succeeded", "compensation_failed",
)

# Fragments that must NEVER appear in EITHER webhook-chain module's import
# surface (sections 9/23/24). Precise enough not to false-positive on the
# sanctioned imports (app.services.outcomes.*, app.services.executions.secrets,
# app.models.execution_outcome, app.core.database/config, sqlalchemy, fastapi).
FORBIDDEN_CHAIN_FRAGMENTS = (
    "executor", "response_execution", "compensat", "retry", "approval",
    "policy", "dispatch", "registry", "app.integrations",
    "httpx", "requests", "urllib", "aiohttp", "socket",
    "threading", "asyncio", "celery", "apscheduler", "schedule",
    "concurrent", "multiprocessing", "subprocess", "queue",
)
# Call names that would betray execution / adapter-IO / background behaviour.
FORBIDDEN_CHAIN_CALLS = (
    "execute", "compensate", "retry", "dispatch", "get_status", "query_status",
    "urlopen", "create_task", "Thread", "Process", "add_job", "sleep",
)


#
# fixtures + helpers (seed pattern mirrors tests/test_correlation.py)
#
@pytest.fixture()
def all_tokens(monkeypatch):
    """Configure all three callback channels with distinct fixture secrets."""
    monkeypatch.setattr(settings, "SHUFFLE_CALLBACK_TOKEN", SHUFFLE_TOKEN)
    monkeypatch.setattr(settings, "WAZUH_CALLBACK_TOKEN", WAZUH_TOKEN)
    monkeypatch.setattr(settings, "THEHIVE_CALLBACK_TOKEN", THEHIVE_TOKEN)


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _raiser(exc):
    def _raise(*args, **kwargs):
        raise exc
    return _raise


def _seed_approval(db_session):
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
    """One dispatch chain of ExecutionLog rows keyed on execution_id. Gate 3
    only needs the chain to EXIST; ``decisions`` may carry a dispatch word to
    prove O5 (section 21) — the outcome is NEVER derived from it."""
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
    return sorted(
        (
            o.id, o.execution_id, o.outcome_status, o.source, o.operator,
            o.observed_at, o.created_at,
            json.dumps(o.detail, sort_keys=True, default=str),
        )
        for o in _all_outcomes(db_session)
    )


def _assert_session_clean(db_session):
    assert not list(db_session.new)
    assert not list(db_session.dirty)
    assert not list(db_session.deleted)


def _body(execution_id, *, external_state="success", external_reference="wazuh-ref-1",
          observed_at=NOW, **extra):
    payload = {
        "execution_id": str(execution_id),
        "external_reference": external_reference,
        "external_state": external_state,
        "observed_at": observed_at.isoformat(),
    }
    payload.update(extra)
    return payload


def _observation(execution_id, *, adapter="wazuh", external_state="success",
                 external_reference="wazuh-ref-1", observed_at=NOW, source="webhook"):
    return ExternalObservation(
        execution_id=execution_id,
        adapter=adapter,
        external_reference=external_reference,
        external_state=external_state,
        observed_at=observed_at,
        source=source,
    )


def _import_surface(module):
    """AST view of a module's imports + call names + async defs. Docstring-immune
    (parses the tree, not prose). Used for the section 9/23/24 structural seals
    over BOTH the router and the service."""
    tree = ast.parse(inspect.getsource(module))
    modules, from_names, calls, async_defs = set(), set(), set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                modules.add(node.module)
            for a in node.names:
                from_names.add(a.name)
        elif isinstance(node, ast.Import):
            for a in node.names:
                modules.add(a.name)
        elif isinstance(node, ast.AsyncFunctionDef):
            async_defs.add(node.name)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
    return modules, from_names, calls, async_defs


def _chain_import_blob():
    """The combined import surface text of BOTH webhook-chain modules."""
    parts = []
    for mod in (webhook_module, webhook_service):
        modules, from_names, *_ = _import_surface(mod)
        parts.extend(modules)
        parts.extend(from_names)
    return " ".join(parts)


def _chain_calls():
    calls = set()
    for mod in (webhook_module, webhook_service):
        _, _, c, _ = _import_surface(mod)
        calls |= c
    return calls


# ==========================================================================
# section 4. Credential secrecy across EVERY sink
# ==========================================================================
class TestCredentialSecrecyFullChain:
    # G1-C / B0 — the "valid callback" leg of each secrecy proof runs on the
    # TEST-ONLY fake adapter (the real Wazuh vocabulary is now refused); the
    # invalid/rejected legs stay on the real Wazuh route (production refusal).
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_token_never_reaches_application_log(self, client, db_session, all_tokens, caplog):
        # The chain imports no logger at all; prove it empirically across a full
        # valid + invalid + rejected cycle.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        with caplog.at_level(logging.DEBUG):
            client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
            client.post(f"{WEBHOOK}/wazuh", json=_body(eid), headers=_bearer("wrong-token"))
            client.post(f"{WEBHOOK}/wazuh", json=_body(eid, external_state=SECRET_STATE),
                        headers=_bearer(WAZUH_TOKEN))
        blob = caplog.text
        assert WAZUH_TOKEN not in blob
        assert "Bearer" not in blob
        assert SECRET_STATE not in blob

    def test_token_absent_from_db_detail_and_execution_log(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        client.post(f"{WEBHOOK}/{FAKE}",
                    json=_body(eid, external_reference=SECRET_REF),
                    headers=_bearer(WAZUH_TOKEN))
        # every persisted outcome detail + every execution_log row, JSON-dumped
        outcome_blob = json.dumps(
            [o.detail for o in _all_outcomes(db_session)], default=str
        ).lower()
        log_blob = json.dumps(
            [(r.detail, r.operator, r.decision) for r in _all_log_rows(db_session)],
            default=str,
        ).lower()
        for blob in (outcome_blob, log_blob):
            assert WAZUH_TOKEN.lower() not in blob
            assert "authorization" not in blob
            assert "bearer" not in blob

    def test_token_absent_from_response_and_exception_and_repr(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/{FAKE}",
                           json=_body(eid, external_reference=SECRET_REF),
                           headers=_bearer(WAZUH_TOKEN))
        assert WAZUH_TOKEN not in resp.text
        fact = _all_outcomes(db_session)[0]
        # section 4: repr must not carry the credential OR the raw detail/ref.
        assert WAZUH_TOKEN not in repr(fact)
        assert SECRET_REF not in repr(fact)
        obs = to_external_observation(
            WebhookCallbackRequest(
                execution_id=eid, external_reference=SECRET_REF,
                external_state="success", observed_at=NOW,
            ),
            adapter="wazuh",
        )
        assert WAZUH_TOKEN not in repr(obs)
        assert "authorization" not in repr(obs).lower()

    def test_body_structurally_cannot_carry_a_credential(self):
        # section 19 defense-in-depth: the schema has NO token/authorization
        # field and extra="forbid", so a credential can never even ENTER the
        # observation -> it can never reach detail regardless of redact_detail.
        fields = set(WebhookCallbackRequest.model_fields)
        assert fields == {"execution_id", "external_reference", "external_state", "observed_at"}
        for forbidden in ("token", "authorization", "bearer", "operator", "source", "adapter"):
            assert forbidden not in fields
        assert WebhookCallbackRequest.model_config.get("extra") == "forbid"


# ==========================================================================
# section 5. Cross-adapter token isolation
# ==========================================================================
class TestCrossAdapterTokenIsolation:
    @pytest.mark.parametrize(
        "route,token",
        [
            ("wazuh", SHUFFLE_TOKEN),
            ("shuffle", WAZUH_TOKEN),
            ("shuffle", THEHIVE_TOKEN),
            ("thehive", WAZUH_TOKEN),
            ("wazuh", THEHIVE_TOKEN),
            ("thehive", SHUFFLE_TOKEN),
        ],
    )
    def test_foreign_token_is_401_and_writes_no_fact(self, client, db_session, all_tokens, route, token):
        # A token minted for adapter X NEVER authenticates adapter Y's route.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/{route}", json=_body(eid), headers=_bearer(token))
        assert resp.status_code == 401
        assert resp.json() == {"detail": CALLBACK_AUTH_FAILURE_DETAIL}
        assert _outcome_count(db_session) == 0


# ==========================================================================
# sections 6/7/8. Identity smuggling (adapter / operator / source) is refused
# ==========================================================================
class TestIdentitySmugglingRefused:
    # G1-C / B0 — the "valid fact" identity proofs run on the fake adapter;
    # the smuggling-refusal proofs stay on the real Wazuh route (schema 422).
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    @pytest.mark.parametrize(
        "smuggled",
        [
            {"adapter": "shuffle"},
            {"operator": "admin"},
            {"source": "manual_reconcile"},
            {"outcome_status": "confirmed_success"},
            {"source": "webhook", "operator": "admin", "adapter": "thehive"},
        ],
    )
    def test_smuggled_identity_field_is_422_zero_fact(self, client, db_session, all_tokens, smuggled):
        # extra="forbid": ANY identity/provenance field in the body is refused at
        # the boundary; the fact's identity stays server-side.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/wazuh", json=_body(eid, **smuggled),
                           headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 422
        assert _outcome_count(db_session) == 0

    def test_valid_fact_identity_is_server_side_only(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 200
        fact = _all_outcomes(db_session)[0]
        assert fact.operator == f"adapter:{FAKE}"    # never a client string
        assert fact.source == "webhook"              # never manual_reconcile
        assert fact.source in OUTCOME_SOURCES
        assert fact.operator != "admin"

    def test_spoofed_source_cannot_masquerade_as_manual_reconcile(self, client, db_session, all_tokens):
        # section 8 / 29: a webhook can NEVER write source=manual_reconcile.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        client.post(f"{WEBHOOK}/wazuh", json=_body(eid, source="manual_reconcile"),
                    headers=_bearer(WAZUH_TOKEN))
        assert _outcome_count(db_session) == 0       # refused, not written
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        sources = {o.source for o in _all_outcomes(db_session)}
        assert sources == {"webhook"}


# ==========================================================================
# section 9. Execution isolation — AST over BOTH chain modules
# ==========================================================================
class TestExecutionIsolationStructural:
    def test_neither_module_imports_execution_or_adapter_machinery(self):
        blob = _chain_import_blob()
        for forbidden in FORBIDDEN_CHAIN_FRAGMENTS:
            assert forbidden not in blob, forbidden

    def test_neither_module_creates_an_execution_log(self):
        # ExecutionLog is READ by Gate 3 (correlation), never imported/created
        # by the router or the persistence service.
        for mod in (webhook_module, webhook_service):
            _, from_names, calls, _ = _import_surface(mod)
            assert "ExecutionLog" not in from_names, mod.__name__
            assert "ExecutionLog" not in calls, mod.__name__

    def test_neither_module_invokes_execute_compensate_retry(self):
        calls = _chain_calls()
        for forbidden in ("execute", "compensate", "retry", "dispatch"):
            assert forbidden not in calls, forbidden

    def test_service_import_surface_excludes_the_router_and_fastapi(self):
        modules, *_ = _import_surface(webhook_service)
        # F re-asserts the independent gate: the service never imports FastAPI
        # or the router, and DOES import the ORM fact module.
        assert "fastapi" not in modules
        assert "app.api.v1.webhooks" not in modules
        assert "app.models.execution_outcome" in modules


# ==========================================================================
# section 10. Replay — three facts, all preserved, final = latest observed_at
# ==========================================================================
class TestReplay:
    # G1-C / B0 — replay/append-only proven on the fake adapter.
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_t1_t2_t1replay_leaves_three_facts_and_derives_latest(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        t1, t2 = NOW, NOW + timedelta(seconds=10)
        # T1 pending
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="running", observed_at=t1),
                    headers=_bearer(WAZUH_TOKEN))
        # T2 confirmed_success
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="success", observed_at=t2),
                    headers=_bearer(WAZUH_TOKEN))
        # T1 replay (pending again)
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="running", observed_at=t1),
                    headers=_bearer(WAZUH_TOKEN))
        facts = _all_outcomes(db_session)
        assert len(facts) == 3                       # NO dedup, NO overwrite
        assert len({f.id for f in facts}) == 3       # three distinct rows
        assert derive_outcome_state(facts) == "confirmed_success"   # T2 is latest

    def test_replay_never_updates_or_deletes_a_prior_fact(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        body = _body(eid, external_state="success", observed_at=NOW)
        client.post(f"{WEBHOOK}/{FAKE}", json=body, headers=_bearer(WAZUH_TOKEN))
        first = set(_outcome_snapshot(db_session))
        client.post(f"{WEBHOOK}/{FAKE}", json=body, headers=_bearer(WAZUH_TOKEN))
        second = set(_outcome_snapshot(db_session))
        assert len(second) == 2
        assert first <= second                       # the prior row is byte-identical


# ==========================================================================
# section 11. Replay ordering — arrival order never decides the derived state
# ==========================================================================
class TestReplayOrdering:
    # G1-C / B0 — arrival-order independence proven on the fake adapter.
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    @pytest.mark.parametrize("reverse", [False, True])
    def test_later_observed_at_wins_regardless_of_arrival(self, client, db_session, all_tokens, reverse):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        early = _body(eid, external_state="running", observed_at=NOW)             # pending @ T1
        late = _body(eid, external_state="success", observed_at=NOW + timedelta(seconds=10))  # cs @ T2
        order = [late, early] if reverse else [early, late]
        for body in order:
            assert client.post(f"{WEBHOOK}/{FAKE}", json=body, headers=_bearer(WAZUH_TOKEN)).status_code == 200
        facts = _all_outcomes(db_session)
        assert len(facts) == 2
        assert derive_outcome_state(facts) == "confirmed_success"   # T2 wins both ways

    def test_confirmed_failure_vs_success_ordering_at_the_model_layer(self, db_session):
        # A webhook cannot produce confirmed_failure today (no adapter evidences
        # a failure vocabulary), so the O5 ordering invariant is proven at the
        # fact/derivation layer with directly-appended rows (the future 3.4.5
        # manual_reconcile shape) — NEVER by widening the D mapping.
        eid = uuid.uuid4()
        t1, t2 = NOW, NOW + timedelta(seconds=10)
        # insert the LATER (confirmed_success @ T2) FIRST, then the earlier
        # confirmed_failure @ T1 as a late replay.
        db_session.add(ExecutionOutcome(
            execution_id=eid, outcome_status="confirmed_success", source="manual_reconcile",
            operator="adapter:wazuh", observed_at=t2, detail={},
        ))
        db_session.add(ExecutionOutcome(
            execution_id=eid, outcome_status="confirmed_failure", source="manual_reconcile",
            operator="ops-1", observed_at=t1, detail={},
        ))
        db_session.commit()
        facts = _all_outcomes(db_session)
        assert len(facts) == 2
        assert derive_outcome_state(facts) == "confirmed_success"   # later observed_at wins


# ==========================================================================
# section 12. Same timestamp — higher id wins, never DB natural order
# ==========================================================================
class TestSameTimestamp:
    # G1-C / B0 — same-timestamp tie-break proven on the TEST-ONLY fake
    # adapter (the real Wazuh vocabulary is empty/refused, so no success fact).
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_equal_observed_at_tie_breaks_by_id_desc_not_list_order(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="running", observed_at=NOW),
                    headers=_bearer(WAZUH_TOKEN))
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="success", observed_at=NOW),
                    headers=_bearer(WAZUH_TOKEN))
        facts = _all_outcomes(db_session)
        assert facts[0].observed_at == facts[1].observed_at          # a genuine tie
        # feed derivation in REVERSED list order: the result must not change.
        assert derive_outcome_state(facts) == derive_outcome_state(list(reversed(facts)))
        winner = max(facts, key=lambda o: (o.observed_at, o.id))
        assert winner.id == max(f.id for f in facts)                 # larger id, not insert order
        assert derive_outcome_state(facts) == winner.outcome_status


# ==========================================================================
# section 13. Historical immutability across the full callback flow
# ==========================================================================
class TestHistoricalImmutability:
    # G1-C / B0 — historical immutability across a NEW callback is proven on
    # the TEST-ONLY fake adapter (a real Wazuh word is refused, never INSERTs).
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_prior_facts_and_execution_log_immutable_across_a_new_callback(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="running", observed_at=NOW),
                    headers=_bearer(WAZUH_TOKEN))
        log_before = _log_snapshot(db_session)
        facts_before = set(_outcome_snapshot(db_session))
        # a NEW callback (different state, later time) only INSERTs
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="success",
                                                   observed_at=NOW + timedelta(seconds=5)),
                    headers=_bearer(WAZUH_TOKEN))
        assert _log_snapshot(db_session) == log_before               # dispatch log untouched
        assert facts_before <= set(_outcome_snapshot(db_session))    # prior fact byte-identical
        assert _outcome_count(db_session) == 2


# ==========================================================================
# section 14. Rollback — flush/commit failure, never accepted=true
# ==========================================================================
class TestRollbackFinalGate:
    # G1-C / B0 — rollback-on-DB-failure must reach flush/commit, which a
    # real Wazuh word no longer does (refused at Gate 4); proven on the fake adapter.
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_flush_failure_http_500_zero_fact_not_accepted(self, client, db_session, all_tokens, monkeypatch):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        monkeypatch.setattr(db_session, "flush", _raiser(SQLAlchemyError("simulated flush failure")))
        resp = client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 500
        assert resp.json() == {"detail": CALLBACK_PERSISTENCE_FAILURE_DETAIL}
        assert resp.json().get("accepted") is not True               # NEVER accepted=true
        assert _outcome_count(db_session) == 0
        _assert_session_clean(db_session)

    def test_commit_failure_rolls_back_no_half_fact(self, db_session, all_tokens, monkeypatch):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        calls = {"rollback": 0}
        orig_rb = db_session.rollback

        def spy_rb():
            calls["rollback"] += 1
            return orig_rb()

        monkeypatch.setattr(db_session, "commit", _raiser(SQLAlchemyError("simulated commit failure")))
        monkeypatch.setattr(db_session, "rollback", spy_rb)
        with pytest.raises(OutcomePersistenceError):
            persist_callback_outcome(db_session, _observation(eid, adapter=FAKE))
        assert calls["rollback"] == 1
        assert _outcome_count(db_session) == 0                       # no half fact
        assert [o.outcome_status for o in _all_outcomes(db_session)] == []


# ==========================================================================
# section 15. Concurrency — interleaved legal callbacks are order-independent
# ==========================================================================
class TestConcurrency:
    # G1-C / B0 — interleaved LEGAL callbacks are proven on the TEST-ONLY
    # fake adapter (the real Wazuh vocabulary is empty/refused).
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    @pytest.mark.parametrize("reverse", [False, True])
    def test_two_concurrent_legal_callbacks_both_persist_deterministically(self, client, db_session, all_tokens, reverse):
        # The append-only design has NO unique index and NEVER UPDATEs, so two
        # concurrent legal callbacks reduce to order-independence: both facts
        # survive, nothing is overwritten, and derivation is deterministic in
        # EITHER arrival order. (A single-connection in-memory fixture is not
        # thread-safe, so concurrency is simulated by interleaving — section 15
        # "at least simulate", "no new complex locking".)
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        a = _body(eid, external_state="running", observed_at=NOW)                       # pending
        b = _body(eid, external_state="success", observed_at=NOW + timedelta(seconds=5))  # cs
        for body in ([b, a] if reverse else [a, b]):
            r = client.post(f"{WEBHOOK}/{FAKE}", json=body, headers=_bearer(WAZUH_TOKEN))
            assert r.status_code == 200
        facts = _all_outcomes(db_session)
        assert len(facts) == 2                        # both saved
        assert len({f.id for f in facts}) == 2        # no overwrite
        assert {f.outcome_status for f in facts} == {"pending", "confirmed_success"}
        assert derive_outcome_state(facts) == "confirmed_success"   # deterministic
        _assert_session_clean(db_session)             # no session corruption / half fact

    def test_no_locking_primitive_was_added(self):
        # section 15: concurrency safety comes from append-only, NOT from locks.
        blob = _chain_import_blob()
        for forbidden in ("with_for_update", "FOR UPDATE", "Lock", "Semaphore"):
            assert forbidden not in blob, forbidden
        for mod in (webhook_module, webhook_service):
            src = inspect.getsource(mod)
            assert "with_for_update" not in src, mod.__name__


# ==========================================================================
# section 16. The explicit zero-fact matrix
# ==========================================================================
class TestZeroFactMatrix:
    # G1-C / B0 — the auth/schema/correlation/mapping rows stay on the REAL
    # Wazuh route (each refuses BEFORE or AT mapping, so they are genuine production
    # refusal proofs). The rollback/valid/duplicate rows need a fact to reach
    # flush/commit, which a refused Wazuh word no longer does, so they run on the
    # TEST-ONLY fake adapter. The channel fixture is additive (wazuh stays refused).
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def _run(self, client, db_session, monkeypatch, kind):
        eid = uuid.uuid4()
        if kind != "correlation":
            _seed_chain(db_session, eid)
        before = _outcome_count(db_session)
        if kind == "auth":
            r = client.post(f"{WEBHOOK}/wazuh", json=_body(eid), headers=_bearer("wrong"))
        elif kind == "schema":
            r = client.post(f"{WEBHOOK}/wazuh", json=_body(eid, operator="admin"), headers=_bearer(WAZUH_TOKEN))
        elif kind == "correlation":
            r = client.post(f"{WEBHOOK}/wazuh", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        elif kind == "mapping":
            r = client.post(f"{WEBHOOK}/wazuh", json=_body(eid, external_state="banana"), headers=_bearer(WAZUH_TOKEN))
        elif kind == "rollback":
            monkeypatch.setattr(db_session, "flush", _raiser(SQLAlchemyError("x")))
            r = client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        elif kind == "valid":
            r = client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        else:  # duplicate — delta of the SECOND identical callback
            client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
            before = _outcome_count(db_session)
            r = client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN))
        return r, _outcome_count(db_session) - before

    @pytest.mark.parametrize("kind,status,delta", [
        ("auth", 401, 0), ("schema", 422, 0), ("correlation", 404, 0),
        ("mapping", 422, 0), ("rollback", 500, 0), ("valid", 200, 1),
        ("duplicate", 200, 1),
    ])
    def test_matrix(self, client, db_session, all_tokens, monkeypatch, kind, status, delta):
        r, d = self._run(client, db_session, monkeypatch, kind)
        assert r.status_code == status, kind
        assert d == delta, kind


# ==========================================================================
# section 17. HTTP security semantics
# ==========================================================================
class TestHttpSecurity:
    # G1-C / B0 — the 200 semantics + the 500 persistence path need a
    # fact to persist, so they run on the TEST-ONLY fake adapter; the 401/404/422
    # refusals stay on the REAL Wazuh route (genuine production refusal proofs).
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_all_status_codes_carry_the_frozen_semantics(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        assert client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN)).status_code == 200
        assert client.post(f"{WEBHOOK}/wazuh", json=_body(eid), headers=_bearer("x")).status_code == 401
        assert client.post(f"{WEBHOOK}/mock", json=_body(eid), headers=_bearer(SHUFFLE_TOKEN)).status_code == 404
        assert client.post(f"{WEBHOOK}/wazuh", json=_body(uuid.uuid4()), headers=_bearer(WAZUH_TOKEN)).status_code == 404
        assert client.post(f"{WEBHOOK}/wazuh", json=_body(eid, operator="admin"), headers=_bearer(WAZUH_TOKEN)).status_code == 422
        assert client.post(f"{WEBHOOK}/wazuh", json=_body(eid, external_state="banana"), headers=_bearer(WAZUH_TOKEN)).status_code == 422

    def test_no_error_response_ever_returns_accepted_true(self, client, db_session, all_tokens, monkeypatch):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        errors = [
            client.post(f"{WEBHOOK}/wazuh", json=_body(eid), headers=_bearer("bad")),
            client.post(f"{WEBHOOK}/mock", json=_body(eid), headers=_bearer(SHUFFLE_TOKEN)),
            client.post(f"{WEBHOOK}/wazuh", json=_body(uuid.uuid4()), headers=_bearer(WAZUH_TOKEN)),
            client.post(f"{WEBHOOK}/wazuh", json=_body(eid, operator="admin"), headers=_bearer(WAZUH_TOKEN)),
        ]
        # the 500 persistence path too (G1-C: fake adapter, so the request is
        # mapping-valid and actually reaches the monkeypatched flush -> 500).
        monkeypatch.setattr(db_session, "flush", _raiser(SQLAlchemyError("x")))
        errors.append(client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid), headers=_bearer(WAZUH_TOKEN)))
        for r in errors:
            assert r.status_code != 200
            assert r.json().get("accepted") is not True
        assert errors[-1].status_code == 500


# ==========================================================================
# section 18. Error leakage
# ==========================================================================
class TestErrorLeakage:
    def test_unrecognized_state_echoes_neither_state_nor_credential(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/wazuh", json=_body(eid, external_state=SECRET_STATE),
                           headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 422
        assert resp.json() == {"detail": CALLBACK_VALIDATION_FAILURE_DETAIL}
        assert SECRET_STATE not in resp.text
        assert WAZUH_TOKEN not in resp.text
        assert "authorization" not in resp.text.lower()

    def test_domain_message_stays_internal_not_the_http_detail(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/wazuh", json=_body(eid, external_state=SECRET_STATE),
                           headers=_bearer(WAZUH_TOKEN))
        assert SECRET_STATE not in resp.text          # the static detail replaces the domain message
        with pytest.raises(UnrecognizedExternalState):  # the domain error is internal only
            persist_callback_outcome(db_session, _observation(eid, external_state=SECRET_STATE))


# ==========================================================================
# section 19. Detail security — defense in depth
# ==========================================================================
class TestDetailSecurity:
    # G1-C / B0 — the detail-allow-list proof persists a real fact, so it runs
    # on the TEST-ONLY fake adapter (a refused Wazuh word never reaches detail).
    pytestmark = pytest.mark.usefixtures("fake_adapter_vocab")

    def test_detail_is_credential_free_even_if_redact_detail_is_a_noop(self, db_session, all_tokens, monkeypatch):
        # Even with redact_detail neutralized, NO credential can appear: the body
        # structurally carries none and the detail keys are a fixed allow-list.
        monkeypatch.setattr(webhook_service, "redact_detail", lambda d: d)
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        fact = persist_callback_outcome(db_session, _observation(eid, adapter=FAKE, external_reference=SECRET_REF))
        blob = json.dumps(fact.detail, default=str).lower()
        assert WAZUH_TOKEN.lower() not in blob
        assert "authorization" not in blob
        assert "bearer" not in blob
        assert set(fact.detail) == {
            "adapter", "external_reference", "observed_state",
            "normalized_state", "outcome_status", "mapping_reason",
        }


# ==========================================================================
# section 20. Outcome-vocabulary boundary
# ==========================================================================
class TestOutcomeVocabularyBoundary:
    # G1-C / B0 — the "valid webhook emits only outcome words" proof needs a
    # fact-producing adapter, so it runs on the TEST-ONLY fake (whose vocab is exactly
    # these seven words); the pure model/CHECK assertions are fixture-independent.
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_outcome_statuses_are_exactly_the_five(self):
        assert OUTCOME_STATUSES == OUTCOME_FIVE

    def test_no_dispatch_word_is_an_outcome_status(self):
        for w in DISPATCH_WORDS:
            assert w not in OUTCOME_STATUSES, w

    def test_model_check_constraint_lists_the_five_only(self):
        from sqlalchemy import CheckConstraint
        sqls = [c.sqltext.text for c in ExecutionOutcome.__table_args__ if isinstance(c, CheckConstraint)]
        status_ck = next(s for s in sqls if "outcome_status" in s)
        for w in OUTCOME_FIVE:
            assert f"'{w}'" in status_ck, w
        for w in DISPATCH_WORDS:
            assert f"'{w}'" not in status_ck, w

    def test_valid_webhook_only_emits_outcome_words(self, client, db_session, all_tokens):
        for state in ("success", "completed", "confirmed", "done", "ok", "running", "unknown"):
            eid = uuid.uuid4()
            _seed_chain(db_session, eid)
            client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state=state), headers=_bearer(WAZUH_TOKEN))
        outcomes = _all_outcomes(db_session)
        assert len(outcomes) == 7
        for o in outcomes:
            assert o.outcome_status in OUTCOME_STATUSES
            assert o.outcome_status not in DISPATCH_WORDS

    def test_storage_check_refuses_a_dispatch_word(self, db_session):
        # The CHECK is the last integrity line (model docstring): a dispatch word
        # cannot be persisted even by a direct ORM insert.
        db_session.add(ExecutionOutcome(
            execution_id=uuid.uuid4(), outcome_status="succeeded", source="webhook",
            operator="adapter:wazuh", observed_at=NOW, detail={},
        ))
        with pytest.raises(SQLAlchemyError):
            db_session.commit()
        db_session.rollback()
        assert _outcome_count(db_session) == 0


# ==========================================================================
# section 21. O5 — dispatch and outcome are independent layers
# ==========================================================================
class TestO5CrossLayer:
    # G1-C / B0 — the O5 independence proof (dispatch=succeeded beside a real
    # confirmed_success) runs on the TEST-ONLY fake adapter; the banana-refusal and
    # direct-ORM confirmed_failure proofs below are fixture-independent / stay wazuh.
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def test_dispatch_succeeded_and_external_outcome_are_independent(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("succeeded",))
        log_before = _log_snapshot(db_session)
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(eid, external_state="success"), headers=_bearer(WAZUH_TOKEN))
        assert _log_snapshot(db_session) == log_before            # dispatch stays succeeded
        assert _all_log_rows(db_session)[0].decision == "succeeded"
        assert _all_outcomes(db_session)[0].outcome_status == "confirmed_success"

    def test_dispatch_failed_does_not_auto_generate_an_outcome(self, client, db_session, all_tokens):
        # A dispatch=failed chain with NO valid external observation yields NO
        # fact: the webhook never invents confirmed_success/confirmed_failure.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("failed",))
        resp = client.post(f"{WEBHOOK}/wazuh", json=_body(eid, external_state="banana"), headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 422
        assert _outcome_count(db_session) == 0

    def test_dispatch_succeeded_beside_confirmed_failure_is_legal(self, db_session):
        # O5: dispatch=succeeded next to outcome=confirmed_failure is LEGAL and
        # the dispatch row stays succeeded forever. confirmed_failure is not
        # webhook-producible today, so append it directly (the 3.4.5 shape).
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, decisions=("succeeded",))
        log_before = _log_snapshot(db_session)
        db_session.add(ExecutionOutcome(
            execution_id=eid, outcome_status="confirmed_failure", source="manual_reconcile",
            operator="ops-1", observed_at=NOW, detail={},
        ))
        db_session.commit()
        assert derive_outcome_state(_all_outcomes(db_session)) == "confirmed_failure"
        assert _log_snapshot(db_session) == log_before            # dispatch unchanged
        assert _all_log_rows(db_session)[0].decision == "succeeded"


# ==========================================================================
# section 22. observed_at boundary (contract level, injected clock)
# ==========================================================================
class TestObservedAtBoundary:
    FIXED_NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)

    def _obs(self, observed_at):
        return ExternalObservation(
            execution_id=uuid.uuid4(), adapter="wazuh", external_reference="ref",
            external_state="success", observed_at=observed_at, source="webhook",
        )

    def test_aware_accepted(self):
        n = validate_observation(self._obs(self.FIXED_NOW), now=self.FIXED_NOW)
        assert n.observed_at == self.FIXED_NOW

    def test_tz_offset_normalized_to_utc(self):
        plus2 = datetime(2026, 9, 3, 14, 0, 0, tzinfo=timezone(timedelta(hours=2)))
        n = validate_observation(self._obs(plus2), now=self.FIXED_NOW)
        assert n.observed_at == self.FIXED_NOW                    # same instant
        assert n.observed_at.tzinfo == timezone.utc

    def test_microseconds_preserved(self):
        micro = self.FIXED_NOW.replace(microsecond=123456)
        n = validate_observation(self._obs(micro), now=self.FIXED_NOW)
        assert n.observed_at.microsecond == 123456

    def test_naive_rejected(self):
        with pytest.raises(InvalidObservedAt):
            validate_observation(self._obs(datetime(2026, 9, 3, 12, 0, 0)), now=self.FIXED_NOW)

    def test_future_exactly_300s_accepted(self):
        edge = self.FIXED_NOW + MAX_FUTURE_SKEW
        n = validate_observation(self._obs(edge), now=self.FIXED_NOW)
        assert n.observed_at == edge.astimezone(timezone.utc)

    def test_future_beyond_300s_rejected(self):
        over = self.FIXED_NOW + MAX_FUTURE_SKEW + timedelta(seconds=1)
        with pytest.raises(InvalidObservedAt):
            validate_observation(self._obs(over), now=self.FIXED_NOW)

    def test_naive_via_http_is_422(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        body = _body(eid)
        body["observed_at"] = "2026-09-03T12:00:00"              # naive ISO, no offset
        resp = client.post(f"{WEBHOOK}/wazuh", json=body, headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 422
        assert _outcome_count(db_session) == 0

    def test_gross_future_via_http_is_422(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        body = _body(eid)
        body["observed_at"] = (datetime.now(timezone.utc) + timedelta(seconds=9999)).isoformat()
        resp = client.post(f"{WEBHOOK}/wazuh", json=body, headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 422
        assert _outcome_count(db_session) == 0


# ==========================================================================
# section 23. No adapter IO (router + service)
# ==========================================================================
class TestNoAdapterIO:
    def test_no_outbound_transport_import(self):
        blob = _chain_import_blob()
        for forbidden in ("httpx", "requests", "urllib", "aiohttp", "socket"):
            assert forbidden not in blob, forbidden

    def test_no_adapter_read_call(self):
        calls = _chain_calls()
        for forbidden in ("get_status", "query_status", "urlopen"):
            assert forbidden not in calls, forbidden


# ==========================================================================
# section 24. No background behaviour
# ==========================================================================
class TestNoBackgroundBehavior:
    def test_no_background_or_scheduler_import(self):
        blob = _chain_import_blob()
        for forbidden in ("threading", "asyncio", "celery", "apscheduler",
                          "schedule", "concurrent", "multiprocessing", "subprocess", "queue"):
            assert forbidden not in blob, forbidden
        _, from_names, _, _ = _import_surface(webhook_module)
        assert "BackgroundTasks" not in from_names

    def test_chain_is_fully_synchronous_no_spawn(self):
        for mod in (webhook_module, webhook_service):
            _, _, _, async_defs = _import_surface(mod)
            assert not async_defs, mod.__name__                  # no async def -> no awaited spawn
        calls = _chain_calls()
        for forbidden in ("create_task", "Thread", "Process", "add_job", "sleep"):
            assert forbidden not in calls, forbidden


# ==========================================================================
# section 25. Test independence — no dev-machine token, fail-closed
# ==========================================================================
class TestTestIndependence:
    def test_unconfigured_channel_is_fail_closed_401(self, client, db_session, monkeypatch):
        monkeypatch.setattr(settings, "WAZUH_CALLBACK_TOKEN", "")
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/wazuh", json=_body(eid), headers=_bearer("any-token"))
        assert resp.status_code == 401
        assert _outcome_count(db_session) == 0

    def test_empty_bearer_is_401(self, client, db_session, all_tokens):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        resp = client.post(f"{WEBHOOK}/wazuh", json=_body(eid), headers={"Authorization": "Bearer "})
        assert resp.status_code == 401
        assert _outcome_count(db_session) == 0


# ==========================================================================
# section 26. The end-to-end cross-layer security matrix (20 scenarios)
# ==========================================================================
class TestCrossLayerSecurityMatrix:
    # G1-C / B0 — the three valid_* rows and persistence_rollback need a fact
    # to persist/rollback, so their route is the TEST-ONLY fake adapter; EVERY
    # rejection row (auth/schema/correlation/mapping/shuffle/thehive/unrecognized)
    # stays on its REAL route as a genuine production refusal proof. The channel
    # fixture is additive (the real Wazuh route stays refused).
    pytestmark = pytest.mark.usefixtures("fake_adapter_channel")

    def _build(self, mode, eid):
        if mode == "valid_success":
            return _body(eid, external_state="success")
        if mode == "valid_pending":
            return _body(eid, external_state="running")
        if mode == "valid_unknown":
            return _body(eid, external_state="unknown")
        if mode == "shuffle_rejected":
            return _body(eid, external_state="success")
        if mode == "thehive_rejected":
            return _body(eid, external_state="resolved")
        if mode in ("invalid_token", "missing_token", "unknown_execution", "persistence_rollback"):
            return _body(eid)
        if mode == "spoof_source":
            return _body(eid, source="manual_reconcile")
        if mode == "spoof_operator":
            return _body(eid, operator="admin")
        if mode == "spoof_adapter":
            return _body(eid, adapter="shuffle")
        if mode == "malformed_uuid":
            b = _body(eid); b["execution_id"] = "not-a-uuid"; return b
        if mode == "malformed_timestamp":
            b = _body(eid); b["observed_at"] = "not-a-timestamp"; return b
        if mode == "future_timestamp":
            b = _body(eid)
            b["observed_at"] = (datetime.now(timezone.utc) + timedelta(seconds=9999)).isoformat()
            return b
        if mode == "unrecognized_state":
            return _body(eid, external_state=SECRET_STATE)
        raise AssertionError(mode)

    @pytest.mark.parametrize("mode,route,token,status,delta,needs_chain,patch_flush", [
        ("valid_success", FAKE, WAZUH_TOKEN, 200, 1, True, False),
        ("valid_pending", FAKE, WAZUH_TOKEN, 200, 1, True, False),
        ("valid_unknown", FAKE, WAZUH_TOKEN, 200, 1, True, False),
        ("shuffle_rejected", "shuffle", SHUFFLE_TOKEN, 422, 0, True, False),
        ("thehive_rejected", "thehive", THEHIVE_TOKEN, 422, 0, True, False),
        ("invalid_token", "wazuh", "wrong-token", 401, 0, True, False),
        ("missing_token", "wazuh", None, 401, 0, True, False),
        ("spoof_source", "wazuh", WAZUH_TOKEN, 422, 0, True, False),
        ("spoof_operator", "wazuh", WAZUH_TOKEN, 422, 0, True, False),
        ("spoof_adapter", "wazuh", WAZUH_TOKEN, 422, 0, True, False),
        ("unknown_execution", "wazuh", WAZUH_TOKEN, 404, 0, False, False),
        ("malformed_uuid", "wazuh", WAZUH_TOKEN, 422, 0, True, False),
        ("malformed_timestamp", "wazuh", WAZUH_TOKEN, 422, 0, True, False),
        ("future_timestamp", "wazuh", WAZUH_TOKEN, 422, 0, True, False),
        ("unrecognized_state", "wazuh", WAZUH_TOKEN, 422, 0, True, False),
        ("persistence_rollback", FAKE, WAZUH_TOKEN, 500, 0, True, True),
    ])
    def test_single_request_matrix(self, client, db_session, all_tokens, monkeypatch,
                                   mode, route, token, status, delta, needs_chain, patch_flush):
        eid = uuid.uuid4()
        if needs_chain:
            _seed_chain(db_session, eid)
        if patch_flush:
            monkeypatch.setattr(db_session, "flush", _raiser(SQLAlchemyError("simulated")))
        before = _outcome_count(db_session)
        headers = _bearer(token) if token is not None else {}
        resp = client.post(f"{WEBHOOK}/{route}", json=self._build(mode, eid), headers=headers)
        assert resp.status_code == status, mode
        assert _outcome_count(db_session) - before == delta, mode

    def test_multi_request_tail(self, client, db_session, all_tokens):
        # Scenarios 17-20: duplicate / out-of-order replay / same-timestamp /
        # concurrent — each on its own chain, asserted by per-execution facts.
        def facts_for(eid):
            return [o for o in _all_outcomes(db_session) if o.execution_id == eid]

        e17 = uuid.uuid4(); _seed_chain(db_session, e17)          # 17 duplicate
        dup = _body(e17, external_state="success")
        client.post(f"{WEBHOOK}/{FAKE}", json=dup, headers=_bearer(WAZUH_TOKEN))
        client.post(f"{WEBHOOK}/{FAKE}", json=dup, headers=_bearer(WAZUH_TOKEN))
        assert len(facts_for(e17)) == 2 and derive_outcome_state(facts_for(e17)) == "confirmed_success"

        e18 = uuid.uuid4(); _seed_chain(db_session, e18)          # 18 out-of-order replay
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(e18, external_state="success", observed_at=NOW + timedelta(seconds=10)), headers=_bearer(WAZUH_TOKEN))
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(e18, external_state="running", observed_at=NOW), headers=_bearer(WAZUH_TOKEN))
        assert len(facts_for(e18)) == 2 and derive_outcome_state(facts_for(e18)) == "confirmed_success"

        e19 = uuid.uuid4(); _seed_chain(db_session, e19)          # 19 same-timestamp ordering
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(e19, external_state="running", observed_at=NOW), headers=_bearer(WAZUH_TOKEN))
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(e19, external_state="success", observed_at=NOW), headers=_bearer(WAZUH_TOKEN))
        f19 = facts_for(e19)
        assert derive_outcome_state(f19) == max(f19, key=lambda o: (o.observed_at, o.id)).outcome_status

        e20 = uuid.uuid4(); _seed_chain(db_session, e20)          # 20 concurrent (interleaved)
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(e20, external_state="success", observed_at=NOW + timedelta(seconds=5)), headers=_bearer(WAZUH_TOKEN))
        client.post(f"{WEBHOOK}/{FAKE}", json=_body(e20, external_state="running", observed_at=NOW), headers=_bearer(WAZUH_TOKEN))
        assert len(facts_for(e20)) == 2 and derive_outcome_state(facts_for(e20)) == "confirmed_success"
        _assert_session_clean(db_session)
