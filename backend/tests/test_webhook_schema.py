"""Phase 3.4.4-B — Strict Webhook Schema tests (Webhook Gate 2 — Schema).

Locks Gate 2 of the four frozen webhook inbound gates:

    External System -> HTTP Webhook
        -> Gate 1 Authentication    (3.4.4-A, sealed f35852b)
        -> Gate 2 Schema            (THIS FILE, 3.4.4-B)
        -> Gate 3 Correlation       (3.4.4-C)
        -> Gate 4 Semantic Mapping  (3.4.4-D)
        -> Outcome Fact Append      (3.4.4-E)

The data flow this file proves (spec §1):

    HTTP JSON -> WebhookCallbackRequest (strict Pydantic, extra="forbid")
              -> to_external_observation(request, adapter=<authenticated>)
              -> ExternalObservation
              -> validate_observation()   (3.4.3-A contract, unchanged)

Coverage map (acceptance gate — spec §15 items 1-23, plus §16 / §18 / §12 / §19):
- Valid payload + external_state preservation (§15.1 / 7 / 8 / 18 / §8).
- Required-field presence (§15.2 / 4 / 6 / 9) -> ValidationError -> 422.
- Field types (§15.3 / 5 / 10) -> malformed UUID / wrong-typed reference /
  non-datetime observed_at are all rejected.
- extra="forbid" (§15.11-15 / §5 / §6 / §7): any extra field, and specifically
  a client-supplied source / operator / adapter, is a schema rejection; the
  payload can never select "manual_reconcile".
- Schema trust boundary (§16): a client body cannot move the authenticated
  adapter, cannot move source off "webhook", cannot inject an operator.
- Contract conversion (§11 / §15.16 / 17 / 19): source is always "webhook",
  adapter always comes from the server-side authenticated identity, and the
  contract validator receives a real ExternalObservation.
- observed_at boundary (§10): the schema types it (naive passes) but does NOT
  normalize / reject it — the 3.4.3-A contract owns tz-awareness, so no second
  timestamp rule is duplicated here.
- external_reference / external_state boundary (§9): the schema checks presence
  + type only (empty / whitespace / blank pass) — semantic rejection belongs to
  the contract, never to a second business rule in the schema.
- No side effects (§15.20-23 / §19): schema validation touches no DB, performs
  no mapping, persists no fact, never accesses execution_log.
- No mapping in B (§14): even external_state="success" never becomes an outcome
  word here — normalize_external_state is Gate 4 (3.4.4-D).
- AST import surface (§18): webhook.py imports ONLY the sanctioned schema
  dependencies + the 3.4.3 reconciliation domain; defines exactly one function
  and one model; never pulls in SQLAlchemy / ExecutionLog / executor / adapter
  clients / httpx / requests / persistence / execution service.
- HTTP error semantics (§12): a schema failure surfaces as a real HTTP 422
  (proved with a THROWAWAY probe app — the production router stays the sealed
  3.4.4-A stub, untouched per spec §3).

SCHEMA ONLY. No correlation, no mapping, no persistence (spec §2 / §3); those
arrive in 3.4.4-C..E. The Shuffle/TheHive Gate-4 fail-closed behaviour is
untouched here and must not be relaxed to "make a demo pass".
"""
import ast
import inspect
import uuid
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.models.execution_outcome import OUTCOME_SOURCES
from app.schemas import webhook as webhook_schema
from app.schemas.webhook import (
    WEBHOOK_SOURCE,
    WebhookCallbackRequest,
    to_external_observation,
)
from app.services.outcomes.reconciliation import (
    ContractValidationFailure,
    ExternalObservation,
    InvalidObservedAt,
    MissingExternalReference,
    MissingExternalState,
    NormalizedObservation,
    validate_observation,
)

# A fixed reference clock so the bounded-future check in the contract is
# deterministic (the schema itself has no clock — it only types observed_at).
NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)
EXECUTION_ID = uuid.UUID("3f2b8c1e-9d47-4a6e-8b1c-2f5e7d9a0c31")
# tz-aware and equal to the NOW instant, so a valid payload also survives the
# contract's bounded-future check.
OBSERVED_AT = "2026-09-03T12:00:00Z"
# The server-side trusted identity a Gate-1 authentication would hand down.
AUTHENTICATED_ADAPTER = "wazuh"
FOUR_FIELDS = {"execution_id", "external_reference", "external_state", "observed_at"}


def valid_payload(**overrides):
    """A minimal, well-formed webhook body (JSON-shaped: strings for the UUID
    and the timestamp, exactly as an external system would POST it)."""
    payload = {
        "execution_id": str(EXECUTION_ID),
        "external_reference": "wazuh-alert-0001",
        "external_state": "success",
        "observed_at": OBSERVED_AT,
    }
    payload.update(overrides)
    return payload


def without(field):
    payload = valid_payload()
    payload.pop(field)
    return payload


def parse(**overrides):
    return WebhookCallbackRequest.model_validate(valid_payload(**overrides))


def error_for(payload):
    with pytest.raises(ValidationError) as exc:
        WebhookCallbackRequest.model_validate(payload)
    return exc.value


def error_types(exc):
    return {e["type"] for e in exc.errors()}


def error_fields(exc):
    return {e["loc"][0] for e in exc.errors() if e["loc"]}


def convert(request, *, adapter=AUTHENTICATED_ADAPTER):
    return to_external_observation(request, adapter=adapter)


# --------------------------------------------------------------------------
# §15.1 / 7 / 8 / 18 — valid payload, external_state typed both ways, and
# preserved RAW (no lower / trim / upper — spec §8).
# --------------------------------------------------------------------------
class TestValidPayloadAndPreservation:
    def test_01_valid_minimal_payload(self):
        req = parse()
        assert req.execution_id == EXECUTION_ID
        assert req.external_reference == "wazuh-alert-0001"
        assert req.external_state == "success"
        assert req.observed_at == NOW

    def test_07_external_state_string(self):
        req = parse(external_state="running")
        assert isinstance(req.external_state, str)
        assert req.external_state == "running"

    def test_08_external_state_mapping(self):
        req = parse(external_state={"agent_status": "completed"})
        assert isinstance(req.external_state, dict)
        assert req.external_state == {"agent_status": "completed"}

    def test_18_external_state_string_remains_unchanged(self):
        # §8: no lower / trim / upper. A mixed-case, padded string survives
        # byte-for-byte through BOTH the schema and the conversion.
        raw = "  MiXeD CaSe Success  "
        req = parse(external_state=raw)
        assert req.external_state == raw
        assert convert(req).external_state == raw

    def test_18_external_state_mapping_remains_unchanged(self):
        # §8: mapping keys AND values keep their exact case; nothing is folded.
        raw = {"Agent_Status": "RuNnInG", "detail": "Not Lowered"}
        req = parse(external_state=raw)
        assert req.external_state == raw
        assert convert(req).external_state == raw

    def test_model_fields_are_exactly_the_four_client_facts(self):
        # §4 / §5 / §6 / §7: the model exposes ONLY the four observation
        # facts. source / adapter / operator are NOT fields — they can never
        # be client-supplied (proved again by the extra="forbid" tests).
        assert set(WebhookCallbackRequest.model_fields) == FOUR_FIELDS
        for server_only in ("source", "adapter", "operator"):
            assert server_only not in WebhookCallbackRequest.model_fields


# --------------------------------------------------------------------------
# §15.2 / 4 / 6 / 9 — required-field presence.
# --------------------------------------------------------------------------
class TestRequiredFields:
    def test_02_missing_execution_id(self):
        exc = error_for(without("execution_id"))
        assert "missing" in error_types(exc)
        assert "execution_id" in error_fields(exc)

    def test_04_missing_external_reference(self):
        exc = error_for(without("external_reference"))
        assert "missing" in error_types(exc)
        assert "external_reference" in error_fields(exc)

    def test_06_missing_external_state(self):
        exc = error_for(without("external_state"))
        assert "missing" in error_types(exc)
        assert "external_state" in error_fields(exc)

    def test_09_missing_observed_at(self):
        exc = error_for(without("observed_at"))
        assert "missing" in error_types(exc)
        assert "observed_at" in error_fields(exc)

    def test_empty_payload_rejects_every_required_field(self):
        exc = error_for({})
        assert error_fields(exc) == FOUR_FIELDS
        assert error_types(exc) == {"missing"}


# --------------------------------------------------------------------------
# §15.3 / 5 / 10 — field types. (int is NOT coerced to str; int IS coerced to
# a datetime by Pydantic, so the invalid-observed_at cases use values that are
# genuinely unparseable rather than an int.)
# --------------------------------------------------------------------------
class TestFieldTypes:
    def test_03_malformed_uuid(self):
        exc = error_for(valid_payload(execution_id="not-a-uuid"))
        assert "uuid_parsing" in error_types(exc)
        assert "execution_id" in error_fields(exc)

    def test_03_non_uuid_type(self):
        exc = error_for(valid_payload(execution_id=12345))
        assert "uuid_type" in error_types(exc)

    def test_05_external_reference_wrong_type_int(self):
        # Pydantic v2 does NOT coerce int -> str, so this is a clean rejection.
        exc = error_for(valid_payload(external_reference=123))
        assert "string_type" in error_types(exc)
        assert "external_reference" in error_fields(exc)

    def test_05_external_reference_wrong_type_list(self):
        exc = error_for(valid_payload(external_reference=["not", "a", "str"]))
        assert "string_type" in error_types(exc)

    def test_10_invalid_observed_at_type_none(self):
        exc = error_for(valid_payload(observed_at=None))
        assert "datetime_type" in error_types(exc)
        assert "observed_at" in error_fields(exc)

    def test_10_invalid_observed_at_unparseable_string(self):
        exc = error_for(valid_payload(observed_at="not-a-date"))
        assert "datetime_from_date_parsing" in error_types(exc)

    def test_external_state_wrong_type_rejected(self):
        # §4: external_state is str | Mapping ONLY. A bare int / list / None is
        # neither, so the union rejects it (both arms report their type error).
        for bad in (123, ["x"], None):
            exc = error_for(valid_payload(external_state=bad))
            assert "external_state" in error_fields(exc)


# --------------------------------------------------------------------------
# §15.11-15 — extra="forbid" rejects any unknown field, and specifically the
# trust-carrying fields source / operator / adapter.
# --------------------------------------------------------------------------
class TestExtraForbid:
    def test_11_extra_field_rejected(self):
        exc = error_for(valid_payload(unexpected="x"))
        assert "extra_forbidden" in error_types(exc)
        assert "unexpected" in error_fields(exc)

    def test_12_source_field_rejected(self):
        exc = error_for(valid_payload(source="webhook"))
        assert "extra_forbidden" in error_types(exc)
        assert "source" in error_fields(exc)

    def test_13_operator_field_rejected(self):
        exc = error_for(valid_payload(operator="admin"))
        assert "extra_forbidden" in error_types(exc)
        assert "operator" in error_fields(exc)

    def test_14_adapter_field_rejected(self):
        exc = error_for(valid_payload(adapter="wazuh"))
        assert "extra_forbidden" in error_types(exc)
        assert "adapter" in error_fields(exc)

    def test_15_payload_cannot_select_manual_reconcile(self):
        # §5: the client can never choose the ingress channel. Sending
        # source="manual_reconcile" is a schema rejection, not a channel switch.
        exc = error_for(valid_payload(source="manual_reconcile"))
        assert "extra_forbidden" in error_types(exc)
        assert "source" in error_fields(exc)

    def test_multiple_smuggled_facts_all_rejected(self):
        exc = error_for(
            valid_payload(source="manual_reconcile", operator="admin", adapter="thehive")
        )
        assert error_types(exc) == {"extra_forbidden"}
        assert {"source", "operator", "adapter"} <= error_fields(exc)


# --------------------------------------------------------------------------
# §16 — Schema trust boundary: a client body cannot move the authenticated
# adapter, cannot move source off "webhook", cannot inject an operator.
# --------------------------------------------------------------------------
class TestSchemaTrustBoundary:
    def test_client_adapter_cannot_change_authenticated_adapter(self):
        # A body that tries to declare adapter="thehive" is rejected outright;
        # the conversion's adapter comes ONLY from the server-side argument.
        error_for(valid_payload(adapter="thehive"))
        req = parse()
        assert convert(req, adapter="wazuh").adapter == "wazuh"
        assert convert(req, adapter="thehive").adapter == "thehive"

    def test_client_source_cannot_change_webhook(self):
        error_for(valid_payload(source="manual_reconcile"))
        # Even with no source field at all, the conversion hardcodes webhook.
        assert convert(parse()).source == "webhook"

    def test_client_operator_cannot_become_outcome_operator(self):
        error_for(valid_payload(operator="admin"))
        obs = convert(parse())
        # ExternalObservation has NO operator field at all — the recorder is
        # derived server-side later (spec §7), never carried from the body.
        assert not hasattr(obs, "operator")

    def test_adapter_argument_is_keyword_only_and_required(self):
        # §6 / §11: the trusted adapter MUST be passed explicitly by the
        # server (keyword-only, no default), so it can never be defaulted from
        # or confused with any client-controlled value.
        params = inspect.signature(to_external_observation).parameters
        assert params["adapter"].kind is inspect.Parameter.KEYWORD_ONLY
        assert params["adapter"].default is inspect.Parameter.empty
        assert params["request"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD

    def test_no_operator_or_source_argument_on_conversion(self):
        # The conversion exposes ONLY (request, adapter) — there is no way to
        # pass an operator or a source, so neither can be client-influenced.
        assert set(inspect.signature(to_external_observation).parameters) == {
            "request",
            "adapter",
        }


# --------------------------------------------------------------------------
# §11 / §15.16 / 17 / 19 — the Schema -> Contract conversion boundary.
# --------------------------------------------------------------------------
class TestContractConversion:
    def test_conversion_returns_external_observation(self):
        obs = convert(parse())
        assert isinstance(obs, ExternalObservation)

    def test_16_source_always_becomes_webhook(self):
        for adapter in ("shuffle", "wazuh", "thehive"):
            assert convert(parse(), adapter=adapter).source == "webhook"

    def test_webhook_source_is_a_frozen_outcome_source(self):
        # Single-source cross-check: the literal the schema hardcodes is a real
        # frozen ingress channel, so it can never drift from OUTCOME_SOURCES.
        assert WEBHOOK_SOURCE == "webhook"
        assert WEBHOOK_SOURCE in OUTCOME_SOURCES

    def test_17_adapter_comes_from_server_side_identity(self):
        # The reference value mentions wazuh, but the authenticated identity is
        # thehive -> the observation carries thehive. Body text is irrelevant.
        req = parse(external_reference="wazuh-alert-0001")
        assert convert(req, adapter="thehive").adapter == "thehive"

    def test_19_contract_validator_receives_external_observation(self):
        obs = convert(parse())
        normalized = validate_observation(obs, now=NOW)
        assert isinstance(normalized, NormalizedObservation)
        assert normalized.source == "webhook"
        assert normalized.adapter == AUTHENTICATED_ADAPTER
        assert normalized.execution_id == EXECUTION_ID
        assert normalized.trust_domain == "adapter_callback"

    def test_conversion_copies_fields_through_unchanged(self):
        req = parse(external_state={"agent_status": "completed"})
        obs = convert(req)
        assert obs.execution_id == req.execution_id
        assert obs.external_reference == req.external_reference
        assert obs.external_state == req.external_state
        assert obs.observed_at == req.observed_at

    def test_conversion_is_deterministic_and_pure(self):
        req = parse()
        first = convert(req)
        second = convert(req)
        assert first == second
        # The request itself is untouched (frozen conversion, no mutation).
        assert req.execution_id == EXECUTION_ID

    def test_conversion_does_not_run_the_contract(self):
        # §9 / §10: the conversion is PURE — an input the contract would reject
        # (empty external_reference) still converts cleanly; only the explicit
        # validate_observation step refuses it. Proves the schema layer does not
        # secretly embed contract logic.
        obs = convert(parse(external_reference=""))
        assert obs.external_reference == ""
        with pytest.raises(MissingExternalReference):
            validate_observation(obs, now=NOW)


# --------------------------------------------------------------------------
# §10 — observed_at boundary: schema types it, contract normalizes / rejects.
# --------------------------------------------------------------------------
class TestObservedAtBoundary:
    def test_schema_accepts_naive_datetime_type_only(self):
        # A naive timestamp is a valid `datetime`, so the schema accepts it and
        # does NOT attach a tz — that decision belongs to the contract (§10.2).
        req = parse(observed_at="2026-09-03T12:00:00")
        assert req.observed_at.tzinfo is None

    def test_contract_refuses_naive_datetime(self):
        req = parse(observed_at="2026-09-03T12:00:00")
        with pytest.raises(InvalidObservedAt):
            validate_observation(convert(req), now=NOW)

    def test_tz_aware_passes_schema_and_contract(self):
        req = parse(observed_at="2026-09-03T12:00:00Z")
        normalized = validate_observation(convert(req), now=NOW)
        assert normalized.observed_at == NOW
        assert normalized.observed_at.tzinfo is not None

    def test_schema_does_not_normalize_timezone(self):
        # A non-UTC offset is preserved by the schema (type only); the contract
        # is what re-expresses it in UTC. No second timestamp rule lives here.
        req = parse(observed_at="2026-09-03T14:00:00+02:00")
        assert req.observed_at.utcoffset().total_seconds() == 7200
        normalized = validate_observation(convert(req), now=NOW)
        assert normalized.observed_at == NOW  # same instant, normalized to UTC

    def test_contract_refuses_excessive_future(self):
        # The schema types a far-future timestamp fine; the contract's bounded
        # skew refuses it. Again: schema = type, contract = semantics.
        req = parse(observed_at="2027-01-01T00:00:00Z")
        with pytest.raises(InvalidObservedAt):
            validate_observation(convert(req), now=NOW)


# --------------------------------------------------------------------------
# §9 / §8 — external_reference / external_state boundary: schema checks
# presence + type only; the contract owns semantic rejection.
# --------------------------------------------------------------------------
class TestSemanticBoundaryBelongsToContract:
    def test_schema_accepts_empty_external_reference(self):
        req = parse(external_reference="")
        assert req.external_reference == ""

    def test_contract_refuses_empty_external_reference(self):
        with pytest.raises(MissingExternalReference):
            validate_observation(convert(parse(external_reference="")), now=NOW)

    def test_schema_accepts_whitespace_external_reference(self):
        req = parse(external_reference="   ")
        assert req.external_reference == "   "

    def test_contract_refuses_whitespace_external_reference(self):
        with pytest.raises(MissingExternalReference):
            validate_observation(convert(parse(external_reference="   ")), now=NOW)

    def test_schema_accepts_blank_external_state(self):
        # An empty string is a str and an empty dict is a Mapping, so the
        # schema (type/presence only) accepts both.
        assert parse(external_state="").external_state == ""
        assert parse(external_state={}).external_state == {}

    def test_contract_refuses_blank_external_state(self):
        with pytest.raises(MissingExternalState):
            validate_observation(convert(parse(external_state="")), now=NOW)
        with pytest.raises(MissingExternalState):
            validate_observation(convert(parse(external_state={})), now=NOW)

    def test_contract_refuses_unknown_authenticated_adapter(self):
        # The schema never validates the adapter; if a bad identity somehow
        # reached the conversion, the contract is what refuses it — not the
        # schema. (Gate 1 already prevents this; this pins the division.)
        with pytest.raises(ContractValidationFailure):
            validate_observation(convert(parse(), adapter="not-an-adapter"), now=NOW)


# --------------------------------------------------------------------------
# §14 / §15.21 — no mapping in B: "success" never becomes an outcome word here.
# --------------------------------------------------------------------------
class TestNoMappingInB:
    def test_normalized_observation_has_no_outcome_status(self):
        # Even external_state="success" yields a NormalizedObservation with NO
        # outcome_status field — mapping is Gate 4 (3.4.4-D), never the schema.
        normalized = validate_observation(convert(parse(external_state="success")), now=NOW)
        assert not hasattr(normalized, "outcome_status")
        assert normalized.external_state == "success"  # still RAW

    def test_schema_module_never_references_the_mapper(self):
        source = inspect.getsource(webhook_schema)
        assert "normalize_external_state" not in source
        assert "confirmed_success" not in source
        assert "confirmed_failure" not in source

    def test_conversion_output_is_not_an_orm_fact(self):
        # The conversion produces a frozen domain dataclass, never an ORM row.
        obs = convert(parse())
        assert isinstance(obs, ExternalObservation)
        assert not hasattr(obs, "__table__")
        assert not hasattr(obs, "__tablename__")


# --------------------------------------------------------------------------
# §15.20 / 22 / 23 / §19 — no DB, no persistence, no execution_log access.
# These run with NO db fixture in scope: if any secretly needed a session they
# would error, which is itself the proof of purity.
# --------------------------------------------------------------------------
class TestNoSideEffects:
    def test_20_schema_validation_needs_no_database(self):
        # Parsing + conversion + contract all succeed with no session anywhere.
        req = parse()
        normalized = validate_observation(convert(req), now=NOW)
        assert isinstance(normalized, NormalizedObservation)

    def test_22_no_outcome_fact_is_constructed(self):
        # The schema module never instantiates the ORM fact.
        source = inspect.getsource(webhook_schema)
        assert "ExecutionOutcome(" not in source
        assert "execution_outcome" not in source

    def test_23_no_execution_log_access(self):
        source = inspect.getsource(webhook_schema)
        assert "ExecutionLog" not in source
        assert "execution_log" not in source

    def test_invalid_payload_needs_no_database(self):
        # A rejected payload raises ValidationError purely in-process — no DB
        # is touched on the error path either.
        with pytest.raises(ValidationError):
            WebhookCallbackRequest.model_validate(without("execution_id"))

    def test_schema_module_has_no_persistence_or_io_constructs(self):
        source = inspect.getsource(webhook_schema)
        for forbidden in (
            "SessionLocal", "db.commit", "db.rollback", ".query(", "select(",
            "derive_outcome_state", "httpx", "requests", "executor",
        ):
            assert forbidden not in source, f"forbidden construct: {forbidden}"


# --------------------------------------------------------------------------
# §18 — AST / import surface of the SCHEMA MODULE.
# --------------------------------------------------------------------------
def _imported_webhook_schema():
    """AST view of webhook.py's OWN imports + defined functions/classes — the
    robust structural proof, immune to docstring mentions (mirrors the 3.4.4-A
    authentication import-surface test)."""
    tree = ast.parse(inspect.getsource(webhook_schema))
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


class TestImportSurface:
    def test_modules_are_exactly_the_schema_dependencies(self):
        # §18: ONLY Pydantic + stdlib (uuid / datetime / collections.abc) + the
        # 3.4.3 reconciliation domain. An exact allowlist is the strongest
        # proof — anything else (SQLAlchemy / httpx / executor / models /
        # adapter clients) fails here loudly.
        modules, _, _, _ = _imported_webhook_schema()
        assert modules == {
            "uuid",
            "datetime",
            "collections.abc",
            "pydantic",
            "app.services.outcomes.reconciliation",
        }

    def test_no_forbidden_module_imported(self):
        modules, names, _, _ = _imported_webhook_schema()
        for mod in modules:
            for bad in (
                "sqlalchemy", "execution_log", "executor", "wazuh", "thehive",
                "shuffle", "mock", "httpx", "requests", "repository",
                "database", "derivation", "response_execution", "operators",
                "registry", "session",
            ):
                assert bad not in mod, f"module {mod} pulls in forbidden {bad}"
        # The ORM fact model is never imported (WEBHOOK_SOURCE is a literal,
        # cross-checked against OUTCOME_SOURCES only from the test side).
        assert "ExecutionOutcome" not in names
        assert "OUTCOME_SOURCES" not in names

    def test_functions_are_exactly_the_conversion_boundary(self):
        # §11 / §3: exactly one function — the Schema -> Contract conversion.
        # No validator, no correlation, no mapper, no persistence function.
        _, _, funcs, _ = _imported_webhook_schema()
        assert funcs == {"to_external_observation"}

    def test_classes_are_exactly_the_request_model(self):
        # §4: one model, no custom exception / validator class (all rejection
        # is delegated to Pydantic's ValidationError and the 3.4.3-A contract).
        _, _, _, classes = _imported_webhook_schema()
        assert classes == {"WebhookCallbackRequest"}

    def test_imported_names_are_the_sanctioned_set(self):
        _, names, _, _ = _imported_webhook_schema()
        assert names == {
            "Mapping", "datetime", "BaseModel", "ConfigDict", "ExternalObservation",
        }


# --------------------------------------------------------------------------
# §12 — HTTP error semantics: a schema failure is a real 422, a valid payload
# parses. Proved with a THROWAWAY probe app so the production router (the
# sealed 3.4.4-A stub) stays untouched (spec §3).
# --------------------------------------------------------------------------
def _probe_app():
    """A minimal, test-only FastAPI app whose sole endpoint takes the schema as
    its body model. It performs NO auth / correlation / mapping / persistence —
    it exists purely to demonstrate FastAPI's ValidationError -> 422 mapping
    against WebhookCallbackRequest with a real HTTP status."""
    app = FastAPI()

    @app.post("/probe")
    def _probe(body: WebhookCallbackRequest):  # pragma: no cover - trivial echo
        return {"accepted": True, "execution_id": str(body.execution_id)}

    return app


@pytest.fixture()
def probe_client():
    return TestClient(_probe_app())


class TestHttpErrorSemantics:
    def test_valid_payload_is_accepted(self, probe_client):
        resp = probe_client.post("/probe", json=valid_payload())
        assert resp.status_code == 200
        assert resp.json()["accepted"] is True

    def test_missing_field_is_422(self, probe_client):
        resp = probe_client.post("/probe", json=without("execution_id"))
        assert resp.status_code == 422

    def test_malformed_uuid_is_422(self, probe_client):
        resp = probe_client.post("/probe", json=valid_payload(execution_id="nope"))
        assert resp.status_code == 422

    def test_client_source_field_is_422(self, probe_client):
        resp = probe_client.post("/probe", json=valid_payload(source="manual_reconcile"))
        assert resp.status_code == 422

    def test_client_operator_field_is_422(self, probe_client):
        resp = probe_client.post("/probe", json=valid_payload(operator="admin"))
        assert resp.status_code == 422

    def test_client_adapter_field_is_422(self, probe_client):
        resp = probe_client.post("/probe", json=valid_payload(adapter="thehive"))
        assert resp.status_code == 422

    def test_no_reconciliation_failed_or_200_on_bad_schema(self, probe_client):
        # §12: a schema failure is never a 200 and never mentions
        # reconciliation_failed — it is a plain 422 at the boundary.
        resp = probe_client.post("/probe", json=valid_payload(observed_at="not-a-date"))
        assert resp.status_code == 422
        assert resp.status_code != 200
        assert "reconciliation_failed" not in resp.text
