"""Phase 3.4.4-D: Webhook Gate 4 — Semantic Mapping Integration tests.

Gate 4 is the ONLY place an external state word becomes an outcome word, and
the entire 3.4.4 anti-fabrication discipline is pinned here. This suite proves
four things about ``map_external_state``:

1. REUSE, NOT REIMPLEMENTATION (spec §3 / §16). The mapping vocabulary comes
   SOLELY from 3.4.3-B ``normalize_external_state``. D adds no table, no
   ``if/elif`` chain, no second DTO — proven structurally: the function body is
   a SINGLE delegated ``return normalize_external_state(...)`` with no branch.
2. THE EVIDENCED VOCABULARY ONLY (spec §4 / §21; G1-C UPDATED). After G1-C NO
   production adapter has an evidenced external-state vocabulary: EVERY Wazuh /
   Shuffle / TheHive / Mock state (including the former Wazuh ``success`` /
   ``running`` / ``unknown`` and a plausible ``success`` / ``resolved``) is
   REFUSED. The platform "an evidenced vocabulary maps onto MAPPABLE" property is
   proven on a TEST-ONLY fake adapter double (B0 §15.4), never by widening a
   production vocabulary to make a demo pass.
3. THE SEMANTIC FIREWALLS (spec §5 / §6 / §7). Dispatch words ``succeeded`` /
   ``failed`` never become outcome words; ``reconciliation_failed`` is never a
   mapping product (structurally impossible); a RECOGNIZED-ambiguous ``unknown``
   is a legit mapping while an UNREGISTERED state is refused — never downgraded
   to ``unknown``.
4. PURE DOMAIN (spec §14 / §15 / §20). No SQLAlchemy / Session / ORM /
   repository / commit / flush, no executor / execution service / adapter client
   / response_execution, no FastAPI. The AST import surface is an exact
   allowlist; the write-verb and capability checks are AST-based so they are
   docstring-immune (the module docstring legitimately NAMES everything Gate 4
   must not do).
"""
import ast
import inspect
import uuid
from datetime import datetime, timezone

import pytest

from app.models import OUTCOME_STATUSES
from app.services.executions.models import OUTCOME_STATUSES as DISPATCH_STATUSES
from app.services.outcomes import mapping as mapping_module
from app.services.outcomes.mapping import map_external_state
from app.services.outcomes.reconciliation import (
    MAPPABLE_OUTCOME_STATUSES,
    ContractValidationFailure,
    ExternalObservation,
    NormalizedObservation,
    StateMapping,
    UnrecognizedExternalState,
    normalize_external_state,
    validate_observation,
)

NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)
EXECUTION_ID = uuid.UUID("3f2b8c1e-9d47-4a6e-8b1c-2f5e7d9a0c31")

#: G1-C / B0 §15.4 — the TEST-ONLY fake adapter identity (matches
#: conftest.FAKE_ADAPTER). Wazuh's external-state vocabulary is now EMPTY
#: (fail-closed), so the platform success-pipeline proofs that once rode on the
#: Wazuh "success" word are re-based on this explicit test double via the
#: ``fake_adapter_vocab`` fixture. It is NEVER a production adapter and NEVER
#: reopens the real Wazuh vocabulary.
FAKE_ADAPTER = "fakesuccess"

#: The exact import surface Gate 4 is allowed (spec §14 / §15 / §20): ONLY the
#: 3.4.3 reconciliation domain. No DB, no FastAPI, no executor, no adapter.
ALLOWED_MODULES = {"app.services.outcomes.reconciliation"}
ALLOWED_NAMES = {"NormalizedObservation", "StateMapping", "normalize_external_state"}

#: Module fragments Gate 4 must NEVER import. Precise enough not to
#: false-positive on the allowed ``app.services.outcomes.reconciliation``.
FORBIDDEN_MODULE_FRAGMENTS = (
    "sqlalchemy",
    "fastapi",
    "app.api",
    "app.core.database",
    "app.services.executions",  # executor / dispatch service / response_execution
    "executor",
    "adapter",
    "app.integrations",
    "requests",
    "httpx",
    "retry",
    "compensation",
    "response_execution",
    "execution_outcome",  # the ORM fact model (persistence is 3.4.4-E)
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _validated(adapter, external_state, *, source="webhook") -> NormalizedObservation:
    """Run the REAL 3.4.3-A validator so Gate 4 consumes a genuinely validated
    observation (spec §8), carrying the trusted adapter end to end."""
    observation = ExternalObservation(
        execution_id=EXECUTION_ID,
        adapter=adapter,
        external_reference="ext-ref-1",
        external_state=external_state,
        observed_at=NOW,
        source=source,
    )
    return validate_observation(observation, now=NOW)


def _map(adapter, external_state) -> StateMapping:
    return map_external_state(_validated(adapter, external_state))


def _imported_mapping():
    """AST import surface of mapping.py — docstring-immune (spec §14 / §15)."""
    tree = ast.parse(inspect.getsource(mapping_module))
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


def _called_names():
    """Every function/method name CALLED in mapping.py (AST, docstring-immune)."""
    tree = ast.parse(inspect.getsource(mapping_module))
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                called.add(func.attr)
            elif isinstance(func, ast.Name):
                called.add(func.id)
    return called


# ---------------------------------------------------------------------------
# §13.1-7 (G1-C REVERSED) — Wazuh now has NO evidenced vocabulary: EVERY state
# is refused. The former {completed,confirmed,done,success,ok}->confirmed_success
# / running->pending / unknown->unknown mapping was fabricated from a fictional
# "agent_status IS the effect status" reading (B0 §4 / §8-§11) and G1-A proved it
# LIVE-reachable (CONFIRMED UNSAFE). G1-C emptied all four sets to fail-closed.
# ---------------------------------------------------------------------------
class TestWazuhVocabularyRefused:
    @pytest.mark.parametrize("word", ["completed", "confirmed", "done", "success", "ok"])
    def test_former_success_words_are_refused(self, word):
        # G1-C: the five former "success" words are NO LONGER evidenced — each is
        # refused, never confirmed_success.
        with pytest.raises(UnrecognizedExternalState):
            _map("wazuh", word)

    def test_running_is_refused(self):
        # G1-C: 'running' was a connection-state false friend (B0 §10) — refused.
        with pytest.raises(UnrecognizedExternalState):
            _map("wazuh", "running")

    def test_unknown_is_refused(self):
        # G1-C: 'unknown' traced to a comment, not a real enum (B0 §11) — refused
        # (and NEVER a downgrade target: a refusal is not the 'unknown' mapping).
        with pytest.raises(UnrecognizedExternalState):
            _map("wazuh", "unknown")

    def test_no_case_folding_survives(self):
        # G1-C: case_insensitive is now False (no evidenced word to fold) — even
        # an upper-case former success word is refused.
        with pytest.raises(UnrecognizedExternalState):
            _map("wazuh", "SUCCESS")

    def test_mapping_form_is_refused(self):
        # G1-C: state_key is now None (no evidenced key) — a Mapping external_state
        # yields no state word -> refused.
        with pytest.raises(UnrecognizedExternalState):
            _map("wazuh", {"agent_status": "completed"})


# ---------------------------------------------------------------------------
# §13.1-7 (G1-C / B0 §15.4) — the PLATFORM evidenced-mapping proof, re-based on
# the TEST-ONLY fake adapter. Preserves the Gate-4 property "an evidenced
# vocabulary maps onto MAPPABLE_OUTCOME_STATUSES end to end" WITHOUT depending on
# any fictional production vocabulary (the real Wazuh set is empty above).
# ---------------------------------------------------------------------------
class TestFakeAdapterEvidencedMapping:
    @pytest.mark.parametrize("word", ["completed", "confirmed", "done", "success", "ok"])
    def test_success_words_map_to_confirmed_success(self, fake_adapter_vocab, word):
        assert _map(fake_adapter_vocab, word).outcome_status == "confirmed_success"

    def test_running_maps_to_pending(self, fake_adapter_vocab):
        assert _map(fake_adapter_vocab, "running").outcome_status == "pending"

    def test_unknown_maps_to_unknown(self, fake_adapter_vocab):
        # A RECOGNIZED-but-ambiguous state -> the outcome word 'unknown' (NOT a
        # refusal — see TestUnknownVsRejected).
        assert _map(fake_adapter_vocab, "unknown").outcome_status == "unknown"

    def test_case_insensitive_per_adapter_evidence(self, fake_adapter_vocab):
        # The fake double lower-cases its state word; D passes the state through
        # and the RAW word is preserved in observed_state (spec §10).
        result = _map(fake_adapter_vocab, "SUCCESS")
        assert result.outcome_status == "confirmed_success"
        assert result.observed_state == "SUCCESS"
        assert result.normalized_state == "success"

    def test_mapping_state_key_is_extracted(self, fake_adapter_vocab):
        # A Mapping external_state yields mapping['agent_status'].
        result = _map(fake_adapter_vocab, {"agent_status": "completed"})
        assert result.outcome_status == "confirmed_success"
        assert result.observed_state == "completed"

    def test_every_result_is_a_mappable_word(self, fake_adapter_vocab):
        # §6: whatever the fake double maps to is always in MAPPABLE_OUTCOME_STATUSES.
        for word in ("completed", "running", "unknown"):
            assert (
                _map(fake_adapter_vocab, word).outcome_status
                in MAPPABLE_OUTCOME_STATUSES
            )


# ---------------------------------------------------------------------------
# §13.8 + §4 + §21 — Wazuh has NO evidenced failure vocabulary
# ---------------------------------------------------------------------------
class TestWazuhFailureUnsupported:
    @pytest.mark.parametrize(
        "word", ["failed", "error", "adapter_error", "timeout", "adapter_unavailable"]
    )
    def test_failure_like_is_rejected_not_confirmed_failure(self, word):
        # §13.8 / §4 / §21: Wazuh declares NO terminal-failure agent_status; its
        # failure words are DISPATCH transport classifications. A failure-like
        # external_state is REFUSED, never mapped to confirmed_failure.
        with pytest.raises(UnrecognizedExternalState):
            _map("wazuh", word)

    def test_confirmed_failure_is_currently_unproducible(self):
        # §6: with no evidenced failure vocabulary anywhere, D produces no
        # confirmed_failure today. Every adapter's failure-like words refuse.
        for adapter in ("wazuh", "shuffle", "thehive", "mock"):
            for word in ("failed", "error", "failure"):
                with pytest.raises(UnrecognizedExternalState):
                    _map(adapter, word)


# ---------------------------------------------------------------------------
# §13.9 / §13.10 / §13.11 + §21 — Shuffle / TheHive / Mock fail closed
# ---------------------------------------------------------------------------
class TestFailClosedAdapters:
    @pytest.mark.parametrize(
        "word", ["success", "completed", "resolved", "done", "true", "finished"]
    )
    def test_shuffle_every_state_rejected(self, word):
        # §13.9 / §21: Shuffle is trigger-only with NO read path — even a
        # plausible 'success' is REFUSED (no fabricated vocabulary).
        with pytest.raises(UnrecognizedExternalState):
            _map("shuffle", word)

    @pytest.mark.parametrize(
        "word", ["resolved", "success", "closed", "open", "completed"]
    )
    def test_thehive_every_state_rejected(self, word):
        # §13.10 / §21: case created != case resolved; no evidenced vocabulary.
        with pytest.raises(UnrecognizedExternalState):
            _map("thehive", word)

    @pytest.mark.parametrize("word", ["success", "completed", "ok", "done"])
    def test_mock_every_state_rejected(self, word):
        # §13.11: Mock has no external system by design — no callback semantics.
        with pytest.raises(UnrecognizedExternalState):
            _map("mock", word)

    def test_shuffle_mapping_payload_rejected(self):
        # A Shuffle Mapping external_state has no evidenced state_key -> refused.
        with pytest.raises(UnrecognizedExternalState):
            _map("shuffle", {"external_execution_id": "abc123", "success": True})

    def test_anti_fabrication_shuffle_success_not_widened(self, fake_adapter_vocab):
        # §21 (THE biggest risk): a Shuffle 'success' MUST be refused — D never
        # adds success -> confirmed_success to make a demo pass — while an adapter
        # with an EVIDENCED 'success' (the test-only fake double, since the real
        # Wazuh set is now empty) is confirmed. Same word, adapter evidence decides.
        with pytest.raises(UnrecognizedExternalState):
            _map("shuffle", "success")
        assert _map(fake_adapter_vocab, "success").outcome_status == "confirmed_success"


# ---------------------------------------------------------------------------
# §13.12 / §13.13 / §13.14 + §5 — Dispatch ≠ External Outcome
# ---------------------------------------------------------------------------
class TestDispatchOutcomeIsolation:
    def test_succeeded_never_becomes_confirmed_success(self):
        # §13.12 / §5: the DISPATCH word 'succeeded' is not an external state.
        # Wazuh's evidenced success word is 'success', never 'succeeded'.
        with pytest.raises(UnrecognizedExternalState):
            _map("wazuh", "succeeded")

    def test_failed_never_becomes_confirmed_failure(self):
        # §13.13 / §5
        with pytest.raises(UnrecognizedExternalState):
            _map("wazuh", "failed")

    @pytest.mark.parametrize("adapter", ["wazuh", "shuffle", "thehive", "mock"])
    @pytest.mark.parametrize("dispatch_word", sorted(DISPATCH_STATUSES))
    def test_no_dispatch_word_maps_to_any_outcome(self, adapter, dispatch_word):
        # §13.14: the dispatch vocabulary {succeeded, failed} never produces an
        # outcome word for ANY adapter (D3.4-04 vocabulary isolation).
        with pytest.raises(UnrecognizedExternalState):
            _map(adapter, dispatch_word)

    def test_dispatch_and_outcome_vocabularies_are_disjoint(self):
        # §5 / §13.14: the two frozen vocabularies share no word.
        assert DISPATCH_STATUSES.isdisjoint(OUTCOME_STATUSES)
        assert DISPATCH_STATUSES == {"succeeded", "failed"}


# ---------------------------------------------------------------------------
# §13.15 / §13.16 / §13.17 + §6 / §7 — unknown vs rejected vs reconciliation_failed
# ---------------------------------------------------------------------------
class TestUnknownVsRejected:
    def test_15_unrecognized_state_raises(self):
        # §13.15: an unregistered state -> UnrecognizedExternalState.
        with pytest.raises(UnrecognizedExternalState):
            _map("wazuh", "banana")

    def test_unrecognized_is_a_contract_validation_failure(self):
        # §12: the refusal stays in the frozen ContractValidationFailure family.
        assert issubclass(UnrecognizedExternalState, ContractValidationFailure)

    def test_16_rejected_never_becomes_unknown(self, fake_adapter_vocab):
        # §13.16 / §7: a refusal is an EXCEPTION, never an 'unknown' mapping.
        with pytest.raises(UnrecognizedExternalState) as excinfo:
            _map("wazuh", "banana")
        assert not isinstance(excinfo.value, StateMapping)
        # contrast: a RECOGNIZED-ambiguous state IS a legit 'unknown' mapping (on
        # the test-only fake double — the real Wazuh 'unknown' is now refused).
        assert _map(fake_adapter_vocab, "unknown").outcome_status == "unknown"

    def test_17_rejected_never_becomes_reconciliation_failed(self):
        # §13.17 / §6: a refusal is never the read-failure verdict.
        with pytest.raises(UnrecognizedExternalState):
            _map("wazuh", "banana")

    def test_state_mapping_structurally_refuses_reconciliation_failed(self):
        # §6: StateMapping.__post_init__ rejects reconciliation_failed, so this
        # gate CANNOT emit it even if a vocabulary branch tried.
        with pytest.raises(ValueError):
            StateMapping(
                adapter="wazuh",
                outcome_status="reconciliation_failed",
                observed_state="x",
                normalized_state="x",
                mapping_reason="x",
            )

    def test_reconciliation_failed_is_not_a_mappable_word(self):
        # §6: the read-failure verdict is excluded from the mappable set.
        assert "reconciliation_failed" in OUTCOME_STATUSES
        assert "reconciliation_failed" not in MAPPABLE_OUTCOME_STATUSES


# ---------------------------------------------------------------------------
# §13.18 / §13.19 / §13.20 + §10 / §11 — determinism, purity, immutability
# ---------------------------------------------------------------------------
class TestDeterminismPurityImmutability:
    def test_18_repeated_mapping_is_deterministic(self, fake_adapter_vocab):
        # §13.18: the same input always yields the same result.
        assert _map(fake_adapter_vocab, "completed") == _map(fake_adapter_vocab, "completed")
        assert _map(fake_adapter_vocab, "completed").outcome_status == "confirmed_success"

    def test_18_repeated_rejection_is_deterministic(self):
        # §13.18: the same unrecognized input always refuses the same way.
        for _ in range(3):
            with pytest.raises(UnrecognizedExternalState):
                _map("shuffle", "success")

    def test_19_string_external_state_unchanged(self, fake_adapter_vocab):
        # §13.19 / §10: D never mutates the observation's external_state.
        observation = _validated(fake_adapter_vocab, "SUCCESS")
        map_external_state(observation)
        assert observation.external_state == "SUCCESS"

    def test_19_mapping_external_state_unchanged(self, fake_adapter_vocab):
        # §13.19 / §10: a Mapping external_state is not rewritten (keys/values).
        payload = {"agent_status": "completed", "extra": "KeepMe"}
        observation = _validated(fake_adapter_vocab, dict(payload))
        map_external_state(observation)
        assert observation.external_state == payload

    def test_20_returned_mapping_is_immutable(self, fake_adapter_vocab):
        # §13.20 / §11: StateMapping is frozen — the result cannot be tampered.
        result = _map(fake_adapter_vocab, "completed")
        with pytest.raises(Exception):
            result.outcome_status = "unknown"  # type: ignore[misc]
        assert result.outcome_status == "confirmed_success"

    def test_returns_state_mapping_not_orm(self, fake_adapter_vocab):
        # §11: the result is the reused immutable StateMapping, never an ORM row.
        result = _map(fake_adapter_vocab, "completed")
        assert type(result) is StateMapping
        assert not hasattr(result, "__table__")


# ---------------------------------------------------------------------------
# §3 / §16 — reuse 3.4.3-B, reimplement nothing
# ---------------------------------------------------------------------------
class TestReuseNotReimplement:
    def test_delegates_to_normalize_external_state(self):
        # §3: the ONLY mapping source is 3.4.3-B's normalize_external_state.
        _, names, _, _ = _imported_mapping()
        assert "normalize_external_state" in names
        assert "normalize_external_state" in _called_names()

    def test_body_is_a_single_delegated_return(self):
        # §3: D reimplements NO mapping logic — the body is ONE return that calls
        # normalize_external_state, with no if/elif vocabulary branch (AST,
        # docstring-immune; the docstring legitimately mentions 'if/elif').
        tree = ast.parse(inspect.getsource(mapping_module))
        fn = next(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == "map_external_state"
        )
        body = fn.body
        # the docstring is itself an Expr statement — skip it, then the body
        # must be exactly ONE delegated Return (no vocabulary branch of its own).
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        assert len(body) == 1
        assert isinstance(body[0], ast.Return)
        assert not any(isinstance(n, ast.If) for n in ast.walk(fn))
        call = body[0].value
        assert isinstance(call, ast.Call)
        assert isinstance(call.func, ast.Name)
        assert call.func.id == "normalize_external_state"

    def test_defines_no_vocabulary_table_or_second_dto(self):
        # §3 / §11 / §16: D adds no mapping table and no second mapping DTO.
        _, _, funcs, classes = _imported_mapping()
        assert funcs == {"map_external_state"}
        assert classes == set()

    def test_reuses_the_reconciliation_state_mapping_dto(self):
        # §11: StateMapping is 3.4.3-B's, imported — not redefined here.
        _, names, _, classes = _imported_mapping()
        assert "StateMapping" in names
        assert classes == set()
        assert StateMapping.__module__ == "app.services.outcomes.reconciliation"

    def test_does_not_revalidate_input(self):
        # §8: D assumes validate_observation already ran; it re-validates nothing.
        _, names, _, _ = _imported_mapping()
        assert "validate_observation" not in names
        assert "ExternalObservation" not in names


# ---------------------------------------------------------------------------
# §9 — the adapter is the trusted identity, never client-supplied
# ---------------------------------------------------------------------------
class TestTrustedAdapter:
    def test_signature_takes_only_the_observation(self):
        # §9: map_external_state(observation) — there is no separate adapter
        # parameter a caller could feed a client-supplied value into.
        params = list(inspect.signature(map_external_state).parameters)
        assert params == ["observation"]

    def test_adapter_is_read_from_the_validated_observation(self, fake_adapter_vocab):
        # §9: the adapter used is observation.adapter (the trusted Gate-1 identity).
        observation = _validated(fake_adapter_vocab, "completed")
        result = map_external_state(observation)
        assert result.adapter == observation.adapter == fake_adapter_vocab

    def test_same_state_maps_by_trusted_adapter(self, fake_adapter_vocab):
        # §9 / §21: the SAME external_state maps differently by trusted adapter —
        # 'completed' is confirmed for an adapter with an evidenced vocabulary (the
        # test-only fake double) but refused for Shuffle AND for the real Wazuh
        # (whose set is now empty). A client cannot pick a lenient adapter to
        # smuggle a confirmed_success.
        assert _map(fake_adapter_vocab, "completed").outcome_status == "confirmed_success"
        with pytest.raises(UnrecognizedExternalState):
            _map("shuffle", "completed")
        with pytest.raises(UnrecognizedExternalState):
            _map("wazuh", "completed")


# ---------------------------------------------------------------------------
# §14 — no database (structural, AST)
# ---------------------------------------------------------------------------
class TestNoDatabase:
    def test_no_sqlalchemy_or_session(self):
        modules, names, _, _ = _imported_mapping()
        assert not any("sqlalchemy" in m for m in modules)
        assert "Session" not in names
        assert "select" not in names

    def test_no_orm_or_repository(self):
        modules, names, _, _ = _imported_mapping()
        assert "ExecutionOutcome" not in names
        assert not any("execution_outcome" in m for m in modules)
        assert not any("repository" in m for m in modules)

    def test_no_write_verb_is_called(self):
        # §14: no commit / flush / add / delete / update / execute / rollback is
        # CALLED (AST — the docstring names these as things D does NOT do).
        called = _called_names()
        for verb in (
            "commit",
            "flush",
            "add",
            "delete",
            "update",
            "execute",
            "rollback",
        ):
            assert verb not in called
        assert called == {"normalize_external_state"}


# ---------------------------------------------------------------------------
# §15 — no execution capability (structural, AST)
# ---------------------------------------------------------------------------
class TestNoExecution:
    def test_no_executor_or_execution_service(self):
        modules, _, funcs, _ = _imported_mapping()
        assert not any("app.services.executions" in m for m in modules)
        assert not any("executor" in m.lower() for m in modules)
        assert not any("response_execution" in m for m in modules)
        assert funcs == {"map_external_state"}

    def test_no_adapter_client_io(self):
        modules, _, _, _ = _imported_mapping()
        assert not any("adapter" in m.lower() for m in modules)
        assert not any("app.integrations" in m for m in modules)
        assert "requests" not in modules
        assert "httpx" not in modules

    def test_no_execute_retry_compensate_functions(self):
        _, _, funcs, _ = _imported_mapping()
        for verb in ("execute", "retry", "compensate"):
            assert not any(verb in f.lower() for f in funcs)


# ---------------------------------------------------------------------------
# §14 / §15 / §20 — the exact AST import boundary
# ---------------------------------------------------------------------------
class TestImportBoundary:
    def test_modules_are_an_exact_allowlist(self):
        modules, _, _, _ = _imported_mapping()
        assert modules == ALLOWED_MODULES

    def test_imported_names_are_an_exact_allowlist(self):
        _, names, _, _ = _imported_mapping()
        assert names == ALLOWED_NAMES

    def test_funcs_and_classes(self):
        _, _, funcs, classes = _imported_mapping()
        assert funcs == {"map_external_state"}
        assert classes == set()

    def test_20_no_fastapi_import(self):
        # §20: the domain layer never imports FastAPI / raises HTTPException;
        # UnrecognizedExternalState propagates as a pure domain exception.
        modules, names, _, _ = _imported_mapping()
        assert not any(m.startswith("fastapi") for m in modules)
        assert "HTTPException" not in names

    def test_no_forbidden_modules(self):
        modules, _, _, _ = _imported_mapping()
        for module in modules:
            for fragment in FORBIDDEN_MODULE_FRAGMENTS:
                assert fragment not in module, f"{module} must not import {fragment}"
