"""Reconciliation Contract — Phase 3.4.3-A专项: Contract Types + Validation.

This suite proves the INPUT layer of the frozen Reconciliation Contract
(docs/design/phase3.4-reconciliation-contract.md, Design Freeze ``a125f1e``):
``ExternalObservation`` -> validation -> ``NormalizedObservation`` (or a
rejection). It is deliberately DB-free — ``validate_observation`` is a PURE
function (the discipline of tests/test_outcome_derivation.py), so lightweight
inputs prove the whole contract without a session.

Requirement map (user section 十一, 1-20):
   1 valid observation ................ TestValidObservation
   2 all required fields .............. TestContractShape
   3 missing execution_id ............. TestRequiredFieldRejection
   4 missing adapter .................. TestRequiredFieldRejection
   5 missing external_reference ....... TestRequiredFieldRejection
   6 missing external_state ........... TestRequiredFieldRejection
   7 missing observed_at .............. TestRequiredFieldRejection
   8 missing source ................... TestRequiredFieldRejection
   9 invalid source ................... TestRequiredFieldRejection
  10 naive datetime rejected .......... TestObservedAtSemantics
  11 aware datetime accepted .......... TestObservedAtSemantics
  12 timezone normalized to UTC ....... TestObservedAtSemantics
  13 invalid timestamp rejected ....... TestObservedAtSemantics
  14 future timestamp boundary ........ TestObservedAtSemantics
  15 excessive future rejected ........ TestObservedAtSemantics
  16 input immutability ............... TestPurityImmutabilityDeterminism
  17 repeated validation deterministic  TestPurityImmutabilityDeterminism
  18 webhook identity shape ........... TestIdentityTrustDomains
  19 manual_reconcile identity shape .. TestIdentityTrustDomains
  20 dispatch words cannot become
     outcome state .................... TestDispatchOutcomeIsolation

The soul of 3.4.3-A (design §0 / §13): a Contract Validation Failure means
NO Outcome Fact — missing reference is NEVER ``reconciliation_failed`` and an
unrecognized state is NEVER ``unknown``. And this layer STRUCTURALLY cannot
emit an outcome word: ``NormalizedObservation`` has no ``outcome_status``
field and the module never imports the outcome vocabulary (that mapping is
3.4.3-B). Several tests below nail exactly that.
"""
import ast
import inspect
import uuid
from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timedelta, timezone, tzinfo

import pytest

from app.models import EXECUTION_DECISIONS, OUTCOME_SOURCES, OUTCOME_STATUSES
from app.services.executions.models import (
    FAILURE_CLASSIFICATIONS,
    OUTCOME_STATUSES as DISPATCH_TERMINAL_STATUSES,
)
from app.services.executions.registry import ADAPTER_NAMES
from app.services.outcomes.reconciliation import (
    CONTRACT_FIELDS,
    MAX_FUTURE_SKEW,
    SOURCE_TRUST_DOMAIN,
    TRUST_DOMAIN_ADAPTER_CALLBACK,
    TRUST_DOMAIN_HUMAN_OPERATOR,
    ContractValidationFailure,
    ExternalObservation,
    InvalidObservedAt,
    InvalidSource,
    MissingExecutionId,
    MissingExternalReference,
    MissingExternalState,
    NormalizedObservation,
    UnknownAdapter,
    trust_domain_for,
    validate_observation,
)

# A FIXED reference clock. Every validation injects now=NOW so the bounded
# future check is deterministic and never depends on the real system time.
NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)

# The dispatch-layer vocabulary: the eight execution_log.decision words, the
# adapter terminal statuses {succeeded, failed}, and the failure
# classifications. NONE may ever become an outcome state (D3.4-04 / RC-06).
# Note the deliberate name collision: app.services.executions.models also
# calls {succeeded, failed} "OUTCOME_STATUSES" — imported here aliased to
# DISPATCH_TERMINAL_STATUSES to keep the two vocabularies visibly apart.
DISPATCH_WORDS = sorted(
    set(EXECUTION_DECISIONS)
    | set(DISPATCH_TERMINAL_STATUSES)
    | set(FAILURE_CLASSIFICATIONS)
)


def valid_observation(**overrides):
    """A well-formed ExternalObservation. Override any field to drive one
    specific rejection. Defaults are all valid: an aware UTC observed_at at
    NOW, a known adapter, a present reference, a raw external_state, and the
    webhook source."""
    kwargs = dict(
        execution_id=uuid.uuid4(),
        adapter="shuffle",
        external_reference="wf-exec-0001",
        external_state="in_progress",
        observed_at=NOW,
        source="webhook",
    )
    kwargs.update(overrides)
    return ExternalObservation(**kwargs)


def validate(obs, *, now=NOW):
    """Validate against the FIXED reference clock (deterministic future
    bound)."""
    return validate_observation(obs, now=now)


def _imported():
    """AST view of reconciliation.py's OWN imports + defined functions — the
    robust structural proof, immune to docstring mentions (unlike a fragile
    source-text scan)."""
    import app.services.outcomes.reconciliation as mod

    tree = ast.parse(inspect.getsource(mod))
    modules, names, funcs = set(), set(), set()
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
    return mod, modules, names, funcs


class _NullOffsetTz(tzinfo):
    """A tzinfo whose utcoffset is None — 'aware' in name only, naive in
    semantics. The contract's second naive-clause must catch it (§10.2)."""

    def utcoffset(self, dt):
        return None

    def dst(self, dt):
        return None

    def tzname(self, dt):
        return "NULL"


# ---------------------------------------------------------------------------
# Contract shape (requirement 2)
# ---------------------------------------------------------------------------


class TestContractShape:
    def test_contract_fields_are_the_six_frozen_names(self):
        # requirement 2 / RC-02: exactly the six frozen fields, in order.
        assert CONTRACT_FIELDS == (
            "execution_id",
            "adapter",
            "external_reference",
            "external_state",
            "observed_at",
            "source",
        )
        assert len(CONTRACT_FIELDS) == 6

    def test_external_observation_field_names_match_contract(self):
        assert tuple(f.name for f in fields(ExternalObservation)) == CONTRACT_FIELDS

    def test_external_observation_is_frozen(self):
        obs = valid_observation()
        with pytest.raises(FrozenInstanceError):
            obs.adapter = "wazuh"

    def test_normalized_observation_has_no_outcome_status_field(self):
        # The structural heart of 3.4.3-A: the output type has nowhere to put
        # an outcome word, so this layer cannot emit one (that is 3.4.3-B).
        assert "outcome_status" not in {f.name for f in fields(NormalizedObservation)}

    def test_normalized_observation_carries_the_seven_expected_fields(self):
        # six contract fields + trust_domain (identity shape), NO status.
        assert tuple(f.name for f in fields(NormalizedObservation)) == (
            "execution_id",
            "adapter",
            "external_reference",
            "external_state",
            "observed_at",
            "source",
            "trust_domain",
        )


# ---------------------------------------------------------------------------
# Valid observation (requirements 1, 11)
# ---------------------------------------------------------------------------


class TestValidObservation:
    def test_valid_webhook_observation_normalizes(self):
        # requirement 1: a fully valid observation yields a normalized one.
        eid = uuid.uuid4()
        obs = valid_observation(execution_id=eid, external_reference="ref-9")
        normalized = validate(obs)
        assert isinstance(normalized, NormalizedObservation)
        assert normalized.execution_id == eid
        assert normalized.adapter == "shuffle"
        assert normalized.external_reference == "ref-9"
        assert normalized.external_state == "in_progress"
        assert normalized.observed_at == NOW
        assert normalized.source == "webhook"
        assert normalized.trust_domain == TRUST_DOMAIN_ADAPTER_CALLBACK

    def test_valid_manual_reconcile_observation_normalizes(self):
        normalized = validate(valid_observation(source="manual_reconcile"))
        assert normalized.source == "manual_reconcile"
        assert normalized.trust_domain == TRUST_DOMAIN_HUMAN_OPERATOR

    @pytest.mark.parametrize("adapter", sorted(ADAPTER_NAMES))
    def test_every_known_adapter_is_accepted(self, adapter):
        # single source: the adapter identity vocabulary is registry's.
        normalized = validate(valid_observation(adapter=adapter))
        assert normalized.adapter == adapter

    @pytest.mark.parametrize("source", sorted(OUTCOME_SOURCES))
    def test_every_frozen_source_is_accepted(self, source):
        normalized = validate(valid_observation(source=source))
        assert normalized.source == source


# ---------------------------------------------------------------------------
# Required-field + invalid-value rejection (requirements 3-9)
# ---------------------------------------------------------------------------


class TestRequiredFieldRejection:
    def test_missing_execution_id_rejected(self):
        # requirement 3
        with pytest.raises(MissingExecutionId):
            validate(valid_observation(execution_id=None))

    def test_non_uuid_execution_id_rejected(self):
        # a string is not a UUID: the contract type is UUID, fail-closed.
        with pytest.raises(MissingExecutionId):
            validate(valid_observation(execution_id="not-a-uuid"))

    def test_missing_adapter_rejected(self):
        # requirement 4
        with pytest.raises(UnknownAdapter) as exc:
            validate(valid_observation(adapter=None))
        assert exc.value.adapter is None

    @pytest.mark.parametrize(
        "bad", ["splunk", "SHUFFLE", "Shuffle", "", "   ", "mock,shuffle"]
    )
    def test_unknown_adapter_rejected(self, bad):
        # unknown identity, case variants (no case folding), blank, and a
        # multi-value are all refused.
        with pytest.raises(UnknownAdapter):
            validate(valid_observation(adapter=bad))

    def test_unknown_adapter_carries_offending_value(self):
        with pytest.raises(UnknownAdapter) as exc:
            validate(valid_observation(adapter="splunk"))
        assert exc.value.adapter == "splunk"

    @pytest.mark.parametrize("bad", [None, "", "   ", "\t\n"])
    def test_missing_external_reference_rejected(self, bad):
        # requirement 5 / RC-05: absent or blank -> rejection (never a fact).
        with pytest.raises(MissingExternalReference):
            validate(valid_observation(external_reference=bad))

    @pytest.mark.parametrize("bad", [None, "", "   ", {}, 123, ["x"], object()])
    def test_missing_external_state_rejected(self, bad):
        # requirement 6: absent / blank str / empty mapping / wrong type.
        with pytest.raises(MissingExternalState):
            validate(valid_observation(external_state=bad))

    def test_missing_observed_at_rejected(self):
        # requirement 7: None is not a datetime.
        with pytest.raises(InvalidObservedAt):
            validate(valid_observation(observed_at=None))

    def test_missing_source_rejected(self):
        # requirement 8
        with pytest.raises(InvalidSource) as exc:
            validate(valid_observation(source=None))
        assert exc.value.source is None

    @pytest.mark.parametrize(
        "bad", ["polling", "scheduler", "callback", "WEBHOOK", "Webhook", "", "reconcile"]
    )
    def test_invalid_source_rejected(self, bad):
        # requirement 9: no third channel; case variants refused (no fold).
        with pytest.raises(InvalidSource):
            validate(valid_observation(source=bad))

    def test_invalid_source_carries_offending_value(self):
        with pytest.raises(InvalidSource) as exc:
            validate(valid_observation(source="polling"))
        assert exc.value.source == "polling"

    @pytest.mark.parametrize(
        "exc_type",
        [
            MissingExecutionId,
            UnknownAdapter,
            MissingExternalReference,
            MissingExternalState,
            InvalidObservedAt,
            InvalidSource,
        ],
    )
    def test_every_rejection_is_a_contract_validation_failure(self, exc_type):
        # design §13: all rejections share one base -> one refusal semantic.
        assert issubclass(exc_type, ContractValidationFailure)
        assert issubclass(ContractValidationFailure, Exception)


# ---------------------------------------------------------------------------
# observed_at semantics (requirements 10-15, design §10 / RC-09)
# ---------------------------------------------------------------------------


class TestObservedAtSemantics:
    def test_naive_datetime_rejected(self):
        # requirement 10: a naive datetime is ambiguous -> refused (§10.2).
        naive = datetime(2026, 9, 3, 12, 0, 0)  # no tzinfo
        with pytest.raises(InvalidObservedAt):
            validate(valid_observation(observed_at=naive))

    def test_null_offset_tzinfo_rejected(self):
        # 'aware' in name only (utcoffset is None) is still naive semantically.
        pseudo_aware = datetime(2026, 9, 3, 12, 0, 0, tzinfo=_NullOffsetTz())
        with pytest.raises(InvalidObservedAt):
            validate(valid_observation(observed_at=pseudo_aware))

    def test_aware_datetime_accepted(self):
        # requirement 11
        normalized = validate(valid_observation(observed_at=NOW))
        assert normalized.observed_at == NOW
        assert normalized.observed_at.tzinfo == timezone.utc

    def test_timezone_normalized_to_utc(self):
        # requirement 12: 14:00 at +02:00 is 12:00Z — same instant, UTC repr.
        plus_two = timezone(timedelta(hours=2))
        local = datetime(2026, 9, 3, 14, 0, 0, tzinfo=plus_two)
        normalized = validate(valid_observation(observed_at=local))
        assert normalized.observed_at == NOW
        assert normalized.observed_at.tzinfo == timezone.utc
        assert normalized.observed_at.utcoffset() == timedelta(0)
        assert normalized.observed_at.hour == 12

    def test_utc_normalization_preserves_the_instant(self):
        # a negative offset: 07:00-05:00 == 12:00Z == NOW. Normalization
        # changes representation only, never the moment (§10.3).
        minus_five = timezone(timedelta(hours=-5))
        local = datetime(2026, 9, 3, 7, 0, 0, tzinfo=minus_five)
        normalized = validate(valid_observation(observed_at=local))
        assert normalized.observed_at == NOW
        assert normalized.observed_at.timestamp() == NOW.timestamp()

    def test_precision_preserved_not_truncated(self):
        # §10.6: microseconds survive; ties are broken downstream by id DESC,
        # so the contract manufactures no fake precision.
        micro = NOW.replace(microsecond=123456)
        normalized = validate(valid_observation(observed_at=micro))
        assert normalized.observed_at.microsecond == 123456

    @pytest.mark.parametrize(
        "bad",
        [
            "2026-09-03T12:00:00Z",  # an ISO string is NOT a datetime
            "not-a-timestamp",
            1756900800,  # epoch int
            1756900800.0,  # epoch float
            object(),
        ],
    )
    def test_invalid_timestamp_rejected(self, bad):
        # requirement 13: a non-datetime is refused (no string parsing here).
        with pytest.raises(InvalidObservedAt):
            validate(valid_observation(observed_at=bad))

    def test_future_skew_constant_is_named_and_300s(self):
        # §八: the tolerance is a NAMED, CENTRAL, TESTED constant, never a
        # scattered magic number; its frozen default (design §10.5) is 300s.
        assert MAX_FUTURE_SKEW == timedelta(seconds=300)
        assert MAX_FUTURE_SKEW.total_seconds() == 300

    def test_future_boundary_is_inclusive_and_accepted(self):
        # requirement 14: exactly now + MAX_FUTURE_SKEW is accepted.
        at_bound = NOW + MAX_FUTURE_SKEW
        normalized = validate(valid_observation(observed_at=at_bound))
        assert normalized.observed_at == at_bound

    def test_excessive_future_rejected(self):
        # requirement 15: one second beyond the bound is refused.
        over = NOW + MAX_FUTURE_SKEW + timedelta(seconds=1)
        with pytest.raises(InvalidObservedAt):
            validate(valid_observation(observed_at=over))

    def test_far_future_rejected(self):
        with pytest.raises(InvalidObservedAt):
            validate(valid_observation(observed_at=NOW + timedelta(days=1)))

    def test_past_timestamp_accepted_no_lower_bound(self):
        # Only the FUTURE bound is safety-critical (a future fact would
        # suppress real observations under observed_at DESC). An old-but-aware
        # timestamp is a legitimate fact — no unjustified lower bound.
        old = NOW - timedelta(days=365)
        normalized = validate(valid_observation(observed_at=old))
        assert normalized.observed_at == old


# ---------------------------------------------------------------------------
# Normalization strategy (trimming vs raw preservation)
# ---------------------------------------------------------------------------


class TestNormalizationStrategy:
    def test_adapter_is_trimmed(self):
        normalized = validate(valid_observation(adapter="  wazuh  "))
        assert normalized.adapter == "wazuh"

    def test_source_is_trimmed(self):
        normalized = validate(valid_observation(source="  webhook  "))
        assert normalized.source == "webhook"
        assert normalized.trust_domain == TRUST_DOMAIN_ADAPTER_CALLBACK

    def test_external_reference_is_trimmed_and_stored_trimmed(self):
        normalized = validate(valid_observation(external_reference="  ref-42  "))
        assert normalized.external_reference == "ref-42"

    def test_external_state_is_preserved_raw_not_trimmed(self):
        # external_state is the external system's PRIVATE data; the contract
        # must not alter it (interpretation is 3.4.3-B). Whitespace feeds the
        # blank check only, never the stored value.
        normalized = validate(valid_observation(external_state="  SUCCESS  "))
        assert normalized.external_state == "  SUCCESS  "

    def test_mapping_external_state_preserved_raw(self):
        payload = {"status": "complete", "code": 200}
        normalized = validate(valid_observation(external_state=payload))
        assert normalized.external_state == payload


# ---------------------------------------------------------------------------
# Purity, immutability, determinism (requirements 16, 17)
# ---------------------------------------------------------------------------


class TestPurityImmutabilityDeterminism:
    def test_input_is_immutable(self):
        # requirement 16: the frozen input cannot be tampered with.
        obs = valid_observation()
        with pytest.raises(FrozenInstanceError):
            obs.external_state = "tampered"
        with pytest.raises(FrozenInstanceError):
            obs.observed_at = NOW + timedelta(days=1)

    def test_validation_does_not_mutate_its_input(self):
        # requirement 16: normalization writes to a NEW object; the input
        # keeps its raw (untrimmed) reference while the output is trimmed.
        obs = valid_observation(external_reference="  ref-1  ")
        normalized = validate(obs)
        assert obs.external_reference == "  ref-1  "  # input untouched
        assert normalized.external_reference == "ref-1"  # output normalized

    def test_output_is_immutable_and_cannot_gain_a_status(self):
        # The frozen output cannot be mutated — and cannot even be given an
        # outcome_status attribute (a second isolation guarantee).
        normalized = validate(valid_observation())
        with pytest.raises(FrozenInstanceError):
            normalized.adapter = "wazuh"
        with pytest.raises(FrozenInstanceError):
            normalized.outcome_status = "confirmed_success"

    def test_repeated_validation_is_deterministic(self):
        # requirement 17: same input -> equal output, every time.
        obs = valid_observation()
        first = validate(obs)
        second = validate(obs)
        third = validate(obs)
        assert first == second == third

    @pytest.mark.parametrize(
        "overrides,exc",
        [
            ({"execution_id": None}, MissingExecutionId),
            ({"adapter": "splunk"}, UnknownAdapter),
            ({"external_reference": ""}, MissingExternalReference),
            ({"external_state": None}, MissingExternalState),
            ({"observed_at": None}, InvalidObservedAt),
            ({"source": "polling"}, InvalidSource),
        ],
    )
    def test_repeated_rejection_is_deterministic(self, overrides, exc):
        # requirement 17: the same broken input raises the same exception.
        obs = valid_observation(**overrides)
        for _ in range(3):
            with pytest.raises(exc):
                validate(obs)

    def test_validation_is_fail_fast_in_contract_field_order(self):
        # Deterministic order: with several fields broken, the earliest in
        # CONTRACT_FIELDS order (execution_id < adapter < ... < source) wins.
        with pytest.raises(MissingExecutionId):
            validate(
                valid_observation(execution_id=None, adapter="splunk", source="polling")
            )
        with pytest.raises(UnknownAdapter):
            validate(valid_observation(adapter="splunk", source="polling"))

    def test_validation_signature_takes_no_database(self):
        # Structural purity: the only parameters are the observation and the
        # injectable reference clock — no session, no repository, no db.
        sig = inspect.signature(validate_observation)
        assert set(sig.parameters) == {"observation", "now"}
        assert sig.parameters["now"].kind is inspect.Parameter.KEYWORD_ONLY


# ---------------------------------------------------------------------------
# Identity trust domains (requirements 18, 19, design §8 / RC-07)
# ---------------------------------------------------------------------------


class TestIdentityTrustDomains:
    def test_webhook_identity_is_adapter_callback_domain(self):
        # requirement 18: webhook -> adapter callback identity shape.
        normalized = validate(valid_observation(source="webhook"))
        assert normalized.trust_domain == TRUST_DOMAIN_ADAPTER_CALLBACK
        assert normalized.trust_domain == "adapter_callback"

    def test_manual_reconcile_identity_is_human_operator_domain(self):
        # requirement 19: manual_reconcile -> authenticated operator shape.
        normalized = validate(valid_observation(source="manual_reconcile"))
        assert normalized.trust_domain == TRUST_DOMAIN_HUMAN_OPERATOR
        assert normalized.trust_domain == "human_operator"

    def test_two_trust_domains_never_merge(self):
        # The SHAPE separation (D3.4-07): the two domains are distinct values.
        # Credential non-reuse is ENFORCED in 3.4.4 (auth is not implemented
        # here) — this layer only fixes the distinguishable shape.
        assert TRUST_DOMAIN_ADAPTER_CALLBACK != TRUST_DOMAIN_HUMAN_OPERATOR
        webhook = validate(valid_observation(source="webhook"))
        manual = validate(valid_observation(source="manual_reconcile"))
        assert webhook.trust_domain != manual.trust_domain

    def test_trust_domain_for_lookup(self):
        assert trust_domain_for("webhook") == TRUST_DOMAIN_ADAPTER_CALLBACK
        assert trust_domain_for("manual_reconcile") == TRUST_DOMAIN_HUMAN_OPERATOR

    def test_source_trust_domain_keys_are_exactly_the_frozen_sources(self):
        # single source: the map's keys are exactly OUTCOME_SOURCES, no third.
        assert set(SOURCE_TRUST_DOMAIN) == set(OUTCOME_SOURCES)
        assert set(SOURCE_TRUST_DOMAIN) == {"webhook", "manual_reconcile"}

    def test_trust_domain_for_unknown_source_is_a_caller_bug(self):
        # validate_observation rejects an unknown source first; asking for its
        # domain directly is a programming error, surfaced as KeyError.
        with pytest.raises(KeyError):
            trust_domain_for("polling")


# ---------------------------------------------------------------------------
# Dispatch / Outcome vocabulary isolation (requirement 20, D3.4-04 / RC-06)
# ---------------------------------------------------------------------------


class TestDispatchOutcomeIsolation:
    @pytest.mark.parametrize("word", DISPATCH_WORDS)
    def test_no_dispatch_word_is_an_outcome_status(self, word):
        # requirement 20 (vocabulary): none of the dispatch words is one of
        # the five outcome words.
        assert word not in OUTCOME_STATUSES

    def test_dispatch_and_outcome_vocabularies_are_disjoint(self):
        assert OUTCOME_STATUSES.isdisjoint(set(DISPATCH_WORDS))

    @pytest.mark.parametrize("word", DISPATCH_WORDS)
    def test_dispatch_word_as_external_state_is_preserved_not_mapped(self, word):
        # requirement 20 (behavior): a dispatch word smuggled in as
        # external_state stays RAW; this layer has no outcome_status to hold a
        # mapped word, so it can never become one (mapping is 3.4.3-B).
        normalized = validate(valid_observation(external_state=word))
        assert normalized.external_state == word
        assert not hasattr(normalized, "outcome_status")

    @pytest.mark.parametrize(
        "dispatch_word,forbidden_outcome",
        [("succeeded", "confirmed_success"), ("failed", "confirmed_failure")],
    )
    def test_succeeded_failed_never_become_confirmed(self, dispatch_word, forbidden_outcome):
        # §九 explicit: this step must NOT turn succeeded/failed into
        # confirmed_success/confirmed_failure. There is no mapping here.
        normalized = validate(valid_observation(external_state=dispatch_word))
        assert normalized.external_state == dispatch_word  # raw, unmapped
        assert not hasattr(normalized, "outcome_status")
        assert forbidden_outcome not in {"outcome_status"}

    def test_module_import_surface_is_exactly_the_contract_dependencies(self):
        # The strongest structural proof: pin the ENTIRE import surface. No
        # DB, no HTTP, no dispatch log, no outcome-status vocabulary, no
        # secrets/auth. Adding any of those (e.g. a 3.4.3-B mapping import)
        # must fail here loudly and be updated deliberately.
        _mod, modules, names, funcs = _imported()
        assert modules == {
            "__future__",
            "uuid",
            "collections.abc",
            "dataclasses",
            "datetime",
            "app.models.execution_outcome",
            "app.services.executions.registry",
        }
        # Imports the ingress + adapter vocabularies, NEVER the outcome one.
        assert "OUTCOME_SOURCES" in names
        assert "ADAPTER_NAMES" in names
        assert "OUTCOME_STATUSES" not in names
        # No state-mapping function exists yet (that is 3.4.3-B).
        assert "validate_observation" in funcs
        assert "trust_domain_for" in funcs
        assert "normalize_external_state" not in funcs

    def test_module_defines_no_mapping_function(self):
        mod, _modules, _names, _funcs = _imported()
        assert not hasattr(mod, "normalize_external_state")
        assert not hasattr(mod, "map_external_state")
        assert not hasattr(mod, "to_outcome_status")


# ---------------------------------------------------------------------------
# Rejection produces NO fact (design §0 / §7 / §13 — the soul of 3.4.3-A)
# ---------------------------------------------------------------------------


class TestRejectionProducesNoFact:
    def test_missing_reference_is_not_reconciliation_failed(self):
        # RC-05: a missing external_reference is a REJECTION (raises), never a
        # reconciliation_failed fact — there is no fact at all.
        with pytest.raises(ContractValidationFailure):
            validate(valid_observation(external_reference=None))
        assert "outcome_status" not in {f.name for f in fields(NormalizedObservation)}

    def test_rejection_returns_nothing_but_raises(self):
        # Every refusal path raises rather than returning a partial/None
        # observation — the caller cannot mistake a rejection for a fact.
        for overrides in (
            {"execution_id": None},
            {"adapter": "splunk"},
            {"external_reference": ""},
            {"external_state": None},
            {"observed_at": None},
            {"source": "polling"},
        ):
            with pytest.raises(ContractValidationFailure):
                validate(valid_observation(**overrides))

    def test_valid_input_is_the_only_path_to_a_normalized_observation(self):
        # Positive control: only a fully valid observation produces output.
        normalized = validate(valid_observation())
        assert isinstance(normalized, NormalizedObservation)
