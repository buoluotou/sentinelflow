"""Reconciliation Contract专项 — A (Contract Types + Validation)
+ 3.4.3-B (External State Mapping).

This suite proves the INPUT + MAPPING layers of the Reconciliation
Contract (docs/design/phase3.4-reconciliation-contract.md, Design Freeze
``a125f1e``):

    3.4.3-A  ``ExternalObservation`` -> validation -> ``NormalizedObservation``
             (or a rejection);
    3.4.3-B  ``adapter`` + validated ``external_state`` -> ``StateMapping``
             (or an ``UnrecognizedExternalState`` rejection).

It is DB-free — ``validate_observation`` (A) and
``normalize_external_state`` (B) are PURE functions (the discipline of
tests/test_outcome_derivation.py), so lightweight inputs prove the whole
contract without a session.

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

3.4.3-B requirement map (user section 十五, 1-25):
  A. Shuffle (1-6) .................... TestShuffleMapping   [GAP -> refused]
  B. TheHive (7-11) ................... TestTheHiveMapping   [fail-closed M2-R]
  C. Wazuh (12-16) .................... TestWazuhMapping     [evidenced vocab]
  D. Isolation (17-20) ................ TestMappingDispatchIsolation
  E. Purity (21-25) ................... TestMappingPurity
  Anti-fabrication pins (§十六) ....... TestAntiFabricationPins
  Mapping boundary (§四) .............. TestMappableVocabularyBoundary
  Mock (§六) .......................... TestMockMapping

The soul of 3.4.3-A: a Contract Validation Failure means
NO Outcome Fact — missing reference is NEVER ``reconciliation_failed`` and an
unrecognized state is NEVER ``unknown``. The A validation path STRUCTURALLY
cannot emit an outcome word: ``NormalizedObservation`` has no ``outcome_status``
field.

The soul of 3.4.3-B: DO NOT FABRICATE. A state word is
into an adapter's vocabulary ONLY when existing adapter code (or the
design) evidences it. G1-C EMPTIED the fabricated Wazuh ``agent_status``
set (B0 — agent_status is NOT a command-level effect; G1-A proved it
LIVE-reachable, CONFIRMED UNSAFE). M2 then added EXACTLY ONE word — TheHive's
synthesized ``case_created`` — but M2-R EMPTIED it again (fail-closed, the G1-C
precedent): this vocabulary is PATH-AGNOSTIC, so a reader-only signal placed in it
is forgeable from the LIVE webhook PUSH path (a valid callback token + a schema/
correlation-valid body carrying the bare string), and the 2-param contract
(``normalize_external_state`` + the single-delegation ``map_external_state``)
STRUCTURALLY cannot express source isolation. So NO adapter (Wazuh / Shuffle /
TheHive / Mock) has an evidenced vocabulary and EVERY reported state — TheHive's
``case_created`` and ``case_unverified`` included — is REFUSED as
``UnrecognizedExternalState``, NEVER guessed to ``unknown``, NEVER
``reconciliation_failed`` (``StateMapping.__post_init__`` enforces the latter). The
reader still EMITS ``case_created`` (isolation-tested); the mapping just does not
ACCEPT it from any source until a trusted-reader source-isolation channel is
approved (M2-R Amendment). The PLATFORM success-pipeline proofs that once borrowed
the Wazuh ``success`` word still run on a TEST-ONLY fake adapter (``fake_adapter_vocab``
/ ``fake_adapter_channel`` fixtures, B0 ) — never on a real adapter word. A
dispatch word is in NO vocabulary: several tests below nail that.
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
    ADAPTER_STATE_VOCABULARIES,
    CONTRACT_FIELDS,
    MAPPABLE_OUTCOME_STATUSES,
    MAX_FUTURE_SKEW,
    SOURCE_TRUST_DOMAIN,
    TRUST_DOMAIN_ADAPTER_CALLBACK,
    TRUST_DOMAIN_HUMAN_OPERATOR,
    AdapterStateVocabulary,
    ContractValidationFailure,
    ExternalObservation,
    InvalidObservedAt,
    InvalidSource,
    MissingExecutionId,
    MissingExternalReference,
    MissingExternalState,
    NormalizedObservation,
    StateMapping,
    UnknownAdapter,
    UnrecognizedExternalState,
    normalize_external_state,
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
    semantics. The contract's second naive-clause must catch it."""

    def utcoffset(self, dt):
        return None

    def dst(self, dt):
        return None

    def tzname(self, dt):
        return "NULL"


#
# Contract shape (requirement 2)
#


class TestContractShape:
    def test_contract_fields_are_the_six_frozen_names(self):
        # requirement 2 / RC-02: exactly the six fields, in order.
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


#
# Valid observation (requirements 1, 11)
#


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


#
# Required-field + invalid-value rejection (requirements 3-9)
#


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
        # all rejections share one base -> one refusal semantic.
        assert issubclass(exc_type, ContractValidationFailure)
        assert issubclass(ContractValidationFailure, Exception)


#
# observed_at semantics
#


class TestObservedAtSemantics:
    def test_naive_datetime_rejected(self):
        # requirement 10: a naive datetime is ambiguous -> refused.
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
        # changes representation only, never the moment.
        minus_five = timezone(timedelta(hours=-5))
        local = datetime(2026, 9, 3, 7, 0, 0, tzinfo=minus_five)
        normalized = validate(valid_observation(observed_at=local))
        assert normalized.observed_at == NOW
        assert normalized.observed_at.timestamp() == NOW.timestamp()

    def test_precision_preserved_not_truncated(self):
        # microseconds survive; ties are broken downstream by id DESC,
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
        # scattered magic number; its default is 300s.
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


#
# Normalization strategy (trimming vs raw preservation)
#


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


#
# Purity, immutability, determinism (requirements 16, 17)
#


class TestPurityImmutabilityDeterminism:
    def test_input_is_immutable(self):
        # requirement 16: the input cannot be tampered with.
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
        # The output cannot be mutated — and cannot even be given an
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


#
# Identity trust domains
#


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


#
# Dispatch / Outcome vocabulary isolation (requirement 20, D3.4-04 / RC-06)
#


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
        # The strongest structural proof: pin the ENTIRE import surface. No DB,
        # no HTTP, no dispatch log, no secrets/auth. 3.4.3-B legitimately adds
        # the OUTCOME-status vocabulary (OUTCOME_STATUSES, to GUARANTEE a mapped
        # word is frozen) and normalize_external_state — this test was WRITTEN to
        # fail loudly on exactly that (see the 3.4.3-A comment) and is updated
        # deliberately. It still forbids every OTHER addition: the pinned
        # `modules` set proves no DB/HTTP/transport module was imported.
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
        # Imports the ingress + adapter vocabularies AND (3.4.3-B) the outcome
        # vocabulary — but ONLY from app.models.execution_outcome, a pure
        # frozen-constant module (still no DB, no HTTP: `modules` proves it).
        assert "OUTCOME_SOURCES" in names
        assert "ADAPTER_NAMES" in names
        assert "OUTCOME_STATUSES" in names
        # 3.4.3-B: the sanctioned mapping function now exists beside the A
        # validator (both PURE).
        assert "validate_observation" in funcs
        assert "trust_domain_for" in funcs
        assert "normalize_external_state" in funcs

    def test_module_defines_exactly_the_sanctioned_mapping_function(self):
        # 3.4.3-A asserted NO mapping function existed; 3.4.3-B adds
        # the SANCTIONED one (normalize_external_state). The forbidden aliases
        # still must not exist — the mapping surface is exactly one named, tested,
        # PURE function, never an ad-hoc converter.
        mod, _modules, _names, _funcs = _imported()
        assert hasattr(mod, "normalize_external_state")
        assert not hasattr(mod, "map_external_state")
        assert not hasattr(mod, "to_outcome_status")


#
# Rejection produces NO fact
#


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


# ===========================================================================
# B专项 — External State Mapping (user §十五, 25 requirements)
# ===========================================================================
#
# THE GOVERNING RULE: DO NOT FABRICATE adapter states.
# G1-C EMPTIED the last evidenced vocabulary: NO adapter (Wazuh / Shuffle /
# TheHive / Mock) now has a verifiable external terminal-state vocabulary, so
# EVERY external_state is REFUSED as UnrecognizedExternalState, never guessed.
# The tests below assert the GAP HONESTLY rather than inventing states to make a
# "terminal success" case pass; a concrete vocabulary lands only with real
# command-effect read evidence + an independent Design Freeze. The
# PLATFORM success-pipeline proofs run on a TEST-ONLY fake adapter.


def map_state(adapter, external_state):
    """Map an ALREADY-VALIDATED external_state (3.4.3-B entry point)."""
    return normalize_external_state(adapter, external_state)


def refused(adapter, external_state):
    """Assert the mapping REFUSES the state (never unknown / never
    reconciliation_failed) and carries the adapter — NOT the raw state value."""
    with pytest.raises(UnrecognizedExternalState) as exc:
        normalize_external_state(adapter, external_state)
    assert exc.value.adapter == adapter
    return exc.value


#
# C. Wazuh (requirements 12-16) — G1-C: vocabulary EMPTIED (fail-closed)
#


class TestWazuhMapping:
    """G1-C / B0 : the former Wazuh external-state vocabulary
    {completed,confirmed,done,success,ok} / running / unknown was FABRICATED from
    a fictional "agent_status IS the effect status" reading of a synchronous
    dispatch response and falsified by B0 (agent_status is NOT a command-level
    effect; "ok" is a task-acceptance false friend). G1-A proved it LIVE-reachable
    via BOTH the webhook (webhook.py:149) and manual (manual_persist.py:204)
    paths — CONFIRMED UNSAFE. G1-C EMPTIED all four sets to fail-closed, so EVERY
    Wazuh external_state is now REFUSED as UnrecognizedExternalState (never
    unknown, never reconciliation_failed), mirroring the Shuffle/TheHive/Mock
    honest-gap shape. The platform success-pipeline proofs that once borrowed the
    Wazuh ``success`` word now run on the TEST-ONLY fake adapter
    (fake_adapter_vocab), so this class asserts ONLY the Wazuh refusal +
    empty-vocabulary pins."""

    def test_wazuh_vocabulary_is_entirely_empty(self):
        # G1-C pin (mirror of shuffle/thehive/mock): all four sets empty, no
        # state_key, no case-folding. An empty vocabulary refuses EVERY word and
        # can never auto-reopen — a registered Reader or a configured production
        # version does NOT repopulate it (that needs command-effect evidence + an
        # independent Design Freeze, B0 ).
        vocab = ADAPTER_STATE_VOCABULARIES["wazuh"]
        assert vocab.terminal_success_states == frozenset()
        assert vocab.terminal_failure_states == frozenset()
        assert vocab.pending_states == frozenset()
        assert vocab.ambiguous_states == frozenset()
        assert vocab.state_key is None
        assert vocab.case_insensitive is False

    @pytest.mark.parametrize(
        "state", ["completed", "confirmed", "done", "ok", "success"]
    )
    def test_12_former_success_words_are_now_refused(self, state):
        # requirement 12 REVERSED (G1-C): the former "confirmed_success" words are
        # NO LONGER evidenced — agent_status is not a command-level effect
        # and a synchronous dispatch response cannot prove an external effect. Each
        # word is REFUSED, never mapped to confirmed_success (anti-fabrication §十六).
        refused("wazuh", state)

    @pytest.mark.parametrize("state", ["failed", "error", "failure", "aborted"])
    def test_13_wazuh_failure_states_are_a_documented_gap(self, state):
        # requirement 13 (UNCHANGED): Wazuh code declares NO terminal-FAILURE
        # agent_status. Its failure words (adapter_unavailable / timeout /
        # adapter_error) are TRANSPORT classifications in the DISPATCH layer, NOT
        # external agent_status values. So confirmed_failure has NO evidence and
        # is NEVER fabricated — a "failed"-like state is refused.
        assert ADAPTER_STATE_VOCABULARIES["wazuh"].terminal_failure_states == frozenset()
        refused("wazuh", state)

    @pytest.mark.parametrize("state", ["running", "RUNNING", "Running"])
    def test_14_running_is_now_refused(self, state):
        # requirement 14 REVERSED (G1-C): "running" no longer maps to pending.
        # With an empty vocabulary + case_insensitive=False, EVERY case variant is
        # refused — no fabricated in-progress semantics from agent_status.
        refused("wazuh", state)

    @pytest.mark.parametrize("state", ["unknown", "UNKNOWN", "Unknown"])
    def test_15_unknown_is_now_refused(self, state):
        # requirement 15 REVERSED (G1-C): "unknown" is NO LONGER an in-vocabulary
        # ambiguous word. Mapping an unrecognized word to the outcome word unknown
        # is the FORBIDDEN fabrication — it
        # is refused instead.
        refused("wazuh", state)

    @pytest.mark.parametrize(
        "state", ["succeeded", "queued", "started", "expired", "in_progress", "waiting"]
    )
    def test_16_unrecognized_wazuh_state_is_refused(self, state):
        # requirement 16 (UNCHANGED): any Wazuh state outside the (now empty)
        # vocabulary is REFUSED, never guessed. "succeeded" is the DISPATCH word.
        refused("wazuh", state)

    def test_wazuh_mapping_form_has_no_evidenced_key(self):
        # G1-C: state_key is now None (de-anchored from "agent_status"), so a
        # Mapping external_state yields no extractable word -> refused (mirror of
        # shuffle/thehive). The former {"agent_status": "completed"} -> success is
        # gone: no evidenced key, no fabricated effect.
        refused("wazuh", {"agent_status": "completed"})
        refused("wazuh", {"status": "completed"})
        refused("wazuh", {"agent_status": 123})

    def test_wazuh_is_now_case_sensitive_and_refuses_every_case(self):
        # G1-C: case_insensitive is now False (de-anchored from wazuh.py:246). A
        # former success word in ANY case is refused — no case-folding can
        # resurrect an unevidenced vocabulary.
        refused("wazuh", "COMPLETED")
        refused("wazuh", "Completed")
        refused("wazuh", "completed")

    def test_wazuh_does_not_trim(self):
        # wazuh.py does NOT trim agent_status, so the mapping must not either: a
        # padded word is unrecognized, never silently trimmed into a match (§十三).
        refused("wazuh", "  completed  ")


#
# A. Shuffle (requirements 1-6) — DELIBERATE GAP (trigger-only, no read path)
#


class TestShuffleMapping:
    """Shuffle is TRIGGER-ONLY: E4 freezes ``succeeded == "workflow trigger
    confirmed"``, explicitly NOT "workflow fully completed" (shuffle.py:8-12,
    250 — detail "workflow triggered"). The adapter parses only the synchronous
    dispatch response (``success:true`` + external_execution_id); it has NO read
    path and NO workflow terminal-state vocabulary. Per user §十六, NO Shuffle
    state word is fabricated: the vocabulary is EMPTY and every state is REFUSED
    until the 3.4.5 read path supplies real evidence. Requirements 1-5 therefore
    assert the HONEST GAP, not an invented mapping."""

    def test_shuffle_vocabulary_is_entirely_empty(self):
        vocab = ADAPTER_STATE_VOCABULARIES["shuffle"]
        assert vocab.terminal_success_states == frozenset()
        assert vocab.terminal_failure_states == frozenset()
        assert vocab.pending_states == frozenset()
        assert vocab.ambiguous_states == frozenset()
        assert vocab.state_key is None
        assert vocab.case_insensitive is False

    @pytest.mark.parametrize(
        "state",
        ["completed", "success", "succeeded", "done", "finished", "SUCCESS",
         "workflow_completed", "terminal_success"],
    )
    def test_1_terminal_success_is_a_documented_gap_not_a_mapping(self, state):
        # requirement 1 (HONEST GAP, user §七): external_execution_id / a trigger
        # success must NEVER imply confirmed_success (shuffle.py:250 "workflow
        # triggered" != completed). No Shuffle success word is evidenced -> refused.
        refused("shuffle", state)

    @pytest.mark.parametrize("state", ["failed", "failure", "error", "aborted"])
    def test_2_terminal_failure_is_a_documented_gap(self, state):
        # requirement 2 (HONEST GAP): no evidenced Shuffle failure word.
        refused("shuffle", state)

    @pytest.mark.parametrize("state", ["running", "executing", "in_progress"])
    def test_3_running_is_a_documented_gap(self, state):
        # requirement 3 (HONEST GAP): no evidenced Shuffle running word.
        refused("shuffle", state)

    @pytest.mark.parametrize("state", ["queued", "pending", "waiting", "scheduled"])
    def test_4_queued_pending_is_a_documented_gap(self, state):
        # requirement 4 (HONEST GAP): no evidenced Shuffle queued/pending word.
        refused("shuffle", state)

    @pytest.mark.parametrize("state", ["unknown", "weird_state", "xyz"])
    def test_5_unknown_legitimate_state_is_a_documented_gap(self, state):
        # requirement 5 (HONEST GAP): with NO evidenced vocabulary, even a
        # plausible "unknown" cannot map to the outcome word unknown — that would
        # be fabrication. It is refused (user §十六).
        refused("shuffle", state)

    def test_6_unrecognized_state_rejection(self):
        # requirement 6: the general refusal — NO Shuffle state maps, and the
        # refusal is an UnrecognizedExternalState (a ContractValidationFailure:
        # NO fact, never unknown, never reconciliation_failed — §十).
        exc = refused("shuffle", "anything_at_all")
        assert isinstance(exc, ContractValidationFailure)

    def test_shuffle_mapping_form_has_no_evidenced_key(self):
        # A Mapping external_state has no evidenced state_key for Shuffle, so no
        # word can be extracted -> refused (never guessed from an arbitrary key).
        refused("shuffle", {"status": "completed"})
        refused("shuffle", {"execution_id": "abc"})


#
# B. TheHive (requirements 7-11) — DELIBERATE GAP (case created != resolved)
#


class TestTheHiveMapping:
    """TheHive creates a case and NEVER auto-closes it — "case created != case
    resolved"; investigation is human-led, so NO native lifecycle STATE word is
    fabricated (requirements 7-10 assert that HONEST GAP: resolved/closed/open/
    unknown are all REFUSED). M2 added EXACTLY ONE word — ``case_created``, the
    SentinelFlow-SYNTHESIZED creation-effect signal emitted by ``TheHiveReadAdapter``
    on a verified ``GET /api/case/{_id}``. M2-R EMPTIED it again (fail-closed):
    the vocabulary is PATH-AGNOSTIC, so the word was forgeable from the LIVE webhook
    path and the 2-param contract cannot express source isolation. EVERY
    TheHive state — ``case_created`` and the reader's ``case_unverified`` included —
    is now REFUSED, so NO path launders a string into success until a trusted-reader
    source-isolation channel is approved (M2-R Amendment).
    """

    def test_thehive_vocabulary_is_entirely_empty(self):
        # M2-R FAIL-CLOSED (mirror of the G1-C wazuh pin): all four sets empty.
        # M2 's synthesized ``case_created`` is REMOVED because the path-agnostic
        # vocabulary let a webhook forge it and the 2-param contract cannot
        # express source isolation. An empty vocabulary refuses EVERY word (including
        # the reader's own ``case_created``) and can never auto-reopen — a registered
        # Reader or a configured production version does NOT re-add it; only an
        # approved source-isolation Amendment (M2-R) may, with an independent freeze.
        vocab = ADAPTER_STATE_VOCABULARIES["thehive"]
        assert vocab.terminal_success_states == frozenset()
        assert vocab.terminal_failure_states == frozenset()
        assert vocab.pending_states == frozenset()
        assert vocab.ambiguous_states == frozenset()
        assert vocab.state_key is None
        assert vocab.case_insensitive is False

    def test_thehive_case_created_is_refused_fail_closed(self):
        # M2-R : the synthesized ``case_created``
        # word is REFUSED at the mapping layer (fail-closed) because the path-agnostic
        # vocabulary cannot tell a trusted-reader signal from a webhook-forged string.
        # The READER still EMITS it on a verified GET (test_read_adapter_thehive.py);
        # the MAPPING no longer ACCEPTS it from any source -> zero fact, until the
        # source-isolation Amendment lands.
        refused("thehive", "case_created")

    def test_thehive_case_unverified_is_refused(self):
        # M2 NEGATIVE: the reader's unverified signal (a 200 that FAILED the
        # identity/correlation conjunction) is NOT in the vocabulary -> REFUSED ->
        # 422 / ZERO facts. A bare HTTP 200 / mere existence is NEVER success.
        refused("thehive", "case_unverified")

    def test_thehive_case_created_is_case_sensitive(self):
        # case_insensitive is False, so ONLY the exact word maps; a case variant is
        # REFUSED (no TheHive-specific normalization is evidenced, §十三).
        refused("thehive", "CASE_CREATED")
        refused("thehive", "Case_Created")

    @pytest.mark.parametrize(
        "state", ["resolved", "closed", "solved", "completed", "success"]
    )
    def test_7_resolved_success_is_a_documented_gap_not_a_mapping(self, state):
        # requirement 7 (HONEST GAP, user §八): case_id existing != confirmed_
        # success; only an evidenced case-lifecycle success could map, and none
        # exists in current code -> refused.
        refused("thehive", state)

    @pytest.mark.parametrize("state", ["failed", "rejected", "error"])
    def test_8_failed_is_a_documented_gap(self, state):
        # requirement 8 (HONEST GAP): no evidenced TheHive failure word.
        refused("thehive", state)

    @pytest.mark.parametrize("state", ["open", "processing", "in_progress", "waiting"])
    def test_9_open_processing_is_a_documented_gap(self, state):
        # requirement 9 (HONEST GAP): no evidenced TheHive in-progress word.
        refused("thehive", state)

    @pytest.mark.parametrize("state", ["unknown", "xyz", "case_123"])
    def test_10_unknown_legitimate_state_is_a_documented_gap(self, state):
        # requirement 10 (HONEST GAP): with NO evidenced vocabulary, "unknown"
        # cannot map to the outcome word unknown — refused (user §十六).
        refused("thehive", state)

    def test_11_unrecognized_state_rejection(self):
        # requirement 11
        exc = refused("thehive", "anything_at_all")
        assert isinstance(exc, ContractValidationFailure)

    def test_thehive_mapping_form_has_no_evidenced_key(self):
        refused("thehive", {"status": "resolved"})
        refused("thehive", {"case_id": "abc"})


#
# Mock (user §六) — PERMANENTLY unsupported (no external system, no outcome)
#


class TestMockMapping:
    """Mock has ZERO outbound traffic and NO external system (mock.py:4-6), so it
    can NEVER produce an external outcome. Unlike Shuffle / TheHive this is NOT a
    3.4.5 gap — it is PERMANENT by design (user §六: "Mock 可以保留明确的
    unsupported / no external outcome"). Every Mock state is refused."""

    def test_mock_vocabulary_is_entirely_empty(self):
        vocab = ADAPTER_STATE_VOCABULARIES["mock"]
        assert vocab.terminal_success_states == frozenset()
        assert vocab.terminal_failure_states == frozenset()
        assert vocab.pending_states == frozenset()
        assert vocab.ambiguous_states == frozenset()

    @pytest.mark.parametrize(
        "state", ["completed", "success", "succeeded", "failed", "running",
                 "unknown", "dry_run", "simulated"]
    )
    def test_mock_has_no_external_outcome_by_design(self, state):
        refused("mock", state)

    def test_mock_evidence_records_permanent_unsupport(self):
        # The reason is DOCUMENTED, not silent (user §十二 auditable mapping).
        assert "no external outcome by design" in ADAPTER_STATE_VOCABULARIES["mock"].evidence


#
# D. Isolation (requirements 17-20) — dispatch vocab NEVER becomes outcome vocab
#


class TestMappingDispatchIsolation:
    def test_17_succeeded_does_not_map_to_confirmed_success(self):
        # requirement 17 (§五): the dispatch word "succeeded" is NOT Wazuh's
        # "success" and is in NO adapter's evidenced vocabulary. For EVERY adapter
        # it is REFUSED — never laundered into confirmed_success by its spelling.
        for adapter in sorted(ADAPTER_NAMES):
            refused(adapter, "succeeded")

    def test_18_failed_does_not_map_to_confirmed_failure(self):
        # requirement 18 (§五): the dispatch word "failed" is in NO adapter's
        # vocabulary (Wazuh has no evidenced failure state at all) -> refused.
        for adapter in sorted(ADAPTER_NAMES):
            refused(adapter, "failed")

    def test_19_no_dispatch_word_is_in_any_adapter_vocabulary(self):
        # requirement 19 (STRUCTURAL): the union of every adapter's evidenced
        # words is DISJOINT from the dispatch vocabulary — so no dispatch word can
        # ever reach an outcome word through the mapping. (Note "success" — Wazuh's
        # word — is NOT a dispatch word; "succeeded" is, and is absent here.)
        for adapter, vocab in ADAPTER_STATE_VOCABULARIES.items():
            evidenced = (
                vocab.terminal_success_states
                | vocab.terminal_failure_states
                | vocab.pending_states
                | vocab.ambiguous_states
            )
            assert evidenced.isdisjoint(DISPATCH_WORDS), adapter

    @pytest.mark.parametrize("word", DISPATCH_WORDS)
    def test_19_no_dispatch_word_maps_for_any_adapter(self, word):
        # requirement 19 (BEHAVIORAL): every dispatch word, fed to every adapter,
        # is refused — the dispatch vocabulary never enters the outcome vocabulary.
        for adapter in sorted(ADAPTER_NAMES):
            refused(adapter, word)

    def test_20_no_adapter_vocabulary_leaks_the_former_wazuh_words(self):
        # requirement 20 REVERSED (G1-C): mappings are adapter-specific — no
        # shared/generic table. Since G1-C EMPTIED the Wazuh vocabulary, NO
        # adapter maps the former Wazuh words: each is refused by wazuh AND every
        # other adapter (total isolation — there is no evidenced word to leak).
        for word in ["completed", "confirmed", "done", "ok", "success", "running", "unknown"]:
            for adapter in sorted(ADAPTER_NAMES):
                refused(adapter, word)

    def test_20_no_adapter_extracts_the_agent_status_key(self):
        # G1-C: the Wazuh Mapping state_key is now None (de-anchored from
        # "agent_status"), so NO adapter extracts a word from that payload — the
        # identical {"agent_status": ...} Mapping is refused everywhere.
        for adapter in sorted(ADAPTER_NAMES):
            refused(adapter, {"agent_status": "completed"})


#
# E. Purity (requirements 21-25) — no DB, no HTTP, no adapter call, no mutation
#


class TestMappingPurity:
    def test_21_repeated_calls_are_deterministic(self, fake_adapter_vocab):
        # requirement 21: same (adapter, state) -> EQUAL StateMapping, every time.
        # G1-C / B0 : the platform determinism proof runs on the TEST-ONLY
        # fake adapter (no production adapter has an evidenced word to map).
        fake = fake_adapter_vocab
        first = map_state(fake, "completed")
        second = map_state(fake, "completed")
        third = map_state(fake, "completed")
        assert first == second == third
        assert first.outcome_status == second.outcome_status == "confirmed_success"

    def test_21_repeated_refusal_is_deterministic(self):
        # A refused state raises the SAME exception type every time.
        for _ in range(3):
            refused("shuffle", "completed")

    def test_22_23_24_mapping_signature_is_pure(self):
        # requirements 22/23/24 (STRUCTURAL): normalize_external_state takes ONLY
        # (adapter, external_state) — no session, no db, no repository, no client,
        # no HTTP. The pinned import surface (TestDispatchOutcomeIsolation) proves
        # no DB/HTTP module is imported; this proves no such PARAMETER exists.
        sig = inspect.signature(normalize_external_state)
        assert list(sig.parameters) == ["adapter", "external_state"]

    def test_22_23_module_imports_no_db_or_http(self):
        # requirements 22/23: the module imports NO database, ORM, session, or
        # HTTP/transport library. B added only the outcome vocabulary (from
        # app.models.execution_outcome, a pure frozen-constant module).
        _mod, modules, names, _funcs = _imported()
        forbidden_roots = {
            "sqlalchemy", "requests", "httpx", "aiohttp", "urllib", "urllib3",
            "asyncpg", "psycopg2", "fastapi", "starlette", "pydantic", "socket",
        }
        for mod_name in modules:
            assert mod_name.split(".")[0] not in forbidden_roots, mod_name
        for forbidden in ("Session", "session", "engine", "Repository", "Client", "AsyncClient"):
            assert forbidden not in names

    def test_24_mapping_is_table_driven_with_no_adapter_client(self):
        # requirement 24: B is state -> outcome ONLY, NEVER adapter -> HTTP ->
        # state -> outcome (3.4.5). The mapping is driven purely by the frozen
        # in-module ADAPTER_STATE_VOCABULARIES table of frozensets/str — it holds
        # NO adapter client, NO callable, NO transport.
        for vocab in ADAPTER_STATE_VOCABULARIES.values():
            assert isinstance(vocab, AdapterStateVocabulary)
            for word_set in (
                vocab.terminal_success_states, vocab.terminal_failure_states,
                vocab.pending_states, vocab.ambiguous_states,
            ):
                assert isinstance(word_set, frozenset)
                assert all(isinstance(w, str) for w in word_set)
            assert vocab.state_key is None or isinstance(vocab.state_key, str)
            assert isinstance(vocab.case_insensitive, bool)

    def test_25_input_mapping_is_not_mutated(self, fake_adapter_vocab):
        # requirement 25 (§十三): a Mapping external_state is never altered.
        # G1-C / B0 : runs on the TEST-ONLY fake adapter (case-insensitive +
        # agent_status state_key), proving the platform non-mutation contract.
        fake = fake_adapter_vocab
        payload = {"agent_status": "COMPLETED", "extra": "keep"}
        snapshot = dict(payload)
        mapping = map_state(fake, payload)
        assert payload == snapshot                     # input untouched
        assert mapping.observed_state == "COMPLETED"   # raw word preserved
        assert mapping.normalized_state == "completed"

    def test_25_result_is_frozen_and_input_str_untouched(self, fake_adapter_vocab):
        # requirement 25: the result StateMapping is immutable (frozen); a str
        # input is inherently unchanged, and no attribute can be reassigned.
        # G1-C / B0 : runs on the TEST-ONLY fake adapter.
        fake = fake_adapter_vocab
        mapping = map_state(fake, "completed")
        with pytest.raises(FrozenInstanceError):
            mapping.outcome_status = "reconciliation_failed"
        with pytest.raises(FrozenInstanceError):
            mapping.adapter = "shuffle"


#
# Anti-fabrication pins (user §十六 — the governing rule of 3.4.3-B)
#


class TestAntiFabricationPins:
    """These tests PIN the deliberate gaps so a future change cannot silently
    fabricate an unevidenced state. Filling any pinned-empty vocabulary requires
    3.4.5 read-path evidence and a DELIBERATE update here (user §十六: "宁可返回
    mapping rejection，不要猜测")."""

    def test_vocabulary_keys_are_exactly_the_adapter_names(self):
        # Single source: every validated adapter has a table; no table exists for
        # a non-adapter (registry.ADAPTER_NAMES is the adapter identity source).
        assert set(ADAPTER_STATE_VOCABULARIES) == set(ADAPTER_NAMES)

    def test_no_adapter_evidences_a_vocabulary(self):
        # M2-R (was: only TheHive evidenced case_created): G1-C emptied Wazuh;
        # M2 added TheHive's case_created; M2-R empties it AGAIN (fail-closed)
        # because the path-agnostic vocabulary made it webhook-forgeable and the
        # 2-param contract cannot express source isolation. So NO adapter
        # (wazuh / shuffle / thehive / mock) evidences ANY word platform-wide.
        # Repopulating ANY vocabulary — including a source-isolated TheHive reader
        # channel — requires real read evidence + an approved Amendment + an
        # independent Design Freeze; this pin fails loudly if a vocabulary
        # is silently reopened on ANY adapter.
        for adapter, vocab in ADAPTER_STATE_VOCABULARIES.items():
            evidenced = (
                vocab.terminal_success_states | vocab.terminal_failure_states
                | vocab.pending_states | vocab.ambiguous_states
            )
            assert evidenced == frozenset(), adapter

    def test_no_adapter_evidences_a_failure_state(self):
        # The strongest anti-fabrication pin: NO adapter — not even Wazuh — has an
        # evidenced terminal_failure vocabulary. confirmed_failure is therefore
        # UNREACHABLE by the mapping today; it lands only with 3.4.5 evidence.
        for adapter, vocab in ADAPTER_STATE_VOCABULARIES.items():
            assert vocab.terminal_failure_states == frozenset(), adapter

    def test_confirmed_failure_is_currently_unreachable(self):
        # Behavioral corollary of the pin above: no evidenced state of any adapter
        # yields confirmed_failure.
        for adapter, vocab in ADAPTER_STATE_VOCABULARIES.items():
            for word in (
                vocab.terminal_success_states | vocab.pending_states
                | vocab.ambiguous_states
            ):
                assert map_state(adapter, word).outcome_status != "confirmed_failure"

    def test_no_adapter_normalizes_case_or_extracts_a_state_key(self):
        # G1-C REVERSAL (§十三): case-folding / a state_key were code-evidenced for
        # Wazuh ONLY; after emptying its vocabulary, EVERY adapter (including
        # Wazuh) keeps case_insensitive False and state_key None — no
        # adapter-specific normalization survives without evidence.
        for adapter in ("wazuh", "shuffle", "thehive", "mock"):
            assert ADAPTER_STATE_VOCABULARIES[adapter].case_insensitive is False
            assert ADAPTER_STATE_VOCABULARIES[adapter].state_key is None

    def test_every_vocabulary_documents_its_evidence_or_gap(self):
        # No silent entries: each vocabulary records WHY (an evidence citation or
        # an explicit GAP note) so the mapping is auditable (user §十二).
        for vocab in ADAPTER_STATE_VOCABULARIES.values():
            assert vocab.evidence  # non-empty string


#
# Mapping boundary (user §四) — reconciliation_failed is NEVER a mapping product
#


class TestMappableVocabularyBoundary:
    def test_mappable_statuses_exclude_reconciliation_failed(self):
        # §四: the mapping target vocabulary is the five MINUS
        # reconciliation_failed (the READ-FAILURE verdict, 3.4.5). Single source.
        assert MAPPABLE_OUTCOME_STATUSES == OUTCOME_STATUSES - {"reconciliation_failed"}
        assert "reconciliation_failed" not in MAPPABLE_OUTCOME_STATUSES
        assert MAPPABLE_OUTCOME_STATUSES == {
            "unknown", "pending", "confirmed_success", "confirmed_failure"
        }

    def test_normalize_external_state_never_returns_reconciliation_failed(self):
        # §四 (BEHAVIORAL): across every evidenced state of every adapter, the
        # mapping never emits reconciliation_failed.
        for adapter, vocab in ADAPTER_STATE_VOCABULARIES.items():
            for word in (
                vocab.terminal_success_states | vocab.terminal_failure_states
                | vocab.pending_states | vocab.ambiguous_states
            ):
                assert map_state(adapter, word).outcome_status != "reconciliation_failed"

    def test_state_mapping_refuses_reconciliation_failed_structurally(self):
        # §四 (STRUCTURAL): StateMapping.__post_init__ rejects the read-failure
        # word even if a branch ever tried to emit it.
        with pytest.raises(ValueError):
            StateMapping("wazuh", "reconciliation_failed", "x", "x", "reason")

    def test_state_mapping_refuses_a_non_outcome_word(self):
        # Defensive (mirrors derivation): a typo'd word outside the five is
        # rejected — the dispatch word "succeeded" is NOT an outcome word.
        with pytest.raises(ValueError):
            StateMapping("wazuh", "succeeded", "x", "x", "reason")

    def test_state_mapping_accepts_every_mappable_word(self):
        for word in sorted(MAPPABLE_OUTCOME_STATUSES):
            assert StateMapping("wazuh", word, "obs", "norm", "reason").outcome_status == word

    def test_state_mapping_fields_are_the_audit_triple(self, fake_adapter_vocab):
        # §十四: the PURE domain result carries the audit triple, no DB write.
        # G1-C / B0 : the positive mapping example runs on the TEST-ONLY fake
        # adapter (no production adapter maps a word); the field-shape assertion
        # is adapter-independent.
        fake = fake_adapter_vocab
        assert tuple(f.name for f in fields(StateMapping)) == (
            "adapter", "outcome_status", "observed_state", "normalized_state",
            "mapping_reason",
        )
        mapping = map_state(fake, "completed")
        assert mapping.adapter == fake
        assert mapping.outcome_status == "confirmed_success"
        assert mapping.observed_state == "completed"
        assert mapping.normalized_state == "completed"
        assert fake in mapping.mapping_reason

    def test_unrecognized_external_state_is_a_contract_validation_failure(self):
        # §十: the mapping rejection shares the A refusal base -> ONE semantic: NO
        # Outcome Fact. It is never unknown, never reconciliation_failed.
        assert issubclass(UnrecognizedExternalState, ContractValidationFailure)

    def test_unrecognized_rejection_never_echoes_the_raw_state(self):
        # Sanitized: the refusal names the adapter (not a secret) but NEVER the raw
        # external_state value (external private data — non-echo discipline).
        secret_state = "SUPER-SECRET-EXTERNAL-VALUE"
        with pytest.raises(UnrecognizedExternalState) as exc:
            normalize_external_state("shuffle", secret_state)
        assert secret_state not in str(exc.value)
        assert exc.value.adapter == "shuffle"
